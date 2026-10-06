// Package intents is the payment orchestrator (RFC 0001 §1.5, §2.2.5,
// §4.4.5). A payment intent is authorised by a TxAuth signed by the payer's
// hardware-bound key, checked byte for byte against the request, gated by
// limits, and backed by a ledger hold. Kinetic throws settle only on CATCH:
// an uncaught throw becomes an asynchronous claim or returns to the payer
// (the boomerang). Handle, QR and split payments settle on acceptance.
//
//	CREATED ──hold──▶ HELD ──INCOMING delivered──▶ DELIVERED ──CATCH(accept)──▶ CAUGHT ──post──▶ SETTLED
//	   │ limits / risk / refused hold   │ live TTL without a catch     │ CATCH(decline), cancel
//	   ▼                                ▼                               ▼
//	ABORTED (no hold)       ASYNC_PENDING ──claim──▶ CAUGHT      VOIDING ──release──▶ VOIDED
//	                                       └─ claim window over ─▶ VOIDING
//
// CAUGHT and VOIDING are durable decisions whose ledger call is still
// pending; every ledger and FX call is idempotent, so the sweeper (or any
// replay of the request) finishes them after a crash.
package intents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/money"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

// State is an intent's lifecycle state.
type State string

// States.
const (
	StateCreated      State = "created"
	StateHeld         State = "held"
	StateDelivered    State = "delivered"
	StateCaught       State = "caught"
	StateSettled      State = "settled"
	StateAsyncPending State = "async_pending"
	StateVoiding      State = "voiding"
	StateVoided       State = "voided"
	StateAborted      State = "aborted"
)

// Final reports whether no further transition is possible.
func (s State) Final() bool { return s == StateSettled || s == StateVoided || s == StateAborted }

func (s State) valid() bool {
	switch s {
	case StateCreated, StateHeld, StateDelivered, StateCaught, StateSettled, StateAsyncPending, StateVoiding,
		StateVoided, StateAborted:
		return true
	}
	return false
}

// Gesture is how the payment was made.
type Gesture string

// Gestures.
const (
	GestureFlick  Gesture = "flick"  // kinetic throw to a locked payee (§3.B.1–3)
	GestureSplit  Gesture = "split"  // a confirmed share of a shaken bill (§3.B.4)
	GestureGrab   Gesture = "grab"   // a drop, grabbed by whoever pulls it back (§3.B.5)
	GestureHandle Gesture = "handle" // to a resolved handle (§4.1.4)
	GestureQR     Gesture = "qr"     // to a scanned payee code
)

func (g Gesture) valid() bool {
	switch g {
	case GestureFlick, GestureSplit, GestureGrab, GestureHandle, GestureQR:
		return true
	}
	return false
}

// Live reports whether the intent waits for a CATCH: flicks and drops.
// Every other intent settles as soon as its hold is placed.
func (g Gesture) Live() bool { return g == GestureFlick || g == GestureGrab }

// Kind is the TxAuth gesture kind (key 9) the payer signs.
func (g Gesture) Kind() txauth.Gesture {
	switch g {
	case GestureFlick:
		return txauth.GestureFlick
	case GestureSplit:
		return txauth.GestureSplit
	case GestureGrab:
		return txauth.GestureGrab
	}
	return txauth.GestureNone
}

// Timeout is what happens to a throw nobody caught within the live TTL.
type Timeout string

// Timeout preferences.
const (
	TimeoutAsync Timeout = "async" // claimable by the payee for the claim window
	TimeoutVoid  Timeout = "void"  // returned to the payer at once
)

// Reasons recorded on aborted and voided intents.
const (
	ReasonGestureLimit      = "gesture_limit"      // K_gest above the gesture limit
	ReasonVelocity          = "velocity"           // K_gest velocity limit
	ReasonAmountLimit       = "amount_limit"       // per-intent cap
	ReasonDailyLimit        = "daily_limit"        // rolling 24 h outflow cap
	ReasonPayerInactive     = "payer_inactive"     // the payer's account is frozen or closed
	ReasonPayeeUnknown      = "payee_unknown"      // no such subject, or no directory entry
	ReasonPayeeUnavailable  = "payee_unavailable"  // the payee closed their account
	ReasonPayeeChanged      = "payee_changed"      // PAYEE_CHANGED: the entry moved past the signed version
	ReasonPayeeCurrency     = "payee_currency"     // the payee does not receive the currency
	ReasonSelfPayment       = "self_payment"       // payer and payee are the same person
	ReasonIntegrityStale    = "integrity_stale"    // the signing device's integrity evidence is too old
	ReasonQuoteInvalid      = "quote_invalid"      // the FX quote is unusable for this intent
	ReasonInsufficientFunds = "insufficient_funds" // the ledger refused the hold for lack of funds
	ReasonAccountFrozen     = "account_frozen"     // the payer's ledger account is frozen
	ReasonHoldRefused       = "hold_refused"       // the ledger refused the hold for another reason
	ReasonHoldExpired       = "hold_expired"       // the hold lapsed before settlement
	ReasonDeclined          = "declined"           // the payee declined
	ReasonCancelled         = "cancelled"          // the payer cancelled
	ReasonUncaught          = "uncaught"           // live TTL over and the intent cannot wait for a claim
	ReasonClaimExpired      = "claim_expired"      // nobody claimed it within the claim window
	ReasonSettleRefused     = "settle_refused"     // the ledger refused the post
	ReasonFXExpired         = "fx_expired"         // the quote expired before the catch
	ReasonFXRequote         = "fx_requote"         // the market moved beyond the breaker
	ReasonFXFailed          = "fx_failed"          // the quote could not be executed
)

// Errors.
var (
	ErrTxAuth      = errors.New("intents: transaction authorisation rejected")
	ErrNonce       = errors.New("intents: server nonce invalid, expired or already used")
	ErrStale       = errors.New("intents: transaction authorisation is too old or from the future")
	ErrMismatch    = errors.New("intents: request differs from the signed authorisation")
	ErrConflict    = errors.New("intents: intent id already used by another authorisation")
	ErrNotFound    = errors.New("intents: intent not found")
	ErrForbidden   = errors.New("intents: not allowed for this user")
	ErrState       = errors.New("intents: not allowed in the intent's state")
	ErrRequest     = errors.New("intents: invalid request")
	ErrUnavailable = errors.New("intents: a dependency is unavailable; the intent completes on retry")
)

// StateError reports an operation refused in a state.
type StateError struct {
	Op    string
	State State
}

func (e *StateError) Error() string {
	return fmt.Sprintf("intents: cannot %s an intent that is %s", e.Op, e.State)
}

// Unwrap makes errors.Is(err, ErrState) true.
func (e *StateError) Unwrap() error { return ErrState }

// Trajectory is the flick's flight as the thrower measured it (§3.B,
// §4.4.3); the receiver animates the entry from it.
type Trajectory struct {
	Azimuth  float64 `json:"az"` // radians in the thrower's world frame
	Speed    float64 `json:"v"`  // peak speed, m/s
	Distance float64 `json:"d"`  // UWB distance, m
}

func (t *Trajectory) validate() error {
	for _, v := range []float64{t.Azimuth, t.Speed, t.Distance} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("%w: trajectory values must be finite", ErrRequest)
		}
	}
	if math.Abs(t.Azimuth) > math.Pi || t.Speed < 0 || t.Speed > 30 || t.Distance < 0 || t.Distance > 100 {
		return fmt.Errorf("%w: trajectory out of range", ErrRequest)
	}
	return nil
}

// Intent is a payment intent.
type Intent struct {
	ID            uuid.UUID
	PayerID       uuid.UUID
	PayerSubject  string
	PayerDeviceID uuid.UUID
	SignerKeyID   uuid.UUID
	SignerRole    string // devicebind.RoleDevice or RoleGesture
	PayeeID       uuid.UUID
	PayeeSubject  string
	PARVersion    uint64 // the payee entry version the payer verified; 0 for drops
	Gesture       Gesture
	Amount        int64 // debited from the payer, minor units of Currency
	Currency      string
	PayeeAmount   int64 // credited to the payee
	PayeeCurrency string
	QuoteID       uuid.UUID // nil for a same-currency payment
	State         State
	Reason        string
	OnTimeout     Timeout
	SignedAt      time.Time
	TxAuth        []byte // the COSE_Sign1, kept as evidence
	HoldID        uuid.UUID
	HoldExpiresAt time.Time
	EntryIDs      []uuid.UUID
	TLand         *time.Time
	LiveUntil     *time.Time
	ClaimUntil    *time.Time
	Trajectory    *Trajectory
	CreatedAt     time.Time
	UpdatedAt     time.Time
	HeldAt        *time.Time
	DeliveredAt   *time.Time
	CaughtAt      *time.Time
	ResolvedAt    *time.Time

	nonce          [16]byte
	quoteSignature []byte
	// fresh marks an intent this process has just inserted: no earlier
	// attempt can have placed its hold.
	fresh bool
}

// Limits are per-currency payment limits, in minor units.
type Limits struct {
	Gesture       int64 // largest K_gest intent (RFC default 100.00)
	GestureWindow int64 // K_gest total per velocity window (RFC default 250.00)
	PerIntent     int64 // largest intent; 0 means no cap
	Daily         int64 // rolling 24 h outflow; 0 means no cap
}

// DefaultLimits are the RFC defaults scaled to the currency's minor unit:
// 100 and 250 major units for gestures, no other caps.
func DefaultLimits(currency string) Limits {
	c, ok := money.Lookup(currency)
	if !ok {
		return Limits{}
	}
	unit := int64(math.Pow10(c.Exponent))
	return Limits{Gesture: 100 * unit, GestureWindow: 250 * unit}
}

// Config configures the orchestrator. Zero durations take the defaults.
type Config struct {
	// NonceKeys MAC the server nonces (≥ 32 bytes each). The first key
	// issues; all verify, so keys rotate without invalidating batches.
	NonceKeys [][]byte
	NonceTTL  time.Duration // how long a nonce can be signed with (10 min)
	MaxAge    time.Duration // how long a TxAuth can take to reach the server (60 s)
	ClockSkew time.Duration // tolerated client clock error (30 s)
	MaxFlight time.Duration // largest t_land after the signing time (2 s; flights last ≤ 820 ms)
	LiveTTL   time.Duration // catch window after t_land (30 s)
	DropTTL   time.Duration // how long a drop stays grabbable (60 s)
	ClaimTTL  time.Duration // asynchronous claim window (7 days)
	// HoldMargin keeps a hold alive past the last moment the intent can
	// need it, so a settlement retried late still finds it (1 h).
	HoldMargin time.Duration
	// Limits overrides DefaultLimits per currency.
	Limits map[string]Limits
	// K_gest velocity: at most GestureCount intents (and the currency's
	// GestureWindow amount) per GestureWindow (5 per 60 s).
	GestureCount  int
	GestureWindow time.Duration
	// IntegrityMaxAge is how old the signing device's latest integrity
	// evidence (its attestation, an App Attest assertion or a Play Integrity
	// verdict) may be (30 days); apps refresh it in the background.
	IntegrityMaxAge time.Duration
	// The sweeper finishes intents whose ledger call has been pending this
	// long (15 s), in batches of SweepBatch (100).
	RedriveAfter time.Duration
	SweepBatch   int
	Now          func() time.Time
	Logger       *slog.Logger
	Registerer   prometheus.Registerer // nil: no metrics
}

func (c *Config) defaults() error {
	if len(c.NonceKeys) == 0 {
		return errors.New("intents: at least one nonce key is required")
	}
	for i, k := range c.NonceKeys {
		if len(k) < 32 {
			return fmt.Errorf("intents: nonce key %d is shorter than 32 bytes", i)
		}
	}
	for _, d := range []struct {
		v   *time.Duration
		def time.Duration
	}{{&c.NonceTTL, 10 * time.Minute}, {&c.MaxAge, time.Minute}, {&c.ClockSkew, 30 * time.Second},
		{&c.MaxFlight, 2 * time.Second}, {&c.LiveTTL, 30 * time.Second}, {&c.DropTTL, time.Minute},
		{&c.ClaimTTL, 7 * 24 * time.Hour}, {&c.HoldMargin, time.Hour}, {&c.GestureWindow, time.Minute},
		{&c.RedriveAfter, 15 * time.Second}, {&c.IntegrityMaxAge, 30 * 24 * time.Hour}} {
		if *d.v == 0 {
			*d.v = d.def
		}
		if *d.v < 0 {
			return errors.New("intents: durations must be positive")
		}
	}
	if c.GestureCount == 0 {
		c.GestureCount = 5
	}
	if c.SweepBatch == 0 {
		c.SweepBatch = 100
	}
	if c.GestureCount < 0 || c.SweepBatch < 0 {
		return errors.New("intents: counts must be positive")
	}
	if worst := c.LiveTTL + c.MaxFlight + 2*c.ClockSkew + c.ClaimTTL + c.HoldMargin; worst > 30*24*time.Hour {
		return fmt.Errorf("intents: holds would outlive the ledger's 31-day maximum (%s)", worst)
	}
	for cur, l := range c.Limits {
		if _, ok := money.Lookup(cur); !ok {
			return fmt.Errorf("intents: limits for unknown currency %q", cur)
		}
		if l.Gesture <= 0 || l.GestureWindow < l.Gesture || l.PerIntent < 0 || l.Daily < 0 {
			return fmt.Errorf("intents: limits for %s are inconsistent", cur)
		}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

func (c *Config) limits(currency string) Limits {
	if l, ok := c.Limits[currency]; ok {
		return l
	}
	return DefaultLimits(currency)
}

// Keys finds device keys (*devicebind.Service).
type Keys interface {
	ActiveKey(ctx context.Context, keyID uuid.UUID) (devicebind.Key, error)
}

// Directory resolves payees (*identity.Service).
type Directory interface {
	Payee(ctx context.Context, subject string) (identity.Payee, error)
	Subject(ctx context.Context, userID uuid.UUID) (string, error)
}

// FX prices and executes cross-currency payments (*fxapi.Client).
type FX interface {
	GetQuote(ctx context.Context, userID, quoteID uuid.UUID) (*fx.Quote, *fx.Execution, error)
	ExecuteQuote(ctx context.Context, r fx.ExecuteRequest) (fx.Execution, error)
}
