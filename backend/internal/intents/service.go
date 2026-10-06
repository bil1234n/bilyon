package intents

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/money"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

// Service orchestrates payment intents.
type Service struct {
	cfg      Config
	db       *store
	pool     *pgxpool.Pool
	nonces   *nonces
	keys     Keys
	dir      Directory
	fx       FX // nil: no cross-currency payments
	ledger   ledger.Ledger
	accounts *accounts.Resolver
	m        *metrics
}

// New returns the orchestrator over the gateway database.
func New(cfg Config, pool *pgxpool.Pool, keys Keys, dir Directory, fxs FX, l ledger.Ledger, accts *accounts.Resolver) (*Service, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	if pool == nil || keys == nil || dir == nil || l == nil || accts == nil {
		return nil, errors.New("intents: database, keys, directory, ledger and accounts are required")
	}
	return &Service{cfg: cfg, db: &store{pool: pool}, pool: pool,
		nonces: &nonces{keys: cfg.NonceKeys, ttl: cfg.NonceTTL, skew: cfg.ClockSkew},
		keys:   keys, dir: dir, fx: fxs, ledger: l, accounts: accts, m: newMetrics(cfg.Registerer)}, nil
}

func (s *Service) now() time.Time { return s.cfg.Now().UTC().Truncate(time.Microsecond) }

// MaxNonces bounds one batch.
const MaxNonces = 16

// IssueNonces hands a device a batch of server nonces, typically when
// throw mode opens, so that signing a throw never waits for a round trip.
func (s *Service) IssueNonces(ctx context.Context, userID, deviceID uuid.UUID, n int) ([]Nonce, error) {
	if n < 1 || n > MaxNonces {
		return nil, fmt.Errorf("%w: between 1 and %d nonces", ErrRequest, MaxNonces)
	}
	owner, revoked, err := s.db.deviceOwner(ctx, deviceID)
	if errors.Is(err, ErrNotFound) || (err == nil && owner != userID) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrForbidden
	}
	now := s.now()
	out := make([]Nonce, n)
	for i := range out {
		if out[i], err = s.nonces.issue(deviceID, now); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SetTimeout records what happens by default to the user's uncaught throws.
func (s *Service) SetTimeout(ctx context.Context, userID uuid.UUID, t Timeout) error {
	if t != TimeoutAsync && t != TimeoutVoid {
		return fmt.Errorf("%w: timeout %q", ErrRequest, t)
	}
	return s.db.setTimeout(ctx, userID, t)
}

// Timeout returns the user's default for uncaught throws.
func (s *Service) Timeout(ctx context.Context, userID uuid.UUID) (Timeout, error) {
	return s.db.timeout(ctx, userID)
}

// CreateRequest submits a signed intent: the THROW of §4.4.5, or a payment
// to a handle or code. Its fields repeat what the TxAuth signs; they must
// match byte for byte.
type CreateRequest struct {
	// SubmitterID is the authenticated user: the payer, or the payee
	// relaying a THROW that reached them only peer to peer (dual-path
	// submission).
	SubmitterID  uuid.UUID
	TxAuth       []byte
	Gesture      Gesture
	PayeeSubject string // empty for a drop
	Amount       int64
	Currency     string
	QuoteID      uuid.UUID   // nil without FX
	TLand        time.Time   // flicks: the landing time in server time
	Trajectory   *Trajectory // flicks, optional
	// OnTimeout is the payer's choice for this throw; empty takes their
	// default. A relayed submission always takes the payer's default.
	OnTimeout Timeout
}

func (r *CreateRequest) check() error {
	switch {
	case !r.Gesture.valid():
		return fmt.Errorf("%w: gesture %q", ErrRequest, r.Gesture)
	case r.Gesture == GestureGrab && r.PayeeSubject != "":
		return fmt.Errorf("%w: a drop has no payee until it is grabbed", ErrRequest)
	case r.Gesture != GestureGrab && !identity.ValidSubject(r.PayeeSubject):
		return fmt.Errorf("%w: payee subject %q", ErrRequest, r.PayeeSubject)
	case r.Gesture == GestureFlick && r.TLand.IsZero():
		return fmt.Errorf("%w: a flick needs its landing time", ErrRequest)
	case r.Gesture != GestureFlick && (!r.TLand.IsZero() || r.Trajectory != nil):
		return fmt.Errorf("%w: only flicks have a landing time and trajectory", ErrRequest)
	case r.OnTimeout != "" && r.OnTimeout != TimeoutAsync && r.OnTimeout != TimeoutVoid:
		return fmt.Errorf("%w: timeout %q", ErrRequest, r.OnTimeout)
	case r.SubmitterID == uuid.Nil:
		return fmt.Errorf("%w: no submitter", ErrRequest)
	}
	if r.Trajectory != nil {
		return r.Trajectory.validate()
	}
	return nil
}

// matches compares the request with the signed fields (PSD2 RTS Art. 5:
// the authentication code is specific to the amount and the payee).
func (r *CreateRequest) matches(t *txauth.TxAuth) error {
	var payee [32]byte
	if r.Gesture == GestureGrab {
		payee = txauth.DropPayeeRef(t.IntentID)
	} else {
		payee = identity.PayeeRef(r.PayeeSubject)
	}
	quote := ""
	if r.QuoteID != uuid.Nil {
		quote = r.QuoteID.String()
	}
	switch {
	case r.Amount != t.Amount:
		return fmt.Errorf("%w: amount", ErrMismatch)
	case r.Currency != t.Currency:
		return fmt.Errorf("%w: currency", ErrMismatch)
	case payee != t.PayeeRef:
		return fmt.Errorf("%w: payee", ErrMismatch)
	case quote != t.QuoteID:
		return fmt.Errorf("%w: quote", ErrMismatch)
	case r.Gesture.Kind() != t.Gesture:
		return fmt.Errorf("%w: gesture", ErrMismatch)
	case r.Gesture == GestureGrab && t.PARVersion != 0:
		return fmt.Errorf("%w: a drop pins no payee version", ErrMismatch)
	case r.Gesture != GestureGrab && t.PARVersion == 0:
		return fmt.Errorf("%w: the payee's directory version is not signed", ErrMismatch)
	}
	return nil
}

// Create accepts a signed intent. Authentication failures (a malformed or
// forged TxAuth, a bad nonce, a stale signature, fields that differ from
// the signed ones) return an error and store nothing. Once authenticated,
// a refusal by policy — limits, the payee, the quote, the ledger — is a
// durable ABORTED intent with its reason. Submitting the same bytes again
// returns the intent and finishes any pending step.
func (s *Service) Create(ctx context.Context, req CreateRequest) (*Intent, error) {
	if err := req.check(); err != nil {
		return nil, err
	}
	msg, err := txauth.Parse(req.TxAuth)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTxAuth, err)
	}
	ta := msg.TxAuth
	if in, err := s.db.get(ctx, s.pool, ta.IntentID); err == nil {
		return s.replay(ctx, in, req)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	key, err := s.keys.ActiveKey(ctx, msg.KeyID)
	if errors.Is(err, devicebind.ErrNotFound) || errors.Is(err, devicebind.ErrRevoked) {
		return nil, fmt.Errorf("%w: key %s is unknown or revoked", ErrTxAuth, msg.KeyID)
	}
	if err != nil {
		return nil, err
	}
	if key.Role != devicebind.RoleDevice && key.Role != devicebind.RoleGesture {
		return nil, fmt.Errorf("%w: a %s key cannot authorise payments", ErrTxAuth, key.Role)
	}
	pub, err := cose.ParseP256(key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("intents: stored key %s: %w", key.ID, err)
	}
	if err := msg.Verify(pub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTxAuth, err)
	}
	// Authentic from here on. Freshness: a TxAuth reaches the server within
	// MaxAge of signing, so a THROW relayed late cannot execute a payment
	// the payer's device already gave up on.
	now := s.now()
	switch {
	case ta.SignedAt.After(now.Add(s.cfg.ClockSkew)):
		return nil, fmt.Errorf("%w: signed at %s", ErrStale, ta.SignedAt)
	case now.Sub(ta.SignedAt) > s.cfg.MaxAge:
		return nil, fmt.Errorf("%w: signed at %s", ErrStale, ta.SignedAt)
	}
	if err := s.nonces.verify(ta.Nonce, key.DeviceID, ta.SignedAt, now); err != nil {
		return nil, err
	}
	if ta.IntentID.Version() != 7 || ta.IntentID.Variant() != uuid.RFC4122 {
		return nil, fmt.Errorf("%w: intent id is not a UUIDv7", ErrTxAuth)
	}
	if err := req.matches(ta); err != nil {
		return nil, err
	}
	if key.Role == devicebind.RoleGesture && req.Gesture.Kind() == txauth.GestureNone {
		return nil, fmt.Errorf("%w: K_gest authorises gestures only", ErrTxAuth)
	}
	if _, ok := money.Lookup(ta.Currency); !ok {
		return nil, fmt.Errorf("%w: unsupported currency %q", ErrRequest, ta.Currency)
	}
	in := &Intent{ID: ta.IntentID, PayerID: key.UserID, PayerDeviceID: key.DeviceID, SignerKeyID: key.ID,
		SignerRole: key.Role, PayeeSubject: req.PayeeSubject, PARVersion: ta.PARVersion, Gesture: req.Gesture,
		Amount: ta.Amount, Currency: ta.Currency, PayeeAmount: ta.Amount, PayeeCurrency: ta.Currency,
		QuoteID: req.QuoteID, State: StateCreated, SignedAt: ta.SignedAt, TxAuth: bytes.Clone(req.TxAuth),
		Trajectory: req.Trajectory, CreatedAt: now, UpdatedAt: now, nonce: ta.Nonce}
	switch req.Gesture {
	case GestureFlick:
		tl := req.TLand.UTC().Truncate(time.Millisecond)
		if tl.Before(ta.SignedAt.Add(-s.cfg.ClockSkew)) || tl.After(ta.SignedAt.Add(s.cfg.MaxFlight+s.cfg.ClockSkew)) {
			return nil, fmt.Errorf("%w: landing time %s does not follow the signing time %s", ErrRequest, tl, ta.SignedAt)
		}
		live := tl.Add(s.cfg.LiveTTL)
		in.TLand, in.LiveUntil = &tl, &live
	case GestureGrab:
		live := now.Add(s.cfg.DropTTL)
		in.LiveUntil = &live
	}
	relayed := req.SubmitterID != in.PayerID
	reason, err := s.resolve(ctx, in, ta, relayed, req.SubmitterID)
	if err != nil {
		return nil, err
	}
	if in.PayerSubject, err = s.dir.Subject(ctx, in.PayerID); err != nil {
		return nil, err
	}
	inserted := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		status, timeout, err := s.db.lockPayer(ctx, tx, in.PayerID)
		if err != nil {
			return err
		}
		_, device, err := devicebind.LockActiveKey(ctx, tx, key.ID)
		if errors.Is(err, devicebind.ErrRevoked) || errors.Is(err, devicebind.ErrNotFound) {
			return fmt.Errorf("%w: key %s was revoked", ErrTxAuth, key.ID)
		} else if err != nil {
			return err
		}
		in.OnTimeout = timeout
		if !relayed && req.OnTimeout != "" {
			in.OnTimeout = req.OnTimeout
		}
		in.HoldExpiresAt = s.holdExpiry(in)
		if reason == "" && status != "active" {
			reason = ReasonPayerInactive
		}
		if reason == "" && now.Sub(device.IntegrityAt) > s.cfg.IntegrityMaxAge {
			reason = ReasonIntegrityStale
		}
		if reason == "" {
			if reason, err = s.checkLimits(ctx, tx, in); err != nil {
				return err
			}
		}
		if reason != "" {
			in.State, in.Reason, in.ResolvedAt = StateAborted, reason, &now
		}
		if inserted, err = s.db.insert(ctx, tx, in); err != nil || !inserted {
			return err
		}
		if in.State == StateAborted {
			return emit(ctx, tx, TopicAborted, in)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !inserted {
		// The same intent arrived on the other path at the same moment.
		existing, err := s.db.get(ctx, s.pool, in.ID)
		if err != nil {
			return nil, err
		}
		return s.replay(ctx, existing, req)
	}
	s.m.moved(in)
	in.fresh = true
	return s.advance(ctx, in)
}

// replay answers a submission of an intent that exists already.
func (s *Service) replay(ctx context.Context, in *Intent, req CreateRequest) (*Intent, error) {
	if !bytes.Equal(in.TxAuth, req.TxAuth) {
		return nil, ErrConflict
	}
	if req.SubmitterID != in.PayerID && (in.PayeeID == uuid.Nil || req.SubmitterID != in.PayeeID) {
		return nil, ErrForbidden
	}
	return s.advance(ctx, in)
}

// resolve checks the payee and the quote. A policy refusal is returned as
// a reason; only infrastructure failures and forbidden relays are errors.
func (s *Service) resolve(ctx context.Context, in *Intent, ta *txauth.TxAuth, relayed bool, submitter uuid.UUID) (string, error) {
	var receives []string
	if in.Gesture == GestureGrab {
		if relayed {
			return "", fmt.Errorf("%w: a drop is submitted by its payer", ErrForbidden)
		}
	} else {
		p, err := s.dir.Payee(ctx, in.PayeeSubject)
		if errors.Is(err, identity.ErrNotFound) {
			if relayed {
				return "", fmt.Errorf("%w: only the payer or the payee submits an intent", ErrForbidden)
			}
			return ReasonPayeeUnknown, nil
		}
		if err != nil {
			return "", err
		}
		if relayed && submitter != p.UserID {
			return "", fmt.Errorf("%w: only the payer or the payee submits an intent", ErrForbidden)
		}
		in.PayeeID = p.UserID
		switch {
		case p.UserID == in.PayerID:
			return ReasonSelfPayment, nil
		case p.Status == "closed":
			return ReasonPayeeUnavailable, nil
		case p.Entry.Version != ta.PARVersion:
			return ReasonPayeeChanged, nil
		}
		receives = p.Entry.Currencies
	}
	if in.QuoteID != uuid.Nil {
		if reason, err := s.quote(ctx, in); reason != "" || err != nil {
			return reason, err
		}
	}
	if len(receives) > 0 && !slices.Contains(receives, in.PayeeCurrency) {
		return ReasonPayeeCurrency, nil
	}
	return "", nil
}

// quote checks that the intent's FX quote is the payer's, converts exactly
// the intent's amount from its currency, is open, and outlives the catch
// window; it records what the payee will receive.
func (s *Service) quote(ctx context.Context, in *Intent) (string, error) {
	if s.fx == nil || in.Gesture == GestureGrab {
		return ReasonQuoteInvalid, nil
	}
	q, _, err := s.fx.GetQuote(ctx, in.PayerID, in.QuoteID)
	if errors.Is(err, fx.ErrUnknownQuote) {
		return ReasonQuoteInvalid, nil
	}
	if err != nil {
		return "", fmt.Errorf("%w: quote: %v", ErrUnavailable, err)
	}
	deadline := in.CreatedAt
	if in.LiveUntil != nil {
		deadline = *in.LiveUntil
	}
	if q.From != in.Currency || q.AmountIn != in.Amount || q.State != fx.StateOpen || !q.ExpiresAt.After(deadline) ||
		q.To == q.From || q.AmountOut <= 0 {
		return ReasonQuoteInvalid, nil
	}
	in.PayeeAmount, in.PayeeCurrency, in.quoteSignature = q.AmountOut, q.To, q.Signature
	return "", nil
}

// holdExpiry keeps the hold for as long as the intent can still settle,
// plus HoldMargin: through the claim window for a throw that may wait for
// a claim, through the catch window for other live intents, and briefly
// for intents that settle on acceptance.
func (s *Service) holdExpiry(in *Intent) time.Time {
	end := in.CreatedAt
	if in.LiveUntil != nil && in.LiveUntil.After(end) {
		end = *in.LiveUntil
	}
	if s.mayWait(in) {
		end = end.Add(s.cfg.ClaimTTL)
	}
	return end.Add(s.cfg.HoldMargin)
}

// mayWait reports whether an uncaught intent becomes a claim rather than
// returning: only same-currency flicks whose payer prefers it (a rate lock
// cannot last the claim window, and a drop has nobody to claim it).
func (s *Service) mayWait(in *Intent) bool {
	return in.Gesture == GestureFlick && in.QuoteID == uuid.Nil && in.OnTimeout == TimeoutAsync
}

// checkLimits applies the K_gest scope, velocity and the payer's caps in
// the creation transaction, under the payer and device locks.
func (s *Service) checkLimits(ctx context.Context, tx pgx.Tx, in *Intent) (string, error) {
	lim := s.cfg.limits(in.Currency)
	if in.SignerRole == devicebind.RoleGesture {
		if in.Amount > lim.Gesture {
			return ReasonGestureLimit, nil
		}
		n, sum, err := s.db.gestureUse(ctx, tx, in.PayerDeviceID, in.Currency, in.CreatedAt.Add(-s.cfg.GestureWindow))
		if err != nil {
			return "", err
		}
		if n+1 > s.cfg.GestureCount || !addWithin(lim.GestureWindow, sum, in.Amount) {
			return ReasonVelocity, nil
		}
	}
	if lim.PerIntent > 0 && in.Amount > lim.PerIntent {
		return ReasonAmountLimit, nil
	}
	if lim.Daily > 0 {
		sum, err := s.db.outflow(ctx, tx, in.PayerID, in.Currency, in.CreatedAt.Add(-24*time.Hour))
		if err != nil {
			return "", err
		}
		if !addWithin(lim.Daily, sum, in.Amount) {
			return ReasonDailyLimit, nil
		}
	}
	return "", nil
}

// Get returns an intent its payer or payee can see.
func (s *Service) Get(ctx context.Context, userID, id uuid.UUID) (*Intent, error) {
	in, err := s.db.get(ctx, s.pool, id)
	if err != nil {
		return nil, err
	}
	if in.PayerID != userID && in.PayeeID != userID {
		return nil, ErrNotFound
	}
	return in, nil
}

// List returns a page of the user's intents, newest first.
func (s *Service) List(ctx context.Context, q ListQuery) ([]*Intent, error) {
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 200 || q.UserID == uuid.Nil {
		return nil, fmt.Errorf("%w: a user and a limit of 1..200", ErrRequest)
	}
	if q.Role != RoleAny && q.Role != RolePayer && q.Role != RolePayee {
		return nil, fmt.Errorf("%w: role %q", ErrRequest, q.Role)
	}
	for _, st := range q.States {
		if !st.valid() {
			return nil, fmt.Errorf("%w: state %q", ErrRequest, st)
		}
	}
	return s.db.list(ctx, q)
}
