package ledger

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/money"
)

// Limits shared by every engine.
const (
	MaxPostings   = 64
	MaxHoldTTL    = 31 * 24 * time.Hour
	MinHoldTTL    = time.Second
	MaxMemoLen    = 512
	MaxNoteLen    = 256
	MaxLabelLen   = 128
	MaxRefIDLen   = 128
	MaxIdemKeyLen = 255
	MaxStripes    = 64
	// Entry kinds only the engine itself may write.
	EntryKindReversal       = "reversal"
	EntryKindHoldPost       = "hold.post"
	EntryKindReserveOpen    = "reserve.open"
	EntryKindReserveRelease = "reserve.release"
)

// Idempotency scopes: a key belongs to exactly one operation type.
const (
	ScopeCreateAccount  = "account.create"
	ScopeSetFrozen      = "account.freeze"
	ScopeTransfer       = "transfer"
	ScopePlaceHold      = "hold.place"
	ScopePostHold       = "hold.post"
	ScopeVoidHold       = "hold.void"
	ScopeReverse        = "entry.reverse"
	ScopeOpenReserve    = "reserve.open"
	ScopeReleaseReserve = "reserve.release"
)

var (
	kindPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.]{1,63}$`)
	reasonPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
	refTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// Kinds only the engine itself may write.
	reservedKinds = map[string]bool{EntryKindReversal: true, EntryKindHoldPost: true,
		EntryKindReserveOpen: true, EntryKindReserveRelease: true}
)

// customerFundKinds hold customer money and can never go negative.
var customerFundKinds = map[AccountKind]bool{
	KindUser: true, KindMerchant: true, KindOfflineReserve: true,
	KindLinkEscrow: true, KindIntentHold: true, KindTipSession: true,
}

// reserveKinds are the escrow account kinds a reserve may use.
var reserveKinds = map[AccountKind]bool{
	KindOfflineReserve: true, KindLinkEscrow: true, KindTipSession: true, KindIntentHold: true,
}

// HoldsCustomerFunds reports whether accounts of this kind must keep a zero floor.
func (k AccountKind) HoldsCustomerFunds() bool { return customerFundKinds[k] }

func checkKey(key string) error {
	if key == "" || len(key) > MaxIdemKeyLen {
		return invalid("idempotency_key", fmt.Sprintf("must be 1..%d bytes", MaxIdemKeyLen))
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return invalid("idempotency_key", "must be printable ASCII without spaces")
		}
	}
	return nil
}

func checkRef(refType, refID string) error {
	if (refType == "") != (refID == "") {
		return invalid("ref", "ref_type and ref_id must be set together")
	}
	if refType != "" && !refTypePattern.MatchString(refType) {
		return invalid("ref_type", "must match ^[a-z][a-z0-9_]{0,31}$")
	}
	if refID != "" && (!utf8.ValidString(refID) || utf8.RuneCountInString(refID) > MaxRefIDLen) {
		return invalid("ref_id", fmt.Sprintf("must be valid UTF-8, at most %d characters", MaxRefIDLen))
	}
	return nil
}

func checkText(field, s string, max int) error {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return invalid(field, fmt.Sprintf("must be valid UTF-8, at most %d characters", max))
	}
	return nil
}

func checkEntryKind(kind string) error {
	if !kindPattern.MatchString(kind) {
		return invalid("kind", "must match ^[a-z][a-z0-9_.]{1,63}$")
	}
	if reservedKinds[kind] {
		return invalid("kind", fmt.Sprintf("%q is reserved for the ledger engine", kind))
	}
	return nil
}

// checkLegs validates postings: distinct non-nil accounts, non-zero amounts,
// no int64 overflow in their sum. positive restricts amounts to > 0.
func checkLegs(field string, legs []Posting, min, max int, positive bool) error {
	if len(legs) < min || len(legs) > max {
		return invalid(field, fmt.Sprintf("must have %d..%d postings", min, max))
	}
	seen := make(map[uuid.UUID]bool, len(legs))
	var sum int64
	for i, p := range legs {
		if p.AccountID == uuid.Nil {
			return invalid(fmt.Sprintf("%s[%d].account_id", field, i), "is required")
		}
		if seen[p.AccountID] {
			return invalid(fmt.Sprintf("%s[%d].account_id", field, i), "appears twice; combine the legs")
		}
		seen[p.AccountID] = true
		if p.Amount == 0 || (positive && p.Amount < 0) {
			return invalid(fmt.Sprintf("%s[%d].amount", field, i), "must be non-zero (positive for credits)")
		}
		var err error
		if sum, err = money.Add(sum, p.Amount); err != nil {
			return invalid(field, "amounts overflow int64")
		}
	}
	return nil
}

// RequestHash is the canonical hash used to detect idempotency-key reuse
// with a different payload: SHA-256(scope 0x00 canonical-JSON(command)).
// Commands exclude their idempotency key from JSON and normalise times to UTC.
func RequestHash(scope string, normalisedCmd any) [32]byte {
	body, err := json.Marshal(normalisedCmd)
	if err != nil {
		panic(fmt.Sprintf("ledger: command not serialisable: %v", err))
	}
	h := sha256.New()
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func utc(t time.Time) time.Time { return t.UTC().Round(time.Microsecond) }

// CreateAccount opens a new account.
type CreateAccount struct {
	IdempotencyKey string      `json:"-"`
	AccountID      uuid.UUID   `json:"account_id"` // optional; generated when zero
	OwnerID        *uuid.UUID  `json:"owner_id,omitempty"`
	Kind           AccountKind `json:"kind"`
	Currency       string      `json:"currency"`
	Floor          *int64      `json:"floor,omitempty"` // nil = unbounded; customer kinds are forced to 0
	Stripes        int         `json:"stripes"`         // 0 means 1
	Label          string      `json:"label,omitempty"`
}

// Normalize validates the command and fills defaults.
func (c CreateAccount) Normalize() (CreateAccount, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if !c.Kind.Valid() {
		return c, invalid("kind", fmt.Sprintf("unknown account kind %q", c.Kind))
	}
	if _, ok := money.Lookup(c.Currency); !ok {
		return c, invalid("currency", fmt.Sprintf("unsupported currency %q", c.Currency))
	}
	if c.Stripes == 0 {
		c.Stripes = 1
	}
	if c.Stripes < 1 || c.Stripes > MaxStripes {
		return c, invalid("stripes", fmt.Sprintf("must be 1..%d", MaxStripes))
	}
	if c.Kind.HoldsCustomerFunds() {
		if c.Floor != nil && *c.Floor != 0 {
			return c, invalid("floor", fmt.Sprintf("%s accounts hold customer funds and must have floor 0", c.Kind))
		}
		zero := int64(0)
		c.Floor = &zero
	}
	if c.Floor != nil && *c.Floor > 0 {
		return c, invalid("floor", "must be <= 0")
	}
	if c.Stripes > 1 && c.Floor != nil {
		return c, invalid("stripes", "striped accounts must be unbounded (floor nil)")
	}
	if err := checkText("label", c.Label, MaxLabelLen); err != nil {
		return c, err
	}
	if c.OwnerID != nil && *c.OwnerID == uuid.Nil {
		c.OwnerID = nil
	}
	return c, nil
}

// SetFrozen freezes or unfreezes an account. A frozen account rejects debits
// and new holds; credits and reversals still apply.
type SetFrozen struct {
	IdempotencyKey string    `json:"-"`
	AccountID      uuid.UUID `json:"account_id"`
	Frozen         bool      `json:"frozen"`
	Reason         string    `json:"reason"`
}

// Normalize validates the command.
func (c SetFrozen) Normalize() (SetFrozen, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if c.AccountID == uuid.Nil {
		return c, invalid("account_id", "is required")
	}
	if c.Reason == "" {
		return c, invalid("reason", "is required")
	}
	return c, checkText("reason", c.Reason, MaxNoteLen)
}

// Transfer posts a balanced multi-leg entry.
type Transfer struct {
	IdempotencyKey string    `json:"-"`
	Kind           string    `json:"kind"`
	RefType        string    `json:"ref_type,omitempty"`
	RefID          string    `json:"ref_id,omitempty"`
	Memo           string    `json:"memo,omitempty"`
	Postings       []Posting `json:"postings"`
}

// Normalize validates the command. Per-currency balance is checked by the
// engine once account currencies are known.
func (c Transfer) Normalize() (Transfer, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if err := checkEntryKind(c.Kind); err != nil {
		return c, err
	}
	if err := checkRef(c.RefType, c.RefID); err != nil {
		return c, err
	}
	if err := checkText("memo", c.Memo, MaxMemoLen); err != nil {
		return c, err
	}
	return c, checkLegs("postings", c.Postings, 2, MaxPostings, false)
}

// PlaceHold reserves Amount on an account until ExpiresAt.
type PlaceHold struct {
	IdempotencyKey string    `json:"-"`
	AccountID      uuid.UUID `json:"account_id"`
	Amount         int64     `json:"amount"`
	Reason         string    `json:"reason"`
	ExpiresAt      time.Time `json:"expires_at"`
	RefType        string    `json:"ref_type,omitempty"`
	RefID          string    `json:"ref_id,omitempty"`
}

// Normalize validates the command. The engine checks ExpiresAt against its
// own clock (MinHoldTTL..MaxHoldTTL from now).
func (c PlaceHold) Normalize() (PlaceHold, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if c.AccountID == uuid.Nil {
		return c, invalid("account_id", "is required")
	}
	if c.Amount <= 0 {
		return c, invalid("amount", "must be positive")
	}
	if !reasonPattern.MatchString(c.Reason) {
		return c, invalid("reason", "must match ^[a-z][a-z0-9_]{1,63}$")
	}
	if c.ExpiresAt.IsZero() {
		return c, invalid("expires_at", "is required")
	}
	c.ExpiresAt = utc(c.ExpiresAt)
	return c, checkRef(c.RefType, c.RefID)
}

// PostHold settles a pending hold: Credits (positive amounts) go to the
// listed accounts, their sum is debited from the held account, and any
// remainder of the hold is released.
type PostHold struct {
	IdempotencyKey string    `json:"-"`
	HoldID         uuid.UUID `json:"hold_id"`
	Kind           string    `json:"kind"`
	Memo           string    `json:"memo,omitempty"`
	Credits        []Posting `json:"credits"`
}

// Normalize validates the command.
func (c PostHold) Normalize() (PostHold, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if c.HoldID == uuid.Nil {
		return c, invalid("hold_id", "is required")
	}
	if c.Kind == "" {
		c.Kind = EntryKindHoldPost
	} else if err := checkEntryKind(c.Kind); err != nil {
		return c, err
	}
	if err := checkText("memo", c.Memo, MaxMemoLen); err != nil {
		return c, err
	}
	return c, checkLegs("credits", c.Credits, 1, MaxPostings-1, true)
}

// VoidHold releases a pending hold without moving money.
type VoidHold struct {
	IdempotencyKey string    `json:"-"`
	HoldID         uuid.UUID `json:"hold_id"`
	Reason         string    `json:"reason,omitempty"`
}

// Normalize validates the command.
func (c VoidHold) Normalize() (VoidHold, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if c.HoldID == uuid.Nil {
		return c, invalid("hold_id", "is required")
	}
	return c, checkText("reason", c.Reason, MaxNoteLen)
}

// Reverse posts the exact inverse of an entry. An entry can be reversed
// once; reversals themselves cannot be reversed.
type Reverse struct {
	IdempotencyKey string    `json:"-"`
	EntryID        uuid.UUID `json:"entry_id"`
	Memo           string    `json:"memo,omitempty"`
}

// Normalize validates the command.
func (c Reverse) Normalize() (Reverse, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if c.EntryID == uuid.Nil {
		return c, invalid("entry_id", "is required")
	}
	return c, checkText("memo", c.Memo, MaxMemoLen)
}

// OpenReserve moves Amount from FundingAccountID into a new reserve account.
type OpenReserve struct {
	IdempotencyKey   string      `json:"-"`
	ReserveID        uuid.UUID   `json:"reserve_id"` // optional; generated when zero
	Kind             AccountKind `json:"kind"`       // escrow kind; default offline_reserve
	FundingAccountID uuid.UUID   `json:"funding_account_id"`
	Amount           int64       `json:"amount"`
	Purpose          string      `json:"purpose"`
	RefType          string      `json:"ref_type,omitempty"`
	RefID            string      `json:"ref_id,omitempty"`
	ExpiresAt        *time.Time  `json:"expires_at,omitempty"`
	Memo             string      `json:"memo,omitempty"`
}

// Normalize validates the command.
func (c OpenReserve) Normalize() (OpenReserve, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if c.FundingAccountID == uuid.Nil {
		return c, invalid("funding_account_id", "is required")
	}
	if c.Kind == "" {
		c.Kind = KindOfflineReserve
	}
	if !reserveKinds[c.Kind] {
		return c, invalid("kind", "reserves must be offline_reserve, link_escrow, tip_session or intent_hold accounts")
	}
	if c.ReserveID != uuid.Nil && c.ReserveID == c.FundingAccountID {
		return c, invalid("reserve_id", "must differ from the funding account")
	}
	if c.Amount <= 0 {
		return c, invalid("amount", "must be positive")
	}
	if !reasonPattern.MatchString(c.Purpose) {
		return c, invalid("purpose", "must match ^[a-z][a-z0-9_]{1,63}$")
	}
	if c.ExpiresAt != nil {
		t := utc(*c.ExpiresAt)
		c.ExpiresAt = &t
	}
	if err := checkText("memo", c.Memo, MaxMemoLen); err != nil {
		return c, err
	}
	return c, checkRef(c.RefType, c.RefID)
}

// ReleaseReserve returns a reserve's remaining balance to its funding
// account and closes it.
type ReleaseReserve struct {
	IdempotencyKey string    `json:"-"`
	ReserveID      uuid.UUID `json:"reserve_id"`
	Memo           string    `json:"memo,omitempty"`
}

// Normalize validates the command.
func (c ReleaseReserve) Normalize() (ReleaseReserve, error) {
	if err := checkKey(c.IdempotencyKey); err != nil {
		return c, err
	}
	if c.ReserveID == uuid.Nil {
		return c, invalid("reserve_id", "is required")
	}
	return c, checkText("memo", c.Memo, MaxMemoLen)
}

// HistoryQuery selects a page of an account's entries, newest first.
type HistoryQuery struct {
	AccountID uuid.UUID
	Before    *uuid.UUID // cursor: entries strictly older than this entry
	Limit     int        // 1..500, default 50
}

// Normalize validates the query.
func (q HistoryQuery) Normalize() (HistoryQuery, error) {
	if q.AccountID == uuid.Nil {
		return q, invalid("account_id", "is required")
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 500 {
		return q, invalid("limit", "must be 1..500")
	}
	return q, nil
}
