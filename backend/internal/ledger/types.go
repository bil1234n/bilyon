// Package ledger defines Bilyon's double-entry ledger: the domain model, the
// commands it accepts, their validation, and the Ledger interface that the
// PostgreSQL (pgledger) and TigerBeetle (tbledger) engines implement
// (RFC 0001 §2.3).
//
// Conventions:
//   - Amounts are int64 minor units of the account's currency.
//   - A posting is a signed balance delta: positive grows the balance.
//     Every entry's postings sum to zero per currency.
//   - Every mutating command carries an idempotency key. Replaying a command
//     with the same key and payload returns the original result; the same
//     key with a different payload is ErrIdempotencyConflict.
package ledger

import (
	"crypto/rand"
	"time"

	"github.com/google/uuid"
)

// AccountKind classifies accounts (RFC 0001 §2.3.2).
type AccountKind string

// Account kinds.
const (
	KindUser             AccountKind = "user"
	KindMerchant         AccountKind = "merchant"
	KindOfflineReserve   AccountKind = "offline_reserve"
	KindOfflineGuarantee AccountKind = "offline_guarantee"
	KindFXBook           AccountKind = "fx_book"
	KindNostro           AccountKind = "nostro"
	KindFee              AccountKind = "fee"
	KindLinkEscrow       AccountKind = "link_escrow"
	KindIntentHold       AccountKind = "intent_hold"
	KindReceivable       AccountKind = "receivable"
	KindClearing         AccountKind = "clearing"
	KindSuspense         AccountKind = "suspense"
	KindTipSession       AccountKind = "tip_session"
	KindSystem           AccountKind = "system"
)

// AccountKinds lists every kind in a stable order. The index (+1) is the
// kind's numeric code where an engine needs one (TigerBeetle's account code).
var AccountKinds = []AccountKind{
	KindUser, KindMerchant, KindOfflineReserve, KindOfflineGuarantee, KindFXBook, KindNostro, KindFee,
	KindLinkEscrow, KindIntentHold, KindReceivable, KindClearing, KindSuspense, KindTipSession, KindSystem,
}

// Valid reports whether k is a known kind.
func (k AccountKind) Valid() bool {
	for _, known := range AccountKinds {
		if k == known {
			return true
		}
	}
	return false
}

// Code returns the kind's stable numeric code (1-based), or 0 if unknown.
func (k AccountKind) Code() uint16 {
	for i, known := range AccountKinds {
		if k == known {
			return uint16(i + 1)
		}
	}
	return 0
}

// KindFromCode is the inverse of Code.
func KindFromCode(code uint16) (AccountKind, bool) {
	if code == 0 || int(code) > len(AccountKinds) {
		return "", false
	}
	return AccountKinds[code-1], true
}

// HoldState is the lifecycle state of a hold.
type HoldState string

// Hold states.
const (
	HoldPending HoldState = "pending"
	HoldPosted  HoldState = "posted"
	HoldVoided  HoldState = "voided"
	HoldExpired HoldState = "expired"
)

// ReserveState is the lifecycle state of a reserve.
type ReserveState string

// Reserve states.
const (
	ReserveOpen   ReserveState = "open"
	ReserveClosed ReserveState = "closed"
)

// Account is a ledger account in a single currency.
type Account struct {
	ID       uuid.UUID   `json:"id"`
	OwnerID  *uuid.UUID  `json:"owner_id,omitempty"`
	Kind     AccountKind `json:"kind"`
	Currency string      `json:"currency"`
	// Floor is the lowest allowed available balance (posted - pending).
	// Nil means unbounded (platform books monitored by treasury).
	Floor     *int64    `json:"floor,omitempty"`
	Stripes   int       `json:"stripes"`
	Frozen    bool      `json:"frozen"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Balance is an account's balance at one instant.
type Balance struct {
	AccountID uuid.UUID `json:"account_id"`
	Currency  string    `json:"currency"`
	Posted    int64     `json:"posted"`
	Pending   int64     `json:"pending"`
	Available int64     `json:"available"`
	Floor     *int64    `json:"floor,omitempty"`
	Frozen    bool      `json:"frozen"`
}

// Posting is one leg of a command: a signed delta on one account.
type Posting struct {
	AccountID uuid.UUID `json:"account_id"`
	Amount    int64     `json:"amount"`
}

// PostingRecord is a committed leg of an entry.
type PostingRecord struct {
	Seq       int       `json:"seq"`
	AccountID uuid.UUID `json:"account_id"`
	Stripe    int       `json:"stripe"`
	Currency  string    `json:"currency"`
	Amount    int64     `json:"amount"`
}

// Entry is a committed, balanced journal entry.
type Entry struct {
	ID             uuid.UUID       `json:"id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Kind           string          `json:"kind"`
	RefType        string          `json:"ref_type,omitempty"`
	RefID          string          `json:"ref_id,omitempty"`
	Memo           string          `json:"memo,omitempty"`
	Reverses       *uuid.UUID      `json:"reverses,omitempty"`
	HoldID         *uuid.UUID      `json:"hold_id,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	Postings       []PostingRecord `json:"postings"`
}

// Hold reserves funds on one account until it is posted, voided or expires.
type Hold struct {
	ID             uuid.UUID  `json:"id"`
	IdempotencyKey string     `json:"idempotency_key"`
	AccountID      uuid.UUID  `json:"account_id"`
	Currency       string     `json:"currency"`
	Amount         int64      `json:"amount"`
	Reason         string     `json:"reason"`
	State          HoldState  `json:"state"`
	ExpiresAt      time.Time  `json:"expires_at"`
	PostedAmount   int64      `json:"posted_amount"`
	EntryID        *uuid.UUID `json:"entry_id,omitempty"`
	RefType        string     `json:"ref_type,omitempty"`
	RefID          string     `json:"ref_id,omitempty"`
	ResolutionNote string     `json:"resolution_note,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}

// Reserve is escrowed value held in its own account (offline allowances,
// payment links), released back to the funding account when closed.
type Reserve struct {
	ID               uuid.UUID    `json:"id"`
	FundingAccountID uuid.UUID    `json:"funding_account_id"`
	Currency         string       `json:"currency"`
	Purpose          string       `json:"purpose"`
	RefType          string       `json:"ref_type,omitempty"`
	RefID            string       `json:"ref_id,omitempty"`
	State            ReserveState `json:"state"`
	OpenedEntryID    uuid.UUID    `json:"opened_entry_id"`
	ClosedEntryID    *uuid.UUID   `json:"closed_entry_id,omitempty"`
	ExpiresAt        *time.Time   `json:"expires_at,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
	ClosedAt         *time.Time   `json:"closed_at,omitempty"`
}

// PostHoldResult is the result of posting a hold.
type PostHoldResult struct {
	Hold  Hold  `json:"hold"`
	Entry Entry `json:"entry"`
}

// OpenReserveResult is the result of opening a reserve.
type OpenReserveResult struct {
	Reserve Reserve `json:"reserve"`
	Entry   Entry   `json:"entry"`
}

// ReleaseReserveResult is the result of releasing a reserve. Entry is nil
// when the reserve was already empty.
type ReleaseReserveResult struct {
	Reserve Reserve `json:"reserve"`
	Entry   *Entry  `json:"entry,omitempty"`
}

// HistoryPage is one page of an account's entries, newest first.
type HistoryPage struct {
	Entries []Entry `json:"entries"`
	// Next is the cursor for the following page; nil at the end.
	Next *uuid.UUID `json:"next,omitempty"`
}

// NewID returns a time-ordered UUIDv7 (RFC 9562).
func NewID() uuid.UUID {
	id, err := uuid.NewV7FromReader(rand.Reader)
	if err != nil {
		// crypto/rand failing means the OS entropy source is broken;
		// no ledger operation can be performed safely.
		panic("ledger: crypto/rand failure: " + err.Error())
	}
	return id
}
