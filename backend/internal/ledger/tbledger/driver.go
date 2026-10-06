package tbledger

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	tb "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// DefaultHoldGrace is how long TigerBeetle keeps a hold pending beyond its
// PostgreSQL expiry (see holdPlan).
const DefaultHoldGrace = 24 * time.Hour

// Driver executes ledger operations against a TigerBeetle cluster. It is
// safe for concurrent use (the client multiplexes requests), but the shadow
// relies on being the cluster's only writer.
type Driver struct {
	client tb.Client
	grace  time.Duration
	now    func() time.Time

	mu        sync.Mutex
	systems   map[string]bool // currencies whose control accounts exist
	closeOnce sync.Once
}

// Option configures a Driver.
type Option func(*Driver)

// WithHoldGrace overrides DefaultHoldGrace.
func WithHoldGrace(d time.Duration) Option { return func(dr *Driver) { dr.grace = d } }

// WithClock overrides the clock used for hold timeouts.
func WithClock(now func() time.Time) Option { return func(dr *Driver) { dr.now = now } }

// Open connects to a cluster. addresses are "host:port" replica addresses.
func Open(clusterID uint64, addresses []string, opts ...Option) (*Driver, error) {
	if len(addresses) == 0 {
		return nil, errors.New("tbledger: no TigerBeetle addresses")
	}
	client, err := tb.NewClient(tb.ToUint128(clusterID), addresses)
	if err != nil {
		return nil, fmt.Errorf("tbledger: connect: %w", err)
	}
	d := &Driver{client: client, grace: DefaultHoldGrace, now: time.Now, systems: map[string]bool{}}
	for _, o := range opts {
		o(d)
	}
	return d, nil
}

// Close releases the client. Requests blocked on an unreachable cluster fail
// with an error; Close may be called more than once.
func (d *Driver) Close() { d.closeOnce.Do(d.client.Close) }

// Ping round-trips a no-op request.
func (d *Driver) Ping() error {
	if err := d.client.Nop(); err != nil {
		return fmt.Errorf("%w: %v", ledger.ErrUnavailable, err)
	}
	return nil
}

// accountError maps a create_accounts status. "exists" is success: replays
// are idempotent.
func accountError(s tb.CreateAccountStatus) error {
	switch s {
	case tb.AccountCreated, tb.AccountExists:
		return nil
	case tb.AccountExistsWithDifferentFlags, tb.AccountExistsWithDifferentUserData128,
		tb.AccountExistsWithDifferentUserData64, tb.AccountExistsWithDifferentUserData32,
		tb.AccountExistsWithDifferentLedger, tb.AccountExistsWithDifferentCode:
		return fmt.Errorf("%w: account exists with different fields (%s)", ledger.ErrIdempotencyConflict, s)
	default:
		return fmt.Errorf("tbledger: create account: %s", s)
	}
}

// transferError maps a create_transfers status to ledger errors. Created and
// exists are success; linked_event_failed is resolved by submit.
func transferError(s tb.CreateTransferStatus) error {
	switch s {
	case tb.TransferCreated, tb.TransferExists:
		return nil
	case tb.TransferExceedsCredits, tb.TransferExceedsDebits:
		return fmt.Errorf("%w (%s)", ledger.ErrInsufficientFunds, s)
	case tb.TransferDebitAccountNotFound, tb.TransferCreditAccountNotFound, tb.TransferPendingTransferNotFound:
		return fmt.Errorf("%w (%s)", ledger.ErrNotFound, s)
	case tb.TransferAccountsMustHaveTheSameLedger, tb.TransferTransferMustHaveTheSameLedgerAsAccounts,
		tb.TransferPendingTransferHasDifferentLedger:
		return fmt.Errorf("%w (%s)", ledger.ErrCurrencyMismatch, s)
	case tb.TransferPendingTransferAlreadyPosted, tb.TransferPendingTransferAlreadyVoided, tb.TransferPendingTransferNotPending:
		return fmt.Errorf("%w (%s)", ledger.ErrHoldNotPending, s)
	case tb.TransferPendingTransferExpired:
		return fmt.Errorf("%w (%s)", ledger.ErrHoldExpired, s)
	case tb.TransferOverflowsDebitsPending, tb.TransferOverflowsCreditsPending, tb.TransferOverflowsDebitsPosted,
		tb.TransferOverflowsCreditsPosted, tb.TransferOverflowsDebits, tb.TransferOverflowsCredits, tb.TransferOverflowsTimeout:
		return fmt.Errorf("%w (%s)", ledger.ErrOverflow, s)
	case tb.TransferExistsWithDifferentFlags, tb.TransferExistsWithDifferentPendingID, tb.TransferExistsWithDifferentTimeout,
		tb.TransferExistsWithDifferentDebitAccountID, tb.TransferExistsWithDifferentCreditAccountID,
		tb.TransferExistsWithDifferentAmount, tb.TransferExistsWithDifferentUserData128,
		tb.TransferExistsWithDifferentUserData64, tb.TransferExistsWithDifferentUserData32,
		tb.TransferExistsWithDifferentLedger, tb.TransferExistsWithDifferentCode:
		return fmt.Errorf("%w (%s)", ledger.ErrIdempotencyConflict, s)
	case tb.TransferIDAlreadyFailed:
		// A previous attempt with this id failed transiently; TigerBeetle
		// will never accept the id again.
		return fmt.Errorf("%w: transfer id burned by an earlier failed attempt (%s)", ledger.ErrIdempotencyConflict, s)
	case tb.TransferExceedsPendingTransferAmount, tb.TransferPendingTransferHasDifferentAmount:
		return fmt.Errorf("%w (%s)", ledger.ErrInvalid, s)
	default:
		return fmt.Errorf("tbledger: create transfer: %s", s)
	}
}

// chainOutcome classifies the results of one submitted chain.
type chainOutcome int

const (
	chainCreated    chainOutcome = iota // every transfer created now
	chainReplayed                       // the chain had been created before
	chainIndefinite                     // some transfer exists: verify the whole chain
)

// classify interprets create_transfers results for one linked chain (or a
// single transfer). TigerBeetle treats "exists" like any other failure inside
// a chain: it reports exists for that transfer and linked_event_failed for
// the rest, so a replayed chain never comes back as all-exists.
func classify(results []tb.CreateTransferResult) (chainOutcome, error) {
	var exists, linkedFailed bool
	for i, r := range results {
		switch r.Status {
		case tb.TransferCreated:
		case tb.TransferExists:
			exists = true
		case tb.TransferLinkedEventFailed:
			linkedFailed = true
		default:
			return 0, fmt.Errorf("transfer %d of %d: %w", i+1, len(results), transferError(r.Status))
		}
	}
	switch {
	case exists && linkedFailed:
		return chainIndefinite, nil
	case exists:
		return chainReplayed, nil
	case linkedFailed:
		return 0, errors.New("tbledger: linked chain failed without a root cause")
	default:
		return chainCreated, nil
	}
}

func (d *Driver) createAccounts(accts []tb.Account) error {
	if len(accts) == 0 {
		return nil
	}
	results, err := d.client.CreateAccounts(accts)
	if err != nil {
		return fmt.Errorf("%w: %v", ledger.ErrUnavailable, err)
	}
	if len(results) != len(accts) {
		return fmt.Errorf("tbledger: %d results for %d accounts", len(results), len(accts))
	}
	for _, r := range results {
		if err := accountError(r.Status); err != nil {
			return err
		}
	}
	return nil
}

// submit creates one linked chain (or a single transfer). A chain that
// already exists counts as success once every transfer is confirmed present.
func (d *Driver) submit(ts []tb.Transfer) error {
	if len(ts) == 0 {
		return nil
	}
	if len(ts) > maxBatch {
		return fmt.Errorf("%w: chain of %d transfers exceeds one request", ledger.ErrInvalid, len(ts))
	}
	results, err := d.client.CreateTransfers(ts)
	if err != nil {
		return fmt.Errorf("%w: %v", ledger.ErrUnavailable, err)
	}
	if len(results) != len(ts) {
		return fmt.Errorf("tbledger: %d results for %d transfers", len(results), len(ts))
	}
	outcome, err := classify(results)
	if err != nil || outcome != chainIndefinite {
		return err
	}
	ids := make([]tb.Uint128, len(ts))
	for i, t := range ts {
		ids[i] = t.ID
	}
	found, err := d.lookupTransfers(ids)
	if err != nil {
		return err
	}
	if len(found) != len(ts) {
		return fmt.Errorf("%w: chain only partly exists (%d of %d transfers)", ledger.ErrIdempotencyConflict, len(found), len(ts))
	}
	return nil
}

// ensureSystem creates a currency's control accounts once per process.
func (d *Driver) ensureSystem(currency string) error {
	d.mu.Lock()
	done := d.systems[currency]
	d.mu.Unlock()
	if done {
		return nil
	}
	accts, err := systemAccounts(currency)
	if err != nil {
		return err
	}
	if err := d.createAccounts(accts); err != nil {
		return err
	}
	d.mu.Lock()
	d.systems[currency] = true
	d.mu.Unlock()
	return nil
}

// submitIndependent creates unlinked transfers in request-sized batches.
func (d *Driver) submitIndependent(ts []tb.Transfer) error {
	for start := 0; start < len(ts); start += maxBatch {
		if err := d.submit(ts[start:min(start+maxBatch, len(ts))]); err != nil {
			return err
		}
	}
	return nil
}

// CreateAccount mirrors a ledger account (idempotent).
func (d *Driver) CreateAccount(a ledger.Account) error {
	return d.CreateAccounts([]ledger.Account{a})
}

// CreateAccounts mirrors ledger accounts in request-sized batches
// (idempotent). Limit pre-funding follows each batch of accounts.
func (d *Driver) CreateAccounts(as []ledger.Account) error {
	for start := 0; start < len(as); start += maxBatch {
		batch := as[start:min(start+maxBatch, len(as))]
		accts := make([]tb.Account, 0, len(batch))
		var funding []tb.Transfer
		for _, a := range batch {
			if err := d.ensureSystem(a.Currency); err != nil {
				return err
			}
			acct, f, err := accountPlan(a)
			if err != nil {
				return err
			}
			accts = append(accts, acct)
			funding = append(funding, f...)
		}
		if err := d.createAccounts(accts); err != nil {
			return err
		}
		if err := d.submitIndependent(funding); err != nil {
			return err
		}
	}
	return nil
}

// ApplyEntry mirrors a committed entry. Hold-settling entries are mapped to
// post_pending + control transfers (ErrHoldExpired if TigerBeetle already
// expired the hold; see ApplyEntryFallback), all others to a pairwise chain.
func (d *Driver) ApplyEntry(en ledger.Entry) error {
	var plan []tb.Transfer
	var err error
	if en.HoldID != nil {
		plan, err = holdPostPlan(en)
	} else {
		plan, err = entryPlan(en)
	}
	if err != nil {
		return err
	}
	return d.submit(plan)
}

// ApplyEntryFallback mirrors a hold-settling entry as plain transfers.
func (d *Driver) ApplyEntryFallback(en ledger.Entry) error {
	plan, err := fallbackPlan(en)
	if err != nil {
		return err
	}
	return d.submit(plan)
}

// PlaceHold mirrors a pending hold. It is idempotent: a hold that already
// has its pending transfer is checked against it instead of resubmitted,
// since the timeout of a resubmission would differ.
func (d *Driver) PlaceHold(h ledger.Hold) error {
	found, err := d.lookupTransfers([]tb.Uint128{ToU128(h.ID)})
	if err != nil {
		return err
	}
	if t, ok := found[ToU128(h.ID)]; ok {
		return matchHold(t, h)
	}
	return d.createHold(h)
}

func (d *Driver) createHold(h ledger.Hold) error {
	if err := d.ensureSystem(h.Currency); err != nil {
		return err
	}
	t, err := holdPlan(h, d.now(), d.grace)
	if err != nil {
		return err
	}
	return d.submit([]tb.Transfer{t})
}

// matchHold checks that an existing transfer is h's pending transfer. The
// timeout depends on when the hold was mirrored and is not compared.
func matchHold(t tb.Transfer, h ledger.Hold) error {
	want, err := holdPlan(h, h.ExpiresAt, 0)
	if err != nil {
		return err
	}
	if t.DebitAccountID != want.DebitAccountID || t.CreditAccountID != want.CreditAccountID || t.Amount != want.Amount ||
		t.Ledger != want.Ledger || t.Code != want.Code || !t.TransferFlags().Pending {
		return fmt.Errorf("%w: transfer %s exists but is not the pending transfer of hold %s", ledger.ErrIdempotencyConflict,
			FromU128(t.ID), h.ID)
	}
	return nil
}

// VoidHold mirrors a voided or expired hold. A hold TigerBeetle already
// expired, or voided, counts as voided.
func (d *Driver) VoidHold(h ledger.Hold) error {
	t, err := voidPlan(h)
	if err != nil {
		return err
	}
	err = d.submit([]tb.Transfer{t})
	if errors.Is(err, ledger.ErrHoldExpired) {
		return nil
	}
	if errors.Is(err, ledger.ErrHoldNotPending) {
		// Already voided is the goal state; already posted is a divergence.
		found, lerr := d.lookupTransfers([]tb.Uint128{derivedID(h.ID, "post", 0)})
		if lerr != nil {
			return lerr
		}
		if len(found) == 0 {
			return nil
		}
		return fmt.Errorf("%w: hold %s is posted in TigerBeetle", ledger.ErrHoldNotPending, h.ID)
	}
	return err
}

// Opening is an account's posted balance at bootstrap.
type Opening struct {
	Account ledger.Account
	Posted  int64
}

// OpenBalances sets bootstrap posted balances (idempotent for the same
// amounts). The accounts must exist.
func (d *Driver) OpenBalances(os []Opening) error {
	var ts []tb.Transfer
	for _, o := range os {
		plan, err := openingPlan(o.Account, o.Posted)
		if err != nil {
			return err
		}
		ts = append(ts, plan...)
	}
	return d.submitIndependent(ts)
}

// placeHolds creates pending transfers for holds known not to be mirrored
// yet (bootstrap). The accounts must exist and hold the funds.
func (d *Driver) placeHolds(hs []ledger.Hold) error {
	ts := make([]tb.Transfer, 0, len(hs))
	now := d.now()
	for _, h := range hs {
		if err := d.ensureSystem(h.Currency); err != nil {
			return err
		}
		t, err := holdPlan(h, now, d.grace)
		if err != nil {
			return err
		}
		ts = append(ts, t)
	}
	return d.submitIndependent(ts)
}

// Accounts looks up accounts by ledger id. Missing accounts are absent.
func (d *Driver) Accounts(ids []uuid.UUID) (map[uuid.UUID]tb.Account, error) {
	out := make(map[uuid.UUID]tb.Account, len(ids))
	for start := 0; start < len(ids); start += maxBatch {
		batch := ids[start:min(start+maxBatch, len(ids))]
		keys := make([]tb.Uint128, len(batch))
		for i, id := range batch {
			keys[i] = ToU128(id)
		}
		found, err := d.client.LookupAccounts(keys)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ledger.ErrUnavailable, err)
		}
		for _, a := range found {
			out[FromU128(a.ID)] = a
		}
	}
	return out, nil
}

// lookupTransfers returns the transfers that exist among ids.
func (d *Driver) lookupTransfers(ids []tb.Uint128) (map[tb.Uint128]tb.Transfer, error) {
	out := make(map[tb.Uint128]tb.Transfer, len(ids))
	for start := 0; start < len(ids); start += maxBatch {
		found, err := d.client.LookupTransfers(ids[start:min(start+maxBatch, len(ids))])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ledger.ErrUnavailable, err)
		}
		for _, t := range found {
			out[t.ID] = t
		}
	}
	return out, nil
}

// Balance is an account's balance as TigerBeetle reports it, adjusted for
// limit pre-funding so it is comparable with the PostgreSQL ledger.
type Balance struct {
	Posted  int64
	Pending int64
}

// Balances looks up accounts in batches. Missing accounts are absent from
// the result.
func (d *Driver) Balances(accounts []ledger.Account) (map[uuid.UUID]Balance, error) {
	ids := make([]uuid.UUID, len(accounts))
	byID := make(map[uuid.UUID]ledger.Account, len(accounts))
	for i, a := range accounts {
		ids[i] = a.ID
		byID[a.ID] = a
	}
	found, err := d.Accounts(ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]Balance, len(found))
	for id, acct := range found {
		b, err := balanceOf(acct, byID[id])
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// balanceOf converts TigerBeetle counters into the ledger's view:
// posted = credits_posted - debits_posted (minus limit pre-funding),
// pending = debits_pending (holds reserve on the debit side).
func balanceOf(acct tb.Account, a ledger.Account) (Balance, error) {
	posted := new(big.Int).Sub(acct.CreditsPosted.BigInt(), acct.DebitsPosted.BigInt())
	if a.Floor != nil && *a.Floor < 0 {
		posted.Add(posted, big.NewInt(*a.Floor))
	}
	pending := acct.DebitsPending.BigInt()
	if !posted.IsInt64() || !pending.IsInt64() {
		return Balance{}, fmt.Errorf("%w: account %s exceeds int64", ledger.ErrOverflow, a.ID)
	}
	return Balance{Posted: posted.Int64(), Pending: pending.Int64()}, nil
}

// available is what a debit may still take from a limited account:
// credits_posted - debits_posted - debits_pending. ok is false for accounts
// without a balance limit.
func available(acct tb.Account) (avail *big.Int, ok bool) {
	if !acct.AccountFlags().DebitsMustNotExceedCredits {
		return nil, false
	}
	v := new(big.Int).Sub(acct.CreditsPosted.BigInt(), acct.DebitsPosted.BigInt())
	return v.Sub(v, acct.DebitsPending.BigInt()), true
}
