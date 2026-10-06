package pgledger_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

func (e *env) hold(acct uuid.UUID, amount int64, ttl time.Duration) (ledger.Hold, error) {
	now, err := e.eng.Now(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return e.eng.PlaceHold(e.ctx(), ledger.PlaceHold{IdempotencyKey: e.key("hold"), AccountID: acct, Amount: amount,
		Reason: "throw_intent", ExpiresAt: now.Add(ttl), RefType: "intent", RefID: uuid.NewString()})
}

func TestHoldPostPartialWithFeeSplitReleasesRemainder(t *testing.T) {
	e := newEnv(t)
	payer, merchant := e.user(), e.account(ledger.KindMerchant, "EUR", nil).ID
	fees, err := e.eng.CreateAccount(e.ctx(), ledger.CreateAccount{IdempotencyKey: "fees", Kind: ledger.KindFee, Currency: "EUR", Stripes: 4})
	if err != nil {
		t.Fatal(err)
	}
	e.fund(payer, 10_000)
	h, err := e.hold(payer, 6_000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if h.State != ledger.HoldPending || h.RefType != "intent" {
		t.Fatalf("placed hold: %+v", h)
	}
	e.wantBalance(payer, 10_000, 6_000)
	if _, err := e.transfer(payer, merchant, 4_001); !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("held funds were spendable: %v", err)
	}
	post := ledger.PostHold{IdempotencyKey: "post-1", HoldID: h.ID, Kind: "merchant_payment",
		Credits: []ledger.Posting{{AccountID: merchant, Amount: 4_900}, {AccountID: fees.ID, Amount: 100}}}
	res, err := e.eng.PostHold(e.ctx(), post)
	if err != nil {
		t.Fatal(err)
	}
	if res.Hold.State != ledger.HoldPosted || res.Hold.PostedAmount != 5_000 || res.Hold.EntryID == nil ||
		*res.Hold.EntryID != res.Entry.ID || res.Entry.HoldID == nil || *res.Entry.HoldID != h.ID || res.Hold.ResolvedAt == nil {
		t.Fatalf("post result: %+v", res)
	}
	e.wantBalance(payer, 5_000, 0) // 1 000 of the hold released
	e.wantBalance(merchant, 4_900, 0)
	e.wantBalance(fees.ID, 100, 0)
	again, err := e.eng.PostHold(e.ctx(), post)
	if err != nil || !reflect.DeepEqual(again, res) {
		t.Fatalf("post replay: %v", err)
	}
	_, err = e.eng.PostHold(e.ctx(), ledger.PostHold{IdempotencyKey: "post-2", HoldID: h.ID,
		Credits: []ledger.Posting{{AccountID: merchant, Amount: 1}}})
	wantErr(t, err, ledger.ErrHoldNotPending)
	_, err = e.eng.VoidHold(e.ctx(), ledger.VoidHold{IdempotencyKey: "void-1", HoldID: h.ID})
	wantErr(t, err, ledger.ErrHoldNotPending)
	got, _ := e.eng.Hold(e.ctx(), h.ID)
	if !reflect.DeepEqual(got, res.Hold) {
		t.Fatalf("Hold() = %+v, want %+v", got, res.Hold)
	}
	if len(e.outboxEvents(ledger.TopicHoldPlaced)) != 1 || len(e.outboxEvents(ledger.TopicHoldPosted)) != 1 {
		t.Fatal("hold events missing")
	}
	e.audit()
}

func TestHoldVoidAndExpiry(t *testing.T) {
	e := newEnv(t)
	payer := e.user()
	e.fund(payer, 3_000)
	h1, err := e.hold(payer, 1_000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := e.hold(payer, 1_500, 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	e.wantBalance(payer, 3_000, 2_500)
	voided, err := e.eng.VoidHold(e.ctx(), ledger.VoidHold{IdempotencyKey: "v1", HoldID: h1.ID, Reason: "receiver declined"})
	if err != nil || voided.State != ledger.HoldVoided || voided.ResolutionNote != "receiver declined" {
		t.Fatalf("void: %+v %v", voided, err)
	}
	e.wantBalance(payer, 3_000, 1_500)

	if expired, err := e.eng.ExpireHolds(e.ctx(), 100); err != nil || len(expired) != 0 {
		t.Fatalf("expired too early: %v %v", expired, err)
	}
	time.Sleep(1600 * time.Millisecond)
	_, err = e.eng.PostHold(e.ctx(), ledger.PostHold{IdempotencyKey: "late", HoldID: h2.ID,
		Credits: []ledger.Posting{{AccountID: e.bank, Amount: 10}}})
	wantErr(t, err, ledger.ErrHoldExpired)
	expired, err := e.eng.ExpireHolds(e.ctx(), 100)
	if err != nil || len(expired) != 1 || expired[0].ID != h2.ID || expired[0].State != ledger.HoldExpired {
		t.Fatalf("expire: %+v %v", expired, err)
	}
	e.wantBalance(payer, 3_000, 0)
	if again, err := e.eng.ExpireHolds(e.ctx(), 100); err != nil || len(again) != 0 {
		t.Fatalf("expired twice: %v %v", again, err)
	}
	if len(e.outboxEvents(ledger.TopicHoldExpired)) != 1 || len(e.outboxEvents(ledger.TopicHoldVoided)) != 1 {
		t.Fatal("expiry/void events missing")
	}
	e.audit()
}

func TestHoldValidation(t *testing.T) {
	e := newEnv(t)
	payer := e.user()
	usd := e.account(ledger.KindUser, "USD", nil).ID
	e.fund(payer, 1_000)
	now, _ := e.eng.Now(e.ctx())
	place := func(amount int64, expires time.Time) error {
		_, err := e.eng.PlaceHold(e.ctx(), ledger.PlaceHold{IdempotencyKey: e.key("h"), AccountID: payer, Amount: amount,
			Reason: "quote_lock", ExpiresAt: expires})
		return err
	}
	wantErr(t, place(10, now.Add(100*time.Millisecond)), ledger.ErrInvalid)
	wantErr(t, place(10, now.Add(ledger.MaxHoldTTL+time.Hour)), ledger.ErrInvalid)
	wantErr(t, place(0, now.Add(time.Minute)), ledger.ErrInvalid)
	err := place(1_001, now.Add(time.Minute))
	var ife *ledger.InsufficientFundsError
	if !errors.As(err, &ife) || ife.Required != 1_001 {
		t.Fatalf("hold above balance: %v", err)
	}
	fees, _ := e.eng.CreateAccount(e.ctx(), ledger.CreateAccount{IdempotencyKey: "fees", Kind: ledger.KindFee, Currency: "EUR", Stripes: 2})
	_, err = e.eng.PlaceHold(e.ctx(), ledger.PlaceHold{IdempotencyKey: "striped", AccountID: fees.ID, Amount: 1,
		Reason: "quote_lock", ExpiresAt: now.Add(time.Minute)})
	wantErr(t, err, ledger.ErrInvalid)

	h, err := e.hold(payer, 500, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	post := func(credits ...ledger.Posting) error {
		_, err := e.eng.PostHold(e.ctx(), ledger.PostHold{IdempotencyKey: e.key("p"), HoldID: h.ID, Credits: credits})
		return err
	}
	wantErr(t, post(ledger.Posting{AccountID: e.bank, Amount: 501}), ledger.ErrInvalid)
	wantErr(t, post(ledger.Posting{AccountID: usd, Amount: 10}), ledger.ErrCurrencyMismatch)
	wantErr(t, post(ledger.Posting{AccountID: payer, Amount: 10}), ledger.ErrInvalid)
	wantErr(t, post(ledger.Posting{AccountID: e.bank, Amount: -10}), ledger.ErrInvalid)
	_, err = e.eng.PostHold(e.ctx(), ledger.PostHold{IdempotencyKey: e.key("p"), HoldID: uuid.New(),
		Credits: []ledger.Posting{{AccountID: e.bank, Amount: 1}}})
	wantErr(t, err, ledger.ErrNotFound)
	e.wantBalance(payer, 1_000, 500)
	e.audit()
}

func TestReverseRestoresBalancesOnce(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.user(), e.user()
	e.fund(alice, 1_000)
	en, err := e.transfer(alice, bob, 300)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := e.eng.Reverse(e.ctx(), ledger.Reverse{IdempotencyKey: "rev-1", EntryID: en.ID, Memo: "chargeback"})
	if err != nil {
		t.Fatal(err)
	}
	if rev.Kind != ledger.EntryKindReversal || rev.Reverses == nil || *rev.Reverses != en.ID {
		t.Fatalf("reversal entry: %+v", rev)
	}
	e.wantBalance(alice, 1_000, 0)
	e.wantBalance(bob, 0, 0)
	_, err = e.eng.Reverse(e.ctx(), ledger.Reverse{IdempotencyKey: "rev-2", EntryID: en.ID})
	wantErr(t, err, ledger.ErrAlreadyReversed)
	_, err = e.eng.Reverse(e.ctx(), ledger.Reverse{IdempotencyKey: "rev-3", EntryID: rev.ID})
	wantErr(t, err, ledger.ErrNotReversible)
	_, err = e.eng.Reverse(e.ctx(), ledger.Reverse{IdempotencyKey: "rev-4", EntryID: uuid.New()})
	wantErr(t, err, ledger.ErrNotFound)

	spent, _ := e.transfer(alice, bob, 400)
	if _, err := e.transfer(bob, alice, 400); err != nil { // bob spends the money first
		t.Fatal(err)
	}
	_, err = e.eng.Reverse(e.ctx(), ledger.Reverse{IdempotencyKey: "rev-5", EntryID: spent.ID})
	wantErr(t, err, ledger.ErrInsufficientFunds)
	e.audit()
}

func TestFreezeBlocksOutflowsOnly(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.user(), e.user()
	e.fund(alice, 1_000)
	paid, _ := e.transfer(alice, bob, 100)
	acct, err := e.eng.SetFrozen(e.ctx(), ledger.SetFrozen{IdempotencyKey: "freeze-1", AccountID: alice, Frozen: true, Reason: "sanctions hit"})
	if err != nil || !acct.Frozen {
		t.Fatalf("freeze: %+v %v", acct, err)
	}
	_, err = e.transfer(alice, bob, 1)
	var fe *ledger.FrozenError
	if !errors.As(err, &fe) || fe.AccountID != alice {
		t.Fatalf("debit while frozen: %v", err)
	}
	_, err = e.hold(alice, 1, time.Minute)
	wantErr(t, err, ledger.ErrAccountFrozen)
	e.fund(alice, 50) // credits still land on a frozen account
	// Reversal of a payment *from* the frozen account credits it: allowed.
	if _, err := e.eng.Reverse(e.ctx(), ledger.Reverse{IdempotencyKey: "rev", EntryID: paid.ID}); err != nil {
		t.Fatalf("reversal while frozen: %v", err)
	}
	if _, err := e.eng.SetFrozen(e.ctx(), ledger.SetFrozen{IdempotencyKey: "freeze-2", AccountID: alice, Frozen: false, Reason: "cleared"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.transfer(alice, bob, 1); err != nil {
		t.Fatalf("debit after unfreeze: %v", err)
	}
	_, err = e.eng.SetFrozen(e.ctx(), ledger.SetFrozen{IdempotencyKey: "freeze-3", AccountID: uuid.New(), Frozen: true, Reason: "x"})
	wantErr(t, err, ledger.ErrNotFound)
	if len(e.outboxEvents(ledger.TopicAccountFrozen)) != 2 {
		t.Fatal("freeze events missing")
	}
	e.audit()
}

func TestReserveLifecycle(t *testing.T) {
	e := newEnv(t)
	owner := uuid.New()
	funding, err := e.eng.CreateAccount(e.ctx(), ledger.CreateAccount{IdempotencyKey: "alice", OwnerID: &owner, Kind: ledger.KindUser, Currency: "EUR"})
	if err != nil {
		t.Fatal(err)
	}
	merchant := e.account(ledger.KindMerchant, "EUR", nil).ID
	e.fund(funding.ID, 20_000)
	now, _ := e.eng.Now(e.ctx())
	exp := now.Add(72 * time.Hour)
	open := ledger.OpenReserve{IdempotencyKey: "allowance-1", FundingAccountID: funding.ID, Amount: 15_000,
		Purpose: "offline_allowance", RefType: "allowance", RefID: "aid-123", ExpiresAt: &exp}
	opened, err := e.eng.OpenReserve(e.ctx(), open)
	if err != nil {
		t.Fatal(err)
	}
	r := opened.Reserve
	if r.State != ledger.ReserveOpen || r.OpenedEntryID != opened.Entry.ID || r.ExpiresAt == nil || r.Currency != "EUR" {
		t.Fatalf("reserve: %+v", r)
	}
	acct, err := e.eng.Account(e.ctx(), r.ID)
	if err != nil || acct.Kind != ledger.KindOfflineReserve || acct.OwnerID == nil || *acct.OwnerID != owner || *acct.Floor != 0 {
		t.Fatalf("reserve account: %+v %v", acct, err)
	}
	e.wantBalance(funding.ID, 5_000, 0)
	e.wantBalance(r.ID, 15_000, 0)
	if again, err := e.eng.OpenReserve(e.ctx(), open); err != nil || !reflect.DeepEqual(again, opened) {
		t.Fatalf("open replay: %v", err)
	}
	// Offline settlement: reserve -> merchant (Algorithm A).
	if _, err := e.transfer(r.ID, merchant, 1_250); err != nil {
		t.Fatal(err)
	}
	released, err := e.eng.ReleaseReserve(e.ctx(), ledger.ReleaseReserve{IdempotencyKey: "release-1", ReserveID: r.ID})
	if err != nil {
		t.Fatal(err)
	}
	if released.Reserve.State != ledger.ReserveClosed || released.Entry == nil || released.Reserve.ClosedAt == nil ||
		*released.Reserve.ClosedEntryID != released.Entry.ID {
		t.Fatalf("release: %+v", released)
	}
	e.wantBalance(funding.ID, 5_000+13_750, 0)
	e.wantBalance(r.ID, 0, 0)
	_, err = e.eng.ReleaseReserve(e.ctx(), ledger.ReleaseReserve{IdempotencyKey: "release-2", ReserveID: r.ID})
	wantErr(t, err, ledger.ErrReserveClosed)
	if _, err := e.transfer(r.ID, merchant, 1); !errors.Is(err, ledger.ErrAccountFrozen) {
		t.Fatalf("closed reserve still spendable: %v", err)
	}
	_, err = e.eng.OpenReserve(e.ctx(), ledger.OpenReserve{IdempotencyKey: "allowance-2", FundingAccountID: funding.ID,
		Amount: 1_000_000, Purpose: "offline_allowance"})
	wantErr(t, err, ledger.ErrInsufficientFunds)
	if n := e.count(`SELECT count(*) FROM accounts WHERE kind = 'offline_reserve'`); n != 1 {
		t.Fatalf("failed open left %d reserve accounts", n)
	}
	got, err := e.eng.Reserve(e.ctx(), r.ID)
	if err != nil || !reflect.DeepEqual(got, released.Reserve) {
		t.Fatalf("Reserve() = %+v %v", got, err)
	}
	e.audit()
}

func TestReserveWithPendingHoldCannotBeReleased(t *testing.T) {
	e := newEnv(t)
	funding := e.user()
	e.fund(funding, 1_000)
	opened, err := e.eng.OpenReserve(e.ctx(), ledger.OpenReserve{IdempotencyKey: "r", FundingAccountID: funding,
		Amount: 800, Purpose: "payment_link", Kind: ledger.KindLinkEscrow})
	if err != nil {
		t.Fatal(err)
	}
	h, err := e.hold(opened.Reserve.ID, 300, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.eng.ReleaseReserve(e.ctx(), ledger.ReleaseReserve{IdempotencyKey: "rel", ReserveID: opened.Reserve.ID})
	wantErr(t, err, ledger.ErrInvalid)
	if _, err := e.eng.VoidHold(e.ctx(), ledger.VoidHold{IdempotencyKey: "v", HoldID: h.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.ReleaseReserve(e.ctx(), ledger.ReleaseReserve{IdempotencyKey: "rel", ReserveID: opened.Reserve.ID}); err != nil {
		t.Fatalf("release after voiding: %v", err)
	}
	e.wantBalance(funding, 1_000, 0)
	e.audit()
}
