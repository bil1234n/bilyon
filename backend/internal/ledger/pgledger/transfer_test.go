package pgledger_test

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

func TestCreateAccountRulesAndIdempotency(t *testing.T) {
	e := newEnv(t)
	cmd := ledger.CreateAccount{IdempotencyKey: "acct-alice-1", Kind: ledger.KindUser, Currency: "EUR", Label: "Alice"}
	a1, err := e.eng.CreateAccount(e.ctx(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if a1.Floor == nil || *a1.Floor != 0 || a1.Stripes != 1 || a1.Frozen {
		t.Fatalf("customer account defaults: %+v", a1)
	}
	a2, err := e.eng.CreateAccount(e.ctx(), cmd)
	if err != nil || !reflect.DeepEqual(a1, a2) {
		t.Fatalf("replay: %+v %v", a2, err)
	}
	cmd.Label = "Mallory"
	_, err = e.eng.CreateAccount(e.ctx(), cmd)
	wantErr(t, err, ledger.ErrIdempotencyConflict)

	bad := []ledger.CreateAccount{
		{IdempotencyKey: "k1", Kind: "wallet", Currency: "EUR"},
		{IdempotencyKey: "k2", Kind: ledger.KindUser, Currency: "XXX"},
		{IdempotencyKey: "k3", Kind: ledger.KindUser, Currency: "EUR", Floor: ptr(int64(-100))},
		{IdempotencyKey: "k4", Kind: ledger.KindFee, Currency: "EUR", Floor: ptr(int64(0)), Stripes: 4},
		{IdempotencyKey: "k5", Kind: ledger.KindFXBook, Currency: "EUR", Floor: ptr(int64(5))},
		{IdempotencyKey: "has space", Kind: ledger.KindUser, Currency: "EUR"},
		{IdempotencyKey: "", Kind: ledger.KindUser, Currency: "EUR"},
	}
	for _, c := range bad {
		if _, err := e.eng.CreateAccount(e.ctx(), c); !errors.Is(err, ledger.ErrInvalid) {
			t.Errorf("%+v: got %v, want ErrInvalid", c, err)
		}
	}
	fx, err := e.eng.CreateAccount(e.ctx(), ledger.CreateAccount{IdempotencyKey: "fx-eur", Kind: ledger.KindFXBook,
		Currency: "EUR", Floor: ptr(int64(-1_000_000))})
	if err != nil || *fx.Floor != -1_000_000 {
		t.Fatalf("platform book with a risk limit: %+v %v", fx, err)
	}
	if len(e.outboxEvents(ledger.TopicAccountCreated)) != 3 { // bank, alice, fx
		t.Fatalf("account.created events: %d", len(e.outboxEvents(ledger.TopicAccountCreated)))
	}
	_, err = e.eng.Account(e.ctx(), uuid.New())
	wantErr(t, err, ledger.ErrNotFound)
}

func TestTransferMovesMoneyAndWritesHistory(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.user(), e.user()
	e.fund(alice, 10_000)
	en, err := e.transfer(alice, bob, 2_500)
	if err != nil {
		t.Fatal(err)
	}
	e.wantBalance(alice, 7_500, 0)
	e.wantBalance(bob, 2_500, 0)
	e.wantBalance(e.bank, -10_000, 0)
	got, err := e.eng.Entry(e.ctx(), en.ID)
	if err != nil || !reflect.DeepEqual(got, en) {
		t.Fatalf("Entry() = %+v, %v; want %+v", got, err, en)
	}
	page, err := e.eng.History(e.ctx(), ledger.HistoryQuery{AccountID: alice})
	if err != nil || len(page.Entries) != 2 || page.Entries[0].ID != en.ID || page.Next != nil {
		t.Fatalf("history: %+v %v", page, err)
	}
	events := e.outboxEvents(ledger.TopicEntryPosted)
	if len(events) != 2 || events[1].Subject != en.ID.String() || events[1].SpecVersion != "1.0" ||
		events[1].Source != "bilyon.ledger" || events[1].DataContentType != "application/json" {
		t.Fatalf("entry events: %+v", events)
	}
	e.audit()
}

func TestTransferValidationAndFailures(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.user(), e.user()
	e.fund(alice, 1_000)
	usd := e.account(ledger.KindUser, "USD", nil).ID

	_, err := e.eng.Transfer(e.ctx(), ledger.Transfer{IdempotencyKey: e.key("u"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: alice, Amount: -100}, {AccountID: bob, Amount: 99}}})
	wantErr(t, err, ledger.ErrUnbalanced)

	_, err = e.eng.Transfer(e.ctx(), ledger.Transfer{IdempotencyKey: e.key("c"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: alice, Amount: -100}, {AccountID: usd, Amount: 100}}})
	wantErr(t, err, ledger.ErrUnbalanced) // EUR -100 and USD +100 each fail to balance

	_, err = e.transfer(alice, uuid.New(), 10)
	wantErr(t, err, ledger.ErrNotFound)

	_, err = e.eng.Transfer(e.ctx(), ledger.Transfer{IdempotencyKey: e.key("d"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: alice, Amount: -1}, {AccountID: alice, Amount: 1}}})
	wantErr(t, err, ledger.ErrInvalid)

	_, err = e.eng.Transfer(e.ctx(), ledger.Transfer{IdempotencyKey: e.key("r"), Kind: ledger.EntryKindReversal,
		Postings: []ledger.Posting{{AccountID: alice, Amount: -1}, {AccountID: bob, Amount: 1}}})
	wantErr(t, err, ledger.ErrInvalid)

	_, err = e.transfer(alice, bob, 1_001)
	var ife *ledger.InsufficientFundsError
	if !errors.As(err, &ife) || ife.AccountID != alice || ife.Available != 1_000 || ife.Required != 1_001 || ife.Floor != 0 {
		t.Fatalf("insufficient funds detail: %v", err)
	}
	e.wantBalance(alice, 1_000, 0)
	if n := e.count(`SELECT count(*) FROM journal_entries`); n != 1 {
		t.Fatalf("failed transfers left %d entries", n)
	}
	if n := e.count(`SELECT count(*) FROM idempotency_keys WHERE scope = 'transfer'`); n != 1 {
		t.Fatalf("failed transfers left idempotency keys: %d", n)
	}
	e.audit()
}

func TestMultiCurrencyFXEntryBalancesPerCurrency(t *testing.T) {
	e := newEnv(t)
	eurUser := e.user()
	usdUser := e.account(ledger.KindUser, "USD", nil).ID
	fxEUR := e.account(ledger.KindFXBook, "EUR", nil).ID
	fxUSD := e.account(ledger.KindFXBook, "USD", nil).ID
	e.fund(eurUser, 1_000_000)
	en, err := e.eng.Transfer(e.ctx(), ledger.Transfer{IdempotencyKey: e.key("fx"), Kind: "fx", RefType: "quote", RefID: "q-000001",
		Postings: []ledger.Posting{
			{AccountID: eurUser, Amount: -1_000_000}, {AccountID: fxEUR, Amount: 1_000_000},
			{AccountID: fxUSD, Amount: -1_083_958}, {AccountID: usdUser, Amount: 1_083_958},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(en.Postings) != 4 || en.RefType != "quote" {
		t.Fatalf("fx entry: %+v", en)
	}
	e.wantBalance(usdUser, 1_083_958, 0)
	e.wantBalance(fxUSD, -1_083_958, 0)
	e.audit()
}

func TestReplayReturnsIdenticalResultAndConflictsAreRejected(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.user(), e.user()
	e.fund(alice, 5_000)
	cmd := ledger.Transfer{IdempotencyKey: "pay-77", Kind: "p2p", Memo: "lunch",
		Postings: []ledger.Posting{{AccountID: alice, Amount: -1_200}, {AccountID: bob, Amount: 1_200}}}
	first, err := e.eng.Transfer(e.ctx(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.eng.Transfer(e.ctx(), cmd)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("replay differs:\n%+v\n%+v (%v)", first, second, err)
	}
	e.wantBalance(bob, 1_200, 0)
	if n := len(e.outboxEvents(ledger.TopicEntryPosted)); n != 2 {
		t.Fatalf("replay emitted another event: %d", n)
	}
	cmd.Postings[0].Amount, cmd.Postings[1].Amount = -1_300, 1_300
	_, err = e.eng.Transfer(e.ctx(), cmd)
	wantErr(t, err, ledger.ErrIdempotencyConflict)
	_, err = e.eng.PlaceHold(e.ctx(), ledger.PlaceHold{IdempotencyKey: "pay-77", AccountID: alice, Amount: 1,
		Reason: "test", ExpiresAt: first.CreatedAt.Add(ledger.MaxHoldTTL / 2)})
	wantErr(t, err, ledger.ErrIdempotencyConflict) // keys are global across operation types
}

func TestConcurrentRequestsWithOneKeyExecuteOnce(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.user(), e.user()
	e.fund(alice, 1_000)
	cmd := ledger.Transfer{IdempotencyKey: "race-1", Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: alice, Amount: -600}, {AccountID: bob, Amount: 600}}}
	const n = 24
	results := make([]ledger.Entry, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { results[i], errs[i] = e.eng.Transfer(e.ctx(), cmd) })
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("request %d: %v", i, errs[i])
		}
		if !reflect.DeepEqual(results[i], results[0]) {
			t.Fatalf("request %d returned a different entry", i)
		}
	}
	e.wantBalance(alice, 400, 0) // debited once although 600 x 24 was requested
	e.audit()
}

func TestStripedAccountSpreadsWritesAndAggregates(t *testing.T) {
	e := newEnv(t)
	fees, err := e.eng.CreateAccount(e.ctx(), ledger.CreateAccount{IdempotencyKey: "fees", Kind: ledger.KindFee,
		Currency: "EUR", Stripes: 8})
	if err != nil {
		t.Fatal(err)
	}
	payer := e.user()
	e.fund(payer, 1_000_000)
	var total int64
	for i := range 40 {
		amt := int64(100 + i)
		if _, err := e.transfer(payer, fees.ID, amt); err != nil {
			t.Fatal(err)
		}
		total += amt
	}
	e.wantBalance(fees.ID, total, 0)
	if used := e.count(`SELECT count(DISTINCT stripe) FROM postings WHERE account_id = $1`, fees.ID); used < 4 {
		t.Fatalf("40 postings landed on only %d of 8 stripes", used)
	}
	if _, err := e.transfer(fees.ID, payer, total); err != nil { // unbounded: any stripe may go negative
		t.Fatalf("debit from striped account: %v", err)
	}
	e.wantBalance(fees.ID, 0, 0)
	e.audit()
}

func TestHistoryPaginatesWithoutGapsOrDuplicates(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.user(), e.user()
	e.fund(alice, 1_000_000)
	for range 24 {
		if _, err := e.transfer(alice, bob, 7); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uuid.UUID]bool{}
	var before *uuid.UUID
	pages := 0
	var last uuid.UUID
	for {
		page, err := e.eng.History(e.ctx(), ledger.HistoryQuery{AccountID: alice, Before: before, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, en := range page.Entries {
			if seen[en.ID] {
				t.Fatalf("duplicate entry %s", en.ID)
			}
			if last != uuid.Nil && en.ID.String() >= last.String() {
				t.Fatal("history not ordered newest first")
			}
			seen[en.ID], last = true, en.ID
			if len(en.Postings) != 2 {
				t.Fatalf("history entry without postings: %+v", en)
			}
		}
		if page.Next == nil {
			break
		}
		before = page.Next
	}
	if len(seen) != 25 || pages != 3 {
		t.Fatalf("%d entries over %d pages, want 25 over 3", len(seen), pages)
	}
	_, err := e.eng.History(e.ctx(), ledger.HistoryQuery{AccountID: alice, Limit: 501})
	wantErr(t, err, ledger.ErrInvalid)
}
