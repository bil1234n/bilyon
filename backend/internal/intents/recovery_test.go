package intents

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

func TestHoldOutageIsFinishedByAReplay(t *testing.T) {
	f := newFixture(t, nil)
	req := f.sign(f.flick(25_00))
	f.ledger.inject("hold", 1, false)
	if _, err := f.svc.Create(ctx(t), req); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("hold outage: %v", err)
	}
	id := mustParse(t, req)
	wantState(t, f.state(id), StateCreated, "")
	in, err := f.svc.Create(ctx(t), req)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, in, StateHeld, "")
	f.wantBalance(f.payer, "EUR", 1_000_00, 975_00)
}

func mustParse(t *testing.T, req CreateRequest) uuid.UUID {
	t.Helper()
	m, err := txauth.Parse(req.TxAuth)
	if err != nil {
		t.Fatal(err)
	}
	return m.TxAuth.IntentID
}

func TestHoldCommittedButAnswerLost(t *testing.T) {
	f := newFixture(t, nil)
	req := f.sign(f.flick(25_00))
	f.ledger.inject("hold", 1, true)
	if _, err := f.svc.Create(ctx(t), req); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost answer: %v", err)
	}
	id := mustParse(t, req)
	// The sweeper leaves fresh work alone, then finishes it with the same
	// hold the ledger already committed.
	if r := f.sweep(); r.Finished != 0 {
		t.Fatalf("swept fresh work: %+v", r)
	}
	f.c.advance(16 * time.Second)
	if r := f.sweep(); r.Finished != 1 {
		t.Fatalf("sweep %+v", r)
	}
	in := f.state(id)
	wantState(t, in, StateHeld, "")
	f.wantBalance(f.payer, "EUR", 1_000_00, 975_00) // one hold, not two
	if n := len(f.events(TopicHeld)); n != 1 {
		t.Fatalf("%d held events", n)
	}
}

func TestPostOutageAfterCommit(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(25_00))
	f.ledger.inject("post", 1, true)
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("post outage: %v", err)
	}
	wantState(t, f.state(in.ID), StateCaught, "")
	// The ledger already moved the money; the intent only lost the answer.
	f.wantBalance(f.payee, "EUR", 25_00, 25_00)
	// A repeated catch finishes it, without paying twice.
	out, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, out, StateSettled, "")
	f.wantBalance(f.payee, "EUR", 25_00, 25_00)
	f.wantBalance(f.payer, "EUR", 975_00, 975_00)
}

func TestPostOutageFinishedBySweeper(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(25_00))
	f.ledger.inject("post", 2, false)
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	f.c.advance(16 * time.Second)
	if r := f.sweep(); r.Failed != 1 || r.Finished != 0 {
		t.Fatalf("sweep during the outage %+v", r)
	}
	f.c.advance(16 * time.Second)
	if r := f.sweep(); r.Finished != 1 {
		t.Fatalf("sweep after the outage %+v", r)
	}
	wantState(t, f.state(in.ID), StateSettled, "")
	f.wantBalance(f.payee, "EUR", 25_00, 25_00)
}

func TestVoidOutage(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(25_00))
	f.ledger.inject("void", 2, false)
	if _, err := f.catch(f.payee, in.ID, false); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("void outage: %v", err)
	}
	wantState(t, f.state(in.ID), StateVoiding, ReasonDeclined)
	// The decision stands: accepting now is refused (and the refusal tries
	// to finish the return, which fails once more).
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrState) {
		t.Fatalf("accept while returning: %v", err)
	}
	wantState(t, f.state(in.ID), StateVoiding, ReasonDeclined)
	f.c.advance(16 * time.Second)
	if r := f.sweep(); r.Finished != 1 {
		t.Fatalf("sweep %+v", r)
	}
	wantState(t, f.state(in.ID), StateVoided, ReasonDeclined)
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	// A refused request finishes a pending return when it can.
	in = f.create(f.flick(25_00))
	f.ledger.inject("void", 1, false)
	if _, err := f.svc.Cancel(ctx(t), f.payer.user, in.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	wantState(t, f.state(in.ID), StateVoided, ReasonCancelled)
}

func TestReturningIntentWhoseHoldWasPostedSettles(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(25_00))
	// The post reaches the ledger but its answer is lost; then (by an
	// operator's mistake, say) the intent is marked as returning.
	f.ledger.inject("post", 1, true)
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx(t), `UPDATE payment_intents SET state = 'voiding', reason = 'settle_refused'
		WHERE intent_id = $1`, in.ID); err != nil {
		t.Fatal(err)
	}
	f.c.advance(16 * time.Second)
	f.sweep()
	// The void finds the intent's own post and finishes the settlement.
	out := f.state(in.ID)
	wantState(t, out, StateSettled, "")
	f.wantBalance(f.payee, "EUR", 25_00, 25_00)
	f.wantBalance(f.payer, "EUR", 975_00, 975_00)
	if n := len(f.events(TopicVoided)); n != 0 {
		t.Fatalf("%d voided events", n)
	}
}

func TestHoldPostedOutsideTheIntent(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(25_00))
	// The hold is consumed by another command before the catch.
	acct := f.fund(f.stranger, "EUR", 1)
	if _, err := f.pg.PostHold(ctx(t), ledger.PostHold{IdempotencyKey: "elsewhere:" + uuid.NewString(), HoldID: in.HoldID,
		Kind: "manual.adjustment", Credits: []ledger.Posting{{AccountID: acct, Amount: 25_00}}}); err != nil {
		t.Fatal(err)
	}
	out, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	// The intent cannot settle and nothing is left to return: it ends
	// voided, and the payee was paid nothing.
	wantState(t, out, StateVoided, ReasonHoldExpired)
	f.wantBalance(f.payee, "EUR", 0, 0)
}

func TestExpiredHoldBeforeItWasRecorded(t *testing.T) {
	f := newFixture(t, nil)
	// The ledger committed the hold, the answer was lost, and the hold
	// lapsed before anyone recorded it.
	th := f.flick(25_00)
	req := f.sign(th)
	f.ledger.inject("hold", 1, true)
	if _, err := f.svc.Create(ctx(t), req); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := f.pg.VoidHold(ctx(t), ledger.VoidHold{IdempotencyKey: "lapse:" + uuid.NewString(),
		HoldID: f.ledgerHoldFor(th.ta.IntentID)}); err != nil {
		t.Fatal(err)
	}
	in, err := f.svc.Create(ctx(t), req)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, in, StateVoided, ReasonHoldExpired)
	if in.HoldID == uuid.Nil || in.HeldAt != nil {
		t.Fatalf("the lapsed hold is recorded, the intent was never held: %+v", in)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	if len(f.events(TopicHeld)) != 0 || len(f.events(TopicVoided)) != 1 {
		t.Fatal("events")
	}
}

func TestHoldOutlivedByARedrive(t *testing.T) {
	f := newFixture(t, nil)
	// The ledger is down for longer than the hold would have lived: the
	// first answer is lost, and the redrive comes after the hold's expiry.
	th := f.flick(25_00)
	th.req.OnTimeout = TimeoutVoid
	req := f.sign(th)
	f.ledger.inject("hold", 1, true)
	if _, err := f.svc.Create(ctx(t), req); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	f.c.advance(2 * time.Hour)
	if r := f.sweep(); r.Finished != 1 {
		t.Fatalf("sweep %+v", r)
	}
	wantState(t, f.state(th.ta.IntentID), StateVoided, ReasonHoldExpired)
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
}

// ledgerHoldFor finds the hold the ledger placed for an intent by its
// idempotency key.
func (f *fixture) ledgerHoldFor(id uuid.UUID) uuid.UUID {
	f.t.Helper()
	acct, err := f.accts.Get(ctx(f.t), f.payer.user, "EUR")
	if err != nil {
		f.t.Fatal(err)
	}
	h, err := f.pg.PlaceHold(ctx(f.t), ledger.PlaceHold{IdempotencyKey: holdKey(id), AccountID: acct.AccountID,
		Amount: f.state(id).Amount, Reason: "throw_intent", ExpiresAt: f.state(id).HoldExpiresAt, RefType: "intent",
		RefID: id.String()})
	if err != nil {
		f.t.Fatal(err)
	}
	return h.ID
}

func TestConcurrentCatchAndCancel(t *testing.T) {
	f := newFixture(t, nil)
	var settled, voided int64
	for round := 0; round < 12; round++ {
		th := f.flick(10_00)
		th.signer, th.keyID = f.payer.dev, f.payer.devKey
		in := f.create(th)
		var wg sync.WaitGroup
		var catchErr, cancelErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, catchErr = f.catch(f.payee, in.ID, true) }()
		go func() { defer wg.Done(); _, cancelErr = f.svc.Cancel(ctx(t), f.payer.user, in.ID) }()
		wg.Wait()
		out := f.state(in.ID)
		switch out.State {
		case StateSettled:
			settled += out.Amount
			if catchErr != nil || !errors.Is(cancelErr, ErrState) {
				t.Fatalf("round %d settled: catch %v cancel %v", round, catchErr, cancelErr)
			}
		case StateVoided:
			voided += out.Amount
			if cancelErr != nil || !errors.Is(catchErr, ErrState) {
				t.Fatalf("round %d voided: catch %v cancel %v", round, catchErr, cancelErr)
			}
		default:
			t.Fatalf("round %d ended %s", round, out.State)
		}
	}
	f.wantBalance(f.payee, "EUR", settled, settled)
	f.wantBalance(f.payer, "EUR", 1_000_00-settled, 1_000_00-settled)
}

func TestConcurrentSweepers(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.SweepBatch = 3; c.GestureCount = 50 })
	var ids []uuid.UUID
	for i := 0; i < 10; i++ {
		ids = append(ids, f.create(f.flick(1_00)).ID)
	}
	f.c.advance(31 * time.Second)
	var wg sync.WaitGroup
	results := make([]SweepResult, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := f.svc.Sweep(ctx(t))
			if err != nil {
				t.Error(err)
			}
			results[i] = r
		}(i)
	}
	wg.Wait()
	total := 0
	for _, r := range results {
		total += r.Uncaught
	}
	if total != 10 {
		t.Fatalf("sweepers moved %d intents: %+v", total, results)
	}
	for _, id := range ids {
		wantState(t, f.state(id), StateAsyncPending, "")
	}
	if n := len(f.events(TopicAsyncPending)); n != 10 {
		t.Fatalf("%d async events", n)
	}
}

func TestDeliveryBeforeTheHold(t *testing.T) {
	f := newFixture(t, nil)
	req := f.sign(f.flick(25_00))
	f.ledger.inject("hold", 1, false)
	if _, err := f.svc.Create(ctx(t), req); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	id := mustParse(t, req)
	if _, err := f.svc.MarkDelivered(ctx(t), f.payee.user, id); !errors.Is(err, ErrState) {
		t.Fatalf("delivery before the hold: %v", err)
	}
	if _, err := f.catch(f.payee, id, true); !errors.Is(err, ErrState) {
		t.Fatalf("catch before the hold: %v", err)
	}
	if _, err := f.svc.Cancel(ctx(t), f.payer.user, id); !errors.Is(err, ErrState) {
		t.Fatalf("cancel before the hold: %v", err)
	}
	wantState(t, f.state(id), StateCreated, "")
}

func TestHoldRefusedByTheLedger(t *testing.T) {
	f := newFixture(t, nil)
	// The ledger refuses a hold whose expiry lies beyond its 31-day limit
	// by its own clock; here the gateway's clock runs 25 days ahead.
	f.c.advance(25 * 24 * time.Hour)
	in, err := f.svc.Create(ctx(t), f.sign(f.flick(25_00)))
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, in, StateAborted, ReasonHoldRefused)
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
}

func TestSweepDrainsAllBatches(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.SweepBatch = 2 })
	var ids []uuid.UUID
	for i := 0; i < 5; i++ {
		ids = append(ids, f.create(f.flick(1_00)).ID)
	}
	f.c.advance(31 * time.Second)
	if r := f.sweep(); r.Uncaught != 5 {
		t.Fatalf("sweep %+v", r)
	}
	for _, id := range ids {
		wantState(t, f.state(id), StateAsyncPending, "")
	}
}

func TestPostRefusedReturnsTheHold(t *testing.T) {
	f := newFixture(t, nil)
	// A payment that settles on acceptance: hold, refused post, return.
	f.ledger.refuse("post", &ledger.ValidationError{Field: "credits", Reason: "refused for the test"})
	in, err := f.svc.Create(ctx(t), f.sign(f.flick(30_00).handle(f.payer)))
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, in, StateVoided, ReasonSettleRefused)
	if h := f.hold(in); h.State != ledger.HoldVoided {
		t.Fatalf("hold %+v", h)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	f.wantBalance(f.payee, "EUR", 0, 0)
}
