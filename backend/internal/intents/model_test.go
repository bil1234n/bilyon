package intents

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// TestRandomLifecycles drives intents through random interleavings of
// catches, declines, cancellations, delivery receipts, replays, clock jumps,
// sweeps and injected ledger outages (before and after commit), then checks
// that the ledger agrees with every intent: settled intents paid the payee
// exactly once, everything else returned to the payer, and nothing is
// left pending.
func TestRandomLifecycles(t *testing.T) {
	for seed := uint64(1); seed <= 6; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) { randomLifecycles(t, seed) })
	}
}

func randomLifecycles(t *testing.T, seed uint64) {
	f := newFixture(t, func(c *Config) {
		c.GestureCount = 100
		c.Limits = map[string]Limits{"EUR": {Gesture: 100_00, GestureWindow: 10_000_00}}
	})
	r := rand.New(rand.NewPCG(seed, 99))
	type tracked struct {
		req CreateRequest
		id  uuid.UUID
	}
	var all []tracked
	for i := 0; i < 8; i++ {
		th := f.flick(int64(1+r.IntN(80)) * 1_00)
		switch r.IntN(4) {
		case 0:
			th.req.OnTimeout = TimeoutVoid
		case 1:
			th.drop()
		case 2:
			th.handle(f.payer)
		}
		req := f.sign(th)
		if r.IntN(3) == 0 {
			f.ledger.inject([]string{"hold", "post"}[r.IntN(2)], 1, r.IntN(2) == 0)
		}
		if _, err := f.svc.Create(ctx(t), req); err != nil && !errors.Is(err, ErrUnavailable) {
			t.Fatalf("create: %v", err)
		}
		all = append(all, tracked{req: req, id: th.ta.IntentID})
	}
	allowed := func(err error) bool {
		return err == nil || errors.Is(err, ErrState) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrForbidden)
	}
	for step := 0; step < 60; step++ {
		x := all[r.IntN(len(all))]
		if r.IntN(5) == 0 {
			f.ledger.inject([]string{"hold", "post", "void"}[r.IntN(3)], 1+r.IntN(2), r.IntN(2) == 0)
		}
		var err error
		switch op := r.IntN(9); op {
		case 0, 1:
			if in := f.state(x.id); in.Gesture == GestureGrab {
				_, err = f.svc.Catch(ctx(t), CatchRequest{IntentID: x.id, UserID: f.stranger.user, Accept: true, Proximity: true})
			} else {
				_, err = f.catch(f.payee, x.id, true)
			}
		case 2:
			if in := f.state(x.id); in.Gesture != GestureGrab {
				_, err = f.catch(f.payee, x.id, false)
			}
		case 3:
			_, err = f.svc.Cancel(ctx(t), f.payer.user, x.id)
		case 4:
			if in := f.state(x.id); in.Gesture != GestureGrab {
				_, err = f.svc.MarkDelivered(ctx(t), f.payee.user, x.id)
			}
		case 5:
			_, err = f.svc.Create(ctx(t), x.req)
		case 6:
			f.c.advance([]time.Duration{5 * time.Second, 20 * time.Second, 40 * time.Second, 3 * 24 * time.Hour}[r.IntN(4)])
		case 7, 8:
			_, err = f.svc.Sweep(ctx(t))
		}
		if !allowed(err) {
			t.Fatalf("step %d: %v", step, err)
		}
	}
	// Outages end; time passes beyond every window; the sweeper finishes.
	f.ledger.inject("hold", 0, false)
	f.ledger.inject("post", 0, false)
	f.ledger.inject("void", 0, false)
	f.c.advance(8 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		f.sweep()
	}
	var paid, paidToStranger int64
	states := map[string]int{}
	for _, x := range all {
		in := f.state(x.id)
		states[string(in.State)+"/"+in.Reason]++
		if !in.State.Final() {
			t.Fatalf("intent %s left %s", in.ID, in.State)
		}
		terminal := 0
		for _, topic := range []string{TopicSettled, TopicVoided, TopicAborted} {
			for _, e := range f.events(topic) {
				if e["intent_id"] == in.ID.String() {
					terminal++
				}
			}
		}
		if terminal != 1 {
			t.Fatalf("intent %s (%s) has %d terminal events", in.ID, in.State, terminal)
		}
		switch in.State {
		case StateSettled:
			if h := f.hold(in); h.State != ledger.HoldPosted || h.PostedAmount != in.Amount {
				t.Fatalf("settled %s: hold %+v", in.ID, h)
			}
			if in.PayeeID == f.stranger.user {
				paidToStranger += in.Amount
			} else {
				paid += in.Amount
			}
		case StateVoided:
			if h := f.hold(in); h.State != ledger.HoldVoided && h.State != ledger.HoldExpired {
				t.Fatalf("voided %s: hold %+v", in.ID, h)
			}
		case StateAborted:
			if in.HoldID != uuid.Nil {
				if h := f.hold(in); h.State == ledger.HoldPending || h.State == ledger.HoldPosted {
					t.Fatalf("aborted %s: hold %+v", in.ID, h)
				}
			}
		}
	}
	t.Logf("final states %v", states)
	f.wantBalance(f.payee, "EUR", paid, paid)
	f.wantBalance(f.stranger, "EUR", paidToStranger, paidToStranger)
	total := paid + paidToStranger
	f.wantBalance(f.payer, "EUR", 1_000_00-total, 1_000_00-total)
}
