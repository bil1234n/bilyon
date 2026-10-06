package intents

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

func TestFlickHeldDeliveredCaughtSettled(t *testing.T) {
	f := newFixture(t, nil)
	th := f.flick(25_00)
	in := f.create(th)
	wantState(t, in, StateHeld, "")
	switch {
	case in.ID != th.ta.IntentID || in.PayerID != f.payer.user || in.PayerSubject != f.payer.subject:
		t.Fatalf("payer %+v", in)
	case in.PayeeID != f.payee.user || in.PayeeSubject != f.payee.subject || in.PARVersion != th.ta.PARVersion:
		t.Fatalf("payee %+v", in)
	case in.SignerKeyID != f.payer.gestKey || in.SignerRole != devicebind.RoleGesture || in.PayerDeviceID != f.payer.device:
		t.Fatalf("signer %+v", in)
	case in.PayeeAmount != 25_00 || in.PayeeCurrency != "EUR" || in.OnTimeout != TimeoutAsync || in.HeldAt == nil:
		t.Fatalf("intent %+v", in)
	case in.TLand == nil || !in.TLand.Equal(th.req.TLand.UTC().Truncate(time.Millisecond)):
		t.Fatalf("t_land %v", in.TLand)
	case !in.LiveUntil.Equal(in.TLand.Add(30 * time.Second)):
		t.Fatalf("live until %v", in.LiveUntil)
	case !in.HoldExpiresAt.Equal(in.LiveUntil.Add(7*24*time.Hour + time.Hour)):
		t.Fatalf("hold expiry %v", in.HoldExpiresAt)
	}
	h := f.hold(in)
	if h.State != ledger.HoldPending || h.Amount != 25_00 || h.Reason != "throw_intent" || h.RefType != "intent" ||
		h.RefID != in.ID.String() || !h.ExpiresAt.Equal(in.HoldExpiresAt) {
		t.Fatalf("hold %+v", h)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 975_00)
	held := f.events(TopicHeld)
	if len(held) != 1 || held[0]["intent_id"] != in.ID.String() || held[0]["t_land_ms"] != float64(in.TLand.UnixMilli()) ||
		held[0]["payee_subject"] != f.payee.subject || held[0]["payer_device_id"] != f.payer.device.String() ||
		held[0]["state"] != "held" || held[0]["trajectory"].(map[string]any)["az"] != 0.4 {
		t.Fatalf("held event %v", held)
	}

	d, err := f.svc.MarkDelivered(ctx(t), f.payee.user, in.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, d, StateDelivered, "")
	if _, err := f.svc.MarkDelivered(ctx(t), f.payer.user, in.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("payer marking delivery: %v", err)
	}
	if again, err := f.svc.MarkDelivered(ctx(t), f.payee.user, in.ID); err != nil || again.State != StateDelivered {
		t.Fatalf("repeated delivery %v %v", again, err)
	}

	c, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, c, StateSettled, "")
	if len(c.EntryIDs) != 1 || c.CaughtAt == nil || c.ResolvedAt == nil || c.DeliveredAt == nil {
		t.Fatalf("settled %+v", c)
	}
	e, err := f.pg.Entry(ctx(t), c.EntryIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != EntryKind || e.HoldID == nil || *e.HoldID != in.HoldID || e.IdempotencyKey != postKey(in.ID) {
		t.Fatalf("entry %+v", e)
	}
	f.wantBalance(f.payer, "EUR", 975_00, 975_00)
	f.wantBalance(f.payee, "EUR", 25_00, 25_00)
	for topic, n := range map[string]int{TopicDelivered: 1, TopicCaught: 1, TopicSettled: 1, TopicVoided: 0} {
		if got := len(f.events(topic)); got != n {
			t.Fatalf("%d %s events, want %d", got, topic, n)
		}
	}
	if s := f.events(TopicSettled)[0]; s["entry_ids"].([]any)[0] != c.EntryIDs[0].String() {
		t.Fatalf("settled event %v", s)
	}
	// Catching again answers with the settlement; declining is too late.
	if again, err := f.catch(f.payee, in.ID, true); err != nil || again.State != StateSettled {
		t.Fatalf("repeated catch %v %v", again, err)
	}
	if _, err := f.catch(f.payee, in.ID, false); !errors.Is(err, ErrState) {
		t.Fatalf("decline after settlement: %v", err)
	}
	if _, err := f.svc.Cancel(ctx(t), f.payer.user, in.ID); !errors.Is(err, ErrState) {
		t.Fatalf("cancel after settlement: %v", err)
	}
	f.wantBalance(f.payee, "EUR", 25_00, 25_00)
}

func TestPaymentsThatSettleOnAcceptance(t *testing.T) {
	f := newFixture(t, nil)
	// A payment to a handle, authorised by K_dev.
	in := f.create(f.flick(120_00).handle(f.payer))
	wantState(t, in, StateSettled, "")
	if in.TLand != nil || in.LiveUntil != nil || in.HeldAt == nil || in.CaughtAt == nil {
		t.Fatalf("handle payment %+v", in)
	}
	if h := f.hold(in); h.State != ledger.HoldPosted || h.Reason != "payment_intent" ||
		!h.ExpiresAt.Equal(in.CreatedAt.Add(time.Hour)) {
		t.Fatalf("hold %+v", h)
	}
	// A split share, authorised by K_gest, and a QR payment by K_dev.
	split := f.flick(30_00)
	split.ta.Gesture, split.req.Gesture = txauth.GestureSplit, GestureSplit
	split.req.TLand, split.req.Trajectory = time.Time{}, nil
	wantState(t, f.create(split), StateSettled, "")
	qr := f.flick(5_00).handle(f.payer)
	qr.req.Gesture = GestureQR
	wantState(t, f.create(qr), StateSettled, "")
	f.wantBalance(f.payee, "EUR", 155_00, 155_00)
	f.wantBalance(f.payer, "EUR", 845_00, 845_00)
	if len(f.events(TopicHeld)) != 0 || len(f.events(TopicCaught)) != 0 || len(f.events(TopicSettled)) != 3 {
		t.Fatal("payments that settle on acceptance publish only their settlement")
	}
}

func TestDropIsGrabbedInProximity(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(10_00).drop())
	wantState(t, in, StateHeld, "")
	if in.PayeeID != uuid.Nil || in.PayeeSubject != "" || in.TLand != nil ||
		!in.LiveUntil.Equal(in.CreatedAt.Add(time.Minute)) || !in.HoldExpiresAt.Equal(in.LiveUntil.Add(time.Hour)) {
		t.Fatalf("drop %+v", in)
	}
	grab := func(p *party, accept, prox bool) (*Intent, error) {
		return f.svc.Catch(ctx(t), CatchRequest{IntentID: in.ID, UserID: p.user, Accept: accept, Proximity: prox})
	}
	if _, err := grab(f.payer, true, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("payer grabbing their own drop: %v", err)
	}
	if _, err := grab(f.stranger, true, false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("grab without proximity: %v", err)
	}
	if _, err := grab(f.stranger, false, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("declining a drop: %v", err)
	}
	// A frozen account cannot grab.
	if _, err := f.pool.Exec(ctx(t), `UPDATE users SET status = 'frozen' WHERE user_id = $1`, f.stranger.user); err != nil {
		t.Fatal(err)
	}
	if _, err := grab(f.stranger, true, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("frozen grabber: %v", err)
	}
	if _, err := f.pool.Exec(ctx(t), `UPDATE users SET status = 'active' WHERE user_id = $1`, f.stranger.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Catch(ctx(t), CatchRequest{IntentID: in.ID, UserID: uuid.New(), Accept: true, Proximity: true}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown grabber: %v", err)
	}
	if _, err := f.svc.MarkDelivered(ctx(t), f.stranger.user, in.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delivering a drop: %v", err)
	}
	if _, err := f.svc.Get(ctx(t), f.stranger.user, in.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an ungrabbed drop is the payer's: %v", err)
	}
	c, err := grab(f.stranger, true, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, c, StateSettled, "")
	if c.PayeeID != f.stranger.user || c.PayeeSubject != f.stranger.subject || c.PARVersion != 0 {
		t.Fatalf("grabbed %+v", c)
	}
	if _, err := grab(f.payee, true, true); !errors.Is(err, ErrState) {
		t.Fatalf("second grabber: %v", err)
	}
	if again, err := grab(f.stranger, true, true); err != nil || again.State != StateSettled {
		t.Fatalf("grabber retrying: %v %v", again, err)
	}
	if _, err := f.svc.Get(ctx(t), f.stranger.user, in.ID); err != nil {
		t.Fatalf("the grabber sees the intent: %v", err)
	}
	f.wantBalance(f.stranger, "EUR", 10_00, 10_00)
	f.wantBalance(f.payer, "EUR", 990_00, 990_00)
}

func TestUngrabbedDropReturns(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(10_00).drop())
	f.c.advance(59 * time.Second)
	if r := f.sweep(); r.Uncaught != 0 {
		t.Fatalf("swept a live drop: %+v", r)
	}
	f.c.advance(2 * time.Second)
	if r := f.sweep(); r.Uncaught != 1 || r.Finished != 1 {
		t.Fatalf("sweep %+v", r)
	}
	out := f.state(in.ID)
	wantState(t, out, StateVoided, ReasonUncaught)
	if h := f.hold(out); h.State != ledger.HoldVoided {
		t.Fatalf("hold %+v", h)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	if v := f.events(TopicVoided); len(v) != 1 || v[0]["reason"] != ReasonUncaught {
		t.Fatalf("voided events %v", v)
	}
	// Even with an asynchronous preference: a drop has nobody to claim it.
	if out.OnTimeout != TimeoutAsync {
		t.Fatalf("timeout %s", out.OnTimeout)
	}
}

func TestUncaughtThrowBecomesAClaim(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(40_00))
	// Delivered to the payee's phone, but nobody catches it.
	if _, err := f.svc.MarkDelivered(ctx(t), f.payee.user, in.ID); err != nil {
		t.Fatal(err)
	}
	f.c.advance(29 * time.Second)
	if r := f.sweep(); r.Uncaught != 0 {
		t.Fatalf("swept a live throw: %+v", r)
	}
	f.c.advance(2 * time.Second)
	if r := f.sweep(); r.Uncaught != 1 {
		t.Fatalf("sweep %+v", r)
	}
	out := f.state(in.ID)
	wantState(t, out, StateAsyncPending, "")
	if !out.ClaimUntil.Equal(in.LiveUntil.Add(7 * 24 * time.Hour)) {
		t.Fatalf("claim until %v", out.ClaimUntil)
	}
	if ev := f.events(TopicAsyncPending); len(ev) != 1 || ev[0]["claim_until_ms"] != float64(out.ClaimUntil.UnixMilli()) {
		t.Fatalf("async events %v", ev)
	}
	f.c.advance(3 * 24 * time.Hour)
	if r := f.sweep(); r.Uncaught+r.Expired != 0 {
		t.Fatalf("swept a claimable throw: %+v", r)
	}
	if _, err := f.svc.MarkDelivered(ctx(t), f.payee.user, in.ID); err != nil {
		t.Fatalf("late delivery acknowledgement: %v", err)
	}
	c, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, c, StateSettled, "")
	f.wantBalance(f.payee, "EUR", 40_00, 40_00)
}

func TestUnclaimedThrowReturnsAfterTheClaimWindow(t *testing.T) {
	f := newFixture(t, nil)
	in := f.create(f.flick(40_00))
	f.c.advance(31 * time.Second)
	f.sweep()
	f.c.advance(7 * 24 * time.Hour)
	if r := f.sweep(); r.Expired != 1 || r.Finished != 1 {
		t.Fatalf("sweep %+v", r)
	}
	wantState(t, f.state(in.ID), StateVoided, ReasonClaimExpired)
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrState) {
		t.Fatalf("claim after the window: %v", err)
	}
}

func TestUncaughtThrowReturnsWhenThePayerPrefers(t *testing.T) {
	f := newFixture(t, nil)
	// For this throw only.
	th := f.flick(40_00)
	th.req.OnTimeout = TimeoutVoid
	in := f.create(th)
	if in.OnTimeout != TimeoutVoid || !in.HoldExpiresAt.Equal(in.LiveUntil.Add(time.Hour)) {
		t.Fatalf("intent %+v", in)
	}
	// By default.
	if err := f.svc.SetTimeout(ctx(t), f.payer.user, TimeoutVoid); err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.Timeout(ctx(t), f.payer.user); err != nil || got != TimeoutVoid {
		t.Fatalf("timeout %s %v", got, err)
	}
	if err := f.svc.SetTimeout(ctx(t), f.payer.user, "later"); !errors.Is(err, ErrRequest) {
		t.Fatalf("invalid timeout: %v", err)
	}
	if err := f.svc.SetTimeout(ctx(t), uuid.New(), TimeoutVoid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	second := f.create(f.flick(10_00))
	if second.OnTimeout != TimeoutVoid {
		t.Fatalf("default timeout %s", second.OnTimeout)
	}
	f.c.advance(31 * time.Second)
	if r := f.sweep(); r.Uncaught != 2 || r.Finished != 2 {
		t.Fatalf("sweep %+v", r)
	}
	for _, id := range []uuid.UUID{in.ID, second.ID} {
		wantState(t, f.state(id), StateVoided, ReasonUncaught)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
}

func TestCatchAfterTheLiveTTLWithoutASweep(t *testing.T) {
	f := newFixture(t, nil)
	claim := f.create(f.flick(15_00))
	th := f.flick(20_00)
	th.req.OnTimeout = TimeoutVoid
	back := f.create(th)
	f.c.advance(31 * time.Second)
	// The catch applies the timeout first: a claim settles…
	c, err := f.catch(f.payee, claim.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, c, StateSettled, "")
	// …and a throw that returns cannot be caught any more.
	if _, err := f.catch(f.payee, back.ID, true); !errors.Is(err, ErrState) {
		t.Fatalf("late catch of a returning throw: %v", err)
	}
	wantState(t, f.state(back.ID), StateVoided, ReasonUncaught)
	f.wantBalance(f.payer, "EUR", 985_00, 985_00)
	if r := f.sweep(); r.Uncaught+r.Expired+r.Finished+r.Failed != 0 {
		t.Fatalf("nothing left to sweep: %+v", r)
	}
}

func TestDeclineAndCancel(t *testing.T) {
	f := newFixture(t, nil)
	declined := f.create(f.flick(30_00))
	if _, err := f.catch(f.stranger, declined.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger declining: %v", err)
	}
	out, err := f.catch(f.payee, declined.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, out, StateVoided, ReasonDeclined)
	if h := f.hold(out); h.State != ledger.HoldVoided {
		t.Fatalf("hold %+v", h)
	}
	if again, err := f.catch(f.payee, declined.ID, false); err != nil || again.State != StateVoided {
		t.Fatalf("repeated decline: %v %v", again, err)
	}
	if _, err := f.catch(f.payee, declined.ID, true); !errors.Is(err, ErrState) {
		t.Fatalf("accept after decline: %v", err)
	}

	cancelled := f.create(f.flick(30_00))
	if _, err := f.svc.Cancel(ctx(t), f.payee.user, cancelled.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("payee cancelling: %v", err)
	}
	if _, err := f.svc.Cancel(ctx(t), f.stranger.user, cancelled.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger cancelling: %v", err)
	}
	out, err = f.svc.Cancel(ctx(t), f.payer.user, cancelled.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, out, StateVoided, ReasonCancelled)
	if again, err := f.svc.Cancel(ctx(t), f.payer.user, cancelled.ID); err != nil || again.State != StateVoided {
		t.Fatalf("repeated cancel: %v %v", again, err)
	}
	if _, err := f.svc.Cancel(ctx(t), f.payer.user, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown intent: %v", err)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	if v := f.events(TopicVoided); len(v) != 2 {
		t.Fatalf("voided events %v", v)
	}
	// A claim can be cancelled too, until it is claimed.
	async := f.create(f.flick(5_00))
	f.c.advance(31 * time.Second)
	f.sweep()
	if out, err := f.svc.Cancel(ctx(t), f.payer.user, async.ID); err != nil || out.State != StateVoided {
		t.Fatalf("cancel a claim: %v %v", out, err)
	}
}

func TestReplayAndDualPathSubmission(t *testing.T) {
	f := newFixture(t, nil)
	req := f.sign(f.flick(25_00))
	first, err := f.svc.Create(ctx(t), req)
	if err != nil {
		t.Fatal(err)
	}
	// A retransmission of the same bytes, and the payee relaying them.
	again, err := f.svc.Create(ctx(t), req)
	if err != nil || again.ID != first.ID || again.State != StateHeld || again.HoldID != first.HoldID {
		t.Fatalf("retransmission %+v %v", again, err)
	}
	relayed := req
	relayed.SubmitterID, relayed.OnTimeout = f.payee.user, TimeoutVoid
	if r, err := f.svc.Create(ctx(t), relayed); err != nil || r.ID != first.ID || r.OnTimeout != TimeoutAsync {
		t.Fatalf("relay %+v %v", r, err)
	}
	stranger := req
	stranger.SubmitterID = f.stranger.user
	if _, err := f.svc.Create(ctx(t), stranger); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stranger relaying: %v", err)
	}
	// The same intent id under different bytes (a fresh signature).
	th := f.flick(25_00)
	th.ta.IntentID = first.ID
	if _, err := f.svc.Create(ctx(t), f.sign(th)); !errors.Is(err, ErrConflict) {
		t.Fatalf("intent id reuse: %v", err)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 975_00)
	if n := len(f.events(TopicHeld)); n != 1 {
		t.Fatalf("%d held events", n)
	}
}

func TestPayeeRelaysFirst(t *testing.T) {
	f := newFixture(t, nil)
	req := f.sign(f.flick(25_00))
	relayed := req
	relayed.SubmitterID, relayed.OnTimeout = f.payee.user, TimeoutVoid
	in, err := f.svc.Create(ctx(t), relayed)
	if err != nil {
		t.Fatal(err)
	}
	// The payer's default applies to a relayed throw, not the relay's wish.
	wantState(t, in, StateHeld, "")
	if in.OnTimeout != TimeoutAsync || in.PayerID != f.payer.user {
		t.Fatalf("relayed %+v", in)
	}
	if out, err := f.svc.Create(ctx(t), req); err != nil || out.ID != in.ID {
		t.Fatalf("payer's own submission %+v %v", out, err)
	}
	// A drop has no payee to relay it.
	drop := f.sign(f.flick(5_00).drop())
	drop.SubmitterID = f.payee.user
	if _, err := f.svc.Create(ctx(t), drop); !errors.Is(err, ErrForbidden) {
		t.Fatalf("relayed drop: %v", err)
	}
	// Nor can anyone relay a throw to a payee they are not.
	th := f.flick(5_00)
	th.req.PayeeSubject = "bil_0000000000000000000Z"
	th.ta.PayeeRef = identity.PayeeRef(th.req.PayeeSubject)
	unknown := f.sign(th)
	unknown.SubmitterID = f.payee.user
	if _, err := f.svc.Create(ctx(t), unknown); !errors.Is(err, ErrForbidden) {
		t.Fatalf("relay to an unknown payee: %v", err)
	}
	th = f.flick(5_00)
	th.req.PayeeSubject, th.ta.PayeeRef = f.stranger.subject, identity.PayeeRef(f.stranger.subject)
	th.ta.PARVersion = f.version(f.stranger)
	other := f.sign(th)
	other.SubmitterID = f.payee.user
	if _, err := f.svc.Create(ctx(t), other); !errors.Is(err, ErrForbidden) {
		t.Fatalf("relay of someone else's throw: %v", err)
	}
}

func TestConcurrentSubmissionsCreateOneIntent(t *testing.T) {
	f := newFixture(t, nil)
	req := f.sign(f.flick(25_00))
	var wg sync.WaitGroup
	ids := make([]uuid.UUID, 8)
	errs := make([]error, 8)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := req
			if i%2 == 1 {
				r.SubmitterID = f.payee.user
			}
			in, err := f.svc.Create(ctx(t), r)
			errs[i] = err
			if err == nil {
				ids[i] = in.ID
			}
		}(i)
	}
	wg.Wait()
	for i := range ids {
		if errs[i] != nil || ids[i] != ids[0] {
			t.Fatalf("submission %d: %v %v", i, ids[i], errs[i])
		}
	}
	wantState(t, f.state(ids[0]), StateHeld, "")
	f.wantBalance(f.payer, "EUR", 1_000_00, 975_00)
}

func TestGetAndList(t *testing.T) {
	f := newFixture(t, nil)
	a := f.create(f.flick(1_00))
	b := f.create(f.flick(2_00))
	c := f.create(f.flick(3_00).handle(f.payer))
	if _, err := f.svc.Get(ctx(t), f.stranger.user, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger reading: %v", err)
	}
	for _, p := range []*party{f.payer, f.payee} {
		if got, err := f.svc.Get(ctx(t), p.user, a.ID); err != nil || got.ID != a.ID {
			t.Fatalf("Get: %v %v", got, err)
		}
	}
	list := func(q ListQuery) []uuid.UUID {
		t.Helper()
		out, err := f.svc.List(ctx(t), q)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]uuid.UUID, len(out))
		for i, in := range out {
			ids[i] = in.ID
		}
		return ids
	}
	eq := func(got []uuid.UUID, want ...uuid.UUID) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("listed %v, want %v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("listed %v, want %v", got, want)
			}
		}
	}
	eq(list(ListQuery{UserID: f.payer.user}), c.ID, b.ID, a.ID)
	eq(list(ListQuery{UserID: f.payee.user, Role: RolePayee}), c.ID, b.ID, a.ID)
	eq(list(ListQuery{UserID: f.payee.user, Role: RolePayer}))
	eq(list(ListQuery{UserID: f.payee.user, States: []State{StateHeld}}), b.ID, a.ID)
	eq(list(ListQuery{UserID: f.payer.user, Limit: 2}), c.ID, b.ID)
	eq(list(ListQuery{UserID: f.payer.user, Limit: 2, Before: b.ID}), a.ID)
	eq(list(ListQuery{UserID: f.stranger.user}))
	for _, q := range []ListQuery{{UserID: f.payer.user, Limit: 201}, {}, {UserID: f.payer.user, Role: "admin"},
		{UserID: f.payer.user, States: []State{"lost"}}} {
		if _, err := f.svc.List(ctx(t), q); !errors.Is(err, ErrRequest) {
			t.Fatalf("List(%+v): %v", q, err)
		}
	}
}

func TestIssueNonces(t *testing.T) {
	f := newFixture(t, nil)
	ns, err := f.svc.IssueNonces(ctx(t), f.payer.user, f.payer.device, MaxNonces)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[[16]byte]bool{}
	now := f.c.now()
	for _, n := range ns {
		if seen[n.Value] {
			t.Fatal("duplicate nonce")
		}
		seen[n.Value] = true
		if d := n.ExpiresAt.Sub(now); d < 9*time.Minute || d > 10*time.Minute {
			t.Fatalf("nonce lifetime %s", d)
		}
		if err := f.svc.nonces.verify(n.Value, f.payer.device, now, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.IssueNonces(ctx(t), f.stranger.user, f.payer.device, 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("someone else's device: %v", err)
	}
	if _, err := f.svc.IssueNonces(ctx(t), f.payer.user, uuid.New(), 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown device: %v", err)
	}
	for _, n := range []int{0, MaxNonces + 1} {
		if _, err := f.svc.IssueNonces(ctx(t), f.payer.user, f.payer.device, n); !errors.Is(err, ErrRequest) {
			t.Fatalf("%d nonces: %v", n, err)
		}
	}
	if err := f.binder.Revoke(ctx(t), f.payer.user, f.payer.device, "lost"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IssueNonces(ctx(t), f.payer.user, f.payer.device, 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked device: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no nonce key":        {},
		"short nonce key":     {NonceKeys: [][]byte{make([]byte, 31)}},
		"negative duration":   {NonceKeys: [][]byte{nonceKey}, LiveTTL: -time.Second},
		"hold beyond 31 days": {NonceKeys: [][]byte{nonceKey}, ClaimTTL: 30 * 24 * time.Hour},
		"unknown currency":    {NonceKeys: [][]byte{nonceKey}, Limits: map[string]Limits{"XXX": {Gesture: 1, GestureWindow: 1}}},
		"window below limit":  {NonceKeys: [][]byte{nonceKey}, Limits: map[string]Limits{"EUR": {Gesture: 10, GestureWindow: 5}}},
		"negative count":      {NonceKeys: [][]byte{nonceKey}, GestureCount: -1},
	} {
		if err := cfg.defaults(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(Config{NonceKeys: [][]byte{nonceKey}}, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("New without dependencies")
	}
	if l := DefaultLimits("JPY"); l.Gesture != 100 || l.GestureWindow != 250 {
		t.Fatalf("JPY limits %+v", l)
	}
	if l := DefaultLimits("KWD"); l.Gesture != 100_000 || l.GestureWindow != 250_000 {
		t.Fatalf("KWD limits %+v", l)
	}
	if l := DefaultLimits("XXX"); l != (Limits{}) {
		t.Fatalf("unknown currency limits %+v", l)
	}
}

func TestMetricsCountTransitions(t *testing.T) {
	f := newFixture(t, nil)
	reg := prometheus.NewRegistry()
	cfg := f.cfg
	cfg.Registerer = reg
	f.svc = f.service(cfg, nil)
	in := f.create(f.flick(5_00))
	if _, err := f.catch(f.payee, in.ID, true); err != nil {
		t.Fatal(err)
	}
	f.ledger.inject("hold", 1, false)
	if _, err := f.svc.Create(ctx(t), f.sign(f.flick(5_00))); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	f.aborted(f.flick(100_01), ReasonGestureLimit)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			for _, l := range m.GetLabel() {
				key += "|" + l.GetValue()
			}
			got[key] = m.GetCounter().GetValue()
		}
	}
	check := func(name string, labels map[string]string, want float64) {
		t.Helper()
		for _, mf := range families {
			if mf.GetName() != name {
				continue
			}
			for _, m := range mf.GetMetric() {
				match := true
				for _, l := range m.GetLabel() {
					if v, ok := labels[l.GetName()]; ok && v != l.GetValue() {
						match = false
					}
				}
				if match && len(m.GetLabel()) >= len(labels) {
					if v := m.GetCounter().GetValue(); v != want {
						t.Fatalf("%s%v = %v, want %v", name, labels, v, want)
					}
					return
				}
			}
		}
		t.Fatalf("%s%v not found in %v", name, labels, got)
	}
	check("bilyon_intents_transitions_total", map[string]string{"state": "created", "reason": ""}, 2)
	check("bilyon_intents_transitions_total", map[string]string{"state": "held", "reason": ""}, 1)
	check("bilyon_intents_transitions_total", map[string]string{"state": "settled", "reason": ""}, 1)
	check("bilyon_intents_transitions_total", map[string]string{"state": "aborted", "reason": "gesture_limit"}, 1)
	check("bilyon_intents_dependency_failures_total", map[string]string{"op": "hold"}, 1)
}
