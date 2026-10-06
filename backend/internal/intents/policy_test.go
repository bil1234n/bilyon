package intents

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
)

// aborted creates th and expects a durable abort with reason and no hold.
func (f *fixture) aborted(th *throw, reason string) *Intent {
	f.t.Helper()
	req := f.sign(th)
	in, err := f.svc.Create(ctx(f.t), req)
	if err != nil {
		f.t.Fatalf("%s: %v", reason, err)
	}
	wantState(f.t, in, StateAborted, reason)
	if in.ResolvedAt == nil {
		f.t.Fatalf("%s: unresolved", reason)
	}
	again, err := f.svc.Create(ctx(f.t), req)
	if err != nil || again.ID != in.ID || again.State != StateAborted {
		f.t.Fatalf("%s: replay %v %v", reason, again, err)
	}
	return in
}

func TestPolicyRefusalsAbort(t *testing.T) {
	f := newFixture(t, nil)
	// No such subject.
	th := f.flick(25_00)
	th.req.PayeeSubject = "bil_0000000000000000000Z"
	th.ta.PayeeRef = identity.PayeeRef(th.req.PayeeSubject)
	if in := f.aborted(th, ReasonPayeeUnknown); in.PayeeID != uuid.Nil || in.PayeeSubject != th.req.PayeeSubject {
		t.Fatalf("unknown payee %+v", in)
	}
	// Paying oneself.
	th = f.flick(25_00)
	th.req.PayeeSubject, th.ta.PayeeRef = f.payer.subject, identity.PayeeRef(f.payer.subject)
	th.ta.PARVersion = f.version(f.payer)
	f.aborted(th, ReasonSelfPayment)
	// PAYEE_CHANGED: the payee's entry moved after the payer verified it.
	th = f.flick(25_00)
	if _, err := f.dir.UpdateProfile(ctx(t), f.payee.user, identity.Profile{Name: "Bruno B."}); err != nil {
		t.Fatal(err)
	}
	f.aborted(th, ReasonPayeeChanged)
	// The payee only receives dollars.
	if _, err := f.dir.UpdateProfile(ctx(t), f.payee.user, identity.Profile{Currencies: []string{"USD"},
		DefaultCurrency: "USD"}); err != nil {
		t.Fatal(err)
	}
	f.aborted(f.flick(25_00), ReasonPayeeCurrency)
	if _, err := f.dir.UpdateProfile(ctx(t), f.payee.user, identity.Profile{Currencies: []string{"EUR", "USD"}}); err != nil {
		t.Fatal(err)
	}
	// More than the balance, and a currency the payer holds none of.
	th = f.flick(2_000_00).handle(f.payer)
	f.aborted(th, ReasonInsufficientFunds)
	th = f.flick(10_00)
	th.ta.Currency, th.req.Currency = "USD", "USD"
	f.aborted(th, ReasonInsufficientFunds)
	// The payer's ledger account is frozen.
	acct, err := f.accts.Get(ctx(t), f.payer.user, "EUR")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pg.SetFrozen(ctx(t), ledger.SetFrozen{IdempotencyKey: "freeze:" + uuid.NewString(),
		AccountID: acct.AccountID, Frozen: true, Reason: "fraud review"}); err != nil {
		t.Fatal(err)
	}
	f.aborted(f.flick(10_00), ReasonAccountFrozen)
	if _, err := f.pg.SetFrozen(ctx(t), ledger.SetFrozen{IdempotencyKey: "thaw:" + uuid.NewString(),
		AccountID: acct.AccountID, Frozen: false, Reason: "cleared"}); err != nil {
		t.Fatal(err)
	}
	// The payer's or the payee's Bilyon account.
	if _, err := f.pool.Exec(ctx(t), `UPDATE users SET status = 'closed' WHERE user_id = $1`, f.payee.user); err != nil {
		t.Fatal(err)
	}
	f.aborted(f.flick(10_00), ReasonPayeeUnavailable)
	if _, err := f.pool.Exec(ctx(t), `UPDATE users SET status = 'active' WHERE user_id = $1`, f.payee.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx(t), `UPDATE users SET status = 'frozen' WHERE user_id = $1`, f.payer.user); err != nil {
		t.Fatal(err)
	}
	f.aborted(f.flick(10_00), ReasonPayerInactive)

	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	if n := len(f.events(TopicAborted)); n != 9 {
		t.Fatalf("%d aborted events", n)
	}
	var holds int
	if err := f.pool.QueryRow(ctx(t), `SELECT count(*) FROM payment_intents WHERE hold_id IS NOT NULL`).Scan(&holds); err != nil {
		t.Fatal(err)
	}
	if holds != 0 {
		t.Fatalf("%d aborted intents hold funds", holds)
	}
}

func TestGestureLimitAndVelocity(t *testing.T) {
	f := newFixture(t, nil)
	f.aborted(f.flick(100_01), ReasonGestureLimit)
	// K_dev is not bound by the gesture limit.
	big := f.flick(150_00)
	big.signer, big.keyID = f.payer.dev, f.payer.devKey
	wantState(t, f.create(big), StateHeld, "")
	// Five K_gest throws per minute; the sixth is refused.
	for i := 0; i < 5; i++ {
		wantState(t, f.create(f.flick(1_00)), StateHeld, "")
	}
	f.aborted(f.flick(1_00), ReasonVelocity)
	// The window slides.
	f.c.advance(61 * time.Second)
	wantState(t, f.create(f.flick(1_00)), StateHeld, "")
}

func TestGestureAmountWindow(t *testing.T) {
	f := newFixture(t, nil)
	wantState(t, f.create(f.flick(100_00)), StateHeld, "")
	wantState(t, f.create(f.flick(100_00)), StateHeld, "")
	f.aborted(f.flick(60_00), ReasonVelocity) // 260.00 > 250.00
	// Refused throws do not count against the window.
	wantState(t, f.create(f.flick(50_00)), StateHeld, "")
	f.aborted(f.flick(1), ReasonVelocity)
	// Neither does another device's use, nor another currency.
	f.fund(f.payer, "USD", 500_00)
	usd := f.flick(100_00)
	usd.ta.Currency, usd.req.Currency = "USD", "USD"
	wantState(t, f.create(usd), StateHeld, "")
}

func TestPerIntentAndDailyCaps(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.Limits = map[string]Limits{"EUR": {Gesture: 100_00, GestureWindow: 250_00, PerIntent: 300_00, Daily: 500_00}}
	})
	dev := func(amount int64) *throw {
		th := f.flick(amount)
		th.signer, th.keyID = f.payer.dev, f.payer.devKey
		return th
	}
	f.aborted(dev(300_01), ReasonAmountLimit)
	first := f.create(dev(300_00))
	wantState(t, first, StateHeld, "")
	wantState(t, f.create(dev(200_00)), StateHeld, "")
	f.aborted(dev(1), ReasonDailyLimit)
	// A returned throw gives its share back.
	if _, err := f.svc.Cancel(ctx(t), f.payer.user, first.ID); err != nil {
		t.Fatal(err)
	}
	wantState(t, f.create(dev(300_00)), StateHeld, "")
	// The cap is rolling.
	f.c.advance(24*time.Hour + time.Minute)
	wantState(t, f.create(dev(300_00).handle(f.payer)), StateSettled, "")
}

func TestCrossCurrencyThrow(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	if _, err := f.dir.UpdateProfile(ctx(t), f.payee.user, identity.Profile{Currencies: []string{"USD"},
		DefaultCurrency: "USD"}); err != nil {
		t.Fatal(err)
	}
	q := f.fxQuote(client, f.payer.user, 100_00, time.Minute)
	th := f.flick(100_00)
	th.signer, th.keyID = f.payer.dev, f.payer.devKey
	th.ta.QuoteID, th.req.QuoteID = q.ID.String(), q.ID
	in := f.create(th)
	wantState(t, in, StateHeld, "")
	if in.QuoteID != q.ID || in.PayeeAmount != q.AmountOut || in.PayeeCurrency != "USD" || in.Currency != "EUR" ||
		!in.HoldExpiresAt.Equal(in.LiveUntil.Add(time.Hour)) {
		t.Fatalf("intent %+v", in)
	}
	c, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, c, StateSettled, "")
	if len(c.EntryIDs) != 2 || c.PayeeAmount != q.AmountOut {
		t.Fatalf("settled %+v", c)
	}
	f.wantBalance(f.payer, "EUR", 900_00, 900_00)
	f.wantBalance(f.payee, "USD", q.AmountOut, q.AmountOut)
	if got, x, err := client.GetQuote(ctx(t), f.payer.user, q.ID); err != nil || got.State != "booked" ||
		x == nil || x.AmountOut != q.AmountOut {
		t.Fatalf("quote %+v %+v %v", got, x, err)
	}
}

func TestQuoteRefusals(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	withQuote := func(amount int64, q uuid.UUID) *throw {
		th := f.flick(amount)
		th.signer, th.keyID = f.payer.dev, f.payer.devKey
		th.ta.QuoteID, th.req.QuoteID = q.String(), q
		return th
	}
	// The rate lock ends before the catch window does.
	short := f.fxQuote(client, f.payer.user, 50_00, 20*time.Second)
	f.aborted(withQuote(50_00, short.ID), ReasonQuoteInvalid)
	// Someone else's quote, a quote for another amount, an unknown quote.
	f.fund(f.stranger, "EUR", 100_00)
	theirs := f.fxQuote(client, f.stranger.user, 50_00, time.Minute)
	f.aborted(withQuote(50_00, theirs.ID), ReasonQuoteInvalid)
	other := f.fxQuote(client, f.payer.user, 49_00, time.Minute)
	f.aborted(withQuote(50_00, other.ID), ReasonQuoteInvalid)
	f.aborted(withQuote(50_00, uuid.New()), ReasonQuoteInvalid)
	// A quote that converts from another currency than the one paid in.
	f.fund(f.payer, "USD", 100_00)
	eur := f.fxQuote(client, f.payer.user, 50_00, time.Minute)
	usd := withQuote(50_00, eur.ID)
	usd.ta.Currency, usd.req.Currency = "USD", "USD"
	f.aborted(usd, ReasonQuoteInvalid)
	// A quote the payer already executed elsewhere.
	spent := f.fxQuote(client, f.payer.user, 20_00, time.Minute)
	src, err := f.accts.Get(ctx(t), f.payer.user, "EUR")
	if err != nil {
		t.Fatal(err)
	}
	dst, err := f.accts.Ensure(ctx(t), f.payer.user, "USD")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExecuteQuote(ctx(t), fx.ExecuteRequest{QuoteID: spent.ID, Signature: spent.Signature,
		UserID: f.payer.user, SourceAccount: src.AccountID, DestinationAccount: dst.AccountID}); err != nil {
		t.Fatal(err)
	}
	f.aborted(withQuote(20_00, spent.ID), ReasonQuoteInvalid)
	// A drop cannot convert: nobody knows the payee's currency.
	drop := f.flick(50_00).drop()
	q := f.fxQuote(client, f.payer.user, 50_00, 2*time.Minute)
	drop.ta.QuoteID, drop.req.QuoteID = q.ID.String(), q.ID
	f.aborted(drop, ReasonQuoteInvalid)
	// A payment that settles at once only needs the quote to be open now.
	quick := f.fxQuote(client, f.payer.user, 30_00, 10*time.Second)
	in := f.create(withQuote(30_00, quick.ID).handle(f.payer))
	wantState(t, in, StateSettled, "")
	f.wantBalance(f.payee, "USD", quick.AmountOut, quick.AmountOut)
	// Without an FX service no quote is usable.
	f.svc = f.service(f.cfg, nil)
	q = f.fxQuote(client, f.payer.user, 10_00, time.Minute)
	f.aborted(withQuote(10_00, q.ID), ReasonQuoteInvalid)
}

func TestCrossCurrencyThrowCannotWaitForAClaim(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	q := f.fxQuote(client, f.payer.user, 100_00, 5*time.Minute)
	th := f.flick(100_00)
	th.signer, th.keyID = f.payer.dev, f.payer.devKey
	th.ta.QuoteID, th.req.QuoteID = q.ID.String(), q.ID
	in := f.create(th)
	if in.OnTimeout != TimeoutAsync {
		t.Fatalf("timeout %s", in.OnTimeout)
	}
	f.c.advance(31 * time.Second)
	f.sweep()
	wantState(t, f.state(in.ID), StateVoided, ReasonUncaught)
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
}

func TestQuoteExpiredAtTheCatch(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	q := f.fxQuote(client, f.payer.user, 100_00, time.Minute)
	th := f.flick(100_00)
	th.signer, th.keyID = f.payer.dev, f.payer.devKey
	th.ta.QuoteID, th.req.QuoteID = q.ID.String(), q.ID
	in := f.create(th)
	// The FX engine's clock passes the quote's expiry while the coin flies.
	f.fxc.advance(61 * time.Second)
	out, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, out, StateVoided, ReasonFXExpired)
	if out.CaughtAt == nil {
		t.Fatal("the catch is recorded")
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	f.wantBalance(f.payee, "USD", 0, 0)
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrState) {
		t.Fatalf("catch after the failed conversion: %v", err)
	}
}

func TestFXPayoutPendingCompletesLater(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	q := f.fxQuote(client, f.payer.user, 100_00, time.Minute)
	th := f.flick(100_00)
	th.signer, th.keyID = f.payer.dev, f.payer.devKey
	th.ta.QuoteID, th.req.QuoteID = q.ID.String(), q.ID
	in := f.create(th)
	// The dollar book cannot pay out: the hold is already converted into
	// the euro book, so the intent must wait, never return.
	freeze := func(frozen bool) {
		t.Helper()
		if _, err := f.pg.SetFrozen(ctx(t), ledger.SetFrozen{IdempotencyKey: "book:" + uuid.NewString(),
			AccountID: f.fxbooks["USD"], Frozen: frozen, Reason: "treasury"}); err != nil {
			t.Fatal(err)
		}
	}
	freeze(true)
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("payout pending: %v", err)
	}
	wantState(t, f.state(in.ID), StateCaught, "")
	if h := f.hold(in); h.State != ledger.HoldPosted {
		t.Fatalf("hold %+v", h)
	}
	f.c.advance(16 * time.Second)
	if r := f.sweep(); r.Failed != 1 {
		t.Fatalf("sweep while frozen %+v", r)
	}
	wantState(t, f.state(in.ID), StateCaught, "")
	freeze(false)
	f.c.advance(16 * time.Second)
	if r := f.sweep(); r.Finished != 1 {
		t.Fatalf("sweep after thaw %+v", r)
	}
	wantState(t, f.state(in.ID), StateSettled, "")
	f.wantBalance(f.payee, "USD", q.AmountOut, q.AmountOut)
	f.wantBalance(f.payer, "EUR", 900_00, 900_00)
}

func TestFXHoldPostedOutsideTheIntent(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	q := f.fxQuote(client, f.payer.user, 100_00, time.Minute)
	th := f.flick(100_00)
	th.signer, th.keyID = f.payer.dev, f.payer.devKey
	th.ta.QuoteID, th.req.QuoteID = q.ID.String(), q.ID
	in := f.create(th)
	acct := f.fund(f.stranger, "EUR", 1)
	if _, err := f.pg.PostHold(ctx(t), ledger.PostHold{IdempotencyKey: "elsewhere:" + uuid.NewString(), HoldID: in.HoldID,
		Kind: "manual.adjustment", Credits: []ledger.Posting{{AccountID: acct, Amount: 100_00}}}); err != nil {
		t.Fatal(err)
	}
	out, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, out, StateVoided, ReasonFXFailed)
	f.wantBalance(f.payee, "USD", 0, 0)
}

func TestFXReturningIntentWhoseHoldTheEngineConvertedSettles(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	q := f.fxQuote(client, f.payer.user, 100_00, time.Minute)
	th := f.flick(100_00)
	th.signer, th.keyID = f.payer.dev, f.payer.devKey
	th.ta.QuoteID, th.req.QuoteID = q.ID.String(), q.ID
	in := f.create(th)
	// The engine converts the hold, the payout stalls, and the intent is
	// then (wrongly) marked as returning.
	freeze := func(frozen bool) {
		t.Helper()
		if _, err := f.pg.SetFrozen(ctx(t), ledger.SetFrozen{IdempotencyKey: "book:" + uuid.NewString(),
			AccountID: f.fxbooks["USD"], Frozen: frozen, Reason: "treasury"}); err != nil {
			t.Fatal(err)
		}
	}
	freeze(true)
	if _, err := f.catch(f.payee, in.ID, true); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx(t), `UPDATE payment_intents SET state = 'voiding', reason = 'fx_failed'
		WHERE intent_id = $1`, in.ID); err != nil {
		t.Fatal(err)
	}
	freeze(false)
	f.c.advance(16 * time.Second)
	f.sweep()
	wantState(t, f.state(in.ID), StateSettled, "")
	f.wantBalance(f.payee, "USD", q.AmountOut, q.AmountOut)
}

func TestFXRequoteAtTheCatch(t *testing.T) {
	f := newFixture(t, nil)
	client := f.withFX()
	q := f.fxQuote(client, f.payer.user, 100_00, time.Minute)
	th := f.flick(100_00)
	th.signer, th.keyID = f.payer.dev, f.payer.devKey
	th.ta.QuoteID, th.req.QuoteID = q.ID.String(), q.ID
	in := f.create(th)
	// The market falls far beyond the breaker while the coin flies.
	if err := f.fxg.SetLadder("eur-usd", []fx.Level{{Size: 1_000_000_00, Rate: "0.9000"}}, f.fxc.now()); err != nil {
		t.Fatal(err)
	}
	out, err := f.catch(f.payee, in.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, out, StateVoided, ReasonFXRequote)
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
	f.wantBalance(f.payee, "USD", 0, 0)
}

func TestStaleDeviceIntegrityAborts(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.IntegrityMaxAge = time.Hour })
	f.c.advance(2 * time.Hour)
	f.aborted(f.flick(10_00), ReasonIntegrityStale)
	// A fresh Play Integrity verdict restores payments from the device.
	ch, err := f.binder.Begin(ctx(t), f.payer.user, f.payer.device, devicebind.PurposeIntegrity)
	if err != nil {
		t.Fatal(err)
	}
	fresh := func(v *devicesim.Verdict) { v.Timestamp = f.c.now() }
	if _, err := f.binder.RefreshIntegrity(ctx(t), f.payer.user, ch.FlowID, devicebind.IntegrityProof{
		IntegrityToken: f.payer.phone.IntegrityToken(ch.Challenge, devicesim.Point(t, f.payer.dev), fresh)}); err != nil {
		t.Fatal(err)
	}
	wantState(t, f.create(f.flick(10_00)), StateHeld, "")
}
