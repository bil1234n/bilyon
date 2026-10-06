package tbledger_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/tbledger"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

func newAccount(kind ledger.AccountKind, currency string, floor *int64) ledger.Account {
	return ledger.Account{ID: ledger.NewID(), Kind: kind, Currency: currency, Floor: floor, Stripes: 1,
		CreatedAt: time.Now().UTC()}
}

func entry(kind string, legs ...ledger.PostingRecord) ledger.Entry {
	for i := range legs {
		if legs[i].Currency == "" {
			legs[i].Currency = "EUR"
		}
	}
	return ledger.Entry{ID: ledger.NewID(), Kind: kind, CreatedAt: time.Now().UTC(), Postings: legs}
}

func leg(a ledger.Account, amount int64) ledger.PostingRecord {
	return ledger.PostingRecord{AccountID: a.ID, Currency: a.Currency, Amount: amount}
}

func wantTB(t *testing.T, d *tbledger.Driver, a ledger.Account, posted, pending int64) {
	t.Helper()
	bals, err := d.Balances([]ledger.Account{a})
	if err != nil {
		t.Fatal(err)
	}
	b, ok := bals[a.ID]
	if !ok {
		t.Fatalf("account %s missing in TigerBeetle", a.ID)
	}
	if b.Posted != posted || b.Pending != pending {
		t.Fatalf("account %s: posted %d pending %d, want %d/%d", a.ID, b.Posted, b.Pending, posted, pending)
	}
}

func envelope(t *testing.T, topic string, data any) outbox.Envelope {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return outbox.Envelope{SpecVersion: "1.0", ID: uuid.NewString(), Type: topic, Data: raw}
}

func TestDriverMirrorsAccountsEntriesAndReplays(t *testing.T) {
	t.Parallel()
	d := openDriver(t)
	bank := newAccount(ledger.KindNostro, "EUR", nil)
	alice := newAccount(ledger.KindUser, "EUR", ptr(0))
	bob := newAccount(ledger.KindUser, "EUR", ptr(0))
	recv := newAccount(ledger.KindReceivable, "EUR", ptr(-500))
	for _, a := range []ledger.Account{bank, alice, bob, recv} {
		if err := d.CreateAccount(a); err != nil {
			t.Fatal(err)
		}
		if err := d.CreateAccount(a); err != nil { // replay
			t.Fatalf("account replay: %v", err)
		}
	}
	wantTB(t, d, recv, 0, 0) // limit pre-funding is not a balance

	deposit := entry("deposit", leg(bank, -1000), leg(alice, 1000))
	split := entry("split", leg(alice, -600), leg(bob, 400), leg(bank, 200))
	for _, en := range []ledger.Entry{deposit, split} {
		if err := d.ApplyEntry(en); err != nil {
			t.Fatal(err)
		}
	}
	for _, en := range []ledger.Entry{deposit, split} {
		if err := d.ApplyEntry(en); err != nil {
			t.Fatalf("entry replay: %v", err)
		}
	}
	wantTB(t, d, bank, -800, 0)
	wantTB(t, d, alice, 400, 0)
	wantTB(t, d, bob, 400, 0)

	// The receivable may go down to its floor, and no further.
	if err := d.ApplyEntry(entry("clawback", leg(recv, -500), leg(bob, 500))); err != nil {
		t.Fatal(err)
	}
	wantTB(t, d, recv, -500, 0)
	if err := d.ApplyEntry(entry("clawback", leg(recv, -1), leg(bob, 1))); !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("debit beyond the floor: %v", err)
	}
	if err := d.ApplyEntry(entry("overdraft", leg(alice, -401), leg(bob, 401))); !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("overdraft: %v", err)
	}
	wantTB(t, d, alice, 400, 0)
	if err := d.ApplyEntry(entry("ghost", leg(newAccount(ledger.KindUser, "EUR", ptr(0)), -1), leg(bob, 1))); !errors.Is(err, ledger.ErrNotFound) {
		t.Fatalf("missing account: %v", err)
	}
	if err := d.CreateAccount(ledger.Account{ID: bob.ID, Kind: ledger.KindMerchant, Currency: "EUR", Floor: ptr(0)}); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("account recreated with another kind: %v", err)
	}
}

func TestDriverDetectsPartlyExistingChains(t *testing.T) {
	t.Parallel()
	d := openDriver(t)
	bank := newAccount(ledger.KindNostro, "EUR", nil)
	a := newAccount(ledger.KindUser, "EUR", nil)
	b := newAccount(ledger.KindUser, "EUR", nil)
	for _, acct := range []ledger.Account{bank, a, b} {
		if err := d.CreateAccount(acct); err != nil {
			t.Fatal(err)
		}
	}
	en := entry("pair", leg(bank, -10), leg(a, 10))
	if err := d.ApplyEntry(en); err != nil {
		t.Fatal(err)
	}
	// Same entry id, one more flow: the first transfer exists, the rest of
	// the chain does not, so this must not count as a replay.
	grown := entry("pair", leg(bank, -15), leg(a, 10), leg(b, 5))
	grown.ID = en.ID
	if err := d.ApplyEntry(grown); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("partly existing chain: %v", err)
	}
	wantTB(t, d, b, 0, 0)
}

func TestDriverHoldLifecycle(t *testing.T) {
	t.Parallel()
	d := openDriver(t)
	bank := newAccount(ledger.KindNostro, "EUR", nil)
	payer := newAccount(ledger.KindUser, "EUR", ptr(0))
	merchant := newAccount(ledger.KindMerchant, "EUR", ptr(0))
	fee := newAccount(ledger.KindFee, "EUR", nil)
	for _, a := range []ledger.Account{bank, payer, merchant, fee} {
		if err := d.CreateAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.ApplyEntry(entry("deposit", leg(bank, -1000), leg(payer, 1000))); err != nil {
		t.Fatal(err)
	}
	h := ledger.Hold{ID: ledger.NewID(), AccountID: payer.ID, Currency: "EUR", Amount: 700, State: ledger.HoldPending,
		ExpiresAt: time.Now().Add(time.Minute)}
	if err := d.PlaceHold(h); err != nil {
		t.Fatal(err)
	}
	if err := d.PlaceHold(h); err != nil { // replay: checked against the existing transfer
		t.Fatalf("hold replay: %v", err)
	}
	wantTB(t, d, payer, 1000, 700)
	other := h
	other.Amount = 1
	if err := d.PlaceHold(other); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("hold replay with another amount: %v", err)
	}

	// Post 600 of 700: 550 to the merchant, 50 fee; 100 is released.
	post := entry("capture", leg(payer, -600), leg(merchant, 550), leg(fee, 50))
	post.HoldID = &h.ID
	if err := d.ApplyEntry(post); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyEntry(post); err != nil {
		t.Fatalf("post replay: %v", err)
	}
	wantTB(t, d, payer, 400, 0)
	wantTB(t, d, merchant, 550, 0)
	wantTB(t, d, fee, 50, 0)
	if err := d.VoidHold(h); !errors.Is(err, ledger.ErrHoldNotPending) {
		t.Fatalf("void after post: %v", err)
	}

	v := ledger.Hold{ID: ledger.NewID(), AccountID: payer.ID, Currency: "EUR", Amount: 300, ExpiresAt: time.Now().Add(time.Minute)}
	if err := d.PlaceHold(v); err != nil {
		t.Fatal(err)
	}
	wantTB(t, d, payer, 400, 300)
	if err := d.PlaceHold(ledger.Hold{ID: ledger.NewID(), AccountID: payer.ID, Currency: "EUR", Amount: 101,
		ExpiresAt: time.Now().Add(time.Minute)}); !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("hold beyond available: %v", err)
	}
	for range 2 {
		if err := d.VoidHold(v); err != nil {
			t.Fatalf("void: %v", err)
		}
	}
	wantTB(t, d, payer, 400, 0)
}

func TestDriverFallsBackWhenTigerBeetleExpiredTheHold(t *testing.T) {
	t.Parallel()
	d := openDriver(t, tbledger.WithHoldGrace(0))
	m := tbledger.NewMirror(d)
	bank := newAccount(ledger.KindNostro, "EUR", nil)
	payer := newAccount(ledger.KindUser, "EUR", ptr(0))
	shop := newAccount(ledger.KindMerchant, "EUR", ptr(0))
	ctx := context.Background()
	for _, a := range []ledger.Account{bank, payer, shop} {
		if err := m.Apply(ctx, envelope(t, ledger.TopicAccountCreated, a)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Apply(ctx, envelope(t, ledger.TopicEntryPosted, entry("deposit", leg(bank, -100), leg(payer, 100)))); err != nil {
		t.Fatal(err)
	}
	// Expires in one second without grace: TigerBeetle times it out itself.
	h := ledger.Hold{ID: ledger.NewID(), AccountID: payer.ID, Currency: "EUR", Amount: 80, State: ledger.HoldPending,
		ExpiresAt: time.Now().Add(time.Second)}
	if err := m.Apply(ctx, envelope(t, ledger.TopicHoldPlaced, h)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, func() bool {
		bals, err := d.Balances([]ledger.Account{payer})
		return err == nil && bals[payer.ID].Pending == 0
	}, "TigerBeetle to expire the hold")
	post := entry("capture", leg(payer, -80), leg(shop, 80))
	post.HoldID = &h.ID
	for range 2 { // the replay must recognise the fallback chain
		if err := m.Apply(ctx, envelope(t, ledger.TopicEntryPosted, post)); err != nil {
			t.Fatalf("post after TigerBeetle expiry: %v", err)
		}
	}
	wantTB(t, d, payer, 20, 0)
	wantTB(t, d, shop, 80, 0)
	// Voiding a hold TigerBeetle already expired is a no-op.
	h2 := ledger.Hold{ID: ledger.NewID(), AccountID: payer.ID, Currency: "EUR", Amount: 10, ExpiresAt: time.Now().Add(time.Second)}
	if err := m.Apply(ctx, envelope(t, ledger.TopicHoldPlaced, h2)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, func() bool {
		bals, err := d.Balances([]ledger.Account{payer})
		return err == nil && bals[payer.ID].Pending == 0
	}, "TigerBeetle to expire the second hold")
	if err := m.Apply(ctx, envelope(t, ledger.TopicHoldExpired, h2)); err != nil {
		t.Fatalf("expire after TigerBeetle expiry: %v", err)
	}
}

// TestMirrorNeverSubmitsDoomedTransfers is the reason the mirror checks
// before it writes: TigerBeetle permanently fails a transfer id after a
// transient error, so an entry rejected for missing funds must still apply
// once the funds arrive.
func TestMirrorNeverSubmitsDoomedTransfers(t *testing.T) {
	t.Parallel()
	d := openDriver(t)
	m := tbledger.NewMirror(d)
	ctx := context.Background()
	bank := newAccount(ledger.KindNostro, "EUR", nil)
	alice := newAccount(ledger.KindUser, "EUR", ptr(0))
	bob := newAccount(ledger.KindUser, "EUR", ptr(0))
	pay := entry("p2p", leg(alice, -50), leg(bob, 50))

	if err := m.Apply(ctx, envelope(t, ledger.TopicEntryPosted, pay)); !errors.Is(err, tbledger.ErrDiverged) {
		t.Fatalf("entry before its accounts: %v", err)
	}
	for _, a := range []ledger.Account{bank, alice, bob} {
		if err := m.Apply(ctx, envelope(t, ledger.TopicAccountCreated, a)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Apply(ctx, envelope(t, ledger.TopicEntryPosted, pay)); !errors.Is(err, tbledger.ErrDiverged) {
		t.Fatalf("entry before its funding: %v", err)
	}
	h := ledger.Hold{ID: ledger.NewID(), AccountID: alice.ID, Currency: "EUR", Amount: 30, ExpiresAt: time.Now().Add(time.Minute)}
	if err := m.Apply(ctx, envelope(t, ledger.TopicHoldPlaced, h)); !errors.Is(err, tbledger.ErrDiverged) {
		t.Fatalf("hold before its funding: %v", err)
	}
	if err := m.Apply(ctx, envelope(t, ledger.TopicHoldVoided, h)); !errors.Is(err, tbledger.ErrDiverged) {
		t.Fatalf("void of an unmirrored hold: %v", err)
	}
	post := entry("capture", leg(alice, -30), leg(bob, 30))
	post.HoldID = &h.ID
	if err := m.Apply(ctx, envelope(t, ledger.TopicEntryPosted, post)); !errors.Is(err, tbledger.ErrDiverged) {
		t.Fatalf("post of an unmirrored hold: %v", err)
	}

	// Once the prerequisites exist, the very same events apply.
	if err := m.Apply(ctx, envelope(t, ledger.TopicEntryPosted, entry("deposit", leg(bank, -100), leg(alice, 100)))); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []outbox.Envelope{
		envelope(t, ledger.TopicEntryPosted, pay),
		envelope(t, ledger.TopicHoldPlaced, h),
		envelope(t, ledger.TopicEntryPosted, post),
	} {
		if err := m.Apply(ctx, ev); err != nil {
			t.Fatalf("%s after prerequisites: %v", ev.Type, err)
		}
		if err := m.Apply(ctx, ev); err != nil {
			t.Fatalf("%s replay: %v", ev.Type, err)
		}
	}
	wantTB(t, d, alice, 20, 0)
	wantTB(t, d, bob, 80, 0)

	// A void after the post is a divergence, reported without writing.
	if err := m.Apply(ctx, envelope(t, ledger.TopicHoldVoided, h)); !errors.Is(err, ledger.ErrHoldNotPending) {
		t.Fatalf("void after post: %v", err)
	}
	// Events without a balance effect are accepted.
	for _, topic := range []string{ledger.TopicHoldPosted, ledger.TopicAccountFrozen, ledger.TopicReserveOpened, ledger.TopicReserveReleased} {
		if err := m.Apply(ctx, envelope(t, topic, map[string]string{"x": "y"})); err != nil {
			t.Fatalf("%s: %v", topic, err)
		}
	}
	if err := m.Apply(ctx, outbox.Envelope{Type: ledger.TopicEntryPosted, Data: []byte("{")}); err == nil {
		t.Fatal("undecodable entry accepted")
	}
}
