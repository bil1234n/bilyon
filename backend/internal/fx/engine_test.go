package fx

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/fxdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, fxdb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

type fixture struct {
	t      *testing.T
	c      *clock
	g      *Graph
	pool   *pgxpool.Pool
	ledger *pgledger.Engine
	eng    *Engine
	cfg    Config
	user   uuid.UUID
	other  uuid.UUID
	acct   map[string]uuid.UUID // the user's accounts
	otherA map[string]uuid.UUID // the other user's accounts
	books  map[string]uuid.UUID
	nostro map[string]uuid.UUID
}

var ledgerCurrencies = []string{"EUR", "USD", "NGN", "JPY"}

func newFixture(t *testing.T, edit func(*Config)) *fixture {
	t.Helper()
	t.Parallel()
	f := &fixture{t: t, c: newClock(), pool: srv.Database(t), user: uuid.New(), other: uuid.New(),
		acct: map[string]uuid.UUID{}, otherA: map[string]uuid.UUID{}, books: map[string]uuid.UUID{},
		nostro: map[string]uuid.UUID{}}
	f.ledger = pgledger.New(srv.DatabaseWith(t, "ledger", ledgerdb.Setup))
	f.g = market(t, f.c, GraphConfig{})
	for _, cur := range ledgerCurrencies {
		f.books[cur] = f.account(ledger.KindFXBook, cur, nil)
		f.nostro[cur] = f.account(ledger.KindNostro, cur, nil)
		f.acct[cur] = f.account(ledger.KindUser, cur, &f.user)
		f.otherA[cur] = f.account(ledger.KindUser, cur, &f.other)
	}
	f.fund(f.acct["EUR"], 1_000_000_00)
	f.fund(f.acct["USD"], 1_000_000_00)
	f.cfg = Config{
		Risk: map[string]PairRisk{"EUR/USD": {SigmaAnnual: 0.07}, "EUR/NGN": {SigmaAnnual: 0.35, JumpBps: 15},
			"USD/JPY": {SigmaAnnual: 0.10, MaxTTL: time.Minute}},
		Keys:    []QuoteKey{{ID: "k2026a", Secret: []byte("0123456789abcdef0123456789abcdef")}},
		FXBooks: f.books, Now: f.c.now,
	}
	if edit != nil {
		edit(&f.cfg)
	}
	f.eng = f.engine(f.g)
	f.mids()
	return f
}

func (f *fixture) engine(g *Graph) *Engine {
	f.t.Helper()
	e, err := NewEngine(f.cfg, g, f.pool, f.ledger)
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f *fixture) mids() {
	f.t.Helper()
	for _, m := range []struct{ from, to, rate string }{{"EUR", "USD", "1.0850"}, {"EUR", "NGN", "1681.75"},
		{"USD", "JPY", "149.45"}} {
		if err := f.eng.SetMid(m.from, m.to, m.rate, f.c.now()); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) account(kind ledger.AccountKind, cur string, owner *uuid.UUID) uuid.UUID {
	f.t.Helper()
	a, err := f.ledger.CreateAccount(ctx(f.t), ledger.CreateAccount{IdempotencyKey: "acct:" + uuid.NewString(),
		Kind: kind, Currency: cur, OwnerID: owner})
	if err != nil {
		f.t.Fatal(err)
	}
	return a.ID
}

func (f *fixture) fund(acct uuid.UUID, amount int64) {
	f.t.Helper()
	b, err := f.ledger.Balance(ctx(f.t), acct)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.ledger.Transfer(ctx(f.t), ledger.Transfer{IdempotencyKey: "fund:" + uuid.NewString(), Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: f.nostro[b.Currency], Amount: -amount}, {AccountID: acct, Amount: amount}}}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) balance(acct uuid.UUID) int64 {
	f.t.Helper()
	b, err := f.ledger.Balance(ctx(f.t), acct)
	if err != nil {
		f.t.Fatal(err)
	}
	return b.Posted
}

func (f *fixture) quote(from, to string, amount int64) *Quote {
	f.t.Helper()
	q, err := f.eng.Quote(ctx(f.t), QuoteRequest{UserID: f.user, From: from, To: to, AmountIn: amount, TTL: 30 * time.Second})
	if err != nil {
		f.t.Fatal(err)
	}
	return q
}

func (f *fixture) direct(q *Quote) ExecuteRequest {
	return ExecuteRequest{QuoteID: q.ID, Signature: q.Signature, UserID: f.user, SourceAccount: f.acct[q.From],
		DestinationAccount: f.acct[q.To]}
}

func (f *fixture) reserved(edgeID string) float64 {
	for _, e := range f.g.Edges() {
		if e.Spec.ID == edgeID {
			return e.Reserved
		}
	}
	f.t.Fatalf("no edge %s", edgeID)
	return 0
}

func (f *fixture) state(id uuid.UUID) string {
	f.t.Helper()
	var s string
	if err := f.pool.QueryRow(ctx(f.t), `SELECT state FROM fx_quotes WHERE quote_id = $1`, id).Scan(&s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) events(topic string) []map[string]any {
	f.t.Helper()
	rows, err := f.pool.Query(ctx(f.t), `SELECT payload->'data' FROM outbox WHERE topic = $1 ORDER BY id`, topic)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			f.t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		out = append(out, m)
	}
	return out
}

func TestQuoteLifecycle(t *testing.T) {
	f := newFixture(t, nil)
	q := f.quote("EUR", "USD", 10_000_00)
	switch {
	case q.AmountOut != 10_839_58 || q.ExecOut != 10_850_00: // ⌊10 850.00 · 999 040 ppm⌋
		t.Fatalf("amounts %d / %d", q.AmountOut, q.ExecOut)
	case math.Abs(q.FeeBps-9.6) > 0.01 || q.FeeBps > 10:
		t.Fatalf("all-in cost %.3f bp", q.FeeBps)
	case math.Abs(q.BufferBps-1.59) > 0.01 || q.MarginBps != 8 || q.MidRate != "1.0850" || q.ExecCostBps != 0:
		t.Fatalf("pricing %+v", q)
	case !q.ExpiresAt.Equal(q.CreatedAt.Add(30*time.Second)) || q.State != StateOpen || len(q.Signature) != 32:
		t.Fatalf("quote %+v", q)
	}
	if r := f.reserved("eur-usd-net"); math.Abs(r-10_000_00/1.5) > 1e-6 {
		t.Fatalf("reservation %.2f", r)
	}
	got, x, err := f.eng.Get(ctx(t), f.user, q.ID)
	if err != nil || x != nil || got.AmountOut != q.AmountOut || len(got.Allocations) != 1 {
		t.Fatalf("Get = %+v %v %v", got, x, err)
	}
	if _, _, err := f.eng.Get(ctx(t), f.other, q.ID); !errors.Is(err, ErrUnknownQuote) {
		t.Fatalf("another user's quote: %v", err)
	}

	ex, err := f.eng.Execute(ctx(t), f.direct(q))
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != StateBooked || ex.AmountOut != 10_839_58 || ex.MarketOut != 10_850_00 || ex.PnL != 10_850_00-10_839_58 ||
		len(ex.EntryIDs) != 1 || ex.BookedAt == nil {
		t.Fatalf("execution %+v", ex)
	}
	for acct, want := range map[uuid.UUID]int64{f.acct["EUR"]: 990_000_00, f.books["EUR"]: 10_000_00,
		f.books["USD"]: -10_839_58, f.acct["USD"]: 1_010_839_58} {
		if got := f.balance(acct); got != want {
			t.Fatalf("balance %d, want %d", got, want)
		}
	}
	if r := f.reserved("eur-usd-net"); r != 0 {
		t.Fatalf("reservation left after execution: %.2f", r)
	}
	again, err := f.eng.Execute(ctx(t), f.direct(q))
	if err != nil || again.MarketOut != ex.MarketOut || again.EntryIDs[0] != ex.EntryIDs[0] {
		t.Fatalf("re-execution %+v %v", again, err)
	}
	if f.balance(f.acct["USD"]) != 1_010_839_58 {
		t.Fatal("re-execution moved money twice")
	}
	if ev := f.events(TopicQuoteBooked); len(ev) != 1 || ev[0]["pnl"].(float64) != 1042 {
		t.Fatalf("booked events %v", ev)
	}
	bad := f.direct(q)
	bad.Signature = append([]byte{}, q.Signature...)
	bad.Signature[0] ^= 1
	if _, err := f.eng.Execute(ctx(t), bad); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered: %v", err)
	}
	foreign := f.direct(q)
	foreign.UserID = f.other
	if _, err := f.eng.Execute(ctx(t), foreign); !errors.Is(err, ErrUnknownQuote) {
		t.Fatalf("another user's execution: %v", err)
	}
	moved := f.direct(q)
	moved.DestinationAccount = f.otherA["USD"]
	if _, err := f.eng.Execute(ctx(t), moved); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-execution to another account: %v", err)
	}
	unknown := f.direct(q)
	unknown.QuoteID = uuid.New()
	if _, err := f.eng.Execute(ctx(t), unknown); !errors.Is(err, ErrUnknownQuote) {
		t.Fatalf("unknown quote: %v", err)
	}
}

func TestExecuteWithHold(t *testing.T) {
	f := newFixture(t, nil)
	q := f.quote("EUR", "USD", 2_500_00)
	h, err := f.ledger.PlaceHold(ctx(t), ledger.PlaceHold{IdempotencyKey: "hold:" + q.ID.String(), AccountID: f.acct["EUR"],
		Amount: 3_000_00, Reason: "fx", ExpiresAt: f.c.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// The payee (another user) receives the converted amount.
	ex, err := f.eng.Execute(ctx(t), ExecuteRequest{QuoteID: q.ID, Signature: q.Signature, UserID: f.user, HoldID: h.ID,
		DestinationAccount: f.otherA["USD"]})
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.EntryIDs) != 2 || f.balance(f.otherA["USD"]) != q.AmountOut || f.balance(f.acct["EUR"]) != 1_000_000_00-2_500_00 {
		t.Fatalf("execution %+v, payee %d", ex, f.balance(f.otherA["USD"]))
	}
	posted, err := f.ledger.Hold(ctx(t), h.ID)
	if err != nil || posted.State != ledger.HoldPosted || posted.PostedAmount != 2_500_00 {
		t.Fatalf("hold %+v %v", posted, err)
	}
}

func TestFundingIsCheckedBeforeExecution(t *testing.T) {
	f := newFixture(t, nil)
	q := f.quote("EUR", "USD", 1_000_00)
	small, err := f.ledger.PlaceHold(ctx(t), ledger.PlaceHold{IdempotencyKey: "hold:" + uuid.NewString(), AccountID: f.acct["EUR"],
		Amount: 999_99, Reason: "fx", ExpiresAt: f.c.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	usdHold, err := f.ledger.PlaceHold(ctx(t), ledger.PlaceHold{IdempotencyKey: "hold:" + uuid.NewString(), AccountID: f.acct["USD"],
		Amount: 5_000_00, Reason: "fx", ExpiresAt: f.c.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]ExecuteRequest{
		"another user's source": {SourceAccount: f.otherA["EUR"], DestinationAccount: f.acct["USD"]},
		"source in USD":         {SourceAccount: f.acct["USD"], DestinationAccount: f.acct["USD"]},
		"destination in EUR":    {SourceAccount: f.acct["EUR"], DestinationAccount: f.acct["EUR"]},
		"unknown destination":   {SourceAccount: f.acct["EUR"], DestinationAccount: uuid.New()},
		"hold too small":        {HoldID: small.ID, DestinationAccount: f.acct["USD"]},
		"hold in USD":           {HoldID: usdHold.ID, DestinationAccount: f.acct["USD"]},
		"unknown hold":          {HoldID: uuid.New(), DestinationAccount: f.acct["USD"]},
	}
	for name, req := range cases {
		req.QuoteID, req.Signature, req.UserID = q.ID, q.Signature, f.user
		if _, err := f.eng.Execute(ctx(t), req); !errors.Is(err, ErrFunding) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, req := range map[string]ExecuteRequest{
		"no destination":  {SourceAccount: f.acct["EUR"]},
		"two fundings":    {SourceAccount: f.acct["EUR"], HoldID: small.ID, DestinationAccount: f.acct["USD"]},
		"neither funding": {DestinationAccount: f.acct["USD"]},
	} {
		req.QuoteID, req.Signature, req.UserID = q.ID, q.Signature, f.user
		if _, err := f.eng.Execute(ctx(t), req); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if f.state(q.ID) != StateOpen || f.reserved("eur-usd-net") == 0 {
		t.Fatal("refused funding must leave the quote open with its reservation")
	}
	if _, err := f.eng.Execute(ctx(t), f.direct(q)); err != nil {
		t.Fatalf("valid funding after refusals: %v", err)
	}
}

func TestExpiryReleasesReservations(t *testing.T) {
	f := newFixture(t, nil)
	q1 := f.quote("EUR", "USD", 5_000_00)
	q2 := f.quote("EUR", "USD", 3_000_00)
	f.c.advance(31 * time.Second)
	if _, err := f.eng.Execute(ctx(t), f.direct(q1)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := f.eng.Execute(ctx(t), f.direct(q1)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired again: %v", err)
	}
	if r := f.reserved("eur-usd-net"); math.Abs(r-3_000_00/1.5) > 1e-6 {
		t.Fatalf("reservation %.2f after the first expiry", r)
	}
	n, err := f.eng.Sweep(ctx(t))
	if err != nil || n != 1 || f.state(q2.ID) != StateExpired || f.reserved("eur-usd-net") != 0 {
		t.Fatalf("Sweep = %d, %v, state %s, reserved %.2f", n, err, f.state(q2.ID), f.reserved("eur-usd-net"))
	}
	if _, err := f.eng.Quote(ctx(t), QuoteRequest{UserID: f.user, From: "EUR", To: "USD", AmountIn: 100}); !errors.Is(err, ErrNoMid) {
		t.Fatalf("stale mid: %v", err)
	}
}

func TestReservationsPreventOverpromising(t *testing.T) {
	f := newFixture(t, nil)
	netting := func(q *Quote) (in int64) {
		for _, a := range q.Allocations {
			if a.Venues[0] == "internal" {
				in += a.In
			}
		}
		return in
	}
	var wg sync.WaitGroup
	quotes := make([]*Quote, 2)
	for i := range quotes {
		wg.Go(func() {
			q, err := f.eng.Quote(context.Background(), QuoteRequest{UserID: f.user, From: "EUR", To: "USD",
				AmountIn: 60_000_00, TTL: 30 * time.Second})
			if err != nil {
				t.Error(err)
			}
			quotes[i] = q
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	first, second := quotes[0], quotes[1]
	if second.CreatedAt.Before(first.CreatedAt) || (second.CreatedAt.Equal(first.CreatedAt) && netting(second) > netting(first)) {
		first, second = second, first
	}
	if second.AmountOut >= first.AmountOut {
		t.Fatalf("the second quote promised the same netting liquidity: %d vs %d", second.AmountOut, first.AmountOut)
	}
	if limit := 50_000_00 - float64(netting(first))/1.5; float64(netting(second)) > limit+1 {
		t.Fatalf("second quote used %d of netting depth, limit %.0f", netting(second), limit)
	}
}

func TestFirmQuoteAndBreaker(t *testing.T) {
	f := newFixture(t, nil)
	shift := func(rate string) {
		for _, id := range []string{"eur-usd-net", "eur-usd-a", "eur-usd-b"} {
			if err := f.g.SetLadder(id, []Level{{Size: 1_000_000_00, Rate: rate}}, f.c.now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	q := f.quote("EUR", "USD", 10_000_00)
	shift("1.0796") // a ~50 bp adverse move inside the lock is honoured at a loss
	ex, err := f.eng.Execute(ctx(t), f.direct(q))
	if err != nil || ex.PnL >= 0 || ex.AmountOut != q.AmountOut {
		t.Fatalf("firm quote not honoured: %+v %v", ex, err)
	}
	shift("1.0850")
	q = f.quote("EUR", "USD", 10_000_00)
	shift("1.0500") // a ~3 % gap trips the breaker
	if _, err := f.eng.Execute(ctx(t), f.direct(q)); !errors.Is(err, ErrRequote) {
		t.Fatalf("breaker: %v", err)
	}
	if f.state(q.ID) != StateRequoted || len(f.events(TopicQuoteRequoted)) != 1 {
		t.Fatal("breaker outcome not recorded")
	}
	if _, err := f.eng.Execute(ctx(t), f.direct(q)); !errors.Is(err, ErrRequote) {
		t.Fatalf("requoted quote executed: %v", err)
	}
}

func TestRefusedBookingFailsTheQuote(t *testing.T) {
	f := newFixture(t, nil)
	poor := f.account(ledger.KindUser, "EUR", &f.user)
	q := f.quote("EUR", "USD", 1_000_00)
	req := f.direct(q)
	req.SourceAccount = poor
	_, err := f.eng.Execute(ctx(t), req)
	if !errors.Is(err, ErrFailed) || !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("err = %v", err)
	}
	if f.state(q.ID) != StateFailed || len(f.events(TopicQuoteFailed)) != 1 {
		t.Fatal("failure not recorded")
	}
	for _, e := range f.g.Edges() {
		if e.Executed != 0 || e.Reserved != 0 {
			t.Fatalf("depth not returned on %s: executed %.2f reserved %.2f", e.Spec.ID, e.Executed, e.Reserved)
		}
	}
	if _, err := f.eng.Execute(ctx(t), req); !errors.Is(err, ErrFailed) {
		t.Fatalf("failed quote re-executed: %v", err)
	}
}

// TestInterruptedPayoutResumes: the USD fx book is at its floor (a position
// limit), so the payout leg is refused after the hold was posted. The quote
// stays executing; once treasury tops the book up, a successor engine
// resumes the booking and the client's retry sees it booked.
func TestInterruptedPayoutResumes(t *testing.T) {
	var limited uuid.UUID
	f := newFixture(t, func(c *Config) {
		books := map[string]uuid.UUID{}
		for k, v := range c.FXBooks {
			books[k] = v
		}
		c.FXBooks = books
	})
	zero := int64(0)
	a, err := f.ledger.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: "acct:" + uuid.NewString(),
		Kind: ledger.KindFXBook, Currency: "USD", Floor: &zero})
	if err != nil {
		t.Fatal(err)
	}
	limited = a.ID
	f.cfg.FXBooks["USD"] = limited
	f.eng = f.engine(f.g)
	f.mids()
	q := f.quote("EUR", "USD", 1_000_00)
	h, err := f.ledger.PlaceHold(ctx(t), ledger.PlaceHold{IdempotencyKey: "hold:" + q.ID.String(), AccountID: f.acct["EUR"],
		Amount: 1_000_00, Reason: "fx", ExpiresAt: f.c.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	req := ExecuteRequest{QuoteID: q.ID, Signature: q.Signature, UserID: f.user, HoldID: h.ID, DestinationAccount: f.acct["USD"]}
	if _, err := f.eng.Execute(ctx(t), req); err == nil || !errors.Is(err, ledger.ErrInsufficientFunds) {
		t.Fatalf("payout from a book at its floor: %v", err)
	}
	if f.state(q.ID) != StateExecuting || f.balance(f.books["EUR"]) != 1_000_00 {
		t.Fatalf("state %s, EUR book %d", f.state(q.ID), f.balance(f.books["EUR"]))
	}
	f.c.advance(time.Minute)
	pending, err := f.eng.Pending(ctx(t), 30*time.Second)
	if err != nil || len(pending) != 1 || pending[0] != q.ID {
		t.Fatalf("Pending = %v, %v", pending, err)
	}
	f.fund(limited, 5_000_00) // treasury restores the book
	successor := f.engine(market(t, f.c, GraphConfig{}))
	ex, err := successor.Resume(ctx(t), q.ID)
	if err != nil || ex.State != StateBooked || len(ex.EntryIDs) != 2 {
		t.Fatalf("Resume = %+v, %v", ex, err)
	}
	if f.balance(f.acct["USD"]) != 1_000_000_00+q.AmountOut || f.balance(limited) != 5_000_00-q.AmountOut {
		t.Fatalf("payout %d, book %d", f.balance(f.acct["USD"]), f.balance(limited))
	}
	if again, err := f.eng.Execute(ctx(t), req); err != nil || again.State != StateBooked {
		t.Fatalf("retry = %+v, %v", again, err)
	}
	if _, err := successor.Resume(ctx(t), q.ID); err != nil {
		t.Fatalf("resuming a booked quote: %v", err)
	}
}

func TestRecoverRebuildsReservations(t *testing.T) {
	f := newFixture(t, nil)
	q1 := f.quote("EUR", "USD", 20_000_00)
	q2 := f.quote("EUR", "NGN", 1_000_00)
	before := map[string]float64{}
	for _, e := range f.g.Edges() {
		before[e.Spec.ID] = e.Reserved
	}
	g := market(t, f.c, GraphConfig{})
	successor := f.engine(g)
	executing, err := successor.Recover(ctx(t))
	if err != nil || len(executing) != 0 {
		t.Fatalf("Recover = %v, %v", executing, err)
	}
	for _, e := range g.Edges() {
		if math.Abs(e.Reserved-before[e.Spec.ID]) > 1e-6 {
			t.Fatalf("%s reserved %.4f, want %.4f", e.Spec.ID, e.Reserved, before[e.Spec.ID])
		}
	}
	// Recover is idempotent.
	if _, err := successor.Recover(ctx(t)); err != nil {
		t.Fatal(err)
	}
	for _, e := range g.Edges() {
		if math.Abs(e.Reserved-before[e.Spec.ID]) > 1e-6 {
			t.Fatalf("second Recover doubled %s", e.Spec.ID)
		}
	}
	if err := successor.SetMid("EUR", "USD", "1.0850", f.c.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := successor.Execute(ctx(t), f.direct(q1)); err != nil {
		t.Fatalf("executing a recovered quote: %v", err)
	}
	_ = q2
}

func TestSnipingShortensLocks(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.SnipingRatio = 3 })
	var last *Quote
	for range 5 {
		last = f.quote("EUR", "USD", 100_00)
	}
	if ttl := last.ExpiresAt.Sub(last.CreatedAt); ttl != 15*time.Second {
		t.Fatalf("TTL after sniping %s", ttl)
	}
	if want := 2 * LockBufferBps(0.07, 15*time.Second, 2.33); math.Abs(last.BufferBps-want) > 1e-9 {
		t.Fatalf("buffer %.4f, want %.4f", last.BufferBps, want)
	}
}

func TestQuoteValidation(t *testing.T) {
	f := newFixture(t, nil)
	for name, c := range map[string]struct {
		req  QuoteRequest
		want error
	}{
		"no user":         {QuoteRequest{From: "EUR", To: "USD", AmountIn: 1}, ErrRequest},
		"zero amount":     {QuoteRequest{UserID: f.user, From: "EUR", To: "USD"}, ErrRequest},
		"same currencies": {QuoteRequest{UserID: f.user, From: "EUR", To: "EUR", AmountIn: 1}, ErrRequest},
		"unknown":         {QuoteRequest{UserID: f.user, From: "EUR", To: "XXX", AmountIn: 1}, ErrUnknownCurrency},
		"no risk":         {QuoteRequest{UserID: f.user, From: "USD", To: "NGN", AmountIn: 1}, ErrPairNotConfigured},
		"short lock":      {QuoteRequest{UserID: f.user, From: "EUR", To: "USD", AmountIn: 1, TTL: time.Second}, ErrRequest},
		"too deep":        {QuoteRequest{UserID: f.user, From: "USD", To: "JPY", AmountIn: 6_000_000_00}, ErrNoRoute},
	} {
		if _, err := f.eng.Quote(ctx(t), c.req); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	q, err := f.eng.Quote(ctx(t), QuoteRequest{UserID: f.user, From: "USD", To: "JPY", AmountIn: 100_00, TTL: time.Hour})
	if err != nil || q.ExpiresAt.Sub(q.CreatedAt) != time.Minute {
		t.Fatalf("MaxTTL cap: %+v %v", q, err)
	}
	for _, bad := range []string{"0", "-1", "abc"} {
		if err := f.eng.SetMid("EUR", "USD", bad, f.c.now()); err == nil {
			t.Errorf("mid %q accepted", bad)
		}
	}
	if _, err := NewEngine(Config{Keys: []QuoteKey{{ID: "k", Secret: []byte("short")}}}, f.g, f.pool, f.ledger); err == nil {
		t.Error("short quote key accepted")
	}
	if _, err := NewEngine(f.cfg, nil, f.pool, f.ledger); err == nil {
		t.Error("missing graph accepted")
	}
}

// TestKeyRotation: quotes signed by the previous key still execute.
func TestKeyRotation(t *testing.T) {
	f := newFixture(t, nil)
	q := f.quote("EUR", "USD", 100_00)
	f.cfg.Keys = []QuoteKey{{ID: "k2026b", Secret: []byte("fedcba9876543210fedcba9876543210")}, f.cfg.Keys[0]}
	rotated := f.engine(f.g)
	if err := rotated.SetMid("EUR", "USD", "1.0850", f.c.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Execute(ctx(t), f.direct(q)); err != nil {
		t.Fatalf("quote under the previous key: %v", err)
	}
	q2, err := rotated.Quote(ctx(t), QuoteRequest{UserID: f.user, From: "EUR", To: "USD", AmountIn: 100_00})
	if err != nil || q2.KeyID != "k2026b" {
		t.Fatalf("new quotes use the new key: %+v %v", q2, err)
	}
	f.cfg.Keys = f.cfg.Keys[:1]
	dropped := f.engine(f.g)
	if _, err := dropped.Execute(ctx(t), f.direct(q2)); err != nil {
		t.Fatalf("current key: %v", err)
	}
	q3 := f.quote("EUR", "USD", 100_00) // signed by k2026a
	if _, err := dropped.Execute(ctx(t), f.direct(q3)); !errors.Is(err, ErrTampered) {
		t.Fatalf("a retired key still verifies: %v", err)
	}
}

func TestConcurrentExecution(t *testing.T) {
	f := newFixture(t, nil)
	q := f.quote("EUR", "USD", 7_500_00)
	var wg sync.WaitGroup
	results := make([]Execution, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Go(func() { results[i], errs[i] = f.eng.Execute(context.Background(), f.direct(q)) })
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("execution %d: %v", i, errs[i])
		}
		if results[i].EntryIDs[0] != results[0].EntryIDs[0] {
			t.Fatal("executions booked different entries")
		}
	}
	if f.balance(f.acct["USD"]) != 1_000_000_00+q.AmountOut {
		t.Fatalf("money moved %d times", (f.balance(f.acct["USD"])-1_000_000_00)/q.AmountOut)
	}
}
