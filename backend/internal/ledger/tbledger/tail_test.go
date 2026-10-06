package tbledger_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/tbledger"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// TestShadowFollowsConcurrentLedgerWorkload drives the PostgreSQL ledger
// with every operation it supports, from concurrent workers contending for
// the same limited accounts, while the shadow tails. TigerBeetle enforces
// the same limits, so any event applied out of serialization order would
// fail and block the shadow; any lost or duplicated event would show up in
// the exact reconciliations taken during and after the run.
func TestShadowFollowsConcurrentLedgerWorkload(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	tl, reg := e.tailer(tbledger.TailerConfig{BatchSize: 200})

	bank := e.account(ledger.KindNostro, "EUR", nil, 1)
	bankUSD := e.account(ledger.KindNostro, "USD", nil, 1)
	fxEUR := e.account(ledger.KindFXBook, "EUR", nil, 1)
	fxUSD := e.account(ledger.KindFXBook, "USD", nil, 1)
	fee := e.account(ledger.KindFee, "EUR", nil, 8)
	recv := e.account(ledger.KindReceivable, "EUR", ptr(-50_000), 1)
	merchant := e.account(ledger.KindMerchant, "EUR", nil, 1)
	users := make([]ledger.Account, 6)
	for i := range users {
		users[i] = e.account(ledger.KindUser, "EUR", nil, 1)
		e.mustTransfer("deposit", ledger.Posting{AccountID: bank.ID, Amount: -100_000}, ledger.Posting{AccountID: users[i].ID, Amount: 100_000})
	}
	usd := make([]ledger.Account, 3)
	for i := range usd {
		usd[i] = e.account(ledger.KindUser, "USD", nil, 1)
		e.mustTransfer("deposit", ledger.Posting{AccountID: bankUSD.ID, Amount: -50_000}, ledger.Posting{AccountID: usd[i].ID, Amount: 50_000})
	}

	acceptable := func(err error) bool {
		for _, ok := range []error{ledger.ErrInsufficientFunds, ledger.ErrAlreadyReversed, ledger.ErrNotReversible,
			ledger.ErrHoldNotPending, ledger.ErrHoldExpired, ledger.ErrAccountFrozen, ledger.ErrReserveClosed} {
			if errors.Is(err, ok) {
				return true
			}
		}
		return err == nil
	}
	var mu sync.Mutex
	var entries []uuid.UUID
	record := func(en ledger.Entry, err error) error {
		if err == nil {
			mu.Lock()
			entries = append(entries, en.ID)
			mu.Unlock()
		}
		return err
	}
	stop := make(chan struct{})
	var bg sync.WaitGroup
	bg.Go(func() { // the hold expiry sweeper
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := e.eng.ExpireHolds(context.Background(), 100); err != nil {
				t.Errorf("expire holds: %v", err)
			}
		}
	})

	const workers, iterations = 8, 60
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(w), 7))
			ctx := context.Background()
			pickUsers := func() (ledger.Account, ledger.Account) {
				i := rng.IntN(len(users))
				return users[i], users[(i+1+rng.IntN(len(users)-1))%len(users)]
			}
			for range iterations {
				var err error
				switch rng.IntN(10) {
				case 0:
					from, to := pickUsers()
					amt := 1 + rng.Int64N(30_000)
					err = record(e.transfer("p2p", ledger.Posting{AccountID: from.ID, Amount: -amt}, ledger.Posting{AccountID: to.ID, Amount: amt}))
				case 1:
					from, to := pickUsers()
					amt := 1 + rng.Int64N(10_000)
					err = record(e.transfer("split", ledger.Posting{AccountID: from.ID, Amount: -3 * amt},
						ledger.Posting{AccountID: to.ID, Amount: 2 * amt}, ledger.Posting{AccountID: fee.ID, Amount: amt}))
				case 2:
					from, _ := pickUsers()
					eur := 1 + rng.Int64N(20_000)
					err = record(e.transfer("fx.convert",
						ledger.Posting{AccountID: from.ID, Amount: -eur}, ledger.Posting{AccountID: fxEUR.ID, Amount: eur},
						ledger.Posting{AccountID: fxUSD.ID, Amount: -(eur * 108 / 100)}, ledger.Posting{AccountID: usd[rng.IntN(len(usd))].ID, Amount: eur * 108 / 100}))
				case 3, 4, 5:
					from, _ := pickUsers()
					expiry := time.Minute
					if rng.IntN(3) == 0 {
						expiry = 1100 * time.Millisecond // the shortest expiry the ledger accepts, plus margin
					}
					var h ledger.Hold
					h, err = e.eng.PlaceHold(ctx, ledger.PlaceHold{IdempotencyKey: e.key("h"), AccountID: from.ID,
						Amount: 1 + rng.Int64N(20_000), Reason: "throw", ExpiresAt: time.Now().Add(expiry)})
					if err != nil || expiry < time.Minute {
						break
					}
					if rng.IntN(3) == 0 {
						_, err = e.eng.VoidHold(ctx, ledger.VoidHold{IdempotencyKey: e.key("v"), HoldID: h.ID, Reason: "cancel"})
						break
					}
					total := 1 + rng.Int64N(h.Amount)
					cut := total / 10
					credits := []ledger.Posting{{AccountID: merchant.ID, Amount: total - cut}}
					if cut > 0 {
						credits = append(credits, ledger.Posting{AccountID: fee.ID, Amount: cut})
					}
					var res ledger.PostHoldResult
					res, err = e.eng.PostHold(ctx, ledger.PostHold{IdempotencyKey: e.key("p"), HoldID: h.ID, Kind: "capture", Credits: credits})
					err = record(res.Entry, err)
				case 6:
					from, _ := pickUsers()
					var res ledger.OpenReserveResult
					res, err = e.eng.OpenReserve(ctx, ledger.OpenReserve{IdempotencyKey: e.key("r"), FundingAccountID: from.ID,
						Amount: 1 + rng.Int64N(10_000), Purpose: "offline"})
					if err == nil && rng.IntN(2) == 0 {
						_, err = e.eng.ReleaseReserve(ctx, ledger.ReleaseReserve{IdempotencyKey: e.key("rr"), ReserveID: res.Reserve.ID})
					}
				case 7:
					mu.Lock()
					var target uuid.UUID
					if len(entries) > 0 {
						target = entries[rng.IntN(len(entries))]
					}
					mu.Unlock()
					if target != uuid.Nil {
						_, err = e.eng.Reverse(ctx, ledger.Reverse{IdempotencyKey: e.key("rev"), EntryID: target})
					}
				case 8:
					u, _ := pickUsers()
					if _, err = e.eng.SetFrozen(ctx, ledger.SetFrozen{IdempotencyKey: e.key("f"), AccountID: u.ID, Frozen: true, Reason: "review"}); err == nil {
						_, err = e.eng.SetFrozen(ctx, ledger.SetFrozen{IdempotencyKey: e.key("uf"), AccountID: u.ID, Frozen: false, Reason: "cleared"})
					}
				case 9:
					to, _ := pickUsers()
					amt := 1 + rng.Int64N(5_000)
					err = record(e.transfer("offline.shortfall", ledger.Posting{AccountID: recv.ID, Amount: -amt},
						ledger.Posting{AccountID: to.ID, Amount: amt}))
				}
				if !acceptable(err) {
					t.Errorf("worker %d: %v", w, err)
					return
				}
			}
		})
	}
	// Exact cuts while the workers run.
	for range 3 {
		time.Sleep(150 * time.Millisecond)
		e.reconciled(tl)
	}
	wg.Wait()
	time.Sleep(1200 * time.Millisecond) // let the short holds expire
	close(stop)
	bg.Wait()
	if _, err := e.eng.ExpireHolds(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	e.reconciled(tl)
	if n := failures(t, reg); n != 0 {
		t.Fatalf("the shadow failed %v times; every event must apply in order", n)
	}
	if n := counterSum(t, reg, "bilyon_tbshadow_events_total"); n < 400 {
		t.Fatalf("only %v events mirrored; the workload did not exercise the shadow", n)
	}
	report, err := e.eng.Audit(context.Background())
	if err != nil || !report.OK() {
		t.Fatalf("ledger audit: %+v %v", report, err)
	}
}

func TestBootstrapImportsExistingLedger(t *testing.T) {
	e := newEnv(t)
	ctx := ctxFor(t)
	bank := e.account(ledger.KindNostro, "EUR", nil, 1)
	recv := e.account(ledger.KindReceivable, "EUR", ptr(-1_000), 1)
	fee := e.account(ledger.KindFee, "EUR", nil, 4)
	alice := e.account(ledger.KindUser, "EUR", nil, 1)
	bob := e.account(ledger.KindUser, "EUR", nil, 1)
	idle := e.account(ledger.KindUser, "JPY", nil, 1)
	e.mustTransfer("deposit", ledger.Posting{AccountID: bank.ID, Amount: -5_000}, ledger.Posting{AccountID: alice.ID, Amount: 5_000})
	e.mustTransfer("clawback", ledger.Posting{AccountID: recv.ID, Amount: -700}, ledger.Posting{AccountID: bob.ID, Amount: 700})
	e.mustTransfer("fee", ledger.Posting{AccountID: alice.ID, Amount: -100}, ledger.Posting{AccountID: fee.ID, Amount: 100})
	keep, err := e.eng.PlaceHold(ctx, ledger.PlaceHold{IdempotencyKey: e.key("h"), AccountID: alice.ID, Amount: 1_500,
		Reason: "throw", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	drop, err := e.eng.PlaceHold(ctx, ledger.PlaceHold{IdempotencyKey: e.key("h"), AccountID: alice.ID, Amount: 400,
		Reason: "throw", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}

	stats := e.bootstrap()
	if stats.Accounts != 6 || stats.Balances != 5 || stats.Holds != 2 || stats.CatchUp != 0 {
		t.Fatalf("bootstrap stats %+v", stats)
	}
	if accts, err := e.d.Accounts([]uuid.UUID{idle.ID}); err != nil || len(accts) != 1 {
		t.Fatalf("zero-balance account not imported: %v %v", accts, err)
	}
	tl, reg := e.tailer(tbledger.TailerConfig{})
	e.reconciled(tl)

	// Holds imported at bootstrap resolve through the normal events.
	if _, err := e.eng.PostHold(ctx, ledger.PostHold{IdempotencyKey: e.key("p"), HoldID: keep.ID, Kind: "capture",
		Credits: []ledger.Posting{{AccountID: bob.ID, Amount: 1_200}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.eng.VoidHold(ctx, ledger.VoidHold{IdempotencyKey: e.key("v"), HoldID: drop.ID}); err != nil {
		t.Fatal(err)
	}
	e.mustTransfer("clawback", ledger.Posting{AccountID: recv.ID, Amount: -300}, ledger.Posting{AccountID: bob.ID, Amount: 300})
	e.reconciled(tl)
	if n := failures(t, reg); n != 0 {
		t.Fatalf("%v failures after bootstrap", n)
	}
}

func TestBootstrapCollectsRowsOfInFlightTransactions(t *testing.T) {
	e := newEnv(t)
	ctx := ctxFor(t)
	e.account(ledger.KindNostro, "EUR", nil, 1)

	// Two ledger transactions are in flight while the bootstrap takes its
	// snapshot. The first drew its outbox id before a transaction that has
	// committed (so below the snapshot's highest id: a catch-up row), the
	// second after it (picked up by normal tailing). Neither may be
	// imported, and both must be mirrored.
	begin := func() pgx.Tx {
		tx, err := e.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		return tx
	}
	first := begin()
	below := insertAccount(t, first, ledger.KindUser, "EUR")
	e.account(ledger.KindUser, "EUR", nil, 1)
	second := begin()
	above := insertAccount(t, second, ledger.KindUser, "EUR")

	type result struct {
		stats tbledger.BootstrapStats
		err   error
	}
	done := make(chan result, 1)
	go func() {
		s, err := tbledger.Bootstrap(ctx, e.pool, e.d, tbledger.DefaultConsumer, nil)
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("bootstrap finished while transactions were in flight: %+v %v", r.stats, r.err)
	case <-time.After(500 * time.Millisecond):
	}
	for _, tx := range []pgx.Tx{first, second} {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.stats.Accounts != 2 || r.stats.CatchUp != 1 {
		t.Fatalf("bootstrap stats %+v; want 2 imported accounts and 1 catch-up row", r.stats)
	}
	tl, reg := e.tailer(tbledger.TailerConfig{})
	e.reconciled(tl)
	if accts, err := e.d.Accounts([]uuid.UUID{below.ID, above.ID}); err != nil || len(accts) != 2 {
		t.Fatalf("in-flight accounts in TigerBeetle: %v %v", accts, err)
	}
	if n := failures(t, reg); n != 0 {
		t.Fatalf("%v failures", n)
	}
}

// insertAccount creates an account the way pgledger does, inside tx.
func insertAccount(t *testing.T, tx pgx.Tx, kind ledger.AccountKind, currency string) ledger.Account {
	t.Helper()
	ctx := context.Background()
	a := ledger.Account{ID: ledger.NewID(), Kind: kind, Currency: currency, Floor: ptr(0), Stripes: 1}
	if err := tx.QueryRow(ctx, `INSERT INTO accounts (account_id, kind, currency, floor_minor, stripes, idempotency_key)
		VALUES ($1, $2, $3, 0, 1, $4) RETURNING created_at`, a.ID, a.Kind, a.Currency, "raw-"+a.ID.String()).Scan(&a.CreatedAt); err != nil {
		t.Fatal(err)
	}
	a.CreatedAt = a.CreatedAt.UTC()
	if _, err := outbox.Write(ctx, tx, outbox.Event{Topic: ledger.TopicAccountCreated, Key: "account:" + a.ID.String(), Data: a}); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestBootstrapAndRunGuardTheCursor(t *testing.T) {
	e := newEnv(t)
	ctx := ctxFor(t)
	run := func() error {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tbledger.NewTailer(e.pool, tbledger.NewMirror(e.d), tbledger.TailerConfig{}).Run(c)
	}
	if err := run(); !errors.Is(err, tbledger.ErrNoCursor) {
		t.Fatalf("run without bootstrap: %v", err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO outbox_cursors (consumer, state) VALUES ($1, 'bootstrapping')`, tbledger.DefaultConsumer); err != nil {
		t.Fatal(err)
	}
	if err := run(); !errors.Is(err, tbledger.ErrBootstrapIncomplete) {
		t.Fatalf("run after a crashed bootstrap: %v", err)
	}
	if _, err := tbledger.Bootstrap(ctx, e.pool, e.d, tbledger.DefaultConsumer, nil); !errors.Is(err, tbledger.ErrBootstrapIncomplete) {
		t.Fatalf("bootstrap after a crashed bootstrap: %v", err)
	}
	if err := tbledger.ResetBootstrap(ctx, e.pool, tbledger.DefaultConsumer); err != nil {
		t.Fatal(err)
	}
	if err := tbledger.ResetBootstrap(ctx, e.pool, tbledger.DefaultConsumer); !errors.Is(err, ledger.ErrNotFound) {
		t.Fatalf("second reset: %v", err)
	}
	e.bootstrap()
	if _, err := tbledger.Bootstrap(ctx, e.pool, e.d, tbledger.DefaultConsumer, nil); !errors.Is(err, tbledger.ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap: %v", err)
	}
	if err := tbledger.ResetBootstrap(ctx, e.pool, tbledger.DefaultConsumer); !errors.Is(err, ledger.ErrNotFound) {
		t.Fatalf("reset of a finished bootstrap: %v", err)
	}
}

type cursorRow struct {
	LastID  int64
	Horizon int64
	Gaps    []struct {
		Snapshot string     `json:"snapshot"`
		Ranges   [][2]int64 `json:"ranges"`
	}
}

func readCursor(t *testing.T, e *env) cursorRow {
	t.Helper()
	var c cursorRow
	var raw []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT last_id, horizon, gaps FROM outbox_cursors WHERE consumer = $1`,
		tbledger.DefaultConsumer).Scan(&c.LastID, &c.Horizon, &raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &c.Gaps); err != nil {
		t.Fatal(err)
	}
	return c
}

func gapIDs(c cursorRow) map[int64]bool {
	out := map[int64]bool{}
	for _, g := range c.Gaps {
		for _, r := range g.Ranges {
			for id := r[0]; id <= r[1]; id++ {
				out[id] = true
			}
		}
	}
	return out
}

func outboxID(t *testing.T, tx pgx.Tx) int64 {
	t.Helper()
	var id int64
	if err := tx.QueryRow(context.Background(), `SELECT max(id) FROM outbox`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTailerAppliesLateCommitsAndForgetsRollbacks(t *testing.T) {
	e := newEnv(t)
	ctx := ctxFor(t)
	e.bootstrap()

	slow, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slow.Rollback(context.Background()) }()
	late := insertAccount(t, slow, ledger.KindUser, "EUR")
	lateID := outboxID(t, slow)

	doomed, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	insertAccount(t, doomed, ledger.KindUser, "EUR")
	doomedID := outboxID(t, doomed)

	early := e.account(ledger.KindUser, "EUR", nil, 1) // commits first, with larger ids
	tl, reg := e.tailer(tbledger.TailerConfig{})
	eventually(t, 10*time.Second, func() bool {
		accts, err := e.d.Accounts([]uuid.UUID{early.ID})
		return err == nil && len(accts) == 1
	}, "the committed account to be mirrored")
	eventually(t, 10*time.Second, func() bool {
		gaps := gapIDs(readCursor(t, e))
		return gaps[lateID] && gaps[doomedID]
	}, "both in-flight rows to be recorded as gaps")
	c := readCursor(t, e)
	if c.Horizon >= min(lateID, doomedID) {
		t.Fatalf("horizon %d passes the gaps %d/%d", c.Horizon, lateID, doomedID)
	}
	if accts, _ := e.d.Accounts([]uuid.UUID{late.ID}); len(accts) != 0 {
		t.Fatal("an uncommitted account was mirrored")
	}

	if err := doomed.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := slow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, func() bool {
		accts, err := e.d.Accounts([]uuid.UUID{late.ID})
		return err == nil && len(accts) == 1
	}, "the late commit to be mirrored")
	eventually(t, 10*time.Second, func() bool {
		c := readCursor(t, e)
		return len(c.Gaps) == 0 && c.Horizon == c.LastID
	}, "the gaps to close")
	e.reconciled(tl)
	if n := failures(t, reg); n != 0 {
		t.Fatalf("%v failures", n)
	}
}

func TestTailerBlocksOnDivergenceAndResumes(t *testing.T) {
	e := newEnv(t)
	ctx := ctxFor(t)
	e.bootstrap()
	bank := e.account(ledger.KindNostro, "EUR", nil, 1)
	alice := e.account(ledger.KindUser, "EUR", nil, 1)
	bob := e.account(ledger.KindUser, "EUR", nil, 1)
	// An entry PostgreSQL never committed, injected into the outbox: alice
	// has no funds in TigerBeetle, so the shadow must stop at it.
	bogus := ledger.Entry{ID: ledger.NewID(), Kind: "p2p", CreatedAt: time.Now().UTC(), Postings: []ledger.PostingRecord{
		{AccountID: alice.ID, Currency: "EUR", Amount: -10}, {AccountID: bob.ID, Currency: "EUR", Amount: 10}}}
	var bogusID int64
	if err := pgx.BeginFunc(ctx, e.pool, func(tx pgx.Tx) error {
		if _, err := outbox.Write(ctx, tx, outbox.Event{Topic: ledger.TopicEntryPosted, Key: "bogus", Data: bogus}); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT max(id) FROM outbox`).Scan(&bogusID)
	}); err != nil {
		t.Fatal(err)
	}
	e.mustTransfer("deposit", ledger.Posting{AccountID: bank.ID, Amount: -50}, ledger.Posting{AccountID: bob.ID, Amount: 50})

	tl, reg := e.tailer(tbledger.TailerConfig{})
	eventually(t, 10*time.Second, func() bool { return failures(t, reg) >= 2 }, "the shadow to retry the divergent event")
	if c := readCursor(t, e); c.LastID >= bogusID {
		t.Fatalf("cursor %d moved past the divergent row %d", c.LastID, bogusID)
	}
	if bals, err := e.d.Balances([]ledger.Account{bob}); err != nil || bals[bob.ID].Posted != 0 {
		t.Fatalf("an event after the divergence was applied: %+v %v", bals, err)
	}
	if v := gaugeValue(t, reg, "bilyon_tbshadow_blocked"); v != 1 {
		t.Fatalf("blocked gauge %v", v)
	}
	// The operator removes the bogus event; the shadow resumes in order.
	if _, err := e.pool.Exec(ctx, `DELETE FROM outbox WHERE id = $1`, bogusID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, func() bool {
		bals, err := e.d.Balances([]ledger.Account{bob})
		return err == nil && bals[bob.ID].Posted == 50
	}, "the shadow to resume")
	e.reconciled(tl)
	if v := gaugeValue(t, reg, "bilyon_tbshadow_blocked"); v != 0 {
		t.Fatalf("blocked gauge %v after resuming", v)
	}
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

func TestReconcileReportsDifferences(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	tl, _ := e.tailer(tbledger.TailerConfig{})
	bank := e.account(ledger.KindNostro, "EUR", nil, 1)
	alice := e.account(ledger.KindUser, "EUR", nil, 1)
	e.mustTransfer("deposit", ledger.Posting{AccountID: bank.ID, Amount: -100}, ledger.Posting{AccountID: alice.ID, Amount: 100})
	e.reconciled(tl)

	// A transfer written to TigerBeetle behind the shadow's back.
	stray := entry("stray", leg(bank, -7), leg(alice, 7))
	if err := e.d.ApplyEntry(stray); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ms, err := tl.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]tbledger.Mismatch{}
	for _, m := range ms {
		got[m.AccountID] = m
	}
	if len(ms) != 2 || got[alice.ID].TBPosted != 107 || got[alice.ID].PostgresPosted != 100 || got[bank.ID].TBPosted != -107 {
		t.Fatalf("mismatches %+v", ms)
	}
	if got[alice.ID].String() == "" || got[alice.ID].MissingInTB {
		t.Fatalf("mismatch rendering %+v", got[alice.ID])
	}
}

func TestTailerBootstrapsAutomatically(t *testing.T) {
	e := newEnv(t)
	bank := e.account(ledger.KindNostro, "EUR", nil, 1)
	alice := e.account(ledger.KindUser, "EUR", nil, 1)
	e.mustTransfer("deposit", ledger.Posting{AccountID: bank.ID, Amount: -250}, ledger.Posting{AccountID: alice.ID, Amount: 250})
	tl, _ := e.tailer(tbledger.TailerConfig{AutoBootstrap: true})
	e.reconciled(tl)
	e.mustTransfer("deposit", ledger.Posting{AccountID: bank.ID, Amount: -50}, ledger.Posting{AccountID: alice.ID, Amount: 50})
	e.reconciled(tl)
}

func TestOneWriterPerConsumerWithStandbyTakeover(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	mirror := tbledger.NewMirror(e.d)
	// start runs a tailer; stop cancels it and returns Run's result (once).
	start := func(cfg tbledger.TailerConfig) (tl *tbledger.Tailer, stop func() error) {
		cfg.PollInterval = 20 * time.Millisecond
		cfg.LockRetry = 50 * time.Millisecond
		tl = tbledger.NewTailer(e.pool, mirror, cfg)
		ctx, cancel := context.WithCancel(context.Background())
		var runErr error
		finished := make(chan struct{})
		go func() {
			runErr = tl.Run(ctx)
			close(finished)
		}()
		stop = func() error {
			cancel()
			<-finished
			return runErr
		}
		t.Cleanup(func() { _ = stop() })
		return tl, stop
	}
	active, stopActive := start(tbledger.TailerConfig{})
	e.reconciled(active) // the active instance holds the lock

	if err := tbledger.NewTailer(e.pool, mirror, tbledger.TailerConfig{LockWait: 300 * time.Millisecond,
		LockRetry: 50 * time.Millisecond}).Run(ctxFor(t)); !errors.Is(err, tbledger.ErrLocked) {
		t.Fatalf("second tailer: %v", err)
	}
	if _, err := tbledger.Bootstrap(ctxFor(t), e.pool, e.d, tbledger.DefaultConsumer, nil); !errors.Is(err, tbledger.ErrLocked) {
		t.Fatalf("bootstrap while tailing: %v", err)
	}

	standby, _ := start(tbledger.TailerConfig{})
	first := e.account(ledger.KindUser, "EUR", nil, 1)
	eventually(t, 10*time.Second, func() bool {
		accts, err := e.d.Accounts([]uuid.UUID{first.ID})
		return err == nil && len(accts) == 1
	}, "the active instance to mirror")
	if err := stopActive(); err != nil {
		t.Fatalf("active tailer: %v", err)
	}
	second := e.account(ledger.KindUser, "EUR", nil, 1)
	eventually(t, 10*time.Second, func() bool {
		accts, err := e.d.Accounts([]uuid.UUID{second.ID})
		return err == nil && len(accts) == 1
	}, "the standby to take over")
	e.reconciled(standby)
}
