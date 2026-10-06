package pgledger_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgregory.net/rapid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// TestConcurrentMixedWorkloadKeepsInvariants hammers a small set of accounts
// with operations in every lock-order-hostile combination: opposite-direction
// transfers, holds posted across each other, multi-leg entries in random leg
// order and reversals. Any deadlock that escaped the retry loop, lost update
// or overdraft makes the test fail.
func TestConcurrentMixedWorkloadKeepsInvariants(t *testing.T) {
	e := newEnv(t)
	const accounts, workers, iterations = 8, 16, 120
	users := make([]uuid.UUID, accounts)
	for i := range users {
		users[i] = e.user()
		e.fund(users[i], 1_000_000)
	}
	var mu sync.Mutex
	var entries []uuid.UUID
	acceptable := func(err error) bool {
		return err == nil || errors.Is(err, ledger.ErrInsufficientFunds) || errors.Is(err, ledger.ErrAlreadyReversed) ||
			errors.Is(err, ledger.ErrHoldNotPending)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := range workers {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(w), 42))
			pick := func() (uuid.UUID, uuid.UUID) {
				i := rng.IntN(accounts)
				j := (i + 1 + rng.IntN(accounts-1)) % accounts
				return users[i], users[j]
			}
			for range iterations {
				var err error
				switch rng.IntN(5) {
				case 0, 1:
					from, to := pick()
					var en ledger.Entry
					if en, err = e.transfer(from, to, 1+rng.Int64N(20_000)); err == nil {
						mu.Lock()
						entries = append(entries, en.ID)
						mu.Unlock()
					}
				case 2:
					from, to := pick()
					var h ledger.Hold
					if h, err = e.hold(from, 1+rng.Int64N(20_000), time.Minute); err == nil {
						if rng.IntN(3) == 0 {
							_, err = e.eng.VoidHold(e.ctx(), ledger.VoidHold{IdempotencyKey: e.key("v"), HoldID: h.ID})
						} else {
							_, err = e.eng.PostHold(e.ctx(), ledger.PostHold{IdempotencyKey: e.key("p"), HoldID: h.ID,
								Credits: []ledger.Posting{{AccountID: to, Amount: 1 + rng.Int64N(h.Amount)}}})
						}
					}
				case 3:
					perm := rng.Perm(accounts)[:4]
					amt := 1 + rng.Int64N(5_000)
					_, err = e.eng.Transfer(e.ctx(), ledger.Transfer{IdempotencyKey: e.key("m"), Kind: "split",
						Postings: []ledger.Posting{
							{AccountID: users[perm[0]], Amount: -3 * amt}, {AccountID: users[perm[1]], Amount: amt},
							{AccountID: users[perm[2]], Amount: amt}, {AccountID: users[perm[3]], Amount: amt},
						}})
				case 4:
					mu.Lock()
					var target uuid.UUID
					if len(entries) > 0 {
						target = entries[rng.IntN(len(entries))]
					}
					mu.Unlock()
					if target != uuid.Nil {
						_, err = e.eng.Reverse(e.ctx(), ledger.Reverse{IdempotencyKey: e.key("r"), EntryID: target})
					}
				}
				if !acceptable(err) {
					errCh <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("unexpected error under concurrency: %v", err)
	}
	var total int64
	for _, u := range users {
		total += e.balance(u).Posted
	}
	if total != accounts*1_000_000 {
		t.Fatalf("money created or destroyed: users hold %d, want %d", total, accounts*1_000_000)
	}
	e.audit()
}

// ---------------------------------------------------------------------------
// Property-based state machine (rapid): the engine must agree with a trivial
// in-memory model after every random step.
// ---------------------------------------------------------------------------

type modelHold struct {
	account uuid.UUID
	amount  int64
}

type modelEntry struct {
	entry    ledger.Entry
	reversed bool
}

type ledgerModel struct {
	e        *env
	accounts []uuid.UUID
	posted   map[uuid.UUID]int64
	pending  map[uuid.UUID]int64
	holds    map[uuid.UUID]modelHold
	entries  []*modelEntry
}

func (m *ledgerModel) available(a uuid.UUID) int64 { return m.posted[a] - m.pending[a] }

func (m *ledgerModel) apply(en ledger.Entry, sign int64) {
	for _, p := range en.Postings {
		m.posted[p.AccountID] += sign * p.Amount
	}
}

func (m *ledgerModel) transfer(t *rapid.T) {
	i := rapid.IntRange(0, len(m.accounts)-1).Draw(t, "from")
	j := rapid.IntRange(0, len(m.accounts)-2).Draw(t, "to")
	if j >= i {
		j++
	}
	from, to := m.accounts[i], m.accounts[j]
	amt := rapid.Int64Range(1, 6_000).Draw(t, "amount")
	en, err := m.e.transfer(from, to, amt)
	if want := m.available(from) >= amt; want != (err == nil) {
		t.Fatalf("transfer %d with available %d: err=%v", amt, m.available(from), err)
	}
	if err != nil {
		if !errors.Is(err, ledger.ErrInsufficientFunds) {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	m.apply(en, 1)
	m.entries = append(m.entries, &modelEntry{entry: en})
}

func (m *ledgerModel) hold(t *rapid.T) {
	a := m.accounts[rapid.IntRange(0, len(m.accounts)-1).Draw(t, "account")]
	amt := rapid.Int64Range(1, 6_000).Draw(t, "amount")
	h, err := m.e.hold(a, amt, time.Hour)
	if want := m.available(a) >= amt; want != (err == nil) {
		t.Fatalf("hold %d with available %d: err=%v", amt, m.available(a), err)
	}
	if err == nil {
		m.pending[a] += amt
		m.holds[h.ID] = modelHold{a, amt}
	}
}

func (m *ledgerModel) pickHold(t *rapid.T) (uuid.UUID, modelHold, bool) {
	if len(m.holds) == 0 {
		return uuid.Nil, modelHold{}, false
	}
	ids := make([]uuid.UUID, 0, len(m.holds))
	for id := range m.holds {
		ids = append(ids, id)
	}
	sortIDs(ids)
	id := ids[rapid.IntRange(0, len(ids)-1).Draw(t, "hold")]
	return id, m.holds[id], true
}

func (m *ledgerModel) post(t *rapid.T) {
	id, h, ok := m.pickHold(t)
	if !ok {
		t.Skip("no pending hold")
	}
	var credits []ledger.Posting
	remaining := rapid.Int64Range(1, h.amount).Draw(t, "posted")
	for _, a := range m.accounts {
		if a == h.account || remaining == 0 {
			continue
		}
		part := rapid.Int64Range(1, remaining).Draw(t, "part")
		credits = append(credits, ledger.Posting{AccountID: a, Amount: part})
		remaining -= part
	}
	if remaining > 0 {
		credits[0].Amount += remaining
	}
	res, err := m.e.eng.PostHold(m.e.ctx(), ledger.PostHold{IdempotencyKey: m.e.key("p"), HoldID: id, Credits: credits})
	if err != nil {
		t.Fatalf("post hold: %v", err)
	}
	m.pending[h.account] -= h.amount
	delete(m.holds, id)
	m.apply(res.Entry, 1)
	m.entries = append(m.entries, &modelEntry{entry: res.Entry})
}

func (m *ledgerModel) void(t *rapid.T) {
	id, h, ok := m.pickHold(t)
	if !ok {
		t.Skip("no pending hold")
	}
	if _, err := m.e.eng.VoidHold(m.e.ctx(), ledger.VoidHold{IdempotencyKey: m.e.key("v"), HoldID: id}); err != nil {
		t.Fatalf("void: %v", err)
	}
	m.pending[h.account] -= h.amount
	delete(m.holds, id)
}

func (m *ledgerModel) reverse(t *rapid.T) {
	var candidates []*modelEntry
	for _, me := range m.entries {
		if !me.reversed && me.entry.Kind != ledger.EntryKindReversal {
			candidates = append(candidates, me)
		}
	}
	if len(candidates) == 0 {
		t.Skip("nothing to reverse")
	}
	me := candidates[rapid.IntRange(0, len(candidates)-1).Draw(t, "entry")]
	want := true
	for _, p := range me.entry.Postings {
		if p.Amount > 0 && m.available(p.AccountID) < p.Amount && m.isModelled(p.AccountID) {
			want = false
		}
	}
	rev, err := m.e.eng.Reverse(m.e.ctx(), ledger.Reverse{IdempotencyKey: m.e.key("r"), EntryID: me.entry.ID})
	if want != (err == nil) {
		t.Fatalf("reverse: want success=%v, err=%v", want, err)
	}
	if err == nil {
		me.reversed = true
		m.apply(rev, 1)
		m.entries = append(m.entries, &modelEntry{entry: rev})
	}
}

func (m *ledgerModel) isModelled(a uuid.UUID) bool {
	for _, x := range m.accounts {
		if x == a {
			return true
		}
	}
	return false
}

func (m *ledgerModel) check(t *rapid.T) {
	for _, a := range m.accounts {
		b, err := m.e.eng.Balance(m.e.ctx(), a)
		if err != nil {
			t.Fatal(err)
		}
		if b.Posted != m.posted[a] || b.Pending != m.pending[a] {
			t.Fatalf("account %s: engine posted=%d pending=%d, model posted=%d pending=%d",
				a, b.Posted, b.Pending, m.posted[a], m.pending[a])
		}
	}
}

func sortIDs(ids []uuid.UUID) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j].String() < ids[j-1].String(); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

func TestPropertyEngineMatchesModel(t *testing.T) {
	e := newEnv(t)
	rapid.Check(t, func(rt *rapid.T) {
		m := &ledgerModel{e: e, posted: map[uuid.UUID]int64{}, pending: map[uuid.UUID]int64{}, holds: map[uuid.UUID]modelHold{}}
		for range 3 {
			a := e.user()
			amt := rapid.Int64Range(0, 20_000).Draw(rt, "initial")
			if amt > 0 {
				e.fund(a, amt)
			}
			m.accounts = append(m.accounts, a)
			m.posted[a] = amt
		}
		rt.Repeat(map[string]func(*rapid.T){
			"transfer": m.transfer,
			"hold":     m.hold,
			"post":     m.post,
			"void":     m.void,
			"reverse":  m.reverse,
			"":         m.check,
		})
	})
	e.audit()
}

// ---------------------------------------------------------------------------
// Least privilege and tamper detection
// ---------------------------------------------------------------------------

func TestRuntimeRoleCannotTamperWithBalancesOrHistory(t *testing.T) {
	e := newEnv(t)
	if _, err := e.pool.Exec(e.ctx(), migrations.Grants); err != nil {
		t.Fatalf("apply grants: %v", err)
	}
	cfg := e.pool.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE bilyon_app")
		return err
	}
	appPool, err := pgxpool.NewWithConfig(e.ctx(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer appPool.Close()
	app := &env{t: t, pool: appPool, eng: pgledger.New(appPool), bank: e.bank}

	// The full command surface works under the runtime role.
	alice, bob := app.user(), app.user()
	app.fund(alice, 10_000)
	if _, err := app.transfer(alice, bob, 1_000); err != nil {
		t.Fatal(err)
	}
	h, err := app.hold(alice, 500, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.eng.PostHold(app.ctx(), ledger.PostHold{IdempotencyKey: "p", HoldID: h.ID,
		Credits: []ledger.Posting{{AccountID: bob, Amount: 400}}}); err != nil {
		t.Fatal(err)
	}
	opened, err := app.eng.OpenReserve(app.ctx(), ledger.OpenReserve{IdempotencyKey: "res", FundingAccountID: alice,
		Amount: 2_000, Purpose: "offline_allowance"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.eng.ReleaseReserve(app.ctx(), ledger.ReleaseReserve{IdempotencyKey: "rel", ReserveID: opened.Reserve.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.eng.SetFrozen(app.ctx(), ledger.SetFrozen{IdempotencyKey: "f", AccountID: bob, Frozen: true, Reason: "kyc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.eng.ExpireHolds(app.ctx(), 10); err != nil {
		t.Fatal(err)
	}
	app.audit()

	for _, sql := range []string{
		"UPDATE account_balances SET balance_minor = balance_minor + 1000000",
		"UPDATE account_balances SET pending_minor = 0",
		"DELETE FROM postings",
		"UPDATE postings SET amount_minor = 1",
		"UPDATE accounts SET floor_minor = -1000000",
		"UPDATE holds SET amount_minor = 1",
		"INSERT INTO account_balances (account_id, stripe) VALUES (gen_random_uuid(), 0)",
	} {
		_, err := appPool.Exec(app.ctx(), sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: want permission denied (42501), got %v", sql, err)
		}
	}
}

func TestAuditDetectsTampering(t *testing.T) {
	e := newEnv(t)
	alice := e.user()
	e.fund(alice, 1_000)
	e.audit()
	// A superuser edits a balance row directly, bypassing the journal.
	if _, err := e.pool.Exec(e.ctx(), `UPDATE account_balances SET balance_minor = balance_minor + 7 WHERE account_id = $1`, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(e.ctx(), `UPDATE account_balances SET frozen = true WHERE account_id = $1`, e.bank); err != nil {
		t.Fatal(err)
	}
	r, err := e.eng.Audit(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, d := range r.Discrepancies {
		found[d.Check] = true
	}
	for _, check := range []string{"balance_matches_postings", "currency_sums_to_zero", "frozen_flag_in_sync"} {
		if !found[check] {
			t.Errorf("audit missed %s: %+v", check, r.Discrepancies)
		}
	}
	if r.OK() || r.Entries != 1 || r.Accounts != 2 {
		t.Fatalf("report: %+v", r)
	}
}
