package migrations_test

// These tests talk to the schema with raw SQL, bypassing the Go engine, to
// prove the database itself enforces the ledger invariants (RFC 0001 §2.3.1).

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, ledgerdb.Setup, &srv)) }

func bg(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func newAccount(t *testing.T, pool *pgxpool.Pool, kind, currency string, floor *int64, stripes int) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := pool.Exec(bg(t), `INSERT INTO accounts (account_id, kind, currency, floor_minor, stripes, idempotency_key)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, kind, currency, floor, stripes, "acct-"+id.String())
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	return id
}

func zero() *int64 { v := int64(0); return &v }

// postEntry inserts an entry with the given postings in one transaction.
func postEntry(ctx context.Context, pool *pgxpool.Pool, kind string, legs map[uuid.UUID]int64, currency string) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		id := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO journal_entries (entry_id, idempotency_key, kind) VALUES ($1, $2, $3)`,
			id, "e-"+id.String(), kind); err != nil {
			return err
		}
		seq := 0
		for acct, amt := range legs {
			if _, err := tx.Exec(ctx, `INSERT INTO postings (entry_id, seq, account_id, stripe, currency, amount_minor)
				VALUES ($1, $2, $3, 0, $4, $5)`, id, seq, acct, currency, amt); err != nil {
				return err
			}
			seq++
		}
		return nil
	})
}

func balance(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) (posted, pending int64) {
	t.Helper()
	if err := pool.QueryRow(bg(t), `SELECT sum(balance_minor), sum(pending_minor) FROM account_balances WHERE account_id = $1`,
		id).Scan(&posted, &pending); err != nil {
		t.Fatal(err)
	}
	return posted, pending
}

func TestBalancesMaterialisedAndFloorsEnforced(t *testing.T) {
	pool := srv.Database(t)
	bank := newAccount(t, pool, "nostro", "EUR", nil, 1) // unbounded: external money enters here
	alice := newAccount(t, pool, "user", "EUR", zero(), 1)
	if err := postEntry(bg(t), pool, "deposit", map[uuid.UUID]int64{bank: -10_000, alice: 10_000}, "EUR"); err != nil {
		t.Fatal(err)
	}
	if p, _ := balance(t, pool, alice); p != 10_000 {
		t.Fatalf("alice balance %d", p)
	}
	err := postEntry(bg(t), pool, "p2p", map[uuid.UUID]int64{alice: -10_001, bank: 10_001}, "EUR")
	if sqlState(err) != "23514" {
		t.Fatalf("overdraft: want check_violation 23514, got %v", err)
	}
	if p, _ := balance(t, pool, alice); p != 10_000 {
		t.Fatalf("failed entry changed the balance: %d", p)
	}
}

func TestUnbalancedAndSingleLegEntriesRejected(t *testing.T) {
	pool := srv.Database(t)
	a := newAccount(t, pool, "nostro", "EUR", nil, 1)
	b := newAccount(t, pool, "nostro", "EUR", nil, 1)
	if err := postEntry(bg(t), pool, "bad", map[uuid.UUID]int64{a: -100, b: 99}, "EUR"); sqlState(err) != "BL003" {
		t.Fatalf("unbalanced: %v", err)
	}
	err := pgx.BeginFunc(bg(t), pool, func(tx pgx.Tx) error {
		id := uuid.Must(uuid.NewV7())
		_, err := tx.Exec(bg(t), `INSERT INTO journal_entries (entry_id, idempotency_key, kind) VALUES ($1, $2, 'empty')`, id, id.String())
		return err
	})
	if sqlState(err) != "BL003" {
		t.Fatalf("entry without postings: %v", err)
	}
}

func TestCurrencyMismatchRejectedByForeignKey(t *testing.T) {
	pool := srv.Database(t)
	eur := newAccount(t, pool, "nostro", "EUR", nil, 1)
	usd := newAccount(t, pool, "nostro", "USD", nil, 1)
	if err := postEntry(bg(t), pool, "bad", map[uuid.UUID]int64{eur: -100, usd: 100}, "EUR"); sqlState(err) != "23503" {
		t.Fatalf("posting in the wrong currency: %v", err)
	}
}

func TestAppendOnly(t *testing.T) {
	pool := srv.Database(t)
	a := newAccount(t, pool, "nostro", "EUR", nil, 1)
	b := newAccount(t, pool, "nostro", "EUR", nil, 1)
	if err := postEntry(bg(t), pool, "ok", map[uuid.UUID]int64{a: -5, b: 5}, "EUR"); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"UPDATE postings SET amount_minor = amount_minor * 2",
		"DELETE FROM postings",
		"TRUNCATE postings",
		"UPDATE journal_entries SET memo = 'x'",
		"DELETE FROM journal_entries",
		"DELETE FROM accounts",
	} {
		if _, err := pool.Exec(bg(t), sql); sqlState(err) != "BL004" {
			t.Errorf("%s: want BL004, got %v", sql, err)
		}
	}
	if _, err := pool.Exec(bg(t), "UPDATE accounts SET currency = 'USD' WHERE account_id = $1", a); sqlState(err) != "BL002" {
		t.Errorf("changing an account currency: %v", err)
	}
}

func TestHoldLifecycleAndStateMachine(t *testing.T) {
	pool := srv.Database(t)
	bank := newAccount(t, pool, "nostro", "EUR", nil, 1)
	alice := newAccount(t, pool, "user", "EUR", zero(), 1)
	if err := postEntry(bg(t), pool, "deposit", map[uuid.UUID]int64{bank: -1_000, alice: 1_000}, "EUR"); err != nil {
		t.Fatal(err)
	}
	hold := uuid.Must(uuid.NewV7())
	insertHold := func(id uuid.UUID, amt int64) error {
		_, err := pool.Exec(bg(t), `INSERT INTO holds (hold_id, idempotency_key, account_id, currency, amount_minor, reason, expires_at)
			VALUES ($1, $2, $3, 'EUR', $4, 'throw_intent', clock_timestamp() + interval '1 minute')`, id, "h-"+id.String(), alice, amt)
		return err
	}
	if err := insertHold(hold, 700); err != nil {
		t.Fatal(err)
	}
	if posted, pending := balance(t, pool, alice); posted != 1_000 || pending != 700 {
		t.Fatalf("after hold: posted %d pending %d", posted, pending)
	}
	if err := insertHold(uuid.Must(uuid.NewV7()), 301); sqlState(err) != "23514" {
		t.Fatalf("hold beyond available: %v", err)
	}
	if err := postEntry(bg(t), pool, "p2p", map[uuid.UUID]int64{alice: -301, bank: 301}, "EUR"); sqlState(err) != "23514" {
		t.Fatalf("spending held funds: %v", err)
	}
	if _, err := pool.Exec(bg(t), "UPDATE holds SET state = 'voided' WHERE hold_id = $1", hold); err != nil {
		t.Fatal(err)
	}
	if _, pending := balance(t, pool, alice); pending != 0 {
		t.Fatalf("void did not release: pending %d", pending)
	}
	if _, err := pool.Exec(bg(t), "UPDATE holds SET state = 'expired' WHERE hold_id = $1", hold); sqlState(err) != "BL005" {
		t.Fatalf("resolving twice: %v", err)
	}
	if _, err := pool.Exec(bg(t), "DELETE FROM holds"); sqlState(err) != "BL004" {
		t.Fatalf("deleting holds: %v", err)
	}
	striped := newAccount(t, pool, "fee", "EUR", nil, 8)
	_, err := pool.Exec(bg(t), `INSERT INTO holds (hold_id, idempotency_key, account_id, currency, amount_minor, reason, expires_at)
		VALUES ($1, 'h-striped', $2, 'EUR', 1, 'throw_intent', clock_timestamp() + interval '1 minute')`, uuid.Must(uuid.NewV7()), striped)
	if sqlState(err) != "BL007" {
		t.Fatalf("hold on striped account: %v", err)
	}
}

func TestFrozenAccountBlocksDebitsButNotCreditsOrReversals(t *testing.T) {
	pool := srv.Database(t)
	bank := newAccount(t, pool, "nostro", "EUR", nil, 1)
	alice := newAccount(t, pool, "user", "EUR", zero(), 1)
	if err := postEntry(bg(t), pool, "deposit", map[uuid.UUID]int64{bank: -500, alice: 500}, "EUR"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(bg(t), "UPDATE accounts SET frozen = true WHERE account_id = $1", alice); err != nil {
		t.Fatal(err)
	}
	if err := postEntry(bg(t), pool, "p2p", map[uuid.UUID]int64{alice: -1, bank: 1}, "EUR"); sqlState(err) != "BL001" {
		t.Fatalf("debit from frozen account: %v", err)
	}
	if err := postEntry(bg(t), pool, "deposit", map[uuid.UUID]int64{bank: -1, alice: 1}, "EUR"); err != nil {
		t.Fatalf("credit to frozen account: %v", err)
	}
	if err := postEntry(bg(t), pool, "reversal", map[uuid.UUID]int64{alice: -1, bank: 1}, "EUR"); err != nil {
		t.Fatalf("reversal from frozen account: %v", err)
	}
}

func TestStripedAccountsSpreadAndAggregate(t *testing.T) {
	pool := srv.Database(t)
	fees := newAccount(t, pool, "fee", "EUR", nil, 4)
	var rows int
	if err := pool.QueryRow(bg(t), "SELECT count(*) FROM account_balances WHERE account_id = $1", fees).Scan(&rows); err != nil || rows != 4 {
		t.Fatalf("striped account has %d balance rows (%v)", rows, err)
	}
	if _, err := pool.Exec(bg(t), `INSERT INTO accounts (account_id, kind, currency, floor_minor, stripes, idempotency_key)
		VALUES ($1, 'fee', 'EUR', 0, 4, 'striped-floor')`, uuid.Must(uuid.NewV7())); sqlState(err) != "23514" {
		t.Fatalf("striped account with a floor: %v", err)
	}
}

func TestBigintOverflowIsAnError(t *testing.T) {
	pool := srv.Database(t)
	a := newAccount(t, pool, "nostro", "EUR", nil, 1)
	b := newAccount(t, pool, "nostro", "EUR", nil, 1)
	const max = int64(^uint64(0) >> 1)
	if err := postEntry(bg(t), pool, "big", map[uuid.UUID]int64{a: -max, b: max}, "EUR"); err != nil {
		t.Fatal(err)
	}
	if err := postEntry(bg(t), pool, "big", map[uuid.UUID]int64{a: -1, b: 1}, "EUR"); sqlState(err) != "22003" {
		t.Fatalf("overflow: %v", err)
	}
}
