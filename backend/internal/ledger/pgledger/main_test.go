package pgledger_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, ledgerdb.Setup, &srv)) }

type env struct {
	t    *testing.T
	pool *pgxpool.Pool
	eng  *pgledger.Engine
	bank uuid.UUID // unbounded nostro account through which money enters
	keys atomic.Int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	t.Parallel()
	pool := srv.Database(t)
	e := &env{t: t, pool: pool, eng: pgledger.New(pool)}
	e.bank = e.account(ledger.KindNostro, "EUR", nil).ID
	return e
}

func (e *env) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	e.t.Cleanup(cancel)
	return c
}

func (e *env) key(prefix string) string {
	return fmt.Sprintf("%s-%d-%s", prefix, e.keys.Add(1), uuid.NewString()[:8])
}

func (e *env) account(kind ledger.AccountKind, currency string, floor *int64) ledger.Account {
	e.t.Helper()
	a, err := e.eng.CreateAccount(e.ctx(), ledger.CreateAccount{
		IdempotencyKey: e.key("acct"), Kind: kind, Currency: currency, Floor: floor,
	})
	if err != nil {
		e.t.Fatalf("create %s account: %v", kind, err)
	}
	return a
}

func (e *env) user() uuid.UUID { return e.account(ledger.KindUser, "EUR", nil).ID }

// fund moves amount from the bank into acct.
func (e *env) fund(acct uuid.UUID, amount int64) ledger.Entry {
	e.t.Helper()
	en, err := e.eng.Transfer(e.ctx(), ledger.Transfer{
		IdempotencyKey: e.key("fund"), Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: e.bank, Amount: -amount}, {AccountID: acct, Amount: amount}},
	})
	if err != nil {
		e.t.Fatalf("fund: %v", err)
	}
	return en
}

func (e *env) transfer(from, to uuid.UUID, amount int64) (ledger.Entry, error) {
	return e.eng.Transfer(e.ctx(), ledger.Transfer{
		IdempotencyKey: e.key("p2p"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: from, Amount: -amount}, {AccountID: to, Amount: amount}},
	})
}

func (e *env) balance(id uuid.UUID) ledger.Balance {
	e.t.Helper()
	b, err := e.eng.Balance(e.ctx(), id)
	if err != nil {
		e.t.Fatalf("balance: %v", err)
	}
	return b
}

func (e *env) wantBalance(id uuid.UUID, posted, pending int64) {
	e.t.Helper()
	b := e.balance(id)
	if b.Posted != posted || b.Pending != pending || b.Available != posted-pending {
		e.t.Fatalf("account %s: posted %d pending %d available %d, want posted %d pending %d",
			id, b.Posted, b.Pending, b.Available, posted, pending)
	}
}

func (e *env) audit() {
	e.t.Helper()
	r, err := e.eng.Audit(e.ctx())
	if err != nil {
		e.t.Fatalf("audit: %v", err)
	}
	if !r.OK() {
		for _, d := range r.Discrepancies {
			e.t.Errorf("audit: %s", d)
		}
		e.t.FailNow()
	}
}

// outboxEvents returns the envelopes of every outbox row with the topic.
func (e *env) outboxEvents(topic string) []outbox.Envelope {
	e.t.Helper()
	rows, err := e.pool.Query(e.ctx(), `SELECT payload FROM outbox WHERE topic = $1 ORDER BY id`, topic)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []outbox.Envelope
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			e.t.Fatal(err)
		}
		var env outbox.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, env)
	}
	return out
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(e.ctx(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}

func ptr[T any](v T) *T { return &v }
