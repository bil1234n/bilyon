package tbledger_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/tbledger"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/tbtest"
)

var (
	pgSrv   *pgtest.Server
	cluster *tbtest.Cluster
)

func TestMain(m *testing.M) {
	cl, err := tbtest.Start()
	if err != nil {
		if os.Getenv("BILYON_REQUIRE_INFRA") == "1" {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err, "- TigerBeetle tests will be skipped")
	}
	cluster = cl
	code := pgtest.Main(m, ledgerdb.Setup, &pgSrv)
	cl.Stop()
	os.Exit(code)
}

func ctxFor(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func openDriver(t *testing.T, opts ...tbledger.Option) *tbledger.Driver {
	t.Helper()
	c := tbtest.Require(t, cluster)
	d, err := tbledger.Open(c.ID, c.Addresses, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if err := d.Ping(); err != nil {
		t.Fatal(err)
	}
	return d
}

// env is a PostgreSQL ledger plus a TigerBeetle driver.
type env struct {
	t    *testing.T
	pool *pgxpool.Pool
	eng  *pgledger.Engine
	d    *tbledger.Driver
	keys atomic.Int64
}

func newEnv(t *testing.T, opts ...tbledger.Option) *env {
	t.Helper()
	t.Parallel()
	d := openDriver(t, opts...)
	pool := pgSrv.Database(t)
	return &env{t: t, pool: pool, eng: pgledger.New(pool), d: d}
}

func (e *env) key(prefix string) string {
	return fmt.Sprintf("%s-%d-%s", prefix, e.keys.Add(1), uuid.NewString()[:8])
}

func (e *env) account(kind ledger.AccountKind, currency string, floor *int64, stripes int) ledger.Account {
	e.t.Helper()
	a, err := e.eng.CreateAccount(ctxFor(e.t), ledger.CreateAccount{IdempotencyKey: e.key("acct"), Kind: kind,
		Currency: currency, Floor: floor, Stripes: stripes})
	if err != nil {
		e.t.Fatalf("create %s account: %v", kind, err)
	}
	return a
}

func (e *env) transfer(kind string, postings ...ledger.Posting) (ledger.Entry, error) {
	return e.eng.Transfer(ctxFor(e.t), ledger.Transfer{IdempotencyKey: e.key("tr"), Kind: kind, Postings: postings})
}

func (e *env) mustTransfer(kind string, postings ...ledger.Posting) ledger.Entry {
	e.t.Helper()
	en, err := e.transfer(kind, postings...)
	if err != nil {
		e.t.Fatalf("%s: %v", kind, err)
	}
	return en
}

// tailer runs a tailer until the test ends and returns it with its metrics.
func (e *env) tailer(cfg tbledger.TailerConfig) (*tbledger.Tailer, *prometheus.Registry) {
	e.t.Helper()
	reg := prometheus.NewRegistry()
	cfg.Registerer = reg
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 20 * time.Millisecond
	}
	if cfg.RetryMax == 0 {
		cfg.RetryMax = 200 * time.Millisecond
	}
	tl := tbledger.NewTailer(e.pool, tbledger.NewMirror(e.d), cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tl.Run(ctx) }()
	e.t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			e.t.Errorf("tailer: %v", err)
		}
	})
	return tl, reg
}

func (e *env) bootstrap() tbledger.BootstrapStats {
	e.t.Helper()
	stats, err := tbledger.Bootstrap(ctxFor(e.t), e.pool, e.d, tbledger.DefaultConsumer, nil)
	if err != nil {
		e.t.Fatalf("bootstrap: %v", err)
	}
	return stats
}

// reconciled asserts that TigerBeetle matches PostgreSQL at the tailer's
// next exact cut.
func (e *env) reconciled(tl *tbledger.Tailer) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ms, err := tl.Reconcile(ctx)
	if err != nil {
		e.t.Fatalf("reconcile: %v", err)
	}
	for _, m := range ms {
		e.t.Errorf("mismatch: %s", m)
	}
	if len(ms) > 0 {
		e.t.FailNow()
	}
}

func counterSum(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var n float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			n += m.GetCounter().GetValue()
		}
	}
	return n
}

func failures(t *testing.T, reg *prometheus.Registry) float64 {
	return counterSum(t, reg, "bilyon_tbshadow_failures_total")
}

func eventually(t *testing.T, within time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func ptr(v int64) *int64 { return &v }
