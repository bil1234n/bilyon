package migrate_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/migrate"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/migrations"
)

var srv *pgtest.Server

// The template stays empty: these tests exercise migration itself.
func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, nil, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestLoadLedgerMigrations(t *testing.T) {
	ms, err := migrate.Load(migrations.Ledger, migrations.LedgerDir)
	if err != nil {
		t.Fatal(err)
	}
	if ms[0].Version != 1 || ms[0].Name != "ledger_core" || ms[0].NoTransaction {
		t.Fatalf("unexpected first migration %+v", ms[0])
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].Version <= ms[i-1].Version {
			t.Fatal("migrations not ordered")
		}
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"bad name":  {"m/1_x.sql": {Data: []byte("SELECT 1")}},
		"duplicate": {"m/0001_a.sql": {Data: []byte("SELECT 1")}, "m/0001_b.sql": {Data: []byte("SELECT 1")}},
		"empty":     {"m/readme.txt": {Data: []byte("x")}},
	}
	for name, fsys := range cases {
		if _, err := migrate.Load(fsys, "m"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestApplyIsIdempotentAndCreatesSchema(t *testing.T) {
	pool := srv.Database(t)
	ms, err := migrate.Load(migrations.Ledger, migrations.LedgerDir)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != len(ms) {
		t.Fatalf("applied %d of %d", len(applied), len(ms))
	}
	again, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{})
	if err != nil || len(again) != 0 {
		t.Fatalf("second apply: %v, %d applied", err, len(again))
	}
	var n int
	if err := pool.QueryRow(ctx(t), `SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN
		('accounts','account_balances','journal_entries','postings','holds','reserves','idempotency_keys','outbox')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("expected 8 ledger tables, found %d", n)
	}
	status, err := migrate.Status(ctx(t), pool, ms, "")
	if err != nil || !status[0].Applied || status[0].Modified {
		t.Fatalf("status: %+v %v", status, err)
	}
}

func TestChecksumMismatchAndOutOfOrder(t *testing.T) {
	pool := srv.Database(t)
	v1 := fstest.MapFS{"m/0001_a.sql": {Data: []byte("CREATE TABLE a (id int)")}}
	ms, _ := migrate.Load(v1, "m")
	if _, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{Table: "mig_test"}); err != nil {
		t.Fatal(err)
	}
	edited := fstest.MapFS{"m/0001_a.sql": {Data: []byte("CREATE TABLE a (id bigint)")}}
	ms, _ = migrate.Load(edited, "m")
	if _, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{Table: "mig_test"}); !errors.Is(err, migrate.ErrChecksumMismatch) {
		t.Fatalf("edited migration: %v", err)
	}
	v3 := fstest.MapFS{
		"m/0001_a.sql": {Data: []byte("CREATE TABLE a (id int)")},
		"m/0003_c.sql": {Data: []byte("CREATE TABLE c (id int)")},
	}
	ms, _ = migrate.Load(v3, "m")
	if _, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{Table: "mig_test"}); err != nil {
		t.Fatal(err)
	}
	late := fstest.MapFS{
		"m/0001_a.sql": {Data: []byte("CREATE TABLE a (id int)")},
		"m/0002_b.sql": {Data: []byte("CREATE TABLE b (id int)")},
		"m/0003_c.sql": {Data: []byte("CREATE TABLE c (id int)")},
	}
	ms, _ = migrate.Load(late, "m")
	if _, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{Table: "mig_test"}); !errors.Is(err, migrate.ErrOutOfOrder) {
		t.Fatalf("late migration: %v", err)
	}
}

func TestFailedMigrationRollsBackAndNoTransactionMode(t *testing.T) {
	pool := srv.Database(t)
	bad := fstest.MapFS{"m/0001_bad.sql": {Data: []byte("CREATE TABLE ok_part (id int); SELECT broken_syntax(;")}}
	ms, _ := migrate.Load(bad, "m")
	if _, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{Table: "mig_bad"}); err == nil {
		t.Fatal("expected failure")
	}
	var exists bool
	if err := pool.QueryRow(ctx(t), "SELECT to_regclass('ok_part') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatalf("partial migration leaked: exists=%v err=%v", exists, err)
	}
	concurrent := fstest.MapFS{
		"m/0001_t.sql": {Data: []byte("CREATE TABLE big (id int)")},
		"m/0002_idx.sql": {Data: []byte(strings.Join([]string{
			"-- bilyon:no-transaction",
			"CREATE INDEX CONCURRENTLY big_id ON big (id)"}, "\n"))},
	}
	ms, _ = migrate.Load(concurrent, "m")
	if !ms[1].NoTransaction {
		t.Fatal("directive not detected")
	}
	if _, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{Table: "mig_conc"}); err != nil {
		t.Fatalf("CREATE INDEX CONCURRENTLY outside a transaction: %v", err)
	}
}

func TestConcurrentMigratorsSerialise(t *testing.T) {
	pool := srv.Database(t)
	ms, _ := migrate.Load(migrations.Ledger, migrations.LedgerDir)
	var wg sync.WaitGroup
	results := make([]int, 6)
	errs := make([]error, 6)
	for i := range results {
		wg.Go(func() {
			applied, err := migrate.Apply(ctx(t), pool, ms, migrate.Options{})
			results[i], errs[i] = len(applied), err
		})
	}
	wg.Wait()
	total := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("migrator %d: %v", i, errs[i])
		}
		total += results[i]
	}
	if total != len(ms) {
		t.Fatalf("migrations applied %d times in total, want exactly %d", total, len(ms))
	}
}
