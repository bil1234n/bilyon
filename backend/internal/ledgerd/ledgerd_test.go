package ledgerd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/ledgerd"
	"github.com/bil1234n/bilyon/backend/internal/migrate"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/natstest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/migrations"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, ledgerdb.Setup, &srv)) }

func bg(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func runCmd(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut syncBuffer
	code := ledgerd.Main(bg(t), args, config.FromMap(env), &out, &errOut, ledgerd.Hooks{})
	return code, out.String(), errOut.String()
}

func TestRunPublishesEventsExpiresHoldsAndShutsDownCleanly(t *testing.T) {
	pool := srv.Database(t)
	ns := natstest.Start(t)
	env := map[string]string{
		"BILYON_DATABASE_URL":        pgtest.URL(pool),
		"BILYON_NATS_URL":            ns.URL,
		"BILYON_HTTP_ADDR":           "127.0.0.1:0",
		"BILYON_MIGRATE_ON_START":    "true",
		"BILYON_HOLD_SWEEP_INTERVAL": "100ms",
		"BILYON_AUDIT_INTERVAL":      "200ms",
		"BILYON_LOG_FORMAT":          "text",
	}
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	exit := make(chan int, 1)
	var logs syncBuffer
	go func() {
		exit <- ledgerd.Main(ctx, []string{"run"}, config.FromMap(env), io.Discard, &logs,
			ledgerd.Hooks{OnListening: func(a string) { addrCh <- a }})
	}()
	var addr string
	select {
	case addr = <-addrCh:
	case code := <-exit:
		t.Fatalf("ledgerd exited early with %d:\n%s", code, logs.String())
	case <-time.After(30 * time.Second):
		t.Fatal("ledgerd did not start")
	}

	eng := pgledger.New(pool)
	bank, _ := eng.CreateAccount(bg(t), ledger.CreateAccount{IdempotencyKey: "bank", Kind: ledger.KindNostro, Currency: "EUR"})
	alice, _ := eng.CreateAccount(bg(t), ledger.CreateAccount{IdempotencyKey: "alice", Kind: ledger.KindUser, Currency: "EUR"})
	if _, err := eng.Transfer(bg(t), ledger.Transfer{IdempotencyKey: "dep", Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: bank.ID, Amount: -5_000}, {AccountID: alice.ID, Amount: 5_000}}}); err != nil {
		t.Fatal(err)
	}
	now, _ := eng.Now(bg(t))
	h, err := eng.PlaceHold(bg(t), ledger.PlaceHold{IdempotencyKey: "hold", AccountID: alice.ID, Amount: 2_000,
		Reason: "throw_intent", ExpiresAt: now.Add(1200 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}

	// The sweeper expires the hold and the relay publishes every event.
	nc := ns.Connect(t)
	js, _ := jetstream.New(nc)
	deadline := time.Now().Add(15 * time.Second)
	want := map[string]int{"bilyon.ledger.account.created": 2, "bilyon.ledger.entry.posted": 1,
		"bilyon.ledger.hold.placed": 1, "bilyon.ledger.hold.expired": 1}
	for {
		got := map[string]int{}
		if stream, err := js.Stream(bg(t), "BILYON_LEDGER"); err == nil {
			info, _ := stream.Info(bg(t), jetstream.WithSubjectFilter("bilyon.ledger.>"))
			if info != nil {
				for subj, n := range info.State.Subjects {
					got[subj] = int(n)
				}
			}
		}
		match := true
		for subj, n := range want {
			if got[subj] != n {
				match = false
			}
		}
		if match {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream subjects %v, want %v\nlogs:\n%s", got, want, logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	held, _ := eng.Hold(bg(t), h.ID)
	if held.State != ledger.HoldExpired {
		t.Fatalf("hold state %s", held.State)
	}

	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	var ready map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&ready)
	resp.Body.Close()
	if resp.StatusCode != 200 || ready["postgres"] != "ok" || ready["nats"] != "ok" {
		t.Fatalf("readyz %d %v", resp.StatusCode, ready)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		resp, err = http.Get("http://" + addr + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := string(body)
		if strings.Contains(m, `bilyon_outbox_published_total{topic="ledger.hold.expired"} 1`) &&
			strings.Contains(m, "bilyon_ledger_audit_discrepancies 0") &&
			strings.Contains(m, "bilyon_ledger_holds_expired_total 1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics missing expected series:\n%s", m)
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit code %d after shutdown:\n%s", code, logs.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ledgerd did not shut down")
	}
}

func TestMigrateStatusAndAuditCommands(t *testing.T) {
	url := srv.EmptyDatabase(t)
	env := map[string]string{"BILYON_DATABASE_URL": url, "BILYON_LOG_FORMAT": "text"}
	ms, err := migrate.Load(migrations.Ledger, migrations.LedgerDir)
	if err != nil {
		t.Fatal(err)
	}
	// status prints one row per migration: version, name, applied, modified.
	wantStatus := func(applied string) {
		t.Helper()
		code, out, errOut := runCmd(t, env, "status")
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if code != 0 || len(lines) != len(ms)+1 {
			t.Fatalf("status: %d %q %s", code, out, errOut)
		}
		for i, m := range ms {
			f := strings.Fields(lines[i+1])
			if len(f) != 4 || f[0] != fmt.Sprintf("%04d", m.Version) || f[1] != m.Name || f[2] != applied || f[3] != "false" {
				t.Fatalf("status row %q, want %04d %s %s false", lines[i+1], m.Version, m.Name, applied)
			}
		}
	}
	wantStatus("false")
	if code, out, errOut := runCmd(t, env, "migrate"); code != 0 || !strings.Contains(out, fmt.Sprintf("applied %d migration(s)", len(ms))) {
		t.Fatalf("migrate: %d %q %s", code, out, errOut)
	}
	if code, out, _ := runCmd(t, env, "migrate"); code != 0 || !strings.Contains(out, "applied 0 migration(s)") {
		t.Fatalf("second migrate: %d %q", code, out)
	}
	wantStatus("true")
	code, out, _ := runCmd(t, env, "audit")
	var report pgledger.AuditReport
	if code != 0 || json.Unmarshal([]byte(out), &report) != nil || !report.OK() {
		t.Fatalf("audit on clean ledger: %d %s", code, out)
	}

	pool := srv.Database(t)
	eng := pgledger.New(pool)
	a, _ := eng.CreateAccount(bg(t), ledger.CreateAccount{IdempotencyKey: "a", Kind: ledger.KindNostro, Currency: "USD"})
	if _, err := pool.Exec(bg(t), `UPDATE account_balances SET balance_minor = 99 WHERE account_id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runCmd(t, map[string]string{"BILYON_DATABASE_URL": pgtest.URL(pool)}, "audit"); code != 1 ||
		!strings.Contains(out, "balance_matches_postings") {
		t.Fatalf("audit on tampered ledger: %d %s", code, out)
	}
}

func TestConfigurationErrors(t *testing.T) {
	if code, _, errOut := runCmd(t, map[string]string{}, "audit"); code != 2 || !strings.Contains(errOut, "BILYON_DATABASE_URL: is required") {
		t.Fatalf("missing database url: %d %s", code, errOut)
	}
	code, _, errOut := runCmd(t, map[string]string{"BILYON_DATABASE_URL": "postgres://x", "BILYON_LOG_LEVEL": "loud",
		"BILYON_AUDIT_INTERVAL": "-5s", "BILYON_DB_MAX_CONNS": "1"}, "run")
	for _, want := range []string{"BILYON_NATS_URL: is required", "BILYON_LOG_LEVEL", "BILYON_AUDIT_INTERVAL", "BILYON_DB_MAX_CONNS"} {
		if code != 2 || !strings.Contains(errOut, want) {
			t.Errorf("config errors should mention %s: %d %s", want, code, errOut)
		}
	}
	if code, _, _ := runCmd(t, nil, "explode"); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
	if code, out, _ := runCmd(t, nil, "help"); code != 0 || !strings.Contains(out, "usage: ledgerd") {
		t.Fatalf("help: %d %s", code, out)
	}
}
