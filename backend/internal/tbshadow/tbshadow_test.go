package tbshadow_test

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

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/tbledger"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/tbshadow"
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

func bg(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

func runCmd(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut syncBuffer
	code := tbshadow.Main(bg(t), args, config.FromMap(env), &out, &errOut, tbshadow.Hooks{})
	return code, out.String(), errOut.String()
}

// fixture is a migrated ledger database plus the environment pointing the
// daemon at it and at the TigerBeetle cluster.
type fixture struct {
	eng  *pgledger.Engine
	env  map[string]string
	keys int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Parallel()
	c := tbtest.Require(t, cluster)
	pool := pgSrv.Database(t)
	return &fixture{eng: pgledger.New(pool), env: map[string]string{
		"BILYON_DATABASE_URL":           pgtest.URL(pool),
		"BILYON_TIGERBEETLE_ADDRESSES":  strings.Join(c.Addresses, ","),
		"BILYON_TIGERBEETLE_CLUSTER_ID": fmt.Sprint(c.ID),
		"BILYON_HTTP_ADDR":              "127.0.0.1:0",
		"BILYON_LOG_FORMAT":             "text",
		"BILYON_RECONCILE_INTERVAL":     "200ms",
	}}
}

func (f *fixture) key() string {
	f.keys++
	return fmt.Sprintf("k-%d-%s", f.keys, uuid.NewString()[:8])
}

func (f *fixture) account(t *testing.T, kind ledger.AccountKind) ledger.Account {
	t.Helper()
	a, err := f.eng.CreateAccount(bg(t), ledger.CreateAccount{IdempotencyKey: f.key(), Kind: kind, Currency: "EUR"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *fixture) move(t *testing.T, from, to ledger.Account, amount int64) {
	t.Helper()
	if _, err := f.eng.Transfer(bg(t), ledger.Transfer{IdempotencyKey: f.key(), Kind: "p2p", Postings: []ledger.Posting{
		{AccountID: from.ID, Amount: -amount}, {AccountID: to.ID, Amount: amount}}}); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestRunMirrorsReconcilesAndShutsDown(t *testing.T) {
	f := newFixture(t)
	bank := f.account(t, ledger.KindNostro)
	alice := f.account(t, ledger.KindUser)
	f.move(t, bank, alice, 1_000) // before the shadow exists: imported by the auto-bootstrap

	ctx, cancel := context.WithCancel(bg(t))
	defer cancel()
	addrCh := make(chan string, 1)
	var mu sync.Mutex
	var results []int // mismatch counts of successful reconciliations
	hooks := tbshadow.Hooks{
		OnListening: func(addr string) { addrCh <- addr },
		OnReconciled: func(ms []tbledger.Mismatch, err error) {
			if err != nil {
				return
			}
			mu.Lock()
			results = append(results, len(ms))
			mu.Unlock()
		},
	}
	var stderr syncBuffer
	exit := make(chan int, 1)
	go func() { exit <- tbshadow.Main(ctx, []string{"run"}, config.FromMap(f.env), io.Discard, &stderr, hooks) }()
	var addr string
	select {
	case addr = <-addrCh:
	case code := <-exit:
		t.Fatalf("exited early with %d: %s", code, stderr.String())
	}
	// cleanFrom waits for a clean reconciliation at index >= from.
	cleanFrom := func(from int) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			mu.Lock()
			clean := false
			for _, r := range results[min(from, len(results)):] {
				clean = clean || r == 0
			}
			mu.Unlock()
			if clean {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("no clean reconciliation from #%d: %v\n%s", from, results, stderr.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	cleanFrom(0) // reconciliations run only once the auto-bootstrap is done
	bob := f.account(t, ledger.KindUser)
	f.move(t, alice, bob, 400)
	// A reconciliation may be running already; the next one starts after
	// the activity, so a clean result from then on covers it.
	mu.Lock()
	seen := len(results)
	mu.Unlock()
	cleanFrom(seen + 1)
	if code, body := get(t, "http://"+addr+"/readyz"); code != http.StatusOK || !strings.Contains(body, `"tigerbeetle":"ok"`) {
		t.Fatalf("readyz %d: %s", code, body)
	}
	_, metrics := get(t, "http://"+addr+"/metrics")
	for _, want := range []string{"bilyon_tbshadow_events_total", "bilyon_tbshadow_reconcile_mismatches 0", "bilyon_tbshadow_blocked 0"} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics lack %q:\n%s", want, grepLines(metrics, "bilyon_"))
		}
	}
	cancel()
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit code %d: %s", code, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("did not shut down")
	}
}

func TestBootstrapReconcileAndResetCommands(t *testing.T) {
	f := newFixture(t)
	bank := f.account(t, ledger.KindNostro)
	alice := f.account(t, ledger.KindUser)
	f.move(t, bank, alice, 500)

	code, out, errOut := runCmd(t, f.env, "reconcile")
	if code != 1 || !strings.Contains(errOut, "run bootstrap first") {
		t.Fatalf("reconcile before bootstrap: %d %s", code, errOut)
	}
	code, out, errOut = runCmd(t, f.env, "bootstrap")
	if code != 0 {
		t.Fatalf("bootstrap: %d %s", code, errOut)
	}
	var stats tbledger.BootstrapStats
	if err := json.Unmarshal([]byte(out), &stats); err != nil || stats.Accounts != 2 || stats.Balances != 2 {
		t.Fatalf("bootstrap output %q: %v", out, err)
	}
	if code, _, _ = runCmd(t, f.env, "bootstrap"); code != 1 {
		t.Fatalf("second bootstrap exit %d", code)
	}
	f.move(t, alice, bank, 100) // tailed by the reconcile command before comparing
	code, out, errOut = runCmd(t, f.env, "reconcile")
	if code != 0 || strings.TrimSpace(out) != `{"mismatches":[]}` {
		t.Fatalf("clean reconcile: %d %q %s", code, out, errOut)
	}

	// Corrupt TigerBeetle behind the shadow's back.
	c := tbtest.Require(t, cluster)
	d, err := tbledger.Open(c.ID, c.Addresses)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	stray := ledger.Entry{ID: ledger.NewID(), Kind: "stray", CreatedAt: time.Now().UTC(), Postings: []ledger.PostingRecord{
		{AccountID: bank.ID, Currency: "EUR", Amount: -1}, {AccountID: alice.ID, Currency: "EUR", Amount: 1}}}
	if err := d.ApplyEntry(stray); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCmd(t, f.env, "reconcile")
	var report struct {
		Mismatches []tbledger.Mismatch `json:"mismatches"`
	}
	if err := json.Unmarshal([]byte(out), &report); code != 1 || err != nil || len(report.Mismatches) != 2 {
		t.Fatalf("reconcile after corruption: %d %q %v", code, out, err)
	}
	if code, _, _ = runCmd(t, f.env, "reset-bootstrap"); code != 1 {
		t.Fatalf("reset of a finished bootstrap exit %d", code)
	}
}

func TestCommandLineAndConfiguration(t *testing.T) {
	if code, out, _ := runCmd(t, nil, "help"); code != 0 || !strings.Contains(out, "reset-bootstrap") {
		t.Fatalf("help: %d %q", code, out)
	}
	if code, _, errOut := runCmd(t, nil, "frobnicate"); code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown command: %d %q", code, errOut)
	}
	code, _, errOut := runCmd(t, map[string]string{"BILYON_TIGERBEETLE_CLUSTER_ID": "x", "BILYON_RECONCILE_INTERVAL": "-1s"}, "run")
	if code != 2 {
		t.Fatalf("invalid configuration exit %d", code)
	}
	for _, want := range []string{"BILYON_DATABASE_URL", "BILYON_TIGERBEETLE_ADDRESSES", "BILYON_TIGERBEETLE_CLUSTER_ID", "BILYON_RECONCILE_INTERVAL"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("configuration error lacks %s: %s", want, errOut)
		}
	}
	cfg, err := tbshadow.LoadConfig(config.FromMap(map[string]string{
		"BILYON_DATABASE_URL":          "postgres://db/ledger",
		"BILYON_TIGERBEETLE_ADDRESSES": " 10.0.0.1:3000, 10.0.0.2:3000 ,",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TBAddresses) != 2 || cfg.TBAddresses[1] != "10.0.0.2:3000" || cfg.Consumer != tbledger.DefaultConsumer ||
		!cfg.AutoBootstrap || cfg.ReconcileInterval != time.Hour || cfg.HoldGrace != tbledger.DefaultHoldGrace {
		t.Fatalf("defaults: %+v", cfg)
	}
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
