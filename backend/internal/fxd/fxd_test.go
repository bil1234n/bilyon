package fxd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ledgerv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/ledger/v1"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/fxapi"
	"github.com/bil1234n/bilyon/backend/internal/fxd"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/ledgerapi"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/natstest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, nil, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

type world struct {
	t       *testing.T
	env     map[string]string
	ledger  *pgledger.Engine
	nc      *nats.Conn
	user    uuid.UUID
	eur     uuid.UUID
	usd     uuid.UUID
	books   map[string]uuid.UUID
	nostros map[string]uuid.UUID
}

// instance is one running fxd.
type instance struct {
	cancel  context.CancelFunc
	done    chan int
	once    sync.Once
	grpc    string
	http    string
	leading chan bool
	stderr  *syncBuffer
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

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, user: uuid.New(), books: map[string]uuid.UUID{}, nostros: map[string]uuid.UUID{}}
	ledgerPool := srv.DatabaseWith(t, "ledger", ledgerdb.Setup)
	w.ledger = pgledger.New(ledgerPool)
	gs := grpc.NewServer()
	ledgerv1.RegisterLedgerServiceServer(gs, ledgerapi.NewServer(w.ledger))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	ns := natstest.Start(t)
	w.nc = ns.Connect(t)

	for _, cur := range []string{"EUR", "USD"} {
		w.books[cur] = w.account(ledger.KindFXBook, cur, nil)
		w.nostros[cur] = w.account(ledger.KindNostro, cur, nil)
	}
	w.eur = w.account(ledger.KindUser, "EUR", &w.user)
	w.usd = w.account(ledger.KindUser, "USD", &w.user)
	if _, err := w.ledger.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: "fund", Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: w.nostros["EUR"], Amount: -100_000_00}, {AccountID: w.eur, Amount: 100_000_00}}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	market := map[string]any{
		"currencies": []map[string]any{{"code": "EUR", "exp": 2}, {"code": "USD", "exp": 2}},
		"edges": []map[string]any{
			{"id": "eur-usd-net", "from": "EUR", "to": "USD", "venue": "internal",
				"ladder": []map[string]any{{"size": 50_000_00, "rate": "1.0850"}}},
			{"id": "eur-usd-a", "from": "EUR", "to": "USD", "venue": "lp:alpha", "stale_after": "10m"},
			{"id": "usd-eur-a", "from": "USD", "to": "EUR", "venue": "lp:alpha", "stale_after": "10m"},
		},
		"risk":     map[string]any{"EUR/USD": map[string]any{"sigma_annual": 0.07, "max_ttl": "5m"}},
		"fx_books": map[string]string{"EUR": w.books["EUR"].String(), "USD": w.books["USD"].String()},
		"route":    map[string]any{"max_hops": 3, "max_latency": "60s"},
		"pricing":  map[string]any{"margin_bps": 8, "default_ttl": "30s", "mid_stale_after": "10m"},
	}
	marketFile := filepath.Join(dir, "market.json")
	raw, _ := json.Marshal(market)
	if err := os.WriteFile(marketFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keysFile := filepath.Join(dir, "keys.json")
	keys, _ := json.Marshal([]map[string]string{{"id": "k1", "secret": base64.StdEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))}})
	if err := os.WriteFile(keysFile, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	w.env = map[string]string{
		"BILYON_DATABASE_URL":       srv.EmptyDatabase(t),
		"BILYON_NATS_URL":           ns.URL,
		"BILYON_FX_MARKET_FILE":     marketFile,
		"BILYON_FX_QUOTE_KEYS_FILE": keysFile,
		"BILYON_GRPC_ADDR":          "127.0.0.1:0",
		"BILYON_GRPC_INSECURE":      "true",
		"BILYON_LEDGER_ADDR":        lis.Addr().String(),
		"BILYON_LEDGER_INSECURE":    "true",
		"BILYON_HTTP_ADDR":          "127.0.0.1:0",
		"BILYON_FX_LOCK_RETRY":      "50ms",
		"BILYON_FX_SWEEP_INTERVAL":  "100ms",
		"BILYON_LOG_LEVEL":          "debug",
	}
	var out, errOut bytes.Buffer
	if code := fxd.Main(ctx(t), []string{"migrate"}, config.FromMap(w.env), &out, &errOut, fxd.Hooks{}); code != 0 {
		t.Fatalf("migrate exited %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "applied 1 migration(s)") {
		t.Fatalf("migrate output %q", out.String())
	}
	return w
}

func (w *world) account(kind ledger.AccountKind, cur string, owner *uuid.UUID) uuid.UUID {
	w.t.Helper()
	a, err := w.ledger.CreateAccount(ctx(w.t), ledger.CreateAccount{IdempotencyKey: "acct:" + uuid.NewString(),
		Kind: kind, Currency: cur, OwnerID: owner})
	if err != nil {
		w.t.Fatal(err)
	}
	return a.ID
}

func (w *world) start() *instance {
	w.t.Helper()
	runCtx, cancel := context.WithCancel(context.Background())
	in := &instance{cancel: cancel, done: make(chan int, 1), leading: make(chan bool, 16), stderr: &syncBuffer{}}
	grpcAddr, httpAddr := make(chan string, 1), make(chan string, 1)
	go func() {
		in.done <- fxd.Main(runCtx, nil, config.FromMap(w.env), &bytes.Buffer{}, in.stderr, fxd.Hooks{
			OnGRPCListening: func(a string) { grpcAddr <- a },
			OnListening:     func(a string) { httpAddr <- a },
			OnLeading:       func(l bool) { in.leading <- l },
		})
	}()
	select {
	case in.grpc = <-grpcAddr:
	case code := <-in.done:
		w.t.Fatalf("fxd exited %d: %s", code, in.stderr.String())
	case <-time.After(30 * time.Second):
		w.t.Fatal("fxd did not start")
	}
	in.http = <-httpAddr
	w.t.Cleanup(in.stop)
	return in
}

func (in *instance) stop() {
	in.once.Do(func() {
		in.cancel()
		select {
		case <-in.done:
		case <-time.After(30 * time.Second):
		}
	})
}

// await waits for the instance's leadership to become want.
func (in *instance) await(t *testing.T, want bool) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case l := <-in.leading:
			if l == want {
				return
			}
		case <-deadline:
			t.Fatalf("leadership never became %v: %s", want, in.stderr.String())
		}
	}
}

func (in *instance) client(t *testing.T) *fxapi.Client {
	t.Helper()
	conn, err := grpc.NewClient(in.grpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return fxapi.NewClient(conn)
}

func (in *instance) ready() int {
	resp, err := http.Get("http://" + in.http + "/readyz")
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (w *world) publish(subject string, v any) {
	w.t.Helper()
	raw, _ := json.Marshal(v)
	if err := w.nc.Publish(subject, raw); err != nil {
		w.t.Fatal(err)
	}
	if err := w.nc.Flush(); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) market() {
	w.publish("bilyon.market.mid", fxd.MidUpdate{From: "EUR", To: "USD", Rate: "1.0850", At: time.Now()})
	w.publish("bilyon.market.ladder", fxd.LadderUpdate{Edge: "eur-usd-a", At: time.Now(),
		Ladder: []fx.Level{{Size: 1_000_000_00, Rate: "1.0847"}}})
	w.publish("bilyon.market.ladder", fxd.LadderUpdate{Edge: "usd-eur-a", At: time.Now(),
		Ladder: []fx.Level{{Size: 1_000_000_00, Rate: "0.9210"}}})
}

func (w *world) balance(id uuid.UUID) int64 {
	w.t.Helper()
	b, err := w.ledger.Balance(ctx(w.t), id)
	if err != nil {
		w.t.Fatal(err)
	}
	return b.Posted
}

// quote retries until the market data has reached the engine.
func quote(t *testing.T, c *fxapi.Client, user uuid.UUID, amount int64) *fx.Quote {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		q, err := c.CreateQuote(ctx(t), fx.QuoteRequest{UserID: user, From: "EUR", To: "USD", AmountIn: amount})
		if err == nil {
			return q
		}
		if !errors.Is(err, fx.ErrNoMid) && !errors.Is(err, fxapi.ErrUnavailable) || time.Now().After(deadline) {
			t.Fatalf("quote: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestFailoverAndExecution(t *testing.T) {
	w := newWorld(t)
	a := w.start()
	a.await(t, true)
	b := w.start()
	w.market()

	ca, cb := a.client(t), b.client(t)
	q1 := quote(t, ca, w.user, 10_000_00)
	if q1.AmountOut != 10_839_58 {
		t.Fatalf("quote %+v", q1)
	}
	ex, err := ca.ExecuteQuote(ctx(t), fx.ExecuteRequest{QuoteID: q1.ID, Signature: q1.Signature, UserID: w.user,
		SourceAccount: w.eur, DestinationAccount: w.usd})
	if err != nil || ex.State != fx.StateBooked {
		t.Fatalf("execute: %+v %v", ex, err)
	}
	if w.balance(w.usd) != 10_839_58 || w.balance(w.books["EUR"]) != 10_000_00 {
		t.Fatalf("balances usd %d book %d", w.balance(w.usd), w.balance(w.books["EUR"]))
	}
	got, x, err := ca.GetQuote(ctx(t), w.user, q1.ID)
	if err != nil || got.State != fx.StateBooked || x == nil || x.EntryIDs[0] != ex.EntryIDs[0] {
		t.Fatalf("GetQuote = %+v %+v %v", got, x, err)
	}

	// The standby refuses service and is not ready.
	if _, err := cb.CreateQuote(ctx(t), fx.QuoteRequest{UserID: w.user, From: "EUR", To: "USD", AmountIn: 100}); !errors.Is(err, fxapi.ErrUnavailable) {
		t.Fatalf("standby served a quote: %v", err)
	}
	if a.ready() != http.StatusOK || b.ready() != http.StatusServiceUnavailable {
		t.Fatalf("readiness leader %d standby %d", a.ready(), b.ready())
	}

	// An open quote survives failover: the standby recovers its reservation.
	q2 := quote(t, ca, w.user, 20_000_00)
	a.stop()
	b.await(t, true)
	ex2, err := cb.ExecuteQuote(ctx(t), fx.ExecuteRequest{QuoteID: q2.ID, Signature: q2.Signature, UserID: w.user,
		SourceAccount: w.eur, DestinationAccount: w.usd})
	if err != nil || ex2.AmountOut != q2.AmountOut {
		t.Fatalf("execution on the new leader: %+v %v", ex2, err)
	}

	// Executions reach the FX stream through the outbox relay.
	js, err := jetstream.New(w.nc)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		stream, err := js.Stream(ctx(t), "BILYON_FX")
		if err == nil {
			info, err := stream.Info(ctx(t))
			if err == nil && info.State.Msgs >= 2 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("booked events never reached the BILYON_FX stream")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A crossed LP price quarantines its edge and alerts treasury.
	w.publish("bilyon.market.ladder", fxd.LadderUpdate{Edge: "usd-eur-a", At: time.Now(),
		Ladder: []fx.Level{{Size: 1_000_000_00, Rate: "0.9300"}}})
	consumer, err := js.OrderedConsumer(ctx(t), "BILYON_FX", jetstream.OrderedConsumerConfig{
		FilterSubjects: []string{"bilyon.fx.edge.quarantined"}})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := consumer.Next(jetstream.FetchMaxWait(20 * time.Second))
	if err != nil {
		t.Fatalf("no quarantine event: %v\n%s", err, b.stderr.String())
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(msg.Data(), &env); err != nil || env.Data["edge_id"] != "usd-eur-a" {
		t.Fatalf("quarantine event %s: %v", msg.Data(), err)
	}
}

func TestCommandsAndConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := fxd.Main(context.Background(), []string{"bogus"}, config.FromMap(nil), &out, &errOut, fxd.Hooks{}); code != 2 {
		t.Fatalf("unknown command exited %d", code)
	}
	if code := fxd.Main(context.Background(), []string{"help"}, config.FromMap(nil), &out, &errOut, fxd.Hooks{}); code != 0 ||
		!strings.Contains(out.String(), "usage: fxd") {
		t.Fatalf("help: %d %q", code, out.String())
	}
	errOut.Reset()
	if code := fxd.Main(context.Background(), nil, config.FromMap(map[string]string{"BILYON_DATABASE_URL": "postgres://x"}),
		&out, &errOut, fxd.Hooks{}); code != 2 {
		t.Fatalf("missing run configuration exited %d", code)
	}
	for _, v := range []string{"BILYON_NATS_URL", "BILYON_FX_MARKET_FILE", "BILYON_FX_QUOTE_KEYS_FILE", "BILYON_GRPC_ADDR",
		"BILYON_LEDGER_ADDR"} {
		if !strings.Contains(errOut.String(), v) {
			t.Errorf("configuration error does not name %s: %s", v, errOut.String())
		}
	}
	if _, err := fxd.LoadConfig(config.FromMap(map[string]string{"BILYON_DATABASE_URL": "postgres://x",
		"BILYON_NATS_URL": "nats://x", "BILYON_FX_MARKET_FILE": "m", "BILYON_FX_QUOTE_KEYS_FILE": "k",
		"BILYON_GRPC_ADDR": ":1", "BILYON_LEDGER_ADDR": "l:1"}), true); err == nil ||
		!strings.Contains(err.Error(), "BILYON_GRPC_TLS_CERT") || !strings.Contains(err.Error(), "BILYON_LEDGER_TLS_CA") {
		t.Fatalf("mTLS requirements: %v", err)
	}

	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := fxd.LoadMarket(write("unknown.json", `{"currencies":[],"bogus":1}`)); err == nil {
		t.Error("unknown market field accepted")
	}
	if _, err := fxd.LoadMarket(write("empty.json", `{}`)); err == nil {
		t.Error("empty market accepted")
	}
	if _, err := fxd.LoadMarket(write("dur.json", `{"edges":[{"latency":5}]}`)); err == nil {
		t.Error("numeric duration accepted")
	}
	if _, err := fxd.LoadQuoteKeys(write("keys.json", `[{"id":"k","secret":"%%%"}]`)); err == nil {
		t.Error("bad base64 secret accepted")
	}

	db := srv.EmptyDatabase(t)
	out.Reset()
	if code := fxd.Main(ctx(t), []string{"status"}, config.FromMap(map[string]string{"BILYON_DATABASE_URL": db}),
		&out, &errOut, fxd.Hooks{}); code != 0 || !strings.Contains(out.String(), "fx_core") {
		t.Fatalf("status: %d %q %s", code, out.String(), errOut.String())
	}
}
