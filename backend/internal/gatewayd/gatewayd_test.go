package gatewayd_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	fxv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/fx/v1"
	ledgerv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/ledger/v1"
	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/fxapi"
	"github.com/bil1234n/bilyon/backend/internal/gatewayapi"
	"github.com/bil1234n/bilyon/backend/internal/gatewayd"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/intentsapi"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/ledgerapi"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/grpcx"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/apiclient"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/authenticator"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/certs"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/fxdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/natstest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
	"github.com/bil1234n/bilyon/backend/migrations"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, nil, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

const (
	origin   = "https://api.bilyon.test"
	clientID = "bilyon-android"
)

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

// world is everything around one gatewayd: databases, Redis, NATS, a
// ledgerd and an fxd stand-in serving the production gRPC APIs, the PKI and
// the key files.
type world struct {
	t        *testing.T
	env      map[string]string
	gwDB     string
	ledger   *pgledger.Engine
	nostro   uuid.UUID
	nc       *nats.Conn
	google   *devicesim.Google
	ca       *certs.CA
	realtime grpcx.TLSFiles // the realtime gateway's client certificate
	dirKey   *ecdsa.PrivateKey
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func pemPrivate(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pemPublic(t *testing.T, k *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func randomB64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func serve(t *testing.T, register func(*grpc.Server)) string {
	t.Helper()
	gs := grpc.NewServer()
	register(gs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, google: devicesim.NewGoogle(t), ca: certs.NewCA(t, "gatewayd-test"), dirKey: newKey(t)}
	w.ledger = pgledger.New(srv.DatabaseWith(t, "ledger", ledgerdb.Setup))
	ledgerAddr := serve(t, func(gs *grpc.Server) { ledgerv1.RegisterLedgerServiceServer(gs, ledgerapi.NewServer(w.ledger)) })
	nostro, err := w.ledger.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: "nostro", Kind: ledger.KindNostro, Currency: "EUR"})
	if err != nil {
		t.Fatal(err)
	}
	w.nostro = nostro.ID
	fxAddr := w.fxService()
	ns := natstest.Start(t)
	w.nc = ns.Connect(t)
	rdb := redistest.Start(t)
	ro := rdb.Options()

	dir := t.TempDir()
	server := w.ca.Leaf("gatewayd", "spiffe://bilyon/gateway", "gatewayd")
	w.realtime = w.ca.Leaf("realtime", "spiffe://bilyon/realtime", "realtime")
	w.gwDB = srv.EmptyDatabase(t)
	w.env = map[string]string{
		"BILYON_DATABASE_URL":                         w.gwDB,
		"BILYON_REDIS_URL":                            fmt.Sprintf("redis://%s/%d", ro.Addr, ro.DB),
		"BILYON_NATS_URL":                             ns.URL,
		"BILYON_HTTP_ADDR":                            "127.0.0.1:0",
		"BILYON_API_ADDR":                             "127.0.0.1:0",
		"BILYON_API_ORIGIN":                           origin,
		"BILYON_API_CLIENTS":                          clientID + ",bilyon-ios",
		"BILYON_SESSION_KEY_FILE":                     writeFile(t, dir, "session.pem", pemPrivate(t, newKey(t))),
		"BILYON_DPOP_NONCE_KEYS_FILE":                 writeFile(t, dir, "dpop.keys", []byte("# current\n"+randomB64(t)+"\n")),
		"BILYON_INTENT_NONCE_KEYS_FILE":               writeFile(t, dir, "intent.keys", []byte(randomB64(t)+"\n"+randomB64(t)+"\n")),
		"BILYON_DIRECTORY_KEY_FILE":                   writeFile(t, dir, "dir.pem", pemPrivate(t, w.dirKey)),
		"BILYON_DIRECTORY_KEY_ID":                     "dir-2026",
		"BILYON_WEBAUTHN_RP_ID":                       "bilyon.test",
		"BILYON_WEBAUTHN_ORIGINS":                     "https://bilyon.test",
		"BILYON_ANDROID_PACKAGE":                      w.google.PackageName,
		"BILYON_ANDROID_CERT_DIGESTS":                 hex.EncodeToString(w.google.SigningCert),
		"BILYON_ANDROID_ROOTS_FILE":                   writeFile(t, dir, "android-roots.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.google.CA.Root.Raw})),
		"BILYON_PLAY_INTEGRITY_DECRYPTION_KEY_FILE":   writeFile(t, dir, "pi.key", []byte(base64.StdEncoding.EncodeToString(w.google.DecryptionKey))),
		"BILYON_PLAY_INTEGRITY_VERIFICATION_KEY_FILE": writeFile(t, dir, "pi.pem", pemPublic(t, &w.google.VerificationKey.PublicKey)),
		"BILYON_LEDGER_ADDR":                          ledgerAddr,
		"BILYON_LEDGER_INSECURE":                      "true",
		"BILYON_FX_ADDR":                              fxAddr,
		"BILYON_FX_INSECURE":                          "true",
		"BILYON_GRPC_ADDR":                            "127.0.0.1:0",
		"BILYON_GRPC_TLS_CERT":                        server.CertFile,
		"BILYON_GRPC_TLS_KEY":                         server.KeyFile,
		"BILYON_GRPC_TLS_CA":                          server.CAFile,
		"BILYON_GRPC_ACL":                             "spiffe://bilyon/realtime=IssueNonces,CreateIntent,GetIntent,MarkDelivered,Catch,Cancel,ListIntents",
		"BILYON_INTENT_SWEEP_INTERVAL":                "100ms",
		"BILYON_LOCK_RETRY":                           "50ms",
		"BILYON_LOG_LEVEL":                            "debug",
	}
	var out, errOut bytes.Buffer
	if code := gatewayd.Main(ctx(t), []string{"migrate"}, config.FromMap(w.env), &out, &errOut, gatewayd.Hooks{}); code != 0 {
		t.Fatalf("migrate exited %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "applied 5 migration(s)") {
		t.Fatalf("migrate output %q", out.String())
	}
	// The daemon runs under the least-privilege role, as in production.
	owner, err := pgxpool.New(ctx(t), w.gwDB)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if _, err := owner.Exec(ctx(t), migrations.GatewayGrants); err != nil {
		t.Fatalf("grants: %v", err)
	}
	w.env["BILYON_DATABASE_URL"] = runtimeURL(w.gwDB)
	return w
}

// runtimeURL connects as the schema owner but acts as bilyon_gateway.
func runtimeURL(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "options=" + strings.ReplaceAll(url.QueryEscape("-c role=bilyon_gateway"), "+", "%20")
}

// fxService serves a real FX engine (EUR → USD) over the production gRPC
// API, as fxd does.
func (w *world) fxService() string {
	t := w.t
	t.Helper()
	g, err := fx.NewGraph(fx.GraphConfig{}, fx.Currency{Code: "EUR", Exp: 2}, fx.Currency{Code: "USD", Exp: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(fx.EdgeSpec{ID: "eur-usd", From: "EUR", To: "USD", Venue: "internal"},
		[]fx.Level{{Size: 1_000_000_00, Rate: "1.0850"}}); err != nil {
		t.Fatal(err)
	}
	books := map[string]uuid.UUID{}
	for _, cur := range []string{"EUR", "USD"} {
		a, err := w.ledger.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: "book:" + cur, Kind: ledger.KindFXBook, Currency: cur})
		if err != nil {
			t.Fatal(err)
		}
		books[cur] = a.ID
	}
	eng, err := fx.NewEngine(fx.Config{Risk: map[string]fx.PairRisk{"EUR/USD": {SigmaAnnual: 0.07}},
		Keys: []fx.QuoteKey{{ID: "k1", Secret: []byte("fedcba9876543210fedcba9876543210")}}, FXBooks: books},
		g, srv.DatabaseWith(t, "fx", fxdb.Setup), w.ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.SetMid("EUR", "USD", "1.0850", time.Now()); err != nil {
		t.Fatal(err)
	}
	return serve(t, func(gs *grpc.Server) { fxv1.RegisterFXServiceServer(gs, fxapi.NewServer(eng, nil, nil)) })
}

// instance is one running gatewayd.
type instance struct {
	cancel context.CancelFunc
	done   chan struct{}
	code   int
	once   sync.Once
	api    string
	grpc   string
	ops    string
	led    chan struct{}
	stderr *syncBuffer
}

func (w *world) start() *instance {
	w.t.Helper()
	runCtx, cancel := context.WithCancel(context.Background())
	in := &instance{cancel: cancel, done: make(chan struct{}), led: make(chan struct{}, 1), stderr: &syncBuffer{}}
	addrs := make(chan func(), 3)
	go func() {
		defer close(in.done)
		in.code = gatewayd.Main(runCtx, nil, config.FromMap(w.env), &bytes.Buffer{}, in.stderr, gatewayd.Hooks{
			OnAPIListening:  func(a string) { addrs <- func() { in.api = a } },
			OnGRPCListening: func(a string) { addrs <- func() { in.grpc = a } },
			OnListening:     func(a string) { addrs <- func() { in.ops = a } },
			OnLeading: func(l bool) {
				if l {
					select {
					case in.led <- struct{}{}:
					default:
					}
				}
			},
		})
	}()
	for i := 0; i < 3; i++ {
		select {
		case set := <-addrs:
			set()
		case <-in.done:
			w.t.Fatalf("gatewayd exited %d: %s", in.code, in.stderr.String())
		case <-time.After(30 * time.Second):
			w.t.Fatalf("gatewayd did not start: %s", in.stderr.String())
		}
	}
	w.t.Cleanup(in.stop)
	return in
}

// stop shuts the instance down and returns its exit code.
func (in *instance) stop() {
	in.once.Do(func() {
		in.cancel()
		select {
		case <-in.done:
		case <-time.After(30 * time.Second):
		}
	})
}

func (in *instance) client(t *testing.T) *apiclient.Client {
	return apiclient.New(t, "http://"+in.api, origin)
}

func (in *instance) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := http.Get("http://" + in.ops + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// realtimeClient is the realtime gateway's mTLS connection to the
// internal API.
func (w *world) realtimeClient(in *instance, files grpcx.TLSFiles) *intentsapi.Client {
	w.t.Helper()
	creds, err := grpcx.ClientTLS(files)
	if err != nil {
		w.t.Fatal(err)
	}
	conn, err := grpc.NewClient(in.grpc, grpc.WithTransportCredentials(creds))
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = conn.Close() })
	return intentsapi.NewClient(conn)
}

func TestGatewayEndToEnd(t *testing.T) {
	w := newWorld(t)
	in := w.start()
	select {
	case <-in.led:
	case <-time.After(30 * time.Second):
		t.Fatalf("never led: %s", in.stderr.String())
	}
	if code, body := in.get(t, "/readyz"); code != http.StatusOK {
		t.Fatalf("readyz %d %s", code, body)
	}
	events, err := w.nc.SubscribeSync("bilyon.gateway.intent.>")
	if err != nil {
		t.Fatal(err)
	}
	auth := authenticator.New(t)

	// Alice signs up, binds her phone and signs in on it.
	alice := in.client(t)
	aliceCred := auth.NewCredential(cose.AlgES256)
	alice.Register(auth, aliceCred, "Alice", clientID)
	phone := w.google.NewDevice(false)
	_, dev := alice.BindAndroid(phone, "dev", uuid.Nil)
	gest, g := alice.BindAndroid(phone, "gest", dev.Device.ID)
	alice.Expect(alice.Login(auth, aliceCred, clientID, &dev.Device.ID), http.StatusOK, nil)
	// A deposit, outside this test's scope, funds her euro account.
	gwPool, err := pgxpool.New(ctx(t), w.gwDB)
	if err != nil {
		t.Fatal(err)
	}
	defer gwPool.Close()
	acct, err := accounts.New(gwPool, w.ledger).Ensure(ctx(t), alice.UserID, "EUR")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ledger.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: "deposit:alice", Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: w.nostro, Amount: -500_00}, {AccountID: acct.AccountID, Amount: 500_00}}}); err != nil {
		t.Fatal(err)
	}

	// Bob signs up and claims a handle; Alice resolves and verifies it.
	bob := in.client(t)
	bob.Register(auth, auth.NewCredential(cose.AlgES256), "Bob", clientID)
	bob.Expect(bob.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "bob_b"}), http.StatusOK, nil)
	var p struct {
		PAR gatewayapi.Bytes `json:"par"`
	}
	alice.Expect(alice.Do(http.MethodGet, "/v1/directory/handles/bob_b", nil), http.StatusOK, &p)
	par, err := identity.VerifyPAR(p.PAR, func(kid []byte) (*ecdsa.PublicKey, error) {
		if string(kid) != "dir-2026" {
			return nil, cose.ErrUnknownKey
		}
		return &w.dirKey.PublicKey, nil
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Alice flicks 42.00 at Bob through the REST API.
	var ns struct {
		Nonces []struct {
			Value gatewayapi.Bytes `json:"value"`
		} `json:"nonces"`
	}
	alice.Expect(alice.Do(http.MethodPost, "/v1/intents/nonces", map[string]any{"count": 1}), http.StatusOK, &ns)
	id := uuid.Must(uuid.NewV7())
	now := time.Now()
	ta := txauth.TxAuth{IntentID: id, Amount: 42_00, Currency: "EUR", PayeeRef: identity.PayeeRef(par.Entry.Subject),
		SignedAt: now.Truncate(time.Second), Gesture: txauth.GestureFlick, PARVersion: par.Entry.Version}
	copy(ta.Nonce[:], ns.Nonces[0].Value)
	signer, _ := cose.NewKeySigner(gest)
	raw, err := txauth.Sign(signer, g.Key.ID, &ta)
	if err != nil {
		t.Fatal(err)
	}
	var thrown struct {
		State string `json:"state"`
	}
	alice.Expect(alice.Do(http.MethodPost, "/v1/intents", map[string]any{"txauth": gatewayapi.Bytes(raw), "gesture": "flick",
		"payee_subject": par.Entry.Subject, "amount": 42_00, "currency": "EUR",
		"t_land_ms": now.Add(450 * time.Millisecond).UnixMilli()}), http.StatusOK, &thrown)
	if thrown.State != "held" {
		t.Fatalf("thrown %+v", thrown)
	}
	awaitEvent(t, events, "bilyon.gateway.intent.held", id)

	// The realtime gateway delivers INCOMING and relays Bob's CATCH.
	rt := w.realtimeClient(in, w.realtime)
	if d, err := rt.MarkDelivered(ctx(t), bob.UserID, id); err != nil || d.State != intents.StateDelivered {
		t.Fatalf("delivered %v %v", d, err)
	}
	caught, err := rt.Catch(ctx(t), intents.CatchRequest{IntentID: id, UserID: bob.UserID, Accept: true})
	if err != nil || caught.State != intents.StateSettled {
		t.Fatalf("catch %v %v", caught, err)
	}
	awaitEvent(t, events, "bilyon.gateway.intent.settled", id)
	var balances struct {
		Accounts []struct {
			Currency string `json:"currency"`
			Posted   int64  `json:"posted"`
		} `json:"accounts"`
	}
	bob.Expect(bob.Do(http.MethodGet, "/v1/accounts", nil), http.StatusOK, &balances)
	if len(balances.Accounts) != 1 || balances.Accounts[0].Posted != 42_00 {
		t.Fatalf("bob's accounts %+v", balances)
	}

	// Only the realtime gateway's identity may call the internal API.
	intruder := w.realtimeClient(in, w.ca.Leaf("intruder", "spiffe://bilyon/intruder", "intruder"))
	if _, err := intruder.Get(ctx(t), bob.UserID, id); !isCode(err, codes.PermissionDenied) {
		t.Fatalf("intruder: %v", err)
	}
	conn, err := grpc.NewClient(in.grpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := intentsapi.NewClient(conn).Get(ctx(t), bob.UserID, id); err == nil {
		t.Fatal("plaintext call to the internal API succeeded")
	}

	// Cross-currency quotes go to the FX service.
	var quote struct {
		ID        uuid.UUID `json:"id"`
		AmountOut int64     `json:"amount_out"`
		State     string    `json:"state"`
	}
	alice.Expect(alice.Do(http.MethodPost, "/v1/fx/quotes", map[string]any{"from": "EUR", "to": "USD", "amount_in": 100_00,
		"ttl_ms": 60_000}), http.StatusCreated, &quote)
	if quote.AmountOut <= 0 || quote.State != "open" {
		t.Fatalf("quote %+v", quote)
	}
	alice.Expect(alice.Do(http.MethodGet, "/v1/fx/quotes/"+quote.ID.String(), nil), http.StatusOK, nil)
	if r := bob.Do(http.MethodGet, "/v1/fx/quotes/"+quote.ID.String(), nil); r.Status != http.StatusNotFound {
		t.Fatalf("someone else's quote: %d", r.Status)
	}

	// The leader publishes signed tree heads; metrics are exposed.
	anon := in.client(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if r := anon.Anonymous(http.MethodGet, "/v1/directory/sth", nil); r.Status == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no tree head published")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, metrics := in.get(t, "/metrics")
	for _, m := range []string{"bilyon_gateway_leader 1", "bilyon_gateway_http_request_duration_seconds",
		"bilyon_intents_transitions_total", "bilyon_gateway_intent_sweeps_total"} {
		if !strings.Contains(metrics, m) {
			t.Fatalf("metrics lack %s", m)
		}
	}
	in.stop()
	if in.code != 0 {
		t.Fatalf("exit %d: %s", in.code, in.stderr.String())
	}

	// What the runtime role must never do.
	runtime, err := pgxpool.New(ctx(t), runtimeURL(w.gwDB))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, sql := range []string{
		"UPDATE tlog_leaves SET data = ''::bytea",
		"DELETE FROM tlog_leaves",
		"UPDATE tlog_nodes SET hash = hash",
		"DELETE FROM tlog_sths",
		"DELETE FROM payment_intents",
		"UPDATE payment_intents SET amount_minor = 1",
		"UPDATE payment_intents SET txauth = ''::bytea",
		"UPDATE payment_intents SET payer_id = payee_id",
		"UPDATE users SET status = 'active'",
		"DELETE FROM webauthn_credentials",
		"UPDATE webauthn_credentials SET public_key = public_key",
		"UPDATE subjects SET subject = subject",
		"UPDATE device_keys SET public_key = public_key",
		"DELETE FROM devices",
		"UPDATE user_accounts SET account_id = account_id",
	} {
		_, err := runtime.Exec(ctx(t), sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: want permission denied, got %v", sql, err)
		}
	}
}

func isCode(err error, c codes.Code) bool {
	st, ok := status.FromError(err)
	if ok {
		return st.Code() == c
	}
	return strings.Contains(err.Error(), c.String()) || strings.Contains(strings.ToLower(err.Error()), "permission")
}

// awaitEvent waits for an outbox event of the intent on subject.
func awaitEvent(t *testing.T, sub *nats.Subscription, subject string, id uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := sub.NextMsg(time.Until(deadline))
		if err != nil {
			break
		}
		if msg.Subject != subject {
			continue
		}
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(msg.Data, &env); err != nil {
			t.Fatal(err)
		}
		if env.Data["intent_id"] == id.String() {
			return
		}
	}
	t.Fatalf("no %s event for %s", subject, id)
}

func TestConfigurationErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := gatewayd.Main(context.Background(), []string{"run"}, config.FromMap(map[string]string{}), &out, &errOut,
		gatewayd.Hooks{}); code != 2 || !strings.Contains(errOut.String(), "BILYON_DATABASE_URL") {
		t.Fatalf("empty environment: %d %s", code, errOut.String())
	}
	errOut.Reset()
	env := map[string]string{"BILYON_DATABASE_URL": "postgres://x", "BILYON_REDIS_URL": "redis://x", "BILYON_NATS_URL": "nats://x",
		"BILYON_API_ORIGIN": "http://insecure.example", "BILYON_API_CLIENTS": "a", "BILYON_SESSION_KEY_FILE": "k",
		"BILYON_DPOP_NONCE_KEYS_FILE": "k", "BILYON_INTENT_NONCE_KEYS_FILE": "k", "BILYON_DIRECTORY_KEY_FILE": "k",
		"BILYON_DIRECTORY_KEY_ID": "d", "BILYON_WEBAUTHN_RP_ID": "x", "BILYON_WEBAUTHN_ORIGINS": "https://x",
		"BILYON_LEDGER_ADDR": "x", "BILYON_LEDGER_INSECURE": "true", "BILYON_GRPC_ADDR": "x", "BILYON_GRPC_INSECURE": "true"}
	if code := gatewayd.Main(context.Background(), nil, config.FromMap(env), &out, &errOut, gatewayd.Hooks{}); code != 2 ||
		!strings.Contains(errOut.String(), "BILYON_API_ORIGIN") || !strings.Contains(errOut.String(), "device binding") {
		t.Fatalf("invalid configuration: %d %s", code, errOut.String())
	}
	if code := gatewayd.Main(context.Background(), []string{"bogus"}, config.FromMap(env), &out, &errOut, gatewayd.Hooks{}); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
	out.Reset()
	if code := gatewayd.Main(context.Background(), []string{"help"}, config.FromMap(env), &out, &errOut, gatewayd.Hooks{}); code != 0 ||
		!strings.Contains(out.String(), "migrate") {
		t.Fatalf("help: %d %s", code, out.String())
	}
}

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good.keys", []byte("# rotated in 2026\n\n"+randomB64(t)+"\n"+randomB64(t)+"\n"))
	keys, err := gatewayd.LoadSymmetricKeys(good, 32)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys %d %v", len(keys), err)
	}
	for name, content := range map[string]string{"empty": "# nothing\n", "not base64": "!!!\n",
		"short": base64.StdEncoding.EncodeToString([]byte("short")) + "\n"} {
		if _, err := gatewayd.LoadSymmetricKeys(writeFile(t, dir, name, []byte(content)), 32); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if d, err := gatewayd.ParseDigests("AB:" + strings.Repeat("cd", 31) + ", " + strings.Repeat("01", 32)); err != nil || len(d) != 2 {
		t.Fatalf("digests %v %v", d, err)
	}
	for _, bad := range []string{"", "abcd", strings.Repeat("zz", 32)} {
		if _, err := gatewayd.ParseDigests(bad); err == nil {
			t.Errorf("digest %q accepted", bad)
		}
	}
	limits := writeFile(t, dir, "limits.json", []byte(`{"EUR": {"gesture": 5000, "gesture_window": 20000, "daily": 100000}}`))
	l, err := gatewayd.LoadLimits(limits)
	if err != nil || l["EUR"].Gesture != 5000 || l["EUR"].Daily != 100000 {
		t.Fatalf("limits %v %v", l, err)
	}
	if _, err := gatewayd.LoadLimits(writeFile(t, dir, "bad.json", []byte(`{"EUR": {"gestures": 1}}`))); err == nil {
		t.Fatal("unknown limit field accepted")
	}
	if _, err := gatewayd.LoadAESKey(writeFile(t, dir, "aes", []byte(base64.StdEncoding.EncodeToString(make([]byte, 16)))), 32); err == nil {
		t.Fatal("short AES key accepted")
	}
	if _, err := gatewayd.LoadCertPool(writeFile(t, dir, "nocert.pem", []byte("hello"))); err == nil {
		t.Fatal("empty cert pool accepted")
	}
	k := newKey(t)
	if got, err := gatewayd.LoadPrivateKey(writeFile(t, dir, "k.pem", pemPrivate(t, k))); err != nil || !got.Equal(k) {
		t.Fatalf("private key %v", err)
	}
	if got, err := gatewayd.LoadPublicKey(writeFile(t, dir, "p.pem", pemPublic(t, &k.PublicKey))); err != nil || !got.Equal(&k.PublicKey) {
		t.Fatalf("public key %v", err)
	}
}
