package intents

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	fxv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/fx/v1"
	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/fxapi"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/fxdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

// clock is a shiftable wall clock: real time plus an offset, so that the
// ledger's own database clock stays in step until a test jumps ahead.
type clock struct {
	mu    sync.Mutex
	shift time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.shift)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shift += d
}

// party is a person with a directory entry and, for payers, an attested
// Android phone with K_dev and K_gest.
type party struct {
	user    uuid.UUID
	subject string
	device  uuid.UUID
	phone   *devicesim.AndroidDevice
	dev     *ecdsa.PrivateKey
	devKey  uuid.UUID
	gest    *ecdsa.PrivateKey
	gestKey uuid.UUID
}

// faultyLedger is the real ledger with injected outages: fail[op] > 0
// makes the next calls of op fail, before (lost) or after (committed but
// the answer lost) the real call.
type faultyLedger struct {
	ledger.Ledger
	mu      sync.Mutex
	fail    map[string]int
	after   map[string]bool
	refusal map[string]error // the next call of op is refused with this error
}

func (l *faultyLedger) refuse(op string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refusal[op] = err
}

func (l *faultyLedger) refused(op string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.refusal[op]
	delete(l.refusal, op)
	return err
}

var errOutage = errors.New("injected outage")

func (l *faultyLedger) inject(op string, n int, afterCommit bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail[op], l.after[op] = n, afterCommit
}

func (l *faultyLedger) fault(op string) (bool, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail[op] == 0 {
		return false, false
	}
	l.fail[op]--
	return true, l.after[op]
}

func outage(op string) error {
	return errors.Join(ledger.ErrUnavailable, errors.New(op+": "+errOutage.Error()))
}

func (l *faultyLedger) PlaceHold(ctx context.Context, cmd ledger.PlaceHold) (ledger.Hold, error) {
	if f, after := l.fault("hold"); f {
		if after {
			_, _ = l.Ledger.PlaceHold(ctx, cmd)
		}
		return ledger.Hold{}, outage("hold")
	}
	return l.Ledger.PlaceHold(ctx, cmd)
}

func (l *faultyLedger) PostHold(ctx context.Context, cmd ledger.PostHold) (ledger.PostHoldResult, error) {
	if err := l.refused("post"); err != nil {
		return ledger.PostHoldResult{}, err
	}
	if f, after := l.fault("post"); f {
		if after {
			_, _ = l.Ledger.PostHold(ctx, cmd)
		}
		return ledger.PostHoldResult{}, outage("post")
	}
	return l.Ledger.PostHold(ctx, cmd)
}

func (l *faultyLedger) VoidHold(ctx context.Context, cmd ledger.VoidHold) (ledger.Hold, error) {
	if f, after := l.fault("void"); f {
		if after {
			_, _ = l.Ledger.VoidHold(ctx, cmd)
		}
		return ledger.Hold{}, outage("void")
	}
	return l.Ledger.VoidHold(ctx, cmd)
}

type fixture struct {
	t        *testing.T
	c        *clock
	pool     *pgxpool.Pool
	pg       *pgledger.Engine
	ledger   *faultyLedger
	google   *devicesim.Google
	binder   *devicebind.Service
	dir      *identity.Service
	accts    *accounts.Resolver
	cfg      Config
	svc      *Service
	nostro   map[string]uuid.UUID
	payer    *party
	payee    *party
	stranger *party

	// FX, when the test asks for it: a real engine behind gRPC.
	fxc     *clock
	fxg     *fx.Graph
	fxe     *fx.Engine
	fxbooks map[string]uuid.UUID
}

var nonceKey = []byte("0123456789abcdef0123456789abcdef")

func newFixture(t *testing.T, edit func(*Config)) *fixture {
	t.Helper()
	t.Parallel()
	f := &fixture{t: t, c: &clock{}, pool: srv.Database(t), nostro: map[string]uuid.UUID{}}
	f.pg = pgledger.New(srv.DatabaseWith(t, "ledger", ledgerdb.Setup))
	f.ledger = &faultyLedger{Ledger: f.pg, fail: map[string]int{}, after: map[string]bool{}, refusal: map[string]error{}}
	for _, cur := range []string{"EUR", "USD"} {
		f.nostro[cur] = f.account(ledger.KindNostro, cur, nil)
	}
	f.google = devicesim.NewGoogle(t)
	var err error
	if f.binder, err = devicebind.New(devicebind.Config{
		Android: devicebind.AndroidConfig{PackageName: f.google.PackageName,
			SigningCertDigests: [][]byte{f.google.SigningCert}, Roots: f.google.CA.Pool()},
		Integrity: &devicebind.IntegrityConfig{DecryptionKey: f.google.DecryptionKey,
			VerificationKey: &f.google.VerificationKey.PublicKey},
		Now: f.c.now,
	}, redistest.Start(t), f.pool); err != nil {
		t.Fatal(err)
	}
	dirKey, err := cose.GenerateKeySigner()
	if err != nil {
		t.Fatal(err)
	}
	if f.dir, err = identity.New(identity.Config{Signer: dirKey, KeyID: []byte("dir1"), Now: f.c.now}, f.pool); err != nil {
		t.Fatal(err)
	}
	f.accts = accounts.New(f.pool, f.ledger)
	f.payer = f.person("alicia", true)
	f.payee = f.person("bruno", false)
	f.stranger = f.person("carmen", true)
	f.fund(f.payer, "EUR", 1_000_00)
	f.cfg = Config{NonceKeys: [][]byte{nonceKey}, Now: f.c.now}
	if edit != nil {
		edit(&f.cfg)
	}
	f.svc = f.service(f.cfg, nil)
	return f
}

func (f *fixture) service(cfg Config, fxs FX) *Service {
	f.t.Helper()
	s, err := New(cfg, f.pool, f.binder, f.dir, fxs, f.ledger, f.accts)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) account(kind ledger.AccountKind, cur string, owner *uuid.UUID) uuid.UUID {
	f.t.Helper()
	a, err := f.pg.CreateAccount(ctx(f.t), ledger.CreateAccount{IdempotencyKey: "acct:" + uuid.NewString(), Kind: kind,
		Currency: cur, OwnerID: owner})
	if err != nil {
		f.t.Fatal(err)
	}
	return a.ID
}

// person creates a user with a handle; phone binds an attested device with
// K_dev and K_gest.
func (f *fixture) person(handle string, phone bool) *party {
	f.t.Helper()
	u, err := webauthn.NewPGStore(f.pool).CreateUser(ctx(f.t), handle)
	if err != nil {
		f.t.Fatal(err)
	}
	p := &party{user: u.ID}
	if _, _, err := f.dir.ClaimHandle(ctx(f.t), p.user, handle); err != nil {
		f.t.Fatal(err)
	}
	if p.subject, err = f.dir.Subject(ctx(f.t), p.user); err != nil {
		f.t.Fatal(err)
	}
	if phone {
		p.phone = f.google.NewDevice(false)
		var b devicebind.Binding
		p.dev, b = f.bind(p, uuid.Nil, devicebind.RoleDevice)
		p.device, p.devKey = b.Device.ID, b.Key.ID
		p.gest, b = f.bind(p, p.device, devicebind.RoleGesture)
		p.gestKey = b.Key.ID
	}
	return p
}

func (f *fixture) bind(p *party, device uuid.UUID, role string) (*ecdsa.PrivateKey, devicebind.Binding) {
	f.t.Helper()
	ch, err := f.binder.Begin(ctx(f.t), p.user, device, devicebind.PurposeBind)
	if err != nil {
		f.t.Fatal(err)
	}
	key, chain := p.phone.GenerateKey(role, ch.Challenge, devicesim.KeyOptions{})
	b, err := f.binder.FinishAndroid(ctx(f.t), p.user, ch.FlowID, devicebind.AndroidBinding{Role: role, Chain: chain,
		IntegrityToken: p.phone.IntegrityToken(ch.Challenge, devicesim.Point(f.t, key), nil)})
	if err != nil {
		f.t.Fatal(err)
	}
	return key, b
}

// fund opens the party's account in cur and deposits amount.
func (f *fixture) fund(p *party, cur string, amount int64) uuid.UUID {
	f.t.Helper()
	a, err := f.accts.Ensure(ctx(f.t), p.user, cur)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.pg.Transfer(ctx(f.t), ledger.Transfer{IdempotencyKey: "fund:" + uuid.NewString(), Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: f.nostro[cur], Amount: -amount}, {AccountID: a.AccountID, Amount: amount}}}); err != nil {
		f.t.Fatal(err)
	}
	return a.AccountID
}

// balance is the party's (posted, available) balance in cur; zero without
// an account.
func (f *fixture) balance(p *party, cur string) (int64, int64) {
	f.t.Helper()
	a, err := f.accts.Get(ctx(f.t), p.user, cur)
	if errors.Is(err, accounts.ErrNotFound) {
		return 0, 0
	}
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := f.pg.Balance(ctx(f.t), a.AccountID)
	if err != nil {
		f.t.Fatal(err)
	}
	return b.Posted, b.Available
}

func (f *fixture) wantBalance(p *party, cur string, posted, available int64) {
	f.t.Helper()
	if gp, ga := f.balance(p, cur); gp != posted || ga != available {
		f.t.Fatalf("%s balance posted %d available %d, want %d / %d", cur, gp, ga, posted, available)
	}
}

func (f *fixture) nonce(p *party) [16]byte {
	f.t.Helper()
	ns, err := f.svc.IssueNonces(ctx(f.t), p.user, p.device, 1)
	if err != nil {
		f.t.Fatal(err)
	}
	return ns[0].Value
}

// throw describes a payment for sign: a flick of 25.00 EUR from the payer
// to the payee with K_gest, unless edited.
type throw struct {
	signer  *ecdsa.PrivateKey
	keyID   uuid.UUID
	ta      txauth.TxAuth
	req     CreateRequest
	payload func(*txauth.TxAuth) // edits the signed fields only
}

func (f *fixture) flick(amount int64) *throw {
	f.t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		f.t.Fatal(err)
	}
	now := f.c.now()
	signed := now.Truncate(time.Second)
	version := f.version(f.payee)
	th := &throw{signer: f.payer.gest, keyID: f.payer.gestKey,
		ta: txauth.TxAuth{IntentID: id, Amount: amount, Currency: "EUR", PayeeRef: identity.PayeeRef(f.payee.subject),
			Nonce: f.nonce(f.payer), SignedAt: signed, Gesture: txauth.GestureFlick, PARVersion: version},
		req: CreateRequest{SubmitterID: f.payer.user, Gesture: GestureFlick, PayeeSubject: f.payee.subject,
			Amount: amount, Currency: "EUR", TLand: now.Add(450 * time.Millisecond),
			Trajectory: &Trajectory{Azimuth: 0.4, Speed: 1.5, Distance: 1.5}}}
	return th
}

// handle turns the throw into a K_dev payment to a handle.
func (th *throw) handle(p *party) *throw {
	th.signer, th.keyID = p.dev, p.devKey
	th.ta.Gesture, th.req.Gesture = txauth.GestureNone, GestureHandle
	th.req.TLand, th.req.Trajectory = time.Time{}, nil
	return th
}

// drop turns the throw into a drop.
func (th *throw) drop() *throw {
	th.ta.Gesture, th.req.Gesture = txauth.GestureGrab, GestureGrab
	th.ta.PayeeRef, th.ta.PARVersion = txauth.DropPayeeRef(th.ta.IntentID), 0
	th.req.PayeeSubject, th.req.TLand, th.req.Trajectory = "", time.Time{}, nil
	return th
}

func (f *fixture) version(p *party) uint64 {
	f.t.Helper()
	v, err := f.dir.CurrentVersion(ctx(f.t), p.subject)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *fixture) sign(th *throw) CreateRequest {
	f.t.Helper()
	ta := th.ta
	if th.payload != nil {
		th.payload(&ta)
	}
	signer, err := cose.NewKeySigner(th.signer)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := txauth.Sign(signer, th.keyID, &ta)
	if err != nil {
		f.t.Fatal(err)
	}
	req := th.req
	req.TxAuth = raw
	return req
}

func (f *fixture) create(th *throw) *Intent {
	f.t.Helper()
	in, err := f.svc.Create(ctx(f.t), f.sign(th))
	if err != nil {
		f.t.Fatalf("Create: %v", err)
	}
	return in
}

func (f *fixture) state(id uuid.UUID) *Intent {
	f.t.Helper()
	in, err := f.svc.db.get(ctx(f.t), f.pool, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return in
}

func (f *fixture) hold(in *Intent) ledger.Hold {
	f.t.Helper()
	h, err := f.pg.Hold(ctx(f.t), in.HoldID)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func (f *fixture) events(topic string) []map[string]any {
	f.t.Helper()
	rows, err := f.pool.Query(ctx(f.t), `SELECT payload->'data' FROM outbox WHERE topic = $1 ORDER BY id`, topic)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			f.t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func (f *fixture) sweep() SweepResult {
	f.t.Helper()
	r, err := f.svc.Sweep(ctx(f.t))
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fixture) catch(p *party, id uuid.UUID, accept bool) (*Intent, error) {
	return f.svc.Catch(ctx(f.t), CatchRequest{IntentID: id, UserID: p.user, Accept: accept})
}

func wantState(t *testing.T, in *Intent, st State, reason string) {
	t.Helper()
	if in == nil {
		t.Fatalf("no intent, want %s", st)
	}
	if in.State != st || in.Reason != reason {
		t.Fatalf("intent is %s (%q), want %s (%q)", in.State, in.Reason, st, reason)
	}
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error %v, want %v", err, target)
	}
}

// withFX starts a real FX engine (EUR → USD at 1.0850) over the test's
// ledger behind an in-process gRPC server, and rebuilds the service with
// its client.
func (f *fixture) withFX() *fxapi.Client {
	f.t.Helper()
	f.fxc = &clock{}
	g, err := fx.NewGraph(fx.GraphConfig{Now: f.fxc.now}, fx.Currency{Code: "EUR", Exp: 2}, fx.Currency{Code: "USD", Exp: 2})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := g.AddEdge(fx.EdgeSpec{ID: "eur-usd", From: "EUR", To: "USD", Venue: "internal"},
		[]fx.Level{{Size: 1_000_000_00, Rate: "1.0850"}}); err != nil {
		f.t.Fatal(err)
	}
	f.fxg = g
	f.fxbooks = map[string]uuid.UUID{"EUR": f.account(ledger.KindFXBook, "EUR", nil),
		"USD": f.account(ledger.KindFXBook, "USD", nil)}
	if f.fxe, err = fx.NewEngine(fx.Config{Risk: map[string]fx.PairRisk{"EUR/USD": {SigmaAnnual: 0.07}},
		Keys:    []fx.QuoteKey{{ID: "k1", Secret: []byte("fedcba9876543210fedcba9876543210")}},
		FXBooks: f.fxbooks, Now: f.fxc.now}, g, srv.DatabaseWith(f.t, "fx", fxdb.Setup), f.ledger); err != nil {
		f.t.Fatal(err)
	}
	if err := f.fxe.SetMid("EUR", "USD", "1.0850", f.fxc.now()); err != nil {
		f.t.Fatal(err)
	}
	gs := grpc.NewServer()
	ready := &atomic.Bool{}
	ready.Store(true)
	api := fxapi.NewServer(f.fxe, ready.Load, nil)
	fxv1.RegisterFXServiceServer(gs, api)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	f.t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	client := fxapi.NewClient(conn)
	f.svc = f.service(f.cfg, client)
	return client
}

func (f *fixture) fxQuote(client *fxapi.Client, user uuid.UUID, amount int64, ttl time.Duration) *fx.Quote {
	f.t.Helper()
	q, err := client.CreateQuote(ctx(f.t), fx.QuoteRequest{UserID: user, From: "EUR", To: "USD", AmountIn: amount, TTL: ttl})
	if err != nil {
		f.t.Fatal(err)
	}
	return q
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}
