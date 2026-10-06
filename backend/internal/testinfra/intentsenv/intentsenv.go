// Package intentsenv assembles a working payment stack over real
// infrastructure for tests of the layers above the orchestrator (its gRPC
// API, the gateway daemon): a migrated gateway database, a PostgreSQL
// ledger, device binding with attested Android phones, the directory,
// account resolution and the intent service.
package intentsenv

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

// Clock is real time plus an adjustable offset.
type Clock struct {
	mu    sync.Mutex
	shift time.Duration
}

// Now returns the shifted time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.shift)
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shift += d
}

// Person is a user with a handle; with a phone, an attested Android device
// holding K_dev and K_gest.
type Person struct {
	User    uuid.UUID
	Subject string
	Device  uuid.UUID
	Dev     *ecdsa.PrivateKey
	DevKey  uuid.UUID
	Gest    *ecdsa.PrivateKey
	GestKey uuid.UUID
	phone   *devicesim.AndroidDevice
}

// Env is the assembled stack.
type Env struct {
	T        testing.TB
	Clock    *Clock
	Pool     *pgxpool.Pool // the gateway database
	Ledger   *pgledger.Engine
	Binder   *devicebind.Service
	Dir      *identity.Service
	Accounts *accounts.Resolver
	Intents  *intents.Service
	Config   intents.Config
	Google   *devicesim.Google // the Android trust root the binder accepts
	Redis    *redis.Client
	DirKey   *cose.KeySigner // K_dir
	DirKeyID []byte
	nostro   map[string]uuid.UUID
}

// NonceKey is the intent service's nonce MAC key in tests.
var NonceKey = []byte("intentsenv nonce key, 32+ bytes!")

func ctx(t testing.TB) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

// New builds the stack on srv, whose template is the gateway schema.
func New(t testing.TB, srv *pgtest.Server, edit func(*intents.Config)) *Env {
	t.Helper()
	e := &Env{T: t, Clock: &Clock{}, Pool: srv.Database(t), nostro: map[string]uuid.UUID{},
		Google: devicesim.NewGoogle(t), Redis: redistest.Start(t), DirKeyID: []byte("dir1")}
	e.Ledger = pgledger.New(srv.DatabaseWith(t, "ledger", ledgerdb.Setup))
	for _, cur := range []string{"EUR", "USD"} {
		a, err := e.Ledger.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: "nostro:" + cur, Kind: ledger.KindNostro,
			Currency: cur})
		if err != nil {
			t.Fatal(err)
		}
		e.nostro[cur] = a.ID
	}
	var err error
	if e.Binder, err = devicebind.New(devicebind.Config{
		Android: devicebind.AndroidConfig{PackageName: e.Google.PackageName,
			SigningCertDigests: [][]byte{e.Google.SigningCert}, Roots: e.Google.CA.Pool()},
		Integrity: &devicebind.IntegrityConfig{DecryptionKey: e.Google.DecryptionKey,
			VerificationKey: &e.Google.VerificationKey.PublicKey},
		Now: e.Clock.Now,
	}, e.Redis, e.Pool); err != nil {
		t.Fatal(err)
	}
	if e.DirKey, err = cose.GenerateKeySigner(); err != nil {
		t.Fatal(err)
	}
	if e.Dir, err = identity.New(identity.Config{Signer: e.DirKey, KeyID: e.DirKeyID, Now: e.Clock.Now}, e.Pool); err != nil {
		t.Fatal(err)
	}
	e.Accounts = accounts.New(e.Pool, e.Ledger)
	e.Config = intents.Config{NonceKeys: [][]byte{NonceKey}, Now: e.Clock.Now}
	if edit != nil {
		edit(&e.Config)
	}
	if e.Intents, err = intents.New(e.Config, e.Pool, e.Binder, e.Dir, nil, e.Ledger, e.Accounts); err != nil {
		t.Fatal(err)
	}
	return e
}

// Person creates a user who claims handle; phone binds an attested device.
func (e *Env) Person(handle string, phone bool) *Person {
	t := e.T
	t.Helper()
	u, err := webauthn.NewPGStore(e.Pool).CreateUser(ctx(t), handle)
	if err != nil {
		t.Fatal(err)
	}
	p := &Person{User: u.ID}
	if _, _, err := e.Dir.ClaimHandle(ctx(t), p.User, handle); err != nil {
		t.Fatal(err)
	}
	if p.Subject, err = e.Dir.Subject(ctx(t), p.User); err != nil {
		t.Fatal(err)
	}
	if phone {
		p.phone = e.Google.NewDevice(false)
		var b devicebind.Binding
		p.Dev, b = e.bind(p, uuid.Nil, devicebind.RoleDevice)
		p.Device, p.DevKey = b.Device.ID, b.Key.ID
		p.Gest, b = e.bind(p, p.Device, devicebind.RoleGesture)
		p.GestKey = b.Key.ID
	}
	return p
}

func (e *Env) bind(p *Person, device uuid.UUID, role string) (*ecdsa.PrivateKey, devicebind.Binding) {
	t := e.T
	t.Helper()
	ch, err := e.Binder.Begin(ctx(t), p.User, device, devicebind.PurposeBind)
	if err != nil {
		t.Fatal(err)
	}
	key, chain := p.phone.GenerateKey(role, ch.Challenge, devicesim.KeyOptions{})
	b, err := e.Binder.FinishAndroid(ctx(t), p.User, ch.FlowID, devicebind.AndroidBinding{Role: role, Chain: chain,
		IntegrityToken: p.phone.IntegrityToken(ch.Challenge, devicesim.Point(t, key), nil)})
	if err != nil {
		t.Fatal(err)
	}
	return key, b
}

// Fund opens p's account in cur and deposits amount.
func (e *Env) Fund(p *Person, cur string, amount int64) uuid.UUID {
	t := e.T
	t.Helper()
	a, err := e.Accounts.Ensure(ctx(t), p.User, cur)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Ledger.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: "fund:" + uuid.NewString(), Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: e.nostro[cur], Amount: -amount}, {AccountID: a.AccountID, Amount: amount}}}); err != nil {
		t.Fatal(err)
	}
	return a.AccountID
}

// Balance is p's posted and available balance in cur (zero without an
// account).
func (e *Env) Balance(p *Person, cur string) (int64, int64) {
	t := e.T
	t.Helper()
	a, err := e.Accounts.Get(ctx(t), p.User, cur)
	if errors.Is(err, accounts.ErrNotFound) {
		return 0, 0
	}
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Ledger.Balance(ctx(t), a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	return b.Posted, b.Available
}

// Version is p's current directory entry version.
func (e *Env) Version(p *Person) uint64 {
	t := e.T
	t.Helper()
	v, err := e.Dir.CurrentVersion(ctx(t), p.Subject)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Payment is an unsigned payment from payer to payee: by default a K_gest
// flick in EUR landing 450 ms after signing.
type Payment struct {
	Signer *ecdsa.PrivateKey
	KeyID  uuid.UUID
	Auth   txauth.TxAuth
	Req    intents.CreateRequest
}

// Flick prepares a flick with a fresh server nonce.
func (e *Env) Flick(payer, payee *Person, amount int64) *Payment {
	t := e.T
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := e.Intents.IssueNonces(ctx(t), payer.User, payer.Device, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := e.Clock.Now()
	return &Payment{Signer: payer.Gest, KeyID: payer.GestKey,
		Auth: txauth.TxAuth{IntentID: id, Amount: amount, Currency: "EUR", PayeeRef: identity.PayeeRef(payee.Subject),
			Nonce: ns[0].Value, SignedAt: now.Truncate(time.Second), Gesture: txauth.GestureFlick,
			PARVersion: e.Version(payee)},
		Req: intents.CreateRequest{SubmitterID: payer.User, Gesture: intents.GestureFlick, PayeeSubject: payee.Subject,
			Amount: amount, Currency: "EUR", TLand: now.Add(450 * time.Millisecond).Truncate(time.Millisecond),
			Trajectory: &intents.Trajectory{Azimuth: -0.2, Speed: 1.8, Distance: 1.2}}}
}

// Handle turns p into a K_dev payment to a handle.
func (p *Payment) Handle(payer *Person) *Payment {
	p.Signer, p.KeyID = payer.Dev, payer.DevKey
	p.Auth.Gesture, p.Req.Gesture = txauth.GestureNone, intents.GestureHandle
	p.Req.TLand, p.Req.Trajectory = time.Time{}, nil
	return p
}

// Sign returns the request with its signed TxAuth.
func (e *Env) Sign(p *Payment) intents.CreateRequest {
	t := e.T
	t.Helper()
	signer, err := cose.NewKeySigner(p.Signer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := txauth.Sign(signer, p.KeyID, &p.Auth)
	if err != nil {
		t.Fatal(err)
	}
	req := p.Req
	req.TxAuth = raw
	return req
}
