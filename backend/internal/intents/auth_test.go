package intents

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

func (f *fixture) intentCount() int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(ctx(f.t), `SELECT count(*) FROM payment_intents`).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestTxAuthRejected(t *testing.T) {
	f := newFixture(t, nil)
	submit := func(name string, req CreateRequest, target error) {
		t.Helper()
		if _, err := f.svc.Create(ctx(t), req); !errors.Is(err, target) {
			t.Fatalf("%s: %v, want %v", name, err, target)
		}
	}
	// Signed by another key under the payer's kid.
	th := f.flick(25_00)
	th.signer = f.stranger.gest
	submit("foreign signature", f.sign(th), ErrTxAuth)
	// A kid no key was bound under.
	th = f.flick(25_00)
	th.keyID = uuid.New()
	submit("unknown kid", f.sign(th), ErrTxAuth)
	// Not a COSE_Sign1, and a COSE_Sign1 for another artefact type.
	req := f.sign(f.flick(25_00))
	req.TxAuth = []byte("not cbor")
	submit("garbage", req, ErrTxAuth)
	th = f.flick(25_00)
	payload, _ := th.ta.Encode()
	signer, _ := cose.NewKeySigner(f.payer.gest)
	req = f.sign(th)
	req.TxAuth, _ = cose.Sign1(signer, f.payer.gestKey[:], payload, "bilyon/ost/v1")
	submit("other artefact type", req, ErrTxAuth)
	// A random (v4) intent id.
	th = f.flick(25_00)
	th.ta.IntentID = uuid.New()
	submit("UUIDv4 intent id", f.sign(th), ErrTxAuth)
	// K_gest authorises gestures, not payments to a handle.
	th = f.flick(25_00).handle(f.payer)
	th.signer, th.keyID = f.payer.gest, f.payer.gestKey
	submit("K_gest handle payment", f.sign(th), ErrTxAuth)
	// A K_off key is for offline tokens only.
	off, b := f.bind(f.payer, f.payer.device, devicebind.RoleOffline)
	th = f.flick(25_00).handle(f.payer)
	th.signer, th.keyID = off, b.Key.ID
	submit("K_off", f.sign(th), ErrTxAuth)
	// A revoked key, and a key whose device was revoked.
	if err := f.binder.RevokeKey(ctx(t), f.payer.user, f.payer.gestKey, "biometry_changed"); err != nil {
		t.Fatal(err)
	}
	submit("revoked key", f.sign(f.flick(25_00)), ErrTxAuth)
	dev := f.flick(25_00).handle(f.payer)
	devReq := f.sign(dev)
	if err := f.binder.Revoke(ctx(t), f.payer.user, f.payer.device, "lost"); err != nil {
		t.Fatal(err)
	}
	submit("revoked device", devReq, ErrTxAuth)
	if n := f.intentCount(); n != 0 {
		t.Fatalf("%d intents stored from rejected authorisations", n)
	}
	f.wantBalance(f.payer, "EUR", 1_000_00, 1_000_00)
}

func TestKeyRevokedDuringCreation(t *testing.T) {
	f := newFixture(t, nil)
	// The key is active when the signature is checked and revoked before
	// the creation transaction locks it: nothing is stored.
	keys := &revokingKeys{Keys: f.binder, revoke: func() {
		if err := f.binder.RevokeKey(ctx(t), f.payer.user, f.payer.gestKey, "lost"); err != nil {
			t.Error(err)
		}
	}}
	svc, err := New(f.cfg, f.pool, keys, f.dir, nil, f.ledger, f.accts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx(t), f.sign(f.flick(25_00))); !errors.Is(err, ErrTxAuth) {
		t.Fatalf("revoked under the lock: %v", err)
	}
	if n := f.intentCount(); n != 0 {
		t.Fatalf("%d intents", n)
	}
}

// revokingKeys revokes the key right after looking it up.
type revokingKeys struct {
	Keys
	revoke func()
}

func (k *revokingKeys) ActiveKey(c context.Context, id uuid.UUID) (devicebind.Key, error) {
	key, err := k.Keys.ActiveKey(c, id)
	k.revoke()
	return key, err
}

func TestNonceRules(t *testing.T) {
	f := newFixture(t, nil)
	submit := func(name string, th *throw, target error) {
		t.Helper()
		if _, err := f.svc.Create(ctx(t), f.sign(th)); !errors.Is(err, target) {
			t.Fatalf("%s: %v, want %v", name, err, target)
		}
	}
	// Issued to another device.
	th := f.flick(25_00)
	th.ta.Nonce = f.nonce(f.stranger)
	submit("foreign device", th, ErrNonce)
	// Tampered with.
	th = f.flick(25_00)
	th.ta.Nonce[15] ^= 1
	submit("tampered mac", th, ErrNonce)
	th = f.flick(25_00)
	th.ta.Nonce[0] ^= 1 // the issue time is under the MAC too
	submit("tampered time", th, ErrNonce)
	// Signed more than ten minutes after it was issued.
	stale := f.nonce(f.payer)
	f.c.advance(10*time.Minute + 2*time.Second)
	th = f.flick(25_00)
	th.ta.Nonce = stale
	submit("expired", th, ErrNonce)
	// Signed before it was issued (beyond the clock skew).
	th = f.flick(25_00)
	th.ta.SignedAt = th.ta.SignedAt.Add(-45 * time.Second)
	th.req.TLand = th.req.TLand.Add(-45 * time.Second)
	submit("signed before issue", th, ErrNonce)
	// From the future: issued beyond the skew, even for a signature that
	// is itself within it.
	future, err := f.svc.nonces.issue(f.payer.device, f.c.now().Add(45*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	th = f.flick(25_00)
	th.ta.Nonce = future.Value
	th.ta.SignedAt = th.ta.SignedAt.Add(20 * time.Second)
	th.req.TLand = th.req.TLand.Add(20 * time.Second)
	submit("future", th, ErrNonce)
	// Single use: a second intent with the same nonce.
	first := f.flick(25_00)
	f.create(first)
	th = f.flick(10_00)
	th.ta.Nonce = first.ta.Nonce
	submit("reused", th, ErrNonce)
	if n := f.intentCount(); n != 1 {
		t.Fatalf("%d intents", n)
	}
	// Rotation: nonces issued under the previous key still verify.
	rotated := f.service(Config{NonceKeys: [][]byte{randomKey(t), nonceKey}, Now: f.c.now}, nil)
	th = f.flick(5_00)
	if in, err := rotated.Create(ctx(t), f.sign(th)); err != nil || in.State != StateHeld {
		t.Fatalf("nonce under a rotated-out key: %v %v", in, err)
	}
	fresh, err := rotated.IssueNonces(ctx(t), f.payer.user, f.payer.device, 1)
	if err != nil {
		t.Fatal(err)
	}
	th = f.flick(5_00)
	th.ta.Nonce = fresh[0].Value
	submit("new key unknown to the old service", th, ErrNonce)
}

func TestFreshness(t *testing.T) {
	f := newFixture(t, nil)
	th := f.flick(25_00)
	th.ta.SignedAt = th.ta.SignedAt.Add(-61 * time.Second)
	th.req.TLand = th.req.TLand.Add(-61 * time.Second)
	if _, err := f.svc.Create(ctx(t), f.sign(th)); !errors.Is(err, ErrStale) {
		t.Fatalf("signed 61 s ago: %v", err)
	}
	th = f.flick(25_00)
	th.ta.SignedAt = th.ta.SignedAt.Add(32 * time.Second)
	th.req.TLand = th.req.TLand.Add(32 * time.Second)
	if _, err := f.svc.Create(ctx(t), f.sign(th)); !errors.Is(err, ErrStale) {
		t.Fatalf("signed in the future: %v", err)
	}
	// A relay arriving within the minute is accepted…
	th = f.flick(25_00)
	req := f.sign(th)
	req.SubmitterID = f.payee.user
	f.c.advance(55 * time.Second)
	in, err := f.svc.Create(ctx(t), req)
	if err != nil {
		t.Fatal(err)
	}
	// …and a retransmission long after is just a replay.
	f.c.advance(time.Hour)
	if again, err := f.svc.Create(ctx(t), req); err != nil || again.ID != in.ID {
		t.Fatalf("replay after an hour: %v %v", again, err)
	}
}

func TestRequestMustMatchTheSignature(t *testing.T) {
	f := newFixture(t, nil)
	for name, edit := range map[string]func(*throw){
		"amount":   func(th *throw) { th.req.Amount++ },
		"currency": func(th *throw) { th.req.Currency = "USD" },
		"payee": func(th *throw) {
			th.req.PayeeSubject = f.stranger.subject
		},
		"quote":         func(th *throw) { th.req.QuoteID = uuid.New() },
		"signed quote":  func(th *throw) { th.ta.QuoteID = uuid.NewString() },
		"gesture":       func(th *throw) { th.ta.Gesture = txauth.GestureSplit },
		"no version":    func(th *throw) { th.ta.PARVersion = 0 },
		"payee ref":     func(th *throw) { th.ta.PayeeRef = identity.PayeeRef(f.stranger.subject) },
		"drop with ref": func(th *throw) { th.drop(); th.ta.PayeeRef = identity.PayeeRef(f.payee.subject) },
		"drop version":  func(th *throw) { th.drop(); th.ta.PARVersion = 1 },
	} {
		th := f.flick(25_00)
		edit(th)
		if _, err := f.svc.Create(ctx(t), f.sign(th)); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := f.intentCount(); n != 0 {
		t.Fatalf("%d intents", n)
	}
}

func TestRequestValidation(t *testing.T) {
	f := newFixture(t, nil)
	for name, edit := range map[string]func(*throw){
		"gesture":            func(th *throw) { th.req.Gesture = "wave" },
		"flick without land": func(th *throw) { th.req.TLand = time.Time{} },
		"handle with land":   func(th *throw) { th.handle(f.payer); th.req.TLand = f.c.now() },
		"handle trajectory":  func(th *throw) { th.handle(f.payer); th.req.Trajectory = &Trajectory{} },
		"bad subject":        func(th *throw) { th.req.PayeeSubject = "alice" },
		"drop with payee":    func(th *throw) { th.drop(); th.req.PayeeSubject = f.payee.subject },
		"trajectory NaN":     func(th *throw) { th.req.Trajectory.Speed = math.NaN() },
		"trajectory range":   func(th *throw) { th.req.Trajectory.Azimuth = 4 },
		"landing too late":   func(th *throw) { th.req.TLand = th.req.TLand.Add(time.Minute) },
		"landing too early":  func(th *throw) { th.req.TLand = th.req.TLand.Add(-time.Minute) },
		"timeout":            func(th *throw) { th.req.OnTimeout = "later" },
		"no submitter":       func(th *throw) { th.req.SubmitterID = uuid.Nil },
		"unsupported currency": func(th *throw) {
			th.ta.Currency, th.req.Currency = "XXX", "XXX"
		},
	} {
		th := f.flick(25_00)
		edit(th)
		if _, err := f.svc.Create(ctx(t), f.sign(th)); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := f.intentCount(); n != 0 {
		t.Fatalf("%d intents", n)
	}
}

func TestIOSDeviceKeysAuthorise(t *testing.T) {
	f := newFixture(t, nil)
	// An iPhone bound through App Attest pays like an Android phone.
	apple := devicesim.NewApple(t)
	binder, err := devicebind.New(devicebind.Config{
		Apple: devicebind.AppleConfig{TeamID: apple.TeamID, BundleID: apple.BundleID, Roots: apple.CA.Pool()},
		Now:   f.c.now,
	}, redistest.Start(t), f.pool)
	if err != nil {
		t.Fatal(err)
	}
	phone := apple.NewDevice()
	key := devicesim.NewKey(t)
	ch, err := binder.Begin(ctx(t), f.stranger.user, uuid.Nil, devicebind.PurposeBind)
	if err != nil {
		t.Fatal(err)
	}
	b, err := binder.FinishIOS(ctx(t), f.stranger.user, ch.FlowID, devicebind.IOSBinding{Role: devicebind.RoleDevice,
		PublicKey: devicesim.Point(t, key), AppAttestKeyID: phone.KeyID,
		Attestation: phone.BindAttestation(ch.Challenge, key, devicesim.AttestOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	f.fund(f.stranger, "EUR", 50_00)
	svc, err := New(f.cfg, f.pool, binder, f.dir, nil, f.ledger, f.accts)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := svc.IssueNonces(ctx(t), f.stranger.user, b.Device.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	th := f.flick(20_00).handle(f.stranger)
	th.signer, th.keyID, th.ta.Nonce = key, b.Key.ID, ns[0].Value
	th.req.SubmitterID = f.stranger.user
	in, err := svc.Create(ctx(t), f.sign(th))
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, in, StateSettled, "")
	if in.PayerID != f.stranger.user || in.SignerRole != devicebind.RoleDevice {
		t.Fatalf("intent %+v", in)
	}
	f.wantBalance(f.payee, "EUR", 20_00, 20_00)
}
