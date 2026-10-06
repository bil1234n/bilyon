package devicebind_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/attest/androidkey"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

type fixture struct {
	t      *testing.T
	pool   *pgxpool.Pool
	svc    *devicebind.Service
	apple  *devicesim.Apple
	google *devicesim.Google
	user   uuid.UUID
	other  uuid.UUID // a second account

	mu    sync.Mutex
	shift time.Duration
}

func (f *fixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.Now().Add(f.shift)
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shift += d
}

func newFixture(t *testing.T, edit func(f *fixture, cfg *devicebind.Config)) *fixture {
	t.Helper()
	t.Parallel()
	pool := srv.Database(t)
	f := &fixture{t: t, pool: pool, apple: devicesim.NewApple(t), google: devicesim.NewGoogle(t)}
	cfg := devicebind.Config{
		Apple: devicebind.AppleConfig{TeamID: f.apple.TeamID, BundleID: f.apple.BundleID, Roots: f.apple.CA.Pool()},
		Android: devicebind.AndroidConfig{PackageName: f.google.PackageName,
			SigningCertDigests: [][]byte{f.google.SigningCert}, Roots: f.google.CA.Pool()},
		Integrity: &devicebind.IntegrityConfig{DecryptionKey: f.google.DecryptionKey,
			VerificationKey: &f.google.VerificationKey.PublicKey},
		Now: f.now,
	}
	if edit != nil {
		edit(f, &cfg)
	}
	svc, err := devicebind.New(cfg, redistest.Start(t), pool)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	users := webauthn.NewPGStore(pool)
	for _, id := range []*uuid.UUID{&f.user, &f.other} {
		u, err := users.CreateUser(ctx(t), "user")
		if err != nil {
			t.Fatal(err)
		}
		*id = u.ID
	}
	return f
}

func (f *fixture) begin(user, device uuid.UUID, p devicebind.Purpose) devicebind.Challenge {
	f.t.Helper()
	ch, err := f.svc.Begin(ctx(f.t), user, device, p)
	if err != nil {
		f.t.Fatalf("Begin(%s): %v", p, err)
	}
	if len(ch.Challenge) != 32 || ch.FlowID == "" {
		f.t.Fatalf("challenge %+v", ch)
	}
	return ch
}

// registerIOS installs the app on dev and binds key as its K_dev.
func (f *fixture) registerIOS(dev *devicesim.IOSDevice, key *ecdsa.PrivateKey) (devicebind.Binding, error) {
	f.t.Helper()
	ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
	return f.svc.FinishIOS(ctx(f.t), f.user, ch.FlowID, devicebind.IOSBinding{Role: devicebind.RoleDevice,
		PublicKey: devicesim.Point(f.t, key), AppAttestKeyID: dev.KeyID,
		Attestation: dev.BindAttestation(ch.Challenge, key, devicesim.AttestOptions{})})
}

// bindIOS binds key with role on a registered iOS device.
func (f *fixture) bindIOS(dev *devicesim.IOSDevice, deviceID uuid.UUID, role string, key *ecdsa.PrivateKey) (devicebind.Binding, error) {
	f.t.Helper()
	ch := f.begin(f.user, deviceID, devicebind.PurposeBind)
	return f.svc.FinishIOS(ctx(f.t), f.user, ch.FlowID, devicebind.IOSBinding{Role: role,
		PublicKey: devicesim.Point(f.t, key), Assertion: dev.BindAssertion(ch.Challenge, key, devicesim.AssertOptions{})})
}

// bindAndroid generates a key with role on dev and binds it (deviceID nil
// registers the device).
func (f *fixture) bindAndroid(dev *devicesim.AndroidDevice, deviceID uuid.UUID, role string) (*ecdsa.PrivateKey, devicebind.Binding, error) {
	f.t.Helper()
	ch := f.begin(f.user, deviceID, devicebind.PurposeBind)
	key, chain := dev.GenerateKey(role, ch.Challenge, devicesim.KeyOptions{})
	b, err := f.svc.FinishAndroid(ctx(f.t), f.user, ch.FlowID, devicebind.AndroidBinding{Role: role, Chain: chain,
		IntegrityToken: dev.IntegrityToken(ch.Challenge, devicesim.Point(f.t, key), nil)})
	return key, b, err
}

func (f *fixture) must(b devicebind.Binding, err error) devicebind.Binding {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// rejected asserts err is a BindError for check.
func rejected(t *testing.T, err error, check string) {
	t.Helper()
	var be *devicebind.BindError
	if !errors.As(err, &be) || !errors.Is(err, devicebind.ErrRejected) {
		t.Fatalf("err = %v, want a %s rejection", err, check)
	}
	if be.Check != check {
		t.Fatalf("check = %s (%s), want %s", be.Check, be.Reason, check)
	}
}

func is(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// events returns the data of the outbox events of a topic, oldest first.
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

func roles(keys []devicebind.Key) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Role
	}
	slices.Sort(out)
	return out
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	apple, google := devicesim.NewApple(t), devicesim.NewGoogle(t)
	good := func() devicebind.Config {
		return devicebind.Config{
			Apple: devicebind.AppleConfig{TeamID: apple.TeamID, BundleID: apple.BundleID, Roots: apple.CA.Pool()},
			Android: devicebind.AndroidConfig{PackageName: google.PackageName,
				SigningCertDigests: [][]byte{google.SigningCert}, Roots: google.CA.Pool()},
			Integrity: &devicebind.IntegrityConfig{DecryptionKey: google.DecryptionKey,
				VerificationKey: &google.VerificationKey.PublicKey},
		}
	}
	if _, err := devicebind.New(good(), nil, nil); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := map[string]func(*devicebind.Config){
		"no platform":          func(c *devicebind.Config) { c.Apple.Roots, c.Android.Roots = nil, nil },
		"no team id":           func(c *devicebind.Config) { c.Apple.TeamID = "" },
		"dotted team id":       func(c *devicebind.Config) { c.Apple.TeamID = "AB.CD" },
		"no bundle id":         func(c *devicebind.Config) { c.Apple.BundleID = "" },
		"no package":           func(c *devicebind.Config) { c.Android.PackageName = "" },
		"no signing digests":   func(c *devicebind.Config) { c.Android.SigningCertDigests = nil },
		"short signing digest": func(c *devicebind.Config) { c.Android.SigningCertDigests = [][]byte{{1, 2, 3}} },
		"no integrity keys":    func(c *devicebind.Config) { c.Integrity = nil },
		"short decryption key": func(c *devicebind.Config) { c.Integrity.DecryptionKey = make([]byte, 16) },
		"no verification key":  func(c *devicebind.Config) { c.Integrity.VerificationKey = nil },
		"P-384 verification":   func(c *devicebind.Config) { c.Integrity.VerificationKey = &p384.PublicKey },
		"package mismatch":     func(c *devicebind.Config) { c.Integrity.PackageName = "example.other" },
	}
	for name, edit := range cases {
		cfg := good()
		edit(&cfg)
		if _, err := devicebind.New(cfg, nil, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ios := good()
	ios.Android, ios.Integrity = devicebind.AndroidConfig{}, nil
	if _, err := devicebind.New(ios, nil, nil); err != nil {
		t.Fatalf("iOS-only configuration rejected: %v", err)
	}
}

func TestIOSLifecycle(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.apple.NewDevice()
	kdev := devicesim.NewKey(t)

	reg := f.must(f.registerIOS(dev, kdev))
	d, k := reg.Device, reg.Key
	switch {
	case d.Platform != devicebind.PlatformIOS || d.UserID != f.user || string(d.AppAttestKeyID) != string(dev.KeyID):
		t.Fatalf("device %+v", d)
	case d.AppAttestCounter == nil || *d.AppAttestCounter != 0 || len(d.AppAttestPublicKey) != 65 || len(d.AppAttestReceipt) == 0:
		t.Fatalf("App Attest state %+v", d)
	case d.Integrity.Source != devicebind.SourceAppAttestation || d.Integrity.Environment != "production":
		t.Fatalf("integrity %+v", d.Integrity)
	case k.Role != devicebind.RoleDevice || k.SecurityLevel != devicebind.LevelSecureEnclave || k.DeviceID != d.ID:
		t.Fatalf("key %+v", k)
	case string(k.PublicKey) != string(devicesim.Point(t, kdev)) || k.Attestation.Method != devicebind.SourceAppAttestation:
		t.Fatalf("key %+v", k)
	}

	kgest := devicesim.NewKey(t)
	gest := f.must(f.bindIOS(dev, d.ID, devicebind.RoleGesture, kgest))
	if *gest.Device.AppAttestCounter != 1 || gest.Key.Attestation.AppAttestCounter != 1 ||
		gest.Key.Attestation.Method != devicebind.SourceAppAssertion {
		t.Fatalf("gesture binding %+v %+v", gest.Device, gest.Key)
	}
	off := f.must(f.bindIOS(dev, d.ID, devicebind.RoleOffline, devicesim.NewKey(t)))
	if *off.Device.AppAttestCounter != 2 {
		t.Fatalf("counter %d", *off.Device.AppAttestCounter)
	}

	// Re-binding K_dev (after a biometric enrolment change) supersedes it.
	kdev2 := devicesim.NewKey(t)
	rebound := f.must(f.bindIOS(dev, d.ID, devicebind.RoleDevice, kdev2))
	_, err := f.svc.ActiveKey(ctx(t), k.ID)
	is(t, err, devicebind.ErrRevoked)
	if got, err := f.svc.ActiveKey(ctx(t), rebound.Key.ID); err != nil || got.Role != devicebind.RoleDevice {
		t.Fatalf("ActiveKey = %+v, %v", got, err)
	}
	keys, err := f.svc.Keys(ctx(t), f.user, d.ID)
	if err != nil || !slices.Equal(roles(keys), []string{"dev", "gest", "off"}) {
		t.Fatalf("Keys = %v, %v", roles(keys), err)
	}
	if ev := f.events(devicebind.TopicKeyRevoked); len(ev) != 1 || ev[0]["reason"] != "superseded" || ev[0]["key_id"] != k.ID.String() {
		t.Fatalf("key revoked events %v", ev)
	}

	// A risky call carries an assertion over request data.
	f.advance(time.Hour)
	before := rebound.Device.IntegrityAt
	clientData := []byte("bilyon/assert/v1 POST /v1/intents 7f3a")
	assertion := dev.Assert(clientData, devicesim.AssertOptions{})
	got, err := f.svc.AssertIOS(ctx(t), f.user, d.ID, assertion, clientData)
	if err != nil || *got.AppAttestCounter != 4 || !got.IntegrityAt.After(before) {
		t.Fatalf("AssertIOS = %+v, %v", got, err)
	}
	// Replaying it is a counter anomaly and raises a clone signal.
	_, err = f.svc.AssertIOS(ctx(t), f.user, d.ID, assertion, clientData)
	rejected(t, err, "ios.counter")
	if ev := f.events(devicebind.TopicCloneSignal); len(ev) != 1 || ev[0]["device_id"] != d.ID.String() {
		t.Fatalf("clone signal events %v", ev)
	}

	// Integrity refresh: an assertion over the refresh challenge; the
	// attestation's facts survive the merge.
	ch := f.begin(f.user, d.ID, devicebind.PurposeIntegrity)
	refreshed, err := f.svc.RefreshIntegrity(ctx(t), f.user, ch.FlowID, devicebind.IntegrityProof{
		Assertion: dev.Assert(devicesim.IntegrityClientData(ch.Challenge), devicesim.AssertOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	if *refreshed.AppAttestCounter != 5 || refreshed.Integrity.Source != devicebind.SourceAppAssertion ||
		refreshed.Integrity.Environment != "production" {
		t.Fatalf("refreshed %+v", refreshed)
	}
	devices, err := f.svc.Devices(ctx(t), f.user)
	if err != nil || len(devices) != 1 || devices[0].ID != d.ID {
		t.Fatalf("Devices = %+v, %v", devices, err)
	}
	if ev := f.events(devicebind.TopicKeyBound); len(ev) != 4 {
		t.Fatalf("%d key bound events", len(ev))
	}
	if ev := f.events(devicebind.TopicDeviceRegistered); len(ev) != 1 || ev[0]["platform"] != "ios" {
		t.Fatalf("device registered events %v", ev)
	}
}

func TestIOSAttestationRejections(t *testing.T) {
	f := newFixture(t, nil)
	rogue := devicesim.NewCA(t, "Rogue")
	other := f.apple.NewDevice()
	cases := []struct {
		name  string
		check string
		build func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding
	}{
		{"nonce over another key", "ios.nonce", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, devicesim.NewKey(t), devicesim.AttestOptions{})}
		}},
		{"nonce over another challenge", "ios.nonce", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(make([]byte, 32), key, devicesim.AttestOptions{})}
		}},
		{"forged nonce extension", "ios.nonce", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{Nonce: make([]byte, 32)})}
		}},
		{"untrusted root", "ios.chain", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{CA: rogue})}
		}},
		{"key id of another App Attest key", "ios.key", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{AppAttestKeyID: other.KeyID,
				Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{})}
		}},
		{"another app", "ios.authData", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{AppID: "ZZZZZ99999.example.other"})}
		}},
		{"non-zero counter", "ios.authData", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{Counter: 1})}
		}},
		{"development environment", "ios.authData", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{AAGUID: devicesim.AAGUIDDevelopment})}
		}},
		{"unknown AAGUID", "ios.authData", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{AAGUID: []byte("appattestXXXXXXX")})}
		}},
		{"credential id is not the key id", "ios.authData", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{CredID: other.KeyID})}
		}},
		{"wrong format", "ios.attestation", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{Format: "packed"})}
		}},
		{"unknown statement member", "ios.attestation", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{ExtraStmt: true})}
		}},
		{"not CBOR", "ios.attestation", func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Attestation: []byte{0xa1, 0x01}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dev, key := f.apple.NewDevice(), devicesim.NewKey(t)
			ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
			b := c.build(dev, ch.Challenge, key)
			b.Role, b.PublicKey = devicebind.RoleDevice, devicesim.Point(t, key)
			if b.AppAttestKeyID == nil {
				b.AppAttestKeyID = dev.KeyID
			}
			_, err := f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, b)
			rejected(t, err, c.check)
		})
	}
	if devices, err := f.svc.Devices(ctx(t), f.user); err != nil || len(devices) != 0 {
		t.Fatalf("rejected attestations left devices: %v %v", devices, err)
	}

	t.Run("App Attest key registered twice", func(t *testing.T) {
		dev := f.apple.NewDevice()
		f.must(f.registerIOS(dev, devicesim.NewKey(t)))
		_, err := f.registerIOS(dev, devicesim.NewKey(t))
		rejected(t, err, "ios.attestation")
	})
	t.Run("key bound twice", func(t *testing.T) {
		key := devicesim.NewKey(t)
		f.must(f.registerIOS(f.apple.NewDevice(), key))
		_, err := f.registerIOS(f.apple.NewDevice(), key)
		is(t, err, devicebind.ErrKeyExists)
	})
	if devices, _ := f.svc.Devices(ctx(t), f.user); len(devices) != 2 {
		t.Fatalf("%d devices, want the two first registrations", len(devices))
	}

	requests := map[string]func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding{
		"coin role": func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Role: devicebind.RoleCoin, PublicKey: devicesim.Point(t, key), AppAttestKeyID: dev.KeyID,
				Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{})}
		},
		"new device binding K_gest": func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Role: devicebind.RoleGesture, PublicKey: devicesim.Point(t, key), AppAttestKeyID: dev.KeyID,
				Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{})}
		},
		"assertion for a new device": func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Role: devicebind.RoleDevice, PublicKey: devicesim.Point(t, key),
				Assertion: dev.BindAssertion(ch, key, devicesim.AssertOptions{})}
		},
		"short key id": func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			return devicebind.IOSBinding{Role: devicebind.RoleDevice, PublicKey: devicesim.Point(t, key), AppAttestKeyID: dev.KeyID[:16],
				Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{})}
		},
		"point off the curve": func(dev *devicesim.IOSDevice, ch []byte, key *ecdsa.PrivateKey) devicebind.IOSBinding {
			bad := devicesim.Point(t, key)
			bad[64] ^= 1
			return devicebind.IOSBinding{Role: devicebind.RoleDevice, PublicKey: bad, AppAttestKeyID: dev.KeyID,
				Attestation: dev.BindAttestation(ch, key, devicesim.AttestOptions{})}
		},
	}
	for name, build := range requests {
		dev, key := f.apple.NewDevice(), devicesim.NewKey(t)
		ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
		if _, err := f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, build(dev, ch.Challenge, key)); !errors.Is(err, devicebind.ErrRequest) {
			t.Errorf("%s: err = %v, want ErrRequest", name, err)
		}
	}
}

func TestIOSDevelopmentEnvironment(t *testing.T) {
	f := newFixture(t, func(_ *fixture, cfg *devicebind.Config) { cfg.Apple.AllowDevelopment = true })
	dev, key := f.apple.NewDevice(), devicesim.NewKey(t)
	ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
	b, err := f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, devicebind.IOSBinding{Role: devicebind.RoleDevice,
		PublicKey: devicesim.Point(t, key), AppAttestKeyID: dev.KeyID,
		Attestation: dev.BindAttestation(ch.Challenge, key, devicesim.AttestOptions{AAGUID: devicesim.AAGUIDDevelopment})})
	if err != nil || b.Device.Integrity.Environment != "development" {
		t.Fatalf("binding = %+v, %v", b.Device.Integrity, err)
	}
}

func TestIOSAssertionRejections(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.apple.NewDevice()
	d := f.must(f.registerIOS(dev, devicesim.NewKey(t))).Device
	cases := []struct {
		name  string
		check string
		build func(ch []byte, key *ecdsa.PrivateKey) []byte
	}{
		{"signed by another key", "ios.assertion", func(ch []byte, key *ecdsa.PrivateKey) []byte {
			return dev.BindAssertion(ch, key, devicesim.AssertOptions{Signer: devicesim.NewKey(t)})
		}},
		{"another app", "ios.assertion", func(ch []byte, key *ecdsa.PrivateKey) []byte {
			return dev.BindAssertion(ch, key, devicesim.AssertOptions{AppID: "ZZZZZ99999.example.other"})
		}},
		{"over another key", "ios.assertion", func(ch []byte, key *ecdsa.PrivateKey) []byte {
			return dev.BindAssertion(ch, devicesim.NewKey(t), devicesim.AssertOptions{})
		}},
		{"over another challenge", "ios.assertion", func(ch []byte, key *ecdsa.PrivateKey) []byte {
			return dev.BindAssertion(make([]byte, 32), key, devicesim.AssertOptions{})
		}},
		{"not CBOR", "ios.assertion", func(ch []byte, key *ecdsa.PrivateKey) []byte { return []byte{0xff} }},
		{"stale counter", "ios.counter", func(ch []byte, key *ecdsa.PrivateKey) []byte {
			zero := uint32(0)
			return dev.BindAssertion(ch, key, devicesim.AssertOptions{Counter: &zero})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := devicesim.NewKey(t)
			ch := f.begin(f.user, d.ID, devicebind.PurposeBind)
			_, err := f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, devicebind.IOSBinding{Role: devicebind.RoleGesture,
				PublicKey: devicesim.Point(t, key), Assertion: c.build(ch.Challenge, key)})
			rejected(t, err, c.check)
		})
	}
	if n := len(f.events(devicebind.TopicCloneSignal)); n != 1 {
		t.Fatalf("%d clone signals, want 1 (only the stale counter)", n)
	}
	// A device that is not iOS cannot assert; nor can another user's device.
	adev := f.google.NewDevice(true)
	_, ab, err := f.bindAndroid(adev, uuid.Nil, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.AssertIOS(ctx(t), f.user, ab.Device.ID, []byte{0xa0}, []byte("x"))
	is(t, err, devicebind.ErrRequest)
	_, err = f.svc.AssertIOS(ctx(t), f.other, d.ID, dev.Assert([]byte("x"), devicesim.AssertOptions{}), []byte("x"))
	is(t, err, devicebind.ErrNotFound)
	// Known-device bindings present an assertion and nothing else.
	ch := f.begin(f.user, d.ID, devicebind.PurposeBind)
	key := devicesim.NewKey(t)
	_, err = f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, devicebind.IOSBinding{Role: devicebind.RoleGesture,
		PublicKey: devicesim.Point(t, key), AppAttestKeyID: dev.KeyID,
		Attestation: dev.BindAttestation(ch.Challenge, key, devicesim.AttestOptions{})})
	is(t, err, devicebind.ErrRequest)
}

func TestAndroidLifecycle(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.google.NewDevice(true)
	kdev, reg, err := f.bindAndroid(dev, uuid.Nil, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	d, k := reg.Device, reg.Key
	switch {
	case d.Platform != devicebind.PlatformAndroid || d.AppAttestKeyID != nil || d.AppAttestCounter != nil:
		t.Fatalf("device %+v", d)
	case d.OSPatchLevel == nil || *d.OSPatchLevel != dev.PatchLevel:
		t.Fatalf("patch level %v", d.OSPatchLevel)
	case d.Integrity.Source != devicebind.SourcePlayIntegrity || d.Integrity.VerifiedBoot != "verified" ||
		!d.Integrity.DeviceLocked || d.Integrity.OSVersion != 150000 || !d.Integrity.Strong():
		t.Fatalf("integrity %+v", d.Integrity)
	case k.SecurityLevel != devicebind.LevelStrongBox || k.Attestation.Method != devicebind.SourceKeyAttestation ||
		k.Attestation.KeyMintVersion != 300 || !k.Attestation.UnlockedDeviceRequired:
		t.Fatalf("key %+v", k)
	case string(k.PublicKey) != string(devicesim.Point(t, kdev)):
		t.Fatal("bound key is not the generated key")
	}

	_, gest, err := f.bindAndroid(dev, d.ID, devicebind.RoleGesture)
	if err != nil || gest.Key.Attestation.AuthTimeoutSeconds != 60 {
		t.Fatalf("gesture binding %+v, %v", gest.Key, err)
	}
	_, off1, err := f.bindAndroid(dev, d.ID, devicebind.RoleOffline)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.bindAndroid(dev, d.ID, devicebind.RoleOffline); err != nil {
		t.Fatal(err)
	}
	kdev2, rebound, err := f.bindAndroid(dev, d.ID, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.bindAndroid(dev, d.ID, devicebind.RoleGesture); err != nil {
		t.Fatalf("re-binding K_gest: %v", err)
	}
	_, err = f.svc.ActiveKey(ctx(t), gest.Key.ID)
	is(t, err, devicebind.ErrRevoked)
	keys, err := f.svc.Keys(ctx(t), f.user, d.ID)
	if err != nil || !slices.Equal(roles(keys), []string{"dev", "gest", "off", "off"}) {
		t.Fatalf("Keys = %v, %v", roles(keys), err)
	}
	_, err = f.svc.ActiveKey(ctx(t), k.ID)
	is(t, err, devicebind.ErrRevoked)
	_, err = f.svc.ActiveKey(ctx(t), uuid.New())
	is(t, err, devicebind.ErrNotFound)

	// Integrity refresh: a verdict bound to the challenge and the current K_dev.
	f.advance(2 * time.Hour)
	ch := f.begin(f.user, d.ID, devicebind.PurposeIntegrity)
	dev.Strong = false
	fresh := func(v *devicesim.Verdict) { v.Timestamp = f.now() }
	refreshed, err := f.svc.RefreshIntegrity(ctx(t), f.user, ch.FlowID, devicebind.IntegrityProof{
		IntegrityToken: dev.IntegrityToken(ch.Challenge, devicesim.Point(t, kdev2), fresh)})
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed.IntegrityAt.After(rebound.Device.IntegrityAt) || refreshed.Integrity.Strong() ||
		refreshed.Integrity.VerifiedBoot != "verified" {
		t.Fatalf("refreshed %+v", refreshed)
	}
	// A verdict bound to the superseded K_dev does not refresh.
	ch = f.begin(f.user, d.ID, devicebind.PurposeIntegrity)
	_, err = f.svc.RefreshIntegrity(ctx(t), f.user, ch.FlowID, devicebind.IntegrityProof{
		IntegrityToken: dev.IntegrityToken(ch.Challenge, devicesim.Point(t, kdev), fresh)})
	rejected(t, err, "integrity.nonce")
	ch = f.begin(f.user, d.ID, devicebind.PurposeIntegrity)
	_, err = f.svc.RefreshIntegrity(ctx(t), f.user, ch.FlowID, devicebind.IntegrityProof{Assertion: []byte{1}})
	is(t, err, devicebind.ErrRequest)

	// Key revocation: owner only, idempotent, reason required.
	is(t, f.svc.RevokeKey(ctx(t), f.other, off1.Key.ID, "closed"), devicebind.ErrNotFound)
	is(t, f.svc.RevokeKey(ctx(t), f.user, off1.Key.ID, ""), devicebind.ErrRequest)
	if err := f.svc.RevokeKey(ctx(t), f.user, off1.Key.ID, "allowance closed"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RevokeKey(ctx(t), f.user, off1.Key.ID, "allowance closed"); err != nil {
		t.Fatalf("second revocation: %v", err)
	}
	_, err = f.svc.ActiveKey(ctx(t), off1.Key.ID)
	is(t, err, devicebind.ErrRevoked)

	// Device revocation revokes every remaining key and ends all flows on it.
	is(t, f.svc.Revoke(ctx(t), f.other, d.ID, "stolen"), devicebind.ErrNotFound)
	if err := f.svc.Revoke(ctx(t), f.user, d.ID, "stolen"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(ctx(t), f.user, d.ID, "stolen"); err != nil {
		t.Fatalf("second revocation: %v", err)
	}
	ev := f.events(devicebind.TopicDeviceRevoked)
	if len(ev) != 1 || ev[0]["reason"] != "stolen" || len(ev[0]["key_ids"].([]any)) != 3 {
		t.Fatalf("device revoked events %v", ev)
	}
	_, err = f.svc.ActiveKey(ctx(t), rebound.Key.ID)
	is(t, err, devicebind.ErrRevoked)
	if keys, err := f.svc.Keys(ctx(t), f.user, d.ID); err != nil || len(keys) != 0 {
		t.Fatalf("keys after revocation %v %v", keys, err)
	}
	if devices, err := f.svc.Devices(ctx(t), f.user); err != nil || len(devices) != 0 {
		t.Fatalf("devices after revocation %v %v", devices, err)
	}
	got, err := f.svc.Device(ctx(t), f.user, d.ID)
	if err != nil || got.RevokedAt == nil || got.RevokeReason != "stolen" {
		t.Fatalf("Device = %+v, %v", got, err)
	}
	_, err = f.svc.Begin(ctx(t), f.user, d.ID, devicebind.PurposeBind)
	is(t, err, devicebind.ErrRevoked)
}

func TestAndroidAttestationRejections(t *testing.T) {
	f := newFixture(t, nil)
	rogue := devicesim.NewCA(t, "Rogue")
	home := f.google.NewDevice(true)
	_, reg, err := f.bindAndroid(home, uuid.Nil, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	monthsAgo := func(n int) int64 {
		m := time.Now().UTC().AddDate(0, -n, 0)
		return int64(m.Year())*100 + int64(m.Month())
	}
	hw := func(edit func(*androidkey.AuthorizationList)) func(*androidkey.KeyDescription) {
		return func(kd *androidkey.KeyDescription) { edit(&kd.Hardware) }
	}
	i64 := func(v int64) *int64 { return &v }
	cases := []struct {
		name  string
		role  string
		check string
		opts  devicesim.KeyOptions
	}{
		{"untrusted root", "dev", "android.chain", devicesim.KeyOptions{CA: rogue}},
		{"no attestation extension", "dev", "android.extension", devicesim.KeyOptions{NoExtension: true}},
		{"another challenge", "dev", "android.challenge", devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
			kd.Challenge = make([]byte, 32)
		}}},
		{"software key", "dev", "android.security_level", devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
			kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel = androidkey.Software, androidkey.Software
		}}},
		{"KeyMint level differs", "dev", "android.security_level", devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
			kd.KeyMintSecurityLevel = androidkey.TrustedEnvironment
		}}},
		{"no SIGN purpose", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.Purpose = []int64{0}
		})}},
		{"SIGN only software-enforced", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
			kd.Software.Purpose, kd.Hardware.Purpose = kd.Hardware.Purpose, nil
		}}},
		{"RSA key", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.Algorithm = i64(androidkey.AlgorithmRSA)
		})}},
		{"P-384 key", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.ECCurve = i64(2)
		})}},
		{"usable by all applications", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.AllApplications = true
		})}},
		{"imported key", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.Origin = i64(2)
		})}},
		{"no origin", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.Origin = nil
		})}},
		{"no authentication required", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.NoAuthRequired = true
		})}},
		{"password authentication", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.UserAuthType = i64(androidkey.AuthTypePassword)
		})}},
		{"no user auth type", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.UserAuthType = nil
		})}},
		{"K_dev with an auth timeout", "dev", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.AuthTimeout = i64(30)
		})}},
		{"K_off with an auth timeout", "off", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.AuthTimeout = i64(300)
		})}},
		{"K_gest without a window", "gest", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.AuthTimeout = nil
		})}},
		{"K_gest with a 30 s window", "gest", "android.auth_list", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.AuthTimeout = i64(30)
		})}},
		{"no root of trust", "dev", "android.root_of_trust", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.RootOfTrust = nil
		})}},
		{"unverified boot", "dev", "android.root_of_trust", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.RootOfTrust.VerifiedBootState = androidkey.VerifiedBootUnverified
		})}},
		{"unlocked bootloader", "dev", "android.root_of_trust", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.RootOfTrust.DeviceLocked = false
		})}},
		{"patch level 14 months old", "dev", "android.patch_level", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.OSPatchLevel = i64(monthsAgo(14))
		})}},
		{"patch level in the future", "dev", "android.patch_level", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.OSPatchLevel = i64(monthsAgo(-2))
		})}},
		{"patch level not YYYYMM", "dev", "android.patch_level", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.OSPatchLevel = i64(202613)
		})}},
		{"no patch level", "dev", "android.patch_level", devicesim.KeyOptions{Tweak: hw(func(l *androidkey.AuthorizationList) {
			l.OSPatchLevel = nil
		})}},
		{"another package", "dev", "android.application", devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
			kd.Software.ApplicationID.Packages[0].Name = "example.repackaged"
		}}},
		{"another signing certificate", "dev", "android.application", devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
			kd.Software.ApplicationID.SignatureDigests = [][]byte{make([]byte, 32)}
		}}},
		{"no application id", "dev", "android.application", devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
			kd.Software.ApplicationID = nil
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			device := uuid.Nil
			if c.role != devicebind.RoleDevice {
				device = reg.Device.ID
			}
			ch := f.begin(f.user, device, devicebind.PurposeBind)
			dev := f.google.NewDevice(true)
			key, chain := dev.GenerateKey(c.role, ch.Challenge, c.opts)
			_, err := f.svc.FinishAndroid(ctx(t), f.user, ch.FlowID, devicebind.AndroidBinding{Role: c.role, Chain: chain,
				IntegrityToken: dev.IntegrityToken(ch.Challenge, devicesim.Point(t, key), nil)})
			rejected(t, err, c.check)
		})
	}
	t.Run("a 12-month-old patch level is accepted", func(t *testing.T) {
		ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
		dev := f.google.NewDevice(false)
		dev.PatchLevel = monthsAgo(12)
		key, chain := dev.GenerateKey(devicebind.RoleDevice, ch.Challenge, devicesim.KeyOptions{})
		b, err := f.svc.FinishAndroid(ctx(t), f.user, ch.FlowID, devicebind.AndroidBinding{Role: devicebind.RoleDevice, Chain: chain,
			IntegrityToken: dev.IntegrityToken(ch.Challenge, devicesim.Point(t, key), nil)})
		if err != nil || b.Key.SecurityLevel != devicebind.LevelTEE {
			t.Fatalf("binding = %+v, %v", b.Key, err)
		}
	})
	t.Run("new device binding K_gest", func(t *testing.T) {
		ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
		dev := f.google.NewDevice(true)
		_, chain := dev.GenerateKey(devicebind.RoleGesture, ch.Challenge, devicesim.KeyOptions{})
		_, err := f.svc.FinishAndroid(ctx(t), f.user, ch.FlowID, devicebind.AndroidBinding{Role: devicebind.RoleGesture, Chain: chain})
		is(t, err, devicebind.ErrRequest)
	})
}

func TestAndroidRevocationList(t *testing.T) {
	f := newFixture(t, func(f *fixture, cfg *devicebind.Config) {
		cfg.Android.Revoked = map[string]bool{strings.ToLower(f.google.CA.Intermediate.SerialNumber.Text(16)): true}
	})
	_, _, err := f.bindAndroid(f.google.NewDevice(true), uuid.Nil, devicebind.RoleDevice)
	rejected(t, err, "android.revocation")
}

func TestPlayIntegrityRejections(t *testing.T) {
	f := newFixture(t, nil)
	otherKey := devicesim.NewKey(t)
	wrongAES := make([]byte, 32)
	cases := []struct {
		name  string
		check string // "" means accepted
		token func(dev *devicesim.AndroidDevice, ch, pub []byte) string
	}{
		{"request hash (standard API)", "", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.Nonce, v.RequestHash = "", v.Nonce })
		}},
		{"padded nonce", "", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.Nonce += "=" })
		}},
		{"nonce over another key", "integrity.nonce", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, devicesim.Point(t, otherKey), nil)
		}},
		{"nonce over another challenge", "integrity.nonce", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(make([]byte, 32), pub, nil)
		}},
		{"no nonce", "integrity.nonce", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.Nonce = "" })
		}},
		{"unrecognised app", "integrity.app", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.AppRecognition = "UNRECOGNIZED_VERSION" })
		}},
		{"signing certificate not configured", "integrity.app", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.CertificateDigests = []string{"AAAA"} })
		}},
		{"basic integrity only", "integrity.device", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.DeviceVerdicts = []string{"MEETS_BASIC_INTEGRITY"} })
		}},
		{"stale verdict", "integrity.verdict", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.Timestamp = time.Now().Add(-10 * time.Minute) })
		}},
		{"verdict from the future", "integrity.verdict", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.Timestamp = time.Now().Add(5 * time.Minute) })
		}},
		{"another requesting package", "integrity.verdict", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.RequestPackageName = "example.other" })
		}},
		{"another app package", "integrity.verdict", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return dev.IntegrityToken(ch, pub, func(v *devicesim.Verdict) { v.PackageName = "example.other" })
		}},
		{"signed by another key", "integrity.signature", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return f.google.Token(dev.Verdict(ch, pub), devicesim.TokenOptions{SigningKey: otherKey})
		}},
		{"HS256 signature", "integrity.signature", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return f.google.Token(dev.Verdict(ch, pub), devicesim.TokenOptions{JWSAlg: "HS256"})
		}},
		{"encrypted under another key", "integrity.token", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			return f.google.Token(dev.Verdict(ch, pub), devicesim.TokenOptions{EncryptionKey: wrongAES})
		}},
		{"tampered ciphertext", "integrity.token", func(dev *devicesim.AndroidDevice, ch, pub []byte) string {
			parts := strings.Split(dev.IntegrityToken(ch, pub, nil), ".")
			c := []byte(parts[3])
			if c[0] == 'A' {
				c[0] = 'B'
			} else {
				c[0] = 'A'
			}
			parts[3] = string(c)
			return strings.Join(parts, ".")
		}},
		{"not a JWE", "integrity.token", func(dev *devicesim.AndroidDevice, ch, pub []byte) string { return "a.b.c" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
			dev := f.google.NewDevice(true)
			key, chain := dev.GenerateKey(devicebind.RoleDevice, ch.Challenge, devicesim.KeyOptions{})
			_, err := f.svc.FinishAndroid(ctx(t), f.user, ch.FlowID, devicebind.AndroidBinding{Role: devicebind.RoleDevice,
				Chain: chain, IntegrityToken: c.token(dev, ch.Challenge, devicesim.Point(t, key))})
			if c.check == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			rejected(t, err, c.check)
		})
	}
}

// mint generates n coin keys on dev for a coins flow.
func mint(t *testing.T, dev *devicesim.AndroidDevice, challenge []byte, n int, opts devicesim.KeyOptions) ([][]byte, [][][]byte) {
	t.Helper()
	pubs := make([][]byte, n)
	chains := make([][][]byte, n)
	for i := range n {
		key, chain := dev.GenerateKey(devicebind.RoleCoin, challenge, opts)
		pubs[i], chains[i] = devicesim.Point(t, key), chain
	}
	return pubs, chains
}

func TestCoins(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.google.NewDevice(true)
	kdev, reg, err := f.bindAndroid(dev, uuid.Nil, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	d := reg.Device
	kdevPub := devicesim.Point(t, kdev)

	ch := f.begin(f.user, d.ID, devicebind.PurposeCoins)
	pubs, chains := mint(t, dev, ch.Challenge, 5, devicesim.KeyOptions{})
	coins, err := f.svc.AttestCoins(ctx(t), f.user, ch.FlowID, devicebind.CoinMinting{Chains: chains,
		IntegrityToken: dev.IntegrityToken(ch.Challenge, kdevPub, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if len(coins) != 5 {
		t.Fatalf("%d coins", len(coins))
	}
	for i, c := range coins {
		if string(c.PublicKey) != string(pubs[i]) || c.SecurityLevel != devicebind.LevelStrongBox {
			t.Fatalf("coin %d = %+v", i, c)
		}
	}

	cases := []struct {
		name   string
		check  string
		chains func(ch []byte) [][][]byte
		token  func(ch []byte) string
		weak   bool // device lacks strong integrity
	}{
		{"no usage count limit", "android.auth_list", func(ch []byte) [][][]byte {
			_, c := mint(t, dev, ch, 2, devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) { kd.Hardware.UsageCountLimit = nil }})
			return c
		}, nil, false},
		{"usage count limit of 2", "android.auth_list", func(ch []byte) [][][]byte {
			two := int64(2)
			_, c := mint(t, dev, ch, 1, devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) { kd.Hardware.UsageCountLimit = &two }})
			return c
		}, nil, false},
		{"usage count limit only software-enforced", "android.auth_list", func(ch []byte) [][][]byte {
			_, c := mint(t, dev, ch, 1, devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) {
				kd.Software.UsageCountLimit, kd.Hardware.UsageCountLimit = kd.Hardware.UsageCountLimit, nil
			}})
			return c
		}, nil, false},
		{"no rollback resistance", "android.auth_list", func(ch []byte) [][][]byte {
			_, c := mint(t, dev, ch, 1, devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) { kd.Hardware.RollbackResistance = false }})
			return c
		}, nil, false},
		{"Android 11", "coins.os_version", func(ch []byte) [][][]byte {
			old := int64(110000)
			_, c := mint(t, dev, ch, 1, devicesim.KeyOptions{Tweak: func(kd *androidkey.KeyDescription) { kd.Hardware.OSVersion = &old }})
			return c
		}, nil, false},
		{"repeated key", "coins.duplicate", func(ch []byte) [][][]byte {
			_, c := mint(t, dev, ch, 1, devicesim.KeyOptions{})
			return [][][]byte{c[0], c[0]}
		}, nil, false},
		{"coin for another challenge", "android.challenge", func(ch []byte) [][][]byte {
			_, c := mint(t, dev, make([]byte, 32), 1, devicesim.KeyOptions{})
			return c
		}, nil, false},
		{"device without strong integrity", "integrity.device", nil, nil, true},
		{"verdict bound to a coin key", "integrity.nonce", nil, func(ch []byte) string {
			return dev.IntegrityToken(ch, pubs[0], nil)
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch := f.begin(f.user, d.ID, devicebind.PurposeCoins)
			chains := func() [][][]byte { _, cs := mint(t, dev, ch.Challenge, 2, devicesim.KeyOptions{}); return cs }()
			if c.chains != nil {
				chains = c.chains(ch.Challenge)
			}
			dev.Strong = !c.weak
			defer func() { dev.Strong = true }()
			token := dev.IntegrityToken(ch.Challenge, kdevPub, nil)
			if c.token != nil {
				token = c.token(ch.Challenge)
			}
			_, err := f.svc.AttestCoins(ctx(t), f.user, ch.FlowID, devicebind.CoinMinting{Chains: chains, IntegrityToken: token})
			rejected(t, err, c.check)
		})
	}

	for _, n := range []int{0, devicebind.MaxCoins + 1} {
		ch := f.begin(f.user, d.ID, devicebind.PurposeCoins)
		_, err := f.svc.AttestCoins(ctx(t), f.user, ch.FlowID, devicebind.CoinMinting{Chains: make([][][]byte, n)})
		is(t, err, devicebind.ErrRequest)
	}
	// Without an active K_dev there is nothing to bind the verdict to.
	ch = f.begin(f.user, d.ID, devicebind.PurposeCoins)
	if err := f.svc.RevokeKey(ctx(t), f.user, reg.Key.ID, "biometric enrolment changed"); err != nil {
		t.Fatal(err)
	}
	_, chains = mint(t, dev, ch.Challenge, 1, devicesim.KeyOptions{})
	_, err = f.svc.AttestCoins(ctx(t), f.user, ch.FlowID, devicebind.CoinMinting{Chains: chains,
		IntegrityToken: dev.IntegrityToken(ch.Challenge, kdevPub, nil)})
	rejected(t, err, "coins.device")

	// Coins are Android only.
	ios := f.must(f.registerIOS(f.apple.NewDevice(), devicesim.NewKey(t))).Device
	_, err = f.svc.Begin(ctx(t), f.user, ios.ID, devicebind.PurposeCoins)
	is(t, err, devicebind.ErrRequest)
}

func TestFlows(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.apple.NewDevice()
	kdev := devicesim.NewKey(t)
	ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
	b := devicebind.IOSBinding{Role: devicebind.RoleDevice, PublicKey: devicesim.Point(t, kdev), AppAttestKeyID: dev.KeyID,
		Attestation: dev.BindAttestation(ch.Challenge, kdev, devicesim.AttestOptions{})}
	reg, err := f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, b)
	is(t, err, devicebind.ErrFlow)
	_, err = f.svc.FinishIOS(ctx(t), f.user, "no-such-flow", b)
	is(t, err, devicebind.ErrFlow)

	_, err = f.svc.Begin(ctx(t), f.user, uuid.Nil, devicebind.Purpose("sudo"))
	is(t, err, devicebind.ErrRequest)
	for _, p := range []devicebind.Purpose{devicebind.PurposeCoins, devicebind.PurposeIntegrity} {
		_, err = f.svc.Begin(ctx(t), f.user, uuid.Nil, p)
		is(t, err, devicebind.ErrRequest)
	}
	_, err = f.svc.Begin(ctx(t), f.other, reg.Device.ID, devicebind.PurposeBind)
	is(t, err, devicebind.ErrNotFound)
	_, err = f.svc.Begin(ctx(t), f.user, uuid.New(), devicebind.PurposeBind)
	is(t, err, devicebind.ErrNotFound)
	_, err = f.svc.Device(ctx(t), f.other, reg.Device.ID)
	is(t, err, devicebind.ErrNotFound)
	_, err = f.svc.Keys(ctx(t), f.other, reg.Device.ID)
	is(t, err, devicebind.ErrNotFound)

	// A flow serves only its purpose, and is consumed by the attempt.
	ch = f.begin(f.user, reg.Device.ID, devicebind.PurposeIntegrity)
	kgest := devicesim.NewKey(t)
	gb := devicebind.IOSBinding{Role: devicebind.RoleGesture, PublicKey: devicesim.Point(t, kgest),
		Assertion: dev.BindAssertion(ch.Challenge, kgest, devicesim.AssertOptions{})}
	_, err = f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, gb)
	is(t, err, devicebind.ErrFlow)
	_, err = f.svc.RefreshIntegrity(ctx(t), f.user, ch.FlowID, devicebind.IntegrityProof{Assertion: []byte{1}})
	is(t, err, devicebind.ErrFlow)

	// An expired flow is refused even while Redis still holds it.
	ch = f.begin(f.user, reg.Device.ID, devicebind.PurposeBind)
	f.advance(6 * time.Minute)
	_, err = f.svc.FinishIOS(ctx(t), f.user, ch.FlowID, devicebind.IOSBinding{Role: devicebind.RoleGesture,
		PublicKey: devicesim.Point(t, kgest), Assertion: dev.BindAssertion(ch.Challenge, kgest, devicesim.AssertOptions{})})
	is(t, err, devicebind.ErrFlow)

	// An iOS device's flow cannot bind an Android key.
	ch = f.begin(f.user, reg.Device.ID, devicebind.PurposeBind)
	adev := f.google.NewDevice(true)
	akey, chain := adev.GenerateKey(devicebind.RoleGesture, ch.Challenge, devicesim.KeyOptions{})
	_, err = f.svc.FinishAndroid(ctx(t), f.user, ch.FlowID, devicebind.AndroidBinding{Role: devicebind.RoleGesture, Chain: chain,
		IntegrityToken: adev.IntegrityToken(ch.Challenge, devicesim.Point(t, akey), nil)})
	is(t, err, devicebind.ErrRequest)

	// A device revoked outside the service fails ActiveKey for its keys.
	if _, err := f.pool.Exec(ctx(t), `UPDATE devices SET revoked_at = now(), revoke_reason = 'support'
		WHERE device_id = $1`, reg.Device.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.ActiveKey(ctx(t), reg.Key.ID)
	is(t, err, devicebind.ErrRevoked)
}

func TestPlatformNotConfigured(t *testing.T) {
	f := newFixture(t, func(_ *fixture, cfg *devicebind.Config) {
		cfg.Android, cfg.Integrity = devicebind.AndroidConfig{}, nil
	})
	ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
	_, err := f.svc.FinishAndroid(ctx(t), f.user, ch.FlowID, devicebind.AndroidBinding{Role: devicebind.RoleDevice})
	is(t, err, devicebind.ErrPlatform)
	f.must(f.registerIOS(f.apple.NewDevice(), devicesim.NewKey(t)))
}

// TestConcurrentRebind races K_dev re-bindings on one device: the device
// row lock serialises them, every one succeeds, each supersedes its
// predecessor, and exactly one K_dev stays active.
func TestConcurrentRebind(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.google.NewDevice(true)
	_, reg, err := f.bindAndroid(dev, uuid.Nil, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	type attempt struct {
		flow  string
		chain [][]byte
		token string
	}
	attempts := make([]attempt, n)
	for i := range attempts {
		ch := f.begin(f.user, reg.Device.ID, devicebind.PurposeBind)
		key, chain := dev.GenerateKey(devicebind.RoleDevice, ch.Challenge, devicesim.KeyOptions{})
		attempts[i] = attempt{ch.FlowID, chain, dev.IntegrityToken(ch.Challenge, devicesim.Point(t, key), nil)}
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, a := range attempts {
		wg.Go(func() {
			_, errs[i] = f.svc.FinishAndroid(context.Background(), f.user, a.flow, devicebind.AndroidBinding{
				Role: devicebind.RoleDevice, Chain: a.chain, IntegrityToken: a.token})
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	keys, err := f.svc.Keys(ctx(t), f.user, reg.Device.ID)
	if err != nil || len(keys) != 1 || keys[0].Role != devicebind.RoleDevice {
		t.Fatalf("active keys %v, %v", roles(keys), err)
	}
	if ev := f.events(devicebind.TopicKeyRevoked); len(ev) != n {
		t.Fatalf("%d superseded events, want %d", len(ev), n)
	}
}

func TestLockActiveKey(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.google.NewDevice(false)
	_, b, err := f.bindAndroid(dev, uuid.Nil, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	_, gest, err := f.bindAndroid(dev, b.Device.ID, devicebind.RoleGesture)
	if err != nil {
		t.Fatal(err)
	}
	var dev1 devicebind.Device
	lock := func(id uuid.UUID) (devicebind.Key, error) {
		var k devicebind.Key
		err := pgx.BeginFunc(ctx(t), f.pool, func(tx pgx.Tx) error {
			var err error
			k, dev1, err = devicebind.LockActiveKey(ctx(t), tx, id)
			return err
		})
		return k, err
	}
	k, err := lock(gest.Key.ID)
	if err != nil || k.ID != gest.Key.ID || k.DeviceID != b.Device.ID || k.Role != devicebind.RoleGesture ||
		!slices.Equal(k.PublicKey, gest.Key.PublicKey) {
		t.Fatalf("locked %+v %v", k, err)
	}
	if dev1.ID != b.Device.ID || dev1.UserID != f.user || dev1.IntegrityAt.IsZero() || dev1.Platform != devicebind.PlatformAndroid {
		t.Fatalf("device %+v", dev1)
	}
	if _, err := lock(uuid.New()); !errors.Is(err, devicebind.ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	// The lock holds off device revocation until the holder commits.
	tx, err := f.pool.Begin(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := devicebind.LockActiveKey(ctx(t), tx, b.Key.ID); err != nil {
		t.Fatal(err)
	}
	revoked := make(chan error, 1)
	go func() { revoked <- f.svc.Revoke(context.Background(), f.user, b.Device.ID, "lost") }()
	select {
	case err := <-revoked:
		t.Fatalf("revocation did not wait for the lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{b.Key.ID, gest.Key.ID} {
		if _, err := lock(id); !errors.Is(err, devicebind.ErrRevoked) {
			t.Fatalf("key of a revoked device: %v", err)
		}
	}
	// A revoked key on an active device.
	dev2 := f.google.NewDevice(true)
	_, b2, err := f.bindAndroid(dev2, uuid.Nil, devicebind.RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RevokeKey(ctx(t), f.user, b2.Key.ID, "biometry_changed"); err != nil {
		t.Fatal(err)
	}
	if _, err := lock(b2.Key.ID); !errors.Is(err, devicebind.ErrRevoked) {
		t.Fatalf("revoked key: %v", err)
	}
}

func TestFlowBelongsToItsUser(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.google.NewDevice(false)
	ch := f.begin(f.user, uuid.Nil, devicebind.PurposeBind)
	key, chain := dev.GenerateKey(devicebind.RoleDevice, ch.Challenge, devicesim.KeyOptions{})
	b := devicebind.AndroidBinding{Role: devicebind.RoleDevice, Chain: chain,
		IntegrityToken: dev.IntegrityToken(ch.Challenge, devicesim.Point(t, key), nil)}
	// Someone else holding the flow id cannot bind into the user's account
	// (or their own); the flow is spent.
	if _, err := f.svc.FinishAndroid(ctx(t), f.other, ch.FlowID, b); !errors.Is(err, devicebind.ErrFlow) {
		t.Fatalf("finish by another user: %v", err)
	}
	if _, err := f.svc.FinishAndroid(ctx(t), f.user, ch.FlowID, b); !errors.Is(err, devicebind.ErrFlow) {
		t.Fatalf("spent flow: %v", err)
	}
	if ds, err := f.svc.Devices(ctx(t), f.other); err != nil || len(ds) != 0 {
		t.Fatalf("other's devices %v %v", ds, err)
	}
}
