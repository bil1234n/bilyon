package webauthn_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/authenticator"
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

var androidOrigin = "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(func() []byte {
	h := sha256.Sum256([]byte("bilyon signing certificate"))
	return h[:]
}())

type fixture struct {
	t     *testing.T
	pool  *pgxpool.Pool
	store *webauthn.PGStore
	rp    *webauthn.RP
	auth  *authenticator.Authenticator
	user  webauthn.User
	now   time.Time
}

func newFixture(t *testing.T, anchors *x509.CertPool) *fixture {
	t.Helper()
	t.Parallel()
	pool := srv.Database(t)
	f := &fixture{t: t, pool: pool, store: webauthn.NewPGStore(pool), auth: authenticator.New(t), now: time.Now()}
	if anchors == nil {
		anchors = x509.NewCertPool() // anchored trust only for chains to an unrelated root: never
	}
	rp, err := webauthn.New(webauthn.Config{RPID: "bilyon.example", RPName: "Bilyon",
		Origins: []string{"https://bilyon.example", "https://pay.bilyon.example", androidOrigin}, TrustAnchors: anchors,
		Now: func() time.Time { return f.now }},
		webauthn.NewRedisChallenges(redistest.Start(t)), f.store)
	if err != nil {
		t.Fatal(err)
	}
	f.rp = rp
	if f.user, err = f.store.CreateUser(ctx(t), "Alice"); err != nil {
		t.Fatal(err)
	}
	return f
}

// register runs a full registration ceremony.
func (f *fixture) register(alg int64, o authenticator.Options) (*authenticator.Credential, *webauthn.Credential, error) {
	f.t.Helper()
	opts, flow, err := f.rp.BeginRegistration(ctx(f.t), f.user)
	if err != nil {
		f.t.Fatal(err)
	}
	cred := f.auth.NewCredential(alg)
	resp := f.auth.Register(cred, opts, o)
	stored, err := f.rp.FinishRegistration(ctx(f.t), flow, roundTrip(f.t, resp))
	return cred, stored, err
}

// roundTrip passes a response through its JSON wire form.
func roundTrip[T any](t *testing.T, v *T) *T {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func (f *fixture) login(cred *authenticator.Credential, o authenticator.AssertOptions) (*webauthn.LoginResult, error) {
	f.t.Helper()
	opts, flow, err := f.rp.BeginLogin(ctx(f.t), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.rp.FinishLogin(ctx(f.t), flow, roundTrip(f.t, f.auth.Assert(cred, opts, o)))
}

func step(err error) string {
	var ve *webauthn.VerificationError
	if errors.As(err, &ve) {
		return ve.Step
	}
	return ""
}

func (f *fixture) events(topic string) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(ctx(f.t), `SELECT count(*) FROM outbox WHERE topic = $1`, topic).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestEveryAttestationFormatRegistersAndLogsIn(t *testing.T) {
	cases := []struct {
		format string
		alg    int64
		trust  string
	}{
		{"none", cose.AlgES256, webauthn.TrustNone},
		{"none", cose.AlgRS256, webauthn.TrustNone},
		{"packed-self", cose.AlgES256, webauthn.TrustSelf},
		{"packed-self", cose.AlgRS256, webauthn.TrustSelf},
		{"packed", cose.AlgES256, webauthn.TrustBasic},
		{"fido-u2f", cose.AlgES256, webauthn.TrustBasic},
		{"apple", cose.AlgES256, webauthn.TrustAnonCA},
		{"android-key", cose.AlgES256, webauthn.TrustBasic},
		{"tpm", cose.AlgES256, webauthn.TrustAttCA},
		{"compound", cose.AlgES256, webauthn.TrustBasic},
	}
	for _, c := range cases {
		t.Run(c.format+"/"+map[int64]string{cose.AlgES256: "ES256", cose.AlgRS256: "RS256"}[c.alg], func(t *testing.T) {
			f := newFixture(t, nil)
			cred, stored, err := f.register(c.alg, authenticator.Options{Format: c.format})
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			wantFmt := strings.TrimSuffix(c.format, "-self")
			if stored.AttestationFormat != wantFmt || stored.AttestationTrust != c.trust || stored.AAGUID != f.auth.AAGUID ||
				stored.Alg != c.alg || stored.UserID != f.user.ID {
				t.Fatalf("stored credential %+v", stored)
			}
			if len(stored.Transports) != 2 { // "bogus" is dropped
				t.Fatalf("transports %v", stored.Transports)
			}
			res, err := f.login(cred, authenticator.AssertOptions{})
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			if res.UserID != f.user.ID || res.CloneSignal {
				t.Fatalf("login result %+v", res)
			}
			if f.events(webauthn.TopicCredentialRegistered) != 1 {
				t.Fatal("registration event missing")
			}
		})
	}
}

func TestTrustAnchorsUpgradeChainedAttestations(t *testing.T) {
	f := newFixture(t, nil)
	anchored := newFixtureWithAuth(t, f.auth)
	_, stored, err := anchored.register(cose.AlgES256, authenticator.Options{Format: "packed"})
	if err != nil {
		t.Fatal(err)
	}
	if stored.AttestationTrust != webauthn.TrustAnchored {
		t.Fatalf("trust %s with the attestation root configured", stored.AttestationTrust)
	}
}

func newFixtureWithAuth(t *testing.T, a *authenticator.Authenticator) *fixture {
	t.Helper()
	pool := srv.Database(t)
	f := &fixture{t: t, pool: pool, store: webauthn.NewPGStore(pool), auth: a, now: time.Now()}
	rp, err := webauthn.New(webauthn.Config{RPID: "bilyon.example", RPName: "Bilyon", Origins: []string{"https://bilyon.example"},
		TrustAnchors: a.Pool(), Now: func() time.Time { return f.now }}, webauthn.NewRedisChallenges(redistest.Start(t)), f.store)
	if err != nil {
		t.Fatal(err)
	}
	f.rp = rp
	if f.user, err = f.store.CreateUser(ctx(t), "Bob"); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRegistrationStepsRejectBadResponses(t *testing.T) {
	f := newFixture(t, nil)
	other := sha256.Sum256([]byte("x"))
	cases := []struct {
		name string
		o    authenticator.Options
		step string
	}{
		{"R1 wrong client data type", authenticator.Options{Type: "webauthn.get"}, "R1"},
		{"R2 wrong challenge", authenticator.Options{Challenge: other[:]}, "R2"},
		{"R3 foreign origin", authenticator.Options{Origin: "https://evil.example"}, "R3"},
		{"R3 cross-origin", authenticator.Options{CrossOrigin: true}, "R3"},
		{"R3 embedded", authenticator.Options{TopOrigin: "https://host.example"}, "R3"},
		{"R5 other RP ID", authenticator.Options{RPID: "evil.example"}, "R5"},
		{"R6 no user verification", authenticator.Options{Flags: authenticator.FlagUP}, "R6"},
		{"R6 no user presence", authenticator.Options{Flags: authenticator.FlagUV}, "R6"},
		{"R9 tampered packed signature", authenticator.Options{Format: "packed", Mutate: func(m cbor.Map) { m["sig"] = []byte{0x30, 0x00} }}, "R9"},
		{"R9 packed self with other alg", authenticator.Options{Format: "packed-self", Mutate: func(m cbor.Map) { m["alg"] = int64(-257) }}, "R9"},
		{"R9 packed certificate without the attestation OU", authenticator.Options{Format: "packed",
			CertTweak: func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"Other"} }}, "R9"},
		{"R9 packed certificate that is a CA", authenticator.Options{Format: "packed",
			CertTweak: func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }}, "R9"},
		{"R9 unknown attStmt key", authenticator.Options{Format: "packed", Mutate: func(m cbor.Map) { m["extra"] = uint64(1) }}, "R9"},
		{"R9 none with a statement", authenticator.Options{Mutate: func(m cbor.Map) { m["sig"] = []byte{1} }}, "R9"},
		{"R9 apple nonce mismatch", authenticator.Options{Format: "apple", Mutate: func(m cbor.Map) {
			m["x5c"] = m["x5c"].([]any)[1:] // the root alone carries no nonce
		}}, "R9"},
		{"R9 android key usable by all apps", authenticator.Options{Format: "android-key", AndroidAllApplications: true}, "R9"},
		{"R9 android key imported", authenticator.Options{Format: "android-key", AndroidOrigin: 2}, "R9"},
		{"R9 tpm extraData", authenticator.Options{Format: "tpm", TPMExtraData: make([]byte, 32)}, "R9"},
		{"R9 tpm unknown vendor", authenticator.Options{Format: "tpm", TPMManufacturer: "id:12345678"}, "R9"},
		{"R9 tpm signature", authenticator.Options{Format: "tpm", Mutate: func(m cbor.Map) {
			sig := append([]byte{}, m["sig"].([]byte)...)
			sig[10] ^= 1
			m["sig"] = sig
		}}, "R9"},
		{"R9 tpm version", authenticator.Options{Format: "tpm", Mutate: func(m cbor.Map) { m["ver"] = "1.2" }}, "R9"},
		{"R9 fido-u2f signature", authenticator.Options{Format: "fido-u2f", Mutate: func(m cbor.Map) { m["sig"] = []byte{0x30, 0x00} }}, "R9"},
	}
	for _, c := range cases {
		if _, _, err := f.register(cose.AlgES256, c.o); step(err) != c.step {
			t.Errorf("%s: got %v, want step %s", c.name, err, c.step)
		}
	}
}

func TestRegistrationCeremonyRules(t *testing.T) {
	f := newFixture(t, nil)
	// R2: a flow is single use, and expires.
	opts, flow, err := f.rp.BeginRegistration(ctx(t), f.user)
	if err != nil {
		t.Fatal(err)
	}
	cred := f.auth.NewCredential(cose.AlgES256)
	resp := f.auth.Register(cred, opts, authenticator.Options{})
	if _, err := f.rp.FinishRegistration(ctx(t), flow, resp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rp.FinishRegistration(ctx(t), flow, resp); step(err) != "R2" {
		t.Fatalf("replayed flow: %v", err)
	}
	opts, flow, _ = f.rp.BeginRegistration(ctx(t), f.user)
	f.now = f.now.Add(121 * time.Second)
	if _, err := f.rp.FinishRegistration(ctx(t), flow, f.auth.Register(f.auth.NewCredential(cose.AlgES256), opts, authenticator.Options{})); step(err) != "R2" {
		t.Fatalf("expired flow: %v", err)
	}
	f.now = time.Now()

	// R7: the same credential cannot be registered twice, by anyone.
	opts, flow, _ = f.rp.BeginRegistration(ctx(t), f.user)
	if len(opts.ExcludeCredentials) != 1 || string(opts.ExcludeCredentials[0].ID) != string(cred.ID) {
		t.Fatalf("excludeCredentials %+v", opts.ExcludeCredentials)
	}
	if _, err := f.rp.FinishRegistration(ctx(t), flow, f.auth.Register(cred, opts, authenticator.Options{})); step(err) != "R7" {
		t.Fatalf("duplicate credential: %v", err)
	}
	// R7: the credential id in authData must be rawId.
	opts, flow, _ = f.rp.BeginRegistration(ctx(t), f.user)
	resp = f.auth.Register(f.auth.NewCredential(cose.AlgES256), opts, authenticator.Options{})
	resp.RawID = append([]byte{}, resp.RawID...)
	resp.RawID[0] ^= 1
	resp.ID = base64.RawURLEncoding.EncodeToString(resp.RawID)
	if _, err := f.rp.FinishRegistration(ctx(t), flow, resp); step(err) != "R7" {
		t.Fatalf("rawId mismatch: %v", err)
	}
	// The envelope: id must encode rawId, type must be public-key.
	opts, flow, _ = f.rp.BeginRegistration(ctx(t), f.user)
	resp = f.auth.Register(f.auth.NewCredential(cose.AlgES256), opts, authenticator.Options{})
	resp.Type = "password"
	if _, err := f.rp.FinishRegistration(ctx(t), flow, resp); !errors.Is(err, webauthn.ErrInvalid) {
		t.Fatalf("wrong type: %v", err)
	}
	// R4: a malformed attestation object.
	opts, flow, _ = f.rp.BeginRegistration(ctx(t), f.user)
	resp = f.auth.Register(f.auth.NewCredential(cose.AlgES256), opts, authenticator.Options{})
	resp.Response.AttestationObject = cbor.MustEncode(cbor.Map{"fmt": "none", "attStmt": cbor.Map{}, "authData": []byte{1}, "x": uint64(1)})
	if _, err := f.rp.FinishRegistration(ctx(t), flow, resp); step(err) != "R4" {
		t.Fatalf("malformed attestation object: %v", err)
	}
	// Creation options follow RFC 0001 §2.2.2.
	raw, _ := json.Marshal(opts)
	for _, want := range []string{`"residentKey":"required"`, `"userVerification":"required"`, `"attestation":"none"`,
		`{"type":"public-key","alg":-7}`, `{"type":"public-key","alg":-257}`, `"hints":["client-device"]`, `"credProps":true`, `"timeout":120000`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("creation options lack %s: %s", want, raw)
		}
	}
	if len(opts.User.ID) != 32 || opts.User.Name != "Alice" {
		t.Fatalf("user entity %+v", opts.User)
	}
}

func TestLoginStepsAndRiskSignals(t *testing.T) {
	f := newFixture(t, nil)
	cred, _, err := f.register(cose.AlgES256, authenticator.Options{Flags: authenticator.FlagUP | authenticator.FlagUV | authenticator.FlagBE})
	if err != nil {
		t.Fatal(err)
	}
	be := byte(authenticator.FlagUP | authenticator.FlagUV | authenticator.FlagBE)
	ok := func(o authenticator.AssertOptions) *webauthn.LoginResult {
		t.Helper()
		if o.Flags == 0 {
			o.Flags = be
		}
		res, err := f.login(cred, o)
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		return res
	}
	// Synced passkeys report 0 forever: not a clone signal.
	if res := ok(authenticator.AssertOptions{}); res.CloneSignal {
		t.Fatal("a zero counter raised a clone signal")
	}
	// A6: becoming backed up is a risk feature.
	if res := ok(authenticator.AssertOptions{Flags: be | authenticator.FlagBS}); !res.BackedUp {
		t.Fatal("backup state not reported")
	}
	if f.events(webauthn.TopicBackupStateChanged) != 1 {
		t.Fatal("backup-state event missing")
	}
	// A5: a counter that goes backwards is a clone signal, but login proceeds.
	five, three := uint32(5), uint32(3)
	ok(authenticator.AssertOptions{SignCount: &five})
	if res := ok(authenticator.AssertOptions{SignCount: &three}); !res.CloneSignal {
		t.Fatal("counter regression not flagged")
	}
	if f.events(webauthn.TopicCloneSignal) != 1 {
		t.Fatal("clone event missing")
	}
	var stored int64
	_ = f.pool.QueryRow(ctx(t), `SELECT sign_count FROM webauthn_credentials`).Scan(&stored)
	if stored != 5 {
		t.Fatalf("stored counter %d; it must never go backwards", stored)
	}

	other := sha256.Sum256([]byte("other"))
	stranger, err := f.store.CreateUser(ctx(t), "Mallory")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		o    authenticator.AssertOptions
		step string
	}{
		{"A2 wrong type", authenticator.AssertOptions{Type: "webauthn.create"}, "A2"},
		{"A2 wrong challenge", authenticator.AssertOptions{Challenge: other[:]}, "A2"},
		{"A2 foreign origin", authenticator.AssertOptions{Origin: "https://evil.example"}, "A2"},
		{"A3 other RP ID", authenticator.AssertOptions{RPID: "evil.example"}, "A3"},
		{"A3 no user verification", authenticator.AssertOptions{Flags: authenticator.FlagUP | authenticator.FlagBE}, "A3"},
		{"A3 backup eligibility changed", authenticator.AssertOptions{Flags: authenticator.FlagUP | authenticator.FlagUV}, "A3"},
		{"A4 bad signature", authenticator.AssertOptions{BadSig: true}, "A4"},
		{"A1 user handle of someone else", authenticator.AssertOptions{UserHandle: stranger.Handle}, "A1"},
	}
	for _, c := range cases {
		if c.o.Flags == 0 {
			c.o.Flags = be
		}
		if _, err := f.login(cred, c.o); step(err) != c.step {
			t.Errorf("%s: got %v, want %s", c.name, err, c.step)
		}
	}
	// A1: unknown credentials and pre-identified accounts.
	if _, err := f.login(f.auth.NewCredential(cose.AlgES256), authenticator.AssertOptions{}); step(err) != "A1" {
		t.Fatalf("unknown credential: %v", err)
	}
	opts, flow, _ := f.rp.BeginLogin(ctx(t), &stranger.ID)
	if _, err := f.rp.FinishLogin(ctx(t), flow, f.auth.Assert(cred, opts, authenticator.AssertOptions{Flags: be})); step(err) != "A1" {
		t.Fatalf("credential of another account: %v", err)
	}
	// Discoverable login works without a user handle too.
	if _, err := f.login(cred, authenticator.AssertOptions{Flags: be, UserHandle: []byte{}}); err != nil {
		t.Fatalf("login without user handle: %v", err)
	}
	// A frozen account cannot log in.
	if _, err := f.pool.Exec(ctx(t), `UPDATE users SET status = 'frozen' WHERE user_id = $1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.login(cred, authenticator.AssertOptions{Flags: be}); step(err) != "A1" {
		t.Fatalf("frozen account: %v", err)
	}
	if _, _, err := f.rp.BeginRegistration(ctx(t), webauthn.User{ID: f.user.ID, Status: "frozen"}); err == nil {
		t.Fatal("registration for a frozen account")
	}
}

func TestConfigValidation(t *testing.T) {
	good := webauthn.Config{RPID: "bilyon.example", RPName: "Bilyon", Origins: []string{"https://pay.bilyon.example:8443"}}
	if _, err := webauthn.New(good, nil, nil); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]webauthn.Config{
		"no RP ID":         {RPName: "B", Origins: []string{"https://bilyon.example"}},
		"URL as RP ID":     {RPID: "https://bilyon.example", RPName: "B", Origins: []string{"https://bilyon.example"}},
		"no name":          {RPID: "bilyon.example", Origins: []string{"https://bilyon.example"}},
		"no origins":       {RPID: "bilyon.example", RPName: "B"},
		"http origin":      {RPID: "bilyon.example", RPName: "B", Origins: []string{"http://bilyon.example"}},
		"foreign origin":   {RPID: "bilyon.example", RPName: "B", Origins: []string{"https://evilbilyon.example"}},
		"origin with path": {RPID: "bilyon.example", RPName: "B", Origins: []string{"https://bilyon.example/login"}},
		"bad android hash": {RPID: "bilyon.example", RPName: "B", Origins: []string{"android:apk-key-hash:abc"}},
	} {
		if _, err := webauthn.New(cfg, nil, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
