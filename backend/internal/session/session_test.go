package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/bil1234n/bilyon/backend/internal/dpop"
	"github.com/bil1234n/bilyon/backend/internal/jose"
	"github.com/bil1234n/bilyon/backend/internal/session"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

const (
	issuer   = "https://api.bilyon.example"
	origin   = "https://api.bilyon.example"
	audience = "https://api.bilyon.example"
	realtime = "wss://rt.bilyon.example"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func thumb(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	jkt, err := jose.Thumbprint(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return jkt
}

type fixture struct {
	t      *testing.T
	pool   *pgxpool.Pool
	rdb    *redis.Client
	keys   *session.KeySet
	svc    *session.Service
	proofs *dpop.Verifier
	auth   *session.Authenticator
	user   uuid.UUID
	other  uuid.UUID
	device uuid.UUID

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

func newFixture(t *testing.T, origins ...string) *fixture {
	t.Helper()
	t.Parallel()
	f := &fixture{t: t, pool: srv.Database(t), rdb: redistest.Start(t)}
	var err error
	if f.keys, err = session.NewKeySet(newKey(t)); err != nil {
		t.Fatal(err)
	}
	f.svc = f.service(f.keys, issuer)
	nonceKey := make([]byte, 32)
	_, _ = rand.Read(nonceKey)
	if f.proofs, err = dpop.NewVerifier(dpop.Config{Origins: append([]string{origin}, origins...),
		NonceKeys: [][]byte{nonceKey}, Now: f.now}, f.rdb); err != nil {
		t.Fatal(err)
	}
	f.auth = session.NewAuthenticator(f.svc, f.proofs)
	users := webauthn.NewPGStore(f.pool)
	for _, id := range []*uuid.UUID{&f.user, &f.other} {
		u, err := users.CreateUser(ctx(t), "user")
		if err != nil {
			t.Fatal(err)
		}
		*id = u.ID
	}
	// A device row for device-bound sessions.
	f.device = uuid.New()
	if _, err := f.pool.Exec(ctx(t), `INSERT INTO devices (device_id, user_id, platform, os_patch_level, integrity_at)
		VALUES ($1, $2, 'android', 202609, now())`, f.device, f.user); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) service(keys *session.KeySet, iss string) *session.Service {
	f.t.Helper()
	s, err := session.New(session.Config{Issuer: iss, Audience: []string{audience, realtime}, Now: f.now}, keys, f.pool, f.rdb)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) issue(key *ecdsa.PrivateKey, device uuid.UUID) session.Tokens {
	f.t.Helper()
	tok, err := f.svc.Issue(ctx(f.t), session.Grant{UserID: f.user, DeviceID: device, ClientID: "bilyon-android",
		JKT: thumb(f.t, key), AMR: []string{"webauthn"}})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// authenticate presents token with a fresh proof by key for GET /v1/me.
func (f *fixture) authenticate(key *ecdsa.PrivateKey, token string) (session.Principal, error) {
	f.t.Helper()
	proof, err := dpop.NewProof(key, "GET", origin+"/v1/me", dpop.ProofOptions{Nonce: f.proofs.Nonce(),
		AccessToken: token, IssuedAt: f.now()})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.auth.Authenticate(ctx(f.t), "GET", "/v1/me", []string{"DPoP " + token}, []string{proof})
}

func authCode(t *testing.T, err error, code string) {
	t.Helper()
	var ae *session.AuthError
	if !errors.As(err, &ae) || ae.Code != code {
		t.Fatalf("err = %v, want %s", err, code)
	}
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
		_ = json.Unmarshal(raw, &m)
		out = append(out, m)
	}
	return out
}

func TestKeySet(t *testing.T) {
	t.Parallel()
	signer, old1, old2 := newKey(t), newKey(t), newKey(t)
	ks, err := session.NewKeySet(signer, &old2.PublicKey, &old1.PublicKey, &signer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ks.KeyID() != thumb(t, signer) {
		t.Fatalf("kid %s", ks.KeyID())
	}
	var set struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := json.Unmarshal(ks.JWKS(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 3 || set.Keys[0].Kid != ks.KeyID() || set.Keys[1].Kid > set.Keys[2].Kid {
		t.Fatalf("JWKS %s", ks.JWKS())
	}
	for _, k := range set.Keys {
		if k.Use != "sig" || k.Alg != "ES256" {
			t.Fatalf("JWK %+v", k)
		}
		if got, _ := k.Thumbprint(); got != k.Kid {
			t.Fatalf("kid %s is not the thumbprint %s", k.Kid, got)
		}
	}
	rec := httptest.NewRecorder()
	ks.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rec.Header().Get("Content-Type") != "application/jwk-set+json" || rec.Body.String() != string(ks.JWKS()) {
		t.Fatalf("JWKS response %v %s", rec.Header(), rec.Body)
	}

	dir := t.TempDir()
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(signer)
	sec1, _ := x509.MarshalECPrivateKey(signer)
	pub, _ := x509.MarshalPKIXPublicKey(&old1.PublicKey)
	for _, file := range []string{write("pkcs8.pem", "PRIVATE KEY", pkcs8), write("sec1.pem", "EC PRIVATE KEY", sec1)} {
		loaded, err := session.LoadKeySet(file, write("old.pem", "PUBLIC KEY", pub))
		if err != nil || loaded.KeyID() != ks.KeyID() {
			t.Fatalf("LoadKeySet(%s) = %v", file, err)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalPKCS8PrivateKey(p384)
	p384pub, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	for name, args := range map[string][]string{
		"P-384 signer":        {write("p384.pem", "PRIVATE KEY", p384der)},
		"P-384 previous":      {write("s.pem", "PRIVATE KEY", pkcs8), write("p384pub.pem", "PUBLIC KEY", p384pub)},
		"public as signer":    {write("pub.pem", "PUBLIC KEY", pub)},
		"garbage":             {write("garbage.pem", "PRIVATE KEY", []byte{1, 2, 3})},
		"missing file":        {filepath.Join(dir, "absent.pem")},
		"private as previous": {write("s2.pem", "PRIVATE KEY", pkcs8), write("s3.pem", "PRIVATE KEY", pkcs8)},
	} {
		if _, err := session.LoadKeySet(args[0], args[1:]...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := session.NewKeySet(p384); err == nil {
		t.Error("P-384 signer accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	f := newFixture(t)
	for name, cfg := range map[string]session.Config{
		"no issuer":           {Audience: []string{audience}},
		"no audience":         {Issuer: issuer},
		"unissued expected":   {Issuer: issuer, Audience: []string{audience}, ExpectAudience: realtime},
		"access over refresh": {Issuer: issuer, Audience: []string{audience}, AccessTTL: time.Hour, RefreshTTL: time.Minute},
	} {
		if _, err := session.New(cfg, f.keys, f.pool, f.rdb); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := session.New(session.Config{Issuer: issuer, Audience: []string{audience}}, nil, f.pool, f.rdb); err == nil {
		t.Error("missing keys accepted")
	}
}

func TestIssueAndVerify(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	tok := f.issue(key, f.device)
	if tok.TokenType != "DPoP" || tok.ExpiresIn != 600 || !strings.HasPrefix(tok.RefreshToken, "bilyon_rt_") {
		t.Fatalf("tokens %+v", tok)
	}
	c, err := f.svc.VerifyAccessToken(tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case c.Issuer != issuer || c.Subject != f.user.String() || c.SessionID != tok.SessionID.String():
		t.Fatalf("claims %+v", c)
	case len(c.Audience) != 2 || c.Confirmation.JKT != thumb(t, key) || c.DeviceID != f.device.String():
		t.Fatalf("claims %+v", c)
	case c.ClientID != "bilyon-android" || len(c.AMR) != 1 || c.Expiry-c.IssuedAt != 600 || c.AuthTime != c.IssuedAt:
		t.Fatalf("claims %+v", c)
	}
	j, _ := jose.Parse(tok.AccessToken)
	if typ, _, _ := j.HeaderString("typ"); typ != "at+jwt" {
		t.Fatalf("typ %q", typ)
	}
	if kid, _, _ := j.HeaderString("kid"); kid != f.keys.KeyID() {
		t.Fatalf("kid %q", kid)
	}
	// The realtime service verifies the same token for its audience.
	rt, err := session.New(session.Config{Issuer: issuer, Audience: []string{audience, realtime}, ExpectAudience: realtime,
		Now: f.now}, f.keys, f.pool, f.rdb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.VerifyAccessToken(tok.AccessToken); err != nil {
		t.Fatalf("realtime audience: %v", err)
	}
	p, err := f.authenticate(key, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != f.user || p.SessionID != tok.SessionID || p.DeviceID != f.device || p.JKT != thumb(t, key) {
		t.Fatalf("principal %+v", p)
	}
	if ev := f.events(session.TopicCreated); len(ev) != 1 || ev[0]["session_id"] != tok.SessionID.String() {
		t.Fatalf("created events %v", ev)
	}

	for name, g := range map[string]session.Grant{
		"no user":       {DeviceID: f.device, ClientID: "bilyon-ios", JKT: thumb(t, key), AMR: []string{"webauthn"}},
		"bad jkt":       {UserID: f.user, ClientID: "bilyon-ios", JKT: "short", AMR: []string{"webauthn"}},
		"bad client":    {UserID: f.user, ClientID: "Bilyon iOS", JKT: thumb(t, key), AMR: []string{"webauthn"}},
		"no amr":        {UserID: f.user, ClientID: "bilyon-ios", JKT: thumb(t, key)},
		"bad amr":       {UserID: f.user, ClientID: "bilyon-ios", JKT: thumb(t, key), AMR: []string{"Web Authn"}},
		"too many amrs": {UserID: f.user, ClientID: "bilyon-ios", JKT: thumb(t, key), AMR: strings.Split("a,b,c,d,e,f,g,h,i", ",")},
	} {
		if _, err := f.svc.Issue(ctx(t), g); !errors.Is(err, session.ErrRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A session without a device carries no did.
	tok2 := f.issue(key, uuid.Nil)
	if c, err := f.svc.VerifyAccessToken(tok2.AccessToken); err != nil || c.DeviceID != "" {
		t.Fatalf("device-less claims %+v, %v", c, err)
	}
}

func TestVerifyAccessTokenRejections(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	tok := f.issue(key, uuid.Nil)

	otherKeys, _ := session.NewKeySet(newKey(t))
	if _, err := f.service(otherKeys, issuer).VerifyAccessToken(tok.AccessToken); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatalf("unknown kid: %v", err)
	}
	if _, err := f.service(f.keys, "https://evil.example").VerifyAccessToken(tok.AccessToken); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatalf("other issuer: %v", err)
	}
	other, _ := session.New(session.Config{Issuer: issuer, Audience: []string{"https://other.example"}, Now: f.now},
		f.keys, f.pool, f.rdb)
	if _, err := other.VerifyAccessToken(tok.AccessToken); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatalf("other audience: %v", err)
	}
	parts := strings.Split(tok.AccessToken, ".")
	if _, err := f.svc.VerifyAccessToken(parts[0] + "." + parts[1] + "x." + parts[2]); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := f.svc.VerifyAccessToken("garbage"); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatalf("garbage: %v", err)
	}

	// Hand-made tokens under the real key, each wrong in one way.
	signer := newKey(t)
	ks, _ := session.NewKeySet(signer)
	svc := f.service(ks, issuer)
	now := f.now().Unix()
	base := func() map[string]any {
		return map[string]any{"iss": issuer, "sub": f.user.String(), "aud": []string{audience}, "exp": now + 600,
			"iat": now, "jti": "j", "client_id": "bilyon-ios", "sid": uuid.NewString(), "auth_time": now,
			"amr": []string{"webauthn"}, "cnf": map[string]string{"jkt": thumb(t, key)}}
	}
	sign := func(header map[string]any, claims map[string]any) string {
		raw, _ := json.Marshal(claims)
		s, err := jose.SignES256(signer, header, raw)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	hdr := map[string]any{"typ": "at+jwt", "kid": ks.KeyID()}
	if _, err := svc.VerifyAccessToken(sign(hdr, base())); err != nil {
		t.Fatalf("well-formed hand-made token refused: %v", err)
	}
	edit := func(e func(map[string]any)) map[string]any { c := base(); e(c); return c }
	for name, token := range map[string]string{
		"typ JWT":           sign(map[string]any{"typ": "JWT", "kid": ks.KeyID()}, base()),
		"no kid":            sign(map[string]any{"typ": "at+jwt"}, base()),
		"expired":           sign(hdr, edit(func(c map[string]any) { c["exp"] = now - 31 })),
		"issued in future":  sign(hdr, edit(func(c map[string]any) { c["iat"] = now + 120 })),
		"no cnf":            sign(hdr, edit(func(c map[string]any) { delete(c, "cnf") })),
		"bad sub":           sign(hdr, edit(func(c map[string]any) { c["sub"] = "alice" })),
		"bad sid":           sign(hdr, edit(func(c map[string]any) { c["sid"] = "1" })),
		"bad did":           sign(hdr, edit(func(c map[string]any) { c["did"] = "phone" })),
		"no amr":            sign(hdr, edit(func(c map[string]any) { c["amr"] = []string{} })),
		"string audience":   sign(hdr, edit(func(c map[string]any) { c["aud"] = audience })),
		"duplicate members": sign(hdr, nil),
	} {
		if name == "duplicate members" {
			raw := []byte(`{"iss":"` + issuer + `","iss":"https://evil.example"}`)
			token, _ = jose.SignES256(signer, hdr, raw)
		}
		if _, err := svc.VerifyAccessToken(token); !errors.Is(err, session.ErrInvalidToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	// Key rotation: tokens from the retired key verify while it is listed.
	rotated, _ := session.NewKeySet(newKey(t), &signer.PublicKey)
	if _, err := f.service(rotated, issuer).VerifyAccessToken(sign(hdr, base())); err != nil {
		t.Fatalf("token under a previous key refused: %v", err)
	}
	// Expiry is enforced with the leeway on the service clock.
	f.advance(10*time.Minute + 31*time.Second)
	if _, err := f.svc.VerifyAccessToken(tok.AccessToken); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatalf("expired token: %v", err)
	}
}

func TestRefreshRotation(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	jkt := thumb(t, key)
	t0 := f.issue(key, uuid.Nil)

	_, err := f.svc.Refresh(ctx(t), t0.RefreshToken, thumb(t, newKey(t)))
	if !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatalf("other key: %v", err)
	}
	_, err = f.svc.Refresh(ctx(t), "bilyon_rt_unknown", jkt)
	if !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatalf("unknown token: %v", err)
	}
	f.advance(time.Minute)
	t1, err := f.svc.Refresh(ctx(t), t0.RefreshToken, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if t1.SessionID != t0.SessionID || t1.RefreshToken == t0.RefreshToken || t1.AccessToken == t0.AccessToken {
		t.Fatalf("rotation %+v", t1)
	}
	if _, err := f.authenticate(key, t1.AccessToken); err != nil {
		t.Fatal(err)
	}
	// A lost response: the key holder retries t0 within the grace and gets
	// a new successor; the unreceived t1 refresh token is retired.
	t2, err := f.svc.Refresh(ctx(t), t0.RefreshToken, jkt)
	if err != nil {
		t.Fatalf("retry within the grace: %v", err)
	}
	t3, err := f.svc.Refresh(ctx(t), t2.RefreshToken, jkt)
	if err != nil {
		t.Fatal(err)
	}
	// t0 again: a later token (t2) has been used, so this is reuse.
	_, err = f.svc.Refresh(ctx(t), t0.RefreshToken, jkt)
	if !errors.Is(err, session.ErrInvalidGrant) || !strings.Contains(err.Error(), "reuse") {
		t.Fatalf("reuse after a later use: %v", err)
	}
	_, err = f.svc.Refresh(ctx(t), t3.RefreshToken, jkt)
	if !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatalf("refresh after revocation: %v", err)
	}
	_, err = f.authenticate(key, t3.AccessToken)
	authCode(t, err, session.CodeInvalidToken)
	if ev := f.events(session.TopicRevoked); len(ev) != 1 || ev[0]["reason"] != session.ReasonRefreshReuse {
		t.Fatalf("revoked events %v", ev)
	}
}

func TestRefreshReuseOutsideGrace(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	jkt := thumb(t, key)
	t0 := f.issue(key, uuid.Nil)
	t1, err := f.svc.Refresh(ctx(t), t0.RefreshToken, jkt)
	if err != nil {
		t.Fatal(err)
	}
	f.advance(2 * time.Minute)
	if _, err := f.svc.Refresh(ctx(t), t0.RefreshToken, jkt); !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatalf("stale reuse: %v", err)
	}
	if _, err := f.svc.Refresh(ctx(t), t1.RefreshToken, jkt); !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatalf("the session should be revoked: %v", err)
	}
	if list, _ := f.svc.Sessions(ctx(t), f.user); len(list) != 0 {
		t.Fatalf("sessions after reuse %v", list)
	}

	// A retired token (a successor nobody received) is reuse too.
	s0 := f.issue(key, uuid.Nil)
	if _, err := f.svc.Refresh(ctx(t), s0.RefreshToken, jkt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(ctx(t), s0.RefreshToken, jkt); err != nil { // retry: retires the first successor
		t.Fatal(err)
	}
	var retired int
	if err := f.pool.QueryRow(ctx(t), `SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND retired_at IS NOT NULL`,
		s0.SessionID).Scan(&retired); err != nil || retired != 1 {
		t.Fatalf("%d retired tokens, %v", retired, err)
	}
}

func TestRefreshExpiry(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	jkt := thumb(t, key)
	t0 := f.issue(key, uuid.Nil)
	f.advance(14*24*time.Hour + time.Second)
	if _, err := f.svc.Refresh(ctx(t), t0.RefreshToken, jkt); !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatalf("idle-expired token: %v", err)
	}
	// Expiry is not reuse: the session survives (and expires on its own).
	if list, _ := f.svc.Sessions(ctx(t), f.user); len(list) != 1 {
		t.Fatalf("sessions %v", list)
	}
	// Keep refreshing within the idle window until the absolute lifetime.
	s := f.issue(key, uuid.Nil)
	tok := s.RefreshToken
	for range 3 {
		f.advance(10 * 24 * time.Hour)
		next, err := f.svc.Refresh(ctx(t), tok, jkt)
		if err != nil {
			if !errors.Is(err, session.ErrInvalidGrant) {
				t.Fatal(err)
			}
			return
		}
		if next.ExpiresAt.After(f.now().Add(10 * time.Minute)) {
			t.Fatalf("access token outlives its TTL: %v", next.ExpiresAt)
		}
		tok = next.RefreshToken
	}
	t.Fatal("refresh succeeded past the 30-day session lifetime")
}

func TestConcurrentRefresh(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	jkt := thumb(t, key)
	t0 := f.issue(key, uuid.Nil)
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { _, errs[i] = f.svc.Refresh(context.Background(), t0.RefreshToken, jkt) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
	}
	var live int
	if err := f.pool.QueryRow(ctx(t), `SELECT count(*) FROM refresh_tokens
		WHERE session_id = $1 AND used_at IS NULL AND retired_at IS NULL`, t0.SessionID).Scan(&live); err != nil || live != 1 {
		t.Fatalf("%d live refresh tokens, %v", live, err)
	}
}

func TestStepUp(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	jkt := thumb(t, key)
	tok := f.issue(key, f.device)
	protected := f.auth.Middleware(f.auth.RequireRecentAuth(5*time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	call := func(token string) *httptest.ResponseRecorder {
		proof, _ := dpop.NewProof(key, "POST", origin+"/v1/devices/rebind", dpop.ProofOptions{Nonce: f.proofs.Nonce(),
			AccessToken: token, IssuedAt: f.now()})
		req := httptest.NewRequest("POST", "/v1/devices/rebind", nil)
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", proof)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		return rec
	}
	if rec := call(tok.AccessToken); rec.Code != http.StatusNoContent {
		t.Fatalf("fresh login: %d %s", rec.Code, rec.Body)
	}
	f.advance(6 * time.Minute)
	refreshed, err := f.svc.Refresh(ctx(t), tok.RefreshToken, jkt)
	if err != nil {
		t.Fatal(err)
	}
	rec := call(refreshed.AccessToken)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), session.CodeInsufficientAuth) {
		t.Fatalf("stale authentication: %d %v", rec.Code, rec.Header())
	}
	if age, ok := session.ParseMaxAge(rec.Header().Get("WWW-Authenticate")); !ok || age != 5*time.Minute {
		t.Fatalf("max_age %v %v", age, ok)
	}
	stepped, err := f.svc.StepUp(ctx(t), tok.SessionID, jkt, "webauthn_uv")
	if err != nil {
		t.Fatal(err)
	}
	if stepped.RefreshToken != "" {
		t.Fatal("step-up must not rotate the refresh token")
	}
	if rec := call(stepped.AccessToken); rec.Code != http.StatusNoContent {
		t.Fatalf("after step-up: %d %s", rec.Code, rec.Body)
	}
	c, _ := f.svc.VerifyAccessToken(stepped.AccessToken)
	if len(c.AMR) != 2 || c.AMR[0] != "webauthn" || c.AMR[1] != "webauthn_uv" {
		t.Fatalf("amr %v", c.AMR)
	}
	// The new auth time survives refreshes.
	again, err := f.svc.Refresh(ctx(t), refreshed.RefreshToken, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if c2, _ := f.svc.VerifyAccessToken(again.AccessToken); c2.AuthTime != c.AuthTime {
		t.Fatalf("auth_time %d after refresh, want %d", c2.AuthTime, c.AuthTime)
	}
	if _, err := f.svc.StepUp(ctx(t), tok.SessionID, thumb(t, newKey(t)), "webauthn"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("step-up with another key: %v", err)
	}
	if _, err := f.svc.StepUp(ctx(t), tok.SessionID, jkt, "Web Authn"); !errors.Is(err, session.ErrRequest) {
		t.Fatalf("bad method: %v", err)
	}
}

func TestRevocation(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	a := f.issue(key, f.device)
	b := f.issue(key, uuid.Nil)
	c := f.issue(key, f.device)

	if err := f.svc.Revoke(ctx(t), f.other, a.SessionID, "sign-out"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("another user's session: %v", err)
	}
	if err := f.svc.Revoke(ctx(t), f.user, uuid.New(), "sign-out"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("unknown session: %v", err)
	}
	if err := f.svc.Revoke(ctx(t), f.user, a.SessionID, ""); !errors.Is(err, session.ErrRequest) {
		t.Fatalf("no reason: %v", err)
	}
	if err := f.svc.Revoke(ctx(t), f.user, a.SessionID, "sign-out"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(ctx(t), f.user, a.SessionID, "sign-out"); err != nil {
		t.Fatalf("second revocation: %v", err)
	}
	_, err := f.authenticate(key, a.AccessToken)
	authCode(t, err, session.CodeInvalidToken)
	if _, err := f.svc.Refresh(ctx(t), a.RefreshToken, thumb(t, key)); !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatalf("refresh of a revoked session: %v", err)
	}
	if _, err := f.authenticate(key, b.AccessToken); err != nil {
		t.Fatalf("other sessions are untouched: %v", err)
	}

	n, err := f.svc.RevokeDevice(ctx(t), f.device, "device revoked")
	if err != nil || n != 1 {
		t.Fatalf("RevokeDevice = %d, %v", n, err)
	}
	_, err = f.authenticate(key, c.AccessToken)
	authCode(t, err, session.CodeInvalidToken)
	if _, err := f.authenticate(key, b.AccessToken); err != nil {
		t.Fatalf("device-less session revoked with the device: %v", err)
	}
	list, err := f.svc.Sessions(ctx(t), f.user)
	if err != nil || len(list) != 1 || list[0].ID != b.SessionID {
		t.Fatalf("Sessions = %v, %v", list, err)
	}
	if n, err := f.svc.RevokeUser(ctx(t), f.user, "account locked"); err != nil || n != 1 {
		t.Fatalf("RevokeUser = %d, %v", n, err)
	}
	if n, err := f.svc.RevokeUser(ctx(t), f.user, "account locked"); err != nil || n != 0 {
		t.Fatalf("second RevokeUser = %d, %v", n, err)
	}
	_, err = f.authenticate(key, b.AccessToken)
	authCode(t, err, session.CodeInvalidToken)
	if ev := f.events(session.TopicRevoked); len(ev) != 3 {
		t.Fatalf("%d revoked events", len(ev))
	}
}

func TestPurge(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	old := f.issue(key, uuid.Nil)
	revoked := f.issue(key, uuid.Nil)
	if err := f.svc.Revoke(ctx(t), f.user, revoked.SessionID, "sign-out"); err != nil {
		t.Fatal(err)
	}
	f.advance(31 * 24 * time.Hour)
	live := f.issue(key, uuid.Nil)
	n, err := f.svc.Purge(ctx(t), 24*time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("Purge = %d, %v", n, err)
	}
	var tokens int
	if err := f.pool.QueryRow(ctx(t), `SELECT count(*) FROM refresh_tokens WHERE session_id = ANY($1)`,
		[]uuid.UUID{old.SessionID, revoked.SessionID}).Scan(&tokens); err != nil || tokens != 0 {
		t.Fatalf("%d orphaned refresh tokens, %v", tokens, err)
	}
	if list, _ := f.svc.Sessions(ctx(t), f.user); len(list) != 1 || list[0].ID != live.SessionID {
		t.Fatalf("sessions after purge %v", list)
	}
}

// TestHTTPMiddleware drives the middleware over real HTTP.
func TestHTTPMiddleware(t *testing.T) {
	type box struct{ h http.Handler }
	var handler atomic.Pointer[box]
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Load().h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	f := newFixture(t, ts.URL)
	mux := http.NewServeMux()
	mux.Handle("GET /v1/me", f.auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := session.PrincipalFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{"user": p.UserID.String(), "session": p.SessionID.String()})
	})))
	mux.Handle("POST /v1/session/refresh", f.auth.RequireProof(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := session.ProofFrom(r.Context())
		_, _ = io.WriteString(w, p.JKT)
	})))
	handler.Store(&box{mux})

	key := newKey(t)
	tok := f.issue(key, uuid.Nil)
	do := func(method, path string, headers map[string][]string) *http.Response {
		req, _ := http.NewRequest(method, ts.URL+path, nil)
		for k, vs := range headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}
	proof := func(method, path, nonce, token string, k *ecdsa.PrivateKey) string {
		p, err := dpop.NewProof(k, method, ts.URL+path, dpop.ProofOptions{Nonce: nonce, AccessToken: token, IssuedAt: f.now()})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	expect := func(resp *http.Response, code int, challenge string) {
		t.Helper()
		if resp.StatusCode != code {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d (%s), want %d", resp.StatusCode, body, code)
		}
		if challenge != "" && !strings.Contains(resp.Header.Get("WWW-Authenticate"), challenge) {
			t.Fatalf("challenge %q lacks %q", resp.Header.Get("WWW-Authenticate"), challenge)
		}
	}

	resp := do("GET", "/v1/me", nil)
	expect(resp, 401, `DPoP algs="ES256"`)
	if strings.Contains(resp.Header.Get("WWW-Authenticate"), "error=") || resp.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("no-credentials challenge %v", resp.Header)
	}
	expect(do("GET", "/v1/me", map[string][]string{"Authorization": {"Bearer " + tok.AccessToken}}), 401, `error="invalid_token"`)
	expect(do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken, "DPoP x"}}), 401, `error="invalid_token"`)
	expect(do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken}}), 401, `error="invalid_dpop_proof"`)

	// First try without a nonce: the server hands one out.
	resp = do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken},
		"DPoP": {proof("GET", "/v1/me", "", tok.AccessToken, key)}})
	expect(resp, 401, `error="use_dpop_nonce"`)
	nonce := resp.Header.Get("DPoP-Nonce")
	good := proof("GET", "/v1/me", nonce, tok.AccessToken, key)
	resp = do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken}, "DPoP": {good}})
	expect(resp, 200, "")
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["user"] != f.user.String() || body["session"] != tok.SessionID.String() || resp.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("body %v headers %v", body, resp.Header)
	}
	expect(do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken}, "DPoP": {good}}),
		401, `error="invalid_dpop_proof"`)
	// A proof by another key: valid on its own, but not the token's key.
	expect(do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken},
		"DPoP": {proof("GET", "/v1/me", nonce, tok.AccessToken, newKey(t))}}), 401, `error="invalid_token"`)
	// A proof for another path.
	expect(do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken},
		"DPoP": {proof("GET", "/v1/other", nonce, tok.AccessToken, key)}}), 401, `error="invalid_dpop_proof"`)

	// Proof-only endpoints (refresh, login).
	resp = do("POST", "/v1/session/refresh", map[string][]string{"DPoP": {proof("POST", "/v1/session/refresh", nonce, "", key)}})
	expect(resp, 200, "")
	if jkt, _ := io.ReadAll(resp.Body); string(jkt) != thumb(t, key) {
		t.Fatalf("proof jkt %s", jkt)
	}
	expect(do("POST", "/v1/session/refresh", nil), 401, `error="invalid_dpop_proof"`)

	// Infrastructure failure: 503, not 401.
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = dead.Close() })
	deadProofs, _ := dpop.NewVerifier(dpop.Config{Origins: []string{ts.URL}, Now: f.now}, dead)
	broken := session.NewAuthenticator(f.svc, deadProofs)
	handler.Store(&box{broken.Middleware(http.NotFoundHandler())})
	expect(do("GET", "/v1/me", map[string][]string{"Authorization": {"DPoP " + tok.AccessToken},
		"DPoP": {proof("GET", "/v1/me", "", tok.AccessToken, key)}}), 503, "")
}

func TestGRPCInterceptors(t *testing.T) {
	f := newFixture(t)
	var public atomic.Bool
	isPublic := func(string) bool { return public.Load() }
	gs := grpc.NewServer(grpc.UnaryInterceptor(f.auth.UnaryInterceptor(isPublic)),
		grpc.StreamInterceptor(f.auth.StreamInterceptor(isPublic)))
	hs := health.NewServer()
	healthpb.RegisterHealthServer(gs, hs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///"+lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := healthpb.NewHealthClient(conn)

	key := newKey(t)
	tok := f.issue(key, uuid.Nil)
	const method = "/grpc.health.v1.Health/Check"
	call := func(md ...string) (metadata.MD, error) {
		var header metadata.MD
		c := metadata.AppendToOutgoingContext(ctx(t), md...)
		_, err := client.Check(c, &healthpb.HealthCheckRequest{}, grpc.Header(&header))
		return header, err
	}
	header, err := call()
	if status.Code(err) != codes.Unauthenticated || len(header.Get("www-authenticate")) != 1 || len(header.Get("dpop-nonce")) != 1 {
		t.Fatalf("anonymous call: %v %v", err, header)
	}
	proof, _ := dpop.NewProof(key, "POST", origin+method, dpop.ProofOptions{Nonce: f.proofs.Nonce(),
		AccessToken: tok.AccessToken, IssuedAt: f.now()})
	if header, err := call("authorization", "DPoP "+tok.AccessToken, "dpop", proof); err != nil || len(header.Get("dpop-nonce")) != 1 {
		t.Fatalf("authenticated call: %v %v", err, header)
	}
	if _, err := call("authorization", "DPoP "+tok.AccessToken, "dpop", proof); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed proof: %v", err)
	}
	// Streams authenticate at start.
	watch, err := client.Watch(ctx(t), &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = watch.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous stream: %v", err)
	}
	streamProof, _ := dpop.NewProof(key, "POST", origin+"/grpc.health.v1.Health/Watch", dpop.ProofOptions{
		Nonce: f.proofs.Nonce(), AccessToken: tok.AccessToken, IssuedAt: f.now()})
	sc := metadata.AppendToOutgoingContext(ctx(t), "authorization", "DPoP "+tok.AccessToken, "dpop", streamProof)
	watch, err = client.Watch(sc, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if update, err := watch.Recv(); err != nil || update.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("authenticated stream: %v %v", update, err)
	}
	public.Store(true)
	if _, err := call(); err != nil {
		t.Fatalf("public method: %v", err)
	}
}

// TestRefreshAfterSessionShortened covers an operator shortening session
// lifetimes in the database: the session's own expiry is enforced even
// while its refresh token is still within its idle lifetime.
func TestRefreshAfterSessionShortened(t *testing.T) {
	f := newFixture(t)
	key := newKey(t)
	tok := f.issue(key, uuid.Nil)
	if _, err := f.pool.Exec(ctx(t), `UPDATE sessions SET expires_at = created_at + interval '1 second'
		WHERE session_id = $1`, tok.SessionID); err != nil {
		t.Fatal(err)
	}
	f.advance(2 * time.Second)
	_, err := f.svc.Refresh(ctx(t), tok.RefreshToken, thumb(t, key))
	if !errors.Is(err, session.ErrInvalidGrant) || !strings.Contains(err.Error(), "session expired") {
		t.Fatalf("refresh of a shortened session: %v", err)
	}
}
