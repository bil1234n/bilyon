package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bil1234n/bilyon/backend/internal/jose"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
)

// RFC 9449 Figure 3 (token request) and Figure 13 (resource request).
const (
	rfcJKT           = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	rfcTokenProof    = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	rfcResourceProof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
	rfcAccessToken   = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func refused(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want %s", err, code)
	}
}

func TestRFC9449Examples(t *testing.T) {
	t.Parallel()
	rdb := redistest.Start(t)
	at := func(sec int64) func() time.Time { return func() time.Time { return time.Unix(sec, 0) } }
	v, err := NewVerifier(Config{Origins: []string{"https://server.example.com"}, Now: at(1562262620)}, rdb)
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Verify(ctx(t), Request{Method: "POST", Path: "/token", Proofs: []string{rfcTokenProof}})
	if err != nil {
		t.Fatal(err)
	}
	if p.JKT != rfcJKT || p.JTI != "-BwC3ESc6acc2lTc" || p.IssuedAt.Unix() != 1562262616 {
		t.Fatalf("proof %+v", p)
	}
	_, err = v.Verify(ctx(t), Request{Method: "POST", Path: "/token", Proofs: []string{rfcTokenProof}})
	refused(t, err, CodeInvalidProof)

	rv, err := NewVerifier(Config{Origins: []string{"https://resource.example.org"}, Now: at(1562262620)}, rdb)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Method: "GET", Path: "/protectedresource", Proofs: []string{rfcResourceProof}}
	req.AccessToken = "another token"
	_, err = rv.Verify(ctx(t), req)
	refused(t, err, CodeInvalidProof)
	req.AccessToken = rfcAccessToken
	if p, err := rv.Verify(ctx(t), req); err != nil || p.JKT != rfcJKT {
		t.Fatalf("resource proof: %+v, %v", p, err)
	}
	if AccessTokenHash(rfcAccessToken) != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatal("ath of the RFC example token")
	}
}

type harness struct {
	t   *testing.T
	v   *Verifier
	key *ecdsa.PrivateKey
	now time.Time
}

const origin = "https://api.bilyon.example"

func newHarness(t *testing.T, keys [][]byte) *harness {
	t.Helper()
	t.Parallel()
	h := &harness{t: t, now: time.Now()}
	h.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, err := NewVerifier(Config{Origins: []string{origin, "http://127.0.0.1:8080"}, NonceKeys: keys,
		Now: func() time.Time { return h.now }}, redistest.Start(t))
	if err != nil {
		t.Fatal(err)
	}
	h.v = v
	return h
}

func (h *harness) proof(method, htu string, o ProofOptions) string {
	h.t.Helper()
	if o.IssuedAt.IsZero() {
		o.IssuedAt = h.now
	}
	p, err := NewProof(h.key, method, htu, o)
	if err != nil {
		h.t.Fatal(err)
	}
	return p
}

// signed builds a proof with an arbitrary header and claims.
func (h *harness) signed(header map[string]any, claims map[string]any) string {
	h.t.Helper()
	payload, _ := json.Marshal(claims)
	tok, err := jose.SignES256(h.key, header, payload)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *harness) verify(method, path string, proofs []string, token string) (*Proof, error) {
	return h.v.Verify(ctx(h.t), Request{Method: method, Path: path, Proofs: proofs, AccessToken: token})
}

func TestVerifyRejections(t *testing.T) {
	h := newHarness(t, nil)
	jwk, _ := jose.PublicJWK(&h.key.PublicKey)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherJWK, _ := jose.PublicJWK(&other.PublicKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	claims := func() map[string]any {
		return map[string]any{"jti": "0123456789abcdef-x", "htm": "POST", "htu": origin + "/v1/intents", "iat": h.now.Unix()}
	}
	with := func(edit func(map[string]any)) map[string]any {
		c := claims()
		edit(c)
		return c
	}
	privateJWK := map[string]any{"kty": "EC", "crv": "P-256", "x": jwk.X, "y": jwk.Y, "d": "AAAA"}
	good := h.proof("POST", origin+"/v1/intents", ProofOptions{})
	type tc struct {
		proofs []string
		reason string // fragment of the refusal's description
	}
	hdr := map[string]any{"typ": "dpop+jwt", "jwk": jwk}
	dup, err := jose.SignES256(h.key, hdr, []byte(fmt.Sprintf(
		`{"jti":"0123456789abcdef-y","htm":"GET","htm":"POST","htu":%q,"iat":%d}`, origin+"/v1/intents", h.now.Unix())))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]tc{
		"no proof":           {nil, "exactly one"},
		"two proofs":         {[]string{good, good}, "exactly one"},
		"not a JWT":          {[]string{"abc"}, "segments"},
		"typ JWT":            {[]string{h.signed(map[string]any{"typ": "JWT", "jwk": jwk}, claims())}, "typ"},
		"no typ":             {[]string{h.signed(map[string]any{"jwk": jwk}, claims())}, "typ"},
		"no jwk":             {[]string{h.signed(map[string]any{"typ": "dpop+jwt"}, claims())}, "no jwk"},
		"private jwk":        {[]string{h.signed(map[string]any{"typ": "dpop+jwt", "jwk": privateJWK}, claims())}, "private key"},
		"jwk of another key": {[]string{h.signed(map[string]any{"typ": "dpop+jwt", "jwk": otherJWK}, claims())}, "signature"},
		"jwk not an object":  {[]string{h.signed(map[string]any{"typ": "dpop+jwt", "jwk": "key"}, claims())}, "jwk"},
		"short jti":          {[]string{h.signed(hdr, with(func(c map[string]any) { c["jti"] = "short" }))}, "jti"},
		"long jti":           {[]string{h.signed(hdr, with(func(c map[string]any) { c["jti"] = strings.Repeat("j", 129) }))}, "jti"},
		"htm GET":            {[]string{h.proof("GET", origin+"/v1/intents", ProofOptions{})}, "htm"},
		"lower-case htm":     {[]string{h.proof("post", origin+"/v1/intents", ProofOptions{})}, "htm"},
		"other origin":       {[]string{h.proof("POST", "https://evil.example/v1/intents", ProofOptions{})}, "does not name this server"},
		"other port":         {[]string{h.proof("POST", "https://api.bilyon.example:8443/v1/intents", ProofOptions{})}, "does not name this server"},
		"http scheme":        {[]string{h.proof("POST", "http://api.bilyon.example/v1/intents", ProofOptions{})}, "does not name this server"},
		"other path":         {[]string{h.proof("POST", origin+"/v1/intents/x", ProofOptions{})}, "request path"},
		"relative htu":       {[]string{h.proof("POST", "/v1/intents", ProofOptions{})}, "absolute"},
		"htu with userinfo":  {[]string{h.proof("POST", "https://u@api.bilyon.example/v1/intents", ProofOptions{})}, "absolute"},
		"bad percent coding": {[]string{h.proof("POST", origin+"/v1/%zz", ProofOptions{})}, "absolute"},
		"iat too old":        {[]string{h.proof("POST", origin+"/v1/intents", ProofOptions{IssuedAt: h.now.Add(-6 * time.Minute)})}, "acceptance window"},
		"iat in the future":  {[]string{h.proof("POST", origin+"/v1/intents", ProofOptions{IssuedAt: h.now.Add(6 * time.Minute)})}, "acceptance window"},
		"no iat":             {[]string{h.signed(hdr, with(func(c map[string]any) { delete(c, "iat") }))}, "iat is required"},
		"string iat":         {[]string{h.signed(hdr, with(func(c map[string]any) { c["iat"] = "now" }))}, "claims"},
		"negative iat":       {[]string{h.signed(hdr, with(func(c map[string]any) { c["iat"] = -1 }))}, "NumericDate"},
		"duplicate claim":    {[]string{dup}, "claims"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := h.verify("POST", "/v1/intents", c.proofs, "")
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeInvalidProof || !strings.Contains(e.Description, c.reason) {
				t.Fatalf("err = %v, want %s mentioning %q", err, CodeInvalidProof, c.reason)
			}
		})
	}
	if _, err := jose.SignES256(p384, nil, nil); err == nil {
		t.Fatal("P-384 signing accepted")
	}
	// A valid proof whose signature was made over other claims.
	parts := strings.Split(good, ".")
	swapped := parts[0] + "." + strings.Split(h.proof("POST", origin+"/v1/other", ProofOptions{}), ".")[1] + "." + parts[2]
	_, err = h.verify("POST", "/v1/other", []string{swapped}, "")
	refused(t, err, CodeInvalidProof)
	// An access token demands a matching ath.
	_, err = h.verify("POST", "/v1/intents", []string{h.proof("POST", origin+"/v1/intents", ProofOptions{})}, "token")
	refused(t, err, CodeInvalidProof)
	if _, err := h.verify("POST", "/v1/intents", []string{h.proof("POST", origin+"/v1/intents", ProofOptions{AccessToken: "token"})}, "token"); err != nil {
		t.Fatalf("matching ath refused: %v", err)
	}
}

func TestVerifyAcceptsEquivalentURIs(t *testing.T) {
	h := newHarness(t, nil)
	for _, c := range []struct{ htu, path string }{
		{"HTTPS://API.Bilyon.Example:443/v1/intents", "/v1/intents"},
		{origin + "/v1/intents?debug=1#frag", "/v1/intents"},
		{origin + "/v1/./x/../intents", "/v1/intents"},
		{origin + "/%7Euser/a%2fb", "/~user/a%2Fb"},
		{origin, "/"},
		{"http://127.0.0.1:8080/v1/intents", "/v1/intents"},
	} {
		if _, err := h.verify("POST", c.path, []string{h.proof("POST", c.htu, ProofOptions{})}, ""); err != nil {
			t.Errorf("htu %s for path %s: %v", c.htu, c.path, err)
		}
	}
	// Fractional NumericDates are valid.
	jwk, _ := jose.PublicJWK(&h.key.PublicKey)
	frac := h.signed(map[string]any{"typ": "dpop+jwt", "jwk": jwk}, map[string]any{"jti": "fraction-0123456789",
		"htm": "GET", "htu": origin + "/v1/me", "iat": float64(h.now.UnixMilli()) / 1000})
	if _, err := h.verify("GET", "/v1/me", []string{frac}, ""); err != nil {
		t.Fatalf("fractional iat: %v", err)
	}
}

func TestReplay(t *testing.T) {
	h := newHarness(t, nil)
	p := h.proof("POST", origin+"/v1/intents", ProofOptions{JTI: "replayed-jti-0123456"})
	if _, err := h.verify("POST", "/v1/intents", []string{p}, ""); err != nil {
		t.Fatal(err)
	}
	_, err := h.verify("POST", "/v1/intents", []string{p}, "")
	refused(t, err, CodeInvalidProof)
	// The jti is scoped to the key: another key may reuse the string.
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p2, _ := NewProof(k2, "POST", origin+"/v1/intents", ProofOptions{JTI: "replayed-jti-0123456", IssuedAt: h.now})
	if _, err := h.verify("POST", "/v1/intents", []string{p2}, ""); err != nil {
		t.Fatalf("same jti under another key: %v", err)
	}
	// A broken replay cache is an infrastructure error, not a refusal.
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = dead.Close() })
	v, err := NewVerifier(Config{Origins: []string{origin}, Now: func() time.Time { return h.now }}, dead)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(ctx(t), Request{Method: "POST", Path: "/v1/intents", Proofs: []string{h.proof("POST", origin+"/v1/intents", ProofOptions{})}})
	var e *Error
	if err == nil || errors.As(err, &e) {
		t.Fatalf("err = %v, want an infrastructure error", err)
	}
}

func TestNonces(t *testing.T) {
	k1, k2 := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(k1)
	_, _ = rand.Read(k2)
	h := newHarness(t, [][]byte{k1})
	call := func(nonce string) error {
		_, err := h.verify("GET", "/v1/me", []string{h.proof("GET", origin+"/v1/me", ProofOptions{Nonce: nonce})}, "")
		return err
	}
	refused(t, call(""), CodeUseNonce)
	n := h.v.Nonce()
	if err := call(n); err != nil {
		t.Fatalf("fresh nonce refused: %v", err)
	}
	if err := call(n); err != nil {
		t.Fatalf("a nonce may serve several proofs: %v", err)
	}
	h.now = h.now.Add(4 * time.Minute)
	if err := call(n); err != nil {
		t.Fatalf("4-minute-old nonce refused: %v", err)
	}
	h.now = h.now.Add(2 * time.Minute)
	refused(t, call(n), CodeUseNonce)

	raw, _ := jose.B64.DecodeString(h.v.Nonce())
	raw[len(raw)-1] ^= 1
	refused(t, call(jose.B64.EncodeToString(raw)), CodeUseNonce)
	refused(t, call("not-a-nonce"), CodeUseNonce)

	// Rotation: nonces from the previous key stay valid.
	old := h.v.Nonce()
	h.v.cfg.NonceKeys = [][]byte{k2, k1}
	if err := call(old); err != nil {
		t.Fatalf("nonce under the previous key refused: %v", err)
	}
	h.v.cfg.NonceKeys = [][]byte{k2}
	refused(t, call(old), CodeUseNonce)

	// A nonce from the future (a peer's clock ahead by a minute) is refused.
	future := h.v.Nonce()
	h.now = h.now.Add(-time.Minute)
	refused(t, call(future), CodeUseNonce)
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })
	for name, cfg := range map[string]Config{
		"no origins":   {},
		"path origin":  {Origins: []string{"https://a.example/api"}},
		"ftp origin":   {Origins: []string{"ftp://a.example"}},
		"query origin": {Origins: []string{"https://a.example?x"}},
		"short nonce":  {Origins: []string{"https://a.example"}, NonceKeys: [][]byte{make([]byte, 16)}},
		"userinfo":     {Origins: []string{"https://u@a.example"}},
		"bare host":    {Origins: []string{"a.example"}},
	} {
		if _, err := NewVerifier(cfg, rdb); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewVerifier(Config{Origins: []string{"https://a.example"}}, nil); err == nil {
		t.Error("missing Redis accepted")
	}
	if _, err := NewVerifier(Config{Origins: []string{"https://a.example/"}}, rdb); err != nil {
		t.Errorf("origin with a root path refused: %v", err)
	}
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()
	// RFC 3986 §5.2.4 and §6.2.2 examples.
	for in, want := range map[string]string{
		"/a/b/c/./../../g":   "/a/g",
		"mid/content=5/../6": "mid/6",
		"/./a":               "/a",
		"/a/..":              "/",
		"/a/b/":              "/a/b/",
		"/..":                "/",
		"":                   "/",
		"/%7euser":           "/~user",
		"/a%2fb":             "/a%2Fb",
		"/%41%42":            "/AB",
		"/%e2%82%ac":         "/%E2%82%AC",
	} {
		got, err := normalizePath(in)
		if err != nil || got != want {
			t.Errorf("normalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"/%", "/%4", "/%G1"} {
		if _, err := normalizePath(bad); err == nil {
			t.Errorf("normalizePath(%q) accepted", bad)
		}
	}
}
