package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// RFC 9449 §4.1 (Figure 3) and §6.1: the example proof key, its thumbprint
// and the token-request proof.
const (
	rfcX     = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"
	rfcY     = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
	rfcJKT   = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	rfcProof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
)

func TestRFC9449Vectors(t *testing.T) {
	k := JWK{Kty: "EC", Crv: "P-256", X: rfcX, Y: rfcY}
	jkt, err := k.Thumbprint()
	if err != nil || jkt != rfcJKT {
		t.Fatalf("thumbprint = %q, %v; want %q", jkt, err, rfcJKT)
	}
	j, err := Parse(rfcProof)
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct {
		Typ string `json:"typ"`
		JWK JWK    `json:"jwk"`
	}
	raw, _ := json.Marshal(j.Header)
	if err := json.Unmarshal(raw, &hdr); err != nil || hdr.Typ != "dpop+jwt" {
		t.Fatalf("header %s: %v", raw, err)
	}
	pub, err := hdr.JWK.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := j.VerifyES256(pub); err != nil {
		t.Fatalf("RFC 9449 proof does not verify: %v", err)
	}
	if got, _ := Thumbprint(pub); got != rfcJKT {
		t.Fatalf("Thumbprint(pub) = %s", got)
	}
	var claims struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
	}
	if err := DecodeStrict(j.Payload, &claims); err != nil || claims.HTU != "https://server.example.com/token" || claims.IAT != 1562262616 {
		t.Fatalf("claims %+v: %v", claims, err)
	}
	// Any change to the signed bytes breaks the signature.
	parts := strings.Split(rfcProof, ".")
	tampered, _ := Parse(parts[0] + "." + B64.EncodeToString([]byte(`{"jti":"-BwC3ESc6acc2lTc","htm":"GET","htu":"https://server.example.com/token","iat":1562262616}`)) + "." + parts[2])
	if err := tampered.VerifyES256(pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered payload: %v", err)
	}
}

func TestJWKValidation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, err := PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	back, err := k.PublicKey()
	if err != nil || !back.Equal(&key.PublicKey) {
		t.Fatalf("round trip: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := PublicJWK(&p384.PublicKey); !errors.Is(err, ErrKey) {
		t.Fatalf("P-384 accepted: %v", err)
	}
	offCurve := k
	y, _ := B64.DecodeString(k.Y)
	y[31] ^= 1
	offCurve.Y = B64.EncodeToString(y)
	bad := map[string]JWK{
		"RSA":             {Kty: "RSA", Crv: "P-256", X: k.X, Y: k.Y},
		"P-384":           {Kty: "EC", Crv: "P-384", X: k.X, Y: k.Y},
		"short x":         {Kty: "EC", Crv: "P-256", X: k.X[:40], Y: k.Y},
		"padded y":        {Kty: "EC", Crv: "P-256", X: k.X, Y: k.Y + "="},
		"point off curve": offCurve,
	}
	for name, jwk := range bad {
		if _, err := jwk.PublicKey(); !errors.Is(err, ErrKey) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
		if _, err := jwk.Thumbprint(); err == nil {
			t.Errorf("%s: thumbprint computed", name)
		}
	}
}

func TestStrictObject(t *testing.T) {
	good := `{"a":1,"b":{"c":[{"d":1},{"d":2}]}}`
	if _, err := StrictObject([]byte(good)); err != nil {
		t.Fatalf("valid object rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"duplicate member":       `{"a":1,"a":2}`,
		"nested duplicate":       `{"a":{"b":1,"b":1}}`,
		"duplicate inside array": `{"a":[{"b":1,"b":2}]}`,
		"array":                  `[1,2]`,
		"string":                 `"x"`,
		"trailing data":          `{"a":1}{"b":2}`,
		"truncated":              `{"a":`,
		"empty":                  ``,
	} {
		if _, err := StrictObject([]byte(raw)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
	if _, err := StrictObject([]byte(deep)); !errors.Is(err, ErrMalformed) {
		t.Errorf("deep nesting: err = %v", err)
	}
}

func TestParseRejections(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok, err := SignES256(key, map[string]any{"typ": "JWT"}, []byte(`{"sub":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	enc := func(s string) string { return B64.EncodeToString([]byte(s)) }
	cases := map[string]string{
		"two segments":         parts[0] + "." + parts[1],
		"four segments":        tok + ".x",
		"padded header":        parts[0] + "=." + parts[1] + "." + parts[2],
		"standard alphabet":    parts[0] + "." + parts[1] + ".+" + parts[2][1:],
		"duplicate header alg": enc(`{"alg":"ES256","alg":"none"}`) + "." + parts[1] + "." + parts[2],
		"critical parameter":   enc(`{"alg":"ES256","crit":["exp"],"exp":1}`) + "." + parts[1] + "." + parts[2],
		"missing alg":          enc(`{"typ":"JWT"}`) + "." + parts[1] + "." + parts[2],
		"numeric alg":          enc(`{"alg":7}`) + "." + parts[1] + "." + parts[2],
		"header not an object": enc(`["ES256"]`) + "." + parts[1] + "." + parts[2],
		"oversized":            strings.Repeat("a", MaxCompactSize+1),
		"bad payload encoding": parts[0] + ".!!!." + parts[2],
		"bad signature coding": parts[0] + "." + parts[1] + ".***",
	}
	for name, c := range cases {
		if _, err := Parse(c); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Non-canonical base64: flip the unused low bits of the last character.
	sig := []byte(parts[2])
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", sig[len(sig)-1])
	sig[len(sig)-1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last^1]
	if _, err := Parse(parts[0] + "." + parts[1] + "." + string(sig)); !errors.Is(err, ErrMalformed) {
		t.Errorf("non-canonical base64 accepted: %v", err)
	}
}

func TestSignVerify(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok, err := SignES256(key, map[string]any{"alg": "none", "kid": "k1"}, []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	j, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if j.Alg() != "ES256" {
		t.Fatalf("alg %q: SignES256 must force ES256", j.Alg())
	}
	if kid, ok, _ := j.HeaderString("kid"); !ok || kid != "k1" {
		t.Fatalf("kid %q", kid)
	}
	if err := j.VerifyES256(&key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := j.VerifyES256(&other.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := j.VerifyES256(&p384.PublicKey); !errors.Is(err, ErrKey) {
		t.Fatalf("P-384 key: %v", err)
	}
	if _, err := SignES256(p384, nil, nil); !errors.Is(err, ErrKey) {
		t.Fatalf("signing with P-384: %v", err)
	}
	parts := strings.Split(tok, ".")
	hs, _ := Parse(B64.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + parts[1] + "." + parts[2])
	if err := hs.VerifyES256(&key.PublicKey); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("HS256: %v", err)
	}
	none, _ := Parse(B64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + ".")
	if err := none.VerifyES256(&key.PublicKey); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("none: %v", err)
	}
	sig, _ := B64.DecodeString(parts[2])
	for _, s := range [][]byte{sig[:63], append(sig, 0)} {
		bad, _ := Parse(parts[0] + "." + parts[1] + "." + B64.EncodeToString(s))
		if err := bad.VerifyES256(&key.PublicKey); !errors.Is(err, ErrSignature) {
			t.Fatalf("%d-byte signature: %v", len(s), err)
		}
	}
}
