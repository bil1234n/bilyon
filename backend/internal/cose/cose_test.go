package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"pgregory.net/rapid"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9052 Appendix C.2.1: a COSE_Sign1 with ES256 by the example key "11".
func TestRFC9052Sign1Vector(t *testing.T) {
	raw := unhex(t, "d28443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e4ca31d1c465ab05aac"+
		"34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36")
	pub, err := ParseP256(append(append([]byte{4},
		unhex(t, "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")...),
		unhex(t, "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")...))
	if err != nil {
		t.Fatal(err)
	}
	keys := func(kid []byte) (*ecdsa.PublicKey, error) {
		if string(kid) != "11" {
			return nil, ErrUnknownKey
		}
		return pub, nil
	}
	payload, kid, err := Verify1(raw, "", keys)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "This is the content." || string(kid) != "11" {
		t.Fatalf("payload %q kid %q", payload, kid)
	}
	if _, _, err := Verify1(raw, "bilyon/ost/v1", keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("verified under another external AAD: %v", err)
	}
}

func TestSign1RoundTripAndDomainSeparation(t *testing.T) {
	s, err := GenerateKeySigner()
	if err != nil {
		t.Fatal(err)
	}
	keys := func([]byte) (*ecdsa.PublicKey, error) { return s.Public(), nil }
	rapid.Check(t, func(t *rapid.T) {
		payload := rapid.SliceOfN(rapid.Byte(), 0, 300).Draw(t, "payload")
		kid := rapid.SliceOfN(rapid.Byte(), 0, MaxKIDLen).Draw(t, "kid")
		aad := rapid.SampledFrom([]string{"bilyon/oac/v1", "bilyon/ost/v1", "bilyon/txauth/v1"}).Draw(t, "aad")
		raw, err := Sign1(s, kid, payload, aad)
		if err != nil {
			t.Fatal(err)
		}
		got, gotKID, err := Verify1(raw, aad, keys)
		if err != nil || !bytes.Equal(got, payload) || !bytes.Equal(gotKID, kid) {
			t.Fatalf("round trip: %v", err)
		}
		other := aad + "x"
		if _, _, err := Verify1(raw, other, keys); !errors.Is(err, ErrSignature) {
			t.Fatalf("signature verified under %q", other)
		}
		m, err := Parse1(raw)
		if err != nil {
			t.Fatal(err)
		}
		if s := new(big.Int).SetBytes(m.signature[32:]); s.Cmp(halfCurveN) > 0 {
			t.Fatal("signer produced a high-S signature")
		}
	})
}

// resign rebuilds a COSE_Sign1 from parts without any validation.
func resign(t *testing.T, prot []byte, unprot cbor.Map, payload, sig []byte, tag uint64) []byte {
	t.Helper()
	return cbor.MustEncode(cbor.Tag{Number: tag, Content: []any{prot, unprot, payload, sig}})
}

func TestVerify1RejectsMalformedAndMalleatedMessages(t *testing.T) {
	s, _ := GenerateKeySigner()
	keys := func([]byte) (*ecdsa.PublicKey, error) { return s.Public(), nil }
	raw, err := Sign1(s, []byte("k1"), []byte("payload"), "bilyon/test/v1")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse1(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := m.signature
	highS := bytes.Clone(sig)
	sv := new(big.Int).SetBytes(sig[32:])
	new(big.Int).Sub(curveN, sv).FillBytes(highS[32:])
	if !ecdsa.Verify(s.Public(), sigStructure(m.Payload, "bilyon/test/v1"), new(big.Int).SetBytes(sig[:32]),
		new(big.Int).SetBytes(highS[32:])) {
		t.Fatal("the high-S twin must be a mathematically valid signature")
	}
	kid := cbor.Map{int64(headerKID): []byte("k1")}
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"high-S twin", resign(t, protectedES256, kid, m.Payload, highS, TagSign1), ErrSignature},
		{"tampered payload", resign(t, protectedES256, kid, []byte("payloaD"), sig, TagSign1), ErrSignature},
		{"other algorithm", resign(t, cbor.MustEncode(cbor.Map{int64(1): int64(-35)}), kid, m.Payload, sig, TagSign1), ErrMalformed},
		{"empty protected header", resign(t, []byte{}, kid, m.Payload, sig, TagSign1), ErrMalformed},
		{"extra unprotected header", resign(t, protectedES256, cbor.Map{int64(headerKID): []byte("k1"), int64(1): int64(-7)}, m.Payload, sig, TagSign1), ErrMalformed},
		{"kid not bytes", resign(t, protectedES256, cbor.Map{int64(headerKID): "k1"}, m.Payload, sig, TagSign1), ErrMalformed},
		{"short signature", resign(t, protectedES256, kid, m.Payload, sig[:63], TagSign1), ErrMalformed},
		{"wrong tag", resign(t, protectedES256, kid, m.Payload, sig, 98), ErrMalformed},
		{"untagged", cbor.MustEncode([]any{protectedES256, kid, m.Payload, sig}), ErrMalformed},
		{"non-canonical CBOR", append(bytes.Clone(raw), 0x00), ErrMalformed},
	}
	for _, c := range cases {
		if _, _, err := Verify1(c.raw, "bilyon/test/v1", keys); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	if _, _, err := Verify1(raw, "bilyon/test/v1", func([]byte) (*ecdsa.PublicKey, error) { return nil, ErrUnknownKey }); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("resolver error not propagated: %v", err)
	}
	if _, err := Sign1(s, make([]byte, MaxKIDLen+1), nil, "x"); err == nil {
		t.Fatal("oversized kid accepted")
	}
}

func TestTaggedHashAndPointEncodings(t *testing.T) {
	want := sha256.Sum256([]byte("bilyon/tid/v1\x00abcdef"))
	if got := TaggedHash("bilyon/tid/v1", []byte("abc"), []byte("def")); got != want {
		t.Fatal("tagged hash")
	}
	if TaggedHash("a", []byte("b")) == TaggedHash("ab") {
		t.Fatal("label and data must be separated")
	}
	rapid.Check(t, func(t *rapid.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c, err := CompressP256(&priv.PublicKey)
		if err != nil || len(c) != 33 {
			t.Fatalf("compress: %v", err)
		}
		back, err := ParseP256(c)
		if err != nil || !back.Equal(&priv.PublicKey) {
			t.Fatalf("decompress: %v", err)
		}
	})
	bad := make([]byte, 33)
	bad[0] = 0x02
	for i := range bad[1:] {
		bad[i+1] = 0xff // x >= p
	}
	for _, b := range [][]byte{bad, make([]byte, 65), make([]byte, 32)} {
		if _, err := ParseP256(b); err == nil {
			t.Errorf("invalid point %x accepted", b[:4])
		}
	}
}

func TestCOSEKeys(t *testing.T) {
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec := &Key{Alg: AlgES256, Public: &ecPriv.PublicKey}
	raw, err := ec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKey(raw)
	if err != nil || !parsed.Equal(ec) {
		t.Fatalf("EC2 round trip: %v", err)
	}
	msg := []byte("authenticatorData||clientDataHash")
	d := sha256.Sum256(msg)
	der, _ := ecdsa.SignASN1(rand.Reader, ecPriv, d[:])
	if err := parsed.VerifySignature(msg, der); err != nil {
		t.Fatalf("ES256 DER signature: %v", err)
	}
	if err := parsed.VerifySignature(append(msg, '!'), der); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered ES256: %v", err)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rk := &Key{Alg: AlgRS256, Public: &rsaPriv.PublicKey}
	rraw, _ := rk.Encode()
	rparsed, err := ParseKey(rraw)
	if err != nil || !rparsed.Equal(rk) {
		t.Fatalf("RSA round trip: %v", err)
	}
	rsig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, d[:])
	if err := rparsed.VerifySignature(msg, rsig); err != nil {
		t.Fatalf("RS256: %v", err)
	}
	if rparsed.Equal(parsed) {
		t.Fatal("different keys compared equal")
	}

	ecRaw, _ := ecPriv.PublicKey.Bytes()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	bad := []cbor.Map{
		{int64(1): int64(2), int64(3): int64(-8), int64(-1): int64(1), int64(-2): ecRaw[1:33], int64(-3): ecRaw[33:]},  // EdDSA alg on EC2
		{int64(1): int64(2), int64(3): int64(-7), int64(-1): int64(2), int64(-2): ecRaw[1:33], int64(-3): ecRaw[33:]},  // P-384 curve id
		{int64(1): int64(2), int64(3): int64(-7), int64(-1): int64(1), int64(-2): ecRaw[1:33], int64(-3): ecRaw[1:33]}, // not on curve
		{int64(1): int64(2), int64(3): int64(-7), int64(-1): int64(1), int64(-2): ecRaw[1:32], int64(-3): ecRaw[33:]},  // short x
		{int64(1): int64(3), int64(3): int64(-257), int64(-1): small.N.Bytes(), int64(-2): []byte{1, 0, 1}},            // 1024-bit RSA
		{int64(1): int64(3), int64(3): int64(-257), int64(-1): rsaPriv.N.Bytes(), int64(-2): []byte{2}},                // even exponent
		{int64(1): int64(3), int64(3): int64(-257), int64(-1): append([]byte{0}, rsaPriv.N.Bytes()...), int64(-2): []byte{1, 0, 1}},
		{int64(3): int64(-7)}, // no kty
	}
	for i, m := range bad {
		if _, err := ParseKeyMap(m); !errors.Is(err, ErrKey) {
			t.Errorf("bad key %d accepted: %v", i, err)
		}
	}
	if _, err := ParseKey([]byte{0x01}); !errors.Is(err, ErrKey) {
		t.Fatal("non-map key accepted")
	}
}
