package x5c

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestVerifySignatureAcrossAlgorithms(t *testing.T) {
	data := []byte("attestation to be signed")
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	sign := func(alg int64) []byte {
		h, _ := HashFor(alg)
		d, _ := Digest(alg, data)
		var sig []byte
		switch alg {
		case AlgES256:
			sig, _ = ecdsa.SignASN1(rand.Reader, ec256, d)
		case AlgES384:
			sig, _ = ecdsa.SignASN1(rand.Reader, ec384, d)
		case AlgPS256:
			sig, _ = rsa.SignPSS(rand.Reader, rk, h, d, nil)
		default:
			sig, _ = rsa.SignPKCS1v15(rand.Reader, rk, h, d)
		}
		return sig
	}
	cases := []struct {
		alg int64
		pub crypto.PublicKey
	}{
		{AlgES256, &ec256.PublicKey}, {AlgES384, &ec384.PublicKey}, {AlgRS256, &rk.PublicKey}, {AlgRS384, &rk.PublicKey},
		{AlgRS512, &rk.PublicKey}, {AlgRS1, &rk.PublicKey}, {AlgPS256, &rk.PublicKey},
	}
	for _, c := range cases {
		sig := sign(c.alg)
		if err := VerifySignature(c.pub, c.alg, data, sig); err != nil {
			t.Errorf("alg %d: %v", c.alg, err)
		}
		if err := VerifySignature(c.pub, c.alg, append(data, '!'), sig); err == nil {
			t.Errorf("alg %d accepted a tampered message", c.alg)
		}
	}
	if err := VerifySignature(edPub, AlgEdDSA, data, ed25519.Sign(edPriv, data)); err != nil {
		t.Fatalf("EdDSA: %v", err)
	}
	if err := VerifySignature(&ec384.PublicKey, AlgES256, data, sign(AlgES384)); err == nil {
		t.Fatal("curve mismatch accepted")
	}
	if err := VerifySignature(&ec256.PublicKey, AlgRS256, data, sign(AlgRS256)); err == nil {
		t.Fatal("key type mismatch accepted")
	}
	if _, err := HashFor(-999); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
	if !SamePublicKey(&ec256.PublicKey, &ec256.PublicKey) || SamePublicKey(&ec256.PublicKey, &ec384.PublicKey) {
		t.Fatal("SamePublicKey")
	}
}

func cert(t *testing.T, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtraExtensions: exts, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(raw)
	return c
}

func TestExtensionsAndChains(t *testing.T) {
	id := uuid.New()
	val, _ := asn1.Marshal(id[:])
	c := cert(t, []pkix.Extension{{Id: OIDAAGUID, Value: val}})
	if got, present, err := AAGUID(c); err != nil || !present || got != id {
		t.Fatalf("AAGUID %v %v %v", got, present, err)
	}
	if _, present, err := AAGUID(cert(t, nil)); present || err != nil {
		t.Fatal("absent AAGUID")
	}
	if _, _, err := AAGUID(cert(t, []pkix.Extension{{Id: OIDAAGUID, Value: val, Critical: true}})); !errors.Is(err, ErrChain) {
		t.Fatalf("critical AAGUID: %v", err)
	}
	short, _ := asn1.Marshal([]byte{1, 2})
	if _, _, err := AAGUID(cert(t, []pkix.Extension{{Id: OIDAAGUID, Value: short}})); !errors.Is(err, ErrChain) {
		t.Fatalf("short AAGUID: %v", err)
	}
	nonce, _ := asn1.Marshal(struct {
		N []byte `asn1:"tag:1,explicit"`
	}{[]byte("nonce")})
	if got, err := AppleNonce(cert(t, []pkix.Extension{{Id: OIDAppleNonce, Value: nonce}})); err != nil || string(got) != "nonce" {
		t.Fatalf("apple nonce %q %v", got, err)
	}
	if _, err := AppleNonce(cert(t, []pkix.Extension{{Id: OIDAppleNonce, Value: []byte{0x30, 0x00}}})); !errors.Is(err, ErrChain) {
		t.Fatalf("empty nonce: %v", err)
	}
	if _, err := AppleNonce(cert(t, nil)); !errors.Is(err, ErrChain) {
		t.Fatal("missing nonce")
	}
	root := cert(t, nil)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := Verify([]*x509.Certificate{root}, pool, time.Now()); err != nil {
		t.Fatalf("self-signed anchor: %v", err)
	}
	if _, err := Verify([]*x509.Certificate{root}, x509.NewCertPool(), time.Now()); !errors.Is(err, ErrChain) {
		t.Fatal("unanchored chain verified")
	}
	if _, err := Verify(nil, pool, time.Now()); !errors.Is(err, ErrChain) {
		t.Fatal("empty chain")
	}
	if _, err := Parse(nil); !errors.Is(err, ErrChain) {
		t.Fatal("no certificates")
	}
	if _, err := Parse([][]byte{{1, 2, 3}}); !errors.Is(err, ErrChain) {
		t.Fatal("garbage certificate")
	}
}
