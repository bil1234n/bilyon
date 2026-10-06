package grpcx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseACLAndAllows(t *testing.T) {
	acl, err := ParseACL(" spiffe://bilyon/gateway = * ; spiffe://bilyon/support=GetAccount, GetBalance ;")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id, method string
		want       bool
	}{
		{"spiffe://bilyon/gateway", "/bilyon.ledger.v1.LedgerService/Transfer", true},
		{"spiffe://bilyon/support", "/bilyon.ledger.v1.LedgerService/GetBalance", true},
		{"spiffe://bilyon/support", "/bilyon.ledger.v1.LedgerService/Transfer", false},
		{"spiffe://bilyon/unknown", "/bilyon.ledger.v1.LedgerService/GetBalance", false},
	}
	for _, c := range cases {
		if got := acl.Allows(c.id, c.method); got != c.want {
			t.Errorf("%s -> %s: %v", c.id, c.method, got)
		}
	}
	for _, bad := range []string{"no-equals", "=Transfer", "spiffe://x=", "spiffe://x= , "} {
		if _, err := ParseACL(bad); err == nil {
			t.Errorf("ACL %q accepted", bad)
		}
	}
	if acl, err := ParseACL(""); err != nil || len(acl) != 0 {
		t.Fatalf("empty ACL: %v %v", acl, err)
	}
}

// writeSelfSigned writes a self-signed certificate and key to the paths.
func writeSelfSigned(t *testing.T, certPath, keyPath, cn string, mod time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
}

func commonName(t *testing.T, kp *keyPair) string {
	t.Helper()
	c, err := kp.get()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestKeyPairReloadsRotatedCertificates(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	base := time.Now().Add(-time.Hour)
	writeSelfSigned(t, certPath, keyPath, "first", base)
	kp, err := newKeyPair(TLSFiles{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	kp.interval = 0
	if got := commonName(t, kp); got != "first" {
		t.Fatalf("initial certificate %q", got)
	}
	writeSelfSigned(t, certPath, keyPath, "second", base.Add(time.Minute))
	if got := commonName(t, kp); got != "second" {
		t.Fatalf("after rotation %q", got)
	}
	// A broken rotation (key missing) keeps serving the last good pair.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if got := commonName(t, kp); got != "second" {
		t.Fatalf("after a broken rotation %q", got)
	}
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := commonName(t, kp); got != "second" {
		t.Fatalf("after a half-written rotation %q", got)
	}
	if _, err := newKeyPair(TLSFiles{CertFile: certPath, KeyFile: keyPath}); err == nil {
		t.Fatal("a missing key pair was accepted at start-up")
	}
	if _, err := loadPool(certPath); err == nil {
		t.Fatal("a CA file without certificates was accepted")
	}
}
