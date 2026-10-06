// Package certs mints throwaway X.509 PKIs for mutual-TLS tests: a CA and
// leaf certificates carrying SPIFFE URI SANs, written as PEM files.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/platform/grpcx"
)

// CA is a test certificate authority.
type CA struct {
	t    testing.TB
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// CAFile is the PEM file holding the CA certificate.
	CAFile string
}

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// NewCA creates a CA in a temporary directory.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{t: t, dir: t.TempDir(), cert: cert, key: key}
	ca.CAFile = ca.write(name+"-ca.pem", "CERTIFICATE", der)
	return ca
}

func (ca *CA) write(name, typ string, der []byte) string {
	path := filepath.Join(ca.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		ca.t.Fatal(err)
	}
	return path
}

// Leaf issues a certificate for a server (DNS localhost, IP 127.0.0.1) and
// client use, identified by spiffeID (may be empty) and commonName.
func (ca *CA) Leaf(name, spiffeID, commonName string) grpcx.TLSFiles {
	ca.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ca.t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial(ca.t), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		if err != nil {
			ca.t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		ca.t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		ca.t.Fatal(err)
	}
	return grpcx.TLSFiles{
		CertFile:   ca.write(name+".pem", "CERTIFICATE", der),
		KeyFile:    ca.write(name+"-key.pem", "PRIVATE KEY", keyDER),
		CAFile:     ca.CAFile,
		ServerName: "localhost",
	}
}
