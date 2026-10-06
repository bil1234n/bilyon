package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"

	"github.com/bil1234n/bilyon/backend/internal/jose"
)

// KeySet holds the access-token signing key and every public key tokens
// may be verified with: the signing key's and those of retired keys whose
// tokens may still be live. Key ids are RFC 7638 thumbprints, so gateways
// and the realtime service agree on them without configuration.
//
// Rotation: deploy the new key as a previous (verification) key
// everywhere, then promote it to signing; drop the old key once
// AccessTTL has passed.
type KeySet struct {
	signer *ecdsa.PrivateKey
	kid    string
	keys   map[string]*ecdsa.PublicKey
	jwks   []byte
}

// NewKeySet builds a key set from P-256 keys.
func NewKeySet(signer *ecdsa.PrivateKey, previous ...*ecdsa.PublicKey) (*KeySet, error) {
	if signer == nil || signer.Curve != elliptic.P256() {
		return nil, errors.New("session: the signing key must be P-256")
	}
	ks := &KeySet{signer: signer, keys: map[string]*ecdsa.PublicKey{}}
	var jwks []jose.JWK
	for i, pub := range append([]*ecdsa.PublicKey{&signer.PublicKey}, previous...) {
		jwk, err := jose.PublicJWK(pub)
		if err != nil {
			return nil, fmt.Errorf("session: key %d: %w", i, err)
		}
		kid, err := jwk.Thumbprint()
		if err != nil {
			return nil, err
		}
		if i == 0 {
			ks.kid = kid
		}
		if _, dup := ks.keys[kid]; dup {
			continue
		}
		ks.keys[kid] = pub
		jwk.Kid, jwk.Use, jwk.Alg = kid, "sig", "ES256"
		jwks = append(jwks, jwk)
	}
	sort.Slice(jwks[1:], func(a, b int) bool { return jwks[1+a].Kid < jwks[1+b].Kid })
	raw, err := json.Marshal(map[string]any{"keys": jwks})
	if err != nil {
		return nil, err
	}
	ks.jwks = raw
	return ks, nil
}

// ParsePrivateKeyPEM decodes a PKCS #8 ("PRIVATE KEY") or SEC 1 ("EC
// PRIVATE KEY") P-256 private key.
func ParsePrivateKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("session: no PEM block")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("session: PEM block %q is not a private key", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("session: the private key is not P-256")
	}
	return ec, nil
}

// ParsePublicKeyPEM decodes a PKIX ("PUBLIC KEY") P-256 public key.
func ParsePublicKeyPEM(b []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("session: no PUBLIC KEY PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("session: the public key is not P-256")
	}
	return ec, nil
}

// LoadKeySet reads the signing key and previous public keys from PEM files.
func LoadKeySet(signerFile string, previousFiles ...string) (*KeySet, error) {
	raw, err := os.ReadFile(signerFile)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	signer, err := ParsePrivateKeyPEM(raw)
	if err != nil {
		return nil, err
	}
	previous := make([]*ecdsa.PublicKey, 0, len(previousFiles))
	for _, f := range previousFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
		pub, err := ParsePublicKeyPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("session: %s: %w", f, err)
		}
		previous = append(previous, pub)
	}
	return NewKeySet(signer, previous...)
}

// KeyID is the signing key's id.
func (k *KeySet) KeyID() string { return k.kid }

// JWKS returns the JSON Web Key Set of the verification keys (RFC 7517
// §5), signing key first.
func (k *KeySet) JWKS() []byte { return append([]byte{}, k.jwks...) }

// ServeHTTP serves the JWKS (e.g. at /.well-known/jwks.json).
func (k *KeySet) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(k.jwks)
}
