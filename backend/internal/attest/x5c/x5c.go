// Package x5c handles attestation certificate chains (the "x5c" arrays of
// WebAuthn statements, App Attest and Android key attestation): parsing,
// optional verification against trust anchors, the extensions verifiers
// read, and signature checks for the COSE algorithms attestations use.
package x5c

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // TPM 1.2-era RS1 attestations are still produced by Windows TPMs
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/google/uuid"
)

// MaxChain bounds the number of certificates in a chain.
const MaxChain = 6

// COSE algorithm identifiers that attestation signatures use.
const (
	AlgES256 = -7
	AlgES384 = -35
	AlgES512 = -36
	AlgEdDSA = -8
	AlgPS256 = -37
	AlgRS256 = -257
	AlgRS384 = -258
	AlgRS512 = -259
	AlgRS1   = -65535
)

// Extension identifiers.
var (
	OIDAAGUID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4} // id-fido-gen-ce-aaguid
	OIDAppleNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
)

// ErrChain reports an unusable certificate chain.
var ErrChain = errors.New("x5c: invalid attestation certificate chain")

// Parse decodes a chain of DER certificates, leaf first.
func Parse(raw [][]byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > MaxChain {
		return nil, fmt.Errorf("%w: %d certificates", ErrChain, len(raw))
	}
	out := make([]*x509.Certificate, len(raw))
	for i, der := range raw {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %v", ErrChain, i, err)
		}
		out[i] = c
	}
	return out, nil
}

// Verify checks that chain (leaf first, intermediates after) leads to one
// of anchors at time at. Extended key usages are not constrained:
// attestation certificates use vendor-specific ones.
func Verify(chain []*x509.Certificate, anchors *x509.CertPool, at time.Time) ([][]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty chain", ErrChain)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	chains, err := chain[0].Verify(x509.VerifyOptions{Roots: anchors, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChain, err)
	}
	return chains, nil
}

// AAGUID returns the id-fido-gen-ce-aaguid extension: present reports
// whether the certificate carries it; the extension must not be critical.
func AAGUID(cert *x509.Certificate) (id uuid.UUID, present bool, err error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDAAGUID) {
			continue
		}
		if ext.Critical {
			return uuid.Nil, true, fmt.Errorf("%w: AAGUID extension is critical", ErrChain)
		}
		var raw []byte
		rest, err := asn1.Unmarshal(ext.Value, &raw)
		if err != nil || len(rest) != 0 || len(raw) != 16 {
			return uuid.Nil, true, fmt.Errorf("%w: malformed AAGUID extension", ErrChain)
		}
		copy(id[:], raw)
		return id, true, nil
	}
	return uuid.Nil, false, nil
}

// AppleNonce returns the nonce of Apple's attestation extension
// (1.2.840.113635.100.8.2: SEQUENCE { [1] EXPLICIT OCTET STRING }).
func AppleNonce(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDAppleNonce) {
			continue
		}
		var v struct {
			Nonce []byte `asn1:"tag:1,explicit"`
		}
		rest, err := asn1.Unmarshal(ext.Value, &v)
		if err != nil || len(rest) != 0 || len(v.Nonce) == 0 {
			return nil, fmt.Errorf("%w: malformed Apple nonce extension", ErrChain)
		}
		return v.Nonce, nil
	}
	return nil, fmt.Errorf("%w: Apple nonce extension missing", ErrChain)
}

// HashFor returns the digest an algorithm signs.
func HashFor(alg int64) (crypto.Hash, error) {
	switch alg {
	case AlgES256, AlgRS256, AlgPS256:
		return crypto.SHA256, nil
	case AlgES384, AlgRS384:
		return crypto.SHA384, nil
	case AlgES512, AlgRS512:
		return crypto.SHA512, nil
	case AlgRS1:
		return crypto.SHA1, nil
	default:
		return 0, fmt.Errorf("x5c: unsupported algorithm %d", alg)
	}
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New() //nolint:gosec
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// Digest hashes data with the algorithm's hash.
func Digest(alg int64, data []byte) ([]byte, error) {
	h, err := HashFor(alg)
	if err != nil {
		return nil, err
	}
	d := newHash(h)
	d.Write(data)
	return d.Sum(nil), nil
}

// VerifySignature checks sig over data with pub under a COSE algorithm.
// ECDSA signatures are ASN.1 DER, as in every attestation format.
func VerifySignature(pub crypto.PublicKey, alg int64, data, sig []byte) error {
	if alg == AlgEdDSA {
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, data, sig) {
			return errors.New("x5c: EdDSA signature invalid")
		}
		return nil
	}
	h, err := HashFor(alg)
	if err != nil {
		return err
	}
	digest, _ := Digest(alg, data)
	switch alg {
	case AlgES256, AlgES384, AlgES512:
		k, ok := pub.(*ecdsa.PublicKey)
		want := map[int64]elliptic.Curve{AlgES256: elliptic.P256(), AlgES384: elliptic.P384(), AlgES512: elliptic.P521()}[alg]
		if !ok || k.Curve != want {
			return fmt.Errorf("x5c: algorithm %d needs a matching ECDSA key, got %T", alg, pub)
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("x5c: ECDSA signature invalid")
		}
	case AlgPS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("x5c: PS256 needs an RSA key, got %T", pub)
		}
		if err := rsa.VerifyPSS(k, h, digest, sig, nil); err != nil {
			return errors.New("x5c: RSA-PSS signature invalid")
		}
	default: // RS*
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("x5c: algorithm %d needs an RSA key, got %T", alg, pub)
		}
		if err := rsa.VerifyPKCS1v15(k, h, digest, sig); err != nil {
			return errors.New("x5c: RSA signature invalid")
		}
	}
	return nil
}

// SamePublicKey reports whether two public keys are equal.
func SamePublicKey(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}
