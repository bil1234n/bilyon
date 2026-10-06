// Package cose implements the COSE (RFC 9052/9053) profile used by Bilyon
// (RFC 0001 §2.1.1):
//
//   - COSE_Sign1 (tag 18) with ES256 only. The protected header is exactly
//     {1: -7} (bytes A1 01 26) and verifiers compare bytes instead of parsing
//     it, which rules out algorithm confusion. The unprotected header may
//     carry only kid (label 4).
//   - Signatures are raw r‖s (64 bytes) normalised to low-S; verifiers reject
//     s > n/2, so every payload has exactly one valid signature encoding.
//   - Every artefact type signs with its own external AAD ("bilyon/ost/v1",
//     "bilyon/txauth/v1", ...): a signature made for one type cannot verify
//     as another.
//
// It also provides tagged hashes and SEC1 point encodings, and parses the
// COSE keys WebAuthn authenticators return (key.go).
package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
)

// COSE identifiers used by Bilyon.
const (
	TagSign1  = 18
	AlgES256  = -7
	AlgRS256  = -257
	headerAlg = 1
	headerKID = 4
	// MaxKIDLen bounds key identifiers.
	MaxKIDLen = 64
)

// protectedES256 is the deterministic encoding of {1: -7}.
var protectedES256 = []byte{0xa1, 0x01, 0x26}

// Errors returned by verification.
var (
	ErrMalformed  = errors.New("cose: malformed COSE_Sign1")
	ErrSignature  = errors.New("cose: signature verification failed")
	ErrUnknownKey = errors.New("cose: unknown signing key")
)

var (
	curveN     = elliptic.P256().Params().N
	halfCurveN = new(big.Int).Rsh(curveN, 1)
)

// Signer signs SHA-256 digests with a P-256 key. Production signers wrap an
// HSM or KMS key; implementations must return a raw r‖s signature.
type Signer interface {
	Public() *ecdsa.PublicKey
	SignDigest(digest []byte) ([]byte, error)
}

// KeySigner is a Signer over an in-memory key: development, tests, and keys
// unwrapped from a KMS envelope at start-up.
type KeySigner struct{ priv *ecdsa.PrivateKey }

// NewKeySigner wraps a P-256 private key.
func NewKeySigner(priv *ecdsa.PrivateKey) (*KeySigner, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errors.New("cose: signer key must be P-256")
	}
	return &KeySigner{priv: priv}, nil
}

// GenerateKeySigner creates a signer with a fresh P-256 key.
func GenerateKeySigner() (*KeySigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeySigner{priv: priv}, nil
}

// Public implements Signer.
func (s *KeySigner) Public() *ecdsa.PublicKey { return &s.priv.PublicKey }

// PrivateKey exposes the key for PEM export by key-management tooling.
func (s *KeySigner) PrivateKey() *ecdsa.PrivateKey { return s.priv }

// SignDigest implements Signer with low-S normalisation.
func (s *KeySigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("cose: digest of %d bytes", len(digest))
	}
	r, sv, err := ecdsa.Sign(rand.Reader, s.priv, digest)
	if err != nil {
		return nil, err
	}
	return RawSignature(r, sv), nil
}

// RawSignature encodes (r, s) as 64-byte r‖s, replacing s by n−s when s is
// in the upper half (the only other valid signature for the same message).
func RawSignature(r, s *big.Int) []byte {
	if s.Cmp(halfCurveN) > 0 {
		s = new(big.Int).Sub(curveN, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

// VerifyRaw checks a raw low-S r‖s signature over a SHA-256 digest.
func VerifyRaw(pub *ecdsa.PublicKey, digest, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("%w: signature of %d bytes", ErrSignature, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if s.Cmp(halfCurveN) > 0 {
		return fmt.Errorf("%w: high-S signature", ErrSignature)
	}
	if !ecdsa.Verify(pub, digest, r, s) {
		return ErrSignature
	}
	return nil
}

// sigStructure is the Sig_structure digest (RFC 9052 §4.4).
func sigStructure(payload []byte, aad string) []byte {
	tbs := cbor.MustEncode([]any{"Signature1", protectedES256, []byte(aad), payload})
	d := sha256.Sum256(tbs)
	return d[:]
}

// Sign1 returns a tagged COSE_Sign1 over payload. kid, when non-empty, goes
// into the unprotected header.
func Sign1(s Signer, kid, payload []byte, aad string) ([]byte, error) {
	if len(kid) > MaxKIDLen {
		return nil, fmt.Errorf("cose: kid of %d bytes", len(kid))
	}
	sig, err := s.SignDigest(sigStructure(payload, aad))
	if err != nil {
		return nil, fmt.Errorf("cose: sign: %w", err)
	}
	unprotected := cbor.Map{}
	if len(kid) > 0 {
		unprotected[int64(headerKID)] = kid
	}
	return cbor.Encode(cbor.Tag{Number: TagSign1, Content: []any{protectedES256, unprotected, payload, sig}})
}

// Sign1Message is a parsed COSE_Sign1 whose signature has not been checked.
type Sign1Message struct {
	KID       []byte
	Payload   []byte
	signature []byte
}

// Parse1 decodes a COSE_Sign1 structurally. Nothing in it is authentic until
// Verify succeeds; Parse1 exists for messages whose key is identified by
// their content (e.g. coin keys authenticated by a Merkle proof).
func Parse1(raw []byte) (*Sign1Message, error) {
	v, err := cbor.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != TagSign1 {
		return nil, fmt.Errorf("%w: not tag 18", ErrMalformed)
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, fmt.Errorf("%w: not a 4-element array", ErrMalformed)
	}
	prot, ok1 := arr[0].([]byte)
	unprot, ok2 := arr[1].(cbor.Map)
	payload, ok3 := arr[2].([]byte)
	sig, ok4 := arr[3].([]byte)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, fmt.Errorf("%w: wrong element types", ErrMalformed)
	}
	if string(prot) != string(protectedES256) {
		return nil, fmt.Errorf("%w: protected header is not exactly {1: -7}", ErrMalformed)
	}
	m := &Sign1Message{Payload: payload, signature: sig}
	f := unprot.Fields()
	f.Optional(int64(headerKID), func() { m.KID = f.BytesMax(int64(headerKID), MaxKIDLen) })
	if err := f.Done(); err != nil {
		return nil, fmt.Errorf("%w: unprotected header: %v", ErrMalformed, err)
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("%w: signature of %d bytes", ErrMalformed, len(sig))
	}
	return m, nil
}

// Verify checks the message's signature with pub under aad.
func (m *Sign1Message) Verify(pub *ecdsa.PublicKey, aad string) error {
	return VerifyRaw(pub, sigStructure(m.Payload, aad), m.signature)
}

// KeyResolver returns the public key for a kid (empty when absent).
type KeyResolver func(kid []byte) (*ecdsa.PublicKey, error)

// Verify1 parses and verifies a COSE_Sign1 and returns its payload and kid.
func Verify1(raw []byte, aad string, keys KeyResolver) (payload, kid []byte, err error) {
	m, err := Parse1(raw)
	if err != nil {
		return nil, nil, err
	}
	pub, err := keys(m.KID)
	if err != nil {
		return nil, nil, err
	}
	if err := m.Verify(pub, aad); err != nil {
		return nil, nil, err
	}
	return m.Payload, m.KID, nil
}

// TaggedHash is H(label, parts…) = SHA-256(label ‖ 0x00 ‖ parts…), the
// domain-separated hash of RFC 0001 §2.1.1.
func TaggedHash(label string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// CompressP256 returns the 33-byte SEC1 compressed encoding of pub.
func CompressP256(pub *ecdsa.PublicKey) ([]byte, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	if len(raw) != 65 || pub.Curve != elliptic.P256() {
		return nil, errors.New("cose: not a P-256 key")
	}
	out := make([]byte, 33)
	out[0] = 0x02 | raw[64]&1
	copy(out[1:], raw[1:33])
	return out, nil
}

// ParseP256 accepts a 33-byte compressed or 65-byte uncompressed SEC1
// point and rejects points not on the curve.
func ParseP256(b []byte) (*ecdsa.PublicKey, error) {
	switch len(b) {
	case 65:
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
	case 33:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
		if x == nil {
			return nil, errors.New("cose: invalid compressed P-256 point")
		}
		raw := make([]byte, 65)
		raw[0] = 4
		x.FillBytes(raw[1:33])
		y.FillBytes(raw[33:])
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	default:
		return nil, fmt.Errorf("cose: P-256 point of %d bytes", len(b))
	}
}
