package offline

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/bil1234n/bilyon/reference/internal/cbor"
)

// Signer abstracts a hardware-resident P-256 key. In production the private
// half never leaves the Secure Enclave (iOS) or StrongBox/TEE (Android) and
// every Sign call is gated by a match-on-device biometric check; the reference
// uses software keys behind the same interface.
type Signer interface {
	// PublicKey returns the SEC1 compressed point (33 bytes).
	PublicKey() []byte
	// Sign returns a raw r||s ECDSA signature (64 bytes) normalised to low-S.
	Sign(digest []byte) ([]byte, error)
}

// ErrKeyExhausted is returned by a single-use key on its second use, modelling
// Android KeyMint's hardware-enforced USAGE_COUNT_LIMIT=1.
var ErrKeyExhausted = errors.New("offline: single-use key already consumed")

// SoftwareKey is a test stand-in for a Secure Enclave / StrongBox key.
type SoftwareKey struct{ priv *ecdsa.PrivateKey }

// NewSoftwareKey generates a P-256 key.
func NewSoftwareKey() (*SoftwareKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SoftwareKey{priv: priv}, nil
}

// PublicKey implements Signer.
func (k *SoftwareKey) PublicKey() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), k.priv.X, k.priv.Y)
}

// Sign implements Signer.
func (k *SoftwareKey) Sign(digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest)
	if err != nil {
		return nil, err
	}
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 { // low-S normalisation (anti-malleability)
		s.Sub(n, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// SingleUseKey models a KeyMint key generated with setMaxUsageCount(1) whose
// attestation shows the limit as hardware-enforced: the TEE deletes the key
// after one private-key operation.
type SingleUseKey struct {
	SoftwareKey
	used bool
}

// NewSingleUseKey generates a single-use P-256 key.
func NewSingleUseKey() (*SingleUseKey, error) {
	k, err := NewSoftwareKey()
	if err != nil {
		return nil, err
	}
	return &SingleUseKey{SoftwareKey: *k}, nil
}

// Sign implements Signer and fails on any use after the first.
func (k *SingleUseKey) Sign(digest []byte) ([]byte, error) {
	if k.used {
		return nil, ErrKeyExhausted
	}
	k.used = true
	return k.SoftwareKey.Sign(digest)
}

// VerifySig checks a raw r||s signature over digest. High-S signatures are
// rejected so that each payload has exactly one valid signature encoding.
func VerifySig(pub, digest, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("signature length %d", len(sig))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
	if x == nil {
		return errors.New("invalid P-256 public key")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if s.Cmp(new(big.Int).Rsh(elliptic.P256().Params().N, 1)) > 0 {
		return errors.New("high-S signature")
	}
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest, r, s) {
		return errors.New("signature verification failed")
	}
	return nil
}

// COSE constants (RFC 9052 / RFC 9053).
const (
	coseSign1Tag  = 18
	coseAlgES256  = -7
	coseHdrAlg    = 1
	coseHdrKID    = 4
	sigContextOne = "Signature1"
)

// protectedES256 is the deterministic encoding of {1: -7}; it is fixed so
// verifiers can compare bytes instead of re-parsing (prevents alg confusion).
var protectedES256 = cbor.MustEncode(cbor.Map{coseHdrAlg: int64(coseAlgES256)})

func sigStructureDigest(payload []byte, aad string) []byte {
	tbs := cbor.MustEncode([]any{sigContextOne, protectedES256, []byte(aad), payload})
	d := sha256.Sum256(tbs)
	return d[:]
}

// Sign1 produces a tagged COSE_Sign1 over payload. The external AAD carries a
// domain-separation label ("bilyon/ost/v1", ...) so a signature made for one
// message type can never verify as another.
func Sign1(s Signer, kid, payload []byte, aad string) ([]byte, error) {
	sig, err := s.Sign(sigStructureDigest(payload, aad))
	if err != nil {
		return nil, err
	}
	unprotected := cbor.Map{}
	if len(kid) > 0 {
		unprotected[coseHdrKID] = kid
	}
	return cbor.Encode(cbor.Tag{Number: coseSign1Tag, Content: []any{protectedES256, unprotected, payload, sig}})
}

// peekPayload returns a COSE_Sign1 payload WITHOUT verifying it. Callers must
// verify with Open1 before trusting any field; it exists for messages whose
// verification key is carried in the payload and authenticated another way
// (Tier S coin keys are authenticated by a Merkle proof).
func peekPayload(raw []byte) ([]byte, error) {
	v, err := cbor.Decode(raw)
	if err != nil {
		return nil, err
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != coseSign1Tag {
		return nil, errors.New("not a COSE_Sign1")
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, errors.New("malformed COSE_Sign1")
	}
	payload, ok := arr[2].([]byte)
	if !ok {
		return nil, errors.New("malformed COSE_Sign1")
	}
	return payload, nil
}

// Open1 verifies a COSE_Sign1 and returns its payload and kid. keyFor maps the
// kid (possibly empty) to the expected public key.
func Open1(raw []byte, aad string, keyFor func(kid []byte) ([]byte, error)) (payload, kid []byte, err error) {
	v, err := cbor.Decode(raw)
	if err != nil {
		return nil, nil, err
	}
	tag, ok := v.(cbor.Tag)
	if !ok || tag.Number != coseSign1Tag {
		return nil, nil, errors.New("not a COSE_Sign1")
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, nil, errors.New("malformed COSE_Sign1")
	}
	prot, ok1 := arr[0].([]byte)
	unprot, ok2 := arr[1].(cbor.Map)
	payload, ok3 := arr[2].([]byte)
	sig, ok4 := arr[3].([]byte)
	if !ok1 || !ok2 || !ok3 || !ok4 || string(prot) != string(protectedES256) {
		return nil, nil, errors.New("malformed COSE_Sign1 or unsupported alg")
	}
	for label := range unprot {
		if label != coseHdrKID {
			return nil, nil, fmt.Errorf("unexpected unprotected header %d", label)
		}
	}
	if k, present := unprot[coseHdrKID]; present {
		if kid, ok = k.([]byte); !ok {
			return nil, nil, errors.New("kid must be a byte string")
		}
	}
	pub, err := keyFor(kid)
	if err != nil {
		return nil, nil, err
	}
	if err := VerifySig(pub, sigStructureDigest(payload, aad), sig); err != nil {
		return nil, nil, err
	}
	return payload, kid, nil
}
