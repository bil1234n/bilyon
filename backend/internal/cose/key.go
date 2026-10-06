package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
)

// COSE_Key labels and values (RFC 9052 §7, RFC 9053 §7).
const (
	keyKty    = 1
	keyAlg    = 3
	keyCrv    = -1 // EC2: curve; RSA: n
	keyX      = -2 // EC2: x;     RSA: e
	keyY      = -3
	ktyEC2    = 2
	ktyRSA    = 3
	crvP256   = 1
	minRSABit = 2048
	maxRSABit = 8192
)

// ErrKey reports an unusable COSE key.
var ErrKey = errors.New("cose: unsupported or invalid key")

// Key is a public key from a COSE_Key structure, as WebAuthn authenticators
// return them (ES256 on P-256, or RS256).
type Key struct {
	Alg    int64
	Public crypto.PublicKey // *ecdsa.PublicKey or *rsa.PublicKey
}

// ParseKey decodes a COSE_Key. Authenticators emit CTAP2 canonical CBOR, so
// the encoding only needs to be well formed. Labels other than the ones the
// key type requires are ignored (kid, key_ops and the like).
func ParseKey(raw []byte) (*Key, error) {
	v, err := cbor.DecodeWellFormed(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, fmt.Errorf("%w: not a map", ErrKey)
	}
	return ParseKeyMap(m)
}

// ParseKeyMap builds a Key from a decoded COSE_Key map.
func ParseKeyMap(m cbor.Map) (*Key, error) {
	intOf := func(label int64) (int64, bool) {
		switch x := m[label].(type) {
		case int64:
			return x, true
		case uint64:
			if x <= 1<<62 {
				return int64(x), true
			}
		}
		return 0, false
	}
	bytesOf := func(label int64) []byte {
		b, _ := m[label].([]byte)
		return b
	}
	kty, ok1 := intOf(keyKty)
	alg, ok2 := intOf(keyAlg)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("%w: kty and alg are required", ErrKey)
	}
	switch {
	case kty == ktyEC2 && alg == AlgES256:
		crv, ok := intOf(keyCrv)
		x, y := bytesOf(keyX), bytesOf(keyY)
		if !ok || crv != crvP256 || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("%w: ES256 needs a P-256 point with 32-byte coordinates", ErrKey)
		}
		pub, err := ParseP256(append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKey, err)
		}
		return &Key{Alg: AlgES256, Public: pub}, nil
	case kty == ktyRSA && alg == AlgRS256:
		n, e := bytesOf(keyCrv), bytesOf(keyX)
		if len(n) == 0 || len(e) == 0 || len(e) > 4 || n[0] == 0 || e[0] == 0 {
			return nil, fmt.Errorf("%w: RSA modulus and exponent must be minimal big-endian", ErrKey)
		}
		mod := new(big.Int).SetBytes(n)
		exp := int(new(big.Int).SetBytes(e).Int64())
		if bits := mod.BitLen(); bits < minRSABit || bits > maxRSABit {
			return nil, fmt.Errorf("%w: RSA modulus of %d bits", ErrKey, bits)
		}
		if exp < 3 || exp%2 == 0 {
			return nil, fmt.Errorf("%w: RSA exponent %d", ErrKey, exp)
		}
		return &Key{Alg: AlgRS256, Public: &rsa.PublicKey{N: mod, E: exp}}, nil
	default:
		return nil, fmt.Errorf("%w: kty %d with alg %d", ErrKey, kty, alg)
	}
}

// VerifySignature checks a WebAuthn-style signature over signed: ES256
// signatures are ASN.1 DER (WebAuthn §6.5.6), RS256 is RSASSA-PKCS1-v1_5,
// both over SHA-256.
func (k *Key) VerifySignature(signed, sig []byte) error {
	digest := sha256.Sum256(signed)
	switch pub := k.Public.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return ErrSignature
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return ErrSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: %T", ErrKey, k.Public)
	}
}

// Encode returns the deterministic COSE_Key encoding of k.
func (k *Key) Encode() ([]byte, error) {
	switch pub := k.Public.(type) {
	case *ecdsa.PublicKey:
		raw, err := pub.Bytes()
		if err != nil || len(raw) != 65 {
			return nil, fmt.Errorf("%w: not a P-256 key", ErrKey)
		}
		return cbor.Encode(cbor.Map{int64(keyKty): int64(ktyEC2), int64(keyAlg): int64(AlgES256),
			int64(keyCrv): int64(crvP256), int64(keyX): raw[1:33], int64(keyY): raw[33:]})
	case *rsa.PublicKey:
		e := big.NewInt(int64(pub.E)).Bytes()
		return cbor.Encode(cbor.Map{int64(keyKty): int64(ktyRSA), int64(keyAlg): int64(AlgRS256),
			int64(keyCrv): pub.N.Bytes(), int64(keyX): e})
	default:
		return nil, fmt.Errorf("%w: %T", ErrKey, k.Public)
	}
}

// Equal reports whether two keys are the same public key and algorithm.
func (k *Key) Equal(o *Key) bool {
	if k == nil || o == nil || k.Alg != o.Alg {
		return false
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := k.Public.(equaler)
	return ok && e.Equal(o.Public)
}
