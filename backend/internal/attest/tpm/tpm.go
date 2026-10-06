// Package tpm parses the TPM 2.0 structures in WebAuthn "tpm" attestation
// statements (WebAuthn §8.3): the attested key's TPMT_PUBLIC ("pubArea")
// and the TPMS_ATTEST the AIK signed ("certInfo").
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // nameAlg SHA-1 is legal in TPM 2.0
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// TPM algorithm and structure constants (TPM 2.0 Part 2).
const (
	AlgRSA    = 0x0001
	AlgSHA1   = 0x0004
	AlgSHA256 = 0x000B
	AlgSHA384 = 0x000C
	AlgSHA512 = 0x000D
	AlgNull   = 0x0010
	AlgECC    = 0x0023

	CurveNISTP256 = 0x0003
	CurveNISTP384 = 0x0004
	CurveNISTP521 = 0x0005

	GeneratedValue  = 0xff544347 // TPM_GENERATED_VALUE
	STAttestCertify = 0x8017     // TPM_ST_ATTEST_CERTIFY
)

// ErrMalformed reports an invalid TPM structure.
var ErrMalformed = errors.New("tpm: malformed structure")

type reader struct {
	b   []byte
	err error
}

func (r *reader) u8() uint8 {
	if r.err != nil || len(r.b) < 1 {
		r.fail()
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil || len(r.b) < 2 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) u32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) u64() uint64 {
	if r.err != nil || len(r.b) < 8 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

// tpm2b reads a size-prefixed buffer.
func (r *reader) tpm2b() []byte {
	n := int(r.u16())
	if r.err != nil || len(r.b) < n {
		r.fail()
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = fmt.Errorf("%w: truncated", ErrMalformed)
	}
}

func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(r.b))
	}
	return nil
}

// Public is a TPMT_PUBLIC.
type Public struct {
	Type       uint16
	NameAlg    uint16
	Attributes uint32
	AuthPolicy []byte

	RSAKeyBits  uint16
	RSAExponent uint32 // 0 means 65537
	RSAModulus  []byte

	ECCCurve uint16
	ECCX     []byte
	ECCY     []byte
}

// skipScheme reads a TPMT_*_SCHEME or TPMT_KDF_SCHEME: an algorithm and,
// unless it is TPM_ALG_NULL, a hash algorithm.
func skipScheme(r *reader) {
	if r.u16() != AlgNull {
		r.u16()
	}
}

// ParsePublic decodes a TPMT_PUBLIC.
func ParsePublic(b []byte) (*Public, error) {
	r := &reader{b: b}
	p := &Public{Type: r.u16(), NameAlg: r.u16(), Attributes: r.u32(), AuthPolicy: r.tpm2b()}
	// symmetric (TPMT_SYM_DEF_OBJECT)
	if r.u16() != AlgNull {
		r.u16() // keyBits
		r.u16() // mode
	}
	switch p.Type {
	case AlgRSA:
		skipScheme(r)
		p.RSAKeyBits = r.u16()
		p.RSAExponent = r.u32()
		p.RSAModulus = r.tpm2b()
	case AlgECC:
		skipScheme(r)
		p.ECCCurve = r.u16()
		skipScheme(r) // kdf
		p.ECCX = r.tpm2b()
		p.ECCY = r.tpm2b()
	default:
		return nil, fmt.Errorf("%w: unsupported key type %#04x", ErrMalformed, p.Type)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return p, nil
}

// PublicKey returns the key the structure describes.
func (p *Public) PublicKey() (crypto.PublicKey, error) {
	switch p.Type {
	case AlgRSA:
		if len(p.RSAModulus) == 0 || p.RSAModulus[0] == 0 {
			return nil, fmt.Errorf("%w: RSA modulus", ErrMalformed)
		}
		e := int(p.RSAExponent)
		if e == 0 {
			e = 65537
		}
		n := new(big.Int).SetBytes(p.RSAModulus)
		if int(p.RSAKeyBits) != n.BitLen() {
			return nil, fmt.Errorf("%w: keyBits %d but modulus has %d bits", ErrMalformed, p.RSAKeyBits, n.BitLen())
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case AlgECC:
		curve, size := map[uint16]elliptic.Curve{CurveNISTP256: elliptic.P256(), CurveNISTP384: elliptic.P384(),
			CurveNISTP521: elliptic.P521()}[p.ECCCurve], map[uint16]int{CurveNISTP256: 32, CurveNISTP384: 48, CurveNISTP521: 66}[p.ECCCurve]
		if curve == nil {
			return nil, fmt.Errorf("%w: unsupported curve %#04x", ErrMalformed, p.ECCCurve)
		}
		if len(p.ECCX) > size || len(p.ECCY) > size {
			return nil, fmt.Errorf("%w: ECC coordinates too long", ErrMalformed)
		}
		raw := make([]byte, 1+2*size)
		raw[0] = 4
		copy(raw[1+size-len(p.ECCX):1+size], p.ECCX)
		copy(raw[1+2*size-len(p.ECCY):], p.ECCY)
		k, err := ecdsa.ParseUncompressedPublicKey(curve, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key type", ErrMalformed)
	}
}

// Attest is a TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY.
type Attest struct {
	Magic                  uint32
	Type                   uint16
	QualifiedSigner        []byte
	ExtraData              []byte
	Clock                  uint64
	ResetCount             uint32
	RestartCount           uint32
	Safe                   uint8
	FirmwareVersion        uint64
	CertifiedName          []byte
	CertifiedQualifiedName []byte
}

// ParseAttest decodes a TPMS_ATTEST carrying TPMS_CERTIFY_INFO.
func ParseAttest(b []byte) (*Attest, error) {
	r := &reader{b: b}
	a := &Attest{Magic: r.u32(), Type: r.u16(), QualifiedSigner: r.tpm2b(), ExtraData: r.tpm2b(),
		Clock: r.u64(), ResetCount: r.u32(), RestartCount: r.u32(), Safe: r.u8(), FirmwareVersion: r.u64()}
	if r.err == nil && a.Type != STAttestCertify {
		return nil, fmt.Errorf("%w: attestation type %#04x is not TPM_ST_ATTEST_CERTIFY", ErrMalformed, a.Type)
	}
	a.CertifiedName = r.tpm2b()
	a.CertifiedQualifiedName = r.tpm2b()
	if err := r.done(); err != nil {
		return nil, err
	}
	return a, nil
}

// Name returns the TPM name of a public area: nameAlg ‖ H_nameAlg(pubArea).
func Name(nameAlg uint16, pubArea []byte) ([]byte, error) {
	var sum []byte
	switch nameAlg {
	case AlgSHA1:
		s := sha1.Sum(pubArea) //nolint:gosec
		sum = s[:]
	case AlgSHA256:
		s := sha256.Sum256(pubArea)
		sum = s[:]
	case AlgSHA384:
		s := sha512.Sum384(pubArea)
		sum = s[:]
	case AlgSHA512:
		s := sha512.Sum512(pubArea)
		sum = s[:]
	default:
		return nil, fmt.Errorf("%w: unsupported nameAlg %#04x", ErrMalformed, nameAlg)
	}
	return append(binary.BigEndian.AppendUint16(nil, nameAlg), sum...), nil
}
