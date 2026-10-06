package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func rsaArea(n []byte, bits uint16, exp uint32) []byte {
	b := binary.BigEndian.AppendUint16(nil, AlgRSA)
	b = binary.BigEndian.AppendUint16(b, AlgSHA256)
	b = binary.BigEndian.AppendUint32(b, 0x00060472)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, AlgNull) // symmetric
	b = binary.BigEndian.AppendUint16(b, 0x0014)  // RSASSA scheme ...
	b = binary.BigEndian.AppendUint16(b, AlgSHA256)
	b = binary.BigEndian.AppendUint16(b, bits)
	b = binary.BigEndian.AppendUint32(b, exp)
	b = binary.BigEndian.AppendUint16(b, uint16(len(n)))
	return append(b, n...)
}

func TestParsePublicRSAAndECC(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePublic(rsaArea(k.N.Bytes(), 2048, 0))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := p.PublicKey()
	if err != nil || !k.PublicKey.Equal(pub) {
		t.Fatalf("RSA key: %v", err)
	}
	if _, err := (&Public{Type: AlgRSA, RSAKeyBits: 1024, RSAModulus: k.N.Bytes()}).PublicKey(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("keyBits mismatch: %v", err)
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := ec.PublicKey.Bytes()
	b := binary.BigEndian.AppendUint16(nil, AlgECC)
	b = binary.BigEndian.AppendUint16(b, AlgSHA256)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0x0006) // AES symmetric
	b = binary.BigEndian.AppendUint16(b, 128)
	b = binary.BigEndian.AppendUint16(b, 0x0043) // CFB
	b = binary.BigEndian.AppendUint16(b, AlgNull)
	b = binary.BigEndian.AppendUint16(b, CurveNISTP256)
	b = binary.BigEndian.AppendUint16(b, AlgNull)
	b = binary.BigEndian.AppendUint16(b, 32)
	b = append(b, raw[1:33]...)
	b = binary.BigEndian.AppendUint16(b, 32)
	b = append(b, raw[33:]...)
	p, err = ParsePublic(b)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = p.PublicKey()
	if err != nil || !ec.PublicKey.Equal(pub) {
		t.Fatalf("ECC key: %v", err)
	}
	if _, err := ParsePublic(append(b, 0)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing byte: %v", err)
	}
	if _, err := ParsePublic(b[:len(b)-1]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated: %v", err)
	}
	if _, err := ParsePublic([]byte{0, 0x25, 0, 0xb}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown type: %v", err)
	}
	if _, err := (&Public{Type: AlgECC, ECCCurve: 0x0010}).PublicKey(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown curve: %v", err)
	}
}

func TestParseAttestAndName(t *testing.T) {
	name, err := Name(AlgSHA256, []byte("area"))
	sum := sha256.Sum256([]byte("area"))
	if err != nil || len(name) != 34 || name[0] != 0 || name[1] != 0x0b || string(name[2:]) != string(sum[:]) {
		t.Fatalf("name %x %v", name, err)
	}
	for _, alg := range []uint16{AlgSHA1, AlgSHA384, AlgSHA512} {
		if _, err := Name(alg, nil); err != nil {
			t.Fatalf("name alg %x: %v", alg, err)
		}
	}
	if _, err := Name(0x9999, nil); !errors.Is(err, ErrMalformed) {
		t.Fatal("unknown name alg")
	}
	info := binary.BigEndian.AppendUint32(nil, GeneratedValue)
	info = binary.BigEndian.AppendUint16(info, STAttestCertify)
	info = binary.BigEndian.AppendUint16(info, 0) // qualifiedSigner
	info = binary.BigEndian.AppendUint16(info, 2) // extraData
	info = append(info, 9, 9)                     //
	info = binary.BigEndian.AppendUint64(info, 1) // clock
	info = binary.BigEndian.AppendUint32(info, 2) // reset
	info = binary.BigEndian.AppendUint32(info, 3) // restart
	info = append(info, 1)                        // safe
	info = binary.BigEndian.AppendUint64(info, 4) // firmware
	info = binary.BigEndian.AppendUint16(info, uint16(len(name)))
	info = append(info, name...)
	info = binary.BigEndian.AppendUint16(info, 0)
	a, err := ParseAttest(info)
	if err != nil || a.Magic != GeneratedValue || string(a.ExtraData) != "\x09\x09" || string(a.CertifiedName) != string(name) ||
		a.ResetCount != 2 || a.Safe != 1 {
		t.Fatalf("attest %+v %v", a, err)
	}
	bad := append([]byte{}, info...)
	binary.BigEndian.PutUint16(bad[4:], 0x8018) // quote, not certify
	if _, err := ParseAttest(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("wrong type: %v", err)
	}
	if _, err := ParseAttest(info[:20]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated: %v", err)
	}
}
