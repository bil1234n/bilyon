// Package keywrap implements AES Key Wrap (RFC 3394) with the default
// initial value, as JWE "A128KW"/"A192KW"/"A256KW" use it. Play Integrity
// verdicts arrive with their content key wrapped this way.
package keywrap

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// defaultIV is the RFC 3394 §2.2.3.1 initial value.
const defaultIV = 0xA6A6A6A6A6A6A6A6

// ErrIntegrity means the unwrapped key failed the integrity check: wrong
// key-encryption key or tampered input.
var ErrIntegrity = errors.New("keywrap: integrity check failed")

// ErrLength means the input is not a whole number of 64-bit blocks of
// acceptable size.
var ErrLength = errors.New("keywrap: invalid length")

// Wrap wraps key (at least 16 bytes, a multiple of 8) under kek (16, 24 or
// 32 bytes).
func Wrap(kek, key []byte) ([]byte, error) {
	if len(key) < 16 || len(key)%8 != 0 {
		return nil, ErrLength
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	out := make([]byte, 8+len(key))
	copy(out[8:], key)
	a := uint64(defaultIV)
	var buf [16]byte
	for j := range 6 {
		for i := 1; i <= n; i++ {
			r := out[8*i : 8*i+8]
			binary.BigEndian.PutUint64(buf[:8], a)
			copy(buf[8:], r)
			block.Encrypt(buf[:], buf[:])
			a = binary.BigEndian.Uint64(buf[:8]) ^ uint64(n*j+i)
			copy(r, buf[8:])
		}
	}
	binary.BigEndian.PutUint64(out[:8], a)
	return out, nil
}

// Unwrap reverses Wrap and checks the integrity value.
func Unwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, ErrLength
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	key := make([]byte, 8*n)
	copy(key, wrapped[8:])
	a := binary.BigEndian.Uint64(wrapped[:8])
	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			r := key[8*(i-1) : 8*i]
			binary.BigEndian.PutUint64(buf[:8], a^uint64(n*j+i))
			copy(buf[8:], r)
			block.Decrypt(buf[:], buf[:])
			a = binary.BigEndian.Uint64(buf[:8])
			copy(r, buf[8:])
		}
	}
	var got, want [8]byte
	binary.BigEndian.PutUint64(got[:], a)
	binary.BigEndian.PutUint64(want[:], defaultIV)
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		return nil, ErrIntegrity
	}
	return key, nil
}
