package keywrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3394 §4 test vectors.
func TestVectors(t *testing.T) {
	cases := []struct{ name, kek, key, wrapped string }{
		{"4.1 128-bit KEK, 128-bit key", "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"},
		{"4.2 192-bit KEK, 128-bit key", "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
			"96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"},
		{"4.3 256-bit KEK, 128-bit key", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"},
		{"4.6 256-bit KEK, 256-bit key", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kek, key, want := unhex(t, c.kek), unhex(t, c.key), unhex(t, c.wrapped)
			got, err := Wrap(kek, key)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("Wrap = %X, %v; want %X", got, err, want)
			}
			back, err := Unwrap(kek, want)
			if err != nil || !bytes.Equal(back, key) {
				t.Fatalf("Unwrap = %X, %v; want %X", back, err, key)
			}
		})
	}
}

func TestRoundTripAndTamper(t *testing.T) {
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{16, 24, 32, 64} {
		key := make([]byte, n)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		w, err := Wrap(kek, key)
		if err != nil {
			t.Fatal(err)
		}
		if back, err := Unwrap(kek, w); err != nil || !bytes.Equal(back, key) {
			t.Fatalf("%d-byte key: round trip failed: %v", n, err)
		}
		for i := range w {
			bad := bytes.Clone(w)
			bad[i] ^= 0x01
			if _, err := Unwrap(kek, bad); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%d-byte key: flipped byte %d: err = %v", n, i, err)
			}
		}
		other := bytes.Clone(kek)
		other[0] ^= 0x80
		if _, err := Unwrap(other, w); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("wrong KEK: err = %v", err)
		}
	}
}

func TestLengths(t *testing.T) {
	kek := make([]byte, 16)
	for _, n := range []int{0, 8, 15, 17, 23} {
		if _, err := Wrap(kek, make([]byte, n)); !errors.Is(err, ErrLength) {
			t.Fatalf("Wrap(%d bytes): err = %v", n, err)
		}
	}
	for _, n := range []int{0, 16, 25, 31} {
		if _, err := Unwrap(kek, make([]byte, n)); !errors.Is(err, ErrLength) {
			t.Fatalf("Unwrap(%d bytes): err = %v", n, err)
		}
	}
	if _, err := Wrap(make([]byte, 7), make([]byte, 16)); err == nil {
		t.Fatal("Wrap accepted a 7-byte KEK")
	}
	if _, err := Unwrap(make([]byte, 7), make([]byte, 24)); err == nil {
		t.Fatal("Unwrap accepted a 7-byte KEK")
	}
}
