package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Vectors from RFC 8949 Appendix A (the subset this package supports).
func TestEncodeRFC8949Vectors(t *testing.T) {
	cases := []struct {
		v    any
		want string
	}{
		{uint64(0), "00"},
		{uint64(23), "17"},
		{uint64(24), "1818"},
		{uint64(100), "1864"},
		{uint64(1000), "1903e8"},
		{uint64(1000000), "1a000f4240"},
		{uint64(1000000000000), "1b000000e8d4a51000"},
		{int64(-1), "20"},
		{int64(-1000), "3903e7"},
		{[]byte{1, 2, 3, 4}, "4401020304"},
		{"IETF", "6449455446"},
		{"ü", "62c3bc"},
		{[]any{uint64(1), []any{uint64(2), uint64(3)}}, "8201820203"},
		{Map{1: uint64(2), 3: uint64(4)}, "a201020304"},
		{Tag{Number: 1, Content: uint64(1363896240)}, "c11a514b67b0"},
	}
	for _, c := range cases {
		got, err := Encode(c.v)
		if err != nil {
			t.Fatalf("Encode(%v): %v", c.v, err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("Encode(%v) = %x, want %s", c.v, got, c.want)
		}
		back, err := Decode(got)
		if err != nil {
			t.Fatalf("Decode(%x): %v", got, err)
		}
		again, _ := Encode(back)
		if !bytes.Equal(again, got) {
			t.Errorf("round trip of %x produced %x", got, again)
		}
	}
}

func TestMapKeyOrderIsBytewise(t *testing.T) {
	// COSE headers mix positive and negative labels: 0x01 < 0x0a < 0x20 (-1).
	got := MustEncode(Map{-1: uint64(0), 10: uint64(0), 1: uint64(0)})
	if hex.EncodeToString(got) != "a301000a002000" {
		t.Fatalf("got %x", got)
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	bad := map[string]string{
		"non-shortest uint":   "1817",       // 23 encoded in two bytes
		"non-shortest length": "5801ff",     // 1-byte bstr with 1-byte length
		"indefinite array":    "9f01ff",     // indefinite-length array
		"unsorted map":        "a203040102", // keys 3, 1
		"duplicate map key":   "a201020103", // key 1 twice
		"trailing bytes":      "0000",       // two items
		"truncated bstr":      "4401",       // claims 4 bytes, has 1
		"float":               "f93c00",     // half-precision 1.0
		"text map key":        "a1616101",   // {"a": 1}
		"reserved ai":         "1c",         // additional info 28
	}
	for name, h := range bad {
		raw, _ := hex.DecodeString(h)
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: Decode(%s) accepted non-canonical input", name, h)
		}
	}
	raw, _ := hex.DecodeString("1817")
	if _, err := Decode(raw); !errors.Is(err, ErrNonCanonical) {
		t.Errorf("want ErrNonCanonical, got %v", err)
	}
}
