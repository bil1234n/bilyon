package der

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"math"
	"testing"

	"pgregory.net/rapid"
)

func TestIntegersMatchEncodingASN1(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.Int64().Draw(t, "v")
		ours := Integer(v)
		std, err := asn1.Marshal(v)
		if err != nil || !bytes.Equal(ours, std) {
			t.Fatalf("%d: %x vs %x", v, ours, std)
		}
		e, err := One(ours)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Int(e.Content)
		if err != nil || got != v {
			t.Fatalf("decode %d: %d %v", v, got, err)
		}
	})
	for _, v := range []int64{0, -1, 127, 128, -128, -129, math.MaxInt64, math.MinInt64} {
		e, _ := One(Integer(v))
		if got, err := Int(e.Content); err != nil || got != v {
			t.Errorf("%d: %d %v", v, got, err)
		}
	}
}

func TestHighTagNumbersRoundTrip(t *testing.T) {
	for _, tag := range []int{0, 30, 31, 127, 128, 600, 702, 709, 16383, 16384} {
		raw := ExplicitTag(tag, Null())
		e, err := One(raw)
		if err != nil || e.Class != ClassContext || e.Tag != tag || !e.Constructed {
			t.Fatalf("tag %d: %+v %v", tag, e, err)
		}
		inner, err := Explicit(e)
		if err != nil || !inner.Is(ClassUniversal, TagNull) {
			t.Fatalf("tag %d inner: %+v %v", tag, inner, err)
		}
	}
	long := OctetString(bytes.Repeat([]byte{7}, 300))
	if e, err := One(long); err != nil || len(e.Content) != 300 {
		t.Fatalf("long length: %v", err)
	}
}

func TestRejectsMalformedDER(t *testing.T) {
	cases := map[string][]byte{
		"truncated header":      {0x30},
		"indefinite length":     {0x30, 0x80, 0x00, 0x00},
		"non-minimal length":    {0x04, 0x81, 0x05, 1, 2, 3, 4, 5},
		"length beyond input":   {0x04, 0x05, 1, 2},
		"non-minimal high tag":  {0xbf, 0x80, 0x05, 0x00},
		"high form for low tag": {0xbf, 0x1e, 0x00},
		"trailing data":         {0x05, 0x00, 0x00},
		"truncated tag":         {0xbf, 0x85},
	}
	for name, b := range cases {
		if _, err := One(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, content := range map[string][]byte{
		"empty":            {},
		"non-minimal zero": {0x00, 0x01},
		"non-minimal ones": {0xff, 0x80},
		"too long":         make([]byte, 9),
	} {
		if _, err := Int(content); !errors.Is(err, ErrMalformed) {
			t.Errorf("integer %s: %v", name, err)
		}
	}
	if _, err := IntSet(Element{Class: ClassUniversal, Tag: TagSequence}); err == nil {
		t.Error("SEQUENCE accepted as SET")
	}
	r := NewReader(Sequence(Integer(1)))
	if _, err := r.Expect(ClassUniversal, TagSet); err == nil {
		t.Error("Expect accepted the wrong tag")
	}
}
