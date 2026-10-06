package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vectors from RFC 8949 Appendix A for the supported data model.
func TestRFC8949Vectors(t *testing.T) {
	cases := []struct {
		hex   string
		value any
	}{
		{"00", uint64(0)},
		{"01", uint64(1)},
		{"0a", uint64(10)},
		{"17", uint64(23)},
		{"1818", uint64(24)},
		{"1819", uint64(25)},
		{"1864", uint64(100)},
		{"1903e8", uint64(1000)},
		{"1a000f4240", uint64(1000000)},
		{"1b000000e8d4a51000", uint64(1000000000000)},
		{"1bffffffffffffffff", uint64(math.MaxUint64)},
		{"20", int64(-1)},
		{"29", int64(-10)},
		{"3863", int64(-100)},
		{"3903e7", int64(-1000)},
		{"3b7fffffffffffffff", int64(math.MinInt64)},
		{"f4", false},
		{"f5", true},
		{"f6", nil},
		{"40", []byte{}},
		{"4401020304", []byte{1, 2, 3, 4}},
		{"60", ""},
		{"6161", "a"},
		{"6449455446", "IETF"},
		{"62225c", "\"\\"},
		{"62c3bc", "ü"},
		{"63e6b0b4", "水"},
		{"64f0908591", "\U00010151"},
		{"80", []any{}},
		{"83010203", []any{uint64(1), uint64(2), uint64(3)}},
		{"8301820203820405", []any{uint64(1), []any{uint64(2), uint64(3)}, []any{uint64(4), uint64(5)}}},
		{"98190102030405060708090a0b0c0d0e0f101112131415161718181819", func() []any {
			a := make([]any, 25)
			for i := range a {
				a[i] = uint64(i + 1)
			}
			return a
		}()},
		{"a0", Map{}},
		{"a201020304", Map{int64(1): uint64(2), int64(3): uint64(4)}},
		{"a26161016162820203", Map{"a": uint64(1), "b": []any{uint64(2), uint64(3)}}},
		{"826161a161626163", []any{"a", Map{"b": "c"}}},
		{"c074323031332d30332d32315432303a30343a30305a", Tag{Number: 0, Content: "2013-03-21T20:04:00Z"}},
		{"d74401020304", Tag{Number: 23, Content: []byte{1, 2, 3, 4}}},
	}
	for _, c := range cases {
		raw := mustHex(t, c.hex)
		got, err := Decode(raw)
		if err != nil {
			t.Errorf("decode %s: %v", c.hex, err)
			continue
		}
		if !reflect.DeepEqual(got, c.value) {
			t.Errorf("decode %s: got %#v, want %#v", c.hex, got, c.value)
		}
		enc, err := Encode(c.value)
		if err != nil || !bytes.Equal(enc, raw) {
			t.Errorf("encode %#v: got %x (%v), want %s", c.value, enc, err, c.hex)
		}
	}
}

func TestDeterministicDecoderRejectsEveryNonCanonicalForm(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want error
	}{
		{"uint in 1-byte head", "1817", ErrNonCanonical},
		{"uint in 2-byte head", "1900ff", ErrNonCanonical},
		{"uint in 4-byte head", "1a0000ffff", ErrNonCanonical},
		{"uint in 8-byte head", "1b00000000ffffffff", ErrNonCanonical},
		{"negative int not shortest", "3800", ErrNonCanonical},
		{"byte string length not shortest", "5801ff", ErrNonCanonical},
		{"array length not shortest", "980101", ErrNonCanonical},
		{"map keys unsorted", "a203040102", ErrNonCanonical},
		{"map keys duplicated", "a201020103", ErrNonCanonical},
		{"text key sorted by length first (CTAP2 order)", "a2616101616202", nil}, // sorted bytewise too: accepted
		{"integer after text key", "a2616101 0102", ErrNonCanonical},
		{"indefinite byte string", "5f41014102ff", ErrUnsupported},
		{"indefinite array", "9f0102ff", ErrUnsupported},
		{"indefinite map", "bf0102ff", ErrUnsupported},
		{"half float", "f93c00", ErrUnsupported},
		{"single float", "fa47c35000", ErrUnsupported},
		{"double float", "fb3ff199999999999a", ErrUnsupported},
		{"undefined", "f7", ErrUnsupported},
		{"one-byte simple value", "f820", ErrUnsupported},
		{"reserved additional info", "1c", ErrMalformed},
		{"trailing bytes", "0000", ErrMalformed},
		{"invalid UTF-8", "62c328", ErrMalformed},
		{"negative below -2^64 range", "3bffffffffffffffff", ErrUnsupported},
		{"map key above 2^63-1", "a11b800000000000000001", ErrUnsupported},
		{"byte string map key", "a1410101", ErrUnsupported},
		{"truncated head", "19ff", ErrTruncated},
		{"truncated byte string", "4401", ErrTruncated},
		{"empty input", "", ErrTruncated},
	}
	for _, c := range cases {
		_, err := Decode(mustHex(t, c.hex))
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: unexpected error %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s (%s): got %v, want %v", c.name, c.hex, err, c.want)
		}
	}
	deep := bytes.Repeat([]byte{0x81}, MaxDepth+2)
	if _, err := Decode(append(deep, 0x00)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("nesting beyond MaxDepth: %v", err)
	}
	huge := mustHex(t, "9b0000000100000000")
	if _, err := Decode(huge); !errors.Is(err, ErrUnsupported) {
		t.Errorf("array claiming 2^32 elements: %v", err)
	}
}

func TestWellFormedDecoderAcceptsNonDeterministicButValidInput(t *testing.T) {
	for _, h := range []string{"1817", "a203040102", "5801ff", "980101"} {
		if _, err := DecodeWellFormed(mustHex(t, h)); err != nil {
			t.Errorf("%s rejected: %v", h, err)
		}
	}
	for _, c := range []struct {
		hex  string
		want error
	}{
		{"a201020103", ErrMalformed}, // duplicate keys are never acceptable
		{"9f0102ff", ErrUnsupported},
		{"f93c00", ErrUnsupported},
		{"0000", ErrMalformed},
	} {
		if _, err := DecodeWellFormed(mustHex(t, c.hex)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.hex, err, c.want)
		}
	}
	v, n, err := DecodeFirstWellFormed(mustHex(t, "a10102 ff ee"))
	if err != nil || n != 3 || !reflect.DeepEqual(v, Map{int64(1): uint64(2)}) {
		t.Fatalf("decode first: %v %d %v", v, n, err)
	}
}

func TestEncodeRejectsUnsupportedValues(t *testing.T) {
	for _, v := range []any{1.5, float32(2), struct{}{}, map[string]int{"a": 1}, Map{1.5: uint64(1)},
		Map{int64(1): uint64(1), 1: uint64(2)}, "\xff"} {
		if _, err := Encode(v); !errors.Is(err, ErrUnsupported) {
			t.Errorf("encode %#v: %v", v, err)
		}
	}
	deep := any(uint64(0))
	for range MaxDepth + 2 {
		deep = []any{deep}
	}
	if _, err := Encode(deep); !errors.Is(err, ErrUnsupported) {
		t.Errorf("deep value: %v", err)
	}
}

func genValue(depth int) *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		kinds := 8
		if depth >= 3 {
			kinds = 5 // leaves only
		}
		switch rapid.IntRange(0, kinds-1).Draw(t, "kind") {
		case 0:
			return rapid.Uint64().Draw(t, "uint")
		case 1:
			return rapid.Int64Range(math.MinInt64, -1).Draw(t, "neg")
		case 2:
			return rapid.SliceOfN(rapid.Byte(), 0, 40).Draw(t, "bytes")
		case 3:
			return rapid.StringN(0, 20, -1).Draw(t, "text")
		case 4:
			return rapid.SampledFrom([]any{true, false, nil}).Draw(t, "simple")
		case 5:
			return rapid.SliceOfN(genValue(depth+1), 0, 5).Draw(t, "array")
		case 6:
			m := Map{}
			for range rapid.IntRange(0, 5).Draw(t, "entries") {
				var k any
				if rapid.Bool().Draw(t, "textKey") {
					k = rapid.StringN(0, 8, -1).Draw(t, "k")
				} else {
					k = rapid.Int64().Draw(t, "k")
				}
				m[k] = genValue(depth+1).Draw(t, "v")
			}
			return m
		default:
			return Tag{Number: rapid.Uint64().Draw(t, "tag"), Content: genValue(depth+1).Draw(t, "content")}
		}
	})
}

// normalise maps decoded values to what was encoded: decoders return
// non-negative int64 map keys and values as their wire types.
func normalise(v any) any {
	switch x := v.(type) {
	case int64:
		if x >= 0 {
			return uint64(x)
		}
	case []byte:
		if x == nil {
			return []byte{}
		}
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalise(e)
		}
		return out
	case Map:
		out := Map{}
		for k, e := range x {
			out[k] = normalise(e)
		}
		return out
	case Tag:
		return Tag{Number: x.Number, Content: normalise(x.Content)}
	}
	return v
}

func TestRoundTripAndUniqueEncoding(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := genValue(0).Draw(t, "value")
		enc, err := Encode(v)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := Decode(enc)
		if err != nil {
			t.Fatalf("decode of own encoding %x: %v", enc, err)
		}
		if !reflect.DeepEqual(normalise(dec), normalise(v)) {
			t.Fatalf("round trip changed the value:\n%#v\n%#v", v, dec)
		}
		again, err := Encode(dec)
		if err != nil || !bytes.Equal(again, enc) {
			t.Fatalf("re-encoding differs: %x vs %x (%v)", again, enc, err)
		}
		wf, err := DecodeWellFormed(enc)
		if err != nil || !reflect.DeepEqual(wf, dec) {
			t.Fatalf("well-formed decode differs: %v", err)
		}
	})
}

// Any input the deterministic decoder accepts re-encodes to itself: there is
// exactly one accepted encoding per value.
func TestAcceptedInputIsTheOnlyEncoding(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(t, "raw")
		v, err := Decode(raw)
		if err != nil {
			return
		}
		enc, err := Encode(v)
		if err != nil || !bytes.Equal(enc, raw) {
			t.Fatalf("accepted %x but it encodes as %x (%v)", raw, enc, err)
		}
	})
}

func FuzzDecode(f *testing.F) {
	for _, h := range []string{"a201020304", "d28443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36", "9f0102ff", "f93c00"} {
		f.Add(mustHex(f, h))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if v, err := Decode(raw); err == nil {
			enc, err := Encode(v)
			if err != nil || !bytes.Equal(enc, raw) {
				t.Fatalf("accepted non-unique encoding %x", raw)
			}
		}
		if v, n, err := DecodeFirstWellFormed(raw); err == nil {
			if n <= 0 || n > len(raw) {
				t.Fatalf("consumed %d of %d bytes", n, len(raw))
			}
			if _, err := Encode(v); err != nil {
				t.Fatalf("well-formed value not encodable: %v", err)
			}
		}
	})
}

func TestFieldsEnforceClosedSchemas(t *testing.T) {
	m := Map{int64(1): uint64(1), int64(2): []byte("0123456789abcdef"), int64(3): "EUR", int64(4): int64(-7),
		"fmt": "none", int64(5): []any{uint64(1)}, int64(6): Map{}, int64(7): true}
	f := m.Fields()
	if f.UintRange(1, 1, 1) != 1 || len(f.BytesN(2, 16)) != 16 || f.Text(3, 3) != "EUR" || f.Int(4) != -7 ||
		f.Text("fmt", -1) != "none" || len(f.Array(5, 1)) != 1 || f.Map(6) == nil || !f.Bool(7) {
		t.Fatalf("accessors: %v", f.Err())
	}
	if err := f.Done(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		read func(*Fields)
	}{
		{"unknown key", func(f *Fields) { f.Uint(1) }},
		{"missing key", func(f *Fields) { f.Uint(99) }},
		{"wrong type", func(f *Fields) { f.Bytes(1) }},
		{"wrong size", func(f *Fields) { f.BytesN(2, 15) }},
		{"too long", func(f *Fields) { f.Text(3, 2) }},
		{"out of range", func(f *Fields) { f.UintRange(1, 2, 3) }},
		{"array too long", func(f *Fields) { f.Array(5, 0) }},
	}
	for _, c := range cases {
		f := m.Fields()
		c.read(f)
		for k := range m {
			if f.err == nil {
				f.read[k] = true
			}
		}
		if c.name == "unknown key" {
			f = m.Fields()
			f.Uint(1)
		}
		if err := f.Done(); !errors.Is(err, ErrSchema) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	f = m.Fields()
	var seen bool
	f.Optional(42, func() { seen = true })
	if seen || f.Has(42) || !f.Has(1) {
		t.Fatal("optional handling")
	}
	f.Fail(1, "semantic")
	var se *SchemaError
	if err := f.Done(); !errors.As(err, &se) || se.Key != 1 || !strings.Contains(err.Error(), "semantic") {
		t.Fatalf("custom failure: %v", err)
	}
}
