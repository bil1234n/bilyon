package der

import "math/big"

// Encode returns the DER TLV for one element.
func Encode(class int, constructed bool, tag int, content []byte) []byte {
	id := byte(class << 6)
	if constructed {
		id |= 0x20
	}
	out := []byte{}
	if tag < 0x1f {
		out = append(out, id|byte(tag))
	} else {
		out = append(out, id|0x1f)
		var digits []byte
		for t := tag; t > 0; t >>= 7 {
			digits = append([]byte{byte(t & 0x7f)}, digits...)
		}
		for i := range digits[:len(digits)-1] {
			digits[i] |= 0x80
		}
		out = append(out, digits...)
	}
	switch l := len(content); {
	case l < 0x80:
		out = append(out, byte(l))
	default:
		var lb []byte
		for v := l; v > 0; v >>= 8 {
			lb = append([]byte{byte(v)}, lb...)
		}
		out = append(out, 0x80|byte(len(lb)))
		out = append(out, lb...)
	}
	return append(out, content...)
}

func concat(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Sequence encodes a SEQUENCE of already-encoded elements.
func Sequence(elems ...[]byte) []byte {
	return Encode(ClassUniversal, true, TagSequence, concat(elems))
}

// Set encodes a SET of already-encoded elements (callers order them).
func Set(elems ...[]byte) []byte { return Encode(ClassUniversal, true, TagSet, concat(elems)) }

// Integer encodes a minimal two's-complement INTEGER.
func Integer(v int64) []byte { return Encode(ClassUniversal, false, TagInteger, intBytes(v)) }

// Enumerated encodes an ENUMERATED value.
func Enumerated(v int64) []byte { return Encode(ClassUniversal, false, TagEnumerated, intBytes(v)) }

func intBytes(v int64) []byte {
	b := big.NewInt(v)
	if v >= 0 {
		raw := b.Bytes()
		if len(raw) == 0 || raw[0]&0x80 != 0 {
			raw = append([]byte{0}, raw...)
		}
		return raw
	}
	// Two's complement of a negative value in the fewest bytes.
	n := 1
	for ; n < 8; n++ {
		if v >= -(int64(1) << (8*n - 1)) {
			break
		}
	}
	raw := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		raw[i] = byte(v)
		v >>= 8
	}
	return raw
}

// OctetString encodes an OCTET STRING.
func OctetString(b []byte) []byte { return Encode(ClassUniversal, false, TagOctetString, b) }

// Boolean encodes a DER BOOLEAN.
func Boolean(v bool) []byte {
	if v {
		return Encode(ClassUniversal, false, TagBoolean, []byte{0xff})
	}
	return Encode(ClassUniversal, false, TagBoolean, []byte{0})
}

// Null encodes NULL.
func Null() []byte { return Encode(ClassUniversal, false, TagNull, nil) }

// ExplicitTag wraps an encoded element in an explicit context tag.
func ExplicitTag(tag int, inner []byte) []byte { return Encode(ClassContext, true, tag, inner) }
