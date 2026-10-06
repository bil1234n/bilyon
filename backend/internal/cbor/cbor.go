// Package cbor implements the CBOR (RFC 8949) data model used by Bilyon.
//
// Two decoding modes exist:
//
//   - Deterministic (Decode): the input must be the unique Core
//     Deterministic Encoding (RFC 8949 §4.2.1) of its value: shortest-form
//     heads, definite lengths, map keys sorted by the bytewise order of their
//     encodings, no duplicates, no floats, no trailing bytes. Every signed
//     Bilyon payload (offline artefacts, TxAuth, payment address records) is
//     decoded this way, which removes parser differentials between the Swift,
//     Kotlin, Rust and Go implementations (RFC 0001 §2.1.1).
//   - Well-formed (DecodeWellFormed, DecodeFirstWellFormed): any well-formed
//     definite-length encoding. WebAuthn attestation objects and COSE keys come
//     from third-party authenticators, which emit CTAP2 canonical CBOR (a
//     different key order) or, for some, plain CBOR.
//
// Both modes reject duplicate map keys, indefinite lengths, floating-point
// numbers, invalid UTF-8 and nesting beyond MaxDepth.
//
// Decoded values use these Go types: uint64 (major 0), int64 (major 1),
// []byte, string, []any, Map, Tag, bool and nil (null). Map keys are int64
// or string; Encode also accepts the other integer types.
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf8"
)

// Map is a CBOR map. Keys are int64 or string.
type Map map[any]any

// Tag is a tagged data item (major type 6); COSE_Sign1 is tag 18.
type Tag struct {
	Number  uint64
	Content any
}

// Limits on decoded input.
const (
	MaxDepth = 16
	// MaxItems bounds the number of elements of one array or map.
	MaxItems = 1 << 16
)

const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7

	simpleFalse = 20
	simpleTrue  = 21
	simpleNull  = 22
)

// Errors returned by the decoders.
var (
	ErrNonCanonical = errors.New("cbor: not the deterministic encoding")
	ErrTruncated    = errors.New("cbor: truncated input")
	ErrMalformed    = errors.New("cbor: malformed input")
	ErrUnsupported  = errors.New("cbor: unsupported data item")
)

// Encode returns the deterministic encoding of v.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustEncode is Encode for values whose encodability is a program invariant.
func MustEncode(v any) []byte {
	b, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return b
}

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= math.MaxUint8:
		return append(b, m|24, byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
	case n <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(b, m|27), n)
	}
}

func writeHead(buf *bytes.Buffer, major byte, n uint64) {
	var tmp [9]byte
	buf.Write(appendHead(tmp[:0], major, n))
}

func encodeInt(buf *bytes.Buffer, x int64) {
	if x >= 0 {
		writeHead(buf, majorUint, uint64(x))
		return
	}
	writeHead(buf, majorNegInt, uint64(-(x + 1)))
}

func encode(buf *bytes.Buffer, v any, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: nesting deeper than %d", ErrUnsupported, MaxDepth)
	}
	switch x := v.(type) {
	case nil:
		buf.WriteByte(majorSimple<<5 | simpleNull)
	case bool:
		if x {
			buf.WriteByte(majorSimple<<5 | simpleTrue)
		} else {
			buf.WriteByte(majorSimple<<5 | simpleFalse)
		}
	case uint64:
		writeHead(buf, majorUint, x)
	case uint:
		writeHead(buf, majorUint, uint64(x))
	case uint32:
		writeHead(buf, majorUint, uint64(x))
	case uint16:
		writeHead(buf, majorUint, uint64(x))
	case uint8:
		writeHead(buf, majorUint, uint64(x))
	case int64:
		encodeInt(buf, x)
	case int:
		encodeInt(buf, int64(x))
	case int32:
		encodeInt(buf, int64(x))
	case int16:
		encodeInt(buf, int64(x))
	case int8:
		encodeInt(buf, int64(x))
	case []byte:
		writeHead(buf, majorBytes, uint64(len(x)))
		buf.Write(x)
	case string:
		if !utf8.ValidString(x) {
			return fmt.Errorf("%w: invalid UTF-8 text string", ErrUnsupported)
		}
		writeHead(buf, majorText, uint64(len(x)))
		buf.WriteString(x)
	case []any:
		writeHead(buf, majorArray, uint64(len(x)))
		for _, e := range x {
			if err := encode(buf, e, depth+1); err != nil {
				return err
			}
		}
	case Map:
		type pair struct{ k, v []byte }
		pairs := make([]pair, 0, len(x))
		for k, val := range x {
			if err := checkKeyType(k); err != nil {
				return err
			}
			var kb, vb bytes.Buffer
			if err := encode(&kb, k, depth+1); err != nil {
				return err
			}
			if err := encode(&vb, val, depth+1); err != nil {
				return err
			}
			pairs = append(pairs, pair{kb.Bytes(), vb.Bytes()})
		}
		slices.SortFunc(pairs, func(a, b pair) int { return bytes.Compare(a.k, b.k) })
		for i := 1; i < len(pairs); i++ {
			if bytes.Equal(pairs[i-1].k, pairs[i].k) {
				return fmt.Errorf("%w: duplicate map key", ErrUnsupported) // e.g. int(1) and int64(1)
			}
		}
		writeHead(buf, majorMap, uint64(len(pairs)))
		for _, p := range pairs {
			buf.Write(p.k)
			buf.Write(p.v)
		}
	case Tag:
		writeHead(buf, majorTag, x.Number)
		return encode(buf, x.Content, depth+1)
	default:
		return fmt.Errorf("%w: %T", ErrUnsupported, v)
	}
	return nil
}

func checkKeyType(k any) error {
	switch k.(type) {
	case int64, int, int32, int16, int8, uint64, uint, uint32, uint16, uint8, string:
		return nil
	default:
		return fmt.Errorf("%w: map key of type %T", ErrUnsupported, k)
	}
}

// Decode parses exactly one data item that must be in deterministic form.
func Decode(b []byte) (any, error) {
	return decodeAll(b, true)
}

// DecodeWellFormed parses exactly one well-formed data item.
func DecodeWellFormed(b []byte) (any, error) {
	return decodeAll(b, false)
}

// DecodeFirstWellFormed parses one well-formed data item from the start of
// b and returns it with the number of bytes it occupied. It is used where
// CBOR items are concatenated without length prefixes (WebAuthn
// authenticator data: the credential public key, then extensions).
func DecodeFirstWellFormed(b []byte) (any, int, error) {
	d := decoder{b: b, deterministic: false}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.off, nil
}

func decodeAll(b []byte, deterministic bool) (any, error) {
	d := decoder{b: b, deterministic: deterministic}
	v, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.off != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(b)-d.off)
	}
	return v, nil
}

type decoder struct {
	b             []byte
	off           int
	deterministic bool
}

func (d *decoder) head() (major byte, n uint64, err error) {
	if d.off >= len(d.b) {
		return 0, 0, ErrTruncated
	}
	ib := d.b[d.off]
	d.off++
	major, ai := ib>>5, ib&0x1f
	var size int
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		size = 1
	case ai == 25:
		size = 2
	case ai == 26:
		size = 4
	case ai == 27:
		size = 8
	case ai == 31:
		return 0, 0, fmt.Errorf("%w: indefinite length", ErrUnsupported)
	default:
		return 0, 0, fmt.Errorf("%w: reserved additional information %d", ErrMalformed, ai)
	}
	if len(d.b)-d.off < size {
		return 0, 0, ErrTruncated
	}
	for _, c := range d.b[d.off : d.off+size] {
		n = n<<8 | uint64(c)
	}
	d.off += size
	if major == majorSimple {
		// Floats (ai 25-27) and two-byte simple values never occur in Bilyon
		// or WebAuthn data.
		return 0, 0, fmt.Errorf("%w: float or extended simple value", ErrUnsupported)
	}
	if d.deterministic {
		var minimum uint64
		switch size {
		case 1:
			minimum = 24
		case 2:
			minimum = 1 << 8
		case 4:
			minimum = 1 << 16
		default:
			minimum = 1 << 32
		}
		if n < minimum {
			return 0, 0, fmt.Errorf("%w: head not in shortest form", ErrNonCanonical)
		}
	}
	return major, n, nil
}

func (d *decoder) length(n uint64, bound uint64) (int, error) {
	if n > bound {
		return 0, fmt.Errorf("%w: %d elements", ErrUnsupported, n)
	}
	return int(n), nil
}

func (d *decoder) item(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d", ErrUnsupported, MaxDepth)
	}
	major, n, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case majorUint:
		return n, nil
	case majorNegInt:
		if n > math.MaxInt64 {
			return nil, fmt.Errorf("%w: negative integer below -2^63", ErrUnsupported)
		}
		return -1 - int64(n), nil
	case majorBytes, majorText:
		if n > uint64(len(d.b)-d.off) {
			return nil, ErrTruncated
		}
		raw := d.b[d.off : d.off+int(n)]
		d.off += int(n)
		if major == majorText {
			if !utf8.Valid(raw) {
				return nil, fmt.Errorf("%w: invalid UTF-8 text string", ErrMalformed)
			}
			return string(raw), nil
		}
		return bytes.Clone(raw), nil
	case majorArray:
		count, err := d.length(n, MaxItems)
		if err != nil {
			return nil, err
		}
		// Every element takes at least one byte: never preallocate beyond the input.
		arr := make([]any, 0, min(count, len(d.b)-d.off))
		for range count {
			e, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, e)
		}
		return arr, nil
	case majorMap:
		count, err := d.length(n, MaxItems)
		if err != nil {
			return nil, err
		}
		m := make(Map, min(count, (len(d.b)-d.off)/2))
		var prevKey []byte
		for range count {
			start := d.off
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			keyBytes := d.b[start:d.off]
			if d.deterministic && prevKey != nil && bytes.Compare(prevKey, keyBytes) >= 0 {
				return nil, fmt.Errorf("%w: map keys unsorted or duplicated", ErrNonCanonical)
			}
			prevKey = keyBytes
			var key any
			switch kk := k.(type) {
			case uint64:
				if kk > math.MaxInt64 {
					return nil, fmt.Errorf("%w: map key above 2^63-1", ErrUnsupported)
				}
				key = int64(kk)
			case int64, string:
				key = kk
			default:
				return nil, fmt.Errorf("%w: map key of type %T", ErrUnsupported, k)
			}
			if _, dup := m[key]; dup {
				return nil, fmt.Errorf("%w: duplicate map key %v", ErrMalformed, key)
			}
			val, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			m[key] = val
		}
		return m, nil
	case majorTag:
		content, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		return Tag{Number: n, Content: content}, nil
	default: // majorSimple with ai < 24
		switch n {
		case simpleFalse:
			return false, nil
		case simpleTrue:
			return true, nil
		case simpleNull:
			return nil, nil
		default:
			return nil, fmt.Errorf("%w: simple value %d", ErrUnsupported, n)
		}
	}
}
