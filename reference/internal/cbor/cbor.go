// Package cbor implements the subset of CBOR (RFC 8949) used by the Bilyon
// offline protocol, with Core Deterministic Encoding (RFC 8949 §4.2.1).
//
// Supported data items: unsigned and negative integers, byte strings, text
// strings, arrays, maps with integer keys, and tags. The decoder is strict: it
// rejects any input that is not the unique deterministic encoding of its value
// (non-shortest integers or lengths, indefinite lengths, unsorted or duplicate
// map keys, trailing bytes). Strictness removes parser differentials between
// the Swift, Kotlin, Rust and Go implementations of the same signed payloads.
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

// Map is a CBOR map whose keys are integers (as used by COSE and by every
// Bilyon payload).
type Map map[int64]any

// Tag is a tagged data item (major type 6), e.g. COSE_Sign1 is tag 18.
type Tag struct {
	Number  uint64
	Content any
}

const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	maxDepth    = 16
	maxItemSize = 1 << 20 // 1 MiB: offline packets are a few hundred bytes
)

// Errors returned by Decode.
var (
	ErrNonCanonical = errors.New("cbor: non-deterministic encoding")
	ErrTruncated    = errors.New("cbor: truncated input")
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

// MustEncode is Encode for values built by this module, where a failure is a
// programming error.
func MustEncode(v any) []byte {
	b, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return b
}

func writeHead(buf *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		buf.WriteByte(m | byte(n))
	case n <= 0xff:
		buf.Write([]byte{m | 24, byte(n)})
	case n <= 0xffff:
		buf.WriteByte(m | 25)
		buf.Write(binary.BigEndian.AppendUint16(nil, uint16(n)))
	case n <= 0xffffffff:
		buf.WriteByte(m | 26)
		buf.Write(binary.BigEndian.AppendUint32(nil, uint32(n)))
	default:
		buf.WriteByte(m | 27)
		buf.Write(binary.BigEndian.AppendUint64(nil, n))
	}
}

func encode(buf *bytes.Buffer, v any, depth int) error {
	if depth > maxDepth {
		return ErrUnsupported
	}
	switch x := v.(type) {
	case uint64:
		writeHead(buf, majorUint, x)
	case uint:
		writeHead(buf, majorUint, uint64(x))
	case uint32:
		writeHead(buf, majorUint, uint64(x))
	case int:
		return encode(buf, int64(x), depth)
	case int64:
		if x >= 0 {
			writeHead(buf, majorUint, uint64(x))
		} else {
			writeHead(buf, majorNegInt, uint64(-(x + 1)))
		}
	case []byte:
		writeHead(buf, majorBytes, uint64(len(x)))
		buf.Write(x)
	case string:
		if !utf8.ValidString(x) {
			return fmt.Errorf("cbor: invalid UTF-8 text string")
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
		type kv struct{ k, v []byte }
		pairs := make([]kv, 0, len(x))
		for k, val := range x {
			var kb, vb bytes.Buffer
			if err := encode(&kb, k, depth+1); err != nil {
				return err
			}
			if err := encode(&vb, val, depth+1); err != nil {
				return err
			}
			pairs = append(pairs, kv{kb.Bytes(), vb.Bytes()})
		}
		// §4.2.1: keys sorted by the bytewise lexicographic order of their
		// deterministic encodings.
		sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].k, pairs[j].k) < 0 })
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

// Decode parses exactly one deterministic data item from b.
func Decode(b []byte) (any, error) {
	d := decoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.off != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrNonCanonical, len(b)-d.off)
	}
	return v, nil
}

type decoder struct {
	b   []byte
	off int
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
	default: // 28-30 reserved, 31 indefinite length
		return 0, 0, ErrNonCanonical
	}
	if len(d.b)-d.off < size {
		return 0, 0, ErrTruncated
	}
	for _, c := range d.b[d.off : d.off+size] {
		n = n<<8 | uint64(c)
	}
	d.off += size
	// Shortest-form rule: the argument must not fit in a smaller encoding.
	var minimum uint64
	switch size {
	case 1:
		minimum = 24
	case 2:
		minimum = 0x100
	case 4:
		minimum = 0x10000
	case 8:
		minimum = 0x100000000
	}
	if n < minimum {
		return 0, 0, ErrNonCanonical
	}
	return major, n, nil
}

func (d *decoder) item(depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrUnsupported
	}
	major, n, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case majorUint:
		return n, nil
	case majorNegInt:
		if n > 1<<63-1 {
			return nil, ErrUnsupported
		}
		return -1 - int64(n), nil
	case majorBytes, majorText:
		if n > maxItemSize || uint64(len(d.b)-d.off) < n {
			return nil, ErrTruncated
		}
		raw := d.b[d.off : d.off+int(n)]
		d.off += int(n)
		if major == majorText {
			if !utf8.Valid(raw) {
				return nil, fmt.Errorf("cbor: invalid UTF-8 text string")
			}
			return string(raw), nil
		}
		return append([]byte(nil), raw...), nil
	case majorArray:
		if n > maxItemSize {
			return nil, ErrUnsupported
		}
		arr := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			e, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, e)
		}
		return arr, nil
	case majorMap:
		if n > maxItemSize {
			return nil, ErrUnsupported
		}
		m := make(Map, n)
		var prevKey []byte
		for i := uint64(0); i < n; i++ {
			start := d.off
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			keyBytes := d.b[start:d.off]
			if prevKey != nil && bytes.Compare(prevKey, keyBytes) >= 0 {
				return nil, fmt.Errorf("%w: map keys unsorted or duplicated", ErrNonCanonical)
			}
			prevKey = keyBytes
			var key int64
			switch kk := k.(type) {
			case uint64:
				if kk > 1<<63-1 {
					return nil, ErrUnsupported
				}
				key = int64(kk)
			case int64:
				key = kk
			default:
				return nil, fmt.Errorf("%w: non-integer map key", ErrUnsupported)
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
	default: // major 7: floats and simple values are not used by the protocol
		return nil, ErrUnsupported
	}
}
