// Package der reads ASN.1 DER encodings element by element. Unlike
// encoding/asn1 struct decoding it handles high tag numbers (Android
// KeyMint's KeyDescription uses context tags such as [702] and [709]) and
// lets callers skip elements they do not understand, which attestation
// formats need because vendors add fields over time.
package der

import (
	"errors"
	"fmt"
	"math/big"
)

// Classes of an identifier octet.
const (
	ClassUniversal   = 0
	ClassApplication = 1
	ClassContext     = 2
	ClassPrivate     = 3
)

// Universal tags used by attestation structures.
const (
	TagBoolean     = 1
	TagInteger     = 2
	TagBitString   = 3
	TagOctetString = 4
	TagNull        = 5
	TagOID         = 6
	TagEnumerated  = 10
	TagUTF8String  = 12
	TagSequence    = 16
	TagSet         = 17
)

// ErrMalformed reports invalid DER.
var ErrMalformed = errors.New("der: malformed encoding")

// Element is one TLV.
type Element struct {
	Class       int
	Constructed bool
	Tag         int
	Content     []byte
}

// Is reports whether e has the class and tag.
func (e Element) Is(class, tag int) bool { return e.Class == class && e.Tag == tag }

// Reader walks consecutive elements.
type Reader struct {
	b []byte
}

// NewReader reads the elements in b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Empty reports whether all input was consumed.
func (r *Reader) Empty() bool { return len(r.b) == 0 }

// Next reads one element.
func (r *Reader) Next() (Element, error) {
	b := r.b
	if len(b) < 2 {
		return Element{}, fmt.Errorf("%w: truncated header", ErrMalformed)
	}
	id := b[0]
	e := Element{Class: int(id >> 6), Constructed: id&0x20 != 0, Tag: int(id & 0x1f)}
	i := 1
	if e.Tag == 0x1f { // high-tag-number form, base 128
		e.Tag = 0
		for {
			if i >= len(b) {
				return Element{}, fmt.Errorf("%w: truncated tag", ErrMalformed)
			}
			c := b[i]
			i++
			if e.Tag == 0 && c == 0x80 {
				return Element{}, fmt.Errorf("%w: non-minimal tag", ErrMalformed)
			}
			if e.Tag > (1<<23)-1 {
				return Element{}, fmt.Errorf("%w: tag too large", ErrMalformed)
			}
			e.Tag = e.Tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		if e.Tag < 0x1f {
			return Element{}, fmt.Errorf("%w: non-minimal tag", ErrMalformed)
		}
	}
	if i >= len(b) {
		return Element{}, fmt.Errorf("%w: truncated length", ErrMalformed)
	}
	l := int(b[i])
	i++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 {
			return Element{}, fmt.Errorf("%w: indefinite length", ErrMalformed)
		}
		if n > 4 || i+n > len(b) {
			return Element{}, fmt.Errorf("%w: bad length", ErrMalformed)
		}
		l = 0
		for _, c := range b[i : i+n] {
			l = l<<8 | int(c)
		}
		if b[i] == 0 || l < 0x80 {
			return Element{}, fmt.Errorf("%w: non-minimal length", ErrMalformed)
		}
		i += n
	}
	if l > len(b)-i {
		return Element{}, fmt.Errorf("%w: content exceeds input", ErrMalformed)
	}
	e.Content = b[i : i+l]
	r.b = b[i+l:]
	return e, nil
}

// One parses b as exactly one element.
func One(b []byte) (Element, error) {
	r := NewReader(b)
	e, err := r.Next()
	if err != nil {
		return Element{}, err
	}
	if !r.Empty() {
		return Element{}, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	return e, nil
}

// Expect reads one element with the given class and tag.
func (r *Reader) Expect(class, tag int) (Element, error) {
	e, err := r.Next()
	if err != nil {
		return Element{}, err
	}
	if !e.Is(class, tag) {
		return Element{}, fmt.Errorf("%w: got class %d tag %d, want class %d tag %d", ErrMalformed, e.Class, e.Tag, class, tag)
	}
	return e, nil
}

// Int decodes a DER INTEGER (or ENUMERATED) content that fits in int64.
func Int(content []byte) (int64, error) {
	if len(content) == 0 || len(content) > 8 {
		return 0, fmt.Errorf("%w: integer of %d bytes", ErrMalformed, len(content))
	}
	if len(content) > 1 && (content[0] == 0 && content[1]&0x80 == 0 || content[0] == 0xff && content[1]&0x80 != 0) {
		return 0, fmt.Errorf("%w: non-minimal integer", ErrMalformed)
	}
	v := new(big.Int).SetBytes(content)
	if content[0]&0x80 != 0 { // negative two's complement
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(content))))
	}
	if !v.IsInt64() {
		return 0, fmt.Errorf("%w: integer overflow", ErrMalformed)
	}
	return v.Int64(), nil
}

// IntElement reads an INTEGER or ENUMERATED element.
func (r *Reader) IntElement() (int64, error) {
	e, err := r.Next()
	if err != nil {
		return 0, err
	}
	if e.Class != ClassUniversal || (e.Tag != TagInteger && e.Tag != TagEnumerated) {
		return 0, fmt.Errorf("%w: expected integer, got tag %d", ErrMalformed, e.Tag)
	}
	return Int(e.Content)
}

// Explicit unwraps an explicitly tagged element's single inner element.
func Explicit(e Element) (Element, error) {
	if !e.Constructed {
		return Element{}, fmt.Errorf("%w: explicit tag %d is not constructed", ErrMalformed, e.Tag)
	}
	return One(e.Content)
}

// IntSet decodes a SET OF INTEGER.
func IntSet(e Element) ([]int64, error) {
	if !e.Is(ClassUniversal, TagSet) {
		return nil, fmt.Errorf("%w: expected SET", ErrMalformed)
	}
	r := NewReader(e.Content)
	var out []int64
	for !r.Empty() {
		v, err := r.IntElement()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
