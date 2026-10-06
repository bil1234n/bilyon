package cbor

import (
	"errors"
	"fmt"
	"math"
)

// ErrSchema reports a value that does not match its closed schema.
var ErrSchema = errors.New("cbor: schema violation")

// SchemaError locates a schema violation.
type SchemaError struct {
	Key    any
	Reason string
}

func (e *SchemaError) Error() string { return fmt.Sprintf("cbor: key %v: %s", e.Key, e.Reason) }

// Unwrap makes errors.Is(err, ErrSchema) hold.
func (e *SchemaError) Unwrap() error { return ErrSchema }

// Fields reads a map against a closed schema: each accessor consumes one
// key, and Done fails on the first type or size error or on any key that
// no accessor read (RFC 0001 §2.1.1: unknown keys are MALFORMED). After an
// error, accessors return zero values.
type Fields struct {
	m    Map
	read map[any]bool
	err  error
}

// Fields starts reading m.
func (m Map) Fields() *Fields { return &Fields{m: m, read: make(map[any]bool, len(m))} }

// keyOf normalises an integer key to int64, the decoder's key type.
func keyOf(k any) any {
	switch x := k.(type) {
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x)
		}
	}
	return k
}

func (f *Fields) fail(k any, format string, args ...any) {
	if f.err == nil {
		f.err = &SchemaError{Key: k, Reason: fmt.Sprintf(format, args...)}
	}
}

func (f *Fields) get(k any, required bool) (any, bool) {
	if f.err != nil {
		return nil, false
	}
	key := keyOf(k)
	v, ok := f.m[key]
	if !ok {
		if required {
			f.fail(k, "missing")
		}
		return nil, false
	}
	f.read[key] = true
	return v, true
}

// Has reports whether k is present, without consuming it.
func (f *Fields) Has(k any) bool {
	_, ok := f.m[keyOf(k)]
	return ok
}

// Uint reads an unsigned integer.
func (f *Fields) Uint(k any) uint64 {
	v, ok := f.get(k, true)
	if !ok {
		return 0
	}
	u, ok := v.(uint64)
	if !ok {
		f.fail(k, "want unsigned integer, got %T", v)
	}
	return u
}

// UintRange reads an unsigned integer in [lo, hi].
func (f *Fields) UintRange(k any, lo, hi uint64) uint64 {
	u := f.Uint(k)
	if f.err == nil && (u < lo || u > hi) {
		f.fail(k, "value %d outside %d..%d", u, lo, hi)
	}
	return u
}

// Int reads a signed integer (either major type).
func (f *Fields) Int(k any) int64 {
	v, ok := f.get(k, true)
	if !ok {
		return 0
	}
	switch x := v.(type) {
	case int64:
		return x
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x)
		}
		f.fail(k, "integer above 2^63-1")
	default:
		f.fail(k, "want integer, got %T", v)
	}
	return 0
}

// Bytes reads a byte string of any length.
func (f *Fields) Bytes(k any) []byte {
	v, ok := f.get(k, true)
	if !ok {
		return nil
	}
	b, ok := v.([]byte)
	if !ok {
		f.fail(k, "want byte string, got %T", v)
	}
	return b
}

// BytesN reads a byte string of exactly n bytes.
func (f *Fields) BytesN(k any, n int) []byte {
	b := f.Bytes(k)
	if f.err == nil && len(b) != n {
		f.fail(k, "want %d bytes, got %d", n, len(b))
	}
	return b
}

// BytesMax reads a byte string of at most max bytes.
func (f *Fields) BytesMax(k any, max int) []byte {
	b := f.Bytes(k)
	if f.err == nil && len(b) > max {
		f.fail(k, "%d bytes exceed %d", len(b), max)
	}
	return b
}

// Text reads a text string of at most max bytes (max < 0: unbounded).
func (f *Fields) Text(k any, max int) string {
	v, ok := f.get(k, true)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		f.fail(k, "want text string, got %T", v)
		return ""
	}
	if max >= 0 && len(s) > max {
		f.fail(k, "%d bytes exceed %d", len(s), max)
	}
	return s
}

// Bool reads a boolean.
func (f *Fields) Bool(k any) bool {
	v, ok := f.get(k, true)
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		f.fail(k, "want boolean, got %T", v)
	}
	return b
}

// Array reads an array of at most max elements (max < 0: unbounded).
func (f *Fields) Array(k any, max int) []any {
	v, ok := f.get(k, true)
	if !ok {
		return nil
	}
	a, ok := v.([]any)
	if !ok {
		f.fail(k, "want array, got %T", v)
		return nil
	}
	if max >= 0 && len(a) > max {
		f.fail(k, "%d elements exceed %d", len(a), max)
	}
	return a
}

// Map reads a nested map.
func (f *Fields) Map(k any) Map {
	v, ok := f.get(k, true)
	if !ok {
		return nil
	}
	m, ok := v.(Map)
	if !ok {
		f.fail(k, "want map, got %T", v)
	}
	return m
}

// Any reads a value of any type.
func (f *Fields) Any(k any) any {
	v, _ := f.get(k, true)
	return v
}

// Fail records a semantic error found by the caller for key k.
func (f *Fields) Fail(k any, reason string) { f.fail(k, "%s", reason) }

// Err returns the first error so far.
func (f *Fields) Err() error { return f.err }

// Done returns the first error, or an error naming a key nobody read.
func (f *Fields) Done() error {
	if f.err != nil {
		return f.err
	}
	for k := range f.m {
		if !f.read[k] {
			return &SchemaError{Key: k, Reason: "unknown key"}
		}
	}
	return nil
}

// Optional runs read only when k is present, so optional fields can use
// the same accessors.
func (f *Fields) Optional(k any, read func()) {
	if f.Has(k) {
		read()
	}
}
