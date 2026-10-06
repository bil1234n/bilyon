package gatewayapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Bytes is binary data in JSON: unpadded base64url, the encoding WebAuthn,
// COSE carriers and JOSE use.
type Bytes []byte

var b64 = base64.RawURLEncoding.Strict()

// MarshalJSON implements json.Marshaler.
func (b Bytes) MarshalJSON() ([]byte, error) { return json.Marshal(b64.EncodeToString(b)) }

// UnmarshalJSON implements json.Unmarshaler.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("want a base64url string")
	}
	raw, err := b64.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid unpadded base64url")
	}
	*b = raw
	return nil
}

// errBody is a request body the API cannot use.
type errBody struct{ reason string }

func (e *errBody) Error() string { return "invalid request body: " + e.reason }

// decode reads exactly one JSON object with no unknown members from a body
// of at most limit bytes.
func decode(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !bytes.HasPrefix([]byte(ct), []byte("application/json")) {
		return &errBody{reason: "Content-Type must be application/json"}
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return &errBody{reason: fmt.Sprintf("larger than %d bytes", limit)}
		}
		if errors.Is(err, io.EOF) {
			return &errBody{reason: "empty body"}
		}
		return &errBody{reason: err.Error()}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &errBody{reason: "trailing data after the JSON object"}
	}
	return nil
}

func jsonEncode(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

// write sends v as JSON with status.
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// tstamp renders an optional time as RFC 3339 (nil stays absent).
func tstamp(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
