// Package jose implements the JSON Object Signing and Encryption subset
// Bilyon uses for HTTP authentication: compact JWS with ES256 (RFC 7515,
// RFC 7518 §3.4), EC P-256 JSON Web Keys and their RFC 7638 thumbprints.
//
// Parsing is strict. Segments are canonical unpadded base64url; header and
// payload are JSON objects without duplicate member names (at any depth);
// "none", unknown critical parameters and malformed signatures are
// rejected; ES256 signatures are the fixed 64-byte r‖s form.
package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Errors.
var (
	ErrMalformed = errors.New("jose: malformed JWS")
	ErrAlgorithm = errors.New("jose: unsupported algorithm")
	ErrSignature = errors.New("jose: signature invalid")
	ErrKey       = errors.New("jose: invalid key")
)

// MaxCompactSize bounds an accepted compact JWS (headers carry them).
const MaxCompactSize = 8 << 10

// B64 is the canonical unpadded base64url encoding JOSE uses.
var B64 = base64.RawURLEncoding.Strict()

// JWK is a public EC P-256 JSON Web Key (RFC 7517, RFC 7518 §6.2).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	// JWK Set metadata (RFC 7517 §4).
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// PublicJWK returns the JWK of a P-256 public key.
func PublicJWK(pub *ecdsa.PublicKey) (JWK, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return JWK{}, fmt.Errorf("%w: not a P-256 key", ErrKey)
	}
	raw, err := pub.Bytes()
	if err != nil {
		return JWK{}, fmt.Errorf("%w: %v", ErrKey, err)
	}
	return JWK{Kty: "EC", Crv: "P-256", X: B64.EncodeToString(raw[1:33]), Y: B64.EncodeToString(raw[33:])}, nil
}

// PublicKey validates the JWK and returns its key: kty EC, crv P-256,
// 32-byte coordinates on the curve.
func (k JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("%w: kty %q crv %q", ErrKey, k.Kty, k.Crv)
	}
	x, errX := B64.DecodeString(k.X)
	y, errY := B64.DecodeString(k.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: coordinates", ErrKey)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	return pub, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url: the hash of
// {"crv":…,"kty":…,"x":…,"y":…} with members in lexicographic order and no
// whitespace. It is what cnf.jkt (RFC 9449) carries.
func (k JWK) Thumbprint() (string, error) {
	if _, err := k.PublicKey(); err != nil {
		return "", err
	}
	canonical := `{"crv":"` + k.Crv + `","kty":"` + k.Kty + `","x":"` + k.X + `","y":"` + k.Y + `"}`
	h := sha256.Sum256([]byte(canonical))
	return B64.EncodeToString(h[:]), nil
}

// Thumbprint returns the RFC 7638 thumbprint of a P-256 public key.
func Thumbprint(pub *ecdsa.PublicKey) (string, error) {
	k, err := PublicJWK(pub)
	if err != nil {
		return "", err
	}
	return k.Thumbprint()
}

// checkUnique walks one JSON value and rejects objects with duplicate
// member names.
func checkUnique(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, _ := key.(string)
			if seen[name] {
				return fmt.Errorf("duplicate member %q", name)
			}
			seen[name] = true
			if err := checkUnique(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkUnique(dec, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// StrictObject checks that raw is exactly one JSON object without
// duplicate member names (at any depth) and returns its members.
func StrictObject(raw []byte) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := checkUnique(dec, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after the object", ErrMalformed)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return members, nil
}

// DecodeStrict checks raw with StrictObject and unmarshals it into v.
func DecodeStrict(raw []byte, v any) error {
	if _, err := StrictObject(raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}

// JWS is a parsed compact JWS whose signature is not yet verified.
type JWS struct {
	Header       map[string]json.RawMessage
	Payload      []byte
	signingInput string
	signature    []byte
}

// Parse splits and decodes a compact JWS.
func Parse(compact string) (*JWS, error) {
	if len(compact) > MaxCompactSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(compact))
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: %d segments", ErrMalformed, len(parts))
	}
	rawHeader, err := B64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	header, err := StrictObject(rawHeader)
	if err != nil {
		return nil, err
	}
	payload, err := B64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	sig, err := B64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	j := &JWS{Header: header, Payload: payload, signingInput: parts[0] + "." + parts[1], signature: sig}
	if _, ok := header["crit"]; ok {
		return nil, fmt.Errorf("%w: critical header parameters are not supported", ErrMalformed)
	}
	alg, ok, err := j.HeaderString("alg")
	if err != nil || !ok || alg == "" {
		return nil, fmt.Errorf("%w: missing alg", ErrMalformed)
	}
	return j, nil
}

// HeaderString returns a string header parameter; ok reports presence.
func (j *JWS) HeaderString(name string) (value string, ok bool, err error) {
	raw, present := j.Header[name]
	if !present {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("%w: header %q is not a string", ErrMalformed, name)
	}
	return value, true, nil
}

// Alg returns the alg header.
func (j *JWS) Alg() string {
	alg, _, _ := j.HeaderString("alg")
	return alg
}

// VerifyES256 checks that alg is ES256 and the signature verifies with pub.
func (j *JWS) VerifyES256(pub *ecdsa.PublicKey) error {
	if j.Alg() != "ES256" {
		return fmt.Errorf("%w: %q", ErrAlgorithm, j.Alg())
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return fmt.Errorf("%w: ES256 needs a P-256 key", ErrKey)
	}
	if len(j.signature) != 64 {
		return fmt.Errorf("%w: ES256 signatures are 64 bytes", ErrSignature)
	}
	digest := sha256.Sum256([]byte(j.signingInput))
	r, s := new(big.Int).SetBytes(j.signature[:32]), new(big.Int).SetBytes(j.signature[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrSignature
	}
	return nil
}

// SignES256 signs payload with key under header (alg is set to ES256) and
// returns the compact serialisation.
func SignES256(key *ecdsa.PrivateKey, header map[string]any, payload []byte) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", fmt.Errorf("%w: ES256 needs a P-256 key", ErrKey)
	}
	h := make(map[string]any, len(header)+1)
	for k, v := range header {
		h[k] = v
	}
	h["alg"] = "ES256"
	rawHeader, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	input := B64.EncodeToString(rawHeader) + "." + B64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + B64.EncodeToString(sig), nil
}
