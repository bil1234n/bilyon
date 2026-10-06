// Package webauthn is Bilyon's FIDO2 / WebAuthn Level 3 relying party
// (RFC 0001 §2.2.2–§2.2.3): passkey registration (steps R1–R10) and
// authentication (A1–A6), with attestation statement verification for the
// none, packed, fido-u2f, apple, android-key, tpm and compound formats.
// Any failed check returns a *VerificationError naming its step.
package webauthn

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
)

// ErrInvalid is the root of every verification failure ("400
// webauthn_invalid").
var ErrInvalid = errors.New("webauthn: invalid")

// VerificationError names the failed step (R1..R10, A1..A6, or a parsing
// stage) for logs; clients only ever see "webauthn_invalid".
type VerificationError struct {
	Step   string
	Reason string
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("webauthn: step %s: %s", e.Step, e.Reason)
}

// Unwrap makes errors.Is(err, ErrInvalid) hold.
func (e *VerificationError) Unwrap() error { return ErrInvalid }

func fail(step, format string, args ...any) error {
	return &VerificationError{Step: step, Reason: fmt.Sprintf(format, args...)}
}

// Bytes is a byte string in the WebAuthn JSON serialisation: base64url
// without padding (padding is tolerated on input).
type Bytes []byte

// MarshalJSON implements json.Marshaler.
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return fmt.Errorf("webauthn: invalid base64url: %w", err)
	}
	*b = raw
	return nil
}

// Authenticator data flags (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flagED = 0x80

	// MaxCredentialIDLen is the largest credential id accepted (R7).
	MaxCredentialIDLen = 1023
)

// authenticatorData is a parsed authData structure.
type authenticatorData struct {
	Raw          []byte
	RPIDHash     []byte
	Flags        byte
	SignCount    uint32
	AAGUID       uuid.UUID
	CredentialID []byte
	KeyRaw       []byte
	Key          *cose.Key
	Extensions   cbor.Map
}

func (a *authenticatorData) up() bool { return a.Flags&flagUP != 0 }
func (a *authenticatorData) uv() bool { return a.Flags&flagUV != 0 }
func (a *authenticatorData) be() bool { return a.Flags&flagBE != 0 }
func (a *authenticatorData) bs() bool { return a.Flags&flagBS != 0 }

// parseAuthenticatorData decodes authData; attested says whether attested
// credential data must be present (registration) or absent (assertion).
func parseAuthenticatorData(b []byte, attested bool) (*authenticatorData, error) {
	if len(b) < 37 {
		return nil, fail("authData", "%d bytes", len(b))
	}
	a := &authenticatorData{Raw: b, RPIDHash: b[:32], Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if (a.Flags&flagAT != 0) != attested {
		return nil, fail("authData", "attested credential data flag is %v", a.Flags&flagAT != 0)
	}
	if a.Flags&flagBS != 0 && a.Flags&flagBE == 0 {
		return nil, fail("authData", "backed up but not backup eligible")
	}
	if attested {
		if len(rest) < 18 {
			return nil, fail("authData", "attested credential data truncated")
		}
		copy(a.AAGUID[:], rest[:16])
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > MaxCredentialIDLen || len(rest) < n {
			return nil, fail("R7", "credential id of %d bytes", n)
		}
		a.CredentialID = rest[:n]
		rest = rest[n:]
		v, used, err := cbor.DecodeFirstWellFormed(rest)
		if err != nil {
			return nil, fail("authData", "credential public key: %v", err)
		}
		m, ok := v.(cbor.Map)
		if !ok {
			return nil, fail("authData", "credential public key is not a map")
		}
		a.KeyRaw = rest[:used]
		if a.Key, err = cose.ParseKeyMap(m); err != nil {
			return nil, fail("R8", "credential public key: %v", err)
		}
		rest = rest[used:]
	}
	if a.Flags&flagED != 0 {
		v, used, err := cbor.DecodeFirstWellFormed(rest)
		if err != nil {
			return nil, fail("authData", "extensions: %v", err)
		}
		m, ok := v.(cbor.Map)
		if !ok {
			return nil, fail("authData", "extensions are not a map")
		}
		a.Extensions = m
		rest = rest[used:]
	}
	if len(rest) != 0 {
		return nil, fail("authData", "%d trailing bytes", len(rest))
	}
	return a, nil
}

// attestationObject is the CBOR map {fmt, attStmt, authData}.
type attestationObject struct {
	Format    string
	Statement any // cbor.Map, or []any for "compound"
	AuthData  []byte
}

func parseAttestationObject(b []byte) (*attestationObject, error) {
	v, err := cbor.DecodeWellFormed(b)
	if err != nil {
		return nil, fail("R4", "attestationObject: %v", err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, fail("R4", "attestationObject is not a map")
	}
	f := m.Fields()
	obj := &attestationObject{Format: f.Text("fmt", 32), Statement: f.Any("attStmt"), AuthData: f.Bytes("authData")}
	if err := f.Done(); err != nil {
		return nil, fail("R4", "attestationObject: %v", err)
	}
	switch obj.Statement.(type) {
	case cbor.Map, []any:
	default:
		return nil, fail("R4", "attStmt has type %T", obj.Statement)
	}
	return obj, nil
}

// clientData is CollectedClientData (WebAuthn §5.8.1).
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin,omitempty"`
	TopOrigin   string `json:"topOrigin,omitempty"`
}

func parseClientData(raw []byte, step string) (*clientData, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, fail(step, "clientDataJSON of %d bytes", len(raw))
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, fail(step, "clientDataJSON: %v", err)
	}
	return &cd, nil
}

// challengeBytes decodes the challenge member (base64url, no padding).
func (cd *clientData) challengeBytes() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(cd.Challenge)
}

// RelyingPartyEntity, UserEntity and the option types mirror the WebAuthn
// L3 JSON serialisation (PublicKeyCredentialCreationOptionsJSON, ...).
type RelyingPartyEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntity identifies the account being registered.
type UserEntity struct {
	ID          Bytes  `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// CredentialParameter is one acceptable algorithm.
type CredentialParameter struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

// CredentialDescriptor names an existing credential.
type CredentialDescriptor struct {
	Type       string   `json:"type"`
	ID         Bytes    `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// AuthenticatorSelection constrains the authenticator.
type AuthenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

// CreationOptions are sent to navigator.credentials.create().
type CreationOptions struct {
	RP                     RelyingPartyEntity     `json:"rp"`
	User                   UserEntity             `json:"user"`
	Challenge              Bytes                  `json:"challenge"`
	PubKeyCredParams       []CredentialParameter  `json:"pubKeyCredParams"`
	Timeout                int64                  `json:"timeout"`
	ExcludeCredentials     []CredentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation"`
	Hints                  []string               `json:"hints,omitempty"`
	Extensions             map[string]any         `json:"extensions,omitempty"`
}

// RequestOptions are sent to navigator.credentials.get().
type RequestOptions struct {
	Challenge        Bytes                  `json:"challenge"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
	Timeout          int64                  `json:"timeout"`
}

// RegistrationResponse is a PublicKeyCredential from create(), JSON form.
type RegistrationResponse struct {
	ID       string `json:"id"`
	RawID    Bytes  `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    Bytes    `json:"clientDataJSON"`
		AttestationObject Bytes    `json:"attestationObject"`
		Transports        []string `json:"transports,omitempty"`
	} `json:"response"`
	AuthenticatorAttachment string         `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any `json:"clientExtensionResults,omitempty"`
}

// AssertionResponse is a PublicKeyCredential from get(), JSON form.
type AssertionResponse struct {
	ID       string `json:"id"`
	RawID    Bytes  `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    Bytes `json:"clientDataJSON"`
		AuthenticatorData Bytes `json:"authenticatorData"`
		Signature         Bytes `json:"signature"`
		UserHandle        Bytes `json:"userHandle,omitempty"`
	} `json:"response"`
	AuthenticatorAttachment string         `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any `json:"clientExtensionResults,omitempty"`
}

// checkCredentialEnvelope enforces id == base64url(rawId) and the type.
func checkCredentialEnvelope(step, id string, rawID []byte, typ string) error {
	if typ != "public-key" {
		return fail(step, "credential type %q", typ)
	}
	if len(rawID) == 0 || len(rawID) > MaxCredentialIDLen {
		return fail(step, "rawId of %d bytes", len(rawID))
	}
	if id != base64.RawURLEncoding.EncodeToString(rawID) {
		return fail(step, "id does not match rawId")
	}
	return nil
}

// validTransports keeps the transport hints WebAuthn defines.
func validTransports(in []string) []string {
	known := map[string]bool{"usb": true, "nfc": true, "ble": true, "smart-card": true, "hybrid": true, "internal": true}
	var out []string
	seen := map[string]bool{}
	for _, t := range in {
		if known[t] && !seen[t] {
			out = append(out, t)
			seen[t] = true
		}
	}
	return out
}

func constantTimeEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
