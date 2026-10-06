package devicebind

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/attest/x5c"
	"github.com/bil1234n/bilyon/backend/internal/cbor"
)

// App Attest authenticator data AAGUIDs.
var (
	aaguidProduction  = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDevelopment = []byte("appattestdevelop")
)

// AppleConfig configures App Attest verification.
type AppleConfig struct {
	TeamID   string
	BundleID string
	// Roots holds the Apple App Attestation Root CA.
	Roots *x509.CertPool
	// AllowDevelopment accepts the development environment's AAGUID
	// (never in production).
	AllowDevelopment bool
}

func (c AppleConfig) appIDHash() [32]byte { return sha256.Sum256([]byte(c.TeamID + "." + c.BundleID)) }

// appAttestation is the verified content of an App Attest attestation.
type appAttestation struct {
	PublicKey   []byte // x963 point of the App Attest key
	Receipt     []byte
	Development bool // attested in the development environment
}

// verifyAppAttestation implements Apple's attestation validation:
// certificate chain to the App Attestation root, nonce extension
// = SHA-256(authData ‖ clientDataHash), key id = SHA-256(public key),
// rpIdHash = SHA-256(teamID.bundleID), counter 0, App Attest AAGUID, and
// credential id = key id.
func verifyAppAttestation(cfg AppleConfig, keyID, attestation, clientDataHash []byte, now time.Time) (*appAttestation, error) {
	v, err := cbor.DecodeWellFormed(attestation)
	if err != nil {
		return nil, reject("ios.attestation", "decode: %v", err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, reject("ios.attestation", "not a map")
	}
	f := m.Fields()
	format, authData := f.Text("fmt", 32), f.Bytes("authData")
	stmt := f.Map("attStmt")
	if err := f.Done(); err != nil {
		return nil, reject("ios.attestation", "%v", err)
	}
	if format != "apple-appattest" {
		return nil, reject("ios.attestation", "format %q", format)
	}
	sf := stmt.Fields()
	list, receipt := sf.Array("x5c", x5c.MaxChain), sf.Bytes("receipt")
	if err := sf.Done(); err != nil {
		return nil, reject("ios.attestation", "attStmt: %v", err)
	}
	raw := make([][]byte, len(list))
	for i, c := range list {
		b, ok := c.([]byte)
		if !ok {
			return nil, reject("ios.chain", "x5c entry %d is not bytes", i)
		}
		raw[i] = b
	}
	chain, err := x5c.Parse(raw)
	if err != nil {
		return nil, reject("ios.chain", "%v", err)
	}
	if _, err := x5c.Verify(chain, cfg.Roots, now); err != nil {
		return nil, reject("ios.chain", "%v", err)
	}
	nonce, err := x5c.AppleNonce(chain[0])
	if err != nil {
		return nil, reject("ios.nonce", "%v", err)
	}
	want := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	if !bytes.Equal(nonce, want[:]) {
		return nil, reject("ios.nonce", "nonce does not cover authData and the bind client data")
	}
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, reject("ios.key", "credential certificate key is not P-256")
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, reject("ios.key", "%v", err)
	}
	if h := sha256.Sum256(point); !bytes.Equal(h[:], keyID) {
		return nil, reject("ios.key", "key id is not the hash of the attested key")
	}
	if len(authData) < 37+16+2 {
		return nil, reject("ios.authData", "%d bytes", len(authData))
	}
	appID := cfg.appIDHash()
	if !bytes.Equal(authData[:32], appID[:]) {
		return nil, reject("ios.authData", "rpIdHash is not SHA-256(teamID.bundleID)")
	}
	if counter := binary.BigEndian.Uint32(authData[33:37]); counter != 0 {
		return nil, reject("ios.authData", "attestation counter %d", counter)
	}
	aaguid := authData[37:53]
	development := bytes.Equal(aaguid, aaguidDevelopment)
	switch {
	case bytes.Equal(aaguid, aaguidProduction):
	case development && cfg.AllowDevelopment:
	default:
		return nil, reject("ios.authData", "AAGUID %q is not the App Attest production environment", aaguid)
	}
	n := int(binary.BigEndian.Uint16(authData[53:55]))
	if len(authData) < 55+n || !bytes.Equal(authData[55:55+n], keyID) {
		return nil, reject("ios.authData", "credential id is not the key id")
	}
	return &appAttestation{PublicKey: point, Receipt: receipt, Development: development}, nil
}

// verifyAppAssertion checks an App Attest assertion over clientData with
// the stored key and returns its counter, which must exceed stored.
func verifyAppAssertion(cfg AppleConfig, storedKey []byte, stored uint32, assertion, clientData []byte) (uint32, error) {
	v, err := cbor.DecodeWellFormed(assertion)
	if err != nil {
		return 0, reject("ios.assertion", "decode: %v", err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return 0, reject("ios.assertion", "not a map")
	}
	f := m.Fields()
	sig, authData := f.Bytes("signature"), f.Bytes("authenticatorData")
	if err := f.Done(); err != nil {
		return 0, reject("ios.assertion", "%v", err)
	}
	if len(authData) < 37 {
		return 0, reject("ios.assertion", "authenticator data of %d bytes", len(authData))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), storedKey)
	if err != nil {
		return 0, reject("ios.assertion", "stored key: %v", err)
	}
	cdh := sha256.Sum256(clientData)
	nonce := sha256.Sum256(append(append([]byte{}, authData...), cdh[:]...))
	digest := sha256.Sum256(nonce[:]) // the key signs the nonce with ES256
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return 0, reject("ios.assertion", "signature invalid")
	}
	appID := cfg.appIDHash()
	if !bytes.Equal(authData[:32], appID[:]) {
		return 0, reject("ios.assertion", "rpIdHash is not SHA-256(teamID.bundleID)")
	}
	counter := binary.BigEndian.Uint32(authData[33:37])
	if counter <= stored {
		return 0, reject(checkCounter, "counter %d does not exceed %d (replay or cloned key)", counter, stored)
	}
	return counter, nil
}
