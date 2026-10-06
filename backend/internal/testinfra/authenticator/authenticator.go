// Package authenticator is a software FIDO2 authenticator for tests. It
// creates real credentials and real attestation statements (none, packed
// self and x5c, fido-u2f, apple, android-key, tpm, compound) under a test
// attestation CA, and signs assertions, so relying-party code is tested
// against genuine protocol messages rather than stubs.
package authenticator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/attest/androidkey"
	"github.com/bil1234n/bilyon/backend/internal/attest/der"
	"github.com/bil1234n/bilyon/backend/internal/attest/tpm"
	"github.com/bil1234n/bilyon/backend/internal/attest/x5c"
	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

// Authenticator holds an attestation CA and an AAGUID.
type Authenticator struct {
	t      testing.TB
	AAGUID uuid.UUID
	Root   *x509.Certificate
	rootK  *ecdsa.PrivateKey
}

// New creates an authenticator model with its own attestation root.
func New(t testing.TB) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Attestation Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(raw)
	return &Authenticator{t: t, AAGUID: uuid.New(), Root: root, rootK: key}
}

// Pool returns a pool containing the attestation root.
func (a *Authenticator) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.Root)
	return p
}

// Credential is a key pair the authenticator created.
type Credential struct {
	ID        []byte
	Signer    crypto.Signer // *ecdsa.PrivateKey or *rsa.PrivateKey
	Alg       int64
	SignCount uint32
	UserID    []byte // user handle
}

// NewCredential creates a credential; alg is cose.AlgES256 or cose.AlgRS256.
func (a *Authenticator) NewCredential(alg int64) *Credential {
	a.t.Helper()
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		a.t.Fatal(err)
	}
	var s crypto.Signer
	var err error
	if alg == cose.AlgRS256 {
		s, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		a.t.Fatal(err)
	}
	return &Credential{ID: id, Signer: s, Alg: alg}
}

func (c *Credential) coseKey(t testing.TB) []byte {
	raw, err := (&cose.Key{Alg: c.Alg, Public: c.Signer.Public()}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (c *Credential) sign(t testing.TB, data []byte) []byte {
	digest := sha256.Sum256(data)
	var sig []byte
	var err error
	if k, ok := c.Signer.(*rsa.PrivateKey); ok {
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	} else {
		sig, err = ecdsa.SignASN1(rand.Reader, c.Signer.(*ecdsa.PrivateKey), digest[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// Flags of authenticator data.
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	flagAT = 0x40
	flagED = 0x80
)

// Options tweak a ceremony to produce valid or deliberately broken data.
type Options struct {
	Format      string // none (default), packed, packed-self, fido-u2f, apple, android-key, tpm, compound
	Origin      string // default https://<rpID>
	Type        string // client data type override
	Challenge   []byte // override
	CrossOrigin bool
	TopOrigin   string
	RPID        string // rpIdHash source override
	Flags       byte   // default UP|UV
	Extensions  cbor.Map
	// Mutate, when set, can alter the attestation statement after signing.
	Mutate func(stmt cbor.Map)
	// CertTweak edits attestation certificate templates before signing.
	CertTweak func(tmpl *x509.Certificate)
	// KeyDescriptionTweak edits the android-key extension.
	AndroidAllApplications bool
	AndroidOrigin          int64
	TPMManufacturer        string
	TPMExtraData           []byte
}

func clientDataJSON(typ string, challenge []byte, origin string, cross bool, top string) []byte {
	cd := map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin,
		"crossOrigin": cross}
	if top != "" {
		cd["topOrigin"] = top
	}
	raw, _ := json.Marshal(cd)
	return raw
}

func (a *Authenticator) authData(rpID string, flags byte, count uint32, attested []byte, ext cbor.Map) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	if attested != nil {
		flags |= flagAT
	}
	if ext != nil {
		flags |= flagED
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, count)
	out = append(out, attested...)
	if ext != nil {
		out = append(out, cbor.MustEncode(ext)...)
	}
	return out
}

// Register answers creation options.
func (a *Authenticator) Register(cred *Credential, opts *webauthn.CreationOptions, o Options) *webauthn.RegistrationResponse {
	a.t.Helper()
	rpID := opts.RP.ID
	if o.RPID != "" {
		rpID = o.RPID
	}
	origin := o.Origin
	if origin == "" {
		origin = "https://" + opts.RP.ID
	}
	typ := o.Type
	if typ == "" {
		typ = "webauthn.create"
	}
	challenge := opts.Challenge
	if o.Challenge != nil {
		challenge = o.Challenge
	}
	flags := o.Flags
	if flags == 0 {
		flags = FlagUP | FlagUV
	}
	cred.UserID = opts.User.ID
	cdj := clientDataJSON(typ, challenge, origin, o.CrossOrigin, o.TopOrigin)
	cdh := sha256.Sum256(cdj)
	attested := append([]byte{}, a.AAGUID[:]...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(cred.ID)))
	attested = append(attested, cred.ID...)
	attested = append(attested, cred.coseKey(a.t)...)
	ad := a.authData(rpID, flags, cred.SignCount, attested, o.Extensions)
	format := o.Format
	if format == "" {
		format = "none"
	}
	stmt := a.statement(format, cred, ad, cdh[:], o)
	if o.Mutate != nil {
		if m, ok := stmt.(cbor.Map); ok {
			o.Mutate(m)
		}
	}
	wire := format
	if format == "packed-self" {
		wire = "packed"
	}
	attObj := cbor.MustEncode(cbor.Map{"fmt": wire, "attStmt": stmt, "authData": ad})
	resp := &webauthn.RegistrationResponse{ID: base64.RawURLEncoding.EncodeToString(cred.ID), RawID: cred.ID, Type: "public-key"}
	resp.Response.ClientDataJSON = cdj
	resp.Response.AttestationObject = attObj
	resp.Response.Transports = []string{"internal", "hybrid", "bogus"}
	return resp
}

func (a *Authenticator) statement(format string, cred *Credential, ad, cdh []byte, o Options) any {
	signed := append(append([]byte{}, ad...), cdh...)
	switch format {
	case "none":
		return cbor.Map{}
	case "packed-self":
		return cbor.Map{"alg": cred.Alg, "sig": cred.sign(a.t, signed)}
	case "packed":
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := a.leafTemplate(pkix.Name{Country: []string{"US"}, Organization: []string{"Bilyon Test"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Test Packed Batch"})
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, a.aaguidExt())
		leaf := a.issue(tmpl, &key.PublicKey, o)
		digest := sha256.Sum256(signed)
		sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
		return cbor.Map{"alg": int64(cose.AlgES256), "sig": sig, "x5c": []any{leaf}}
	case "fido-u2f":
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leaf := a.issue(a.leafTemplate(pkix.Name{CommonName: "U2F Test"}), &key.PublicKey, o)
		pub, _ := cred.Signer.Public().(*ecdsa.PublicKey).Bytes()
		data := append([]byte{0}, ad[:32]...) // rpIdHash
		data = append(data, cdh...)
		data = append(data, cred.ID...)
		data = append(data, pub...)
		digest := sha256.Sum256(data)
		sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
		return cbor.Map{"x5c": []any{leaf}, "sig": sig}
	case "apple":
		nonce := sha256.Sum256(signed)
		ext, _ := asn1.Marshal(struct {
			Nonce []byte `asn1:"tag:1,explicit"`
		}{nonce[:]})
		tmpl := a.leafTemplate(pkix.Name{CommonName: "Apple Anonymous Test"})
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: x5c.OIDAppleNonce, Value: ext})
		leaf := a.issue(tmpl, cred.Signer.Public(), o)
		return cbor.Map{"x5c": []any{leaf, a.Root.Raw}}
	case "android-key":
		origin := o.AndroidOrigin
		hw := [][]byte{
			der.ExplicitTag(1, der.Set(der.Integer(androidkey.PurposeSign))),
			der.ExplicitTag(2, der.Integer(androidkey.AlgorithmEC)),
			der.ExplicitTag(702, der.Integer(origin)),
		}
		if o.AndroidAllApplications {
			hw = append(hw, der.ExplicitTag(600, der.Null()))
		}
		kd := der.Sequence(der.Integer(300), der.Enumerated(1), der.Integer(300), der.Enumerated(1),
			der.OctetString(cdh), der.OctetString(nil), der.Sequence(), der.Sequence(hw...))
		tmpl := a.leafTemplate(pkix.Name{CommonName: "Android Keystore Key"})
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: androidkey.OID, Value: kd})
		leaf := a.issue(tmpl, cred.Signer.Public(), o)
		return cbor.Map{"alg": cred.Alg, "sig": cred.sign(a.t, signed), "x5c": []any{leaf}}
	case "tpm":
		return a.tpmStatement(cred, signed, o)
	case "compound":
		return []any{
			cbor.Map{"fmt": "packed", "attStmt": a.statement("packed", cred, ad, cdh, o)},
			cbor.Map{"fmt": "packed", "attStmt": a.statement("packed-self", cred, ad, cdh, o)},
		}
	default:
		a.t.Fatalf("unknown format %s", format)
		return nil
	}
}

func (a *Authenticator) aaguidExt() pkix.Extension {
	v, _ := asn1.Marshal(a.AAGUID[:])
	return pkix.Extension{Id: x5c.OIDAAGUID, Value: v}
}

func (a *Authenticator) leafTemplate(subject pkix.Name) *x509.Certificate {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return &x509.Certificate{SerialNumber: n, Subject: subject, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: false,
		KeyUsage: x509.KeyUsageDigitalSignature}
}

func (a *Authenticator) issue(tmpl *x509.Certificate, pub crypto.PublicKey, o Options) []byte {
	if o.CertTweak != nil {
		o.CertTweak(tmpl)
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, a.Root, pub, a.rootK)
	if err != nil {
		a.t.Fatal(err)
	}
	return raw
}

func (a *Authenticator) tpmStatement(cred *Credential, signed []byte, o Options) cbor.Map {
	pub := cred.Signer.Public().(*ecdsa.PublicKey)
	raw, _ := pub.Bytes()
	// TPMT_PUBLIC for an ECC P-256 signing key with SHA-256 name algorithm.
	area := binary.BigEndian.AppendUint16(nil, tpm.AlgECC)
	area = binary.BigEndian.AppendUint16(area, tpm.AlgSHA256)
	area = binary.BigEndian.AppendUint32(area, 0x00060472)  // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|noDA|sign
	area = binary.BigEndian.AppendUint16(area, 0)           // authPolicy (empty)
	area = binary.BigEndian.AppendUint16(area, tpm.AlgNull) // symmetric
	area = binary.BigEndian.AppendUint16(area, tpm.AlgNull) // scheme
	area = binary.BigEndian.AppendUint16(area, tpm.CurveNISTP256)
	area = binary.BigEndian.AppendUint16(area, tpm.AlgNull) // kdf
	area = binary.BigEndian.AppendUint16(area, 32)
	area = append(area, raw[1:33]...)
	area = binary.BigEndian.AppendUint16(area, 32)
	area = append(area, raw[33:]...)
	name, _ := tpm.Name(tpm.AlgSHA256, area)

	extra := o.TPMExtraData
	if extra == nil {
		d := sha256.Sum256(signed)
		extra = d[:]
	}
	info := binary.BigEndian.AppendUint32(nil, tpm.GeneratedValue)
	info = binary.BigEndian.AppendUint16(info, tpm.STAttestCertify)
	signer := []byte{0x00, 0x0b, 1, 2, 3}
	info = binary.BigEndian.AppendUint16(info, uint16(len(signer)))
	info = append(info, signer...)
	info = binary.BigEndian.AppendUint16(info, uint16(len(extra)))
	info = append(info, extra...)
	info = binary.BigEndian.AppendUint64(info, 123456789) // clock
	info = binary.BigEndian.AppendUint32(info, 7)         // resetCount
	info = binary.BigEndian.AppendUint32(info, 1)         // restartCount
	info = append(info, 1)                                // safe
	info = binary.BigEndian.AppendUint64(info, 0x2000000000000)
	info = binary.BigEndian.AppendUint16(info, uint16(len(name)))
	info = append(info, name...)
	info = binary.BigEndian.AppendUint16(info, uint16(len(name)))
	info = append(info, name...)

	aikKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	vendor := o.TPMManufacturer
	if vendor == "" {
		vendor = "id:FFFFF1D0"
	}
	dirName, _ := asn1.Marshal(pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: vendor}},
		{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 2}, Value: "NPCT6xx"}},
		{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 3}, Value: "id:0007"}},
	})
	san := der.Sequence(der.Encode(der.ClassContext, true, 4, dirName))
	tmpl := a.leafTemplate(pkix.Name{})
	tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{2, 23, 133, 8, 3}}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san},
		a.aaguidExt())
	aik := a.issue(tmpl, &aikKey.PublicKey, o)
	digest := sha256.Sum256(info)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, aikKey, crypto.SHA256, digest[:])
	return cbor.Map{"ver": "2.0", "alg": int64(cose.AlgRS256), "x5c": []any{aik}, "sig": sig, "certInfo": info, "pubArea": area}
}

// AssertOptions tweak an assertion.
type AssertOptions struct {
	Origin     string
	Type       string
	Challenge  []byte
	RPID       string
	Flags      byte // default UP|UV
	SignCount  *uint32
	UserHandle []byte // default the credential's user handle; set []byte{} to omit
	BadSig     bool
}

// Assert answers request options with cred.
func (a *Authenticator) Assert(cred *Credential, opts *webauthn.RequestOptions, o AssertOptions) *webauthn.AssertionResponse {
	a.t.Helper()
	rpID := opts.RPID
	if o.RPID != "" {
		rpID = o.RPID
	}
	origin := o.Origin
	if origin == "" {
		origin = "https://" + opts.RPID
	}
	typ := o.Type
	if typ == "" {
		typ = "webauthn.get"
	}
	challenge := opts.Challenge
	if o.Challenge != nil {
		challenge = o.Challenge
	}
	flags := o.Flags
	if flags == 0 {
		flags = FlagUP | FlagUV
	}
	if o.SignCount != nil {
		cred.SignCount = *o.SignCount
	} else if cred.SignCount != 0 { // counter-based authenticators advance; passkeys report 0
		cred.SignCount++
	}
	cdj := clientDataJSON(typ, challenge, origin, false, "")
	ad := a.authData(rpID, flags, cred.SignCount, nil, nil)
	cdh := sha256.Sum256(cdj)
	sig := cred.sign(a.t, append(append([]byte{}, ad...), cdh[:]...))
	if o.BadSig {
		sig = cred.sign(a.t, []byte("something else"))
	}
	resp := &webauthn.AssertionResponse{ID: base64.RawURLEncoding.EncodeToString(cred.ID), RawID: cred.ID, Type: "public-key"}
	resp.Response.ClientDataJSON = cdj
	resp.Response.AuthenticatorData = ad
	resp.Response.Signature = sig
	resp.Response.UserHandle = cred.UserID
	if o.UserHandle != nil {
		resp.Response.UserHandle = o.UserHandle
	}
	return resp
}
