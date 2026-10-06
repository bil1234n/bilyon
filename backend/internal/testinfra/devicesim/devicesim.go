// Package devicesim models attested phones for tests of device binding and
// of everything later signed with bound keys: an App Attest service and a
// Google hardware attestation PKI under throwaway roots, iOS installs with
// an App Attest key, Android devices whose Keystore attests every key it
// generates, and Play Integrity verdicts encrypted and signed with the
// app's test response keys. The artefacts have the wire formats of the
// real ones; nothing on the verifier side is replaced.
package devicesim

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/attest/androidkey"
	"github.com/bil1234n/bilyon/backend/internal/attest/x5c"
	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/keywrap"
)

// Protocol labels, as the Bilyon apps compute them.
const (
	BindDomain      = "bilyon/bind/v1"
	IntegrityDomain = "bilyon/integrity/v1"
)

// Key roles.
const (
	RoleDevice  = "dev"
	RoleGesture = "gest"
	RoleOffline = "off"
	RoleCoin    = "coin"
)

var b64 = base64.RawURLEncoding

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// NewKey creates a P-256 key, as the Secure Enclave or Keystore would.
func NewKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Point returns the SEC1 uncompressed encoding (x963) of a key.
func Point(t testing.TB, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	p, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// CA is a two-level attestation PKI: root → intermediate → leaves.
type CA struct {
	t            testing.TB
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	interKey     *ecdsa.PrivateKey
}

// NewCA creates a root and an intermediate valid around now.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	rootKey, interKey := NewKey(t), NewKey(t)
	now := time.Now()
	rootTmpl := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: name + " Root"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interTmpl := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: name + " Intermediate"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	return &CA{t: t, Root: root, Intermediate: inter, interKey: interKey}
}

// Pool returns a pool holding the root.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Root)
	return p
}

// Issue signs a leaf with the intermediate and returns the chain (leaf,
// intermediate), as devices send it.
func (c *CA) Issue(tmpl *x509.Certificate, pub crypto.PublicKey) [][]byte {
	c.t.Helper()
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, c.Intermediate, pub, c.interKey)
	if err != nil {
		c.t.Fatal(err)
	}
	return [][]byte{leaf, c.Intermediate.Raw}
}

func leafTemplate(t testing.TB, cn string) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
}

// BindClientData is what a binding attests or asserts: BindDomain ‖
// challenge ‖ x963(key).
func BindClientData(challenge, pub []byte) []byte {
	return slices.Concat([]byte(BindDomain), challenge, pub)
}

// IntegrityClientData is what an iOS integrity refresh asserts.
func IntegrityClientData(challenge []byte) []byte {
	return slices.Concat([]byte(IntegrityDomain), challenge)
}

// Apple is the App Attest service for one app.
type Apple struct {
	t        testing.TB
	CA       *CA
	TeamID   string
	BundleID string
}

// NewApple creates an App Attest service with its own root.
func NewApple(t testing.TB) *Apple {
	return &Apple{t: t, CA: NewCA(t, "Test App Attestation"), TeamID: "ABCDE12345", BundleID: "example.bilyon.app"}
}

// AppID is the App Attest relying party: teamID.bundleID.
func (a *Apple) AppID() string { return a.TeamID + "." + a.BundleID }

// IOSDevice is an app install holding an App Attest key.
type IOSDevice struct {
	apple     *Apple
	attestKey *ecdsa.PrivateKey
	// KeyID is the App Attest key id: SHA-256 of its public key.
	KeyID []byte
	// Counter is the App Attest counter of the last assertion.
	Counter uint32
}

// NewDevice installs the app: DCAppAttestService.generateKey().
func (a *Apple) NewDevice() *IOSDevice {
	k := NewKey(a.t)
	id := sha256.Sum256(Point(a.t, k))
	return &IOSDevice{apple: a, attestKey: k, KeyID: id[:]}
}

// Production and development App Attest AAGUIDs.
var (
	AAGUIDProduction  = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	AAGUIDDevelopment = []byte("appattestdevelop")
)

// AttestOptions alter an attestation to provoke verifier failures; the
// zero value is an honest attestation.
type AttestOptions struct {
	Format    string // default "apple-appattest"
	AppID     string // relying party hashed into authData; default teamID.bundleID
	Counter   uint32
	AAGUID    []byte // default production
	CredID    []byte // default the key id
	Nonce     []byte // replaces the nonce extension
	CA        *CA    // issuing PKI; default Apple's
	ExtraStmt bool   // adds an unknown attStmt member
}

// Attest is DCAppAttestService.attestKey(keyId, clientDataHash).
func (d *IOSDevice) Attest(clientDataHash []byte, o AttestOptions) []byte {
	t := d.apple.t
	t.Helper()
	appID := o.AppID
	if appID == "" {
		appID = d.apple.AppID()
	}
	aaguid := o.AAGUID
	if aaguid == nil {
		aaguid = AAGUIDProduction
	}
	credID := o.CredID
	if credID == nil {
		credID = d.KeyID
	}
	coseKey, err := (&cose.Key{Alg: cose.AlgES256, Public: &d.attestKey.PublicKey}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte(appID))
	authData := slices.Concat(rp[:], []byte{0x40})
	authData = binary.BigEndian.AppendUint32(authData, o.Counter)
	authData = append(authData, aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credID)))
	authData = append(authData, credID...)
	authData = append(authData, coseKey...)
	nonce := o.Nonce
	if nonce == nil {
		h := sha256.Sum256(slices.Concat(authData, clientDataHash))
		nonce = h[:]
	}
	ext, err := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{nonce})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := leafTemplate(t, hexID(d.KeyID))
	tmpl.ExtraExtensions = []pkix.Extension{{Id: x5c.OIDAppleNonce, Value: ext}}
	ca := o.CA
	if ca == nil {
		ca = d.apple.CA
	}
	chain := ca.Issue(tmpl, &d.attestKey.PublicKey)
	receipt := make([]byte, 64)
	if _, err := rand.Read(receipt); err != nil {
		t.Fatal(err)
	}
	stmt := cbor.Map{"x5c": []any{chain[0], chain[1]}, "receipt": receipt}
	if o.ExtraStmt {
		stmt["alg"] = int64(-7)
	}
	format := o.Format
	if format == "" {
		format = "apple-appattest"
	}
	return cbor.MustEncode(cbor.Map{"fmt": format, "attStmt": stmt, "authData": authData})
}

func hexID(b []byte) string { return fmt.Sprintf("%x", b) }

// AssertOptions alter an assertion; the zero value is honest.
type AssertOptions struct {
	AppID   string            // default teamID.bundleID
	Counter *uint32           // absolute counter; default the next one
	Signer  *ecdsa.PrivateKey // default the App Attest key
}

// Assert is DCAppAttestService.generateAssertion(keyId,
// clientDataHash: SHA-256(clientData)).
func (d *IOSDevice) Assert(clientData []byte, o AssertOptions) []byte {
	t := d.apple.t
	t.Helper()
	appID := o.AppID
	if appID == "" {
		appID = d.apple.AppID()
	}
	counter := d.Counter + 1
	if o.Counter != nil {
		counter = *o.Counter
	} else {
		d.Counter = counter
	}
	rp := sha256.Sum256([]byte(appID))
	authData := binary.BigEndian.AppendUint32(slices.Concat(rp[:], []byte{0}), counter)
	cdh := sha256.Sum256(clientData)
	nonce := sha256.Sum256(slices.Concat(authData, cdh[:]))
	digest := sha256.Sum256(nonce[:])
	signer := o.Signer
	if signer == nil {
		signer = d.attestKey
	}
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return cbor.MustEncode(cbor.Map{"signature": sig, "authenticatorData": authData})
}

// BindAttestation attests a new install's binding of key.
func (d *IOSDevice) BindAttestation(challenge []byte, key *ecdsa.PrivateKey, o AttestOptions) []byte {
	cdh := sha256.Sum256(BindClientData(challenge, Point(d.apple.t, key)))
	return d.Attest(cdh[:], o)
}

// BindAssertion asserts a known install's binding of key.
func (d *IOSDevice) BindAssertion(challenge []byte, key *ecdsa.PrivateKey, o AssertOptions) []byte {
	return d.Assert(BindClientData(challenge, Point(d.apple.t, key)), o)
}

// Google is the Android attestation PKI and the Play Integrity response
// keys of one app.
type Google struct {
	t           testing.TB
	CA          *CA
	PackageName string
	// SigningCert is the SHA-256 digest of the app signing certificate.
	SigningCert []byte
	// DecryptionKey and VerificationKey are the app's Play Integrity
	// response encryption (AES-256) and signing (P-256) keys.
	DecryptionKey   []byte
	VerificationKey *ecdsa.PrivateKey
}

// NewGoogle creates the Android side with fresh keys.
func NewGoogle(t testing.TB) *Google {
	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		t.Fatal(err)
	}
	cert := sha256.Sum256([]byte("bilyon test app signing certificate"))
	return &Google{t: t, CA: NewCA(t, "Test Android Hardware Attestation"), PackageName: "example.bilyon.app",
		SigningCert: cert[:], DecryptionKey: dk, VerificationKey: NewKey(t)}
}

// AndroidDevice is a phone with a hardware-backed Keystore.
type AndroidDevice struct {
	g          *Google
	StrongBox  bool
	Strong     bool  // Play Integrity reports MEETS_STRONG_INTEGRITY
	OSVersion  int64 // e.g. 150000 for Android 15
	PatchLevel int64 // YYYYMM
	BootKey    []byte
}

// NewDevice creates a locked, verified-boot Android 15 phone patched this
// month.
func (g *Google) NewDevice(strongBox bool) *AndroidDevice {
	boot := sha256.Sum256([]byte("oem verified boot key"))
	now := time.Now().UTC()
	return &AndroidDevice{g: g, StrongBox: strongBox, Strong: true, OSVersion: 150000,
		PatchLevel: int64(now.Year())*100 + int64(now.Month()), BootKey: boot[:]}
}

func i64(v int64) *int64 { return &v }

// Description is the KeyDescription the device's Keystore attests for a
// key of the given role generated with the given attestation challenge.
func (d *AndroidDevice) Description(role string, challenge []byte) *androidkey.KeyDescription {
	level := androidkey.TrustedEnvironment
	if d.StrongBox {
		level = androidkey.StrongBox
	}
	hw := androidkey.AuthorizationList{
		Purpose: []int64{androidkey.PurposeSign}, Algorithm: i64(androidkey.AlgorithmEC), KeySize: i64(256),
		Digest: []int64{4}, ECCurve: i64(androidkey.CurveP256), UserAuthType: i64(androidkey.AuthTypeBiometric),
		UnlockedDeviceRequired: true, Origin: i64(androidkey.OriginGenerated),
		RootOfTrust: &androidkey.RootOfTrust{VerifiedBootKey: d.BootKey, DeviceLocked: true,
			VerifiedBootState: androidkey.VerifiedBootVerified, VerifiedBootHash: make([]byte, 32)},
		OSVersion: i64(d.OSVersion), OSPatchLevel: i64(d.PatchLevel),
	}
	switch role {
	case RoleGesture:
		hw.AuthTimeout = i64(60)
	case RoleCoin:
		hw.UsageCountLimit = i64(1)
		hw.RollbackResistance = true
	}
	return &androidkey.KeyDescription{AttestationVersion: 300, AttestationSecurityLevel: level, KeyMintVersion: 300,
		KeyMintSecurityLevel: level, Challenge: challenge,
		Software: androidkey.AuthorizationList{ApplicationID: &androidkey.ApplicationID{
			Packages:         []androidkey.PackageInfo{{Name: d.g.PackageName, Version: 1}},
			SignatureDigests: [][]byte{d.g.SigningCert}}},
		Hardware: hw}
}

// KeyOptions alter a generated key's attestation.
type KeyOptions struct {
	Tweak       func(*androidkey.KeyDescription)
	NoExtension bool
	CA          *CA // issuing PKI; default Google's
}

// GenerateKey is KeyPairGenerator.generateKeyPair() with
// setAttestationChallenge(challenge), followed by getCertificateChain().
func (d *AndroidDevice) GenerateKey(role string, challenge []byte, o KeyOptions) (*ecdsa.PrivateKey, [][]byte) {
	t := d.g.t
	t.Helper()
	key := NewKey(t)
	kd := d.Description(role, challenge)
	if o.Tweak != nil {
		o.Tweak(kd)
	}
	tmpl := leafTemplate(t, "Android Keystore Key")
	if !o.NoExtension {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: androidkey.OID, Value: kd.Marshal()}}
	}
	ca := o.CA
	if ca == nil {
		ca = d.g.CA
	}
	return key, ca.Issue(tmpl, &key.PublicKey)
}

// IntegrityNonce is the binding nonce: base64url(SHA-256(challenge ‖ key)).
func IntegrityNonce(challenge, pub []byte) string {
	h := sha256.Sum256(slices.Concat(challenge, pub))
	return b64.EncodeToString(h[:])
}

// Verdict is a Play Integrity verdict payload.
type Verdict struct {
	RequestPackageName string
	Nonce              string // classic requests
	RequestHash        string // standard requests
	Timestamp          time.Time
	AppRecognition     string
	PackageName        string
	CertificateDigests []string
	DeviceVerdicts     []string
}

// Verdict is the honest verdict for a request bound to challenge and pub.
func (d *AndroidDevice) Verdict(challenge, pub []byte) Verdict {
	labels := []string{"MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"}
	if d.Strong {
		labels = append(labels, "MEETS_STRONG_INTEGRITY")
	}
	return Verdict{RequestPackageName: d.g.PackageName, Nonce: IntegrityNonce(challenge, pub), Timestamp: time.Now(),
		AppRecognition: "PLAY_RECOGNIZED", PackageName: d.g.PackageName,
		CertificateDigests: []string{b64.EncodeToString(d.g.SigningCert)}, DeviceVerdicts: labels}
}

// TokenOptions alter how a verdict is protected.
type TokenOptions struct {
	EncryptionKey []byte            // default the app's decryption key
	SigningKey    *ecdsa.PrivateKey // default the app's verification key
	JWSAlg        string            // default ES256
}

// Token encodes, signs (JWS ES256) and encrypts (JWE A256KW/A256GCM) a
// verdict, as Google's servers return it.
func (g *Google) Token(v Verdict, o TokenOptions) string {
	t := g.t
	t.Helper()
	doc := map[string]any{
		"requestDetails": map[string]any{"requestPackageName": v.RequestPackageName, "nonce": v.Nonce,
			"requestHash": v.RequestHash, "timestampMillis": strconv.FormatInt(v.Timestamp.UnixMilli(), 10)},
		"appIntegrity": map[string]any{"appRecognitionVerdict": v.AppRecognition, "packageName": v.PackageName,
			"certificateSha256Digest": v.CertificateDigests, "versionCode": "1"},
		"deviceIntegrity": map[string]any{"deviceRecognitionVerdict": v.DeviceVerdicts},
		"accountDetails":  map[string]any{"appLicensingVerdict": "LICENSED"},
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	alg := o.JWSAlg
	if alg == "" {
		alg = "ES256"
	}
	signer := o.SigningKey
	if signer == nil {
		signer = g.VerificationKey
	}
	signingInput := b64.EncodeToString([]byte(`{"alg":"`+alg+`"}`)) + "." + b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	jws := signingInput + "." + b64.EncodeToString(sig)

	kek := o.EncryptionKey
	if kek == nil {
		kek = g.DecryptionKey
	}
	cek := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	wrapped, err := keywrap.Wrap(kek, cek)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	header := b64.EncodeToString([]byte(`{"alg":"A256KW","enc":"A256GCM"}`))
	sealed := gcm.Seal(nil, iv, []byte(jws), []byte(header))
	ct, tag := sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():]
	return header + "." + b64.EncodeToString(wrapped) + "." + b64.EncodeToString(iv) + "." +
		b64.EncodeToString(ct) + "." + b64.EncodeToString(tag)
}

// IntegrityToken is the honest token for a request bound to challenge and
// pub, after tweak edits the verdict.
func (d *AndroidDevice) IntegrityToken(challenge, pub []byte, tweak func(*Verdict)) string {
	v := d.Verdict(challenge, pub)
	if tweak != nil {
		tweak(&v)
	}
	return d.g.Token(v, TokenOptions{})
}
