package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/attest/androidkey"
	"github.com/bil1234n/bilyon/backend/internal/attest/der"
	"github.com/bil1234n/bilyon/backend/internal/attest/tpm"
	"github.com/bil1234n/bilyon/backend/internal/attest/x5c"
	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
)

// Attestation trust types recorded with a credential. They are
// informational (R9): registration never requires a trusted attestation.
const (
	TrustNone     = "none"     // fmt "none"
	TrustSelf     = "self"     // signed by the credential key itself
	TrustBasic    = "basic"    // certificate chain, signature verified, root unknown
	TrustAttCA    = "attca"    // TPM attestation identity key
	TrustAnonCA   = "anonca"   // anonymising CA (Apple)
	TrustAnchored = "anchored" // chain verified against a configured trust anchor
)

// attestationResult is the outcome of statement verification.
type attestationResult struct {
	Format string
	Trust  string
	Chain  []*x509.Certificate
}

type verifyContext struct {
	ad      *authenticatorData
	cdh     []byte
	anchors *x509.CertPool
	now     time.Time
}

// signedData is authenticatorData ‖ clientDataHash, the bytes every
// attestation signature covers.
func (vc *verifyContext) signedData() []byte {
	out := make([]byte, 0, len(vc.ad.Raw)+len(vc.cdh))
	return append(append(out, vc.ad.Raw...), vc.cdh...)
}

func verifyAttestation(format string, stmt any, vc *verifyContext) (attestationResult, error) {
	if format == "compound" {
		return verifyCompound(stmt, vc)
	}
	m, ok := stmt.(cbor.Map)
	if !ok {
		return attestationResult{}, fail("R9", "%s attStmt is not a map", format)
	}
	var res attestationResult
	var err error
	switch format {
	case "none":
		if len(m) != 0 {
			return attestationResult{}, fail("R9", "none attStmt must be empty")
		}
		res = attestationResult{Trust: TrustNone}
	case "packed":
		res, err = verifyPacked(m, vc)
	case "fido-u2f":
		res, err = verifyU2F(m, vc)
	case "apple":
		res, err = verifyApple(m, vc)
	case "android-key":
		res, err = verifyAndroidKey(m, vc)
	case "tpm":
		res, err = verifyTPM(m, vc)
	default:
		return attestationResult{}, fail("R9", "unsupported attestation format %q", format)
	}
	if err != nil {
		return attestationResult{}, err
	}
	res.Format = format
	if vc.anchors != nil && len(res.Chain) > 0 {
		if _, err := x5c.Verify(res.Chain, vc.anchors, vc.now); err == nil {
			res.Trust = TrustAnchored
		}
	}
	return res, nil
}

func verifyCompound(stmt any, vc *verifyContext) (attestationResult, error) {
	list, ok := stmt.([]any)
	if !ok || len(list) < 2 || len(list) > 8 {
		return attestationResult{}, fail("R9", "compound attStmt must list 2..8 statements")
	}
	var first attestationResult
	for i, item := range list {
		m, ok := item.(cbor.Map)
		if !ok {
			return attestationResult{}, fail("R9", "compound statement %d is not a map", i)
		}
		f := m.Fields()
		format, sub := f.Text("fmt", 32), f.Any("attStmt")
		if err := f.Done(); err != nil {
			return attestationResult{}, fail("R9", "compound statement %d: %v", i, err)
		}
		if format == "compound" {
			return attestationResult{}, fail("R9", "nested compound attestation")
		}
		res, err := verifyAttestation(format, sub, vc)
		if err != nil {
			return attestationResult{}, err
		}
		if i == 0 {
			first = res
		}
	}
	return attestationResult{Format: "compound", Trust: first.Trust, Chain: first.Chain}, nil
}

func chainFrom(list []any) ([]*x509.Certificate, error) {
	raw := make([][]byte, len(list))
	for i, c := range list {
		b, ok := c.([]byte)
		if !ok {
			return nil, fail("R9", "x5c entry %d is not a byte string", i)
		}
		raw[i] = b
	}
	chain, err := x5c.Parse(raw)
	if err != nil {
		return nil, fail("R9", "%v", err)
	}
	return chain, nil
}

func checkAAGUIDExtension(cert *x509.Certificate, want uuid.UUID) error {
	id, present, err := x5c.AAGUID(cert)
	if err != nil {
		return fail("R9", "%v", err)
	}
	if present && id != want {
		return fail("R9", "certificate AAGUID %s differs from authenticator data %s", id, want)
	}
	return nil
}

// verifyPacked implements WebAuthn §8.2.
func verifyPacked(m cbor.Map, vc *verifyContext) (attestationResult, error) {
	f := m.Fields()
	alg, sig := f.Int("alg"), f.Bytes("sig")
	var list []any
	f.Optional("x5c", func() { list = f.Array("x5c", x5c.MaxChain) })
	if err := f.Done(); err != nil {
		return attestationResult{}, fail("R9", "packed attStmt: %v", err)
	}
	if list == nil { // self attestation
		if alg != vc.ad.Key.Alg {
			return attestationResult{}, fail("R9", "self attestation alg %d differs from credential alg %d", alg, vc.ad.Key.Alg)
		}
		if err := vc.ad.Key.VerifySignature(vc.signedData(), sig); err != nil {
			return attestationResult{}, fail("R9", "self attestation signature invalid")
		}
		return attestationResult{Trust: TrustSelf}, nil
	}
	chain, err := chainFrom(list)
	if err != nil {
		return attestationResult{}, err
	}
	leaf := chain[0]
	if err := x5c.VerifySignature(leaf.PublicKey, alg, vc.signedData(), sig); err != nil {
		return attestationResult{}, fail("R9", "packed signature: %v", err)
	}
	if err := checkPackedCertificate(leaf); err != nil {
		return attestationResult{}, err
	}
	if err := checkAAGUIDExtension(leaf, vc.ad.AAGUID); err != nil {
		return attestationResult{}, err
	}
	return attestationResult{Trust: TrustBasic, Chain: chain}, nil
}

// checkPackedCertificate enforces WebAuthn §8.2.1.
func checkPackedCertificate(c *x509.Certificate) error {
	s := c.Subject
	switch {
	case c.Version != 3:
		return fail("R9", "packed certificate version %d", c.Version)
	case len(s.Country) != 1 || len(s.Country[0]) != 2:
		return fail("R9", "packed certificate subject needs a two-letter country")
	case len(s.Organization) != 1 || s.Organization[0] == "":
		return fail("R9", "packed certificate subject needs an organisation")
	case len(s.OrganizationalUnit) != 1 || s.OrganizationalUnit[0] != "Authenticator Attestation":
		return fail("R9", "packed certificate OU must be \"Authenticator Attestation\"")
	case s.CommonName == "":
		return fail("R9", "packed certificate subject needs a common name")
	case c.IsCA:
		return fail("R9", "packed attestation certificate is a CA")
	}
	return nil
}

// verifyU2F implements WebAuthn §8.6.
func verifyU2F(m cbor.Map, vc *verifyContext) (attestationResult, error) {
	f := m.Fields()
	list, sig := f.Array("x5c", 1), f.Bytes("sig")
	if err := f.Done(); err != nil {
		return attestationResult{}, fail("R9", "fido-u2f attStmt: %v", err)
	}
	chain, err := chainFrom(list)
	if err != nil {
		return attestationResult{}, err
	}
	certKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || certKey.Curve != elliptic.P256() {
		return attestationResult{}, fail("R9", "fido-u2f certificate key is not P-256")
	}
	credKey, ok := vc.ad.Key.Public.(*ecdsa.PublicKey)
	if !ok {
		return attestationResult{}, fail("R9", "fido-u2f credential key is not EC2 P-256")
	}
	point, err := credKey.Bytes()
	if err != nil {
		return attestationResult{}, fail("R9", "fido-u2f credential key: %v", err)
	}
	data := []byte{0}
	data = append(data, vc.ad.RPIDHash...)
	data = append(data, vc.cdh...)
	data = append(data, vc.ad.CredentialID...)
	data = append(data, point...)
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(certKey, digest[:], sig) {
		return attestationResult{}, fail("R9", "fido-u2f signature invalid")
	}
	return attestationResult{Trust: TrustBasic, Chain: chain}, nil
}

// verifyApple implements WebAuthn §8.8 (Apple Anonymous).
func verifyApple(m cbor.Map, vc *verifyContext) (attestationResult, error) {
	f := m.Fields()
	list := f.Array("x5c", x5c.MaxChain)
	if err := f.Done(); err != nil {
		return attestationResult{}, fail("R9", "apple attStmt: %v", err)
	}
	chain, err := chainFrom(list)
	if err != nil {
		return attestationResult{}, err
	}
	nonce, err := x5c.AppleNonce(chain[0])
	if err != nil {
		return attestationResult{}, fail("R9", "%v", err)
	}
	want := sha256.Sum256(vc.signedData())
	if !bytes.Equal(nonce, want[:]) {
		return attestationResult{}, fail("R9", "apple nonce does not match")
	}
	if !x5c.SamePublicKey(chain[0].PublicKey, vc.ad.Key.Public) {
		return attestationResult{}, fail("R9", "apple certificate key differs from the credential key")
	}
	return attestationResult{Trust: TrustAnonCA, Chain: chain}, nil
}

// verifyAndroidKey implements WebAuthn §8.4.
func verifyAndroidKey(m cbor.Map, vc *verifyContext) (attestationResult, error) {
	f := m.Fields()
	alg, sig, list := f.Int("alg"), f.Bytes("sig"), f.Array("x5c", x5c.MaxChain)
	if err := f.Done(); err != nil {
		return attestationResult{}, fail("R9", "android-key attStmt: %v", err)
	}
	chain, err := chainFrom(list)
	if err != nil {
		return attestationResult{}, err
	}
	leaf := chain[0]
	if err := x5c.VerifySignature(leaf.PublicKey, alg, vc.signedData(), sig); err != nil {
		return attestationResult{}, fail("R9", "android-key signature: %v", err)
	}
	if !x5c.SamePublicKey(leaf.PublicKey, vc.ad.Key.Public) {
		return attestationResult{}, fail("R9", "android-key certificate key differs from the credential key")
	}
	kd, err := androidkey.FromCertificate(leaf)
	if err != nil {
		return attestationResult{}, fail("R9", "android-key: %v", err)
	}
	if !bytes.Equal(kd.Challenge, vc.cdh) {
		return attestationResult{}, fail("R9", "android-key attestationChallenge is not the client data hash")
	}
	if kd.Software.AllApplications || kd.Hardware.AllApplications {
		return attestationResult{}, fail("R9", "android-key key is usable by all applications")
	}
	origin := kd.Union(func(l *androidkey.AuthorizationList) *int64 { return l.Origin })
	if origin == nil || *origin != androidkey.OriginGenerated {
		return attestationResult{}, fail("R9", "android-key key was not generated on the device")
	}
	if !kd.Hardware.HasPurpose(androidkey.PurposeSign) && !kd.Software.HasPurpose(androidkey.PurposeSign) {
		return attestationResult{}, fail("R9", "android-key key purpose is not SIGN")
	}
	return attestationResult{Trust: TrustBasic, Chain: chain}, nil
}

// TPM attestation identity key certificate identifiers (TCG EK/AIK
// credential profile).
var (
	oidSAN             = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidAIKCertificate  = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
)

// tpmVendors is the TCG TPM vendor ID registry (plus the FIDO conformance
// test vendor).
var tpmVendors = map[string]string{
	"id:414D4400": "AMD", "id:41544D4C": "Atmel", "id:4252434D": "Broadcom", "id:4353434F": "Cisco",
	"id:464C5953": "Flyslice", "id:524F4343": "Fuzhou Rockchip", "id:474F4F47": "Google", "id:48504900": "HPI",
	"id:48504500": "HPE", "id:48495349": "Huawei", "id:49424D00": "IBM", "id:49465800": "Infineon",
	"id:494E5443": "Intel", "id:4C454E00": "Lenovo", "id:4D534654": "Microsoft", "id:4E534D20": "National Semiconductor",
	"id:4E545A00": "Nationz", "id:4E544300": "Nuvoton", "id:51434F4D": "Qualcomm", "id:534D5343": "SMSC",
	"id:53544D20": "STMicroelectronics", "id:534D534E": "Samsung", "id:534E5300": "Sinosun",
	"id:54584E00": "Texas Instruments", "id:57454300": "Winbond", "id:5345414C": "Wisekey",
	"id:FFFFF1D0": "FIDO Alliance conformance",
}

// verifyTPM implements WebAuthn §8.3.
func verifyTPM(m cbor.Map, vc *verifyContext) (attestationResult, error) {
	f := m.Fields()
	ver, alg, list := f.Text("ver", 8), f.Int("alg"), f.Array("x5c", x5c.MaxChain)
	sig, certInfo, pubArea := f.Bytes("sig"), f.Bytes("certInfo"), f.Bytes("pubArea")
	if err := f.Done(); err != nil {
		return attestationResult{}, fail("R9", "tpm attStmt: %v", err)
	}
	if ver != "2.0" {
		return attestationResult{}, fail("R9", "tpm version %q", ver)
	}
	pub, err := tpm.ParsePublic(pubArea)
	if err != nil {
		return attestationResult{}, fail("R9", "tpm pubArea: %v", err)
	}
	key, err := pub.PublicKey()
	if err != nil {
		return attestationResult{}, fail("R9", "tpm pubArea: %v", err)
	}
	if !x5c.SamePublicKey(key, vc.ad.Key.Public) {
		return attestationResult{}, fail("R9", "tpm pubArea key differs from the credential key")
	}
	att, err := tpm.ParseAttest(certInfo)
	if err != nil {
		return attestationResult{}, fail("R9", "tpm certInfo: %v", err)
	}
	if att.Magic != tpm.GeneratedValue {
		return attestationResult{}, fail("R9", "tpm certInfo magic %#x", att.Magic)
	}
	extra, err := x5c.Digest(alg, vc.signedData())
	if err != nil {
		return attestationResult{}, fail("R9", "tpm alg: %v", err)
	}
	if !bytes.Equal(att.ExtraData, extra) {
		return attestationResult{}, fail("R9", "tpm extraData is not the hash of the signed data")
	}
	name, err := tpm.Name(pub.NameAlg, pubArea)
	if err != nil {
		return attestationResult{}, fail("R9", "tpm name: %v", err)
	}
	if !bytes.Equal(att.CertifiedName, name) {
		return attestationResult{}, fail("R9", "tpm certified name does not match pubArea")
	}
	chain, err := chainFrom(list)
	if err != nil {
		return attestationResult{}, err
	}
	aik := chain[0]
	if err := x5c.VerifySignature(aik.PublicKey, alg, certInfo, sig); err != nil {
		return attestationResult{}, fail("R9", "tpm signature: %v", err)
	}
	if err := checkAIKCertificate(aik); err != nil {
		return attestationResult{}, err
	}
	if err := checkAAGUIDExtension(aik, vc.ad.AAGUID); err != nil {
		return attestationResult{}, err
	}
	return attestationResult{Trust: TrustAttCA, Chain: chain}, nil
}

// checkAIKCertificate enforces WebAuthn §8.3.1.
func checkAIKCertificate(c *x509.Certificate) error {
	if c.Version != 3 {
		return fail("R9", "AIK certificate version %d", c.Version)
	}
	if len(c.Subject.Names) != 0 {
		return fail("R9", "AIK certificate subject must be empty")
	}
	if c.IsCA {
		return fail("R9", "AIK certificate is a CA")
	}
	hasEKU := false
	for _, u := range c.UnknownExtKeyUsage {
		hasEKU = hasEKU || u.Equal(oidAIKCertificate)
	}
	if !hasEKU {
		return fail("R9", "AIK certificate lacks the tcg-kp-AIKCertificate EKU")
	}
	attrs, err := tpmSANAttributes(c)
	if err != nil {
		return err
	}
	vendor := attrs[oidTPMManufacturer.String()]
	if _, known := tpmVendors[vendor]; !known {
		return fail("R9", "unknown TPM manufacturer %q", vendor)
	}
	if attrs[oidTPMModel.String()] == "" || attrs[oidTPMVersion.String()] == "" {
		return fail("R9", "AIK certificate SAN lacks TPM model or version")
	}
	return nil
}

// tpmSANAttributes reads the directoryName attributes of the subject
// alternative name extension.
func tpmSANAttributes(c *x509.Certificate) (map[string]string, error) {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		seq, err := der.One(ext.Value)
		if err != nil || !seq.Is(der.ClassUniversal, der.TagSequence) {
			return nil, fail("R9", "malformed AIK subject alternative name")
		}
		out := map[string]string{}
		r := der.NewReader(seq.Content)
		for !r.Empty() {
			gn, err := r.Next()
			if err != nil {
				return nil, fail("R9", "malformed AIK subject alternative name")
			}
			if !gn.Is(der.ClassContext, 4) { // directoryName
				continue
			}
			var rdn pkix.RDNSequence
			if rest, err := asn1.Unmarshal(gn.Content, &rdn); err != nil || len(rest) != 0 {
				return nil, fail("R9", "malformed AIK directoryName")
			}
			for _, set := range rdn {
				for _, atv := range set {
					if s, ok := atv.Value.(string); ok {
						out[atv.Type.String()] = s
					}
				}
			}
		}
		return out, nil
	}
	return nil, fail("R9", "AIK certificate has no subject alternative name")
}

// verifyAssertionSignature checks A4 with the stored COSE key.
func verifyAssertionSignature(coseKey []byte, authData, clientDataJSON, sig []byte) error {
	key, err := cose.ParseKey(coseKey)
	if err != nil {
		return fail("A4", "stored key: %v", err)
	}
	cdh := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), cdh[:]...)
	if err := key.VerifySignature(signed, sig); err != nil {
		return fail("A4", "assertion signature invalid")
	}
	return nil
}
