// Package androidkey parses the Android Key Attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17, the KeyMint KeyDescription) carried by the
// leaf certificate of an Android hardware attestation chain. It is used by
// the WebAuthn "android-key" format and by device-key binding (RFC 0001
// §2.2.4), which needs the security level, the hardware-enforced
// authorisation list, the root of trust and the attested application.
package androidkey

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/bil1234n/bilyon/backend/internal/attest/der"
)

// OID is the attestation extension's object identifier.
var OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// ErrNoExtension means the certificate carries no attestation extension.
var ErrNoExtension = errors.New("androidkey: certificate has no key attestation extension")

// SecurityLevel is where a key lives.
type SecurityLevel int64

// Security levels.
const (
	Software           SecurityLevel = 0
	TrustedEnvironment SecurityLevel = 1
	StrongBox          SecurityLevel = 2
)

func (s SecurityLevel) String() string {
	switch s {
	case Software:
		return "Software"
	case TrustedEnvironment:
		return "TrustedEnvironment"
	case StrongBox:
		return "StrongBox"
	default:
		return fmt.Sprintf("SecurityLevel(%d)", int64(s))
	}
}

// KeyMint constants used by verifiers.
const (
	AlgorithmRSA      = 1
	AlgorithmEC       = 3
	CurveP256         = 1
	PurposeSign       = 2
	OriginGenerated   = 0
	AuthTypePassword  = 1
	AuthTypeBiometric = 2

	VerifiedBootVerified   = 0
	VerifiedBootSelfSigned = 1
	VerifiedBootUnverified = 2
	VerifiedBootFailed     = 3
)

// RootOfTrust describes the device's verified boot state.
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState int64
	VerifiedBootHash  []byte
}

// PackageInfo is one attested application package.
type PackageInfo struct {
	Name    string
	Version int64
}

// ApplicationID identifies the app that generated the key.
type ApplicationID struct {
	Packages         []PackageInfo
	SignatureDigests [][]byte // SHA-256 of each signing certificate
}

// AuthorizationList holds the KeyMint tags verifiers use; others are
// accepted and ignored.
type AuthorizationList struct {
	Purpose                []int64
	Algorithm              *int64
	KeySize                *int64
	Digest                 []int64
	ECCurve                *int64
	RollbackResistance     bool
	UsageCountLimit        *int64
	NoAuthRequired         bool
	UserAuthType           *int64
	AuthTimeout            *int64
	UnlockedDeviceRequired bool
	AllApplications        bool
	Origin                 *int64
	RootOfTrust            *RootOfTrust
	OSVersion              *int64
	OSPatchLevel           *int64
	ApplicationID          *ApplicationID
}

// KeyDescription is the attestation extension.
type KeyDescription struct {
	AttestationVersion       int64
	AttestationSecurityLevel SecurityLevel
	KeyMintVersion           int64
	KeyMintSecurityLevel     SecurityLevel
	Challenge                []byte
	UniqueID                 []byte
	Software                 AuthorizationList
	Hardware                 AuthorizationList // "teeEnforced" before KeyMint
}

// FromCertificate finds and parses the extension in cert.
func FromCertificate(cert *x509.Certificate) (*KeyDescription, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OID) {
			return Parse(ext.Value)
		}
	}
	return nil, ErrNoExtension
}

// Parse decodes a DER KeyDescription.
func Parse(b []byte) (*KeyDescription, error) {
	seq, err := der.One(b)
	if err != nil {
		return nil, err
	}
	if !seq.Is(der.ClassUniversal, der.TagSequence) {
		return nil, fmt.Errorf("%w: KeyDescription is not a SEQUENCE", der.ErrMalformed)
	}
	r := der.NewReader(seq.Content)
	kd := &KeyDescription{}
	var lvl int64
	if kd.AttestationVersion, err = r.IntElement(); err != nil {
		return nil, err
	}
	if lvl, err = r.IntElement(); err != nil {
		return nil, err
	}
	kd.AttestationSecurityLevel = SecurityLevel(lvl)
	if kd.KeyMintVersion, err = r.IntElement(); err != nil {
		return nil, err
	}
	if lvl, err = r.IntElement(); err != nil {
		return nil, err
	}
	kd.KeyMintSecurityLevel = SecurityLevel(lvl)
	ch, err := r.Expect(der.ClassUniversal, der.TagOctetString)
	if err != nil {
		return nil, err
	}
	kd.Challenge = ch.Content
	uid, err := r.Expect(der.ClassUniversal, der.TagOctetString)
	if err != nil {
		return nil, err
	}
	kd.UniqueID = uid.Content
	for _, list := range []*AuthorizationList{&kd.Software, &kd.Hardware} {
		e, err := r.Expect(der.ClassUniversal, der.TagSequence)
		if err != nil {
			return nil, err
		}
		if err := parseAuthList(e.Content, list); err != nil {
			return nil, err
		}
	}
	// Later attestation versions may append fields; they are ignored.
	return kd, nil
}

func intPtr(e der.Element) (*int64, error) {
	inner, err := der.Explicit(e)
	if err != nil {
		return nil, err
	}
	if inner.Class != der.ClassUniversal || (inner.Tag != der.TagInteger && inner.Tag != der.TagEnumerated) {
		return nil, fmt.Errorf("%w: tag [%d] is not an integer", der.ErrMalformed, e.Tag)
	}
	v, err := der.Int(inner.Content)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func intSet(e der.Element) ([]int64, error) {
	inner, err := der.Explicit(e)
	if err != nil {
		return nil, err
	}
	return der.IntSet(inner)
}

func null(e der.Element) error {
	inner, err := der.Explicit(e)
	if err != nil {
		return err
	}
	if !inner.Is(der.ClassUniversal, der.TagNull) || len(inner.Content) != 0 {
		return fmt.Errorf("%w: tag [%d] is not NULL", der.ErrMalformed, e.Tag)
	}
	return nil
}

func parseAuthList(b []byte, l *AuthorizationList) error {
	r := der.NewReader(b)
	seen := map[int]bool{}
	for !r.Empty() {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e.Class != der.ClassContext {
			return fmt.Errorf("%w: authorisation list entry of class %d", der.ErrMalformed, e.Class)
		}
		if seen[e.Tag] {
			return fmt.Errorf("%w: duplicate authorisation tag [%d]", der.ErrMalformed, e.Tag)
		}
		seen[e.Tag] = true
		switch e.Tag {
		case 1:
			l.Purpose, err = intSet(e)
		case 2:
			l.Algorithm, err = intPtr(e)
		case 3:
			l.KeySize, err = intPtr(e)
		case 5:
			l.Digest, err = intSet(e)
		case 10:
			l.ECCurve, err = intPtr(e)
		case 303:
			err = null(e)
			l.RollbackResistance = err == nil
		case 405:
			l.UsageCountLimit, err = intPtr(e)
		case 503:
			err = null(e)
			l.NoAuthRequired = err == nil
		case 504:
			l.UserAuthType, err = intPtr(e)
		case 505:
			l.AuthTimeout, err = intPtr(e)
		case 509:
			err = null(e)
			l.UnlockedDeviceRequired = err == nil
		case 600:
			err = null(e)
			l.AllApplications = err == nil
		case 702:
			l.Origin, err = intPtr(e)
		case 704:
			l.RootOfTrust, err = parseRootOfTrust(e)
		case 705:
			l.OSVersion, err = intPtr(e)
		case 706:
			l.OSPatchLevel, err = intPtr(e)
		case 709:
			l.ApplicationID, err = parseApplicationID(e)
		default:
			if !e.Constructed {
				err = fmt.Errorf("%w: tag [%d] is not explicitly tagged", der.ErrMalformed, e.Tag)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func parseRootOfTrust(e der.Element) (*RootOfTrust, error) {
	seq, err := der.Explicit(e)
	if err != nil {
		return nil, err
	}
	if !seq.Is(der.ClassUniversal, der.TagSequence) {
		return nil, fmt.Errorf("%w: RootOfTrust is not a SEQUENCE", der.ErrMalformed)
	}
	r := der.NewReader(seq.Content)
	rot := &RootOfTrust{}
	key, err := r.Expect(der.ClassUniversal, der.TagOctetString)
	if err != nil {
		return nil, err
	}
	rot.VerifiedBootKey = key.Content
	locked, err := r.Expect(der.ClassUniversal, der.TagBoolean)
	if err != nil {
		return nil, err
	}
	if len(locked.Content) != 1 || (locked.Content[0] != 0 && locked.Content[0] != 0xff) {
		return nil, fmt.Errorf("%w: deviceLocked is not a DER BOOLEAN", der.ErrMalformed)
	}
	rot.DeviceLocked = locked.Content[0] == 0xff
	if rot.VerifiedBootState, err = r.IntElement(); err != nil {
		return nil, err
	}
	if !r.Empty() {
		h, err := r.Expect(der.ClassUniversal, der.TagOctetString)
		if err != nil {
			return nil, err
		}
		rot.VerifiedBootHash = h.Content
	}
	return rot, nil
}

func parseApplicationID(e der.Element) (*ApplicationID, error) {
	octets, err := der.Explicit(e)
	if err != nil {
		return nil, err
	}
	if !octets.Is(der.ClassUniversal, der.TagOctetString) {
		return nil, fmt.Errorf("%w: attestationApplicationId is not an OCTET STRING", der.ErrMalformed)
	}
	seq, err := der.One(octets.Content)
	if err != nil {
		return nil, err
	}
	if !seq.Is(der.ClassUniversal, der.TagSequence) {
		return nil, fmt.Errorf("%w: AttestationApplicationId is not a SEQUENCE", der.ErrMalformed)
	}
	r := der.NewReader(seq.Content)
	pkgSet, err := r.Expect(der.ClassUniversal, der.TagSet)
	if err != nil {
		return nil, err
	}
	digSet, err := r.Expect(der.ClassUniversal, der.TagSet)
	if err != nil {
		return nil, err
	}
	id := &ApplicationID{}
	pr := der.NewReader(pkgSet.Content)
	for !pr.Empty() {
		pkg, err := pr.Expect(der.ClassUniversal, der.TagSequence)
		if err != nil {
			return nil, err
		}
		fr := der.NewReader(pkg.Content)
		name, err := fr.Expect(der.ClassUniversal, der.TagOctetString)
		if err != nil {
			return nil, err
		}
		version, err := fr.IntElement()
		if err != nil {
			return nil, err
		}
		id.Packages = append(id.Packages, PackageInfo{Name: string(name.Content), Version: version})
	}
	dr := der.NewReader(digSet.Content)
	for !dr.Empty() {
		d, err := dr.Expect(der.ClassUniversal, der.TagOctetString)
		if err != nil {
			return nil, err
		}
		id.SignatureDigests = append(id.SignatureDigests, d.Content)
	}
	return id, nil
}

// Union returns the value of an optional integer tag from the hardware
// list, falling back to the software list (WebAuthn §8.4 permits either).
func (kd *KeyDescription) Union(get func(*AuthorizationList) *int64) *int64 {
	if v := get(&kd.Hardware); v != nil {
		return v
	}
	return get(&kd.Software)
}

// HasPurpose reports whether list grants purpose p.
func (l *AuthorizationList) HasPurpose(p int64) bool {
	for _, v := range l.Purpose {
		if v == p {
			return true
		}
	}
	return false
}
