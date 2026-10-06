package androidkey

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/bil1234n/bilyon/backend/internal/attest/der"
)

func sampleAppID() []byte {
	digest := sha256.Sum256([]byte("signing certificate"))
	return der.Sequence(
		der.Set(der.Sequence(der.OctetString([]byte("example.bilyon")), der.Integer(42))),
		der.Set(der.OctetString(digest[:])),
	)
}

// sample builds a KeyMint v300 KeyDescription for a StrongBox P-256 signing
// key with biometric-per-use authentication.
func sample(challenge []byte, extraHW ...[]byte) []byte {
	sw := der.Sequence(
		der.ExplicitTag(701, der.Integer(1_791_273_600_000)), // creationDateTime (ignored)
		der.ExplicitTag(709, der.OctetString(sampleAppID())),
	)
	hwElems := [][]byte{
		der.ExplicitTag(1, der.Set(der.Integer(PurposeSign))),
		der.ExplicitTag(2, der.Integer(AlgorithmEC)),
		der.ExplicitTag(3, der.Integer(256)),
		der.ExplicitTag(5, der.Set(der.Integer(4))),
		der.ExplicitTag(10, der.Integer(CurveP256)),
		der.ExplicitTag(303, der.Null()),
		der.ExplicitTag(405, der.Integer(1)),
		der.ExplicitTag(504, der.Integer(AuthTypeBiometric)),
		der.ExplicitTag(509, der.Null()),
		der.ExplicitTag(702, der.Integer(OriginGenerated)),
		der.ExplicitTag(704, der.Sequence(der.OctetString(bytes.Repeat([]byte{1}, 32)), der.Boolean(true),
			der.Enumerated(VerifiedBootVerified), der.OctetString(bytes.Repeat([]byte{2}, 32)))),
		der.ExplicitTag(705, der.Integer(150000)),
		der.ExplicitTag(706, der.Integer(202609)),
		der.ExplicitTag(718, der.Integer(20260901)), // vendorPatchLevel: unknown to the parser, skipped
	}
	hwElems = append(hwElems, extraHW...)
	return der.Sequence(der.Integer(300), der.Enumerated(int64(StrongBox)), der.Integer(300),
		der.Enumerated(int64(StrongBox)), der.OctetString(challenge), der.OctetString(nil), sw, der.Sequence(hwElems...))
}

func TestParseKeyMintDescription(t *testing.T) {
	challenge := []byte("bind-challenge-0123456789abcdef!")
	kd, err := Parse(sample(challenge))
	if err != nil {
		t.Fatal(err)
	}
	hw := kd.Hardware
	switch {
	case kd.AttestationVersion != 300 || kd.AttestationSecurityLevel != StrongBox || kd.KeyMintSecurityLevel != StrongBox:
		t.Fatalf("header %+v", kd)
	case !bytes.Equal(kd.Challenge, challenge):
		t.Fatal("challenge")
	case !hw.HasPurpose(PurposeSign) || hw.HasPurpose(1):
		t.Fatalf("purpose %v", hw.Purpose)
	case *hw.Algorithm != AlgorithmEC || *hw.ECCurve != CurveP256 || *hw.KeySize != 256:
		t.Fatal("algorithm")
	case !hw.RollbackResistance || *hw.UsageCountLimit != 1 || hw.NoAuthRequired || hw.AuthTimeout != nil:
		t.Fatal("usage limits")
	case *hw.UserAuthType != AuthTypeBiometric || !hw.UnlockedDeviceRequired:
		t.Fatal("authentication")
	case *hw.Origin != OriginGenerated || *hw.OSPatchLevel != 202609 || *hw.OSVersion != 150000:
		t.Fatal("origin and patch level")
	case hw.RootOfTrust == nil || !hw.RootOfTrust.DeviceLocked || hw.RootOfTrust.VerifiedBootState != VerifiedBootVerified ||
		len(hw.RootOfTrust.VerifiedBootHash) != 32:
		t.Fatalf("root of trust %+v", hw.RootOfTrust)
	case kd.Software.ApplicationID == nil || kd.Software.ApplicationID.Packages[0] != (PackageInfo{"example.bilyon", 42}) ||
		len(kd.Software.ApplicationID.SignatureDigests) != 1:
		t.Fatalf("application id %+v", kd.Software.ApplicationID)
	case kd.Hardware.AllApplications:
		t.Fatal("allApplications")
	}
	if v := kd.Union(func(l *AuthorizationList) *int64 { return l.Origin }); v == nil || *v != OriginGenerated {
		t.Fatal("union lookup")
	}
	if v := kd.Union(func(l *AuthorizationList) *int64 { return l.AuthTimeout }); v != nil {
		t.Fatal("union of an absent tag")
	}
	if StrongBox.String() != "StrongBox" || SecurityLevel(9).String() == "" {
		t.Fatal("security level names")
	}
}

func TestRejectsMalformedDescriptions(t *testing.T) {
	cases := map[string][]byte{
		"duplicate tag":   sample(nil, der.ExplicitTag(2, der.Integer(AlgorithmRSA))),
		"implicit tag":    sample(nil, der.Encode(der.ClassContext, false, 800, []byte{1})),
		"universal entry": sample(nil, der.Integer(5)),
		"not null":        sample(nil, der.ExplicitTag(600, der.Integer(1))),
		"not a sequence":  der.Integer(1),
		"truncated":       sample(nil)[:20],
	}
	for name, b := range cases {
		if _, err := Parse(b); !errors.Is(err, der.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A non-integer value for a known integer tag.
	bad := der.Sequence(der.Integer(3), der.Enumerated(1), der.Integer(4), der.Enumerated(1), der.OctetString(nil),
		der.OctetString(nil), der.Sequence(), der.Sequence(der.ExplicitTag(702, der.Null())))
	if _, err := Parse(bad); !errors.Is(err, der.ErrMalformed) {
		t.Errorf("non-integer origin: %v", err)
	}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "plain"}}
	if _, err := FromCertificate(cert); !errors.Is(err, ErrNoExtension) {
		t.Fatalf("missing extension: %v", err)
	}
	cert.Extensions = []pkix.Extension{{Id: OID, Value: sample([]byte("c"))}}
	if kd, err := FromCertificate(cert); err != nil || string(kd.Challenge) != "c" {
		t.Fatalf("extension in certificate: %v", err)
	}
}
