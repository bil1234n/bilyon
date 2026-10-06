package androidkey

import (
	"slices"

	"github.com/bil1234n/bilyon/backend/internal/attest/der"
)

// Marshal encodes the KeyDescription as DER, the inverse of Parse.
// Authorisation list entries are written in ascending tag order and SET OF
// members in DER order, as KeyMint does. Attestation producers (device
// models in tests, conformance fixtures) use it.
func (kd *KeyDescription) Marshal() []byte {
	return der.Sequence(
		der.Integer(kd.AttestationVersion),
		der.Enumerated(int64(kd.AttestationSecurityLevel)),
		der.Integer(kd.KeyMintVersion),
		der.Enumerated(int64(kd.KeyMintSecurityLevel)),
		der.OctetString(kd.Challenge),
		der.OctetString(kd.UniqueID),
		kd.Software.marshal(),
		kd.Hardware.marshal(),
	)
}

// intSetDER encodes a SET OF INTEGER with members sorted by encoding.
func intSetDER(vs []int64) []byte {
	enc := make([][]byte, len(vs))
	for i, v := range vs {
		enc[i] = der.Integer(v)
	}
	return der.Set(sortedDER(enc)...)
}

// sortedDER orders SET OF members by their encodings (X.690 §11.6).
func sortedDER(enc [][]byte) [][]byte {
	out := slices.Clone(enc)
	slices.SortFunc(out, func(a, b []byte) int {
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] != b[i] {
				return int(a[i]) - int(b[i])
			}
		}
		return len(a) - len(b)
	})
	return out
}

func (l *AuthorizationList) marshal() []byte {
	var e [][]byte
	tagInt := func(tag int, v *int64) {
		if v != nil {
			e = append(e, der.ExplicitTag(tag, der.Integer(*v)))
		}
	}
	tagNull := func(tag int, on bool) {
		if on {
			e = append(e, der.ExplicitTag(tag, der.Null()))
		}
	}
	if l.Purpose != nil {
		e = append(e, der.ExplicitTag(1, intSetDER(l.Purpose)))
	}
	tagInt(2, l.Algorithm)
	tagInt(3, l.KeySize)
	if l.Digest != nil {
		e = append(e, der.ExplicitTag(5, intSetDER(l.Digest)))
	}
	tagInt(10, l.ECCurve)
	tagNull(303, l.RollbackResistance)
	tagInt(405, l.UsageCountLimit)
	tagNull(503, l.NoAuthRequired)
	tagInt(504, l.UserAuthType)
	tagInt(505, l.AuthTimeout)
	tagNull(509, l.UnlockedDeviceRequired)
	tagNull(600, l.AllApplications)
	tagInt(702, l.Origin)
	if r := l.RootOfTrust; r != nil {
		fields := [][]byte{der.OctetString(r.VerifiedBootKey), der.Boolean(r.DeviceLocked),
			der.Enumerated(r.VerifiedBootState)}
		if r.VerifiedBootHash != nil {
			fields = append(fields, der.OctetString(r.VerifiedBootHash))
		}
		e = append(e, der.ExplicitTag(704, der.Sequence(fields...)))
	}
	tagInt(705, l.OSVersion)
	tagInt(706, l.OSPatchLevel)
	if a := l.ApplicationID; a != nil {
		pkgs := make([][]byte, len(a.Packages))
		for i, p := range a.Packages {
			pkgs[i] = der.Sequence(der.OctetString([]byte(p.Name)), der.Integer(p.Version))
		}
		digests := make([][]byte, len(a.SignatureDigests))
		for i, d := range a.SignatureDigests {
			digests[i] = der.OctetString(d)
		}
		inner := der.Sequence(der.Set(sortedDER(pkgs)...), der.Set(sortedDER(digests)...))
		e = append(e, der.ExplicitTag(709, der.OctetString(inner)))
	}
	return der.Sequence(e...)
}
