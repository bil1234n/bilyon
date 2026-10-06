package androidkey

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
)

func TestMarshalRoundTripsSample(t *testing.T) {
	kd, err := Parse(sample([]byte("bind-challenge-0123456789abcdef!")))
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(kd.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, kd) {
		t.Fatalf("round trip changed the description:\n got %+v\nwant %+v", back, kd)
	}
}

// randomDescription draws a KeyDescription whose SET OF members are already
// in DER order, so Parse(Marshal(kd)) must equal kd exactly.
func randomDescription(r *rand.Rand) *KeyDescription {
	bytesN := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.UintN(256))
		}
		return b
	}
	opt := func(max int64) *int64 {
		if r.IntN(3) == 0 {
			return nil
		}
		v := r.Int64N(max)
		return &v
	}
	set := func() []int64 {
		if r.IntN(3) == 0 {
			return nil
		}
		var out []int64
		for v := int64(0); v < 8; v++ {
			if r.IntN(2) == 0 {
				out = append(out, v)
			}
		}
		if out == nil {
			out = []int64{int64(r.IntN(8))}
		}
		return out
	}
	list := func() AuthorizationList {
		l := AuthorizationList{Purpose: set(), Algorithm: opt(4), KeySize: opt(4096), Digest: set(), ECCurve: opt(4),
			RollbackResistance: r.IntN(2) == 0, UsageCountLimit: opt(3), NoAuthRequired: r.IntN(2) == 0,
			UserAuthType: opt(4), AuthTimeout: opt(1 << 20), UnlockedDeviceRequired: r.IntN(2) == 0,
			AllApplications: r.IntN(2) == 0, Origin: opt(4), OSVersion: opt(160000), OSPatchLevel: opt(203012)}
		if r.IntN(2) == 0 {
			l.RootOfTrust = &RootOfTrust{VerifiedBootKey: bytesN(32), DeviceLocked: r.IntN(2) == 0,
				VerifiedBootState: r.Int64N(4)}
			if r.IntN(2) == 0 {
				l.RootOfTrust.VerifiedBootHash = bytesN(32)
			}
		}
		if r.IntN(2) == 0 {
			digests := [][]byte{bytesN(32), bytesN(32), bytesN(32)}[:1+r.IntN(3)]
			slices.SortFunc(digests, bytes.Compare)
			l.ApplicationID = &ApplicationID{Packages: []PackageInfo{{Name: "app.example." + string(rune('a'+r.IntN(26))),
				Version: r.Int64N(1 << 40)}}, SignatureDigests: digests}
		}
		return l
	}
	return &KeyDescription{AttestationVersion: r.Int64N(400), AttestationSecurityLevel: SecurityLevel(r.Int64N(3)),
		KeyMintVersion: r.Int64N(400), KeyMintSecurityLevel: SecurityLevel(r.Int64N(3)), Challenge: bytesN(1 + r.IntN(64)),
		UniqueID: bytesN(1 + r.IntN(16)), Software: list(), Hardware: list()}
}

func TestMarshalParseProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(20261006, 17))
	for i := range 2000 {
		kd := randomDescription(r)
		enc := kd.Marshal()
		back, err := Parse(enc)
		if err != nil {
			t.Fatalf("case %d: Parse(Marshal(kd)): %v", i, err)
		}
		if !reflect.DeepEqual(back, kd) {
			t.Fatalf("case %d: round trip changed the description:\n got %+v\nwant %+v", i, back, kd)
		}
		if !bytes.Equal(back.Marshal(), enc) {
			t.Fatalf("case %d: Marshal is not canonical", i)
		}
	}
}

func TestMarshalSortsSets(t *testing.T) {
	kd := &KeyDescription{Challenge: []byte{1}, UniqueID: []byte{2},
		Hardware: AuthorizationList{Purpose: []int64{7, 2, 3}},
		Software: AuthorizationList{ApplicationID: &ApplicationID{
			Packages:         []PackageInfo{{Name: "zz.long.package", Version: 1}, {Name: "a.b", Version: 2}},
			SignatureDigests: [][]byte{{9, 9}, {1, 1}}}}}
	back, err := Parse(kd.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.Hardware.Purpose, []int64{2, 3, 7}) {
		t.Fatalf("purposes %v", back.Hardware.Purpose)
	}
	app := back.Software.ApplicationID
	if app.Packages[0].Name != "a.b" || !bytes.Equal(app.SignatureDigests[0], []byte{1, 1}) {
		t.Fatalf("application id members not in DER order: %+v", app)
	}
}
