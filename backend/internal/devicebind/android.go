package devicebind

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/attest/androidkey"
	"github.com/bil1234n/bilyon/backend/internal/attest/x5c"
)

// AndroidConfig configures Android Key Attestation verification.
type AndroidConfig struct {
	PackageName string
	// SigningCertDigests are SHA-256 digests of the app's signing
	// certificates; the attested app must carry one of them.
	SigningCertDigests [][]byte
	// Roots holds the Google hardware attestation roots.
	Roots *x509.CertPool
	// Revoked is the attestation revocation list: lowercase hex serial
	// numbers of revoked or suspended certificates.
	Revoked map[string]bool
	// MaxPatchAgeMonths bounds how old the attested OS patch level may be
	// (default 12).
	MaxPatchAgeMonths int
	// GestureTimeout is the authorisation window of K_gest keys (60 s).
	GestureTimeout time.Duration
}

// androidKey is the outcome of a verified Android key attestation.
type androidKey struct {
	PublicKey     []byte // x963 point
	SecurityLevel string
	PatchLevel    int64
	Description   *androidkey.KeyDescription
}

// patchAge returns how many whole months separate a YYYYMM patch level
// from now.
func patchAge(level int64, now time.Time) (int, error) {
	y, m := level/100, level%100
	if y < 2000 || m < 1 || m > 12 {
		return 0, fmt.Errorf("patch level %d is not YYYYMM", level)
	}
	return (now.Year()-int(y))*12 + int(now.Month()) - int(m), nil
}

// verifyAndroidKey enforces the RFC 0001 §2.2.4 Android table for a key of
// the given role: the chain leads to a Google root and nothing in it is
// revoked; the challenge matches; the key is in a TEE or StrongBox; the
// hardware-enforced list says SIGN, EC P-256 and the role's authentication
// rules; the device booted verified and locked with a recent patch level;
// and the attested application is ours.
func verifyAndroidKey(cfg AndroidConfig, rawChain [][]byte, challenge []byte, role string, now time.Time) (*androidKey, error) {
	chain, err := x5c.Parse(rawChain)
	if err != nil {
		return nil, reject("android.chain", "%v", err)
	}
	if _, err := x5c.Verify(chain, cfg.Roots, now); err != nil {
		return nil, reject("android.chain", "%v", err)
	}
	for i, c := range chain {
		if cfg.Revoked[strings.ToLower(c.SerialNumber.Text(16))] {
			return nil, reject("android.revocation", "certificate %d (serial %x) is revoked", i, c.SerialNumber)
		}
	}
	kd, err := androidkey.FromCertificate(chain[0])
	if err != nil {
		return nil, reject("android.extension", "%v", err)
	}
	if !bytes.Equal(kd.Challenge, challenge) {
		return nil, reject("android.challenge", "attestation challenge is not the bind challenge")
	}
	if kd.AttestationSecurityLevel != androidkey.TrustedEnvironment && kd.AttestationSecurityLevel != androidkey.StrongBox {
		return nil, reject("android.security_level", "attestation security level %s", kd.AttestationSecurityLevel)
	}
	if kd.KeyMintSecurityLevel != kd.AttestationSecurityLevel {
		return nil, reject("android.security_level", "KeyMint level %s differs from attestation level %s",
			kd.KeyMintSecurityLevel, kd.AttestationSecurityLevel)
	}
	hw := &kd.Hardware
	switch {
	case !hw.HasPurpose(androidkey.PurposeSign):
		return nil, reject("android.auth_list", "hardware-enforced purpose lacks SIGN")
	case hw.Algorithm == nil || *hw.Algorithm != androidkey.AlgorithmEC:
		return nil, reject("android.auth_list", "key is not hardware-enforced EC")
	case hw.ECCurve == nil || *hw.ECCurve != androidkey.CurveP256:
		return nil, reject("android.auth_list", "key is not hardware-enforced P-256")
	case kd.Software.AllApplications || hw.AllApplications:
		return nil, reject("android.auth_list", "key is usable by all applications")
	}
	if origin := kd.Union(func(l *androidkey.AuthorizationList) *int64 { return l.Origin }); origin == nil || *origin != androidkey.OriginGenerated {
		return nil, reject("android.auth_list", "key was not generated in the secure hardware")
	}
	if err := checkRoleAuth(cfg, role, kd); err != nil {
		return nil, err
	}
	rot := hw.RootOfTrust
	if rot == nil {
		return nil, reject("android.root_of_trust", "no hardware-enforced root of trust")
	}
	if rot.VerifiedBootState != androidkey.VerifiedBootVerified || !rot.DeviceLocked {
		return nil, reject("android.root_of_trust", "verified boot state %d, bootloader locked %v", rot.VerifiedBootState, rot.DeviceLocked)
	}
	patch := kd.Union(func(l *androidkey.AuthorizationList) *int64 { return l.OSPatchLevel })
	if patch == nil {
		return nil, reject("android.patch_level", "no OS patch level")
	}
	age, err := patchAge(*patch, now)
	maxAge := cfg.MaxPatchAgeMonths
	if maxAge == 0 {
		maxAge = 12
	}
	if err != nil || age < 0 || age > maxAge {
		return nil, reject("android.patch_level", "OS patch level %d is too old or invalid", *patch)
	}
	if err := checkApplication(cfg, kd); err != nil {
		return nil, err
	}
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, reject("android.key", "attested key is not P-256")
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, reject("android.key", "%v", err)
	}
	level := "trusted_environment"
	if kd.AttestationSecurityLevel == androidkey.StrongBox {
		level = "strongbox"
	}
	return &androidKey{PublicKey: point, SecurityLevel: level, PatchLevel: *patch, Description: kd}, nil
}

// checkRoleAuth applies the per-role authentication rules: K_dev and
// K_off need a biometric for every use; K_gest a biometric valid for the
// gesture window; coin keys a hardware-enforced single use with rollback
// resistance (Tier S, §3.A.9).
func checkRoleAuth(cfg AndroidConfig, role string, kd *androidkey.KeyDescription) error {
	hw := &kd.Hardware
	if role == RoleCoin {
		if hw.UsageCountLimit == nil || *hw.UsageCountLimit != 1 {
			return reject("android.auth_list", "coin key lacks a hardware-enforced usage count limit of 1")
		}
		if !hw.RollbackResistance {
			return reject("android.auth_list", "coin key is not rollback resistant in hardware")
		}
		return nil
	}
	if hw.NoAuthRequired || kd.Software.NoAuthRequired {
		return reject("android.auth_list", "key does not require user authentication")
	}
	if hw.UserAuthType == nil || *hw.UserAuthType&androidkey.AuthTypeBiometric == 0 {
		return reject("android.auth_list", "key does not require a strong biometric")
	}
	timeout := hw.AuthTimeout
	switch role {
	case RoleDevice, RoleOffline:
		if timeout != nil && *timeout != 0 {
			return reject("android.auth_list", "%s key has an authentication timeout of %d s", role, *timeout)
		}
	case RoleGesture:
		window := cfg.GestureTimeout
		if window == 0 {
			window = 60 * time.Second
		}
		if timeout == nil || time.Duration(*timeout)*time.Second != window {
			return reject("android.auth_list", "gesture key must allow %s after one biometric", window)
		}
	default:
		return reject("android.role", "unknown key role %q", role)
	}
	return nil
}

func checkApplication(cfg AndroidConfig, kd *androidkey.KeyDescription) error {
	app := kd.Software.ApplicationID
	if app == nil {
		app = kd.Hardware.ApplicationID
	}
	if app == nil {
		return reject("android.application", "no attested application id")
	}
	pkgOK := false
	for _, p := range app.Packages {
		pkgOK = pkgOK || p.Name == cfg.PackageName
	}
	if !pkgOK {
		return reject("android.application", "attested package is not %s", cfg.PackageName)
	}
	for _, d := range app.SignatureDigests {
		for _, want := range cfg.SigningCertDigests {
			if bytes.Equal(d, want) {
				return nil
			}
		}
	}
	return reject("android.application", "attested app is not signed with a configured certificate")
}
