// Package devicebind binds hardware keys to attested app installs (RFC 0001
// §2.2.4): K_dev, K_gest and K_off keys in the Secure Enclave, StrongBox or
// the TEE.
//
// On iOS a new device presents the App Attest attestation of a fresh App
// Attest key; every later key on that device is vouched for by an App
// Attest assertion whose counter must strictly increase. On Android every
// key carries its own Key Attestation chain, and every binding is backed by
// a Play Integrity verdict decrypted and verified locally. Tier S coin keys
// (§3.A.9) are attested in batches with a strong-integrity verdict.
//
// All bindings run in single-use challenge flows. A failed check is a
// *BindError naming it; errors.Is(err, ErrRejected) holds for all of them.
package devicebind

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bil1234n/bilyon/backend/internal/attest/androidkey"
	"github.com/bil1234n/bilyon/backend/internal/platform/onetime"
)

// Key roles.
const (
	RoleDevice  = "dev"  // K_dev: biometric per use, signs money movements
	RoleGesture = "gest" // K_gest: valid for the gesture window after one biometric
	RoleOffline = "off"  // K_off(aid): one per offline allowance
	RoleCoin    = "coin" // Tier S single-use coin key; attested, never stored as a device key
)

// Platforms.
const (
	PlatformIOS     = "ios"
	PlatformAndroid = "android"
)

// Security levels of a bound key.
const (
	LevelSecureEnclave = "secure_enclave" // asserted by attested app code (iOS cannot attest key location)
	LevelTEE           = "trusted_environment"
	LevelStrongBox     = "strongbox"
)

// Domain labels of the bytes a device attests or asserts.
const (
	// BindDomain: a binding covers BindDomain ‖ challenge ‖ x963(key).
	BindDomain = "bilyon/bind/v1"
	// IntegrityDomain: an iOS integrity refresh asserts IntegrityDomain ‖ challenge.
	IntegrityDomain = "bilyon/integrity/v1"
)

// MaxCoins bounds the coin keys of one Tier S allowance (§3.A.9).
const MaxCoins = 64

// minCoinOSVersion is Android 12, the first release whose KeyMint enforces
// usage count limits (§3.A.1).
const minCoinOSVersion = 120000

// checkCounter names the App Attest counter check; failing it raises a
// clone signal.
const checkCounter = "ios.counter"

// Errors.
var (
	// ErrRejected is the root of every failed attestation check.
	ErrRejected = errors.New("devicebind: attestation rejected")
	// ErrFlow means the flow never existed, expired or was already used.
	ErrFlow = errors.New("devicebind: binding flow not found, expired or already used")
	// ErrNotFound means no such device or key belongs to the user.
	ErrNotFound = errors.New("devicebind: not found")
	// ErrRevoked means the device or key was revoked.
	ErrRevoked = errors.New("devicebind: revoked")
	// ErrKeyExists means the public key is already bound.
	ErrKeyExists = errors.New("devicebind: key already bound")
	// ErrPlatform means binding is not configured for the platform.
	ErrPlatform = errors.New("devicebind: platform not configured")
	// ErrRequest means the request is malformed (wrong fields for the flow).
	ErrRequest = errors.New("devicebind: invalid request")
)

// BindError reports the check that failed. Clients see only that binding
// failed; Check and Reason go to logs.
type BindError struct {
	Check  string
	Reason string
}

func (e *BindError) Error() string { return "devicebind: " + e.Check + ": " + e.Reason }

// Unwrap makes errors.Is(err, ErrRejected) hold.
func (e *BindError) Unwrap() error { return ErrRejected }

func reject(check, format string, args ...any) error {
	return &BindError{Check: check, Reason: fmt.Sprintf(format, args...)}
}

func badRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRequest, fmt.Sprintf(format, args...))
}

// Purpose is what a challenge may be used for.
type Purpose string

// Flow purposes.
const (
	PurposeBind      Purpose = "bind"      // bind a K_dev, K_gest or K_off key
	PurposeCoins     Purpose = "coins"     // attest Tier S coin keys
	PurposeIntegrity Purpose = "integrity" // refresh a device's integrity evidence
)

// Config configures the binding service.
type Config struct {
	// Apple enables iOS binding when Apple.Roots is set.
	Apple AppleConfig
	// Android enables Android binding when Android.Roots is set; Integrity
	// is then required.
	Android   AndroidConfig
	Integrity *IntegrityConfig
	// ChallengeTTL bounds a flow's lifetime (default 5 minutes: key
	// generation and an integrity verdict take a few seconds each).
	ChallengeTTL time.Duration
	Now          func() time.Time
}

// Service runs binding flows.
type Service struct {
	cfg   Config
	flows *onetime.Store[flow]
	db    *store
}

// flow is the server-side state of one challenge.
type flow struct {
	Purpose   Purpose   `json:"k"`
	UserID    uuid.UUID `json:"u"`
	DeviceID  uuid.UUID `json:"d"` // uuid.Nil: a new device
	Platform  string    `json:"p,omitempty"`
	Challenge []byte    `json:"c"`
	Expires   time.Time `json:"e"`
}

// New validates the configuration and returns a service that keeps flows
// in Redis and devices in the migrated gateway database.
func New(cfg Config, rdb redis.UniversalClient, pool *pgxpool.Pool) (*Service, error) {
	if cfg.Apple.Roots == nil && cfg.Android.Roots == nil {
		return nil, errors.New("devicebind: neither iOS nor Android binding is configured")
	}
	if cfg.Apple.Roots != nil {
		if cfg.Apple.TeamID == "" || strings.Contains(cfg.Apple.TeamID, ".") || cfg.Apple.BundleID == "" {
			return nil, errors.New("devicebind: Apple team and bundle ids are required")
		}
	}
	if cfg.Android.Roots != nil {
		if cfg.Android.PackageName == "" {
			return nil, errors.New("devicebind: Android package name is required")
		}
		if len(cfg.Android.SigningCertDigests) == 0 {
			return nil, errors.New("devicebind: at least one Android signing certificate digest is required")
		}
		for _, d := range cfg.Android.SigningCertDigests {
			if len(d) != sha256.Size {
				return nil, errors.New("devicebind: signing certificate digests are SHA-256")
			}
		}
		ic := cfg.Integrity
		if ic == nil {
			return nil, errors.New("devicebind: Android binding requires Play Integrity verification keys")
		}
		if len(ic.DecryptionKey) != 32 {
			return nil, errors.New("devicebind: the Play Integrity decryption key is 32 bytes")
		}
		if ic.VerificationKey == nil || ic.VerificationKey.Curve != elliptic.P256() {
			return nil, errors.New("devicebind: the Play Integrity verification key is P-256")
		}
		copied := *ic
		if copied.PackageName == "" {
			copied.PackageName = cfg.Android.PackageName
		}
		if copied.PackageName != cfg.Android.PackageName {
			return nil, errors.New("devicebind: Play Integrity and Android package names differ")
		}
		cfg.Integrity = &copied
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg, flows: onetime.New[flow](rdb, "bilyon:devicebind:flow:"), db: &store{pool: pool}}, nil
}

// Challenge is an issued flow.
type Challenge struct {
	FlowID    string
	Challenge []byte // 32 random bytes
	Expires   time.Time
}

// Begin issues a challenge. deviceID is uuid.Nil to register a new device
// (only for PurposeBind); otherwise it names one of the user's active
// devices. The caller has authenticated the user, and requires step-up for
// re-binding (§2.2.7).
func (s *Service) Begin(ctx context.Context, userID, deviceID uuid.UUID, purpose Purpose) (Challenge, error) {
	f := flow{Purpose: purpose, UserID: userID, DeviceID: deviceID}
	switch purpose {
	case PurposeBind, PurposeCoins, PurposeIntegrity:
	default:
		return Challenge{}, badRequest("unknown purpose %q", purpose)
	}
	if deviceID == uuid.Nil {
		if purpose != PurposeBind {
			return Challenge{}, badRequest("purpose %q needs a device", purpose)
		}
	} else {
		d, err := s.ownedDevice(ctx, userID, deviceID)
		if err != nil {
			return Challenge{}, err
		}
		if purpose == PurposeCoins && d.Platform != PlatformAndroid {
			return Challenge{}, badRequest("Tier S coins need an Android device")
		}
		f.Platform = d.Platform
	}
	f.Challenge = make([]byte, 32)
	if _, err := rand.Read(f.Challenge); err != nil {
		return Challenge{}, err
	}
	rawID := make([]byte, 16)
	if _, err := rand.Read(rawID); err != nil {
		return Challenge{}, err
	}
	f.Expires = s.cfg.Now().Add(s.cfg.ChallengeTTL).UTC()
	id := base64.RawURLEncoding.EncodeToString(rawID)
	if err := s.flows.Put(ctx, id, f, s.cfg.ChallengeTTL); err != nil {
		return Challenge{}, err
	}
	return Challenge{FlowID: id, Challenge: f.Challenge, Expires: f.Expires}, nil
}

// take consumes a flow and checks its purpose, its lifetime and that the
// authenticated caller is the user who began it: a leaked flow id cannot
// bind a key to someone else's account.
func (s *Service) take(ctx context.Context, userID uuid.UUID, flowID string, purpose Purpose) (flow, error) {
	f, err := s.flows.Take(ctx, flowID)
	if errors.Is(err, onetime.ErrNotFound) {
		return flow{}, ErrFlow
	}
	if err != nil {
		return flow{}, err
	}
	if f.Purpose != purpose || !s.cfg.Now().Before(f.Expires) || f.UserID != userID {
		return flow{}, ErrFlow
	}
	return f, nil
}

func (s *Service) ownedDevice(ctx context.Context, userID, deviceID uuid.UUID) (Device, error) {
	d, err := s.db.device(ctx, s.db.pool, deviceID)
	if err != nil {
		return Device{}, err
	}
	if d.UserID != userID {
		return Device{}, ErrNotFound
	}
	if d.RevokedAt != nil {
		return Device{}, ErrRevoked
	}
	return d, nil
}

// parsePoint validates an uncompressed P-256 point.
func parsePoint(pub []byte) error {
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub); err != nil {
		return badRequest("public key is not an uncompressed P-256 point")
	}
	return nil
}

func bindPreimage(challenge, pub []byte) []byte {
	return slices.Concat([]byte(BindDomain), challenge, pub)
}

func checkRole(role string) error {
	switch role {
	case RoleDevice, RoleGesture, RoleOffline:
		return nil
	default:
		return badRequest("role %q cannot be bound", role)
	}
}

// Binding is the outcome of a successful binding.
type Binding struct {
	Device Device
	Key    Key
}

// IOSBinding binds a Secure Enclave key on iOS. A new device presents the
// App Attest attestation of a fresh App Attest key with clientDataHash =
// SHA-256(BindDomain ‖ challenge ‖ x963(PublicKey)); a known device
// presents an App Attest assertion over BindDomain ‖ challenge ‖
// x963(PublicKey).
type IOSBinding struct {
	Role           string
	PublicKey      []byte // x963 P-256 point
	AppAttestKeyID []byte // new device: SHA-256 of the App Attest public key
	Attestation    []byte // new device: the App Attest attestation object
	Assertion      []byte // known device: an App Attest assertion
}

// FinishIOS verifies an iOS binding and stores the key.
func (s *Service) FinishIOS(ctx context.Context, userID uuid.UUID, flowID string, b IOSBinding) (Binding, error) {
	f, err := s.take(ctx, userID, flowID, PurposeBind)
	if err != nil {
		return Binding{}, err
	}
	if s.cfg.Apple.Roots == nil {
		return Binding{}, ErrPlatform
	}
	if err := checkRole(b.Role); err != nil {
		return Binding{}, err
	}
	if err := parsePoint(b.PublicKey); err != nil {
		return Binding{}, err
	}
	now := s.cfg.Now()
	preimage := bindPreimage(f.Challenge, b.PublicKey)
	key := Key{Role: b.Role, PublicKey: b.PublicKey, SecurityLevel: LevelSecureEnclave, UserID: f.UserID}

	if f.DeviceID == uuid.Nil {
		if len(b.Attestation) == 0 || len(b.AppAttestKeyID) != sha256.Size || len(b.Assertion) != 0 {
			return Binding{}, badRequest("a new iOS device presents an App Attest key id and attestation")
		}
		if b.Role != RoleDevice {
			return Binding{}, badRequest("a new device binds K_dev first")
		}
		cdh := sha256.Sum256(preimage)
		att, err := verifyAppAttestation(s.cfg.Apple, b.AppAttestKeyID, b.Attestation, cdh[:], now)
		if err != nil {
			return Binding{}, err
		}
		env := "production"
		if att.Development {
			env = "development"
		}
		counter := uint32(0)
		d := Device{UserID: f.UserID, Platform: PlatformIOS, AppAttestKeyID: b.AppAttestKeyID,
			AppAttestPublicKey: att.PublicKey, AppAttestCounter: &counter, AppAttestReceipt: att.Receipt,
			Integrity: Integrity{Source: SourceAppAttestation, Environment: env}, IntegrityAt: now}
		key.Attestation = KeyAttestation{Method: SourceAppAttestation}
		return s.db.registerDevice(ctx, d, key)
	}

	if f.Platform != PlatformIOS {
		return Binding{}, badRequest("device is not an iOS device")
	}
	if len(b.Assertion) == 0 || len(b.Attestation) != 0 || len(b.AppAttestKeyID) != 0 {
		return Binding{}, badRequest("a known iOS device presents an App Attest assertion")
	}
	res, err := s.db.addKey(ctx, f.UserID, f.DeviceID, key, func(d Device, k *Key) (deviceUpdate, error) {
		if d.Platform != PlatformIOS {
			return deviceUpdate{}, badRequest("device is not an iOS device")
		}
		counter, err := verifyAppAssertion(s.cfg.Apple, d.AppAttestPublicKey, *d.AppAttestCounter, b.Assertion, preimage)
		if err != nil {
			return deviceUpdate{}, err
		}
		k.Attestation = KeyAttestation{Method: SourceAppAssertion, AppAttestCounter: counter}
		return deviceUpdate{Counter: &counter, Integrity: Integrity{Source: SourceAppAssertion}, At: now}, nil
	})
	if err != nil {
		s.cloneSignal(ctx, f.UserID, f.DeviceID, err)
	}
	return res, err
}

// AndroidBinding binds a StrongBox or TEE key on Android: the key's
// attestation chain (attestationChallenge = the flow challenge) and a Play
// Integrity token whose nonce (or request hash) is
// base64url(SHA-256(challenge ‖ x963(key))).
type AndroidBinding struct {
	Role           string
	Chain          [][]byte // DER certificates, leaf first
	IntegrityToken string
}

// FinishAndroid verifies an Android binding and stores the key.
func (s *Service) FinishAndroid(ctx context.Context, userID uuid.UUID, flowID string, b AndroidBinding) (Binding, error) {
	f, err := s.take(ctx, userID, flowID, PurposeBind)
	if err != nil {
		return Binding{}, err
	}
	if s.cfg.Android.Roots == nil {
		return Binding{}, ErrPlatform
	}
	if err := checkRole(b.Role); err != nil {
		return Binding{}, err
	}
	if f.DeviceID == uuid.Nil && b.Role != RoleDevice {
		return Binding{}, badRequest("a new device binds K_dev first")
	}
	if f.DeviceID != uuid.Nil && f.Platform != PlatformAndroid {
		return Binding{}, badRequest("device is not an Android device")
	}
	now := s.cfg.Now()
	ak, err := verifyAndroidKey(s.cfg.Android, b.Chain, f.Challenge, b.Role, now)
	if err != nil {
		return Binding{}, err
	}
	verdict, err := s.verdict(b.IntegrityToken, f.Challenge, ak.PublicKey, false, now)
	if err != nil {
		return Binding{}, err
	}
	integrity := androidIntegrity(ak, verdict)
	key := Key{Role: b.Role, PublicKey: ak.PublicKey, SecurityLevel: ak.SecurityLevel, UserID: f.UserID,
		Attestation: androidKeyAttestation(ak)}
	if f.DeviceID == uuid.Nil {
		d := Device{UserID: f.UserID, Platform: PlatformAndroid, OSPatchLevel: &ak.PatchLevel,
			Integrity: integrity, IntegrityAt: now}
		return s.db.registerDevice(ctx, d, key)
	}
	return s.db.addKey(ctx, f.UserID, f.DeviceID, key, func(d Device, _ *Key) (deviceUpdate, error) {
		if d.Platform != PlatformAndroid {
			return deviceUpdate{}, badRequest("device is not an Android device")
		}
		return deviceUpdate{PatchLevel: &ak.PatchLevel, Integrity: integrity, At: now}, nil
	})
}

// verdict decrypts, verifies and applies policy to a Play Integrity token
// bound to challenge and key, including the signing-certificate check.
func (s *Service) verdict(token string, challenge, key []byte, strong bool, now time.Time) (*IntegrityVerdict, error) {
	v, err := s.cfg.Integrity.Verify(token, now)
	if err != nil {
		return nil, err
	}
	if err := requireIntegrity(v, challenge, key, strong); err != nil {
		return nil, err
	}
	for _, enc := range v.CertificateDigests {
		d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(enc, "="))
		if err != nil {
			continue
		}
		for _, want := range s.cfg.Android.SigningCertDigests {
			if bytes.Equal(d, want) {
				return v, nil
			}
		}
	}
	return nil, reject("integrity.app", "verdict does not name a configured signing certificate")
}

func androidIntegrity(ak *androidKey, v *IntegrityVerdict) Integrity {
	in := Integrity{Source: SourcePlayIntegrity, VerifiedBoot: "verified", DeviceLocked: true,
		PatchLevel: ak.PatchLevel, DeviceVerdicts: v.DeviceVerdicts, AppRecognition: v.AppRecognition,
		VerdictAt: v.Timestamp}
	if os := ak.Description.Union(func(l *androidkey.AuthorizationList) *int64 { return l.OSVersion }); os != nil {
		in.OSVersion = *os
	}
	return in
}

func androidKeyAttestation(ak *androidKey) KeyAttestation {
	kd := ak.Description
	ka := KeyAttestation{Method: SourceKeyAttestation, AttestationVersion: kd.AttestationVersion,
		KeyMintVersion: kd.KeyMintVersion, PatchLevel: ak.PatchLevel,
		UnlockedDeviceRequired: kd.Hardware.UnlockedDeviceRequired}
	if os := kd.Union(func(l *androidkey.AuthorizationList) *int64 { return l.OSVersion }); os != nil {
		ka.OSVersion = *os
	}
	if t := kd.Hardware.AuthTimeout; t != nil {
		ka.AuthTimeoutSeconds = *t
	}
	return ka
}

// CoinMinting attests the coin keys of a Tier S allowance: one attestation
// chain per key (attestationChallenge = the flow challenge) and a Play
// Integrity token with MEETS_STRONG_INTEGRITY whose nonce is
// base64url(SHA-256(challenge ‖ x963(K_dev))) for the device's K_dev.
type CoinMinting struct {
	Chains         [][][]byte
	IntegrityToken string
}

// CoinKey is a verified single-use coin key.
type CoinKey struct {
	PublicKey     []byte // x963 point
	SecurityLevel string
}

// AttestCoins verifies a batch of coin keys (§3.A.9): every key shows a
// hardware-enforced usage count limit of 1 and rollback resistance, on
// Android 12 or later, and the device has strong integrity. The caller
// builds the allowance's coin Merkle tree from the returned keys, in order.
func (s *Service) AttestCoins(ctx context.Context, userID uuid.UUID, flowID string, m CoinMinting) ([]CoinKey, error) {
	f, err := s.take(ctx, userID, flowID, PurposeCoins)
	if err != nil {
		return nil, err
	}
	if s.cfg.Android.Roots == nil {
		return nil, ErrPlatform
	}
	if len(m.Chains) == 0 || len(m.Chains) > MaxCoins {
		return nil, badRequest("%d coin keys (1..%d)", len(m.Chains), MaxCoins)
	}
	kdev, err := s.db.activeRoleKey(ctx, f.DeviceID, RoleDevice)
	if err != nil {
		return nil, reject("coins.device", "device has no active K_dev")
	}
	now := s.cfg.Now()
	coins := make([]CoinKey, len(m.Chains))
	seen := map[string]bool{}
	var latest *androidKey
	for i, chain := range m.Chains {
		ak, err := verifyAndroidKey(s.cfg.Android, chain, f.Challenge, RoleCoin, now)
		if err != nil {
			var be *BindError
			if errors.As(err, &be) {
				be.Reason = fmt.Sprintf("coin %d: %s", i, be.Reason)
			}
			return nil, err
		}
		os := ak.Description.Union(func(l *androidkey.AuthorizationList) *int64 { return l.OSVersion })
		if os == nil || *os < minCoinOSVersion {
			return nil, reject("coins.os_version", "coin %d: Tier S needs Android 12 or later", i)
		}
		if seen[string(ak.PublicKey)] {
			return nil, reject("coins.duplicate", "coin %d repeats an earlier key", i)
		}
		seen[string(ak.PublicKey)] = true
		coins[i] = CoinKey{PublicKey: ak.PublicKey, SecurityLevel: ak.SecurityLevel}
		latest = ak
	}
	verdict, err := s.verdict(m.IntegrityToken, f.Challenge, kdev.PublicKey, true, now)
	if err != nil {
		return nil, err
	}
	in := androidIntegrity(latest, verdict)
	if err := s.db.refresh(ctx, f.UserID, f.DeviceID, func(Device) (deviceUpdate, error) {
		return deviceUpdate{PatchLevel: &latest.PatchLevel, Integrity: in, At: now}, nil
	}); err != nil {
		return nil, err
	}
	return coins, nil
}

// IntegrityProof refreshes a device's integrity evidence: on iOS an App
// Attest assertion over IntegrityDomain ‖ challenge; on Android a Play
// Integrity token whose nonce is base64url(SHA-256(challenge ‖ x963(K_dev))).
type IntegrityProof struct {
	Assertion      []byte
	IntegrityToken string
}

// RefreshIntegrity verifies fresh integrity evidence (offline allowances
// require evidence under 24 h old, §3.A.3) and returns the updated device.
func (s *Service) RefreshIntegrity(ctx context.Context, userID uuid.UUID, flowID string, p IntegrityProof) (Device, error) {
	f, err := s.take(ctx, userID, flowID, PurposeIntegrity)
	if err != nil {
		return Device{}, err
	}
	now := s.cfg.Now()
	switch f.Platform {
	case PlatformIOS:
		if s.cfg.Apple.Roots == nil {
			return Device{}, ErrPlatform
		}
		if len(p.Assertion) == 0 || p.IntegrityToken != "" {
			return Device{}, badRequest("an iOS device refreshes with an App Attest assertion")
		}
		return s.assert(ctx, f.UserID, f.DeviceID, p.Assertion, slices.Concat([]byte(IntegrityDomain), f.Challenge), now)
	default:
		if s.cfg.Android.Roots == nil {
			return Device{}, ErrPlatform
		}
		if p.IntegrityToken == "" || len(p.Assertion) != 0 {
			return Device{}, badRequest("an Android device refreshes with a Play Integrity token")
		}
		kdev, err := s.db.activeRoleKey(ctx, f.DeviceID, RoleDevice)
		if err != nil {
			return Device{}, reject("integrity.device", "device has no active K_dev")
		}
		verdict, err := s.verdict(p.IntegrityToken, f.Challenge, kdev.PublicKey, false, now)
		if err != nil {
			return Device{}, err
		}
		in := Integrity{Source: SourcePlayIntegrity, DeviceVerdicts: verdict.DeviceVerdicts,
			AppRecognition: verdict.AppRecognition, VerdictAt: verdict.Timestamp}
		if err := s.db.refresh(ctx, f.UserID, f.DeviceID, func(Device) (deviceUpdate, error) {
			return deviceUpdate{Integrity: in, At: now}, nil
		}); err != nil {
			return Device{}, err
		}
		return s.db.device(ctx, s.db.pool, f.DeviceID)
	}
}

// AssertIOS verifies an App Attest assertion over clientData from one of
// the user's iOS devices, as risky calls require (TB3). The caller chooses
// clientData so that it covers the request; the counter makes every
// assertion single use.
func (s *Service) AssertIOS(ctx context.Context, userID, deviceID uuid.UUID, assertion, clientData []byte) (Device, error) {
	if s.cfg.Apple.Roots == nil {
		return Device{}, ErrPlatform
	}
	return s.assert(ctx, userID, deviceID, assertion, clientData, s.cfg.Now())
}

func (s *Service) assert(ctx context.Context, userID, deviceID uuid.UUID, assertion, clientData []byte, now time.Time) (Device, error) {
	err := s.db.refresh(ctx, userID, deviceID, func(d Device) (deviceUpdate, error) {
		if d.Platform != PlatformIOS {
			return deviceUpdate{}, badRequest("device is not an iOS device")
		}
		counter, err := verifyAppAssertion(s.cfg.Apple, d.AppAttestPublicKey, *d.AppAttestCounter, assertion, clientData)
		if err != nil {
			return deviceUpdate{}, err
		}
		return deviceUpdate{Counter: &counter, Integrity: Integrity{Source: SourceAppAssertion}, At: now}, nil
	})
	if err != nil {
		s.cloneSignal(ctx, userID, deviceID, err)
		return Device{}, err
	}
	return s.db.device(ctx, s.db.pool, deviceID)
}

// cloneSignal publishes an App Attest counter anomaly (§2.2.7: step-up,
// lower limits, manual review if it repeats). It runs after the failed
// transaction rolled back; a failure to publish is not the caller's error.
func (s *Service) cloneSignal(ctx context.Context, userID, deviceID uuid.UUID, err error) {
	var be *BindError
	if !errors.As(err, &be) || be.Check != checkCounter {
		return
	}
	_ = s.db.emitCloneSignal(ctx, userID, deviceID, be.Reason)
}

// Revoke revokes one of the user's devices and all its keys (lost or
// stolen device, §2.2.7). Revoking a revoked device is a no-op.
func (s *Service) Revoke(ctx context.Context, userID, deviceID uuid.UUID, reason string) error {
	if reason == "" {
		return badRequest("a revocation reason is required")
	}
	return s.db.revokeDevice(ctx, userID, deviceID, reason)
}

// RevokeKey revokes one of the user's keys (an allowance's K_off at close,
// or a key the user removes). Revoking a revoked key is a no-op.
func (s *Service) RevokeKey(ctx context.Context, userID, keyID uuid.UUID, reason string) error {
	if reason == "" {
		return badRequest("a revocation reason is required")
	}
	return s.db.revokeKey(ctx, userID, keyID, reason)
}

// Device returns one of the user's devices, revoked or not.
func (s *Service) Device(ctx context.Context, userID, deviceID uuid.UUID) (Device, error) {
	d, err := s.db.device(ctx, s.db.pool, deviceID)
	if err != nil {
		return Device{}, err
	}
	if d.UserID != userID {
		return Device{}, ErrNotFound
	}
	return d, nil
}

// Devices lists the user's active devices.
func (s *Service) Devices(ctx context.Context, userID uuid.UUID) ([]Device, error) {
	return s.db.devicesForUser(ctx, userID)
}

// Keys lists the active keys of one of the user's devices.
func (s *Service) Keys(ctx context.Context, userID, deviceID uuid.UUID) ([]Key, error) {
	if _, err := s.Device(ctx, userID, deviceID); err != nil {
		return nil, err
	}
	return s.db.keysForDevice(ctx, deviceID)
}

// ActiveKey returns a key for signature verification (TxAuth, offline
// artefacts): ErrNotFound when it does not exist and ErrRevoked when the
// key or its device is revoked.
func (s *Service) ActiveKey(ctx context.Context, keyID uuid.UUID) (Key, error) {
	return s.db.activeKey(ctx, keyID)
}
