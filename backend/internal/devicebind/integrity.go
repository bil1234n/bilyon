package devicebind

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/keywrap"
)

// IntegrityConfig configures local Play Integrity verdict verification
// with the keys from the Play Console ("manage response encryption").
type IntegrityConfig struct {
	DecryptionKey   []byte           // 32-byte AES key
	VerificationKey *ecdsa.PublicKey // P-256 verdict signing key
	PackageName     string
	MaxAge          time.Duration // default 5 minutes
}

// IntegrityVerdict is the part of a Play Integrity verdict the binding uses.
type IntegrityVerdict struct {
	Nonce              string
	RequestHash        string
	PackageName        string
	Timestamp          time.Time
	AppRecognition     string
	CertificateDigests []string
	DeviceVerdicts     []string
}

// Device integrity labels.
const (
	MeetsDeviceIntegrity = "MEETS_DEVICE_INTEGRITY"
	MeetsStrongIntegrity = "MEETS_STRONG_INTEGRITY"
)

var b64 = base64.RawURLEncoding

// Verify decrypts (JWE A256KW / A256GCM) and verifies (JWS ES256) an
// integrity token and checks its package name and freshness.
func (c *IntegrityConfig) Verify(token string, now time.Time) (*IntegrityVerdict, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, reject("integrity.token", "not a compact JWE")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	}
	rawHdr, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(rawHdr, &hdr) != nil || hdr.Alg != "A256KW" || hdr.Enc != "A256GCM" {
		return nil, reject("integrity.token", "unsupported JWE header")
	}
	segs := make([][]byte, 4)
	for i, p := range parts[1:] {
		if segs[i], err = b64.DecodeString(p); err != nil {
			return nil, reject("integrity.token", "segment %d: %v", i+1, err)
		}
	}
	cek, err := keywrap.Unwrap(c.DecryptionKey, segs[0])
	if err != nil || len(cek) != 32 {
		return nil, reject("integrity.token", "content key: %v", err)
	}
	block, _ := aes.NewCipher(cek)
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(segs[1]) != gcm.NonceSize() {
		return nil, reject("integrity.token", "content encryption parameters")
	}
	jws, err := gcm.Open(nil, segs[1], append(append([]byte{}, segs[2]...), segs[3]...), []byte(parts[0]))
	if err != nil {
		return nil, reject("integrity.token", "decryption failed")
	}
	payload, err := verifyES256JWS(string(jws), c.VerificationKey)
	if err != nil {
		return nil, err
	}
	var doc struct {
		RequestDetails struct {
			RequestPackageName string `json:"requestPackageName"`
			Nonce              string `json:"nonce"`
			RequestHash        string `json:"requestHash"`
			TimestampMillis    string `json:"timestampMillis"`
		} `json:"requestDetails"`
		AppIntegrity struct {
			AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
			PackageName             string   `json:"packageName"`
			CertificateSha256Digest []string `json:"certificateSha256Digest"`
		} `json:"appIntegrity"`
		DeviceIntegrity struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		} `json:"deviceIntegrity"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, reject("integrity.verdict", "payload: %v", err)
	}
	var ms int64
	if _, err := fmt.Sscan(doc.RequestDetails.TimestampMillis, &ms); err != nil {
		return nil, reject("integrity.verdict", "timestamp %q", doc.RequestDetails.TimestampMillis)
	}
	v := &IntegrityVerdict{Nonce: doc.RequestDetails.Nonce, RequestHash: doc.RequestDetails.RequestHash,
		PackageName: doc.RequestDetails.RequestPackageName, Timestamp: time.UnixMilli(ms).UTC(),
		AppRecognition: doc.AppIntegrity.AppRecognitionVerdict, CertificateDigests: doc.AppIntegrity.CertificateSha256Digest,
		DeviceVerdicts: doc.DeviceIntegrity.DeviceRecognitionVerdict}
	if v.PackageName != c.PackageName || doc.AppIntegrity.PackageName != c.PackageName {
		return nil, reject("integrity.verdict", "package %q", v.PackageName)
	}
	maxAge := c.MaxAge
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	if age := now.Sub(v.Timestamp); age > maxAge || age < -time.Minute {
		return nil, reject("integrity.verdict", "verdict is %s old", age)
	}
	return v, nil
}

// verifyES256JWS verifies a compact JWS signed with ES256 and returns its
// payload.
func verifyES256JWS(jws string, key *ecdsa.PublicKey) ([]byte, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, reject("integrity.signature", "not a compact JWS")
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	rawHdr, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(rawHdr, &hdr) != nil || hdr.Alg != "ES256" {
		return nil, reject("integrity.signature", "JWS algorithm must be ES256")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, reject("integrity.signature", "malformed signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if key == nil || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, reject("integrity.signature", "verdict signature invalid")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, reject("integrity.signature", "payload: %v", err)
	}
	return payload, nil
}

// requireIntegrity applies the binding policy to a verdict: recognised by
// Play, device integrity (strong integrity when strong is set), and the
// nonce bound to the challenge and key: base64url(SHA-256(challenge ‖ key)).
func requireIntegrity(v *IntegrityVerdict, challenge, publicKey []byte, strong bool) error {
	if v.AppRecognition != "PLAY_RECOGNIZED" {
		return reject("integrity.app", "app recognition verdict %q", v.AppRecognition)
	}
	want := MeetsDeviceIntegrity
	if strong {
		want = MeetsStrongIntegrity
	}
	if !slices.Contains(v.DeviceVerdicts, want) {
		return reject("integrity.device", "device verdicts %v lack %s", v.DeviceVerdicts, want)
	}
	h := sha256.Sum256(append(append([]byte{}, challenge...), publicKey...))
	expected := b64.EncodeToString(h[:])
	got := strings.TrimRight(v.Nonce, "=")
	if got == "" {
		got = strings.TrimRight(v.RequestHash, "=")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		return reject("integrity.nonce", "verdict nonce is not bound to the challenge and key")
	}
	return nil
}
