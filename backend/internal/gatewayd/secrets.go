package gatewayd

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/session"
)

// LoadSymmetricKeys reads a key file: one standard-base64 key per line,
// blank lines and "#" comments ignored. The first key is the current one
// (it issues), the others still verify, so keys rotate by prepending.
func LoadSymmetricKeys(path string, minLen int) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var keys [][]byte
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: not base64", path, line)
		}
		if len(k) < minLen {
			return nil, fmt.Errorf("%s:%d: key shorter than %d bytes", path, line, minLen)
		}
		keys = append(keys, k)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no keys", path)
	}
	return keys, nil
}

// LoadCertPool reads PEM certificates (trust anchors).
func LoadCertPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s: no PEM certificates", path)
	}
	return pool, nil
}

// LoadPrivateKey reads a PEM P-256 private key (SEC 1 or PKCS #8).
func LoadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := session.ParsePrivateKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// LoadPublicKey reads a PEM P-256 public key (PKIX).
func LoadPublicKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := session.ParsePublicKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// LoadAESKey reads a base64 file holding exactly n key bytes.
func LoadAESKey(path string, n int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(k) != n {
		return nil, fmt.Errorf("%s: want %d base64 bytes", path, n)
	}
	return k, nil
}

// ParseDigests parses comma-separated hex SHA-256 digests.
func ParseDigests(s string) ([][]byte, error) {
	var out [][]byte
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(strings.ReplaceAll(part, ":", ""))
		if part == "" {
			continue
		}
		d, err := hex.DecodeString(part)
		if err != nil || len(d) != 32 {
			return nil, fmt.Errorf("%q is not a hex SHA-256 digest", part)
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("no digests")
	}
	return out, nil
}

// LoadLimits reads per-currency payment limits:
// {"EUR": {"gesture": 10000, "gesture_window": 25000, "per_intent": 0, "daily": 0}}.
func LoadLimits(path string) (map[string]intents.Limits, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in map[string]struct {
		Gesture       int64 `json:"gesture"`
		GestureWindow int64 `json:"gesture_window"`
		PerIntent     int64 `json:"per_intent"`
		Daily         int64 `json:"daily"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := make(map[string]intents.Limits, len(in))
	for cur, l := range in {
		out[cur] = intents.Limits{Gesture: l.Gesture, GestureWindow: l.GestureWindow, PerIntent: l.PerIntent, Daily: l.Daily}
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
