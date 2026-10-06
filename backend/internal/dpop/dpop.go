// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession
// (RFC 9449) for Bilyon's device sessions (RFC 0001 §2.2.3 A7, TB3): every
// request carries a proof signed by the device's session key over the
// method, the URI, a timestamp and a server nonce. The verifier checks the
// proof per RFC 9449 §4.3, binds it to the presented access token (ath),
// issues and checks stateless server nonces, and rejects replays through a
// Redis jti cache shared by all gateways.
package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bil1234n/bilyon/backend/internal/jose"
)

// HTTP header names.
const (
	Header      = "DPoP"
	NonceHeader = "DPoP-Nonce"
)

// Error codes (RFC 9449 §7.1, §8).
const (
	CodeInvalidProof = "invalid_dpop_proof"
	CodeUseNonce     = "use_dpop_nonce"
)

const (
	proofType  = "dpop+jwt"
	nonceLabel = "bilyon/dpop-nonce/v1"
	minJTI     = 16 // characters: at least 96 bits of base64url entropy
	maxJTI     = 128
)

// Error is a refused proof. Code and Description go into the
// WWW-Authenticate challenge.
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string { return "dpop: " + e.Code + ": " + e.Description }

func invalid(format string, args ...any) error {
	return &Error{Code: CodeInvalidProof, Description: fmt.Sprintf(format, args...)}
}

// Config configures proof verification.
type Config struct {
	// Origins are the public origins (scheme://host[:port]) the API is
	// served under; a proof's htu must name one of them.
	Origins []string
	// NonceKeys are HMAC-SHA256 keys (at least 32 bytes) for stateless
	// server nonces: the first issues, all verify, so keys rotate by
	// prepending. Without keys nonces are not required (tests, tools).
	NonceKeys [][]byte
	// NonceTTL is how long a nonce stays acceptable (default 5 minutes).
	NonceTTL time.Duration
	// Skew bounds |iat − now| (default 5 minutes). A jti is remembered for
	// 2·Skew, the longest time a proof can be acceptable.
	Skew time.Duration
	Now  func() time.Time
}

// Verifier checks DPoP proofs.
type Verifier struct {
	cfg     Config
	origins map[string]bool
	rdb     redis.UniversalClient
}

// NewVerifier validates the configuration. rdb holds the replay cache.
func NewVerifier(cfg Config, rdb redis.UniversalClient) (*Verifier, error) {
	if rdb == nil {
		return nil, errors.New("dpop: a Redis client for replay detection is required")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("dpop: at least one origin is required")
	}
	origins := map[string]bool{}
	for _, o := range cfg.Origins {
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("dpop: origin %q is not scheme://host[:port]", o)
		}
		origins[normalizeOrigin(u)] = true
	}
	for i, k := range cfg.NonceKeys {
		if len(k) < 32 {
			return nil, fmt.Errorf("dpop: nonce key %d is shorter than 32 bytes", i)
		}
	}
	if cfg.NonceTTL == 0 {
		cfg.NonceTTL = 5 * time.Minute
	}
	if cfg.Skew == 0 {
		cfg.Skew = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg, origins: origins, rdb: rdb}, nil
}

// Request is what a proof is checked against.
type Request struct {
	Method      string
	Path        string   // the request path as received (escaped form)
	Proofs      []string // every DPoP header value
	AccessToken string   // the access token the request presents, if any
}

// Proof is a verified proof.
type Proof struct {
	JKT       string // RFC 7638 thumbprint of the proof key
	PublicKey *ecdsa.PublicKey
	JTI       string
	IssuedAt  time.Time
}

type claims struct {
	JTI   string      `json:"jti"`
	HTM   string      `json:"htm"`
	HTU   string      `json:"htu"`
	IAT   json.Number `json:"iat"`
	ATH   string      `json:"ath"`
	Nonce string      `json:"nonce"`
}

// numericDate parses a JWT NumericDate (seconds, possibly fractional).
func numericDate(n json.Number) (time.Time, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1<<40 {
		return time.Time{}, fmt.Errorf("NumericDate %q", n)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), nil
}

// AccessTokenHash is the ath claim: base64url(SHA-256(access token)).
func AccessTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return jose.B64.EncodeToString(h[:])
}

// Verify checks a request's proof (RFC 9449 §4.3, steps 1-12): one
// well-formed JWT of type dpop+jwt signed with ES256 by the public key in
// its header; htm and htu matching the request; iat in the acceptance
// window; ath matching the access token; a valid server nonce when nonces
// are configured; and a jti not seen before for this key. A refused proof
// is an *Error; any other error is an infrastructure failure.
func (v *Verifier) Verify(ctx context.Context, r Request) (*Proof, error) {
	if len(r.Proofs) != 1 {
		return nil, invalid("exactly one DPoP header is required, got %d", len(r.Proofs))
	}
	j, err := jose.Parse(r.Proofs[0])
	if err != nil {
		return nil, invalid("%v", err)
	}
	if typ, _, _ := j.HeaderString("typ"); typ != proofType {
		return nil, invalid("typ %q is not %s", typ, proofType)
	}
	if alg := j.Alg(); alg != "ES256" {
		return nil, invalid("alg %q is not supported", alg)
	}
	rawJWK, ok := j.Header["jwk"]
	if !ok {
		return nil, invalid("the header carries no jwk")
	}
	members, err := jose.StrictObject(rawJWK)
	if err != nil {
		return nil, invalid("jwk: %v", err)
	}
	if _, private := members["d"]; private {
		return nil, invalid("the jwk contains a private key")
	}
	var jwk jose.JWK
	if err := json.Unmarshal(rawJWK, &jwk); err != nil {
		return nil, invalid("jwk: %v", err)
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return nil, invalid("jwk: %v", err)
	}
	if err := j.VerifyES256(pub); err != nil {
		return nil, invalid("signature: %v", err)
	}
	var c claims
	if err := jose.DecodeStrict(j.Payload, &c); err != nil {
		return nil, invalid("claims: %v", err)
	}
	if n := len(c.JTI); n < minJTI || n > maxJTI {
		return nil, invalid("jti must have %d to %d characters", minJTI, maxJTI)
	}
	if c.HTM == "" || c.HTM != r.Method {
		return nil, invalid("htm %q does not match the request method %s", c.HTM, r.Method)
	}
	if err := v.checkHTU(c.HTU, r.Path); err != nil {
		return nil, err
	}
	if c.IAT == "" {
		return nil, invalid("iat is required")
	}
	iat, err := numericDate(c.IAT)
	if err != nil {
		return nil, invalid("iat: %v", err)
	}
	now := v.cfg.Now()
	if iat.Before(now.Add(-v.cfg.Skew)) || iat.After(now.Add(v.cfg.Skew)) {
		return nil, invalid("iat is outside the acceptance window")
	}
	if r.AccessToken != "" {
		if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(AccessTokenHash(r.AccessToken))) != 1 {
			return nil, invalid("ath does not match the access token")
		}
	}
	if len(v.cfg.NonceKeys) > 0 {
		if c.Nonce == "" {
			return nil, &Error{Code: CodeUseNonce, Description: "a server nonce is required"}
		}
		if !v.validNonce(c.Nonce, now) {
			return nil, &Error{Code: CodeUseNonce, Description: "the nonce is invalid or expired"}
		}
	}
	jkt, err := jwk.Thumbprint()
	if err != nil {
		return nil, invalid("jwk: %v", err)
	}
	fresh, err := v.rdb.SetNX(ctx, "bilyon:dpop:jti:"+jkt+":"+c.JTI, 1, 2*v.cfg.Skew).Result()
	if err != nil {
		return nil, fmt.Errorf("dpop: replay cache: %w", err)
	}
	if !fresh {
		return nil, invalid("the proof was already used")
	}
	return &Proof{JKT: jkt, PublicKey: pub, JTI: c.JTI, IssuedAt: iat}, nil
}

func (v *Verifier) checkHTU(htu, path string) error {
	u, err := url.Parse(htu)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" || u.User != nil {
		return invalid("htu %q is not an absolute http(s) URI", htu)
	}
	if !v.origins[normalizeOrigin(u)] {
		return invalid("htu %q does not name this server", htu)
	}
	got, err := normalizePath(u.EscapedPath())
	if err != nil {
		return invalid("htu path: %v", err)
	}
	want, err := normalizePath(path)
	if err != nil || got != want {
		return invalid("htu %q does not match the request path", htu)
	}
	return nil
}

// Nonce returns a fresh server nonce ("" when nonces are disabled):
// base64url(t ‖ HMAC-SHA256(key, label ‖ t)[:16]) with t the issue time in
// seconds. Any gateway sharing the keys accepts it for NonceTTL.
func (v *Verifier) Nonce() string {
	if len(v.cfg.NonceKeys) == 0 {
		return ""
	}
	ts := binary.BigEndian.AppendUint64(nil, uint64(v.cfg.Now().Unix()))
	return jose.B64.EncodeToString(append(ts, nonceMAC(v.cfg.NonceKeys[0], ts)...))
}

func nonceMAC(key, ts []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(nonceLabel))
	m.Write(ts)
	return m.Sum(nil)[:16]
}

func (v *Verifier) validNonce(nonce string, now time.Time) bool {
	raw, err := jose.B64.DecodeString(nonce)
	if err != nil || len(raw) != 24 {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	// Gateways keep their clocks within milliseconds (§6.3); a few seconds
	// of future tolerance covers a nonce from a peer that just ticked.
	if age := now.Sub(issued); age < -5*time.Second || age > v.cfg.NonceTTL {
		return false
	}
	for _, k := range v.cfg.NonceKeys {
		if hmac.Equal(raw[8:], nonceMAC(k, raw[:8])) {
			return true
		}
	}
	return false
}

// ProofOptions are a proof's optional parts.
type ProofOptions struct {
	Nonce       string
	AccessToken string    // sets ath
	IssuedAt    time.Time // default now
	JTI         string    // default 16 random bytes, base64url
}

// NewProof signs a DPoP proof for a request (clients and tests).
func NewProof(key *ecdsa.PrivateKey, method, htu string, o ProofOptions) (string, error) {
	jwk, err := jose.PublicJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}
	jti := o.JTI
	if jti == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		jti = jose.B64.EncodeToString(b)
	}
	iat := o.IssuedAt
	if iat.IsZero() {
		iat = time.Now()
	}
	c := map[string]any{"jti": jti, "htm": method, "htu": htu, "iat": iat.Unix()}
	if o.Nonce != "" {
		c["nonce"] = o.Nonce
	}
	if o.AccessToken != "" {
		c["ath"] = AccessTokenHash(o.AccessToken)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return jose.SignES256(key, map[string]any{"typ": proofType, "jwk": jwk}, payload)
}

// normalizeOrigin applies RFC 3986 §6.2.2-6.2.3 to scheme and authority:
// lower case, default port removed.
func normalizeOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

func isHex(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func isUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// normalizePath applies RFC 3986 syntax-based normalisation to a path:
// percent-encoded unreserved characters decoded, other percent-encodings
// upper-cased, dot segments removed, and an empty path made "/".
func normalizePath(p string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
			return "", errors.New("invalid percent-encoding")
		}
		if v := unhex(p[i+1])<<4 | unhex(p[i+2]); isUnreserved(v) {
			b.WriteByte(v)
		} else {
			b.WriteString("%" + strings.ToUpper(p[i+1:i+3]))
		}
		i += 2
	}
	out := removeDotSegments(b.String())
	if out == "" {
		out = "/"
	}
	return out, nil
}

// removeDotSegments is RFC 3986 §5.2.4.
func removeDotSegments(in string) string {
	var out []string // output segments, each with its leading "/" when it had one
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "/..":
			in = "/"
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "." || in == "..":
			in = ""
		default:
			start := 0
			if in[0] == '/' {
				start = 1
			}
			end := strings.IndexByte(in[start:], '/')
			if end < 0 {
				end = len(in)
			} else {
				end += start
			}
			out = append(out, in[:end])
			in = in[end:]
		}
	}
	return strings.Join(out, "")
}
