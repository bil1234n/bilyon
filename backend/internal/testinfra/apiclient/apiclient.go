// Package apiclient is a test client for the gateway's REST API: it signs
// a DPoP proof (RFC 9449) for every request, follows use_dpop_nonce
// challenges, keeps the session's tokens, and runs the passkey and device
// binding flows with the software authenticator and device simulators, so
// tests drive the API exactly as the apps do.
package apiclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/dpop"
	"github.com/bil1234n/bilyon/backend/internal/gatewayapi"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/authenticator"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

// Tokens is a token response.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	RefreshToken string    `json:"refresh_token"`
	SessionID    uuid.UUID `json:"session_id"`
}

// Client is one app instance: its DPoP key and session.
type Client struct {
	t      testing.TB
	base   string // where requests are sent, e.g. http://127.0.0.1:41234
	origin string // the API's public origin, which proofs name in htu
	http   *http.Client
	Key    *ecdsa.PrivateKey
	nonce  string
	Tokens Tokens
	UserID uuid.UUID
	// Clock dates the proofs (default time.Now); tests that shift the
	// server's clock shift this one too.
	Clock func() time.Time
	// ContentType of request bodies (default application/json).
	ContentType string
}

// New returns a client with a fresh DPoP key.
func New(t testing.TB, base, origin string) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{t: t, base: strings.TrimRight(base, "/"), origin: origin, http: &http.Client{Timeout: 30 * time.Second},
		Key: key, Clock: time.Now, ContentType: "application/json"}
}

// Response is an API response.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	Problem gatewayapi.Problem
}

// Decode unmarshals the body into v.
func (r *Response) Decode(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("decode %s: %v", r.Body, err)
	}
}

// Do sends a request with a DPoP proof and, when the client holds one, its
// access token. body is JSON-encoded unless it is a []byte.
func (c *Client) Do(method, path string, body any) *Response {
	c.t.Helper()
	return c.do(method, path, body, c.Tokens.AccessToken, true)
}

// Anonymous sends a request with neither proof nor token.
func (c *Client) Anonymous(method, path string, body any) *Response {
	c.t.Helper()
	return c.do(method, path, body, "", false)
}

// ProofOnly sends a request with a proof but no access token.
func (c *Client) ProofOnly(method, path string, body any) *Response {
	c.t.Helper()
	return c.do(method, path, body, "", true)
}

func (c *Client) do(method, path string, body any, token string, prove bool) *Response {
	c.t.Helper()
	var raw []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		raw = b
	default:
		var err error
		if raw, err = json.Marshal(b); err != nil {
			c.t.Fatal(err)
		}
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequest(method, c.base+path, bytes.NewReader(raw))
		if err != nil {
			c.t.Fatal(err)
		}
		if raw != nil {
			req.Header.Set("Content-Type", c.ContentType)
		}
		if prove {
			htu := c.origin + path
			if i := strings.IndexByte(htu, '?'); i >= 0 {
				htu = htu[:i]
			}
			proof, err := dpop.NewProof(c.Key, method, htu, dpop.ProofOptions{Nonce: c.nonce, AccessToken: token,
				IssuedAt: c.Clock()})
			if err != nil {
				c.t.Fatal(err)
			}
			req.Header.Set(dpop.Header, proof)
		}
		if token != "" {
			req.Header.Set("Authorization", "DPoP "+token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			c.t.Fatalf("%s %s: %v", method, path, err)
		}
		out := &Response{Status: resp.StatusCode, Header: resp.Header}
		out.Body, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			c.t.Fatal(err)
		}
		if n := resp.Header.Get(dpop.NonceHeader); n != "" {
			c.nonce = n
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 &&
			strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
			continue // retry once with the nonce the server just supplied
		}
		if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/problem+json") {
			_ = json.Unmarshal(out.Body, &out.Problem)
		}
		return out
	}
}

// Expect checks the status and decodes the body into out (when not nil).
func (c *Client) Expect(r *Response, status int, out any) *Response {
	c.t.Helper()
	if r.Status != status {
		c.t.Fatalf("status %d, want %d: %s", r.Status, status, r.Body)
	}
	if out != nil {
		r.Decode(c.t, out)
	}
	return r
}

type authResult struct {
	UserID      uuid.UUID `json:"user_id"`
	Tokens      Tokens    `json:"tokens"`
	CloneSignal bool      `json:"clone_signal"`
}

// Register creates an account with a new passkey and keeps its session.
func (c *Client) Register(a *authenticator.Authenticator, cred *authenticator.Credential, name, clientID string) uuid.UUID {
	c.t.Helper()
	var begin struct {
		FlowID  string                   `json:"flow_id"`
		Options webauthn.CreationOptions `json:"options"`
	}
	c.Expect(c.ProofOnly(http.MethodPost, "/v1/auth/register/begin", map[string]any{"display_name": name}),
		http.StatusOK, &begin)
	resp := a.Register(cred, &begin.Options, authenticator.Options{})
	var res authResult
	c.Expect(c.ProofOnly(http.MethodPost, "/v1/auth/register/finish", map[string]any{"flow_id": begin.FlowID,
		"credential": resp, "client_id": clientID}), http.StatusCreated, &res)
	c.Tokens, c.UserID = res.Tokens, res.UserID
	return res.UserID
}

// Login signs in with a passkey; device binds the session to a device.
func (c *Client) Login(a *authenticator.Authenticator, cred *authenticator.Credential, clientID string, device *uuid.UUID) *Response {
	c.t.Helper()
	var begin struct {
		FlowID  string                  `json:"flow_id"`
		Options webauthn.RequestOptions `json:"options"`
	}
	c.Expect(c.ProofOnly(http.MethodPost, "/v1/auth/login/begin", map[string]any{}), http.StatusOK, &begin)
	body := map[string]any{"flow_id": begin.FlowID, "credential": a.Assert(cred, &begin.Options, authenticator.AssertOptions{}),
		"client_id": clientID}
	if device != nil {
		body["device_id"] = device
	}
	r := c.ProofOnly(http.MethodPost, "/v1/auth/login/finish", body)
	if r.Status == http.StatusOK {
		var res authResult
		r.Decode(c.t, &res)
		c.Tokens, c.UserID = res.Tokens, res.UserID
	}
	return r
}

// StepUp re-authenticates the session with the passkey.
func (c *Client) StepUp(a *authenticator.Authenticator, cred *authenticator.Credential) {
	c.t.Helper()
	var begin struct {
		FlowID  string                  `json:"flow_id"`
		Options webauthn.RequestOptions `json:"options"`
	}
	c.Expect(c.Do(http.MethodPost, "/v1/auth/step-up/begin", map[string]any{}), http.StatusOK, &begin)
	var tokens Tokens
	c.Expect(c.Do(http.MethodPost, "/v1/auth/step-up/finish", map[string]any{"flow_id": begin.FlowID,
		"credential": a.Assert(cred, &begin.Options, authenticator.AssertOptions{})}), http.StatusOK, &tokens)
	c.Tokens = tokens
}

// Binding is a device binding response.
type Binding struct {
	Device struct {
		ID uuid.UUID `json:"id"`
	} `json:"device"`
	Key struct {
		ID   uuid.UUID `json:"id"`
		Role string    `json:"role"`
	} `json:"key"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// BindAndroid generates a key with role on phone and binds it; device
// uuid.Nil registers the phone.
func (c *Client) BindAndroid(phone *devicesim.AndroidDevice, role string, device uuid.UUID) (*ecdsa.PrivateKey, Binding) {
	c.t.Helper()
	req := map[string]any{"purpose": "bind"}
	if device != uuid.Nil {
		req["device_id"] = device
	}
	var ch struct {
		FlowID    string           `json:"flow_id"`
		Challenge gatewayapi.Bytes `json:"challenge"`
	}
	c.Expect(c.Do(http.MethodPost, "/v1/devices/challenges", req), http.StatusOK, &ch)
	key, chain := phone.GenerateKey(role, ch.Challenge, devicesim.KeyOptions{})
	certs := make([]string, len(chain))
	for i, cert := range chain {
		certs[i] = b64(cert)
	}
	var b Binding
	c.Expect(c.Do(http.MethodPost, "/v1/devices/android", map[string]any{"flow_id": ch.FlowID, "role": role,
		"chain": certs, "integrity_token": phone.IntegrityToken(ch.Challenge, devicesim.Point(c.t, key), nil)}),
		http.StatusCreated, &b)
	return key, b
}
