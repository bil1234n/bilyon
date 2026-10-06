package gatewayapi_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/dpop"
	"github.com/bil1234n/bilyon/backend/internal/gatewayapi"
	"github.com/bil1234n/bilyon/backend/internal/session"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/apiclient"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/authenticator"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/intentsenv"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

const (
	origin   = "https://api.bilyon.test"
	rpID     = "bilyon.test"
	clientID = "bilyon-android"
)

type harness struct {
	t        *testing.T
	env      *intentsenv.Env
	server   *httptest.Server
	auth     *authenticator.Authenticator
	sessions *session.Service
	reg      *prometheus.Registry
}

func newHarness(t *testing.T, edit func(*gatewayapi.Config)) *harness {
	t.Helper()
	t.Parallel()
	env := intentsenv.New(t, srv, nil)
	// As gatewayd does at start-up.
	if err := env.Dir.EnsureReserved(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, env: env, auth: authenticator.New(t), reg: prometheus.NewRegistry()}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := session.NewKeySet(signing)
	if err != nil {
		t.Fatal(err)
	}
	if h.sessions, err = session.New(session.Config{Issuer: origin, Audience: []string{origin}, Now: env.Clock.Now},
		keys, env.Pool, env.Redis); err != nil {
		t.Fatal(err)
	}
	nonceKey := make([]byte, 32)
	_, _ = rand.Read(nonceKey)
	proofs, err := dpop.NewVerifier(dpop.Config{Origins: []string{origin}, NonceKeys: [][]byte{nonceKey},
		Now: env.Clock.Now}, env.Redis)
	if err != nil {
		t.Fatal(err)
	}
	users := webauthn.NewPGStore(env.Pool)
	rp, err := webauthn.New(webauthn.Config{RPID: rpID, RPName: "Bilyon", Origins: []string{"https://" + rpID},
		Now: env.Clock.Now}, webauthn.NewRedisChallenges(env.Redis), users)
	if err != nil {
		t.Fatal(err)
	}
	cfg := gatewayapi.Config{Clients: []string{clientID, "bilyon-ios"}, RateLimits: gatewayapi.DefaultRateLimits}
	if edit != nil {
		edit(&cfg)
	}
	api, err := gatewayapi.New(cfg, gatewayapi.Deps{Users: users, WebAuthn: rp, Sessions: h.sessions, SessionKeys: keys,
		Auth: session.NewAuthenticator(h.sessions, proofs), Devices: env.Binder, Directory: env.Dir,
		DirectoryKeys: []gatewayapi.DirectoryKey{{KID: env.DirKeyID, Public: env.DirKey.Public()}},
		Accounts:      env.Accounts, Intents: env.Intents, Limiter: gatewayapi.NewLimiter(env.Redis, env.Clock.Now),
		Registerer: h.reg})
	if err != nil {
		t.Fatal(err)
	}
	h.server = httptest.NewServer(api)
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) client() *apiclient.Client {
	c := apiclient.New(h.t, h.server.URL, origin)
	c.Clock = h.env.Clock.Now
	return c
}

// person registers an account with a passkey.
func (h *harness) person(name string) (*apiclient.Client, *authenticator.Credential) {
	h.t.Helper()
	c := h.client()
	cred := h.auth.NewCredential(cose.AlgES256)
	c.Register(h.auth, cred, name, clientID)
	return c, cred
}

func TestPasskeyRegistrationLoginAndSessions(t *testing.T) {
	h := newHarness(t, nil)
	alice, cred := h.person("Alice")
	var me map[string]any
	alice.Expect(alice.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, &me)
	if me["display_name"] != "Alice" || me["status"] != "active" || me["intent_timeout"] != "async" ||
		me["user_id"] != alice.UserID.String() || me["subject"] == "" || me["entry"] != nil {
		t.Fatalf("me %v", me)
	}
	// A second app instance logs in with the same passkey.
	other := h.client()
	other.Expect(other.Login(h.auth, cred, "bilyon-ios", nil), http.StatusOK, nil)
	if other.UserID != alice.UserID {
		t.Fatalf("logged in as %s", other.UserID)
	}
	var list struct {
		Sessions []struct {
			ID       uuid.UUID `json:"id"`
			ClientID string    `json:"client_id"`
			Current  bool      `json:"current"`
		} `json:"sessions"`
	}
	alice.Expect(alice.Do(http.MethodGet, "/v1/auth/sessions", nil), http.StatusOK, &list)
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions %+v", list)
	}
	current := 0
	for _, s := range list.Sessions {
		if s.Current {
			current++
			if s.ID != alice.Tokens.SessionID || s.ClientID != clientID {
				t.Fatalf("current session %+v", s)
			}
		}
	}
	if current != 1 {
		t.Fatalf("%d current sessions", current)
	}
	// Refresh rotates the tokens; the old refresh token is spent.
	old := alice.Tokens
	var fresh apiclient.Tokens
	alice.Expect(alice.ProofOnly(http.MethodPost, "/v1/auth/refresh", map[string]any{"refresh_token": old.RefreshToken}),
		http.StatusOK, &fresh)
	if fresh.RefreshToken == old.RefreshToken || fresh.SessionID != old.SessionID || fresh.TokenType != "DPoP" {
		t.Fatalf("refreshed %+v", fresh)
	}
	alice.Tokens = fresh
	alice.Expect(alice.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, nil)
	// Refreshing with another client's key fails.
	if r := other.ProofOnly(http.MethodPost, "/v1/auth/refresh", map[string]any{"refresh_token": fresh.RefreshToken}); r.Status != http.StatusBadRequest ||
		r.Problem.Code != "invalid_grant" {
		t.Fatalf("refresh with a foreign key: %d %s", r.Status, r.Body)
	}
	// Logout ends the session: its token no longer works.
	alice.Expect(alice.Do(http.MethodPost, "/v1/auth/logout", nil), http.StatusNoContent, nil)
	if r := alice.Do(http.MethodGet, "/v1/me", nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", r.Status)
	}
	other.Expect(other.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, nil)
}

func TestRegistrationRefusals(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	for name, body := range map[string]any{"empty name": map[string]any{"display_name": ""},
		"control characters": map[string]any{"display_name": "a\u0007b"},
		"long name":          map[string]any{"display_name": string(make([]rune, 65))}} {
		if r := c.ProofOnly(http.MethodPost, "/v1/auth/register/begin", body); r.Status != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	// An unknown client id cannot get a session.
	var begin struct {
		FlowID  string                   `json:"flow_id"`
		Options webauthn.CreationOptions `json:"options"`
	}
	c.Expect(c.ProofOnly(http.MethodPost, "/v1/auth/register/begin", map[string]any{"display_name": "Eve"}), http.StatusOK, &begin)
	cred := h.auth.NewCredential(cose.AlgES256)
	resp := h.auth.Register(cred, &begin.Options, authenticator.Options{})
	if r := c.ProofOnly(http.MethodPost, "/v1/auth/register/finish", map[string]any{"flow_id": begin.FlowID,
		"credential": resp, "client_id": "evil-app"}); r.Status != http.StatusUnprocessableEntity || r.Problem.Code != "invalid_client" {
		t.Fatalf("unknown client: %d %s", r.Status, r.Body)
	}
	// A response for another relying party is rejected at its step.
	c.Expect(c.ProofOnly(http.MethodPost, "/v1/auth/register/begin", map[string]any{"display_name": "Eve"}), http.StatusOK, &begin)
	resp = h.auth.Register(cred, &begin.Options, authenticator.Options{Origin: "https://evil.example"})
	r := c.ProofOnly(http.MethodPost, "/v1/auth/register/finish", map[string]any{"flow_id": begin.FlowID, "credential": resp,
		"client_id": clientID})
	if r.Status != http.StatusBadRequest || r.Problem.Code != "webauthn_rejected" || r.Problem.Step == "" {
		t.Fatalf("foreign origin: %d %s", r.Status, r.Body)
	}
	// Proof-only endpoints need a proof.
	if r := c.Anonymous(http.MethodPost, "/v1/auth/login/begin", map[string]any{}); r.Status != http.StatusUnauthorized {
		t.Fatalf("login without a proof: %d", r.Status)
	}
}

func TestStepUpForSensitiveOperations(t *testing.T) {
	h := newHarness(t, nil)
	alice, cred := h.person("Alice")
	other := h.client()
	other.Expect(other.Login(h.auth, cred, clientID, nil), http.StatusOK, nil)
	// Six minutes later, closing another session needs a fresh passkey.
	h.env.Clock.Advance(6 * time.Minute)
	r := alice.Do(http.MethodDelete, "/v1/auth/sessions/"+other.Tokens.SessionID.String(), nil)
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("stale authentication: %d %s", r.Status, r.Body)
	}
	if maxAge, ok := session.ParseMaxAge(r.Header.Get("WWW-Authenticate")); !ok || maxAge != 5*time.Minute {
		t.Fatalf("step-up challenge %q", r.Header.Get("WWW-Authenticate"))
	}
	alice.StepUp(h.auth, cred)
	alice.Expect(alice.Do(http.MethodDelete, "/v1/auth/sessions/"+other.Tokens.SessionID.String(), nil), http.StatusNoContent, nil)
	if r := other.Do(http.MethodGet, "/v1/me", nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("closed session still works: %d", r.Status)
	}
	// Step-up with someone else's passkey is refused.
	_, mallory := h.person("Mallory")
	var begin struct {
		FlowID  string                  `json:"flow_id"`
		Options webauthn.RequestOptions `json:"options"`
	}
	alice.Expect(alice.Do(http.MethodPost, "/v1/auth/step-up/begin", map[string]any{}), http.StatusOK, &begin)
	begin.Options.AllowCredentials = nil
	if r := alice.Do(http.MethodPost, "/v1/auth/step-up/finish", map[string]any{"flow_id": begin.FlowID,
		"credential": h.auth.Assert(mallory, &begin.Options, authenticator.AssertOptions{})}); r.Status < 400 {
		t.Fatalf("foreign passkey stepped up: %d %s", r.Status, r.Body)
	}
}

func TestDeviceBindingAndRevocation(t *testing.T) {
	h := newHarness(t, nil)
	alice, cred := h.person("Alice")
	phone := h.env.Google.NewDevice(true)
	_, dev := alice.BindAndroid(phone, "dev", uuid.Nil)
	_, gest := alice.BindAndroid(phone, "gest", dev.Device.ID)
	if gest.Device.ID != dev.Device.ID || dev.Key.Role != "dev" || gest.Key.Role != "gest" {
		t.Fatalf("bindings %+v %+v", dev, gest)
	}
	var list struct {
		Devices []struct {
			ID        uuid.UUID `json:"id"`
			Platform  string    `json:"platform"`
			Integrity struct {
				Source string `json:"source"`
			} `json:"integrity"`
			Keys []struct {
				ID            uuid.UUID `json:"id"`
				Role          string    `json:"role"`
				SecurityLevel string    `json:"security_level"`
			} `json:"keys"`
		} `json:"devices"`
	}
	alice.Expect(alice.Do(http.MethodGet, "/v1/devices", nil), http.StatusOK, &list)
	if len(list.Devices) != 1 || list.Devices[0].Platform != "android" || len(list.Devices[0].Keys) != 2 ||
		list.Devices[0].Keys[0].SecurityLevel != "strongbox" {
		t.Fatalf("devices %+v", list)
	}
	// A session bound to the phone.
	bound := h.client()
	bound.Expect(bound.Login(h.auth, cred, clientID, &dev.Device.ID), http.StatusOK, nil)
	var me map[string]any
	bound.Expect(bound.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, &me)
	if me["device_id"] != dev.Device.ID.String() {
		t.Fatalf("bound session %v", me)
	}
	// Someone else's device cannot be bound to a session.
	mallory, mcred := h.person("Mallory")
	if r := mallory.Login(h.auth, mcred, clientID, &dev.Device.ID); r.Status != http.StatusNotFound {
		t.Fatalf("login bound to another's device: %d %s", r.Status, r.Body)
	}
	// Revoking a key, then the device: its keys and sessions end with it.
	alice.Expect(alice.Do(http.MethodDelete, "/v1/devices/"+dev.Device.ID.String()+"/keys/"+gest.Key.ID.String(), nil),
		http.StatusNoContent, nil)
	if r := alice.Do(http.MethodDelete, "/v1/devices/"+dev.Device.ID.String()+"/keys/"+gest.Key.ID.String(), nil); r.Status != http.StatusNotFound {
		t.Fatalf("revoked key again: %d", r.Status)
	}
	if r := mallory.Do(http.MethodDelete, "/v1/devices/"+dev.Device.ID.String(), nil); r.Status != http.StatusNotFound {
		t.Fatalf("revoking another's device: %d %s", r.Status, r.Body)
	}
	alice.Expect(alice.Do(http.MethodDelete, "/v1/devices/"+dev.Device.ID.String(), nil), http.StatusNoContent, nil)
	if r := bound.Do(http.MethodGet, "/v1/me", nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("session of a revoked device: %d", r.Status)
	}
	alice.Expect(alice.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, nil)
	alice.Expect(alice.Do(http.MethodGet, "/v1/devices", nil), http.StatusOK, &list)
	if len(list.Devices) != 0 {
		t.Fatalf("revoked device listed: %+v", list)
	}
	// Challenges for an unknown purpose or someone else's device fail.
	if r := alice.Do(http.MethodPost, "/v1/devices/challenges", map[string]any{"purpose": "mine"}); r.Status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown purpose: %d %s", r.Status, r.Body)
	}
	if r := alice.Do(http.MethodPost, "/v1/devices/android", map[string]any{"flow_id": "nope", "role": "dev",
		"chain": []string{}, "integrity_token": ""}); r.Status != http.StatusBadRequest || r.Problem.Code != "flow_invalid" {
		t.Fatalf("unknown flow: %d %s", r.Status, r.Body)
	}
}
