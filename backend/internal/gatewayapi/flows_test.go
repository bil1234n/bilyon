package gatewayapi_test

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/gatewayapi"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/jose"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/apiclient"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/intentsenv"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

type par struct {
	PAR   gatewayapi.Bytes `json:"par"`
	Entry struct {
		Subject    string   `json:"subject"`
		Version    uint64   `json:"version"`
		Handle     string   `json:"handle"`
		Name       string   `json:"name"`
		Currencies []string `json:"currencies"`
	} `json:"entry"`
	TreeSize uint64 `json:"tree_size"`
}

// directoryKeys fetches K_dir from the public endpoint, as a client does.
func directoryKeys(t *testing.T, c *apiclient.Client) cose.KeyResolver {
	t.Helper()
	var out struct {
		Keys []struct {
			KID gatewayapi.Bytes `json:"kid"`
			JWK jose.JWK         `json:"jwk"`
		} `json:"keys"`
	}
	c.Expect(c.Anonymous(http.MethodGet, "/v1/directory/keys", nil), http.StatusOK, &out)
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range out.Keys {
		pub, err := k.JWK.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[string(k.KID)] = pub
	}
	return func(kid []byte) (*ecdsa.PublicKey, error) {
		if k, ok := keys[string(kid)]; ok {
			return k, nil
		}
		return nil, cose.ErrUnknownKey
	}
}

func TestDirectory(t *testing.T) {
	h := newHarness(t, nil)
	alice, _ := h.person("Alice")
	bob, _ := h.person("Bob")
	var claimed struct {
		Handle string `json:"handle"`
		Entry  struct {
			Version uint64 `json:"version"`
			Subject string `json:"subject"`
		} `json:"entry"`
	}
	alice.Expect(alice.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "@Alicia"}), http.StatusOK, &claimed)
	if claimed.Handle != "Alicia" || claimed.Entry.Version != 1 {
		t.Fatalf("claimed %+v", claimed)
	}
	if r := bob.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "alicia"}); r.Status != http.StatusConflict ||
		r.Problem.Code != "handle_taken" {
		t.Fatalf("taken handle: %d %s", r.Status, r.Body)
	}
	if r := bob.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "support"}); r.Status != http.StatusConflict ||
		r.Problem.Code != "handle_reserved" {
		t.Fatalf("reserved handle: %d %s", r.Status, r.Body)
	}
	if r := bob.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "b"}); r.Status != http.StatusUnprocessableEntity ||
		r.Problem.Code != "invalid_handle" || r.Problem.Rule == "" {
		t.Fatalf("invalid handle: %d %s", r.Status, r.Body)
	}
	alice.Expect(alice.Do(http.MethodPut, "/v1/me/profile", map[string]any{"name": "Alice A.",
		"currencies": []string{"EUR", "USD"}, "default_currency": "EUR"}), http.StatusOK, nil)
	if r := alice.Do(http.MethodPut, "/v1/me/profile", map[string]any{"name": "x", "currencies": []string{"EUR"},
		"default_currency": "USD"}); r.Status != http.StatusUnprocessableEntity || r.Problem.Code != "invalid_profile" {
		t.Fatalf("inconsistent profile: %d %s", r.Status, r.Body)
	}
	// Bob resolves Alice by a lookalike of her handle and verifies the PAR.
	var p par
	bob.Expect(bob.Do(http.MethodGet, "/v1/directory/handles/a1icia", nil), http.StatusOK, &p)
	verified, err := identity.VerifyPAR(p.PAR, directoryKeys(t, bob), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Entry.Subject != claimed.Entry.Subject || verified.Entry.Version != 2 || p.Entry.Name != "Alice A." ||
		p.Entry.Handle != "Alicia" || len(p.Entry.Currencies) != 2 {
		t.Fatalf("PAR %+v / %+v", p, verified.Entry)
	}
	var bySubject par
	bob.Expect(bob.Do(http.MethodGet, "/v1/directory/subjects/"+claimed.Entry.Subject, nil), http.StatusOK, &bySubject)
	if bySubject.Entry.Version != 2 {
		t.Fatalf("by subject %+v", bySubject)
	}
	if r := bob.Do(http.MethodGet, "/v1/directory/handles/nobody_here", nil); r.Status != http.StatusNotFound {
		t.Fatalf("unknown handle: %d", r.Status)
	}
	if r := bob.Do(http.MethodGet, "/v1/directory/subjects/not-a-subject", nil); r.Status != http.StatusUnprocessableEntity {
		t.Fatalf("malformed subject: %d", r.Status)
	}
	var me map[string]any
	alice.Expect(alice.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, &me)
	if entry, ok := me["entry"].(map[string]any); !ok || entry["handle"] != "Alicia" {
		t.Fatalf("me %v", me)
	}
	// The transparency log is public.
	anon := h.client()
	if r := anon.Anonymous(http.MethodGet, "/v1/directory/log?from=0&limit=10", nil); r.Status != http.StatusOK {
		t.Fatalf("log: %d", r.Status)
	}
	var leaves struct {
		Leaves []gatewayapi.Bytes `json:"leaves"`
	}
	anon.Expect(anon.Anonymous(http.MethodGet, "/v1/directory/log?from=0&limit=10", nil), http.StatusOK, &leaves)
	if len(leaves.Leaves) != 2 {
		t.Fatalf("%d leaves", len(leaves.Leaves))
	}
	if e, err := identity.DecodeEntry(leaves.Leaves[1]); err != nil || e.Version != 2 {
		t.Fatalf("leaf %v %v", e, err)
	}
	var sth struct {
		TreeSize uint64           `json:"tree_size"`
		STH      gatewayapi.Bytes `json:"sth"`
	}
	anon.Expect(anon.Anonymous(http.MethodGet, "/v1/directory/sth", nil), http.StatusOK, &sth)
	if sth.TreeSize < 2 {
		t.Fatalf("tree head %+v", sth)
	}
	var cons struct {
		Proof []gatewayapi.Bytes `json:"proof"`
	}
	anon.Expect(anon.Anonymous(http.MethodGet, "/v1/directory/consistency?first=1&second=2", nil), http.StatusOK, &cons)
	if len(cons.Proof) != 1 {
		t.Fatalf("consistency proof %+v", cons)
	}
	for _, q := range []string{"first=3&second=2", "first=x", "second=-1"} {
		if r := anon.Anonymous(http.MethodGet, "/v1/directory/consistency?"+q, nil); r.Status/100 != 4 {
			t.Fatalf("consistency %s: %d", q, r.Status)
		}
	}
	if r := anon.Anonymous(http.MethodGet, "/v1/directory/log?limit=5000", nil); r.Status != http.StatusBadRequest {
		t.Fatalf("oversized page: %d", r.Status)
	}
	// Releasing the handle publishes a new version without it.
	var released struct {
		Entry struct {
			Version uint64 `json:"version"`
			Handle  string `json:"handle"`
		} `json:"entry"`
	}
	alice.Expect(alice.Do(http.MethodDelete, "/v1/me/handle", nil), http.StatusOK, &released)
	if released.Entry.Version != 3 || released.Entry.Handle != "" {
		t.Fatalf("released %+v", released)
	}
}

// payer registers with a bound phone (K_dev, K_gest) and a funded account.
type payer struct {
	c       *apiclient.Client
	gest    *ecdsa.PrivateKey
	gestKey uuid.UUID
	device  uuid.UUID
}

func (h *harness) payer(name string) payer {
	h.t.Helper()
	c, cred := h.person(name)
	phone := h.env.Google.NewDevice(false)
	_, dev := c.BindAndroid(phone, "dev", uuid.Nil)
	gest, g := c.BindAndroid(phone, "gest", dev.Device.ID)
	// Sign in on the phone so the session is bound to it.
	c.Expect(c.Login(h.auth, cred, clientID, &dev.Device.ID), http.StatusOK, nil)
	return payer{c: c, gest: gest, gestKey: g.Key.ID, device: dev.Device.ID}
}

// throw builds and submits a flick to subject the way the app does:
// resolve the payee's PAR, take a nonce, sign with K_gest.
func (h *harness) throw(p payer, subject string, amount int64, edit func(*txauth.TxAuth)) *apiclient.Response {
	h.t.Helper()
	var payee par
	p.c.Expect(p.c.Do(http.MethodGet, "/v1/directory/subjects/"+subject, nil), http.StatusOK, &payee)
	var ns struct {
		Nonces []struct {
			Value gatewayapi.Bytes `json:"value"`
		} `json:"nonces"`
	}
	p.c.Expect(p.c.Do(http.MethodPost, "/v1/intents/nonces", map[string]any{"count": 2}), http.StatusOK, &ns)
	id, err := uuid.NewV7()
	if err != nil {
		h.t.Fatal(err)
	}
	now := h.env.Clock.Now()
	ta := txauth.TxAuth{IntentID: id, Amount: amount, Currency: "EUR", PayeeRef: identity.PayeeRef(subject),
		SignedAt: now.Truncate(time.Second), Gesture: txauth.GestureFlick, PARVersion: payee.Entry.Version}
	copy(ta.Nonce[:], ns.Nonces[0].Value)
	if edit != nil {
		edit(&ta)
	}
	signer, err := cose.NewKeySigner(p.gest)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := txauth.Sign(signer, p.gestKey, &ta)
	if err != nil {
		h.t.Fatal(err)
	}
	return p.c.Do(http.MethodPost, "/v1/intents", map[string]any{"txauth": gatewayapi.Bytes(raw), "gesture": "flick",
		"payee_subject": subject, "amount": amount, "currency": "EUR", "t_land_ms": now.Add(450 * time.Millisecond).UnixMilli(),
		"trajectory": map[string]any{"az": 0.1, "v": 1.6, "d": 1.4}})
}

type intentOut struct {
	ID           uuid.UUID `json:"id"`
	State        string    `json:"state"`
	Reason       string    `json:"reason"`
	Role         string    `json:"role"`
	PayerSubject string    `json:"payer_subject"`
	PayeeSubject string    `json:"payee_subject"`
	Amount       int64     `json:"amount"`
	OnTimeout    string    `json:"on_timeout"`
	TLandMs      *int64    `json:"t_land_ms"`
	EntryIDs     []string  `json:"entry_ids"`
}

func TestThrowAndCatchOverREST(t *testing.T) {
	h := newHarness(t, nil)
	alice := h.payer("Alice")
	h.env.Fund(&intentsenv.Person{User: alice.c.UserID}, "EUR", 300_00)
	bob, _ := h.person("Bob")
	var bobMe struct {
		Subject string `json:"subject"`
	}
	bob.Expect(bob.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "bob_b"}), http.StatusOK, nil)
	bob.Expect(bob.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, &bobMe)

	var in intentOut
	alice.c.Expect(h.throw(alice, bobMe.Subject, 42_00, nil), http.StatusOK, &in)
	if in.State != "held" || in.Role != "payer" || in.OnTimeout != "async" || in.TLandMs == nil || in.Amount != 42_00 {
		t.Fatalf("thrown %+v", in)
	}
	// The payee sees it, acknowledges delivery and catches.
	var list struct {
		Intents []intentOut `json:"intents"`
	}
	bob.Expect(bob.Do(http.MethodGet, "/v1/intents?role=payee&state=held", nil), http.StatusOK, &list)
	if len(list.Intents) != 1 || list.Intents[0].ID != in.ID || list.Intents[0].Role != "payee" || list.Intents[0].OnTimeout != "" {
		t.Fatalf("payee's list %+v", list)
	}
	bob.Expect(bob.Do(http.MethodPost, "/v1/intents/"+in.ID.String()+"/delivered", nil), http.StatusOK, nil)
	var caught intentOut
	bob.Expect(bob.Do(http.MethodPost, "/v1/intents/"+in.ID.String()+"/catch", map[string]any{"accept": true}),
		http.StatusOK, &caught)
	if caught.State != "settled" || len(caught.EntryIDs) != 1 {
		t.Fatalf("caught %+v", caught)
	}
	var accts struct {
		Accounts []struct {
			Currency  string `json:"currency"`
			Posted    int64  `json:"posted"`
			Available int64  `json:"available"`
		} `json:"accounts"`
	}
	bob.Expect(bob.Do(http.MethodGet, "/v1/accounts", nil), http.StatusOK, &accts)
	if len(accts.Accounts) != 1 || accts.Accounts[0].Posted != 42_00 {
		t.Fatalf("payee accounts %+v", accts)
	}
	alice.c.Expect(alice.c.Do(http.MethodGet, "/v1/accounts", nil), http.StatusOK, &accts)
	if accts.Accounts[0].Posted != 258_00 || accts.Accounts[0].Available != 258_00 {
		t.Fatalf("payer accounts %+v", accts)
	}
	// Refusals carry problem details.
	r := alice.c.Do(http.MethodPost, "/v1/intents/"+in.ID.String()+"/cancel", nil)
	if r.Status != http.StatusConflict || r.Problem.Code != "invalid_state" || r.Problem.State != "settled" {
		t.Fatalf("cancel after settlement: %d %s", r.Status, r.Body)
	}
	if r := alice.c.Do(http.MethodGet, "/v1/intents/"+uuid.NewString(), nil); r.Status != http.StatusNotFound {
		t.Fatalf("unknown intent: %d", r.Status)
	}
	r = h.throw(alice, bobMe.Subject, 5_00, func(ta *txauth.TxAuth) { ta.Amount = 6_00 })
	if r.Status != http.StatusUnprocessableEntity || r.Problem.Code != "txauth_mismatch" {
		t.Fatalf("mismatch: %d %s", r.Status, r.Body)
	}
	r = h.throw(alice, bobMe.Subject, 5_00, func(ta *txauth.TxAuth) { ta.Nonce[15] ^= 1 })
	if r.Status != http.StatusForbidden || r.Problem.Code != "nonce_rejected" {
		t.Fatalf("bad nonce: %d %s", r.Status, r.Body)
	}
	// A refused payment is a durable intent, answered with its reason.
	var aborted intentOut
	alice.c.Expect(h.throw(alice, bobMe.Subject, 100_01, nil), http.StatusOK, &aborted)
	if aborted.State != "aborted" || aborted.Reason != "gesture_limit" {
		t.Fatalf("over the gesture limit %+v", aborted)
	}
	// The payer's preference for uncaught throws.
	alice.c.Expect(alice.c.Do(http.MethodPut, "/v1/me/preferences", map[string]any{"intent_timeout": "void"}), http.StatusOK, nil)
	var voidThrow intentOut
	alice.c.Expect(h.throw(alice, bobMe.Subject, 1_00, nil), http.StatusOK, &voidThrow)
	if voidThrow.OnTimeout != "void" {
		t.Fatalf("preference %+v", voidThrow)
	}
	if r := alice.c.Do(http.MethodPut, "/v1/me/preferences", map[string]any{"intent_timeout": "soon"}); r.Status != http.StatusUnprocessableEntity {
		t.Fatalf("bad preference: %d", r.Status)
	}
	// Nonces need a device: an unbound session must name one of its own.
	unbound, _ := h.person("Carol")
	if r := unbound.Do(http.MethodPost, "/v1/intents/nonces", map[string]any{"count": 1}); r.Status != http.StatusUnprocessableEntity {
		t.Fatalf("nonces without a device: %d", r.Status)
	}
	if r := unbound.Do(http.MethodPost, "/v1/intents/nonces", map[string]any{"count": 1, "device_id": alice.device}); r.Status != http.StatusForbidden {
		t.Fatalf("nonces for another's device: %d", r.Status)
	}
	// Cross-currency quotes are off without an FX service.
	if r := alice.c.Do(http.MethodPost, "/v1/fx/quotes", map[string]any{"from": "EUR", "to": "USD", "amount_in": 100}); r.Status != http.StatusNotImplemented ||
		r.Problem.Code != "fx_disabled" {
		t.Fatalf("fx: %d %s", r.Status, r.Body)
	}
}

func TestErrorsAndLimits(t *testing.T) {
	h := newHarness(t, func(c *gatewayapi.Config) {
		c.RateLimits.LookupMinute = gatewayapi.Limit{N: 3, Per: time.Minute}
		c.RateLimits.Auth = gatewayapi.Limit{N: 8, Per: time.Minute}
	})
	alice, _ := h.person("Alice")
	if r := alice.Do(http.MethodGet, "/v1/nothing", nil); r.Status != http.StatusNotFound || r.Problem.Code != "not_found" ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/problem+json") {
		t.Fatalf("unknown route: %d %s", r.Status, r.Body)
	}
	for name, body := range map[string][]byte{"not json": []byte("{"), "unknown member": []byte(`{"handle":"x","extra":1}`),
		"trailing data": []byte(`{"handle":"abc"} {}`), "empty": []byte("")} {
		if r := alice.Do(http.MethodPut, "/v1/me/handle", body); r.Status != http.StatusBadRequest || r.Problem.Code != "invalid_request" {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	if r := alice.Do(http.MethodPut, "/v1/me/handle", make([]byte, 70<<10)); r.Status != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", r.Status)
	}
	// No credentials, a bearer token, a token without its proof.
	if r := alice.Anonymous(http.MethodGet, "/v1/me", nil); r.Status != http.StatusUnauthorized ||
		!strings.HasPrefix(r.Header.Get("WWW-Authenticate"), "DPoP") {
		t.Fatalf("anonymous: %d %v", r.Status, r.Header)
	}
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+alice.Tokens.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer token: %d", resp.StatusCode)
	}
	// Lookups: three per minute here.
	for i := 0; i < 3; i++ {
		if r := alice.Do(http.MethodGet, "/v1/directory/handles/nobody_x", nil); r.Status != http.StatusNotFound {
			t.Fatalf("lookup %d: %d", i, r.Status)
		}
	}
	r := alice.Do(http.MethodGet, "/v1/directory/handles/nobody_x", nil)
	if r.Status != http.StatusTooManyRequests || r.Problem.Code != "rate_limited" || r.Header.Get("Retry-After") == "" {
		t.Fatalf("fourth lookup: %d %s", r.Status, r.Body)
	}
	h.env.Clock.Advance(time.Minute)
	if r := alice.Do(http.MethodGet, "/v1/directory/handles/nobody_x", nil); r.Status != http.StatusNotFound {
		t.Fatalf("lookup in the next window: %d", r.Status)
	}
	// Unauthenticated endpoints, per address.
	anon := h.client()
	limited := false
	for i := 0; i < 12 && !limited; i++ {
		limited = anon.ProofOnly(http.MethodPost, "/v1/auth/login/begin", map[string]any{}).Status == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("login was never rate limited")
	}
	// Request ids are echoed (or generated) and metrics recorded.
	req, _ = http.NewRequest(http.MethodGet, h.server.URL+"/v1/directory/keys", nil)
	req.Header.Set("X-Request-Id", "trace-42")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("X-Request-Id") != "trace-42" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", resp.Header)
	}
	families, err := h.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "route" && l.GetValue() == "GET /v1/directory/keys" {
					seen = true
				}
			}
		}
	}
	if !seen {
		t.Fatal("request metrics missing")
	}
	if r := alice.Do(http.MethodGet, "/v1/intents/not-a-uuid", nil); r.Status != http.StatusNotFound {
		t.Fatalf("malformed id: %d", r.Status)
	}
	if r := alice.Do(http.MethodGet, fmt.Sprintf("/v1/intents?limit=%d", 500), nil); r.Status != http.StatusUnprocessableEntity {
		t.Fatalf("oversized page: %d %s", r.Status, r.Body)
	}
}
