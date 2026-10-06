package gatewayapi_test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/gatewayapi"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/devicesim"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/intentsenv"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

func TestCallsAreRateLimitedPerAccount(t *testing.T) {
	h := newHarness(t, func(c *gatewayapi.Config) { c.RateLimits.Calls = gatewayapi.Limit{N: 4, Per: time.Minute} })
	alice, _ := h.person("Alice")
	bob, _ := h.person("Bob")
	for i := 0; i < 4; i++ {
		alice.Expect(alice.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, nil)
	}
	if r := alice.Do(http.MethodGet, "/v1/me", nil); r.Status != http.StatusTooManyRequests {
		t.Fatalf("fifth call: %d", r.Status)
	}
	// Another account has its own budget.
	bob.Expect(bob.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, nil)
}

func TestSensitiveDeviceOperationsNeedRecentAuth(t *testing.T) {
	h := newHarness(t, nil)
	alice, cred := h.person("Alice")
	phone := h.env.Google.NewDevice(false)
	_, dev := alice.BindAndroid(phone, "dev", uuid.Nil)
	_, gest := alice.BindAndroid(phone, "gest", dev.Device.ID)
	_, dev2 := alice.BindAndroid(h.env.Google.NewDevice(false), "dev", uuid.Nil)
	h.env.Clock.Advance(6 * time.Minute)
	for _, path := range []string{"/v1/devices/" + dev.Device.ID.String(),
		"/v1/devices/" + dev.Device.ID.String() + "/keys/" + gest.Key.ID.String()} {
		r := alice.Do(http.MethodDelete, path, nil)
		if r.Status != http.StatusUnauthorized || !strings.Contains(r.Header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
			t.Fatalf("DELETE %s without recent auth: %d %v", path, r.Status, r.Header)
		}
	}
	alice.StepUp(h.auth, cred)
	// A key that belongs to another of the user's devices is not on this one.
	if r := alice.Do(http.MethodDelete, "/v1/devices/"+dev2.Device.ID.String()+"/keys/"+gest.Key.ID.String(), nil); r.Status != http.StatusNotFound {
		t.Fatalf("key of another device: %d %s", r.Status, r.Body)
	}
	alice.Expect(alice.Do(http.MethodDelete, "/v1/devices/"+dev.Device.ID.String()+"/keys/"+gest.Key.ID.String(), nil),
		http.StatusNoContent, nil)
	// Nobody closes another account's session.
	mallory, _ := h.person("Mallory")
	if r := mallory.Do(http.MethodDelete, "/v1/auth/sessions/"+alice.Tokens.SessionID.String(), nil); r.Status != http.StatusNotFound {
		t.Fatalf("closing another's session: %d %s", r.Status, r.Body)
	}
	alice.Expect(alice.Do(http.MethodGet, "/v1/me", nil), http.StatusOK, nil)
}

func TestIntegrityRefreshAndCoins(t *testing.T) {
	h := newHarness(t, nil)
	alice, _ := h.person("Alice")
	phone := h.env.Google.NewDevice(true)
	kdev, dev := alice.BindAndroid(phone, "dev", uuid.Nil)
	_, dev2 := alice.BindAndroid(h.env.Google.NewDevice(false), "dev", uuid.Nil)
	challenge := func(purpose string, device uuid.UUID) (string, []byte) {
		var ch struct {
			FlowID    string           `json:"flow_id"`
			Challenge gatewayapi.Bytes `json:"challenge"`
		}
		alice.Expect(alice.Do(http.MethodPost, "/v1/devices/challenges", map[string]any{"purpose": purpose,
			"device_id": device}), http.StatusOK, &ch)
		return ch.FlowID, ch.Challenge
	}
	flow, ch := challenge("integrity", dev.Device.ID)
	token := phone.IntegrityToken(ch, devicesim.Point(t, kdev), nil)
	var refreshed struct {
		ID        uuid.UUID `json:"id"`
		Integrity struct {
			Source         string   `json:"source"`
			DeviceVerdicts []string `json:"device_verdicts"`
		} `json:"integrity"`
	}
	alice.Expect(alice.Do(http.MethodPost, "/v1/devices/"+dev.Device.ID.String()+"/integrity",
		map[string]any{"flow_id": flow, "integrity_token": token}), http.StatusOK, &refreshed)
	if refreshed.ID != dev.Device.ID || refreshed.Integrity.Source != devicebind.SourcePlayIntegrity ||
		len(refreshed.Integrity.DeviceVerdicts) == 0 {
		t.Fatalf("refreshed %+v", refreshed)
	}
	// The path must name the flow's device.
	flow, ch = challenge("integrity", dev.Device.ID)
	if r := alice.Do(http.MethodPost, "/v1/devices/"+dev2.Device.ID.String()+"/integrity", map[string]any{"flow_id": flow,
		"integrity_token": phone.IntegrityToken(ch, devicesim.Point(t, kdev), nil)}); r.Status != http.StatusBadRequest {
		t.Fatalf("flow for another device: %d %s", r.Status, r.Body)
	}
	// Tier S coins: single-use, rollback-resistant StrongBox keys.
	flow, ch = challenge("coins", dev.Device.ID)
	chains := make([][]string, 3)
	var pubs [][]byte
	for i := range chains {
		key, chain := phone.GenerateKey(devicebind.RoleCoin, ch, devicesim.KeyOptions{})
		pubs = append(pubs, devicesim.Point(t, key))
		for _, cert := range chain {
			chains[i] = append(chains[i], base64.RawURLEncoding.EncodeToString(cert))
		}
	}
	var coins struct {
		Coins []struct {
			PublicKey     gatewayapi.Bytes `json:"public_key"`
			SecurityLevel string           `json:"security_level"`
		} `json:"coins"`
	}
	alice.Expect(alice.Do(http.MethodPost, "/v1/devices/coins", map[string]any{"flow_id": flow, "chains": chains,
		"integrity_token": phone.IntegrityToken(ch, devicesim.Point(t, kdev), nil)}), http.StatusOK, &coins)
	if len(coins.Coins) != 3 || string(coins.Coins[2].PublicKey) != string(pubs[2]) || coins.Coins[0].SecurityLevel != "strongbox" {
		t.Fatalf("coins %+v", coins)
	}
}

func TestDropsAreNotGrabbedOverREST(t *testing.T) {
	h := newHarness(t, nil)
	alice := h.payer("Alice")
	h.env.Fund(&intentsenv.Person{User: alice.c.UserID}, "EUR", 100_00)
	var ns struct {
		Nonces []struct {
			Value gatewayapi.Bytes `json:"value"`
		} `json:"nonces"`
	}
	alice.c.Expect(alice.c.Do(http.MethodPost, "/v1/intents/nonces", map[string]any{"count": 1}), http.StatusOK, &ns)
	id := uuid.Must(uuid.NewV7())
	ta := txauth.TxAuth{IntentID: id, Amount: 5_00, Currency: "EUR", PayeeRef: txauth.DropPayeeRef(id),
		SignedAt: h.env.Clock.Now().Truncate(time.Second), Gesture: txauth.GestureGrab}
	copy(ta.Nonce[:], ns.Nonces[0].Value)
	signer, _ := cose.NewKeySigner(alice.gest)
	raw, err := txauth.Sign(signer, alice.gestKey, &ta)
	if err != nil {
		t.Fatal(err)
	}
	var drop intentOut
	alice.c.Expect(alice.c.Do(http.MethodPost, "/v1/intents", map[string]any{"txauth": gatewayapi.Bytes(raw), "gesture": "grab",
		"amount": 5_00, "currency": "EUR"}), http.StatusOK, &drop)
	if drop.State != "held" || drop.PayeeSubject != "" {
		t.Fatalf("drop %+v", drop)
	}
	// Only the realtime gateway can vouch for proximity.
	grabber, _ := h.person("Grabber")
	r := grabber.Do(http.MethodPost, "/v1/intents/"+id.String()+"/catch", map[string]any{"accept": true})
	if r.Status != http.StatusForbidden || r.Problem.Code != "forbidden" {
		t.Fatalf("grab over REST: %d %s", r.Status, r.Body)
	}
}

func TestContentTypeAndRequestIDs(t *testing.T) {
	h := newHarness(t, nil)
	alice, _ := h.person("Alice")
	req, _ := http.NewRequest(http.MethodPut, h.server.URL+"/v1/me/handle", strings.NewReader(`{"handle":"abc"}`))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated text body: %d", resp.StatusCode)
	}
	// Authenticated, but not declared as JSON.
	alice.ContentType = "text/plain"
	r := alice.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "abc"})
	if r.Status != http.StatusBadRequest || !strings.Contains(r.Problem.Detail, "Content-Type") {
		t.Fatalf("text body: %d %s", r.Status, r.Body)
	}
	alice.ContentType = "application/json; charset=utf-8"
	alice.Expect(alice.Do(http.MethodPut, "/v1/me/handle", map[string]any{"handle": "abc"}), http.StatusOK, nil)
	req, _ = http.NewRequest(http.MethodGet, h.server.URL+"/v1/directory/keys", nil)
	req.Header.Set("X-Request-Id", "bad id with spaces")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if id := resp.Header.Get("X-Request-Id"); id == "" || strings.Contains(id, " ") || len(id) != 24 {
		t.Fatalf("generated request id %q", id)
	}
	// API responses are never cached; only the public key set may be.
	if r := alice.Do(http.MethodGet, "/v1/me", nil); r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", r.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("keys Cache-Control %q", resp.Header.Get("Cache-Control"))
	}
}
