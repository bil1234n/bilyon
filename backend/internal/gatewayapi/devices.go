package gatewayapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/devicebind"
)

type challengeView struct {
	FlowID    string    `json:"flow_id"`
	Challenge Bytes     `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *API) deviceChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Purpose  string     `json:"purpose"`             // bind, coins, integrity
		DeviceID *uuid.UUID `json:"device_id,omitempty"` // absent: register a new device
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	device := uuid.Nil
	if req.DeviceID != nil {
		device = *req.DeviceID
	}
	ch, err := a.d.Devices.Begin(r.Context(), principal(r).UserID, device, devicebind.Purpose(req.Purpose))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, challengeView{FlowID: ch.FlowID, Challenge: ch.Challenge, ExpiresAt: ch.Expires.UTC()})
}

type keyView struct {
	ID            uuid.UUID  `json:"id"`
	Role          string     `json:"role"`
	PublicKey     Bytes      `json:"public_key"`
	SecurityLevel string     `json:"security_level"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

type deviceView struct {
	ID          uuid.UUID  `json:"id"`
	Platform    string     `json:"platform"`
	Integrity   any        `json:"integrity"`
	IntegrityAt time.Time  `json:"integrity_at"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	Keys        []keyView  `json:"keys,omitempty"`
}

func viewKey(k devicebind.Key) keyView {
	return keyView{ID: k.ID, Role: k.Role, PublicKey: k.PublicKey, SecurityLevel: k.SecurityLevel,
		CreatedAt: k.CreatedAt.UTC(), RevokedAt: tstamp(k.RevokedAt)}
}

func viewDevice(d devicebind.Device, keys []devicebind.Key) deviceView {
	v := deviceView{ID: d.ID, Platform: d.Platform, Integrity: d.Integrity, IntegrityAt: d.IntegrityAt.UTC(),
		CreatedAt: d.CreatedAt.UTC(), RevokedAt: tstamp(d.RevokedAt)}
	for _, k := range keys {
		v.Keys = append(v.Keys, viewKey(k))
	}
	return v
}

type bindingView struct {
	Device deviceView `json:"device"`
	Key    keyView    `json:"key"`
}

func (a *API) bindAndroid(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FlowID         string  `json:"flow_id"`
		Role           string  `json:"role"`
		Chain          []Bytes `json:"chain"` // DER certificates, leaf first
		IntegrityToken string  `json:"integrity_token"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	chain := make([][]byte, len(req.Chain))
	for i, c := range req.Chain {
		chain[i] = c
	}
	b, err := a.d.Devices.FinishAndroid(r.Context(), principal(r).UserID, req.FlowID, devicebind.AndroidBinding{
		Role: req.Role, Chain: chain, IntegrityToken: req.IntegrityToken})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusCreated, bindingView{Device: viewDevice(b.Device, nil), Key: viewKey(b.Key)})
}

func (a *API) bindIOS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FlowID         string `json:"flow_id"`
		Role           string `json:"role"`
		PublicKey      Bytes  `json:"public_key"`                  // x963 P-256 point
		AppAttestKeyID Bytes  `json:"app_attest_key_id,omitempty"` // new device
		Attestation    Bytes  `json:"attestation,omitempty"`       // new device
		Assertion      Bytes  `json:"assertion,omitempty"`         // known device
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	b, err := a.d.Devices.FinishIOS(r.Context(), principal(r).UserID, req.FlowID, devicebind.IOSBinding{
		Role: req.Role, PublicKey: req.PublicKey, AppAttestKeyID: req.AppAttestKeyID, Attestation: req.Attestation,
		Assertion: req.Assertion})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusCreated, bindingView{Device: viewDevice(b.Device, nil), Key: viewKey(b.Key)})
}

func (a *API) attestCoins(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FlowID         string    `json:"flow_id"`
		Chains         [][]Bytes `json:"chains"`
		IntegrityToken string    `json:"integrity_token"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	chains := make([][][]byte, len(req.Chains))
	for i, c := range req.Chains {
		chains[i] = make([][]byte, len(c))
		for j, cert := range c {
			chains[i][j] = cert
		}
	}
	coins, err := a.d.Devices.AttestCoins(r.Context(), principal(r).UserID, req.FlowID, devicebind.CoinMinting{
		Chains: chains, IntegrityToken: req.IntegrityToken})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type coinView struct {
		PublicKey     Bytes  `json:"public_key"`
		SecurityLevel string `json:"security_level"`
	}
	out := make([]coinView, len(coins))
	for i, c := range coins {
		out[i] = coinView{PublicKey: c.PublicKey, SecurityLevel: c.SecurityLevel}
	}
	write(w, http.StatusOK, map[string]any{"coins": out})
}

func (a *API) refreshIntegrity(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		FlowID         string `json:"flow_id"`
		Assertion      Bytes  `json:"assertion,omitempty"`       // iOS: App Attest assertion
		IntegrityToken string `json:"integrity_token,omitempty"` // Android: Play Integrity token
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	user := principal(r).UserID
	// The flow names the device; the path must agree with it.
	if _, err := a.d.Devices.Device(r.Context(), user, id); err != nil {
		a.fail(w, r, err)
		return
	}
	d, err := a.d.Devices.RefreshIntegrity(r.Context(), user, req.FlowID, devicebind.IntegrityProof{
		Assertion: req.Assertion, IntegrityToken: req.IntegrityToken})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if d.ID != id {
		writeProblem(w, Problem{Status: http.StatusBadRequest, Code: "flow_invalid", Detail: "the flow is for another device"})
		return
	}
	write(w, http.StatusOK, viewDevice(d, nil))
}

func (a *API) devices(w http.ResponseWriter, r *http.Request) {
	user := principal(r).UserID
	list, err := a.d.Devices.Devices(r.Context(), user)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]deviceView, 0, len(list))
	for _, d := range list {
		keys, err := a.d.Devices.Keys(r.Context(), user, d.ID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		out = append(out, viewDevice(d, keys))
	}
	write(w, http.StatusOK, map[string]any{"devices": out})
}

// revokeDevice revokes a lost or replaced device, all its keys and every
// session bound to it (§2.2.7).
func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	user := principal(r).UserID
	if err := a.d.Devices.Revoke(r.Context(), user, id, "revoked_by_user"); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.d.Sessions.RevokeDevice(r.Context(), id, "device_revoked"); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeKey(w http.ResponseWriter, r *http.Request) {
	device, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	key, ok := pathUUID(w, r, "key")
	if !ok {
		return
	}
	user := principal(r).UserID
	keys, err := a.d.Devices.Keys(r.Context(), user, device)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	found := false
	for _, k := range keys {
		found = found || k.ID == key
	}
	if !found {
		writeProblem(w, Problem{Status: http.StatusNotFound, Code: "not_found", Detail: "no such key on this device"})
		return
	}
	if err := a.d.Devices.RevokeKey(r.Context(), user, key, "revoked_by_user"); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
