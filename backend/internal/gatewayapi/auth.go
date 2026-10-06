package gatewayapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/session"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

// AMR values sessions record.
const amrPasskey = "webauthn"

func (a *API) jwks(w http.ResponseWriter, r *http.Request) { a.d.SessionKeys.ServeHTTP(w, r) }

func validDisplayName(s string) bool {
	n := utf8.RuneCountInString(s)
	if !utf8.ValidString(s) || n < 1 || n > 64 {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

type flowResponse struct {
	FlowID  string `json:"flow_id"`
	Options any    `json:"options"`
}

type authResponse struct {
	UserID      uuid.UUID      `json:"user_id"`
	Tokens      session.Tokens `json:"tokens"`
	CloneSignal bool           `json:"clone_signal,omitempty"`
}

func (a *API) registerBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if !validDisplayName(req.DisplayName) {
		writeProblem(w, Problem{Status: http.StatusUnprocessableEntity, Code: "invalid_request",
			Detail: "display_name must be 1 to 64 printable characters"})
		return
	}
	u, err := a.d.Users.CreateUser(r.Context(), req.DisplayName)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	opts, flow, err := a.d.WebAuthn.BeginRegistration(r.Context(), u)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, flowResponse{FlowID: flow, Options: opts})
}

// credentialRequest carries a PublicKeyCredential in JSON. The credential
// itself is decoded leniently: WebAuthn Level 3 toJSON() adds members
// (publicKey, authenticatorData, ...) that relying parties ignore.
type credentialRequest struct {
	FlowID     string          `json:"flow_id"`
	Credential json.RawMessage `json:"credential"`
	ClientID   string          `json:"client_id,omitempty"`
	DeviceID   *uuid.UUID      `json:"device_id,omitempty"`
}

func (a *API) client(w http.ResponseWriter, id string) bool {
	if !a.clients[id] {
		writeProblem(w, Problem{Status: http.StatusUnprocessableEntity, Code: "invalid_client",
			Detail: fmt.Sprintf("unknown client_id %q", id)})
		return false
	}
	return true
}

func (a *API) registerFinish(w http.ResponseWriter, r *http.Request) {
	var req credentialRequest
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if !a.client(w, req.ClientID) {
		return
	}
	var resp webauthn.RegistrationResponse
	if err := json.Unmarshal(req.Credential, &resp); err != nil {
		a.fail(w, r, &errBody{reason: "credential: " + err.Error()})
		return
	}
	cred, err := a.d.WebAuthn.FinishRegistration(r.Context(), req.FlowID, &resp)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	proof, _ := session.ProofFrom(r.Context())
	tokens, err := a.d.Sessions.Issue(r.Context(), session.Grant{UserID: cred.UserID, ClientID: req.ClientID,
		JKT: proof.JKT, AMR: []string{amrPasskey}})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusCreated, authResponse{UserID: cred.UserID, Tokens: tokens})
}

func (a *API) loginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID *uuid.UUID `json:"user_id,omitempty"` // absent: discoverable credentials
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	opts, flow, err := a.d.WebAuthn.BeginLogin(r.Context(), req.UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, flowResponse{FlowID: flow, Options: opts})
}

// assertion verifies a login assertion from req.
func (a *API) assertion(w http.ResponseWriter, r *http.Request, req credentialRequest) (*webauthn.LoginResult, bool) {
	var resp webauthn.AssertionResponse
	if err := json.Unmarshal(req.Credential, &resp); err != nil {
		a.fail(w, r, &errBody{reason: "credential: " + err.Error()})
		return nil, false
	}
	res, err := a.d.WebAuthn.FinishLogin(r.Context(), req.FlowID, &resp)
	if err != nil {
		a.fail(w, r, err)
		return nil, false
	}
	return res, true
}

func (a *API) loginFinish(w http.ResponseWriter, r *http.Request) {
	var req credentialRequest
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if !a.client(w, req.ClientID) {
		return
	}
	res, ok := a.assertion(w, r, req)
	if !ok {
		return
	}
	grant := session.Grant{UserID: res.UserID, ClientID: req.ClientID, AMR: []string{amrPasskey}}
	if req.DeviceID != nil {
		// A device-bound session ends when the device is revoked.
		if _, err := a.d.Devices.Device(r.Context(), res.UserID, *req.DeviceID); err != nil {
			a.fail(w, r, err)
			return
		}
		grant.DeviceID = *req.DeviceID
	}
	proof, _ := session.ProofFrom(r.Context())
	grant.JKT = proof.JKT
	tokens, err := a.d.Sessions.Issue(r.Context(), grant)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if res.CloneSignal {
		a.log.WarnContext(r.Context(), "passkey counter did not advance", "user", res.UserID)
	}
	write(w, http.StatusOK, authResponse{UserID: res.UserID, Tokens: tokens, CloneSignal: res.CloneSignal})
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	proof, _ := session.ProofFrom(r.Context())
	tokens, err := a.d.Sessions.Refresh(r.Context(), req.RefreshToken, proof.JKT)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, tokens)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if err := a.d.Sessions.Revoke(r.Context(), p.UserID, p.SessionID, "logout"); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) stepUpBegin(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	opts, flow, err := a.d.WebAuthn.BeginLogin(r.Context(), &p.UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, flowResponse{FlowID: flow, Options: opts})
}

func (a *API) stepUpFinish(w http.ResponseWriter, r *http.Request) {
	var req credentialRequest
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, ok := a.assertion(w, r, req)
	if !ok {
		return
	}
	p := principal(r)
	if res.UserID != p.UserID {
		writeProblem(w, Problem{Status: http.StatusForbidden, Code: "forbidden",
			Detail: "the passkey belongs to another account"})
		return
	}
	tokens, err := a.d.Sessions.StepUp(r.Context(), p.SessionID, p.JKT, amrPasskey)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, tokens)
}

type sessionView struct {
	ID            uuid.UUID  `json:"id"`
	ClientID      string     `json:"client_id"`
	DeviceID      *uuid.UUID `json:"device_id,omitempty"`
	AMR           []string   `json:"amr"`
	AuthTime      time.Time  `json:"auth_time"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	LastRefreshAt *time.Time `json:"last_refresh_at,omitempty"`
	Current       bool       `json:"current"`
}

func (a *API) sessions(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	list, err := a.d.Sessions.Sessions(r.Context(), p.UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]sessionView, 0, len(list))
	for _, s := range list {
		v := sessionView{ID: s.ID, ClientID: s.ClientID, AMR: s.AMR, AuthTime: s.AuthTime.UTC(),
			CreatedAt: s.CreatedAt.UTC(), ExpiresAt: s.ExpiresAt.UTC(), LastRefreshAt: tstamp(s.LastRefreshAt),
			Current: s.ID == p.SessionID}
		if s.DeviceID != uuid.Nil {
			d := s.DeviceID
			v.DeviceID = &d
		}
		out = append(out, v)
	}
	write(w, http.StatusOK, map[string]any{"sessions": out})
}

func (a *API) closeSession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := a.d.Sessions.Revoke(r.Context(), principal(r).UserID, id, "closed_by_user"); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pathUUID reads a canonical UUID path parameter.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	s := r.PathValue(name)
	id, err := uuid.Parse(s)
	if err != nil || id.String() != s || id == uuid.Nil {
		writeProblem(w, Problem{Status: http.StatusNotFound, Code: "not_found", Detail: name + " is not a UUID"})
		return uuid.Nil, false
	}
	return id, true
}
