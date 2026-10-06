package gatewayapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/identity/tlog"
	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/jose"
)

type publishedKey struct {
	KID string `json:"kid"`
	Use string `json:"use"`
	Pub Bytes  `json:"pub"` // compressed P-256 point
}

type entryView struct {
	Subject         string         `json:"subject"`
	Version         uint64         `json:"version"`
	Handle          string         `json:"handle,omitempty"` // display form
	Name            string         `json:"name,omitempty"`
	AvatarSHA256    Bytes          `json:"avatar_sha256,omitempty"`
	Verified        []string       `json:"verified"`
	Currencies      []string       `json:"currencies"`
	DefaultCurrency string         `json:"default_currency,omitempty"`
	Keys            []publishedKey `json:"keys"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func viewEntry(e *identity.Entry) entryView {
	v := entryView{Subject: e.Subject, Version: e.Version, Handle: e.Display.Handle, Name: e.Display.Name,
		AvatarSHA256: e.Display.AvatarSHA256, Verified: e.Display.Verified, Currencies: e.Currencies,
		DefaultCurrency: e.DefaultCurrency, Keys: []publishedKey{}, UpdatedAt: e.Time.UTC()}
	if v.Verified == nil {
		v.Verified = []string{}
	}
	if v.Currencies == nil {
		v.Currencies = []string{}
	}
	for _, k := range e.Keys {
		v.Keys = append(v.Keys, publishedKey{KID: k.KID, Use: k.Use, Pub: k.Pub})
	}
	return v
}

// parView is a Payment Address Record: the raw COSE_Sign1, which the
// client verifies (signature, tree head, inclusion), and its decoded entry
// for display.
type parView struct {
	PAR       Bytes     `json:"par"`
	Entry     entryView `json:"entry"`
	LeafIndex uint64    `json:"leaf_index"`
	TreeSize  uint64    `json:"tree_size"`
	ExpiresAt time.Time `json:"expires_at"`
}

func viewPAR(p *identity.PAR) parView {
	return parView{PAR: p.Raw, Entry: viewEntry(p.Entry), LeafIndex: p.LeafIndex, TreeSize: p.TreeHead.Size,
		ExpiresAt: p.ExpiresAt.UTC()}
}

func (a *API) claimHandle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Handle string `json:"handle"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	h, e, err := a.d.Directory.ClaimHandle(r.Context(), principal(r).UserID, req.Handle)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, map[string]any{"handle": h.Display, "entry": viewEntry(e)})
}

func (a *API) releaseHandle(w http.ResponseWriter, r *http.Request) {
	e, err := a.d.Directory.ReleaseHandle(r.Context(), principal(r).UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, map[string]any{"entry": viewEntry(e)})
}

func (a *API) updateProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string         `json:"name"`
		AvatarSHA256    Bytes          `json:"avatar_sha256,omitempty"`
		Currencies      []string       `json:"currencies"`
		DefaultCurrency string         `json:"default_currency,omitempty"`
		Keys            []publishedKey `json:"keys"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	p := identity.Profile{Name: req.Name, Currencies: req.Currencies, DefaultCurrency: req.DefaultCurrency}
	if len(req.AvatarSHA256) > 0 {
		p.AvatarSHA256 = req.AvatarSHA256
	}
	for _, k := range req.Keys {
		p.Keys = append(p.Keys, identity.PublicKey{KID: k.KID, Use: k.Use, Pub: k.Pub})
	}
	e, err := a.d.Directory.UpdateProfile(r.Context(), principal(r).UserID, p)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, map[string]any{"entry": viewEntry(e)})
}

// lookupLimited applies the directory's lookup limits per account and per
// device (RFC 0001 §4.1.4).
func (a *API) lookupLimited(w http.ResponseWriter, r *http.Request) bool {
	p := principal(r)
	lims := []Limit{a.cfg.RateLimits.LookupMinute, a.cfg.RateLimits.LookupDay}
	if a.limited(w, r, "lookup:user:"+p.UserID.String(), lims...) {
		return true
	}
	return p.DeviceID != uuid.Nil && a.limited(w, r, "lookup:device:"+p.DeviceID.String(), lims...)
}

func (a *API) resolveHandle(w http.ResponseWriter, r *http.Request) {
	if a.lookupLimited(w, r) {
		return
	}
	par, err := a.d.Directory.Resolve(r.Context(), r.PathValue("handle"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewPAR(par))
}

func (a *API) resolveSubject(w http.ResponseWriter, r *http.Request) {
	if a.lookupLimited(w, r) {
		return
	}
	par, err := a.d.Directory.ResolveSubject(r.Context(), r.PathValue("subject"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewPAR(par))
}

func (a *API) directoryKeys(w http.ResponseWriter, r *http.Request) {
	type keyOut struct {
		KID  Bytes    `json:"kid"`
		JWK  jose.JWK `json:"jwk"`
		COSE Bytes    `json:"cose_key"` // compressed SEC1 point, as directory entries publish keys
	}
	out := make([]keyOut, 0, len(a.d.DirectoryKeys))
	for _, k := range a.d.DirectoryKeys {
		jwk, err := jose.PublicJWK(k.Public)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		point, err := cose.CompressP256(k.Public)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		out = append(out, keyOut{KID: k.KID, JWK: jwk, COSE: point})
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	write(w, http.StatusOK, map[string]any{"keys": out})
}

func (a *API) treeHead(w http.ResponseWriter, r *http.Request) {
	sth, err := a.d.Directory.Log().Latest(r.Context())
	if errors.Is(err, tlog.ErrNoTreeHead) {
		writeProblem(w, Problem{Status: http.StatusNotFound, Code: "not_found", Detail: "no tree head published yet"})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, map[string]any{"tree_size": sth.Size, "root": Bytes(sth.Root[:]),
		"signed_at": sth.Time.UTC(), "sth": Bytes(sth.Raw)})
}

func queryUint(r *http.Request, name string, def uint64) (uint64, error) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	v, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return 0, &errBody{reason: fmt.Sprintf("query parameter %s must be a non-negative integer", name)}
	}
	return v, nil
}

func (a *API) consistency(w http.ResponseWriter, r *http.Request) {
	first, err := queryUint(r, "first", 0)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	second, err := queryUint(r, "second", 0)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	proof, err := a.d.Directory.Log().ConsistencyProof(r.Context(), first, second)
	if errors.Is(err, tlog.ErrRange) {
		writeProblem(w, Problem{Status: http.StatusUnprocessableEntity, Code: "invalid_request", Detail: err.Error()})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]Bytes, len(proof))
	for i, h := range proof {
		out[i] = Bytes(h[:])
	}
	write(w, http.StatusOK, map[string]any{"first": first, "second": second, "proof": out})
}

// MaxLogPage bounds a page of log leaves.
const MaxLogPage = 1000

func (a *API) logLeaves(w http.ResponseWriter, r *http.Request) {
	from, err := queryUint(r, "from", 0)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	limit, err := queryUint(r, "limit", 100)
	if err != nil || limit < 1 || limit > MaxLogPage {
		a.fail(w, r, &errBody{reason: fmt.Sprintf("limit must be 1..%d", MaxLogPage)})
		return
	}
	leaves, err := a.d.Directory.Log().Leaves(r.Context(), from, int(limit))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]Bytes, len(leaves))
	for i, l := range leaves {
		out[i] = l
	}
	write(w, http.StatusOK, map[string]any{"from": from, "leaves": out})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	u, err := a.d.Users.UserByID(r.Context(), p.UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	subject, err := a.d.Directory.Subject(r.Context(), p.UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	timeout, err := a.d.Intents.Timeout(r.Context(), p.UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := map[string]any{"user_id": u.ID, "display_name": u.DisplayName, "status": u.Status, "subject": subject,
		"intent_timeout": timeout, "session_id": p.SessionID, "created_at": u.CreatedAt.UTC()}
	if p.DeviceID != uuid.Nil {
		out["device_id"] = p.DeviceID
	}
	payee, err := a.d.Directory.Payee(r.Context(), subject)
	switch {
	case err == nil:
		out["entry"] = viewEntry(payee.Entry)
	case !errors.Is(err, identity.ErrNotFound):
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, out)
}

func (a *API) preferences(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IntentTimeout intents.Timeout `json:"intent_timeout"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.d.Intents.SetTimeout(r.Context(), principal(r).UserID, req.IntentTimeout); err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, map[string]any{"intent_timeout": req.IntentTimeout})
}
