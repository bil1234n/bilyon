package gatewayapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/intents"
)

func (a *API) accountList(w http.ResponseWriter, r *http.Request) {
	bals, err := a.d.Accounts.Balances(r.Context(), principal(r).UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type balanceView struct {
		Currency  string `json:"currency"`
		Posted    int64  `json:"posted"`
		Pending   int64  `json:"pending"`
		Available int64  `json:"available"`
		Frozen    bool   `json:"frozen"`
	}
	out := make([]balanceView, len(bals))
	for i, b := range bals {
		out[i] = balanceView{Currency: b.Currency, Posted: b.Posted, Pending: b.Pending, Available: b.Available,
			Frozen: b.Frozen}
	}
	write(w, http.StatusOK, map[string]any{"accounts": out})
}

type intentView struct {
	ID            uuid.UUID           `json:"id"`
	State         intents.State       `json:"state"`
	Reason        string              `json:"reason,omitempty"`
	Gesture       intents.Gesture     `json:"gesture"`
	Role          string              `json:"role"` // payer or payee, from the caller's side
	PayerSubject  string              `json:"payer_subject"`
	PayeeSubject  string              `json:"payee_subject,omitempty"`
	Amount        int64               `json:"amount"`
	Currency      string              `json:"currency"`
	PayeeAmount   int64               `json:"payee_amount"`
	PayeeCurrency string              `json:"payee_currency"`
	QuoteID       *uuid.UUID          `json:"quote_id,omitempty"`
	OnTimeout     intents.Timeout     `json:"on_timeout,omitempty"`
	TLandMs       *int64              `json:"t_land_ms,omitempty"` // server time
	LiveUntil     *time.Time          `json:"live_until,omitempty"`
	ClaimUntil    *time.Time          `json:"claim_until,omitempty"`
	Trajectory    *intents.Trajectory `json:"trajectory,omitempty"`
	EntryIDs      []uuid.UUID         `json:"entry_ids"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
	ResolvedAt    *time.Time          `json:"resolved_at,omitempty"`
}

func viewIntent(in *intents.Intent, caller uuid.UUID) intentView {
	v := intentView{ID: in.ID, State: in.State, Reason: in.Reason, Gesture: in.Gesture, Role: "payee",
		PayerSubject: in.PayerSubject, PayeeSubject: in.PayeeSubject, Amount: in.Amount, Currency: in.Currency,
		PayeeAmount: in.PayeeAmount, PayeeCurrency: in.PayeeCurrency, LiveUntil: tstamp(in.LiveUntil),
		ClaimUntil: tstamp(in.ClaimUntil), Trajectory: in.Trajectory, EntryIDs: in.EntryIDs,
		CreatedAt: in.CreatedAt.UTC(), UpdatedAt: in.UpdatedAt.UTC(), ResolvedAt: tstamp(in.ResolvedAt)}
	if in.PayerID == caller {
		v.Role, v.OnTimeout = "payer", in.OnTimeout
	}
	if in.QuoteID != uuid.Nil {
		q := in.QuoteID
		v.QuoteID = &q
	}
	if in.TLand != nil {
		ms := in.TLand.UnixMilli()
		v.TLandMs = &ms
	}
	if v.EntryIDs == nil {
		v.EntryIDs = []uuid.UUID{}
	}
	return v
}

func (a *API) nonces(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID *uuid.UUID `json:"device_id,omitempty"` // default: the session's device
		Count    int        `json:"count"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	p := principal(r)
	device := p.DeviceID
	if req.DeviceID != nil {
		device = *req.DeviceID
	}
	if device == uuid.Nil {
		writeProblem(w, Problem{Status: http.StatusUnprocessableEntity, Code: "invalid_request",
			Detail: "device_id is required for a session that is not bound to a device"})
		return
	}
	ns, err := a.d.Intents.IssueNonces(r.Context(), p.UserID, device, req.Count)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type nonceView struct {
		Value     Bytes     `json:"value"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	out := make([]nonceView, len(ns))
	for i, n := range ns {
		out[i] = nonceView{Value: n.Value[:], ExpiresAt: n.ExpiresAt}
	}
	write(w, http.StatusOK, map[string]any{"nonces": out})
}

func (a *API) createIntent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TxAuth       Bytes               `json:"txauth"`
		Gesture      intents.Gesture     `json:"gesture"`
		PayeeSubject string              `json:"payee_subject,omitempty"`
		Amount       int64               `json:"amount"`
		Currency     string              `json:"currency"`
		QuoteID      *uuid.UUID          `json:"quote_id,omitempty"`
		TLandMs      int64               `json:"t_land_ms,omitempty"`
		Trajectory   *intents.Trajectory `json:"trajectory,omitempty"`
		OnTimeout    intents.Timeout     `json:"on_timeout,omitempty"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	p := principal(r)
	cr := intents.CreateRequest{SubmitterID: p.UserID, TxAuth: req.TxAuth, Gesture: req.Gesture,
		PayeeSubject: req.PayeeSubject, Amount: req.Amount, Currency: req.Currency, Trajectory: req.Trajectory,
		OnTimeout: req.OnTimeout}
	if req.QuoteID != nil {
		cr.QuoteID = *req.QuoteID
	}
	if req.TLandMs != 0 {
		cr.TLand = time.UnixMilli(req.TLandMs).UTC()
	}
	in, err := a.d.Intents.Create(r.Context(), cr)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewIntent(in, p.UserID))
}

func (a *API) listIntents(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	q := r.URL.Query()
	lq := intents.ListQuery{UserID: p.UserID, Role: intents.Role(q.Get("role"))}
	for _, st := range q["state"] {
		lq.States = append(lq.States, intents.State(st))
	}
	if s := q.Get("before"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil || id.String() != s {
			a.fail(w, r, &errBody{reason: "before must be an intent id"})
			return
		}
		lq.Before = id
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			a.fail(w, r, &errBody{reason: "limit must be an integer"})
			return
		}
		lq.Limit = n
	}
	list, err := a.d.Intents.List(r.Context(), lq)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]intentView, len(list))
	for i, in := range list {
		out[i] = viewIntent(in, p.UserID)
	}
	write(w, http.StatusOK, map[string]any{"intents": out})
}

func (a *API) getIntent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	p := principal(r)
	in, err := a.d.Intents.Get(r.Context(), p.UserID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewIntent(in, p.UserID))
}

func (a *API) catchIntent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Accept bool `json:"accept"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	p := principal(r)
	// Proximity is vouched for only by the realtime gateway, so drops are
	// grabbed through it, never here.
	in, err := a.d.Intents.Catch(r.Context(), intents.CatchRequest{IntentID: id, UserID: p.UserID, Accept: req.Accept})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewIntent(in, p.UserID))
}

func (a *API) cancelIntent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	p := principal(r)
	in, err := a.d.Intents.Cancel(r.Context(), p.UserID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewIntent(in, p.UserID))
}

func (a *API) deliveredIntent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	p := principal(r)
	in, err := a.d.Intents.MarkDelivered(r.Context(), p.UserID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewIntent(in, p.UserID))
}

type quoteView struct {
	ID        uuid.UUID `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	AmountIn  int64     `json:"amount_in"`
	AmountOut int64     `json:"amount_out"`
	MidRate   string    `json:"mid_rate"`
	FeeBps    float64   `json:"fee_bps"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Delivered *int64    `json:"delivered_amount,omitempty"`
}

func viewQuote(q *fx.Quote, x *fx.Execution) quoteView {
	v := quoteView{ID: q.ID, From: q.From, To: q.To, AmountIn: q.AmountIn, AmountOut: q.AmountOut, MidRate: q.MidRate,
		FeeBps: q.FeeBps, State: q.State, CreatedAt: q.CreatedAt.UTC(), ExpiresAt: q.ExpiresAt.UTC()}
	if x != nil {
		v.State = x.State
		out := x.AmountOut
		v.Delivered = &out
	}
	return v
}

func (a *API) createQuote(w http.ResponseWriter, r *http.Request) {
	if a.d.FX == nil {
		a.fail(w, r, errFXDisabled)
		return
	}
	var req struct {
		From     string `json:"from"`
		To       string `json:"to"`
		AmountIn int64  `json:"amount_in"`
		TTLMs    int64  `json:"ttl_ms,omitempty"`
	}
	if err := decode(w, r, a.cfg.MaxBody, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if req.TTLMs < 0 || req.TTLMs > int64(time.Hour/time.Millisecond) {
		a.fail(w, r, &errBody{reason: fmt.Sprintf("ttl_ms must be 0..%d", int64(time.Hour/time.Millisecond))})
		return
	}
	user := principal(r).UserID
	q, err := a.d.FX.CreateQuote(r.Context(), fx.QuoteRequest{UserID: user, From: req.From, To: req.To,
		AmountIn: req.AmountIn, TTL: time.Duration(req.TTLMs) * time.Millisecond})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusCreated, viewQuote(q, nil))
}

func (a *API) getQuote(w http.ResponseWriter, r *http.Request) {
	if a.d.FX == nil {
		a.fail(w, r, errFXDisabled)
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q, x, err := a.d.FX.GetQuote(r.Context(), principal(r).UserID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, viewQuote(q, x))
}
