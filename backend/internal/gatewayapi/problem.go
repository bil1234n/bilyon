package gatewayapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/fxapi"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/identity/handle"
	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/session"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

// ProblemBase prefixes problem type URIs (RFC 9457).
const ProblemBase = "https://errors.bilyon.dev/"

// Problem is an RFC 9457 problem detail. Code is stable and machine
// readable; the optional members locate the failure.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code"`
	State  string `json:"state,omitempty"` // intent state, for invalid_state
	Check  string `json:"check,omitempty"` // failed attestation check
	Rule   string `json:"rule,omitempty"`  // violated handle rule
	Step   string `json:"step,omitempty"`  // failed WebAuthn verification step
}

func writeProblem(w http.ResponseWriter, p Problem) {
	if p.Type == "" {
		p.Type = ProblemBase + p.Code
	}
	if p.Title == "" {
		p.Title = http.StatusText(p.Status)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	_ = jsonEncode(w, p)
}

type mapping struct {
	err    error
	status int
	code   string
}

// mappings translate domain sentinels; the first match wins.
var mappings = []mapping{
	{intents.ErrTxAuth, http.StatusForbidden, "txauth_rejected"},
	{intents.ErrNonce, http.StatusForbidden, "nonce_rejected"},
	{intents.ErrStale, http.StatusForbidden, "txauth_stale"},
	{intents.ErrMismatch, http.StatusUnprocessableEntity, "txauth_mismatch"},
	{intents.ErrConflict, http.StatusConflict, "intent_conflict"},
	{intents.ErrNotFound, http.StatusNotFound, "not_found"},
	{intents.ErrForbidden, http.StatusForbidden, "forbidden"},
	{intents.ErrState, http.StatusConflict, "invalid_state"},
	{intents.ErrRequest, http.StatusUnprocessableEntity, "invalid_request"},
	{intents.ErrUnavailable, http.StatusServiceUnavailable, "temporarily_unavailable"},
	{identity.ErrTaken, http.StatusConflict, "handle_taken"},
	{identity.ErrReserved, http.StatusConflict, "handle_reserved"},
	{identity.ErrTooSoon, http.StatusConflict, "handle_change_too_soon"},
	{handle.ErrInvalid, http.StatusUnprocessableEntity, "invalid_handle"},
	{identity.ErrEntry, http.StatusUnprocessableEntity, "invalid_profile"},
	{identity.ErrRequest, http.StatusUnprocessableEntity, "invalid_request"},
	{identity.ErrNotFound, http.StatusNotFound, "not_found"},
	{devicebind.ErrRejected, http.StatusUnprocessableEntity, "attestation_rejected"},
	{devicebind.ErrFlow, http.StatusBadRequest, "flow_invalid"},
	{devicebind.ErrNotFound, http.StatusNotFound, "not_found"},
	{devicebind.ErrRevoked, http.StatusConflict, "revoked"},
	{devicebind.ErrKeyExists, http.StatusConflict, "key_exists"},
	{devicebind.ErrPlatform, http.StatusBadRequest, "platform_unsupported"},
	{devicebind.ErrRequest, http.StatusUnprocessableEntity, "invalid_request"},
	{webauthn.ErrCredentialExists, http.StatusConflict, "credential_exists"},
	{webauthn.ErrInvalid, http.StatusBadRequest, "webauthn_rejected"},
	{webauthn.ErrNotFound, http.StatusNotFound, "not_found"},
	{session.ErrInvalidGrant, http.StatusBadRequest, "invalid_grant"},
	{session.ErrNotFound, http.StatusNotFound, "not_found"},
	{session.ErrRevoked, http.StatusUnauthorized, "session_revoked"},
	{session.ErrRequest, http.StatusUnprocessableEntity, "invalid_request"},
	{accounts.ErrCurrency, http.StatusUnprocessableEntity, "unsupported_currency"},
	{accounts.ErrNotFound, http.StatusNotFound, "not_found"},
	{fx.ErrUnknownQuote, http.StatusNotFound, "not_found"},
	{fx.ErrUnknownCurrency, http.StatusUnprocessableEntity, "unsupported_currency"},
	{fx.ErrPairNotConfigured, http.StatusUnprocessableEntity, "pair_not_supported"},
	{fx.ErrNoRoute, http.StatusUnprocessableEntity, "no_liquidity"},
	{fx.ErrRequest, http.StatusUnprocessableEntity, "invalid_request"},
	{fx.ErrNoMid, http.StatusServiceUnavailable, "temporarily_unavailable"},
	{fxapi.ErrUnavailable, http.StatusServiceUnavailable, "temporarily_unavailable"},
	{ledger.ErrUnavailable, http.StatusServiceUnavailable, "temporarily_unavailable"},
	{errFXDisabled, http.StatusNotImplemented, "fx_disabled"},
	{errLimiter, http.StatusServiceUnavailable, "temporarily_unavailable"},
	{errUnauthenticated, http.StatusUnauthorized, "unauthenticated"},
}

var (
	errFXDisabled      = errors.New("cross-currency payments are not enabled")
	errUnauthenticated = errors.New("authentication failed")
	errLimiter         = errors.New("rate limiter unavailable")
)

// fail answers a failed request. Expected refusals keep their message;
// anything else is logged and becomes a bare 500.
func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	var body *errBody
	if errors.As(err, &body) {
		writeProblem(w, Problem{Status: http.StatusBadRequest, Code: "invalid_request", Detail: body.Error()})
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		w.Header().Set("Retry-After", "1")
		writeProblem(w, Problem{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Detail: "the request did not complete in time"})
		return
	}
	for _, m := range mappings {
		if !errors.Is(err, m.err) {
			continue
		}
		p := Problem{Status: m.status, Code: m.code, Detail: err.Error()}
		var se *intents.StateError
		var be *devicebind.BindError
		var he *handle.InvalidError
		var ve *webauthn.VerificationError
		switch {
		case errors.As(err, &se):
			p.State = string(se.State)
		case errors.As(err, &be):
			p.Check = be.Check
		case errors.As(err, &he):
			p.Rule = he.Rule
		case errors.As(err, &ve):
			p.Step = ve.Step
		}
		if m.status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
			a.log.WarnContext(r.Context(), "dependency unavailable", slog.String("route", r.Pattern), slog.Any("error", err))
		}
		writeProblem(w, p)
		return
	}
	a.log.ErrorContext(r.Context(), "request failed", slog.String("route", r.Pattern), slog.Any("error", err))
	writeProblem(w, Problem{Status: http.StatusInternalServerError, Code: "internal_error"})
}
