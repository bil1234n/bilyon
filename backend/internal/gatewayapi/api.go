// Package gatewayapi is the API the Bilyon apps call (RFC 0001 §1.1): JSON
// over HTTPS, authenticated with DPoP-bound access tokens (RFC 9449) after
// a passkey login, rate limited per account, device and address. It
// fronts passkey registration and login, sessions, hardware device
// binding, the payee directory, accounts, payment intents and FX quotes;
// errors are RFC 9457 problem details.
package gatewayapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/session"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

// FXQuotes prices conversions (*fxapi.Client).
type FXQuotes interface {
	CreateQuote(ctx context.Context, r fx.QuoteRequest) (*fx.Quote, error)
	GetQuote(ctx context.Context, userID, quoteID uuid.UUID) (*fx.Quote, *fx.Execution, error)
}

// DirectoryKey is a K_dir public key clients verify PARs and tree heads
// with.
type DirectoryKey struct {
	KID    []byte
	Public *ecdsa.PublicKey
}

// Deps are the services the API fronts.
type Deps struct {
	Users         *webauthn.PGStore
	WebAuthn      *webauthn.RP
	Sessions      *session.Service
	SessionKeys   *session.KeySet
	Auth          *session.Authenticator
	Devices       *devicebind.Service
	Directory     *identity.Service
	DirectoryKeys []DirectoryKey
	Accounts      *accounts.Resolver
	Intents       *intents.Service
	FX            FXQuotes // nil: cross-currency payments disabled
	Limiter       *Limiter
	Logger        *slog.Logger
	Registerer    prometheus.Registerer // nil: no metrics
}

// Config configures the API.
type Config struct {
	// Clients are the client ids sessions may be issued to.
	Clients []string
	// RecentAuth is how recent a passkey authentication sensitive
	// operations (revoking devices and keys, closing sessions) require
	// (default 5 minutes; RFC 9470 step-up beyond it).
	RecentAuth time.Duration
	RateLimits RateLimits
	// TrustedProxyHops is how many proxies in front of the API append to
	// X-Forwarded-For (0: use the connection's address).
	TrustedProxyHops int
	// MaxBody bounds request bodies (default 64 KiB).
	MaxBody int64
}

// API is the HTTP handler.
type API struct {
	cfg     Config
	d       Deps
	log     *slog.Logger
	limiter *Limiter
	clients map[string]bool
	m       *metrics
	handler http.Handler
}

// New assembles the API.
func New(cfg Config, d Deps) (*API, error) {
	if d.Users == nil || d.WebAuthn == nil || d.Sessions == nil || d.SessionKeys == nil || d.Auth == nil ||
		d.Devices == nil || d.Directory == nil || d.Accounts == nil || d.Intents == nil || d.Limiter == nil {
		return nil, errors.New("gatewayapi: missing dependency")
	}
	if len(cfg.Clients) == 0 {
		return nil, errors.New("gatewayapi: at least one client id is required")
	}
	if len(d.DirectoryKeys) == 0 {
		return nil, errors.New("gatewayapi: the directory's public key is required")
	}
	if cfg.RecentAuth == 0 {
		cfg.RecentAuth = 5 * time.Minute
	}
	if cfg.MaxBody == 0 {
		cfg.MaxBody = 64 << 10
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	a := &API{cfg: cfg, d: d, log: d.Logger, limiter: d.Limiter, clients: map[string]bool{}, m: newMetrics(d.Registerer)}
	for _, c := range cfg.Clients {
		a.clients[c] = true
	}
	a.handler = a.middleware(a.routes())
	return a, nil
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.handler.ServeHTTP(w, r) }

// Access levels of routes.
const (
	public = iota // no credentials; rate limited per address
	proof         // a DPoP proof but no token (login, refresh)
	authed        // a DPoP-bound access token
	recent        // authed, with a recent passkey authentication
)

func (a *API) routes() http.Handler {
	mux := http.NewServeMux()
	handle := func(pattern string, level int, h http.HandlerFunc) {
		var next http.Handler = h
		switch level {
		case public:
			next = a.perAddress(next)
		case proof:
			next = a.perAddress(a.d.Auth.RequireProof(next))
		case authed:
			next = a.d.Auth.Middleware(a.perAccount(next))
		case recent:
			next = a.d.Auth.Middleware(a.perAccount(a.d.Auth.RequireRecentAuth(a.cfg.RecentAuth, next)))
		}
		mux.Handle(pattern, next)
	}
	// Keys and the transparency log are public: verifiers need them.
	handle("GET /.well-known/jwks.json", public, a.jwks)
	handle("GET /v1/directory/keys", public, a.directoryKeys)
	handle("GET /v1/directory/sth", public, a.treeHead)
	handle("GET /v1/directory/consistency", public, a.consistency)
	handle("GET /v1/directory/log", public, a.logLeaves)

	handle("POST /v1/auth/register/begin", proof, a.registerBegin)
	handle("POST /v1/auth/register/finish", proof, a.registerFinish)
	handle("POST /v1/auth/login/begin", proof, a.loginBegin)
	handle("POST /v1/auth/login/finish", proof, a.loginFinish)
	handle("POST /v1/auth/refresh", proof, a.refresh)
	handle("POST /v1/auth/logout", authed, a.logout)
	handle("POST /v1/auth/step-up/begin", authed, a.stepUpBegin)
	handle("POST /v1/auth/step-up/finish", authed, a.stepUpFinish)
	handle("GET /v1/auth/sessions", authed, a.sessions)
	handle("DELETE /v1/auth/sessions/{id}", recent, a.closeSession)

	handle("GET /v1/me", authed, a.me)
	handle("PUT /v1/me/preferences", authed, a.preferences)
	handle("PUT /v1/me/handle", authed, a.claimHandle)
	handle("DELETE /v1/me/handle", authed, a.releaseHandle)
	handle("PUT /v1/me/profile", authed, a.updateProfile)
	handle("GET /v1/directory/handles/{handle}", authed, a.resolveHandle)
	handle("GET /v1/directory/subjects/{subject}", authed, a.resolveSubject)

	handle("POST /v1/devices/challenges", authed, a.deviceChallenge)
	handle("POST /v1/devices/android", authed, a.bindAndroid)
	handle("POST /v1/devices/ios", authed, a.bindIOS)
	handle("POST /v1/devices/coins", authed, a.attestCoins)
	handle("POST /v1/devices/{id}/integrity", authed, a.refreshIntegrity)
	handle("GET /v1/devices", authed, a.devices)
	handle("DELETE /v1/devices/{id}", recent, a.revokeDevice)
	handle("DELETE /v1/devices/{id}/keys/{key}", recent, a.revokeKey)

	handle("GET /v1/accounts", authed, a.accountList)
	handle("POST /v1/intents/nonces", authed, a.nonces)
	handle("POST /v1/intents", authed, a.createIntent)
	handle("GET /v1/intents", authed, a.listIntents)
	handle("GET /v1/intents/{id}", authed, a.getIntent)
	handle("POST /v1/intents/{id}/catch", authed, a.catchIntent)
	handle("POST /v1/intents/{id}/cancel", authed, a.cancelIntent)
	handle("POST /v1/intents/{id}/delivered", authed, a.deliveredIntent)
	handle("POST /v1/fx/quotes", authed, a.createQuote)
	handle("GET /v1/fx/quotes/{id}", authed, a.getQuote)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, Problem{Status: http.StatusNotFound, Code: "not_found", Detail: "no such endpoint"})
	})
	return mux
}

func (a *API) perAddress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.limited(w, r, "ip:"+clientIP(r, a.cfg.TrustedProxyHops), a.cfg.RateLimits.Auth) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) perAccount(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := session.PrincipalFrom(r.Context())
		if a.limited(w, r, "user:"+p.UserID.String(), a.cfg.RateLimits.Calls) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// principal is the authenticated caller (routes at level authed and above).
func principal(r *http.Request) session.Principal {
	p, _ := session.PrincipalFrom(r.Context())
	return p
}

type metrics struct {
	requests *prometheus.HistogramVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{requests: prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "bilyon_gateway_http_request_duration_seconds", Help: "API requests by route, method and status.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}}, []string{"route", "method", "status"})}
	if reg != nil {
		reg.MustRegister(m.requests)
	}
	return m
}

type recorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status, r.wrote = http.StatusOK, true
	}
	return r.ResponseWriter.Write(b)
}

type requestIDKey struct{}

// RequestID returns the request's id (from X-Request-Id or generated).
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 64 {
		ok := true
		for i := 0; i < len(id); i++ {
			if c := id[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
				ok = false
				break
			}
		}
		if ok {
			return id
		}
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// middleware adds request ids, security headers, panic recovery, metrics
// and access logs.
func (a *API) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := requestID(r)
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		h := w.Header()
		h.Set("X-Request-Id", id)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				a.log.ErrorContext(r.Context(), "panic serving request", slog.Any("panic", v),
					slog.String("stack", string(debug.Stack())), slog.String("request_id", id))
				if !rec.wrote {
					writeProblem(rec, Problem{Status: http.StatusInternalServerError, Code: "internal_error"})
				}
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			a.m.requests.WithLabelValues(route, r.Method, strconv.Itoa(rec.status)).Observe(time.Since(start).Seconds())
			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			}
			a.log.Log(r.Context(), level, "request", slog.String("request_id", id), slog.String("method", r.Method),
				slog.String("route", route), slog.Int("status", rec.status), slog.Duration("took", time.Since(start)))
		}()
		next.ServeHTTP(rec, r)
	})
}
