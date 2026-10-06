package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/bil1234n/bilyon/backend/internal/dpop"
)

// Challenge error codes besides the DPoP ones (RFC 6750 §3.1, RFC 9470).
const (
	CodeInvalidToken     = "invalid_token"
	CodeInsufficientAuth = "insufficient_user_authentication"
)

// Principal is an authenticated caller.
type Principal struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	DeviceID  uuid.UUID // uuid.Nil when the session is not tied to a device
	ClientID  string
	JKT       string
	AuthTime  time.Time
	AMR       []string
	TokenID   string
}

type principalKey struct{}
type proofKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated caller.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// ProofFrom returns the DPoP proof verified by RequireProof.
func ProofFrom(ctx context.Context) (*dpop.Proof, bool) {
	p, ok := ctx.Value(proofKey{}).(*dpop.Proof)
	return p, ok
}

// AuthError is a refused request: Code and Description go into the
// WWW-Authenticate challenge (Code empty when no credentials were sent).
type AuthError struct {
	Code        string
	Description string
	MaxAge      time.Duration // insufficient_user_authentication only
}

func (e *AuthError) Error() string { return "session: " + e.Code + ": " + e.Description }

// Authenticator authenticates requests with a DPoP-bound access token and
// its proof.
type Authenticator struct {
	sessions *Service
	proofs   *dpop.Verifier
}

// NewAuthenticator combines the session service and the proof verifier.
func NewAuthenticator(s *Service, v *dpop.Verifier) *Authenticator {
	return &Authenticator{sessions: s, proofs: v}
}

// Authenticate checks a request's credentials: exactly one "DPoP" access
// token, valid and not revoked, and a proof for this method and path,
// bound to the token (ath) and made with its key (cnf.jkt). A refusal is
// an *AuthError; any other error is an infrastructure failure.
func (a *Authenticator) Authenticate(ctx context.Context, method, path string, authorization, proofs []string) (Principal, error) {
	if len(authorization) == 0 {
		return Principal{}, &AuthError{Description: "authentication required"}
	}
	if len(authorization) != 1 {
		return Principal{}, &AuthError{Code: CodeInvalidToken, Description: "exactly one Authorization header is allowed"}
	}
	scheme, token, ok := strings.Cut(authorization[0], " ")
	if !ok || token == "" || strings.ContainsAny(token, " \t") {
		return Principal{}, &AuthError{Code: CodeInvalidToken, Description: "malformed Authorization header"}
	}
	if !strings.EqualFold(scheme, TokenType) {
		// RFC 9449 §7.2: a DPoP-bound token presented as a bearer token
		// is refused like any other scheme.
		return Principal{}, &AuthError{Code: CodeInvalidToken, Description: "the DPoP scheme is required"}
	}
	claims, err := a.sessions.VerifyAccessToken(token)
	if err != nil {
		return Principal{}, &AuthError{Code: CodeInvalidToken, Description: err.Error()}
	}
	proof, err := a.proofs.Verify(ctx, dpop.Request{Method: method, Path: path, Proofs: proofs, AccessToken: token})
	if err != nil {
		var pe *dpop.Error
		if errors.As(err, &pe) {
			return Principal{}, &AuthError{Code: pe.Code, Description: pe.Description}
		}
		return Principal{}, err
	}
	if proof.JKT != claims.Confirmation.JKT {
		return Principal{}, &AuthError{Code: CodeInvalidToken, Description: "the proof key is not the token's key"}
	}
	revoked, err := a.sessions.revoked(ctx, claims.SessionID)
	if err != nil {
		return Principal{}, fmt.Errorf("session: revocation check: %w", err)
	}
	if revoked {
		return Principal{}, &AuthError{Code: CodeInvalidToken, Description: "the session was revoked"}
	}
	p := Principal{UserID: uuid.MustParse(claims.Subject), SessionID: uuid.MustParse(claims.SessionID),
		ClientID: claims.ClientID, JKT: claims.Confirmation.JKT, AuthTime: time.Unix(claims.AuthTime, 0).UTC(),
		AMR: claims.AMR, TokenID: claims.JTI}
	if claims.DeviceID != "" {
		p.DeviceID = uuid.MustParse(claims.DeviceID)
	}
	return p, nil
}

// quoted makes a challenge parameter value safe for a quoted-string.
func quoted(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r > 0x7e {
			return '\''
		}
		return r
	}, s)
}

// challenge renders a WWW-Authenticate value (RFC 9449 §7.1).
func challenge(e *AuthError) string {
	var b strings.Builder
	b.WriteString(TokenType)
	if e.Code != "" {
		fmt.Fprintf(&b, ` error="%s", error_description="%s",`, e.Code, quoted(e.Description))
	}
	if e.MaxAge > 0 {
		fmt.Fprintf(&b, ` max_age=%d,`, int64(e.MaxAge/time.Second))
	}
	b.WriteString(` algs="ES256"`)
	return b.String()
}

// WriteError answers a refused or failed request: 401 with a challenge and
// a fresh nonce for refusals, 503 for infrastructure failures.
func (a *Authenticator) WriteError(w http.ResponseWriter, err error) {
	var ae *AuthError
	if !errors.As(err, &ae) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
		return
	}
	if n := a.proofs.Nonce(); n != "" {
		w.Header().Set(dpop.NonceHeader, n)
	}
	w.Header().Set("WWW-Authenticate", challenge(ae))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	body := map[string]string{"error": ae.Code, "error_description": ae.Description}
	if ae.Code == "" {
		body = map[string]string{"error": "unauthorized"}
	}
	_ = json.NewEncoder(w).Encode(body)
}

// Middleware authenticates every request and puts the Principal in its
// context. Responses carry a fresh DPoP-Nonce.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r.Context(), r.Method, r.URL.EscapedPath(), r.Header.Values("Authorization"),
			r.Header.Values(dpop.Header))
		if err != nil {
			a.WriteError(w, err)
			return
		}
		if n := a.proofs.Nonce(); n != "" {
			w.Header().Set(dpop.NonceHeader, n)
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireProof guards endpoints that take a DPoP proof but no access
// token (login, refresh): the verified proof goes into the context.
func (a *Authenticator) RequireProof(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof, err := a.proofs.Verify(r.Context(), dpop.Request{Method: r.Method, Path: r.URL.EscapedPath(),
			Proofs: r.Header.Values(dpop.Header)})
		if err != nil {
			var pe *dpop.Error
			if errors.As(err, &pe) {
				err = &AuthError{Code: pe.Code, Description: pe.Description}
			}
			a.WriteError(w, err)
			return
		}
		if n := a.proofs.Nonce(); n != "" {
			w.Header().Set(dpop.NonceHeader, n)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), proofKey{}, proof)))
	})
}

// RequireRecentAuth guards sensitive operations (device re-binding,
// recovery settings): the user must have authenticated within maxAge,
// otherwise the client is challenged to step up (RFC 9470).
func (a *Authenticator) RequireRecentAuth(maxAge time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			a.WriteError(w, &AuthError{Description: "authentication required"})
			return
		}
		if a.sessions.cfg.Now().Sub(p.AuthTime) > maxAge {
			a.WriteError(w, &AuthError{Code: CodeInsufficientAuth, MaxAge: maxAge,
				Description: "a more recent authentication is required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// grpcAuth authenticates a gRPC call: the HTTP/2 request is
// POST /<full method>.
func (a *Authenticator) grpcAuth(ctx context.Context, fullMethod string) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	p, err := a.Authenticate(ctx, http.MethodPost, fullMethod, md.Get("authorization"), md.Get("dpop"))
	header := metadata.MD{}
	if n := a.proofs.Nonce(); n != "" {
		header.Set("dpop-nonce", n)
	}
	var ae *AuthError
	switch {
	case errors.As(err, &ae):
		header.Set("www-authenticate", challenge(ae))
		_ = grpc.SetHeader(ctx, header)
		return nil, status.Error(codes.Unauthenticated, ae.Error())
	case err != nil:
		return nil, status.Error(codes.Unavailable, "authentication is temporarily unavailable")
	}
	_ = grpc.SetHeader(ctx, header)
	return WithPrincipal(ctx, p), nil
}

// UnaryInterceptor authenticates unary calls except those public reports
// true for (health checks, login).
func (a *Authenticator) UnaryInterceptor(public func(fullMethod string) bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if public != nil && public(info.FullMethod) {
			return handler(ctx, req)
		}
		ctx, err := a.grpcAuth(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedStream) Context() context.Context { return s.ctx }

// StreamInterceptor authenticates streaming calls at stream start.
func (a *Authenticator) StreamInterceptor(public func(fullMethod string) bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if public != nil && public(info.FullMethod) {
			return handler(srv, ss)
		}
		ctx, err := a.grpcAuth(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &authedStream{ServerStream: ss, ctx: ctx})
	}
}

// ParseMaxAge reads the max_age parameter of a step-up challenge (clients
// and tests).
func ParseMaxAge(wwwAuthenticate string) (time.Duration, bool) {
	_, rest, ok := strings.Cut(wwwAuthenticate, "max_age=")
	if !ok {
		return 0, false
	}
	end := strings.IndexAny(rest, ", ")
	if end >= 0 {
		rest = rest[:end]
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}
