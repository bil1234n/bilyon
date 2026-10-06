// Package session issues and verifies Bilyon's device sessions (RFC 0001
// §2.2.3 A7): 10-minute ES256 access tokens ("at+jwt", RFC 9068) bound to
// the device's DPoP key through cnf.jkt (RFC 9449), and refresh tokens
// that rotate on every use, are bound to the same key, and are stored only
// as hashes, with reuse detection. Revocation takes effect on every
// gateway at the next request through a Redis marker, and on refresh
// through PostgreSQL.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bil1234n/bilyon/backend/internal/jose"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// Errors.
var (
	// ErrInvalidToken means an access token failed verification.
	ErrInvalidToken = errors.New("session: invalid access token")
	// ErrInvalidGrant means a refresh token cannot be exchanged.
	ErrInvalidGrant = errors.New("session: invalid refresh token")
	// ErrRevoked means the session was revoked.
	ErrRevoked = errors.New("session: revoked")
	// ErrNotFound means no such active session belongs to the user.
	ErrNotFound = errors.New("session: not found")
	// ErrRequest means a grant or argument is malformed.
	ErrRequest = errors.New("session: invalid request")
)

// Event topics.
const (
	TopicCreated = "gateway.session.created"
	TopicRevoked = "gateway.session.revoked"
	EventSource  = "bilyon.gateway"
)

// Revocation reasons the service itself records.
const (
	ReasonRefreshReuse = "refresh_token_reuse"
)

// TokenType is the access token type (RFC 9449 §5).
const TokenType = "DPoP"

const (
	accessTokenType = "at+jwt"
	refreshPrefix   = "bilyon_rt_"
	revokedPrefix   = "bilyon:session:revoked:"
)

var (
	jktPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	clientIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,63}$`)
	amrPattern      = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
)

// Config configures the service.
type Config struct {
	Issuer string // e.g. "https://api.bilyon.example"
	// Audience is what tokens are issued for (the API and the realtime
	// service); ExpectAudience is what this verifier requires (default
	// Audience[0]).
	Audience       []string
	ExpectAudience string
	AccessTTL      time.Duration // default 10 minutes (RFC 0001 A7)
	RefreshTTL     time.Duration // idle lifetime of a refresh token, default 14 days
	SessionTTL     time.Duration // absolute session lifetime, default 30 days
	// RetryGrace lets the key holder retry a refresh whose response was
	// lost (default 60 s): the used token is exchanged again and the
	// unreceived successor retired. Later reuse revokes the session.
	RetryGrace time.Duration
	Leeway     time.Duration // clock tolerance for exp and iat, default 30 s
	Now        func() time.Time
	Logger     *slog.Logger
}

// Service issues, refreshes, verifies and revokes sessions.
type Service struct {
	cfg  Config
	keys *KeySet
	pool *pgxpool.Pool
	rdb  redis.UniversalClient
}

// New validates the configuration.
func New(cfg Config, keys *KeySet, pool *pgxpool.Pool, rdb redis.UniversalClient) (*Service, error) {
	if cfg.Issuer == "" || len(cfg.Audience) == 0 {
		return nil, errors.New("session: issuer and audience are required")
	}
	if keys == nil || pool == nil || rdb == nil {
		return nil, errors.New("session: keys, PostgreSQL and Redis are required")
	}
	if cfg.ExpectAudience == "" {
		cfg.ExpectAudience = cfg.Audience[0]
	}
	if !slices.Contains(cfg.Audience, cfg.ExpectAudience) {
		return nil, errors.New("session: the expected audience is not issued")
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = 10 * time.Minute
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = 14 * 24 * time.Hour
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}
	if cfg.RetryGrace == 0 {
		cfg.RetryGrace = time.Minute
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.AccessTTL > cfg.RefreshTTL || cfg.RefreshTTL > cfg.SessionTTL {
		return nil, errors.New("session: lifetimes must satisfy access ≤ refresh ≤ session")
	}
	return &Service{cfg: cfg, keys: keys, pool: pool, rdb: rdb}, nil
}

// Grant is what a successful login establishes.
type Grant struct {
	UserID   uuid.UUID
	DeviceID uuid.UUID // uuid.Nil when the session is not tied to a bound device
	ClientID string    // e.g. "bilyon-ios"
	JKT      string    // thumbprint of the DPoP key the login proof used
	AMR      []string  // authentication methods, e.g. ["webauthn"]
}

// Tokens is a token response.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	SessionID    uuid.UUID `json:"session_id"`
	ExpiresAt    time.Time `json:"-"`
}

// Session is a session's record.
type Session struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	DeviceID      uuid.UUID
	ClientID      string
	JKT           string
	AMR           []string
	AuthTime      time.Time
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastRefreshAt *time.Time
	RevokedAt     *time.Time
	RevokeReason  string
}

// Claims are an access token's claims.
type Claims struct {
	Issuer       string       `json:"iss"`
	Subject      string       `json:"sub"`
	Audience     []string     `json:"aud"`
	Expiry       int64        `json:"exp"`
	IssuedAt     int64        `json:"iat"`
	JTI          string       `json:"jti"`
	ClientID     string       `json:"client_id"`
	SessionID    string       `json:"sid"`
	AuthTime     int64        `json:"auth_time"`
	AMR          []string     `json:"amr"`
	DeviceID     string       `json:"did,omitempty"`
	Confirmation Confirmation `json:"cnf"`
}

// Confirmation binds a token to a key (RFC 7800, RFC 9449 §6.1).
type Confirmation struct {
	JKT string `json:"jkt"`
}

func (g Grant) validate() error {
	switch {
	case g.UserID == uuid.Nil:
		return fmt.Errorf("%w: user id", ErrRequest)
	case !jktPattern.MatchString(g.JKT):
		return fmt.Errorf("%w: key thumbprint", ErrRequest)
	case !clientIDPattern.MatchString(g.ClientID):
		return fmt.Errorf("%w: client id %q", ErrRequest, g.ClientID)
	case len(g.AMR) == 0 || len(g.AMR) > 8:
		return fmt.Errorf("%w: %d authentication methods", ErrRequest, len(g.AMR))
	}
	for _, m := range g.AMR {
		if !amrPattern.MatchString(m) {
			return fmt.Errorf("%w: authentication method %q", ErrRequest, m)
		}
	}
	return nil
}

func newRefreshToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = refreshPrefix + jose.B64.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

func hashRefresh(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// accessToken signs an access token for a session.
func (s *Service) accessToken(sess Session, now time.Time) (string, time.Time, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	exp := earliest(now.Add(s.cfg.AccessTTL), sess.ExpiresAt)
	c := Claims{Issuer: s.cfg.Issuer, Subject: sess.UserID.String(), Audience: s.cfg.Audience, Expiry: exp.Unix(),
		IssuedAt: now.Unix(), JTI: jose.B64.EncodeToString(jti), ClientID: sess.ClientID, SessionID: sess.ID.String(),
		AuthTime: sess.AuthTime.Unix(), AMR: sess.AMR, Confirmation: Confirmation{JKT: sess.JKT}}
	if sess.DeviceID != uuid.Nil {
		c.DeviceID = sess.DeviceID.String()
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", time.Time{}, err
	}
	tok, err := jose.SignES256(s.keys.signer, map[string]any{"typ": accessTokenType, "kid": s.keys.kid}, payload)
	return tok, exp, err
}

func (s *Service) tokens(sess Session, refresh string, now time.Time) (Tokens, error) {
	at, exp, err := s.accessToken(sess, now)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: at, TokenType: TokenType, ExpiresIn: int64(exp.Sub(now).Round(time.Second) / time.Second),
		RefreshToken: refresh, SessionID: sess.ID, ExpiresAt: exp}, nil
}

// VerifyAccessToken checks an access token's signature, type, issuer,
// audience and lifetime. It does not check revocation or the DPoP proof
// (the Authenticator does both).
func (s *Service) VerifyAccessToken(token string) (*Claims, error) {
	j, err := jose.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if typ, _, _ := j.HeaderString("typ"); typ != accessTokenType {
		return nil, fmt.Errorf("%w: typ %q", ErrInvalidToken, typ)
	}
	kid, _, _ := j.HeaderString("kid")
	key, ok := s.keys.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: unknown key id", ErrInvalidToken)
	}
	if err := j.VerifyES256(key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	var c Claims
	if err := jose.DecodeStrict(j.Payload, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	now := s.cfg.Now()
	switch {
	case c.Issuer != s.cfg.Issuer:
		return nil, fmt.Errorf("%w: issuer %q", ErrInvalidToken, c.Issuer)
	case !slices.Contains(c.Audience, s.cfg.ExpectAudience):
		return nil, fmt.Errorf("%w: audience", ErrInvalidToken)
	case !now.Before(time.Unix(c.Expiry, 0).Add(s.cfg.Leeway)):
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	case time.Unix(c.IssuedAt, 0).After(now.Add(s.cfg.Leeway)):
		return nil, fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	case !jktPattern.MatchString(c.Confirmation.JKT):
		return nil, fmt.Errorf("%w: no key confirmation", ErrInvalidToken)
	case len(c.AMR) == 0 || c.JTI == "":
		return nil, fmt.Errorf("%w: incomplete claims", ErrInvalidToken)
	}
	if _, err := uuid.Parse(c.Subject); err != nil {
		return nil, fmt.Errorf("%w: subject", ErrInvalidToken)
	}
	if _, err := uuid.Parse(c.SessionID); err != nil {
		return nil, fmt.Errorf("%w: session id", ErrInvalidToken)
	}
	if c.DeviceID != "" {
		if _, err := uuid.Parse(c.DeviceID); err != nil {
			return nil, fmt.Errorf("%w: device id", ErrInvalidToken)
		}
	}
	return &c, nil
}

// Issue starts a session after a successful login and returns its first
// tokens.
func (s *Service) Issue(ctx context.Context, g Grant) (Tokens, error) {
	if err := g.validate(); err != nil {
		return Tokens{}, err
	}
	now := s.cfg.Now().UTC().Truncate(time.Microsecond)
	id, err := uuid.NewV7()
	if err != nil {
		return Tokens{}, err
	}
	refresh, hash, err := newRefreshToken()
	if err != nil {
		return Tokens{}, err
	}
	sess := Session{ID: id, UserID: g.UserID, DeviceID: g.DeviceID, ClientID: g.ClientID, JKT: g.JKT,
		AMR: slices.Clone(g.AMR), AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(s.cfg.SessionTTL)}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var device *uuid.UUID
		if g.DeviceID != uuid.Nil {
			device = &g.DeviceID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sessions (session_id, user_id, device_id, client_id, jkt, amr, auth_time,
				created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)`,
			sess.ID, sess.UserID, device, sess.ClientID, sess.JKT, sess.AMR, now, sess.ExpiresAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (token_hash, session_id, generation, issued_at, expires_at)
				VALUES ($1, $2, 0, $3, $4)`, hash, sess.ID, now, earliest(now.Add(s.cfg.RefreshTTL), sess.ExpiresAt)); err != nil {
			return err
		}
		return emit(ctx, tx, TopicCreated, sess.UserID, map[string]any{"user_id": sess.UserID, "session_id": sess.ID,
			"device_id": g.DeviceID, "client_id": sess.ClientID, "amr": sess.AMR})
	})
	if err != nil {
		return Tokens{}, err
	}
	return s.tokens(sess, refresh, now)
}

func emit(ctx context.Context, tx pgx.Tx, topic string, userID uuid.UUID, data map[string]any) error {
	_, err := outbox.Write(ctx, tx, outbox.Event{Source: EventSource, Topic: topic, Key: "user:" + userID.String(),
		Subject: userID.String(), Data: data})
	return err
}

const sessionColumns = `s.session_id, s.user_id, s.device_id, s.client_id, s.jkt, s.amr, s.auth_time, s.created_at,
	s.expires_at, s.last_refresh_at, s.revoked_at, s.revoke_reason`

func scanSession(row pgx.Row, extra ...any) (Session, error) {
	var sess Session
	var device *uuid.UUID
	var reason *string
	dest := append([]any{&sess.ID, &sess.UserID, &device, &sess.ClientID, &sess.JKT, &sess.AMR, &sess.AuthTime,
		&sess.CreatedAt, &sess.ExpiresAt, &sess.LastRefreshAt, &sess.RevokedAt, &reason}, extra...)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	if device != nil {
		sess.DeviceID = *device
	}
	if reason != nil {
		sess.RevokeReason = *reason
	}
	sess.AuthTime, sess.CreatedAt, sess.ExpiresAt = sess.AuthTime.UTC(), sess.CreatedAt.UTC(), sess.ExpiresAt.UTC()
	return sess, nil
}

// Refresh exchanges a refresh token, presented with a DPoP proof by key
// jkt, for new tokens. The token rotates; presenting a used token again
// revokes the session, except for the key holder retrying within
// RetryGrace while no later token has been used.
func (s *Service) Refresh(ctx context.Context, refreshToken, jkt string) (Tokens, error) {
	now := s.cfg.Now().UTC().Truncate(time.Microsecond)
	var out Tokens
	var reused *Session
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var generation int32
		var expires time.Time
		var usedAt, retiredAt *time.Time
		sess, err := scanSession(tx.QueryRow(ctx, `SELECT `+sessionColumns+`, r.generation, r.expires_at, r.used_at, r.retired_at
			FROM refresh_tokens r JOIN sessions s USING (session_id)
			WHERE r.token_hash = $1 FOR UPDATE OF r, s`, hashRefresh(refreshToken)), &generation, &expires, &usedAt, &retiredAt)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: unknown token", ErrInvalidGrant)
		}
		if err != nil {
			return err
		}
		switch {
		case sess.RevokedAt != nil:
			return fmt.Errorf("%w: session revoked", ErrInvalidGrant)
		case sess.JKT != jkt:
			return fmt.Errorf("%w: the token is bound to another key", ErrInvalidGrant)
		case !now.Before(sess.ExpiresAt):
			return fmt.Errorf("%w: session expired", ErrInvalidGrant)
		}
		switch {
		case usedAt == nil && retiredAt == nil:
			if !now.Before(expires) {
				return fmt.Errorf("%w: token expired", ErrInvalidGrant)
			}
			if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE token_hash = $1`,
				hashRefresh(refreshToken), now); err != nil {
				return err
			}
		case usedAt != nil && now.Sub(*usedAt) <= s.cfg.RetryGrace:
			var laterUse bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM refresh_tokens
				WHERE session_id = $1 AND generation > $2 AND used_at IS NOT NULL)`, sess.ID, generation).Scan(&laterUse); err != nil {
				return err
			}
			if laterUse {
				return s.revokeForReuse(ctx, tx, &sess, now, &reused)
			}
			if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET retired_at = $3
				WHERE session_id = $1 AND generation > $2 AND used_at IS NULL AND retired_at IS NULL`,
				sess.ID, generation, now); err != nil {
				return err
			}
		default:
			return s.revokeForReuse(ctx, tx, &sess, now, &reused)
		}
		refresh, hash, err := newRefreshToken()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (token_hash, session_id, generation, issued_at, expires_at)
			SELECT $1, $2, max(generation) + 1, $3, $4 FROM refresh_tokens WHERE session_id = $2`,
			hash, sess.ID, now, earliest(now.Add(s.cfg.RefreshTTL), sess.ExpiresAt)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET last_refresh_at = $2 WHERE session_id = $1`, sess.ID, now); err != nil {
			return err
		}
		out, err = s.tokens(sess, refresh, now)
		return err
	})
	if reused != nil {
		// The transaction committed the revocation; outstanding access
		// tokens die at their next request.
		if err := s.markRevoked(ctx, reused.ID); err != nil {
			s.cfg.Logger.Error("session: revocation marker after refresh token reuse", "session", reused.ID, "err", err)
		}
		return Tokens{}, fmt.Errorf("%w: reuse detected, session revoked", ErrInvalidGrant)
	}
	return out, err
}

// revokeForReuse revokes the session inside the refresh transaction, which
// then commits so that the revocation sticks.
func (s *Service) revokeForReuse(ctx context.Context, tx pgx.Tx, sess *Session, now time.Time, reused **Session) error {
	if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE session_id = $1`,
		sess.ID, now, ReasonRefreshReuse); err != nil {
		return err
	}
	if err := emit(ctx, tx, TopicRevoked, sess.UserID, map[string]any{"user_id": sess.UserID, "session_id": sess.ID,
		"reason": ReasonRefreshReuse}); err != nil {
		return err
	}
	*reused = sess
	return nil
}

// StepUp records a fresh user authentication (a passkey assertion during
// the session) and returns an access token carrying the new auth_time.
// jkt must be the session's key: the caller authenticated the request.
func (s *Service) StepUp(ctx context.Context, sessionID uuid.UUID, jkt, method string) (Tokens, error) {
	if !amrPattern.MatchString(method) {
		return Tokens{}, fmt.Errorf("%w: authentication method %q", ErrRequest, method)
	}
	now := s.cfg.Now().UTC().Truncate(time.Microsecond)
	var sess Session
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		sess, err = scanSession(tx.QueryRow(ctx, `UPDATE sessions s SET auth_time = $3,
				amr = (SELECT array_agg(DISTINCT m ORDER BY m) FROM unnest(s.amr || $4::text) AS m)
			WHERE session_id = $1 AND jkt = $2 AND revoked_at IS NULL AND expires_at > $3
			RETURNING `+sessionColumns, sessionID, jkt, now, method))
		return err
	})
	if err != nil {
		return Tokens{}, err
	}
	return s.tokens(sess, "", now)
}

func (s *Service) markRevoked(ctx context.Context, ids ...uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	ttl := s.cfg.AccessTTL + s.cfg.Leeway
	_, err := s.rdb.Pipelined(ctx, func(p redis.Pipeliner) error {
		for _, id := range ids {
			p.Set(ctx, revokedPrefix+id.String(), 1, ttl)
		}
		return nil
	})
	return err
}

// revoked reports whether a session carries a revocation marker.
func (s *Service) revoked(ctx context.Context, id string) (bool, error) {
	n, err := s.rdb.Exists(ctx, revokedPrefix+id).Result()
	return n > 0, err
}

// revokeWhere revokes the active sessions selected by cond (with args)
// and returns how many it revoked. The Redis markers are written first, so
// a failure leaves sessions at worst unusable, never live-but-revoked.
func (s *Service) revokeWhere(ctx context.Context, reason, cond string, args ...any) (int, error) {
	if reason == "" {
		return 0, fmt.Errorf("%w: a revocation reason is required", ErrRequest)
	}
	rows, err := s.pool.Query(ctx, `SELECT session_id FROM sessions s WHERE revoked_at IS NULL AND `+cond, args...)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if err := s.markRevoked(ctx, ids...); err != nil {
		return 0, fmt.Errorf("session: revocation markers: %w", err)
	}
	now := s.cfg.Now().UTC().Truncate(time.Microsecond)
	var n int
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3
			WHERE session_id = ANY($1) AND revoked_at IS NULL RETURNING session_id, user_id`, ids, now, reason)
		if err != nil {
			return err
		}
		type revokedRow struct {
			ID, User uuid.UUID
		}
		revoked, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (revokedRow, error) {
			var v revokedRow
			return v, r.Scan(&v.ID, &v.User)
		})
		if err != nil {
			return err
		}
		for _, r := range revoked {
			if err := emit(ctx, tx, TopicRevoked, r.User, map[string]any{"user_id": r.User, "session_id": r.ID,
				"reason": reason}); err != nil {
				return err
			}
		}
		n = len(revoked)
		return nil
	})
	if err != nil {
		return 0, err
	}
	// Again after the commit: a refresh that held the session row while
	// the first markers were written may have minted a token since.
	if err := s.markRevoked(ctx, ids...); err != nil {
		s.cfg.Logger.Error("session: revocation markers after commit", "sessions", len(ids), "err", err)
	}
	return n, nil
}

// Revoke revokes one of the user's sessions (sign-out, or removal from
// the session list). Revoking a revoked session is a no-op; another
// user's session is ErrNotFound.
func (s *Service) Revoke(ctx context.Context, userID, sessionID uuid.UUID, reason string) error {
	var owner uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT user_id FROM sessions WHERE session_id = $1`, sessionID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != userID) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = s.revokeWhere(ctx, reason, `session_id = $1`, sessionID)
	return err
}

// RevokeUser revokes every session of a user (account lock, recovery).
func (s *Service) RevokeUser(ctx context.Context, userID uuid.UUID, reason string) (int, error) {
	return s.revokeWhere(ctx, reason, `user_id = $1`, userID)
}

// RevokeDevice revokes every session tied to a device (the device was
// revoked, §2.2.7).
func (s *Service) RevokeDevice(ctx context.Context, deviceID uuid.UUID, reason string) (int, error) {
	return s.revokeWhere(ctx, reason, `device_id = $1`, deviceID)
}

// Sessions lists the user's active sessions, newest first.
func (s *Service) Sessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sessionColumns+` FROM sessions s
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2 ORDER BY created_at DESC, session_id`,
		userID, s.cfg.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// Purge deletes sessions (and their refresh tokens) that expired or were
// revoked more than retention ago, and returns how many it deleted.
func (s *Service) Purge(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := s.cfg.Now().Add(-retention)
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1 OR revoked_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
