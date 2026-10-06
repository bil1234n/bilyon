package webauthn

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
	"github.com/bil1234n/bilyon/backend/internal/platform/onetime"
)

// Store errors.
var (
	ErrNotFound         = errors.New("webauthn: not found")
	ErrCredentialExists = errors.New("webauthn: credential already registered")
)

// User is a person's account as WebAuthn sees it.
type User struct {
	ID          uuid.UUID
	Handle      []byte // WebAuthn user.id: 32 random bytes, never PII
	DisplayName string
	Status      string
	CreatedAt   time.Time
}

// Credential is a registered passkey (R10).
type Credential struct {
	ID                []byte
	UserID            uuid.UUID
	PublicKey         []byte // COSE_Key
	Alg               int64
	SignCount         uint32
	Transports        []string
	BackupEligible    bool
	BackedUp          bool
	AAGUID            uuid.UUID
	AttestationFormat string
	AttestationTrust  string
	CreatedAt         time.Time
	LastUsedAt        *time.Time
}

// Event topics the relying party publishes (risk features, A5/A6).
const (
	TopicCredentialRegistered = "gateway.webauthn.credential_registered"
	TopicCloneSignal          = "gateway.webauthn.clone_signal"
	TopicBackupStateChanged   = "gateway.webauthn.backup_state_changed"
	EventSource               = "bilyon.gateway"
)

// PGStore keeps users and credentials in the gateway database.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore returns a store over the migrated gateway schema.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

const userColumns = `user_id, webauthn_handle, display_name, status, created_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Handle, &u.DisplayName, &u.Status, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	u.CreatedAt = u.CreatedAt.UTC()
	return u, err
}

// CreateUser creates an account with a fresh random user handle.
func (s *PGStore) CreateUser(ctx context.Context, displayName string) (User, error) {
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return User{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, err
	}
	return scanUser(s.pool.QueryRow(ctx, `INSERT INTO users (user_id, webauthn_handle, display_name) VALUES ($1, $2, $3)
		RETURNING `+userColumns, id, handle, displayName))
}

// UserByID loads an account.
func (s *PGStore) UserByID(ctx context.Context, id uuid.UUID) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE user_id = $1`, id))
}

// UserByHandle resolves a WebAuthn user handle (discoverable login).
func (s *PGStore) UserByHandle(ctx context.Context, handle []byte) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE webauthn_handle = $1`, handle))
}

const credentialColumns = `credential_id, user_id, public_key, alg, sign_count, transports, backup_eligible, backed_up,
	aaguid, attestation_fmt, attestation_trust, created_at, last_used_at`

func scanCredential(row pgx.Row) (Credential, error) {
	var c Credential
	var signCount int64
	err := row.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.Alg, &signCount, &c.Transports, &c.BackupEligible, &c.BackedUp,
		&c.AAGUID, &c.AttestationFormat, &c.AttestationTrust, &c.CreatedAt, &c.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	c.SignCount = uint32(signCount)
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// CredentialByID loads an active (not revoked) credential.
func (s *PGStore) CredentialByID(ctx context.Context, id []byte) (Credential, error) {
	return scanCredential(s.pool.QueryRow(ctx, `SELECT `+credentialColumns+` FROM webauthn_credentials
		WHERE credential_id = $1 AND revoked_at IS NULL`, id))
}

// CredentialsForUser lists a user's active credentials.
func (s *PGStore) CredentialsForUser(ctx context.Context, userID uuid.UUID) ([]Credential, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+credentialColumns+` FROM webauthn_credentials
		WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertCredential persists a new credential (R10) and announces it. A
// credential id registered before, to anyone, is ErrCredentialExists (R7).
func (s *PGStore) InsertCredential(ctx context.Context, c Credential) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO webauthn_credentials (credential_id, user_id, public_key, alg, sign_count,
				transports, backup_eligible, backed_up, aaguid, attestation_fmt, attestation_trust)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			c.ID, c.UserID, c.PublicKey, c.Alg, int64(c.SignCount), c.Transports, c.BackupEligible, c.BackedUp,
			c.AAGUID, c.AttestationFormat, c.AttestationTrust)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrCredentialExists
		}
		if err != nil {
			return err
		}
		_, err = outbox.Write(ctx, tx, outbox.Event{Source: EventSource, Topic: TopicCredentialRegistered,
			Key: "user:" + c.UserID.String(), Subject: c.UserID.String(), Data: map[string]any{
				"user_id": c.UserID, "aaguid": c.AAGUID, "attestation_fmt": c.AttestationFormat,
				"attestation_trust": c.AttestationTrust, "backup_eligible": c.BackupEligible, "backed_up": c.BackedUp,
			}})
		return err
	})
}

// AssertionUpdate is what a successful login changes on a credential.
type AssertionUpdate struct {
	CredentialID []byte
	UserID       uuid.UUID
	SignCount    uint32
	BackedUp     bool
	CloneSignal  bool // A5: the counter did not increase
	BecameBacked bool // A6: BS went from 0 to 1
}

// RecordAssertion stores the new counter (never lowering it) and backup
// state and publishes risk signals, atomically.
func (s *PGStore) RecordAssertion(ctx context.Context, u AssertionUpdate) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE webauthn_credentials
			SET sign_count = greatest(sign_count, $2), backed_up = $3, last_used_at = clock_timestamp()
			WHERE credential_id = $1`, u.CredentialID, int64(u.SignCount), u.BackedUp); err != nil {
			return err
		}
		emit := func(topic string, data map[string]any) error {
			_, err := outbox.Write(ctx, tx, outbox.Event{Source: EventSource, Topic: topic,
				Key: "user:" + u.UserID.String(), Subject: u.UserID.String(), Data: data})
			return err
		}
		if u.CloneSignal {
			if err := emit(TopicCloneSignal, map[string]any{"user_id": u.UserID, "credential_id": u.CredentialID,
				"received_sign_count": u.SignCount}); err != nil {
				return err
			}
		}
		if u.BecameBacked {
			if err := emit(TopicBackupStateChanged, map[string]any{"user_id": u.UserID, "credential_id": u.CredentialID,
				"backed_up": true}); err != nil {
				return err
			}
		}
		return nil
	})
}

// ceremony is the server-side state of one registration or login.
type ceremony struct {
	Kind      string    `json:"k"` // "create" or "get"
	Challenge []byte    `json:"c"`
	UserID    uuid.UUID `json:"u"`
	Algs      []int64   `json:"a,omitempty"`
	Expires   time.Time `json:"e"`
}

// ChallengeStore keeps ceremonies until their single use (R2, A2).
type ChallengeStore interface {
	Put(ctx context.Context, flowID string, c ceremony, ttl time.Duration) error
	// Take returns and deletes a ceremony atomically: ErrNotFound when it
	// never existed, expired or was already used.
	Take(ctx context.Context, flowID string) (ceremony, error)
}

// RedisChallenges stores ceremonies in Redis, single use.
type RedisChallenges struct {
	s *onetime.Store[ceremony]
}

// NewRedisChallenges returns a Redis-backed ChallengeStore.
func NewRedisChallenges(rdb redis.UniversalClient) *RedisChallenges {
	return &RedisChallenges{s: onetime.New[ceremony](rdb, "bilyon:webauthn:flow:")}
}

// Put implements ChallengeStore.
func (r *RedisChallenges) Put(ctx context.Context, flowID string, c ceremony, ttl time.Duration) error {
	return r.s.Put(ctx, flowID, c, ttl)
}

// Take implements ChallengeStore.
func (r *RedisChallenges) Take(ctx context.Context, flowID string) (ceremony, error) {
	c, err := r.s.Take(ctx, flowID)
	if errors.Is(err, onetime.ErrNotFound) {
		return ceremony{}, ErrNotFound
	}
	return c, err
}
