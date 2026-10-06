package identity

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/identity/handle"
	"github.com/bil1234n/bilyon/backend/internal/identity/tlog"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// Errors.
var (
	ErrNotFound = errors.New("identity: not found")
	ErrTaken    = errors.New("identity: handle taken")
	ErrReserved = errors.New("identity: handle reserved")
	ErrTooSoon  = errors.New("identity: handle changed too recently")
	ErrRequest  = errors.New("identity: invalid request")
)

// Event topics (owners' devices and risk consume them).
const (
	TopicEntryUpdated = "gateway.directory.entry_updated"
	EventSource       = "bilyon.gateway"
)

// DefaultReserved are names nobody can claim (brand, system and
// impersonation-prone names); their confusable variants are blocked too.
var DefaultReserved = []string{"bilyon", "admin", "administrator", "support", "help", "helpdesk", "security",
	"official", "root", "system", "payments", "pay", "wallet", "bank", "verify", "verified", "team", "staff",
	"billing", "refund", "refunds", "compliance", "fraud", "info", "noreply", "api", "treasury", "ceo"}

// Config configures the directory.
type Config struct {
	Signer         cose.Signer // K_dir: signs PARs and tree heads
	KeyID          []byte
	PARTTL         time.Duration // PAR lifetime (default 10 minutes)
	ChangeInterval time.Duration // minimum time between handle changes (default 30 days)
	Quarantine     time.Duration // how long a released handle stays with its owner (default 90 days)
	Now            func() time.Time
}

// Service is the payee directory.
type Service struct {
	cfg   Config
	pool  *pgxpool.Pool
	log   *tlog.Log
	sthMu sync.Mutex
}

// New returns the directory over a migrated gateway database.
func New(cfg Config, pool *pgxpool.Pool) (*Service, error) {
	if cfg.Signer == nil || len(cfg.KeyID) == 0 || len(cfg.KeyID) > cose.MaxKIDLen {
		return nil, errors.New("identity: a K_dir signer and key id are required")
	}
	if cfg.PARTTL == 0 {
		cfg.PARTTL = 10 * time.Minute
	}
	if cfg.ChangeInterval == 0 {
		cfg.ChangeInterval = 30 * 24 * time.Hour
	}
	if cfg.Quarantine == 0 {
		cfg.Quarantine = 90 * 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg, pool: pool, log: tlog.New(pool)}, nil
}

// Log returns the transparency log.
func (s *Service) Log() *tlog.Log { return s.log }

// Keys resolves K_dir key ids for verifiers in this process (clients get
// the public keys out of band).
func (s *Service) Keys() cose.KeyResolver {
	pub := s.cfg.Signer.Public()
	kid := string(s.cfg.KeyID)
	return func(k []byte) (*ecdsa.PublicKey, error) {
		if string(k) != kid {
			return nil, cose.ErrUnknownKey
		}
		return pub, nil
	}
}

func (s *Service) now() time.Time { return s.cfg.Now().UTC().Truncate(time.Second) }

// ensureSubject returns the user's subject, creating it on first use.
func ensureSubject(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (string, error) {
	var subject string
	err := tx.QueryRow(ctx, `SELECT subject FROM subjects WHERE user_id = $1 FOR UPDATE`, userID).Scan(&subject)
	if err == nil {
		return subject, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if subject, err = NewSubject(); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO subjects (user_id, subject) VALUES ($1, $2)`, userID, subject); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return "", fmt.Errorf("%w: unknown user", ErrRequest)
		}
		return "", err
	}
	return subject, nil
}

// currentEntry loads and locks the subject's entry; nil before the first.
func currentEntry(ctx context.Context, tx pgx.Tx, subject string) (*Entry, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT entry FROM directory_entries WHERE subject = $1 FOR UPDATE`, subject).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return DecodeEntry(raw)
}

// commit appends the next version of an entry to the log and records it,
// in the caller's transaction.
func (s *Service) commit(ctx context.Context, tx pgx.Tx, prev *Entry, next Entry) (*Entry, error) {
	next.Version = 1
	if prev != nil {
		next.Version = prev.Version + 1
	}
	next.Time = s.now()
	raw, err := next.Encode()
	if err != nil {
		return nil, err
	}
	idx, err := s.log.Append(ctx, tx, raw)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO directory_entries (subject, version, entry, leaf_index, updated_at)
			VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (subject) DO UPDATE SET version = EXCLUDED.version, entry = EXCLUDED.entry,
			leaf_index = EXCLUDED.leaf_index, updated_at = EXCLUDED.updated_at`,
		next.Subject, int64(next.Version), raw, int64(idx), next.Time); err != nil {
		return nil, err
	}
	_, err = outbox.Write(ctx, tx, outbox.Event{Source: EventSource, Topic: TopicEntryUpdated, Key: "subject:" + next.Subject,
		Subject: next.Subject, Data: map[string]any{"subject": next.Subject, "version": next.Version, "leaf_index": idx,
			"handle": next.Handle}})
	return &next, err
}

// update runs fn on the user's current entry (a zero entry before the
// first) and commits the result, unless fn reports no change.
func (s *Service) update(ctx context.Context, userID uuid.UUID, fn func(tx pgx.Tx, e *Entry) (bool, error)) (*Entry, error) {
	var out *Entry
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		subject, err := ensureSubject(ctx, tx, userID)
		if err != nil {
			return err
		}
		prev, err := currentEntry(ctx, tx, subject)
		if err != nil {
			return err
		}
		next := Entry{Subject: subject}
		if prev != nil {
			next = *prev
		}
		changed, err := fn(tx, &next)
		if err != nil {
			return err
		}
		if !changed && prev != nil {
			out = prev
			return nil
		}
		out, err = s.commit(ctx, tx, prev, next)
		return err
	})
	return out, err
}

// Subject returns the user's subject, creating it on first use.
func (s *Service) Subject(ctx context.Context, userID uuid.UUID) (string, error) {
	var subject string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		subject, err = ensureSubject(ctx, tx, userID)
		return err
	})
	return subject, err
}

// ClaimHandle sets the user's handle: a first claim, a change (at most one
// per ChangeInterval; the old handle is quarantined for its owner), or a
// change of display case only (always allowed).
func (s *Service) ClaimHandle(ctx context.Context, userID uuid.UUID, input string) (handle.Handle, *Entry, error) {
	h, err := handle.Parse(input)
	if err != nil {
		return handle.Handle{}, nil, fmt.Errorf("%w: %w", ErrRequest, err)
	}
	now := s.now()
	e, err := s.update(ctx, userID, func(tx pgx.Tx, e *Entry) (bool, error) {
		var curKey, curSkeleton, curDisplay string
		var claimedAt time.Time
		err := tx.QueryRow(ctx, `SELECT handle, skeleton, display, claimed_at FROM handles WHERE user_id = $1 FOR UPDATE`,
			userID).Scan(&curKey, &curSkeleton, &curDisplay, &claimedAt)
		hasHandle := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
		if hasHandle && curKey == h.Key {
			if curDisplay == h.Display {
				return false, nil
			}
			if _, err := tx.Exec(ctx, `UPDATE handles SET display = $2 WHERE user_id = $1`, userID, h.Display); err != nil {
				return false, err
			}
			e.Display.Handle = h.Display
			return true, nil
		}
		if hasHandle && now.Before(claimedAt.Add(s.cfg.ChangeInterval)) {
			return false, fmt.Errorf("%w: next change after %s", ErrTooSoon, claimedAt.Add(s.cfg.ChangeInterval).Format(time.RFC3339))
		}
		var reserved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM reserved_handles WHERE skeleton = $1)`, h.Skeleton).
			Scan(&reserved); err != nil {
			return false, err
		}
		if reserved {
			return false, ErrReserved
		}
		var heldByOther bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM handle_quarantine
			WHERE skeleton = $1 AND user_id <> $2 AND released_at > $3)`, h.Skeleton, userID, now).Scan(&heldByOther); err != nil {
			return false, err
		}
		if heldByOther {
			return false, ErrTaken
		}
		if hasHandle {
			if _, err := tx.Exec(ctx, `DELETE FROM handles WHERE user_id = $1`, userID); err != nil {
				return false, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO handle_quarantine (skeleton, handle, user_id, released_at)
				VALUES ($1, $2, $3, $4) ON CONFLICT (skeleton) DO UPDATE
				SET handle = EXCLUDED.handle, user_id = EXCLUDED.user_id, released_at = EXCLUDED.released_at`,
				curSkeleton, curKey, userID, now.Add(s.cfg.Quarantine)); err != nil {
				return false, err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM handle_quarantine WHERE skeleton = $1 AND (user_id = $2 OR released_at <= $3)`,
			h.Skeleton, userID, now); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO handles (handle, skeleton, display, user_id, claimed_at) VALUES ($1, $2, $3, $4, $5)`,
			h.Key, h.Skeleton, h.Display, userID, now); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return false, ErrTaken
			}
			return false, err
		}
		e.Handle, e.Display.Handle = h.Key, h.Display
		return true, nil
	})
	if err != nil {
		return handle.Handle{}, nil, err
	}
	return h, e, nil
}

// ReleaseHandle gives up the user's handle; it stays quarantined for the
// user for the quarantine period.
func (s *Service) ReleaseHandle(ctx context.Context, userID uuid.UUID) (*Entry, error) {
	now := s.now()
	return s.update(ctx, userID, func(tx pgx.Tx, e *Entry) (bool, error) {
		var key, skeleton string
		err := tx.QueryRow(ctx, `DELETE FROM handles WHERE user_id = $1 RETURNING handle, skeleton`, userID).Scan(&key, &skeleton)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO handle_quarantine (skeleton, handle, user_id, released_at)
			VALUES ($1, $2, $3, $4) ON CONFLICT (skeleton) DO UPDATE
			SET handle = EXCLUDED.handle, user_id = EXCLUDED.user_id, released_at = EXCLUDED.released_at`,
			skeleton, key, userID, now.Add(s.cfg.Quarantine)); err != nil {
			return false, err
		}
		e.Handle, e.Display.Handle = "", ""
		return true, nil
	})
}

// Profile is what a user publishes beyond the handle.
type Profile struct {
	Name            string
	AvatarSHA256    []byte
	Currencies      []string
	DefaultCurrency string
	Keys            []PublicKey
}

// UpdateProfile publishes a new version of the user's profile.
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, p Profile) (*Entry, error) {
	return s.update(ctx, userID, func(_ pgx.Tx, e *Entry) (bool, error) {
		e.Display.Name, e.Display.AvatarSHA256 = p.Name, p.AvatarSHA256
		e.Currencies, e.DefaultCurrency = slices.Clone(p.Currencies), p.DefaultCurrency
		e.Keys = slices.Clone(p.Keys)
		return true, nil
	})
}

// SetVerified sets the user's verification badges (trusted callers only:
// KYC and link verification).
func (s *Service) SetVerified(ctx context.Context, userID uuid.UUID, badges []string) (*Entry, error) {
	return s.update(ctx, userID, func(_ pgx.Tx, e *Entry) (bool, error) {
		if slices.Equal(e.Display.Verified, badges) {
			return false, nil
		}
		e.Display.Verified = slices.Clone(badges)
		return true, nil
	})
}

// Reserve blocks a name and its confusable variants from being claimed.
func (s *Service) Reserve(ctx context.Context, name, reason string) error {
	key := handle.Fold(name)
	if key == "" || reason == "" {
		return fmt.Errorf("%w: a name and a reason are required", ErrRequest)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO reserved_handles (skeleton, handle, reason) VALUES ($1, $2, $3)
		ON CONFLICT (skeleton) DO NOTHING`, handle.HandleSkeleton(key), key, reason)
	return err
}

// EnsureReserved reserves DefaultReserved (idempotent; run at start-up).
func (s *Service) EnsureReserved(ctx context.Context) error {
	for _, name := range DefaultReserved {
		if err := s.Reserve(ctx, name, "reserved"); err != nil {
			return err
		}
	}
	return nil
}

// Resolve returns the PAR of the handle that input denotes. Lookup is by
// skeleton, so a lookalike of a handle resolves to that handle's owner (the
// only one who can hold it), and the PAR shows the real display handle.
func (s *Service) Resolve(ctx context.Context, input string) (*PAR, error) {
	sk, err := handle.LookupSkeleton(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRequest, err)
	}
	var subject string
	err = s.pool.QueryRow(ctx, `SELECT s.subject FROM handles h JOIN subjects s USING (user_id) WHERE h.skeleton = $1`,
		sk).Scan(&subject)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.ResolveSubject(ctx, subject)
}

// ResolveSubject returns a subject's PAR.
func (s *Service) ResolveSubject(ctx context.Context, subject string) (*PAR, error) {
	if !ValidSubject(subject) {
		return nil, fmt.Errorf("%w: subject %q", ErrRequest, subject)
	}
	var raw []byte
	var leaf int64
	err := s.pool.QueryRow(ctx, `SELECT entry, leaf_index FROM directory_entries WHERE subject = $1`, subject).Scan(&raw, &leaf)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sth, err := s.treeHeadCovering(ctx, uint64(leaf))
	if err != nil {
		return nil, err
	}
	proof, err := s.log.InclusionProof(ctx, uint64(leaf), sth.Size)
	if err != nil {
		return nil, err
	}
	entry, err := DecodeEntry(raw)
	if err != nil {
		return nil, err
	}
	iat := s.now()
	exp := iat.Add(s.cfg.PARTTL)
	signed, err := signPAR(s.cfg.Signer, s.cfg.KeyID, raw, uint64(leaf), sth, proof, iat, exp)
	if err != nil {
		return nil, err
	}
	return &PAR{Raw: signed, Entry: entry, EntryRaw: raw, LeafIndex: uint64(leaf), TreeHead: sth.TreeHead, STH: sth.Raw,
		Inclusion: proof, IssuedAt: iat, ExpiresAt: exp}, nil
}

// treeHeadCovering returns a signed tree head that includes leaf, signing
// a new one when the latest predates the leaf.
func (s *Service) treeHeadCovering(ctx context.Context, leaf uint64) (tlog.SignedTreeHead, error) {
	s.sthMu.Lock()
	defer s.sthMu.Unlock()
	latest, err := s.log.Latest(ctx)
	if err == nil && latest.Size > leaf {
		return latest, nil
	}
	if err != nil && !errors.Is(err, tlog.ErrNoTreeHead) {
		return tlog.SignedTreeHead{}, err
	}
	return s.log.Publish(ctx, s.cfg.Signer, s.cfg.KeyID, s.cfg.Now())
}

// PublishTreeHead signs the current tree head (every 10 minutes, §4.1.3).
func (s *Service) PublishTreeHead(ctx context.Context) (tlog.SignedTreeHead, error) {
	s.sthMu.Lock()
	defer s.sthMu.Unlock()
	return s.log.Publish(ctx, s.cfg.Signer, s.cfg.KeyID, s.cfg.Now())
}

// Payee is the account holder behind a subject and their current entry.
type Payee struct {
	UserID uuid.UUID
	Status string // the user's status: active, frozen or closed
	Entry  *Entry
}

// Payee resolves a subject for a payment: its owner and current directory
// entry. A subject without an entry has no PAR, so nobody can have
// verified it as a payee: ErrNotFound.
func (s *Service) Payee(ctx context.Context, subject string) (Payee, error) {
	if !ValidSubject(subject) {
		return Payee{}, fmt.Errorf("%w: subject %q", ErrRequest, subject)
	}
	var p Payee
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT s.user_id, u.status, d.entry FROM subjects s
		JOIN users u ON u.user_id = s.user_id JOIN directory_entries d ON d.subject = s.subject
		WHERE s.subject = $1`, subject).Scan(&p.UserID, &p.Status, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Payee{}, ErrNotFound
	}
	if err != nil {
		return Payee{}, err
	}
	if p.Entry, err = DecodeEntry(raw); err != nil {
		return Payee{}, err
	}
	return p, nil
}

// CurrentVersion is the subject's current entry version: payments re-check
// it at execution and refuse a payee that changed (PAYEE_CHANGED).
func (s *Service) CurrentVersion(ctx context.Context, subject string) (uint64, error) {
	var v int64
	err := s.pool.QueryRow(ctx, `SELECT version FROM directory_entries WHERE subject = $1`, subject).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return uint64(v), err
}

// Entries returns logged entries from index from (auditors and owners'
// self-audit replay them).
func (s *Service) Entries(ctx context.Context, from uint64, limit int) ([]*Entry, error) {
	leaves, err := s.log.Leaves(ctx, from, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*Entry, len(leaves))
	for i, raw := range leaves {
		if out[i], err = DecodeEntry(raw); err != nil {
			return nil, fmt.Errorf("identity: log leaf %d: %w", from+uint64(i), err)
		}
	}
	return out, nil
}
