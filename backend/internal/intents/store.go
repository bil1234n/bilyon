package intents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/money"
)

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type store struct {
	pool *pgxpool.Pool
}

const columns = `intent_id, payer_id, payer_subject, payer_device_id, signer_key_id, signer_role, payee_id,
	payee_subject, par_version, gesture, amount_minor, currency, payee_amount, payee_currency, quote_id,
	quote_signature, state, reason, on_timeout, server_nonce, signed_at, txauth, hold_id, hold_expires_at, entry_ids,
	t_land, live_until, claim_until, trajectory, created_at, updated_at, held_at, delivered_at, caught_at, resolved_at`

func scanIntent(row pgx.Row) (*Intent, error) {
	in := &Intent{}
	var payee, quote, hold *uuid.UUID
	var payeeSubject, reason *string
	var parVersion *int64
	var nonce, trajectory []byte
	err := row.Scan(&in.ID, &in.PayerID, &in.PayerSubject, &in.PayerDeviceID, &in.SignerKeyID, &in.SignerRole, &payee,
		&payeeSubject, &parVersion, &in.Gesture, &in.Amount, &in.Currency, &in.PayeeAmount, &in.PayeeCurrency, &quote,
		&in.quoteSignature, &in.State, &reason, &in.OnTimeout, &nonce, &in.SignedAt, &in.TxAuth, &hold, &in.HoldExpiresAt,
		&in.EntryIDs, &in.TLand, &in.LiveUntil, &in.ClaimUntil, &trajectory, &in.CreatedAt, &in.UpdatedAt, &in.HeldAt,
		&in.DeliveredAt, &in.CaughtAt, &in.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if payee != nil {
		in.PayeeID = *payee
	}
	if quote != nil {
		in.QuoteID = *quote
	}
	if hold != nil {
		in.HoldID = *hold
	}
	if payeeSubject != nil {
		in.PayeeSubject = *payeeSubject
	}
	if reason != nil {
		in.Reason = *reason
	}
	if parVersion != nil {
		in.PARVersion = uint64(*parVersion)
	}
	copy(in.nonce[:], nonce)
	if trajectory != nil {
		in.Trajectory = &Trajectory{}
		if err := json.Unmarshal(trajectory, in.Trajectory); err != nil {
			return nil, fmt.Errorf("intents: trajectory of %s: %w", in.ID, err)
		}
	}
	if in.EntryIDs == nil {
		in.EntryIDs = []uuid.UUID{}
	}
	for _, t := range []*time.Time{&in.SignedAt, &in.HoldExpiresAt, &in.CreatedAt, &in.UpdatedAt} {
		*t = t.UTC()
	}
	for _, t := range []**time.Time{&in.TLand, &in.LiveUntil, &in.ClaimUntil, &in.HeldAt, &in.DeliveredAt, &in.CaughtAt,
		&in.ResolvedAt} {
		if *t != nil {
			u := (*t).UTC()
			*t = &u
		}
	}
	return in, nil
}

func (s *store) get(ctx context.Context, q querier, id uuid.UUID) (*Intent, error) {
	return scanIntent(q.QueryRow(ctx, `SELECT `+columns+` FROM payment_intents WHERE intent_id = $1`, id))
}

func (s *store) lock(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*Intent, error) {
	return scanIntent(tx.QueryRow(ctx, `SELECT `+columns+` FROM payment_intents WHERE intent_id = $1 FOR UPDATE`, id))
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullVersion(v uint64) *int64 {
	if v == 0 {
		return nil
	}
	n := int64(v)
	return &n
}

func nullTrajectory(t *Trajectory) ([]byte, error) {
	if t == nil {
		return nil, nil
	}
	return json.Marshal(t)
}

// errNonceUsed reports a nonce consumed by another intent.
var errNonceUsed = fmt.Errorf("%w: already used by another intent", ErrNonce)

// insert stores a new intent; false means the intent id exists already.
func (s *store) insert(ctx context.Context, tx pgx.Tx, in *Intent) (bool, error) {
	traj, err := nullTrajectory(in.Trajectory)
	if err != nil {
		return false, err
	}
	var quoteSig []byte
	if in.QuoteID != uuid.Nil {
		quoteSig = in.quoteSignature
	}
	tag, err := tx.Exec(ctx, `INSERT INTO payment_intents (intent_id, payer_id, payer_subject, payer_device_id,
			signer_key_id, signer_role, payee_id, payee_subject, par_version, gesture, amount_minor, currency, payee_amount,
			payee_currency, quote_id, quote_signature, state, reason, on_timeout, server_nonce, signed_at, txauth,
			hold_expires_at, t_land, live_until, trajectory, created_at, updated_at, resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
			$24, $25, $26, $27, $27, $28)
		ON CONFLICT (intent_id) DO NOTHING`,
		in.ID, in.PayerID, in.PayerSubject, in.PayerDeviceID, in.SignerKeyID, in.SignerRole, nullUUID(in.PayeeID),
		nullString(in.PayeeSubject), nullVersion(in.PARVersion), in.Gesture, in.Amount, in.Currency, in.PayeeAmount,
		in.PayeeCurrency, nullUUID(in.QuoteID), quoteSig, in.State, nullString(in.Reason), in.OnTimeout, in.nonce[:],
		in.SignedAt, in.TxAuth, in.HoldExpiresAt, in.TLand, in.LiveUntil, traj, in.CreatedAt, in.ResolvedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "payment_intents_server_nonce_key" {
		return false, errNonceUsed
	}
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// change is one state transition. Fields left zero keep the stored value;
// timestamps are recorded the first time a state is reached.
type change struct {
	From       []State
	To         State
	Reason     string // stored for aborted, voiding and voided; cleared otherwise
	HoldID     uuid.UUID
	EntryIDs   []uuid.UUID
	PayeeID    uuid.UUID
	Subject    string
	ClaimUntil *time.Time
	Topic      string // event to publish with the transition, if any
}

// apply performs c on intent id if its state is one of c.From and returns
// the updated intent; nil means the state had already moved on.
func (s *store) apply(ctx context.Context, tx pgx.Tx, id uuid.UUID, c change, now time.Time) (*Intent, error) {
	var held, delivered, caught, resolved *time.Time
	switch c.To {
	case StateHeld:
		held = &now
	case StateDelivered:
		delivered = &now
	case StateCaught:
		caught = &now
	case StateSettled, StateVoided, StateAborted:
		resolved = &now
	}
	if c.HoldID != uuid.Nil && c.To == StateCaught {
		held = &now // an intent that settles on acceptance goes straight from created to caught
	}
	var reason *string
	if c.To == StateAborted || c.To == StateVoiding || c.To == StateVoided {
		reason = nullString(c.Reason)
	}
	var entries []uuid.UUID
	if c.EntryIDs != nil {
		entries = c.EntryIDs
	}
	from := make([]string, len(c.From))
	for i, st := range c.From {
		from[i] = string(st)
	}
	in, err := scanIntent(tx.QueryRow(ctx, `UPDATE payment_intents SET state = $2,
			reason = CASE WHEN $2 IN ('aborted', 'voiding', 'voided') THEN COALESCE($3, reason) END,
			updated_at = $4, hold_id = COALESCE(hold_id, $5), entry_ids = COALESCE($6, entry_ids),
			payee_id = COALESCE(payee_id, $7), payee_subject = COALESCE(payee_subject, $8),
			claim_until = COALESCE($9, claim_until), held_at = COALESCE(held_at, $10),
			delivered_at = COALESCE(delivered_at, $11), caught_at = COALESCE(caught_at, $12), resolved_at = $13
		WHERE intent_id = $1 AND state = ANY($14) RETURNING `+columns,
		id, c.To, reason, now, nullUUID(c.HoldID), entries, nullUUID(c.PayeeID), nullString(c.Subject), c.ClaimUntil,
		held, delivered, caught, resolved, from))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if c.Topic != "" {
		if err := emit(ctx, tx, c.Topic, in); err != nil {
			return nil, err
		}
	}
	return in, nil
}

// gestureUse is the K_gest use of a device inside the velocity window.
func (s *store) gestureUse(ctx context.Context, tx pgx.Tx, device uuid.UUID, currency string, since time.Time) (int, int64, error) {
	var n int
	var sum int64
	err := tx.QueryRow(ctx, `SELECT count(*), COALESCE(sum(amount_minor) FILTER (WHERE currency = $2), 0)
		FROM payment_intents WHERE payer_device_id = $1 AND signer_role = 'gest' AND state <> 'aborted'
		AND created_at > $3`, device, currency, since).Scan(&n, &sum)
	return n, sum, err
}

// outflow is what a payer committed in currency since a time: intents that
// hold or moved money.
func (s *store) outflow(ctx context.Context, tx pgx.Tx, payer uuid.UUID, currency string, since time.Time) (int64, error) {
	var sum int64
	err := tx.QueryRow(ctx, `SELECT COALESCE(sum(amount_minor), 0) FROM payment_intents
		WHERE payer_id = $1 AND currency = $2 AND state NOT IN ('aborted', 'voiding', 'voided') AND created_at > $3`,
		payer, currency, since).Scan(&sum)
	return sum, err
}

// due locks up to limit intents in states whose deadline column has passed.
func (s *store) due(ctx context.Context, tx pgx.Tx, states []State, deadline string, now time.Time, limit int) ([]*Intent, error) {
	names := make([]string, len(states))
	for i, st := range states {
		names[i] = string(st)
	}
	rows, err := tx.Query(ctx, `SELECT `+columns+` FROM payment_intents
		WHERE state = ANY($1) AND `+deadline+` <= $2 ORDER BY `+deadline+` LIMIT $3 FOR UPDATE SKIP LOCKED`,
		names, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Intent
	for rows.Next() {
		in, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// unfinished lists intents whose ledger call has been pending since before
// a time.
func (s *store) unfinished(ctx context.Context, before time.Time, limit int) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT intent_id FROM payment_intents
		WHERE state IN ('created', 'caught', 'voiding') AND updated_at <= $1 ORDER BY updated_at LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// Role selects the side of the intents a listing returns.
type Role string

// Roles.
const (
	RoleAny   Role = ""
	RolePayer Role = "payer"
	RolePayee Role = "payee"
)

// ListQuery selects a page of a user's intents, newest first.
type ListQuery struct {
	UserID uuid.UUID
	Role   Role
	States []State   // empty: every state
	Before uuid.UUID // cursor: the last intent of the previous page
	Limit  int       // 1..200, default 50
}

func (s *store) list(ctx context.Context, q ListQuery) ([]*Intent, error) {
	var side string
	switch q.Role {
	case RolePayer:
		side = `payer_id = $1`
	case RolePayee:
		side = `payee_id = $1`
	default:
		side = `(payer_id = $1 OR payee_id = $1)`
	}
	states := make([]string, len(q.States))
	for i, st := range q.States {
		states[i] = string(st)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+columns+` FROM payment_intents WHERE `+side+`
			AND (cardinality($2::text[]) = 0 OR state = ANY($2))
			AND ($3::uuid IS NULL OR (created_at, intent_id) <
				(SELECT created_at, intent_id FROM payment_intents WHERE intent_id = $3))
		ORDER BY created_at DESC, intent_id DESC LIMIT $4`, q.UserID, states, nullUUID(q.Before), q.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Intent
	for rows.Next() {
		in, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// lockPayer locks the payer's row (without blocking inserts that reference
// it) and returns the status and the default timeout preference.
func (s *store) lockPayer(ctx context.Context, tx pgx.Tx, payer uuid.UUID) (string, Timeout, error) {
	var status string
	var timeout Timeout
	err := tx.QueryRow(ctx, `SELECT status, intent_timeout FROM users WHERE user_id = $1 FOR NO KEY UPDATE`,
		payer).Scan(&status, &timeout)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", fmt.Errorf("%w: unknown payer", ErrTxAuth)
	}
	return status, timeout, err
}

func (s *store) userStatus(ctx context.Context, user uuid.UUID) (string, error) {
	var status string
	err := s.pool.QueryRow(ctx, `SELECT status FROM users WHERE user_id = $1`, user).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return status, err
}

func (s *store) deviceOwner(ctx context.Context, device uuid.UUID) (uuid.UUID, bool, error) {
	var owner uuid.UUID
	var revoked bool
	err := s.pool.QueryRow(ctx, `SELECT user_id, revoked_at IS NOT NULL FROM devices WHERE device_id = $1`,
		device).Scan(&owner, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, ErrNotFound
	}
	return owner, revoked, err
}

// SetTimeout records a user's default for uncaught throws.
func (s *store) setTimeout(ctx context.Context, user uuid.UUID, t Timeout) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET intent_timeout = $2 WHERE user_id = $1`, user, t)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *store) timeout(ctx context.Context, user uuid.UUID) (Timeout, error) {
	var t Timeout
	err := s.pool.QueryRow(ctx, `SELECT intent_timeout FROM users WHERE user_id = $1`, user).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return t, err
}

// addWithin adds amounts and reports whether the total stays within max.
func addWithin(max int64, amounts ...int64) bool {
	total, err := money.Sum(amounts...)
	return err == nil && total <= max
}
