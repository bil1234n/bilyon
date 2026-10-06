// Package pgledger is the PostgreSQL implementation of ledger.Ledger
// (RFC 0001 §2.3, Phase 1 system of record).
//
// Correctness rests on three layers:
//  1. The schema (migrations/ledger) enforces the invariants itself:
//     balanced entries, floors, append-only history, the hold state machine.
//  2. Every command runs in one READ COMMITTED transaction that claims its
//     idempotency key first, so a command takes effect exactly once and a
//     replay returns the stored result.
//  3. Lock ordering prevents deadlocks: hold and reserve rows are locked
//     before balance rows, and balance rows are locked in (account_id,
//     stripe) order before any trigger touches them. Deadlocks that still
//     occur (they should not) and serialisation failures are retried.
package pgledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/money"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// Engine is a ledger.Ledger backed by PostgreSQL.
type Engine struct {
	pool       *pgxpool.Pool
	log        *slog.Logger
	maxRetries int
}

var _ ledger.Ledger = (*Engine)(nil)

// Option configures an Engine.
type Option func(*Engine)

// WithLogger sets the logger used for retry diagnostics.
func WithLogger(l *slog.Logger) Option { return func(e *Engine) { e.log = l } }

// WithMaxRetries sets how often a transaction is retried on serialisation
// failures and deadlocks (default 8).
func WithMaxRetries(n int) Option { return func(e *Engine) { e.maxRetries = n } }

// New returns an engine using pool. The schema must be migrated.
func New(pool *pgxpool.Pool, opts ...Option) *Engine {
	e := &Engine{pool: pool, log: slog.New(slog.DiscardHandler), maxRetries: 8}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Pool exposes the underlying pool (used by workers sharing it).
func (e *Engine) Pool() *pgxpool.Pool { return e.pool }

// ---------------------------------------------------------------------------
// Transactions, retries, idempotency
// ---------------------------------------------------------------------------

func retryable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001" || pgErr.Code == "40P01"
	}
	return false
}

func (e *Engine) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	for attempt := 0; ; attempt++ {
		err := pgx.BeginTxFunc(ctx, e.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, fn)
		if err == nil {
			return nil
		}
		if retryable(err) && attempt < e.maxRetries {
			wait := time.Duration(1<<min(attempt, 6)) * time.Millisecond
			wait += time.Duration(rand.Int64N(int64(wait)))
			e.log.WarnContext(ctx, "ledger transaction retried", slog.Int("attempt", attempt+1), slog.Any("error", err))
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return mapError(err)
	}
}

// idempotent runs fn exactly once per key inside one transaction. The key is
// claimed first; a concurrent request with the same key blocks on the unique
// index until the first commits, then replays its stored response.
func idempotent[T any](ctx context.Context, e *Engine, scope, key string, hash [32]byte, fn func(tx pgx.Tx) (T, error)) (T, error) {
	var out T
	err := e.inTx(ctx, func(tx pgx.Tx) error {
		replay, claimed, err := claimKey(ctx, tx, scope, key, hash)
		if err != nil {
			return err
		}
		if !claimed {
			if err := json.Unmarshal(replay, &out); err != nil {
				return fmt.Errorf("pgledger: decode stored response for %q: %w", key, err)
			}
			return nil
		}
		res, err := fn(tx)
		if err != nil {
			return err
		}
		body, err := json.Marshal(res)
		if err != nil {
			return fmt.Errorf("pgledger: encode response: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE idempotency_keys SET response = $2, completed_at = clock_timestamp()
			WHERE idempotency_key = $1`, key, body); err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

func claimKey(ctx context.Context, tx pgx.Tx, scope, key string, hash [32]byte) ([]byte, bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO idempotency_keys (idempotency_key, scope, request_hash)
		VALUES ($1, $2, $3) ON CONFLICT (idempotency_key) DO NOTHING`, key, scope, hash[:])
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() == 1 {
		return nil, true, nil
	}
	var gotScope string
	var gotHash, resp []byte
	if err := tx.QueryRow(ctx, `SELECT scope, request_hash, response FROM idempotency_keys WHERE idempotency_key = $1`,
		key).Scan(&gotScope, &gotHash, &resp); err != nil {
		return nil, false, err
	}
	if gotScope != scope || !bytes.Equal(gotHash, hash[:]) {
		return nil, false, fmt.Errorf("%w: key %q was used for a different %s request", ledger.ErrIdempotencyConflict, key, gotScope)
	}
	if resp == nil {
		// The key row and its response commit together, so a visible row
		// without a response means the schema was tampered with.
		return nil, false, fmt.Errorf("pgledger: idempotency key %q has no stored response", key)
	}
	return resp, false, nil
}

// mapError turns database errors that escaped the pre-checks into ledger errors.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		var connErr *pgconn.ConnectError
		if errors.As(err, &connErr) || pgconn.Timeout(err) {
			return fmt.Errorf("%w: %v", ledger.ErrUnavailable, err)
		}
		return err
	}
	switch pgErr.Code {
	case "23514":
		if pgErr.ConstraintName == "account_balances_floor" {
			return fmt.Errorf("%w: %s", ledger.ErrInsufficientFunds, pgErr.Message)
		}
		return fmt.Errorf("%w: %s", ledger.ErrInvalid, pgErr.Message)
	case "BL001":
		return fmt.Errorf("%w: %s", ledger.ErrAccountFrozen, pgErr.Message)
	case "BL003":
		return fmt.Errorf("%w: %s", ledger.ErrUnbalanced, pgErr.Message)
	case "BL005":
		return fmt.Errorf("%w: %s", ledger.ErrHoldNotPending, pgErr.Message)
	case "BL007":
		return fmt.Errorf("%w: %s", ledger.ErrInvalid, pgErr.Message)
	case "BL008":
		return fmt.Errorf("%w: %s", ledger.ErrReserveClosed, pgErr.Message)
	case "22003":
		return fmt.Errorf("%w: %s", ledger.ErrOverflow, pgErr.Message)
	case "23503":
		return fmt.Errorf("%w: %s", ledger.ErrCurrencyMismatch, pgErr.Message)
	case "23505":
		switch pgErr.ConstraintName {
		case "journal_entries_reverses_key":
			return fmt.Errorf("%w: %s", ledger.ErrAlreadyReversed, pgErr.Message)
		case "accounts_pkey":
			return &ledger.ValidationError{Field: "account_id", Reason: "already exists"}
		case "reserves_pkey":
			return &ledger.ValidationError{Field: "reserve_id", Reason: "already exists"}
		default:
			return fmt.Errorf("%w: %s", ledger.ErrIdempotencyConflict, pgErr.Message)
		}
	}
	return err
}

// ---------------------------------------------------------------------------
// Accounts, balance locks and fund checks
// ---------------------------------------------------------------------------

type acctRow struct {
	id       uuid.UUID
	kind     ledger.AccountKind
	currency string
	stripes  int
	frozen   bool
	floor    *int64
}

func loadAccounts(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID]acctRow, error) {
	rows, err := tx.Query(ctx, `SELECT account_id, kind, currency, stripes, frozen, floor_minor
		FROM accounts WHERE account_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[uuid.UUID]acctRow, len(ids))
	for rows.Next() {
		var a acctRow
		var stripes int16
		if err := rows.Scan(&a.id, &a.kind, &a.currency, &stripes, &a.frozen, &a.floor); err != nil {
			return nil, err
		}
		a.stripes = int(stripes)
		out[a.id] = a
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, ok := out[id]; !ok {
			return nil, &ledger.NotFoundError{Object: "account", ID: id}
		}
	}
	return out, nil
}

type balKey struct {
	account uuid.UUID
	stripe  int
}

type balRow struct {
	balance, pending int64
	floor            *int64
	frozen           bool
}

func (b balRow) available() int64 { return b.balance - b.pending }

// lockBalances locks balance rows in (account_id, stripe) order. Callers must
// already hold any hold/reserve row locks they need (hold rows come first).
func lockBalances(ctx context.Context, tx pgx.Tx, keys []balKey) (map[balKey]balRow, error) {
	accts := make([]uuid.UUID, len(keys))
	stripes := make([]int16, len(keys))
	for i, k := range keys {
		accts[i], stripes[i] = k.account, int16(k.stripe)
	}
	rows, err := tx.Query(ctx, `SELECT b.account_id, b.stripe, b.balance_minor, b.pending_minor, b.floor_minor, b.frozen
		FROM account_balances b
		JOIN unnest($1::uuid[], $2::smallint[]) AS k(account_id, stripe)
		  ON b.account_id = k.account_id AND b.stripe = k.stripe
		ORDER BY b.account_id, b.stripe
		FOR UPDATE OF b`, accts, stripes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[balKey]balRow, len(keys))
	for rows.Next() {
		var k balKey
		var stripe int16
		var b balRow
		if err := rows.Scan(&k.account, &stripe, &b.balance, &b.pending, &b.floor, &b.frozen); err != nil {
			return nil, err
		}
		k.stripe = int(stripe)
		out[k] = b
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			return nil, &ledger.NotFoundError{Object: "account", ID: k.account}
		}
	}
	return out, nil
}

// stripeFor spreads an account's postings over its stripes deterministically.
func stripeFor(entryID, account uuid.UUID, stripes int) int {
	if stripes <= 1 {
		return 0
	}
	h := fnv.New32a()
	h.Write(entryID[:])
	h.Write(account[:])
	return int(h.Sum32() % uint32(stripes))
}

// leg is a posting resolved to a currency and stripe, ready to write.
type leg struct {
	account  uuid.UUID
	stripe   int
	currency string
	amount   int64
}

func compareLeg(a, b leg) int {
	if c := bytes.Compare(a.account[:], b.account[:]); c != 0 {
		return c
	}
	return a.stripe - b.stripe
}

// checkFunds verifies, under the balance locks, that applying deltas keeps
// every row within its floor and int64 range. allowFrozenDebit is true for
// reversals and compliance releases (mirrors the schema trigger).
func checkFunds(legs []leg, bals map[balKey]balRow, pendingRelease map[balKey]int64, allowFrozenDebit bool) error {
	for _, l := range legs {
		k := balKey{l.account, l.stripe}
		b := bals[k]
		if l.amount < 0 && b.frozen && !allowFrozenDebit {
			return &ledger.FrozenError{AccountID: l.account}
		}
		newBalance, err := money.Add(b.balance, l.amount)
		if err != nil {
			return fmt.Errorf("%w: balance of %s", ledger.ErrOverflow, l.account)
		}
		if b.floor == nil || l.amount > 0 {
			continue
		}
		pending := b.pending - pendingRelease[k]
		if newBalance-pending < *b.floor {
			return &ledger.InsufficientFundsError{AccountID: l.account, Available: b.balance - pending,
				Required: -l.amount, Floor: *b.floor}
		}
	}
	return nil
}

// checkBalanced enforces per-currency zero sums before the database does.
func checkBalanced(legs []leg) error {
	sums := map[string]int64{}
	for _, l := range legs {
		s, err := money.Add(sums[l.currency], l.amount)
		if err != nil {
			return fmt.Errorf("%w: %s legs", ledger.ErrOverflow, l.currency)
		}
		sums[l.currency] = s
	}
	currencies := make([]string, 0, len(sums))
	for c := range sums {
		currencies = append(currencies, c)
	}
	sort.Strings(currencies)
	for _, c := range currencies {
		if sums[c] != 0 {
			return fmt.Errorf("%w: %s legs sum to %d", ledger.ErrUnbalanced, c, sums[c])
		}
	}
	return nil
}

// entryHeader is the non-posting part of an entry being written.
type entryHeader struct {
	id       uuid.UUID
	key      string
	kind     string
	refType  string
	refID    string
	memo     string
	reverses *uuid.UUID
	holdID   *uuid.UUID
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func sortLegs(legs []leg) {
	sort.Slice(legs, func(i, j int) bool { return compareLeg(legs[i], legs[j]) < 0 })
}

// writeEntry inserts the entry header and its postings. Balance rows must be
// locked already; the schema triggers apply the deltas.
func writeEntry(ctx context.Context, tx pgx.Tx, h entryHeader, legs []leg) (ledger.Entry, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO journal_entries
			(entry_id, idempotency_key, kind, ref_type, ref_id, memo, reverses, hold_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		h.id, h.key, h.kind, nullable(h.refType), nullable(h.refID), nullable(h.memo), h.reverses, h.holdID,
	); err != nil {
		return ledger.Entry{}, err
	}
	en, err := writePostings(ctx, tx, h.id, append([]leg(nil), legs...))
	if err != nil {
		return ledger.Entry{}, err
	}
	en.IdempotencyKey, en.Kind, en.RefType, en.RefID, en.Memo = h.key, h.kind, h.refType, h.refID, h.memo
	en.Reverses, en.HoldID = h.reverses, h.holdID
	return en, nil
}

// entryEvent is the payload of ledger.entry.posted.
type entryEvent struct {
	ledger.Entry
}

func entryKey(en ledger.Entry) string {
	if en.RefType != "" {
		return en.RefType + ":" + en.RefID
	}
	return "entry:" + en.ID.String()
}

func emitEntry(ctx context.Context, tx pgx.Tx, en ledger.Entry) error {
	_, err := outbox.Write(ctx, tx, outbox.Event{
		Topic: ledger.TopicEntryPosted, Key: entryKey(en), Subject: en.ID.String(), Data: entryEvent{en},
	})
	return err
}

func dbNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now)
	return now, err
}
