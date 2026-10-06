package fx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

type store struct {
	pool *pgxpool.Pool
}

// storedQuote is a quote with its execution state.
type storedQuote struct {
	Quote
	Reserved           []Leg
	HoldID             uuid.UUID
	SourceAccount      uuid.UUID
	DestinationAccount uuid.UUID
	MarketOut          int64
	PnL                int64
	EntryIDs           []uuid.UUID
	ExecutedAt         *time.Time
	BookedAt           *time.Time
	Failure            string
	// Executed is the depth this process consumed at execution; it is not
	// stored (a restarted engine starts from fresh counters).
	Executed []Leg
}

func (q *storedQuote) execution() Execution {
	x := Execution{QuoteID: q.ID, AmountIn: q.AmountIn, AmountOut: q.AmountOut, MarketOut: q.MarketOut, PnL: q.PnL,
		EntryIDs: q.EntryIDs, State: q.State, BookedAt: q.BookedAt, Failure: q.Failure}
	if q.ExecutedAt != nil {
		x.ExecutedAt = *q.ExecutedAt
	}
	return x
}

const quoteColumns = `quote_id, user_id, from_ccy, to_ccy, amount_in, amount_out, exec_out, mid_rate, mid_out,
	exec_cost_bps, buffer_bps, margin_bps, allocations, reserved, key_id, sig, state, created_at, expires_at,
	hold_id, source_account, destination_account, market_out, pnl, entry_ids, executed_at, booked_at, failure`

func scanQuote(row pgx.Row) (*storedQuote, error) {
	var q storedQuote
	var allocations, reserved []byte
	var hold, source, dest *uuid.UUID
	var marketOut, pnl *int64
	var failure *string
	err := row.Scan(&q.ID, &q.UserID, &q.From, &q.To, &q.AmountIn, &q.AmountOut, &q.ExecOut, &q.MidRate, &q.MidOut,
		&q.ExecCostBps, &q.BufferBps, &q.MarginBps, &allocations, &reserved, &q.KeyID, &q.Signature, &q.State,
		&q.CreatedAt, &q.ExpiresAt, &hold, &source, &dest, &marketOut, &pnl, &q.EntryIDs, &q.ExecutedAt, &q.BookedAt, &failure)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownQuote
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(allocations, &q.Allocations); err != nil {
		return nil, fmt.Errorf("fx: quote %s allocations: %w", q.ID, err)
	}
	if err := json.Unmarshal(reserved, &q.Reserved); err != nil {
		return nil, fmt.Errorf("fx: quote %s reservation: %w", q.ID, err)
	}
	for _, p := range []struct {
		src *uuid.UUID
		dst *uuid.UUID
	}{{hold, &q.HoldID}, {source, &q.SourceAccount}, {dest, &q.DestinationAccount}} {
		if p.src != nil {
			*p.dst = *p.src
		}
	}
	if marketOut != nil {
		q.MarketOut = *marketOut
	}
	if pnl != nil {
		q.PnL = *pnl
	}
	if failure != nil {
		q.Failure = *failure
	}
	q.CreatedAt, q.ExpiresAt = q.CreatedAt.UTC(), q.ExpiresAt.UTC()
	q.FeeBps = (q.MidOut - float64(q.AmountOut)) / q.MidOut * 1e4
	return &q, nil
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func (s *store) insert(ctx context.Context, q *Quote, reserved []Leg) error {
	allocations, err := json.Marshal(q.Allocations)
	if err != nil {
		return err
	}
	if reserved == nil {
		reserved = []Leg{}
	}
	res, err := json.Marshal(reserved)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO fx_quotes (quote_id, user_id, from_ccy, to_ccy, amount_in, amount_out, exec_out,
			mid_rate, mid_out, exec_cost_bps, buffer_bps, margin_bps, allocations, reserved, key_id, sig, state, created_at,
			expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		q.ID, q.UserID, q.From, q.To, q.AmountIn, q.AmountOut, q.ExecOut, q.MidRate, q.MidOut, q.ExecCostBps, q.BufferBps,
		q.MarginBps, allocations, res, q.KeyID, q.Signature, q.State, q.CreatedAt, q.ExpiresAt)
	return err
}

// lock begins a transaction holding the quote's row.
func (s *store) lock(ctx context.Context, id uuid.UUID) (pgx.Tx, *storedQuote, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	q, err := scanQuote(tx.QueryRow(ctx, `SELECT `+quoteColumns+` FROM fx_quotes WHERE quote_id = $1 FOR UPDATE`, id))
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, err
	}
	return tx, q, nil
}

func (s *store) get(ctx context.Context, id uuid.UUID) (*storedQuote, error) {
	return scanQuote(s.pool.QueryRow(ctx, `SELECT `+quoteColumns+` FROM fx_quotes WHERE quote_id = $1`, id))
}

func (s *store) setState(ctx context.Context, tx pgx.Tx, id uuid.UUID, state, failure string) error {
	var f *string
	if failure != "" {
		f = &failure
	}
	_, err := tx.Exec(ctx, `UPDATE fx_quotes SET state = $2, failure = coalesce($3, failure) WHERE quote_id = $1`, id, state, f)
	return err
}

func (s *store) markExecuting(ctx context.Context, tx pgx.Tx, q *storedQuote) error {
	tag, err := tx.Exec(ctx, `UPDATE fx_quotes SET state = 'executing', hold_id = $2, source_account = $3,
			destination_account = $4, market_out = $5, pnl = $6, executed_at = $7
		WHERE quote_id = $1 AND state = 'open'`,
		q.ID, nullUUID(q.HoldID), nullUUID(q.SourceAccount), q.DestinationAccount, q.MarketOut, q.PnL, q.ExecutedAt)
	if err == nil && tag.RowsAffected() != 1 {
		err = fmt.Errorf("fx: quote %s left the open state concurrently", q.ID)
	}
	return err
}

func (s *store) emit(ctx context.Context, tx pgx.Tx, topic string, q *storedQuote, extra map[string]any) error {
	data := map[string]any{"quote_id": q.ID, "user_id": q.UserID, "from": q.From, "to": q.To,
		"amount_in": q.AmountIn, "amount_out": q.AmountOut}
	for k, v := range extra {
		data[k] = v
	}
	_, err := outbox.Write(ctx, tx, outbox.Event{Source: EventSource, Topic: topic, Key: "quote:" + q.ID.String(),
		Subject: q.ID.String(), Data: data})
	return err
}

// markBooked records the ledger entries of an executing quote.
func (s *store) markBooked(ctx context.Context, q *storedQuote, entries []uuid.UUID, at time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE fx_quotes SET state = 'booked', entry_ids = $2, booked_at = $3
			WHERE quote_id = $1 AND state = 'executing'`, q.ID, entries, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return nil // a concurrent resume booked it first, with the same idempotent entries
		}
		return s.emit(ctx, tx, TopicQuoteBooked, q, map[string]any{"market_out": q.MarketOut, "pnl": q.PnL,
			"entry_ids": entries, "destination_account": q.DestinationAccount})
	})
}

// markFailed ends an executing quote whose booking was refused.
func (s *store) markFailed(ctx context.Context, q *storedQuote, reason string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE fx_quotes SET state = 'failed', failure = $2
			WHERE quote_id = $1 AND state = 'executing'`, q.ID, reason)
		if err != nil || tag.RowsAffected() != 1 {
			return err
		}
		return s.emit(ctx, tx, TopicQuoteFailed, q, map[string]any{"reason": reason})
	})
}

// expire closes open quotes whose expiry passed and returns their ids.
func (s *store) expire(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `UPDATE fx_quotes SET state = 'expired'
		WHERE state = 'open' AND expires_at < $1 RETURNING quote_id`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// recoverable returns the reservations of open quotes and the executing
// quotes.
func (s *store) recoverable(ctx context.Context) (map[uuid.UUID][]Leg, []uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT quote_id, state, reserved FROM fx_quotes
		WHERE state IN ('open', 'executing') ORDER BY created_at`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	open := map[uuid.UUID][]Leg{}
	var executing []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var state string
		var raw []byte
		if err := rows.Scan(&id, &state, &raw); err != nil {
			return nil, nil, err
		}
		if state == StateExecuting {
			executing = append(executing, id)
			continue
		}
		var legs []Leg
		if err := json.Unmarshal(raw, &legs); err != nil {
			return nil, nil, fmt.Errorf("fx: quote %s reservation: %w", id, err)
		}
		open[id] = legs
	}
	return open, executing, rows.Err()
}

// activity counts a user's quotes and trades since a time (sniping control).
func (s *store) activity(ctx context.Context, user uuid.UUID, since time.Time) (quotes, trades int64, err error) {
	err = s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE state IN ('executing', 'booked'))
		FROM fx_quotes WHERE user_id = $1 AND created_at >= $2`, user, since).Scan(&quotes, &trades)
	return quotes, trades, err
}

// Stale lists executing quotes whose booking has not completed for longer
// than age (the recovery sweeper resumes them).
func (s *store) stale(ctx context.Context, before time.Time) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT quote_id FROM fx_quotes WHERE state = 'executing' AND executed_at < $1
		ORDER BY executed_at LIMIT 100`, before)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}
