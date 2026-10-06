package pgledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/money"
)

// Transfer implements ledger.Ledger.
func (e *Engine) Transfer(ctx context.Context, cmd ledger.Transfer) (ledger.Entry, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.Entry{}, err
	}
	return idempotent(ctx, e, ledger.ScopeTransfer, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopeTransfer, cmd),
		func(tx pgx.Tx) (ledger.Entry, error) {
			ids := make([]uuid.UUID, len(cmd.Postings))
			for i, p := range cmd.Postings {
				ids[i] = p.AccountID
			}
			accts, err := loadAccounts(ctx, tx, ids)
			if err != nil {
				return ledger.Entry{}, err
			}
			entryID := ledger.NewID()
			legs := make([]leg, len(cmd.Postings))
			keys := make([]balKey, len(cmd.Postings))
			for i, p := range cmd.Postings {
				a := accts[p.AccountID]
				legs[i] = leg{account: a.id, stripe: stripeFor(entryID, a.id, a.stripes), currency: a.currency, amount: p.Amount}
				keys[i] = balKey{legs[i].account, legs[i].stripe}
			}
			if err := checkBalanced(legs); err != nil {
				return ledger.Entry{}, err
			}
			bals, err := lockBalances(ctx, tx, keys)
			if err != nil {
				return ledger.Entry{}, err
			}
			if err := checkFunds(legs, bals, nil, cmd.Kind == "compliance.release"); err != nil {
				return ledger.Entry{}, err
			}
			en, err := writeEntry(ctx, tx, entryHeader{
				id: entryID, key: cmd.IdempotencyKey, kind: cmd.Kind, refType: cmd.RefType, refID: cmd.RefID, memo: cmd.Memo,
			}, legs)
			if err != nil {
				return ledger.Entry{}, err
			}
			return en, emitEntry(ctx, tx, en)
		})
}

// Reverse implements ledger.Ledger.
func (e *Engine) Reverse(ctx context.Context, cmd ledger.Reverse) (ledger.Entry, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.Entry{}, err
	}
	return idempotent(ctx, e, ledger.ScopeReverse, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopeReverse, cmd),
		func(tx pgx.Tx) (ledger.Entry, error) {
			orig, err := loadEntry(ctx, tx, cmd.EntryID)
			if err != nil {
				return ledger.Entry{}, err
			}
			if orig.Kind == ledger.EntryKindReversal {
				return ledger.Entry{}, fmt.Errorf("%w: %s is itself a reversal", ledger.ErrNotReversible, orig.ID)
			}
			var existing uuid.UUID
			err = tx.QueryRow(ctx, `SELECT entry_id FROM journal_entries WHERE reverses = $1`, orig.ID).Scan(&existing)
			if err == nil {
				return ledger.Entry{}, fmt.Errorf("%w: %s by %s", ledger.ErrAlreadyReversed, orig.ID, existing)
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return ledger.Entry{}, err
			}
			legs := make([]leg, len(orig.Postings))
			keys := make([]balKey, len(orig.Postings))
			for i, p := range orig.Postings {
				neg, err := money.Neg(p.Amount)
				if err != nil {
					return ledger.Entry{}, fmt.Errorf("%w: cannot negate %d", ledger.ErrOverflow, p.Amount)
				}
				legs[i] = leg{account: p.AccountID, stripe: p.Stripe, currency: p.Currency, amount: neg}
				keys[i] = balKey{p.AccountID, p.Stripe}
			}
			bals, err := lockBalances(ctx, tx, keys)
			if err != nil {
				return ledger.Entry{}, err
			}
			if err := checkFunds(legs, bals, nil, true); err != nil {
				return ledger.Entry{}, err
			}
			id := orig.ID
			en, err := writeEntry(ctx, tx, entryHeader{
				id: ledger.NewID(), key: cmd.IdempotencyKey, kind: ledger.EntryKindReversal,
				refType: orig.RefType, refID: orig.RefID, memo: cmd.Memo, reverses: &id,
			}, legs)
			if err != nil {
				return ledger.Entry{}, err
			}
			return en, emitEntry(ctx, tx, en)
		})
}

// Entry implements ledger.Ledger.
func (e *Engine) Entry(ctx context.Context, id uuid.UUID) (ledger.Entry, error) {
	var en ledger.Entry
	err := e.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		en, err = loadEntry(ctx, tx, id)
		return err
	})
	return en, err
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const entryColumns = `entry_id, idempotency_key, kind, coalesce(ref_type, ''), coalesce(ref_id, ''),
	coalesce(memo, ''), reverses, hold_id, created_at`

func scanEntryHeader(row pgx.Row) (ledger.Entry, error) {
	var en ledger.Entry
	if err := row.Scan(&en.ID, &en.IdempotencyKey, &en.Kind, &en.RefType, &en.RefID, &en.Memo,
		&en.Reverses, &en.HoldID, &en.CreatedAt); err != nil {
		return ledger.Entry{}, err
	}
	en.CreatedAt = en.CreatedAt.UTC()
	return en, nil
}

func loadEntry(ctx context.Context, q querier, id uuid.UUID) (ledger.Entry, error) {
	en, err := scanEntryHeader(q.QueryRow(ctx, `SELECT `+entryColumns+` FROM journal_entries WHERE entry_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ledger.Entry{}, &ledger.NotFoundError{Object: "entry", ID: id}
	}
	if err != nil {
		return ledger.Entry{}, err
	}
	postings, err := loadPostings(ctx, q, []uuid.UUID{id})
	if err != nil {
		return ledger.Entry{}, err
	}
	en.Postings = postings[id]
	return en, nil
}

func loadPostings(ctx context.Context, q querier, entryIDs []uuid.UUID) (map[uuid.UUID][]ledger.PostingRecord, error) {
	rows, err := q.Query(ctx, `SELECT entry_id, seq, account_id, stripe, currency, amount_minor
		FROM postings WHERE entry_id = ANY($1) ORDER BY entry_id, seq`, entryIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[uuid.UUID][]ledger.PostingRecord, len(entryIDs))
	for rows.Next() {
		var id uuid.UUID
		var p ledger.PostingRecord
		var seq, stripe int16
		if err := rows.Scan(&id, &seq, &p.AccountID, &stripe, &p.Currency, &p.Amount); err != nil {
			return nil, err
		}
		p.Seq, p.Stripe = int(seq), int(stripe)
		out[id] = append(out[id], p)
	}
	return out, rows.Err()
}

// History implements ledger.Ledger: entries touching the account, newest
// first, paginated by entry id (UUIDv7, so id order is time order).
func (e *Engine) History(ctx context.Context, q ledger.HistoryQuery) (ledger.HistoryPage, error) {
	q, err := q.Normalize()
	if err != nil {
		return ledger.HistoryPage{}, err
	}
	var page ledger.HistoryPage
	err = e.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := loadAccounts(ctx, tx, []uuid.UUID{q.AccountID}); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+entryColumns+` FROM journal_entries
			WHERE entry_id IN (
				SELECT entry_id FROM postings
				 WHERE account_id = $1 AND ($2::uuid IS NULL OR entry_id < $2)
				 ORDER BY entry_id DESC LIMIT $3)
			ORDER BY entry_id DESC`, q.AccountID, q.Before, q.Limit+1)
		if err != nil {
			return err
		}
		var entries []ledger.Entry
		for rows.Next() {
			en, err := scanEntryHeader(rows)
			if err != nil {
				rows.Close()
				return err
			}
			entries = append(entries, en)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(entries) > q.Limit {
			entries = entries[:q.Limit]
			next := entries[len(entries)-1].ID
			page.Next = &next
		}
		ids := make([]uuid.UUID, len(entries))
		for i := range entries {
			ids[i] = entries[i].ID
		}
		postings, err := loadPostings(ctx, tx, ids)
		if err != nil {
			return err
		}
		for i := range entries {
			entries[i].Postings = postings[entries[i].ID]
		}
		page.Entries = entries
		return nil
	})
	return page, err
}

// Now returns the database clock, which is the clock every expiry uses.
func (e *Engine) Now(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := e.pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now)
	return now.UTC(), err
}
