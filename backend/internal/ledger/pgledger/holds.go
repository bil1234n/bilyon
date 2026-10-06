package pgledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

const holdColumns = `hold_id, idempotency_key, account_id, currency, amount_minor, reason, state, expires_at,
	posted_minor, entry_id, coalesce(ref_type, ''), coalesce(ref_id, ''), coalesce(resolution_note, ''),
	created_at, resolved_at`

func scanHold(row pgx.Row) (ledger.Hold, error) {
	var h ledger.Hold
	if err := row.Scan(&h.ID, &h.IdempotencyKey, &h.AccountID, &h.Currency, &h.Amount, &h.Reason, &h.State,
		&h.ExpiresAt, &h.PostedAmount, &h.EntryID, &h.RefType, &h.RefID, &h.ResolutionNote,
		&h.CreatedAt, &h.ResolvedAt); err != nil {
		return ledger.Hold{}, err
	}
	h.ExpiresAt, h.CreatedAt = h.ExpiresAt.UTC(), h.CreatedAt.UTC()
	if h.ResolvedAt != nil {
		t := h.ResolvedAt.UTC()
		h.ResolvedAt = &t
	}
	return h, nil
}

func holdKey(h ledger.Hold) string {
	if h.RefType != "" {
		return h.RefType + ":" + h.RefID
	}
	return "hold:" + h.ID.String()
}

func emitHold(ctx context.Context, tx pgx.Tx, topic string, h ledger.Hold) error {
	_, err := outbox.Write(ctx, tx, outbox.Event{Topic: topic, Key: holdKey(h), Subject: h.ID.String(), Data: h})
	return err
}

// PlaceHold implements ledger.Ledger.
func (e *Engine) PlaceHold(ctx context.Context, cmd ledger.PlaceHold) (ledger.Hold, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.Hold{}, err
	}
	return idempotent(ctx, e, ledger.ScopePlaceHold, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopePlaceHold, cmd),
		func(tx pgx.Tx) (ledger.Hold, error) {
			accts, err := loadAccounts(ctx, tx, []uuid.UUID{cmd.AccountID})
			if err != nil {
				return ledger.Hold{}, err
			}
			a := accts[cmd.AccountID]
			if a.stripes != 1 {
				return ledger.Hold{}, &ledger.ValidationError{Field: "account_id", Reason: "holds need a single-stripe account"}
			}
			now, err := dbNow(ctx, tx)
			if err != nil {
				return ledger.Hold{}, err
			}
			ttl := cmd.ExpiresAt.Sub(now)
			if ttl < ledger.MinHoldTTL || ttl > ledger.MaxHoldTTL {
				return ledger.Hold{}, &ledger.ValidationError{Field: "expires_at",
					Reason: fmt.Sprintf("must be %s..%s from now", ledger.MinHoldTTL, ledger.MaxHoldTTL)}
			}
			bals, err := lockBalances(ctx, tx, []balKey{{a.id, 0}})
			if err != nil {
				return ledger.Hold{}, err
			}
			b := bals[balKey{a.id, 0}]
			if b.frozen {
				return ledger.Hold{}, &ledger.FrozenError{AccountID: a.id}
			}
			if b.floor != nil && b.available()-cmd.Amount < *b.floor {
				return ledger.Hold{}, &ledger.InsufficientFundsError{AccountID: a.id, Available: b.available(),
					Required: cmd.Amount, Floor: *b.floor}
			}
			h, err := scanHold(tx.QueryRow(ctx, `INSERT INTO holds
					(hold_id, idempotency_key, account_id, currency, amount_minor, reason, expires_at, ref_type, ref_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+holdColumns,
				ledger.NewID(), cmd.IdempotencyKey, a.id, a.currency, cmd.Amount, cmd.Reason, cmd.ExpiresAt,
				nullable(cmd.RefType), nullable(cmd.RefID)))
			if err != nil {
				return ledger.Hold{}, err
			}
			return h, emitHold(ctx, tx, ledger.TopicHoldPlaced, h)
		})
}

// lockHold locks a hold row and reports whether its expiry has passed (by
// the database clock).
func lockHold(ctx context.Context, tx pgx.Tx, id uuid.UUID) (ledger.Hold, bool, error) {
	var expired bool
	var h ledger.Hold
	err := tx.QueryRow(ctx, `SELECT `+holdColumns+`, expires_at <= clock_timestamp() FROM holds
		WHERE hold_id = $1 FOR UPDATE`, id).Scan(&h.ID, &h.IdempotencyKey, &h.AccountID, &h.Currency, &h.Amount,
		&h.Reason, &h.State, &h.ExpiresAt, &h.PostedAmount, &h.EntryID, &h.RefType, &h.RefID, &h.ResolutionNote,
		&h.CreatedAt, &h.ResolvedAt, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return ledger.Hold{}, false, &ledger.NotFoundError{Object: "hold", ID: id}
	}
	return h, expired, err
}

// PostHold implements ledger.Ledger.
func (e *Engine) PostHold(ctx context.Context, cmd ledger.PostHold) (ledger.PostHoldResult, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.PostHoldResult{}, err
	}
	return idempotent(ctx, e, ledger.ScopePostHold, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopePostHold, cmd),
		func(tx pgx.Tx) (ledger.PostHoldResult, error) {
			h, expired, err := lockHold(ctx, tx, cmd.HoldID)
			if err != nil {
				return ledger.PostHoldResult{}, err
			}
			if h.State != ledger.HoldPending {
				return ledger.PostHoldResult{}, fmt.Errorf("%w: hold %s is %s", ledger.ErrHoldNotPending, h.ID, h.State)
			}
			if expired {
				return ledger.PostHoldResult{}, fmt.Errorf("%w: hold %s expired at %s", ledger.ErrHoldExpired, h.ID,
					h.ExpiresAt.Format(time.RFC3339Nano))
			}
			var total int64
			ids := make([]uuid.UUID, 0, len(cmd.Credits))
			for _, c := range cmd.Credits {
				if c.AccountID == h.AccountID {
					return ledger.PostHoldResult{}, &ledger.ValidationError{Field: "credits", Reason: "cannot credit the held account"}
				}
				total += c.Amount // overflow already excluded by Normalize
				ids = append(ids, c.AccountID)
			}
			if total > h.Amount {
				return ledger.PostHoldResult{}, &ledger.ValidationError{Field: "credits",
					Reason: fmt.Sprintf("total %d exceeds held amount %d", total, h.Amount)}
			}
			accts, err := loadAccounts(ctx, tx, ids)
			if err != nil {
				return ledger.PostHoldResult{}, err
			}
			entryID := ledger.NewID()
			legs := []leg{{account: h.AccountID, stripe: 0, currency: h.Currency, amount: -total}}
			keys := []balKey{{h.AccountID, 0}}
			for _, c := range cmd.Credits {
				a := accts[c.AccountID]
				if a.currency != h.Currency {
					return ledger.PostHoldResult{}, fmt.Errorf("%w: hold is %s, account %s is %s",
						ledger.ErrCurrencyMismatch, h.Currency, a.id, a.currency)
				}
				l := leg{account: a.id, stripe: stripeFor(entryID, a.id, a.stripes), currency: a.currency, amount: c.Amount}
				legs = append(legs, l)
				keys = append(keys, balKey{l.account, l.stripe})
			}
			bals, err := lockBalances(ctx, tx, keys)
			if err != nil {
				return ledger.PostHoldResult{}, err
			}
			release := map[balKey]int64{{h.AccountID, 0}: h.Amount}
			if err := checkFunds(legs, bals, release, false); err != nil {
				return ledger.PostHoldResult{}, err
			}
			holdID := h.ID
			// The entry must exist before the hold can reference it; the hold
			// update releases the reservation, then the postings move money.
			if _, err := tx.Exec(ctx, `INSERT INTO journal_entries
					(entry_id, idempotency_key, kind, ref_type, ref_id, memo, hold_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				entryID, cmd.IdempotencyKey, cmd.Kind, nullable(h.RefType), nullable(h.RefID), nullable(cmd.Memo), holdID); err != nil {
				return ledger.PostHoldResult{}, err
			}
			posted, err := scanHold(tx.QueryRow(ctx, `UPDATE holds SET state = 'posted', posted_minor = $2, entry_id = $3
				WHERE hold_id = $1 RETURNING `+holdColumns, h.ID, total, entryID))
			if err != nil {
				return ledger.PostHoldResult{}, err
			}
			en, err := writePostings(ctx, tx, entryID, legs)
			if err != nil {
				return ledger.PostHoldResult{}, err
			}
			en.IdempotencyKey, en.Kind, en.RefType, en.RefID, en.Memo, en.HoldID = cmd.IdempotencyKey, cmd.Kind, h.RefType, h.RefID, cmd.Memo, &holdID
			if err := emitHold(ctx, tx, ledger.TopicHoldPosted, posted); err != nil {
				return ledger.PostHoldResult{}, err
			}
			return ledger.PostHoldResult{Hold: posted, Entry: en}, emitEntry(ctx, tx, en)
		})
}

// writePostings inserts postings for an already-inserted entry header and
// returns the entry with its creation time.
func writePostings(ctx context.Context, tx pgx.Tx, entryID uuid.UUID, legs []leg) (ledger.Entry, error) {
	sortLegs(legs)
	seqs := make([]int16, len(legs))
	accts := make([]uuid.UUID, len(legs))
	stripes := make([]int16, len(legs))
	currencies := make([]string, len(legs))
	amounts := make([]int64, len(legs))
	records := make([]ledger.PostingRecord, len(legs))
	for i, l := range legs {
		seqs[i], accts[i], stripes[i], currencies[i], amounts[i] = int16(i), l.account, int16(l.stripe), l.currency, l.amount
		records[i] = ledger.PostingRecord{Seq: i, AccountID: l.account, Stripe: l.stripe, Currency: l.currency, Amount: l.amount}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO postings (entry_id, seq, account_id, stripe, currency, amount_minor)
		SELECT $1, t.seq, t.account_id, t.stripe, t.currency, t.amount
		  FROM unnest($2::smallint[], $3::uuid[], $4::smallint[], $5::text[], $6::bigint[])
		       AS t(seq, account_id, stripe, currency, amount)
		 ORDER BY t.seq`, entryID, seqs, accts, stripes, currencies, amounts); err != nil {
		return ledger.Entry{}, err
	}
	var createdAt time.Time
	if err := tx.QueryRow(ctx, `SELECT created_at FROM journal_entries WHERE entry_id = $1`, entryID).Scan(&createdAt); err != nil {
		return ledger.Entry{}, err
	}
	return ledger.Entry{ID: entryID, CreatedAt: createdAt.UTC(), Postings: records}, nil
}

// VoidHold implements ledger.Ledger.
func (e *Engine) VoidHold(ctx context.Context, cmd ledger.VoidHold) (ledger.Hold, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.Hold{}, err
	}
	return idempotent(ctx, e, ledger.ScopeVoidHold, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopeVoidHold, cmd),
		func(tx pgx.Tx) (ledger.Hold, error) {
			h, _, err := lockHold(ctx, tx, cmd.HoldID)
			if err != nil {
				return ledger.Hold{}, err
			}
			if h.State != ledger.HoldPending {
				return ledger.Hold{}, fmt.Errorf("%w: hold %s is %s", ledger.ErrHoldNotPending, h.ID, h.State)
			}
			if _, err := lockBalances(ctx, tx, []balKey{{h.AccountID, 0}}); err != nil {
				return ledger.Hold{}, err
			}
			voided, err := scanHold(tx.QueryRow(ctx, `UPDATE holds SET state = 'voided', resolution_note = $2
				WHERE hold_id = $1 RETURNING `+holdColumns, h.ID, nullable(cmd.Reason)))
			if err != nil {
				return ledger.Hold{}, err
			}
			return voided, emitHold(ctx, tx, ledger.TopicHoldVoided, voided)
		})
}

// Hold implements ledger.Ledger.
func (e *Engine) Hold(ctx context.Context, id uuid.UUID) (ledger.Hold, error) {
	h, err := scanHold(e.pool.QueryRow(ctx, `SELECT `+holdColumns+` FROM holds WHERE hold_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ledger.Hold{}, &ledger.NotFoundError{Object: "hold", ID: id}
	}
	if err != nil {
		return ledger.Hold{}, mapError(err)
	}
	return h, nil
}

// ExpireHolds implements ledger.Ledger. Rows being posted or voided
// concurrently are skipped (SKIP LOCKED) and picked up next round if still
// pending.
func (e *Engine) ExpireHolds(ctx context.Context, limit int) ([]ledger.Hold, error) {
	if limit <= 0 || limit > 10_000 {
		return nil, &ledger.ValidationError{Field: "limit", Reason: "must be 1..10000"}
	}
	var expired []ledger.Hold
	err := e.inTx(ctx, func(tx pgx.Tx) error {
		expired = expired[:0]
		rows, err := tx.Query(ctx, `SELECT hold_id, account_id FROM holds
			WHERE state = 'pending' AND expires_at <= clock_timestamp()
			ORDER BY expires_at, hold_id LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		var keys []balKey
		seen := map[uuid.UUID]bool{}
		for rows.Next() {
			var id, acct uuid.UUID
			if err := rows.Scan(&id, &acct); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
			if !seen[acct] {
				seen[acct] = true
				keys = append(keys, balKey{acct, 0})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil || len(ids) == 0 {
			return err
		}
		if _, err := lockBalances(ctx, tx, keys); err != nil {
			return err
		}
		updated, err := tx.Query(ctx, `UPDATE holds SET state = 'expired' WHERE hold_id = ANY($1) RETURNING `+holdColumns, ids)
		if err != nil {
			return err
		}
		for updated.Next() {
			h, err := scanHold(updated)
			if err != nil {
				updated.Close()
				return err
			}
			expired = append(expired, h)
		}
		updated.Close()
		if err := updated.Err(); err != nil {
			return err
		}
		for _, h := range expired {
			if err := emitHold(ctx, tx, ledger.TopicHoldExpired, h); err != nil {
				return err
			}
		}
		return nil
	})
	return expired, err
}
