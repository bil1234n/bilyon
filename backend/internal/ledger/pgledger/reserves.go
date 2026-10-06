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

const reserveColumns = `reserve_id, funding_account_id, currency, purpose, coalesce(ref_type, ''), coalesce(ref_id, ''),
	state, opened_entry_id, closed_entry_id, expires_at, created_at, closed_at`

func scanReserve(row pgx.Row) (ledger.Reserve, error) {
	var r ledger.Reserve
	if err := row.Scan(&r.ID, &r.FundingAccountID, &r.Currency, &r.Purpose, &r.RefType, &r.RefID, &r.State,
		&r.OpenedEntryID, &r.ClosedEntryID, &r.ExpiresAt, &r.CreatedAt, &r.ClosedAt); err != nil {
		return ledger.Reserve{}, err
	}
	r.CreatedAt = r.CreatedAt.UTC()
	r.ExpiresAt, r.ClosedAt = utcPtr(r.ExpiresAt), utcPtr(r.ClosedAt)
	return r, nil
}

func emitReserve(ctx context.Context, tx pgx.Tx, topic string, r ledger.Reserve) error {
	key := "reserve:" + r.ID.String()
	if r.RefType != "" {
		key = r.RefType + ":" + r.RefID
	}
	_, err := outbox.Write(ctx, tx, outbox.Event{Topic: topic, Key: key, Subject: r.ID.String(), Data: r})
	return err
}

// OpenReserve implements ledger.Ledger: it creates the escrow account, moves
// the amount into it and records the reserve, atomically.
func (e *Engine) OpenReserve(ctx context.Context, cmd ledger.OpenReserve) (ledger.OpenReserveResult, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.OpenReserveResult{}, err
	}
	if cmd.ReserveID == uuid.Nil {
		cmd.ReserveID = uuid.NewSHA1(reserveNamespace, []byte(cmd.IdempotencyKey))
	}
	return idempotent(ctx, e, ledger.ScopeOpenReserve, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopeOpenReserve, cmd),
		func(tx pgx.Tx) (ledger.OpenReserveResult, error) {
			accts, err := loadAccounts(ctx, tx, []uuid.UUID{cmd.FundingAccountID})
			if err != nil {
				return ledger.OpenReserveResult{}, err
			}
			funding := accts[cmd.FundingAccountID]
			if cmd.ExpiresAt != nil {
				now, err := dbNow(ctx, tx)
				if err != nil {
					return ledger.OpenReserveResult{}, err
				}
				if !cmd.ExpiresAt.After(now) {
					return ledger.OpenReserveResult{}, &ledger.ValidationError{Field: "expires_at", Reason: "must be in the future"}
				}
			}
			var owner *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT owner_id FROM accounts WHERE account_id = $1`, funding.id).Scan(&owner); err != nil {
				return ledger.OpenReserveResult{}, err
			}
			if _, err := insertAccount(ctx, tx, ledger.CreateAccount{
				IdempotencyKey: cmd.IdempotencyKey, AccountID: cmd.ReserveID, OwnerID: owner,
				Kind: cmd.Kind, Currency: funding.currency, Floor: zeroFloor(), Stripes: 1,
				Label: cmd.Purpose,
			}); err != nil {
				return ledger.OpenReserveResult{}, err
			}
			entryID := ledger.NewID()
			legs := []leg{
				{account: funding.id, stripe: stripeFor(entryID, funding.id, funding.stripes), currency: funding.currency, amount: -cmd.Amount},
				{account: cmd.ReserveID, stripe: 0, currency: funding.currency, amount: cmd.Amount},
			}
			bals, err := lockBalances(ctx, tx, []balKey{{legs[0].account, legs[0].stripe}, {legs[1].account, 0}})
			if err != nil {
				return ledger.OpenReserveResult{}, err
			}
			if err := checkFunds(legs, bals, nil, false); err != nil {
				return ledger.OpenReserveResult{}, err
			}
			en, err := writeEntry(ctx, tx, entryHeader{
				id: entryID, key: cmd.IdempotencyKey, kind: ledger.EntryKindReserveOpen,
				refType: cmd.RefType, refID: cmd.RefID, memo: cmd.Memo,
			}, legs)
			if err != nil {
				return ledger.OpenReserveResult{}, err
			}
			r, err := scanReserve(tx.QueryRow(ctx, `INSERT INTO reserves
					(reserve_id, funding_account_id, currency, purpose, ref_type, ref_id, opened_entry_id, expires_at, idempotency_key)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+reserveColumns,
				cmd.ReserveID, funding.id, funding.currency, cmd.Purpose, nullable(cmd.RefType), nullable(cmd.RefID),
				en.ID, cmd.ExpiresAt, cmd.IdempotencyKey))
			if err != nil {
				return ledger.OpenReserveResult{}, err
			}
			if err := emitEntry(ctx, tx, en); err != nil {
				return ledger.OpenReserveResult{}, err
			}
			return ledger.OpenReserveResult{Reserve: r, Entry: en}, emitReserve(ctx, tx, ledger.TopicReserveOpened, r)
		})
}

var reserveNamespace = uuid.MustParse("0b5b2f8e-3d4a-4c8e-8f0a-7c1e2d3b4a59")

func zeroFloor() *int64 { z := int64(0); return &z }

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// ReleaseReserve implements ledger.Ledger: the remaining available balance
// returns to the funding account, the reserve closes and its account is
// frozen so no further debits can draw on it.
func (e *Engine) ReleaseReserve(ctx context.Context, cmd ledger.ReleaseReserve) (ledger.ReleaseReserveResult, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.ReleaseReserveResult{}, err
	}
	return idempotent(ctx, e, ledger.ScopeReleaseReserve, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopeReleaseReserve, cmd),
		func(tx pgx.Tx) (ledger.ReleaseReserveResult, error) {
			r, err := scanReserve(tx.QueryRow(ctx, `SELECT `+reserveColumns+` FROM reserves WHERE reserve_id = $1 FOR UPDATE`, cmd.ReserveID))
			if errors.Is(err, pgx.ErrNoRows) {
				return ledger.ReleaseReserveResult{}, &ledger.NotFoundError{Object: "reserve", ID: cmd.ReserveID}
			}
			if err != nil {
				return ledger.ReleaseReserveResult{}, err
			}
			if r.State != ledger.ReserveOpen {
				return ledger.ReleaseReserveResult{}, fmt.Errorf("%w: reserve %s", ledger.ErrReserveClosed, r.ID)
			}
			accts, err := loadAccounts(ctx, tx, []uuid.UUID{r.FundingAccountID})
			if err != nil {
				return ledger.ReleaseReserveResult{}, err
			}
			funding := accts[r.FundingAccountID]
			entryID := ledger.NewID()
			fundingKey := balKey{funding.id, stripeFor(entryID, funding.id, funding.stripes)}
			bals, err := lockBalances(ctx, tx, []balKey{{r.ID, 0}, fundingKey})
			if err != nil {
				return ledger.ReleaseReserveResult{}, err
			}
			rb := bals[balKey{r.ID, 0}]
			if rb.pending > 0 {
				return ledger.ReleaseReserveResult{}, &ledger.ValidationError{Field: "reserve_id",
					Reason: fmt.Sprintf("reserve has %d in pending holds; resolve them first", rb.pending)}
			}
			var en *ledger.Entry
			if rb.balance > 0 {
				legs := []leg{
					{account: r.ID, stripe: 0, currency: r.Currency, amount: -rb.balance},
					{account: funding.id, stripe: fundingKey.stripe, currency: r.Currency, amount: rb.balance},
				}
				if err := checkFunds(legs, bals, nil, false); err != nil {
					return ledger.ReleaseReserveResult{}, err
				}
				written, err := writeEntry(ctx, tx, entryHeader{
					id: entryID, key: cmd.IdempotencyKey, kind: ledger.EntryKindReserveRelease,
					refType: r.RefType, refID: r.RefID, memo: cmd.Memo,
				}, legs)
				if err != nil {
					return ledger.ReleaseReserveResult{}, err
				}
				if err := emitEntry(ctx, tx, written); err != nil {
					return ledger.ReleaseReserveResult{}, err
				}
				en = &written
			}
			var closedEntry *uuid.UUID
			if en != nil {
				closedEntry = &en.ID
			}
			closed, err := scanReserve(tx.QueryRow(ctx, `UPDATE reserves SET state = 'closed', closed_entry_id = $2
				WHERE reserve_id = $1 RETURNING `+reserveColumns, r.ID, closedEntry))
			if err != nil {
				return ledger.ReleaseReserveResult{}, err
			}
			if _, err := tx.Exec(ctx, `UPDATE accounts SET frozen = true WHERE account_id = $1`, r.ID); err != nil {
				return ledger.ReleaseReserveResult{}, err
			}
			return ledger.ReleaseReserveResult{Reserve: closed, Entry: en}, emitReserve(ctx, tx, ledger.TopicReserveReleased, closed)
		})
}

// Reserve implements ledger.Ledger.
func (e *Engine) Reserve(ctx context.Context, id uuid.UUID) (ledger.Reserve, error) {
	r, err := scanReserve(e.pool.QueryRow(ctx, `SELECT `+reserveColumns+` FROM reserves WHERE reserve_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ledger.Reserve{}, &ledger.NotFoundError{Object: "reserve", ID: id}
	}
	if err != nil {
		return ledger.Reserve{}, mapError(err)
	}
	return r, nil
}
