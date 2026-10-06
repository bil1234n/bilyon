package pgledger

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

const accountColumns = `account_id, owner_id, kind, currency, floor_minor, stripes, frozen, coalesce(label, ''), created_at`

func scanAccount(row pgx.Row) (ledger.Account, error) {
	var a ledger.Account
	var stripes int16
	if err := row.Scan(&a.ID, &a.OwnerID, &a.Kind, &a.Currency, &a.Floor, &stripes, &a.Frozen, &a.Label, &a.CreatedAt); err != nil {
		return ledger.Account{}, err
	}
	a.Stripes = int(stripes)
	a.CreatedAt = a.CreatedAt.UTC()
	return a, nil
}

// CreateAccount implements ledger.Ledger.
func (e *Engine) CreateAccount(ctx context.Context, cmd ledger.CreateAccount) (ledger.Account, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.Account{}, err
	}
	if cmd.AccountID == uuid.Nil {
		// Derive the id from the key so a replay after a lost response, or a
		// retry racing the original, refers to the same account.
		cmd.AccountID = uuid.NewSHA1(accountNamespace, []byte(cmd.IdempotencyKey))
	}
	return idempotent(ctx, e, ledger.ScopeCreateAccount, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopeCreateAccount, cmd),
		func(tx pgx.Tx) (ledger.Account, error) {
			return insertAccount(ctx, tx, cmd)
		})
}

// accountNamespace is the UUIDv5 namespace for key-derived account ids.
var accountNamespace = uuid.MustParse("6d3c1a52-6b0e-4f3e-9a63-5a0c0f2f9b1e")

func insertAccount(ctx context.Context, tx pgx.Tx, cmd ledger.CreateAccount) (ledger.Account, error) {
	a, err := scanAccount(tx.QueryRow(ctx, `INSERT INTO accounts
			(account_id, owner_id, kind, currency, floor_minor, stripes, label, idempotency_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+accountColumns,
		cmd.AccountID, cmd.OwnerID, cmd.Kind, cmd.Currency, cmd.Floor, int16(cmd.Stripes), nullable(cmd.Label), cmd.IdempotencyKey))
	if err != nil {
		return ledger.Account{}, err
	}
	if _, err := outbox.Write(ctx, tx, outbox.Event{
		Topic: ledger.TopicAccountCreated, Key: "account:" + a.ID.String(), Subject: a.ID.String(), Data: a,
	}); err != nil {
		return ledger.Account{}, err
	}
	return a, nil
}

// SetFrozen implements ledger.Ledger.
func (e *Engine) SetFrozen(ctx context.Context, cmd ledger.SetFrozen) (ledger.Account, error) {
	cmd, err := cmd.Normalize()
	if err != nil {
		return ledger.Account{}, err
	}
	return idempotent(ctx, e, ledger.ScopeSetFrozen, cmd.IdempotencyKey, ledger.RequestHash(ledger.ScopeSetFrozen, cmd),
		func(tx pgx.Tx) (ledger.Account, error) {
			a, err := scanAccount(tx.QueryRow(ctx, `UPDATE accounts SET frozen = $2 WHERE account_id = $1
				RETURNING `+accountColumns, cmd.AccountID, cmd.Frozen))
			if errors.Is(err, pgx.ErrNoRows) {
				return ledger.Account{}, &ledger.NotFoundError{Object: "account", ID: cmd.AccountID}
			}
			if err != nil {
				return ledger.Account{}, err
			}
			type frozenEvent struct {
				AccountID uuid.UUID `json:"account_id"`
				Frozen    bool      `json:"frozen"`
				Reason    string    `json:"reason"`
			}
			if _, err := outbox.Write(ctx, tx, outbox.Event{
				Topic: ledger.TopicAccountFrozen, Key: "account:" + a.ID.String(), Subject: a.ID.String(),
				Data: frozenEvent{a.ID, a.Frozen, cmd.Reason},
			}); err != nil {
				return ledger.Account{}, err
			}
			return a, nil
		})
}

// Account implements ledger.Ledger.
func (e *Engine) Account(ctx context.Context, id uuid.UUID) (ledger.Account, error) {
	a, err := scanAccount(e.pool.QueryRow(ctx, `SELECT `+accountColumns+` FROM accounts WHERE account_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ledger.Account{}, &ledger.NotFoundError{Object: "account", ID: id}
	}
	if err != nil {
		return ledger.Account{}, mapError(err)
	}
	return a, nil
}

// Balance implements ledger.Ledger. Striped accounts are summed.
func (e *Engine) Balance(ctx context.Context, id uuid.UUID) (ledger.Balance, error) {
	var b ledger.Balance
	err := e.pool.QueryRow(ctx, `SELECT a.account_id, a.currency, sum(b.balance_minor)::bigint, sum(b.pending_minor)::bigint,
			a.floor_minor, a.frozen
		FROM accounts a JOIN account_balances b ON b.account_id = a.account_id
		WHERE a.account_id = $1
		GROUP BY a.account_id`, id).Scan(&b.AccountID, &b.Currency, &b.Posted, &b.Pending, &b.Floor, &b.Frozen)
	if errors.Is(err, pgx.ErrNoRows) {
		return ledger.Balance{}, &ledger.NotFoundError{Object: "account", ID: id}
	}
	if err != nil {
		return ledger.Balance{}, mapError(err)
	}
	b.Available = b.Posted - b.Pending
	return b, nil
}

// ListAccounts returns up to limit accounts with ids greater than after, in
// id order (keyset pagination for reconciliation and exports).
func (e *Engine) ListAccounts(ctx context.Context, after uuid.UUID, limit int) ([]ledger.Account, error) {
	return ListAccountsIn(ctx, e.pool, after, limit)
}

// Balances returns the balances of several accounts in one query. Unknown
// ids are absent from the result.
func (e *Engine) Balances(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]ledger.Balance, error) {
	return BalancesIn(ctx, e.pool, ids)
}
