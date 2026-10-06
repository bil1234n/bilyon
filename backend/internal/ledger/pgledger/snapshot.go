package pgledger

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// Querier is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx. The readers
// below accept one so that several reads can share a caller's snapshot:
// reconciliation and the TigerBeetle bootstrap read at exact cuts.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// MaxPage bounds the page size of the keyset readers.
const MaxPage = 10_000

func checkLimit(limit int) error {
	if limit <= 0 || limit > MaxPage {
		return &ledger.ValidationError{Field: "limit", Reason: "must be 1..10000"}
	}
	return nil
}

// ListAccountsIn returns up to limit accounts with ids greater than after,
// in id order.
func ListAccountsIn(ctx context.Context, q Querier, after uuid.UUID, limit int) ([]ledger.Account, error) {
	if err := checkLimit(limit); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT `+accountColumns+` FROM accounts WHERE account_id > $1 ORDER BY account_id LIMIT $2`,
		after, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []ledger.Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, mapError(err)
		}
		out = append(out, a)
	}
	return out, mapError(rows.Err())
}

// BalancesIn returns the balances of several accounts, striped accounts
// summed. Unknown ids are absent from the result.
func BalancesIn(ctx context.Context, q Querier, ids []uuid.UUID) (map[uuid.UUID]ledger.Balance, error) {
	rows, err := q.Query(ctx, `SELECT a.account_id, a.currency, sum(b.balance_minor)::bigint, sum(b.pending_minor)::bigint,
			a.floor_minor, a.frozen
		FROM accounts a JOIN account_balances b ON b.account_id = a.account_id
		WHERE a.account_id = ANY($1)
		GROUP BY a.account_id`, ids)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	out := make(map[uuid.UUID]ledger.Balance, len(ids))
	for rows.Next() {
		var b ledger.Balance
		if err := rows.Scan(&b.AccountID, &b.Currency, &b.Posted, &b.Pending, &b.Floor, &b.Frozen); err != nil {
			return nil, mapError(err)
		}
		b.Available = b.Posted - b.Pending
		out[b.AccountID] = b
	}
	return out, mapError(rows.Err())
}

// PendingHoldsIn returns up to limit pending holds with ids greater than
// after, in id order.
func PendingHoldsIn(ctx context.Context, q Querier, after uuid.UUID, limit int) ([]ledger.Hold, error) {
	if err := checkLimit(limit); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT `+holdColumns+` FROM holds WHERE state = 'pending' AND hold_id > $1
		ORDER BY hold_id LIMIT $2`, after, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []ledger.Hold
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return nil, mapError(err)
		}
		out = append(out, h)
	}
	return out, mapError(rows.Err())
}
