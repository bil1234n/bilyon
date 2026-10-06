// Package accounts resolves people's ledger accounts: one user account per
// (user, currency), opened in the ledger on first use and recorded in the
// gateway database. The gateway never holds balances (RFC 0001 §1.1); it
// only knows which ledger account is whose.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/money"
)

// Errors.
var (
	ErrNotFound    = errors.New("accounts: no account in this currency")
	ErrUnknownUser = errors.New("accounts: unknown user")
	ErrCurrency    = errors.New("accounts: unsupported currency")
	ErrMismatch    = errors.New("accounts: ledger account does not match the user and currency")
)

// Account maps a user and currency to a ledger account.
type Account struct {
	UserID    uuid.UUID
	Currency  string
	AccountID uuid.UUID
	CreatedAt time.Time
}

// Resolver resolves and opens user accounts.
type Resolver struct {
	pool   *pgxpool.Pool
	ledger ledger.Ledger
}

// New returns a resolver over the gateway database and the ledger.
func New(pool *pgxpool.Pool, l ledger.Ledger) *Resolver { return &Resolver{pool: pool, ledger: l} }

func scan(row pgx.Row) (Account, error) {
	var a Account
	err := row.Scan(&a.UserID, &a.Currency, &a.AccountID, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	a.CreatedAt = a.CreatedAt.UTC()
	return a, err
}

const columns = `user_id, currency, account_id, created_at`

// Get returns the user's account in currency.
func (r *Resolver) Get(ctx context.Context, userID uuid.UUID, currency string) (Account, error) {
	return scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM user_accounts WHERE user_id = $1 AND currency = $2`,
		userID, currency))
}

// IdempotencyKey is the ledger key that opens the user's account in
// currency: every attempt, including one that crashed after the ledger
// committed, gets the same account back.
func IdempotencyKey(userID uuid.UUID, currency string) string {
	return "user-account:" + userID.String() + ":" + currency
}

// Ensure returns the user's account in currency, opening it on first use.
func (r *Resolver) Ensure(ctx context.Context, userID uuid.UUID, currency string) (Account, error) {
	a, err := r.Get(ctx, userID, currency)
	if !errors.Is(err, ErrNotFound) {
		return a, err
	}
	if _, ok := money.Lookup(currency); !ok {
		return Account{}, fmt.Errorf("%w: %q", ErrCurrency, currency)
	}
	var exists bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE user_id = $1)`, userID).Scan(&exists); err != nil {
		return Account{}, err
	}
	if !exists {
		return Account{}, ErrUnknownUser
	}
	owner := userID
	la, err := r.ledger.CreateAccount(ctx, ledger.CreateAccount{IdempotencyKey: IdempotencyKey(userID, currency),
		OwnerID: &owner, Kind: ledger.KindUser, Currency: currency, Label: "user"})
	if err != nil {
		return Account{}, fmt.Errorf("accounts: open %s account: %w", currency, err)
	}
	if la.Kind != ledger.KindUser || la.Currency != currency || la.OwnerID == nil || *la.OwnerID != userID {
		return Account{}, fmt.Errorf("%w: %s", ErrMismatch, la.ID)
	}
	if _, err := r.pool.Exec(ctx, `INSERT INTO user_accounts (user_id, currency, account_id) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, currency) DO NOTHING`, userID, currency, la.ID); err != nil {
		return Account{}, err
	}
	if a, err = r.Get(ctx, userID, currency); err != nil {
		return Account{}, err
	}
	if a.AccountID != la.ID {
		// Unreachable while the idempotency key decides the account; a
		// different row means someone wrote user_accounts by hand.
		return Account{}, fmt.Errorf("%w: recorded %s, ledger %s", ErrMismatch, a.AccountID, la.ID)
	}
	return a, nil
}

// List returns the user's accounts ordered by currency.
func (r *Resolver) List(ctx context.Context, userID uuid.UUID) ([]Account, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+columns+` FROM user_accounts WHERE user_id = $1 ORDER BY currency`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Balance is an account with its ledger balance.
type Balance struct {
	Account
	Posted    int64 // settled
	Pending   int64 // held
	Available int64 // posted minus pending
	Frozen    bool
}

// Balances returns the user's accounts with their balances.
func (r *Resolver) Balances(ctx context.Context, userID uuid.UUID) ([]Balance, error) {
	accts, err := r.List(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Balance, 0, len(accts))
	for _, a := range accts {
		b, err := r.ledger.Balance(ctx, a.AccountID)
		if err != nil {
			return nil, fmt.Errorf("accounts: balance of %s: %w", a.AccountID, err)
		}
		out = append(out, Balance{Account: a, Posted: b.Posted, Pending: b.Pending, Available: b.Available, Frozen: b.Frozen})
	}
	return out, nil
}
