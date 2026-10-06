package ledger

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Sentinel errors. Engines wrap them with detail; callers match with errors.Is.
var (
	ErrInvalid             = errors.New("ledger: invalid command")
	ErrNotFound            = errors.New("ledger: not found")
	ErrInsufficientFunds   = errors.New("ledger: insufficient funds")
	ErrAccountFrozen       = errors.New("ledger: account frozen")
	ErrCurrencyMismatch    = errors.New("ledger: currency mismatch")
	ErrUnbalanced          = errors.New("ledger: entry does not balance")
	ErrHoldNotPending      = errors.New("ledger: hold is not pending")
	ErrHoldExpired         = errors.New("ledger: hold has expired")
	ErrIdempotencyConflict = errors.New("ledger: idempotency key reused with a different request")
	ErrOverflow            = errors.New("ledger: amount overflow")
	ErrAlreadyReversed     = errors.New("ledger: entry already reversed")
	ErrNotReversible       = errors.New("ledger: entry cannot be reversed")
	ErrReserveClosed       = errors.New("ledger: reserve is closed")
	ErrUnavailable         = errors.New("ledger: storage unavailable")
)

// ValidationError explains why a command was rejected before execution.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("ledger: invalid %s: %s", e.Field, e.Reason)
}

// Unwrap makes errors.Is(err, ErrInvalid) true.
func (e *ValidationError) Unwrap() error { return ErrInvalid }

func invalid(field, reason string) error { return &ValidationError{Field: field, Reason: reason} }

// NotFoundError names the missing object.
type NotFoundError struct {
	Object string // "account", "hold", "entry", "reserve"
	ID     uuid.UUID
}

func (e *NotFoundError) Error() string { return fmt.Sprintf("ledger: %s %s not found", e.Object, e.ID) }

// Unwrap makes errors.Is(err, ErrNotFound) true.
func (e *NotFoundError) Unwrap() error { return ErrNotFound }

// InsufficientFundsError reports which account could not cover a debit.
type InsufficientFundsError struct {
	AccountID uuid.UUID
	Available int64 // posted - pending before the command
	Required  int64 // amount the command needed to debit or hold
	Floor     int64
}

func (e *InsufficientFundsError) Error() string {
	return fmt.Sprintf("ledger: insufficient funds on %s: available %d, required %d, floor %d",
		e.AccountID, e.Available, e.Required, e.Floor)
}

// Unwrap makes errors.Is(err, ErrInsufficientFunds) true.
func (e *InsufficientFundsError) Unwrap() error { return ErrInsufficientFunds }

// FrozenError names the frozen account.
type FrozenError struct{ AccountID uuid.UUID }

func (e *FrozenError) Error() string { return fmt.Sprintf("ledger: account %s is frozen", e.AccountID) }

// Unwrap makes errors.Is(err, ErrAccountFrozen) true.
func (e *FrozenError) Unwrap() error { return ErrAccountFrozen }
