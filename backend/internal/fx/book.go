package fx

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// EntryKind is the journal entry kind of FX bookings.
const EntryKind = "fx.convert"

// refused reports whether the ledger refused a booking for a business
// reason (it will not succeed on retry), as opposed to being unavailable.
func refused(err error) bool {
	for _, target := range []error{ledger.ErrInvalid, ledger.ErrNotFound, ledger.ErrInsufficientFunds,
		ledger.ErrAccountFrozen, ledger.ErrCurrencyMismatch, ledger.ErrHoldNotPending, ledger.ErrHoldExpired,
		ledger.ErrUnbalanced, ledger.ErrOverflow} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// book moves the money of an executing quote with idempotency keys derived
// from the quote id, so retries and the recovery sweeper converge on the
// same entries:
//
//	hold funding:    PostHold(hold → fx_book[from], in)   key fx:<id>:in
//	                 Transfer(fx_book[to] → dest, out)     key fx:<id>:out
//	account funding: Transfer(source → fx_book[from], in; fx_book[to] → dest, out)  key fx:<id>
//
// A refused first step fails the quote and returns its depth; a refused
// payout leaves the quote executing, to be resumed.
func (e *Engine) book(ctx context.Context, q *storedQuote) (Execution, error) {
	key := "fx:" + q.ID.String()
	ref := q.ID.String()
	bookFrom, bookTo := e.cfg.FXBooks[q.From], e.cfg.FXBooks[q.To]
	var entries []uuid.UUID
	if q.HoldID != uuid.Nil {
		res, err := e.ledger.PostHold(ctx, ledger.PostHold{IdempotencyKey: key + ":in", HoldID: q.HoldID, Kind: EntryKind,
			Memo: "fx quote " + ref, Credits: []ledger.Posting{{AccountID: bookFrom, Amount: q.AmountIn}}})
		if err != nil {
			return e.refusedFirst(ctx, q, err)
		}
		entries = append(entries, res.Entry.ID)
		en, err := e.ledger.Transfer(ctx, ledger.Transfer{IdempotencyKey: key + ":out", Kind: EntryKind,
			RefType: "fx_quote", RefID: ref, Postings: []ledger.Posting{
				{AccountID: bookTo, Amount: -q.AmountOut}, {AccountID: q.DestinationAccount, Amount: q.AmountOut}}})
		if err != nil {
			return e.refusedPayout(ctx, q, err)
		}
		entries = append(entries, en.ID)
	} else {
		en, err := e.ledger.Transfer(ctx, ledger.Transfer{IdempotencyKey: key, Kind: EntryKind, RefType: "fx_quote",
			RefID: ref, Postings: []ledger.Posting{
				{AccountID: q.SourceAccount, Amount: -q.AmountIn}, {AccountID: bookFrom, Amount: q.AmountIn},
				{AccountID: bookTo, Amount: -q.AmountOut}, {AccountID: q.DestinationAccount, Amount: q.AmountOut}}})
		if err != nil {
			return e.refusedFirst(ctx, q, err)
		}
		entries = append(entries, en.ID)
	}
	return e.finish(ctx, q, entries)
}

func (e *Engine) finish(ctx context.Context, q *storedQuote, entries []uuid.UUID) (Execution, error) {
	now := e.cfg.Now().UTC().Truncate(time.Microsecond)
	if err := e.db.markBooked(ctx, q, entries, now); err != nil {
		return Execution{}, err
	}
	booked, err := e.db.get(ctx, q.ID)
	if err != nil {
		return Execution{}, err
	}
	return booked.execution(), nil
}

func (e *Engine) refusedFirst(ctx context.Context, q *storedQuote, err error) (Execution, error) {
	if !refused(err) {
		return Execution{}, fmt.Errorf("fx: booking quote %s: %w", q.ID, err)
	}
	if ferr := e.db.markFailed(ctx, q, err.Error()); ferr != nil {
		return Execution{}, ferr
	}
	e.unconsume(q.Executed)
	return Execution{}, fmt.Errorf("%w: %w", ErrFailed, err)
}

func (e *Engine) refusedPayout(ctx context.Context, q *storedQuote, err error) (Execution, error) {
	// The source side is booked, so the quote cannot fail any more: it
	// stays executing until the payout goes through (the recovery sweeper
	// retries, e.g. once treasury restores an fx book at its floor).
	e.cfg.Logger.Error("fx: payout not booked; the quote stays executing", "quote", q.ID, "err", err)
	return Execution{}, fmt.Errorf("%w: quote %s: %w", ErrPayoutPending, q.ID, err)
}
