package intents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

// EntryKind is the ledger entry kind of a same-currency settlement.
const EntryKind = "payment.intent"

// Ledger idempotency keys: every attempt at a step, before or after a
// crash, sends the same key and so gets the same hold or entry.
func holdKey(id uuid.UUID) string { return "intent:" + id.String() + ":hold" }
func postKey(id uuid.UUID) string { return "intent:" + id.String() + ":post" }
func voidKey(id uuid.UUID) string { return "intent:" + id.String() + ":void" }

// fxPostKey is the key under which the FX engine posts a hold it converts.
func fxPostKey(quote uuid.UUID) string { return "fx:" + quote.String() + ":in" }

func holdReason(g Gesture) string {
	if g.Kind() != txauth.GestureNone {
		return "throw_intent"
	}
	return "payment_intent"
}

// refused reports a definitive ledger refusal, as opposed to an outage.
func refused(err error) bool {
	for _, e := range []error{ledger.ErrInsufficientFunds, ledger.ErrAccountFrozen, ledger.ErrCurrencyMismatch,
		ledger.ErrInvalid, ledger.ErrNotFound, ledger.ErrHoldNotPending, ledger.ErrHoldExpired} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func (s *Service) transient(op string, err error) error {
	s.m.ledger.WithLabelValues(op).Inc()
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, op, err)
}

// maxSteps bounds one advance: created → caught → voiding → caught (a
// healed void) → settled is the longest legitimate path.
const maxSteps = 8

// advance drives an intent through its pending ledger steps. A transient
// failure returns ErrUnavailable with the intent where it stopped; a
// replay or the sweeper continues from there.
func (s *Service) advance(ctx context.Context, in *Intent) (*Intent, error) {
	for i := 0; i < maxSteps; i++ {
		var next *Intent
		var err error
		switch in.State {
		case StateCreated:
			next, err = s.placeHold(ctx, in)
		case StateCaught:
			next, err = s.settle(ctx, in)
		case StateVoiding:
			next, err = s.release(ctx, in)
		default:
			return in, nil
		}
		if err != nil {
			return in, err
		}
		in = next
	}
	return in, nil
}

// move applies a transition in its own transaction. When another actor
// moved the intent first, it returns the intent as it is now.
func (s *Service) move(ctx context.Context, id uuid.UUID, c change) (*Intent, error) {
	var out *Intent
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = s.db.apply(ctx, tx, id, c, s.now())
		return err
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return s.db.get(ctx, s.pool, id)
	}
	s.m.moved(out)
	return out, nil
}

// placeHold reserves the amount on the payer's account. A live intent
// waits for its catch; any other settles on acceptance, so it goes
// straight to CAUGHT.
func (s *Service) placeHold(ctx context.Context, in *Intent) (*Intent, error) {
	created := []State{StateCreated}
	acct, err := s.accounts.Get(ctx, in.PayerID, in.Currency)
	if errors.Is(err, accounts.ErrNotFound) {
		return s.move(ctx, in.ID, change{From: created, To: StateAborted, Reason: ReasonInsufficientFunds, Topic: TopicAborted})
	}
	if err != nil {
		return nil, err
	}
	h, err := s.ledger.PlaceHold(ctx, ledger.PlaceHold{IdempotencyKey: holdKey(in.ID), AccountID: acct.AccountID,
		Amount: in.Amount, Reason: holdReason(in.Gesture), ExpiresAt: in.HoldExpiresAt, RefType: "intent",
		RefID: in.ID.String()})
	switch {
	case err == nil:
		// A replayed command answers with the hold as it was placed. When
		// an earlier attempt may have placed it, read its state now: it
		// may have lapsed or been released before the intent recorded it.
		if !in.fresh {
			if h, err = s.ledger.Hold(ctx, h.ID); err != nil {
				return nil, s.transient("hold", err)
			}
		}
		if h.State != ledger.HoldPending || !in.HoldExpiresAt.After(s.now()) {
			return s.move(ctx, in.ID, change{From: created, To: StateVoiding, Reason: ReasonHoldExpired, HoldID: h.ID})
		}
		c := change{From: created, To: StateHeld, HoldID: h.ID, Topic: TopicHeld}
		if !in.Gesture.Live() {
			c.To, c.Topic = StateCaught, ""
		}
		return s.move(ctx, in.ID, c)
	case errors.Is(err, ledger.ErrInsufficientFunds):
		return s.move(ctx, in.ID, change{From: created, To: StateAborted, Reason: ReasonInsufficientFunds, Topic: TopicAborted})
	case errors.Is(err, ledger.ErrAccountFrozen):
		return s.move(ctx, in.ID, change{From: created, To: StateAborted, Reason: ReasonAccountFrozen, Topic: TopicAborted})
	case refused(err):
		return s.move(ctx, in.ID, change{From: created, To: StateAborted, Reason: ReasonHoldRefused, Topic: TopicAborted})
	}
	return nil, s.transient("hold", err)
}

// settle posts the hold to the payee: directly in the same currency, or
// through the FX engine, which converts the hold at the quoted rate.
func (s *Service) settle(ctx context.Context, in *Intent) (*Intent, error) {
	payee, err := s.accounts.Ensure(ctx, in.PayeeID, in.PayeeCurrency)
	if err != nil {
		return nil, s.transient("payee_account", err)
	}
	var entries []uuid.UUID
	if in.QuoteID == uuid.Nil {
		res, err := s.ledger.PostHold(ctx, ledger.PostHold{IdempotencyKey: postKey(in.ID), HoldID: in.HoldID, Kind: EntryKind,
			Credits: []ledger.Posting{{AccountID: payee.AccountID, Amount: in.Amount}}})
		switch {
		case errors.Is(err, ledger.ErrHoldNotPending) || errors.Is(err, ledger.ErrHoldExpired):
			return s.abandon(ctx, in, ReasonHoldExpired)
		case err != nil && refused(err):
			return s.abandon(ctx, in, ReasonSettleRefused)
		case err != nil:
			return nil, s.transient("post", err)
		}
		entries = []uuid.UUID{res.Entry.ID}
	} else {
		if s.fx == nil {
			return s.abandon(ctx, in, ReasonFXFailed)
		}
		x, err := s.fx.ExecuteQuote(ctx, fx.ExecuteRequest{QuoteID: in.QuoteID, Signature: in.quoteSignature,
			UserID: in.PayerID, HoldID: in.HoldID, DestinationAccount: payee.AccountID})
		switch {
		case err == nil && len(x.EntryIDs) > 0:
			entries = x.EntryIDs
		case err == nil:
			return nil, s.transient("fx", fmt.Errorf("execution of %s is %s without entries", in.QuoteID, x.State))
		case errors.Is(err, fx.ErrExpired):
			return s.abandon(ctx, in, ReasonFXExpired)
		case errors.Is(err, fx.ErrRequote):
			return s.abandon(ctx, in, ReasonFXRequote)
		case errors.Is(err, fx.ErrFailed), errors.Is(err, fx.ErrUnknownQuote), errors.Is(err, fx.ErrTampered),
			errors.Is(err, fx.ErrFunding), errors.Is(err, fx.ErrRequest), errors.Is(err, fx.ErrConflict):
			return s.abandon(ctx, in, ReasonFXFailed)
		default:
			// Outages, and ErrPayoutPending: the hold is already in the FX
			// book, so the intent must never void now; the payout
			// completes on retry.
			return nil, s.transient("fx", err)
		}
	}
	return s.move(ctx, in.ID, change{From: []State{StateCaught}, To: StateSettled, EntryIDs: entries, Topic: TopicSettled})
}

// abandon gives up a settlement the ledger or the FX engine definitively
// refused: the hold goes back to the payer.
func (s *Service) abandon(ctx context.Context, in *Intent, reason string) (*Intent, error) {
	return s.move(ctx, in.ID, change{From: []State{StateCaught}, To: StateVoiding, Reason: reason})
}

// release voids the hold. A hold that is no longer pending was released
// already (it expired) — unless it was posted: if the post was this
// intent's own (a settlement whose answer was lost), the intent returns to
// CAUGHT and the idempotent settlement finishes it.
func (s *Service) release(ctx context.Context, in *Intent) (*Intent, error) {
	_, err := s.ledger.VoidHold(ctx, ledger.VoidHold{IdempotencyKey: voidKey(in.ID), HoldID: in.HoldID, Reason: in.Reason})
	if err != nil {
		if !errors.Is(err, ledger.ErrHoldNotPending) && !errors.Is(err, ledger.ErrHoldExpired) {
			return nil, s.transient("void", err)
		}
		h, err := s.ledger.Hold(ctx, in.HoldID)
		if err != nil {
			return nil, s.transient("void", err)
		}
		if h.State == ledger.HoldPosted {
			ours, err := s.postedByIntent(ctx, in, h)
			if err != nil {
				return nil, s.transient("void", err)
			}
			if ours {
				return s.move(ctx, in.ID, change{From: []State{StateVoiding}, To: StateCaught})
			}
			s.cfg.Logger.Error("intents: hold posted outside the intent", "intent", in.ID, "hold", h.ID)
		}
	}
	return s.move(ctx, in.ID, change{From: []State{StateVoiding}, To: StateVoided, Topic: TopicVoided})
}

func (s *Service) postedByIntent(ctx context.Context, in *Intent, h ledger.Hold) (bool, error) {
	if h.EntryID == nil {
		return false, nil
	}
	e, err := s.ledger.Entry(ctx, *h.EntryID)
	if err != nil {
		return false, err
	}
	if in.QuoteID != uuid.Nil {
		return e.IdempotencyKey == fxPostKey(in.QuoteID), nil
	}
	return e.IdempotencyKey == postKey(in.ID), nil
}

// expire applies a due timeout to a locked intent: an uncaught throw
// becomes a claim or starts returning, and an unclaimed one returns.
func (s *Service) expire(ctx context.Context, tx pgx.Tx, in *Intent, now time.Time) (*Intent, error) {
	var c change
	switch {
	case (in.State == StateHeld || in.State == StateDelivered) && in.LiveUntil != nil && !now.Before(*in.LiveUntil):
		if s.mayWait(in) {
			claim := in.LiveUntil.Add(s.cfg.ClaimTTL)
			c = change{From: []State{in.State}, To: StateAsyncPending, ClaimUntil: &claim, Topic: TopicAsyncPending}
		} else {
			c = change{From: []State{in.State}, To: StateVoiding, Reason: ReasonUncaught}
		}
	case in.State == StateAsyncPending && in.ClaimUntil != nil && !now.Before(*in.ClaimUntil):
		c = change{From: []State{StateAsyncPending}, To: StateVoiding, Reason: ReasonClaimExpired}
	default:
		return in, nil
	}
	out, err := s.db.apply(ctx, tx, in.ID, c, now)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("intents: %s changed under its row lock", in.ID)
	}
	return out, nil
}

// locked runs fn on the locked intent after applying any due timeout. fn
// returns a refusal (committed with the timeout, then returned) or an
// error (rolled back).
func (s *Service) locked(ctx context.Context, id uuid.UUID,
	fn func(tx pgx.Tx, in *Intent, now time.Time) (*Intent, error, error)) (*Intent, error) {
	var out *Intent
	var refusal error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now()
		in, err := s.db.lock(ctx, tx, id)
		if err != nil {
			return err
		}
		before := in.State
		if in, err = s.expire(ctx, tx, in, now); err != nil {
			return err
		}
		if in.State != before {
			s.m.moved(in)
		}
		out, refusal, err = fn(tx, in, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		// A timeout applied on the way may have started a return.
		if out != nil && out.State == StateVoiding {
			_, _ = s.advance(ctx, out)
		}
		return nil, refusal
	}
	return s.advance(ctx, out)
}

// CatchRequest is a CATCH (§4.4.5). After the live TTL an accept is a
// claim of the asynchronous transfer.
type CatchRequest struct {
	IntentID uuid.UUID
	UserID   uuid.UUID
	Accept   bool
	// Proximity is set by the realtime gateway when the user's device is in
	// a mutual proximity session with the payer's and made the pull-back
	// gesture (§3.B.5). Grabbing a drop requires it.
	Proximity bool
}

// Catch accepts or declines an intent as its payee, or grabs a drop.
func (s *Service) Catch(ctx context.Context, req CatchRequest) (*Intent, error) {
	in, err := s.db.get(ctx, s.pool, req.IntentID)
	if err != nil {
		return nil, err
	}
	drop := in.Gesture == GestureGrab
	var subject string
	if drop {
		switch {
		case req.UserID == in.PayerID:
			return nil, fmt.Errorf("%w: the payer cancels a drop instead", ErrForbidden)
		case !req.Accept:
			return nil, fmt.Errorf("%w: a drop is grabbed or left, never declined", ErrForbidden)
		case !req.Proximity:
			return nil, fmt.Errorf("%w: grabbing needs a proximity session with the payer", ErrForbidden)
		}
		status, err := s.db.userStatus(ctx, req.UserID)
		if errors.Is(err, ErrNotFound) || (err == nil && status != "active") {
			return nil, ErrForbidden
		}
		if err != nil {
			return nil, err
		}
		if subject, err = s.dir.Subject(ctx, req.UserID); err != nil {
			return nil, err
		}
	} else if in.PayeeID != req.UserID {
		return nil, ErrNotFound
	}
	op := "decline"
	if req.Accept {
		op = "accept"
	}
	return s.locked(ctx, req.IntentID, func(tx pgx.Tx, in *Intent, now time.Time) (*Intent, error, error) {
		if drop && in.PayeeID != uuid.Nil && in.PayeeID != req.UserID {
			return nil, &StateError{Op: "grab", State: in.State}, nil
		}
		switch in.State {
		case StateHeld, StateDelivered, StateAsyncPending:
			c := change{From: []State{in.State}, To: StateVoiding, Reason: ReasonDeclined}
			if req.Accept {
				c = change{From: []State{in.State}, To: StateCaught, Topic: TopicCaught}
				if drop {
					c.PayeeID, c.Subject = req.UserID, subject
				}
			}
			out, err := s.db.apply(ctx, tx, in.ID, c, now)
			if err == nil && out == nil {
				err = fmt.Errorf("intents: %s changed under its row lock", in.ID)
			}
			s.m.moved(out)
			return out, nil, err
		case StateCaught, StateSettled:
			if req.Accept {
				return in, nil, nil
			}
		case StateVoiding, StateVoided:
			if !req.Accept {
				return in, nil, nil
			}
		}
		return in, &StateError{Op: op, State: in.State}, nil
	})
}

// Cancel returns an intent nobody has caught yet to its payer.
func (s *Service) Cancel(ctx context.Context, userID, id uuid.UUID) (*Intent, error) {
	return s.locked(ctx, id, func(tx pgx.Tx, in *Intent, now time.Time) (*Intent, error, error) {
		if in.PayerID != userID {
			if in.PayeeID == userID {
				return nil, fmt.Errorf("%w: the payee declines instead", ErrForbidden), nil
			}
			return nil, ErrNotFound, nil
		}
		switch in.State {
		case StateHeld, StateDelivered, StateAsyncPending:
			out, err := s.db.apply(ctx, tx, in.ID, change{From: []State{in.State}, To: StateVoiding, Reason: ReasonCancelled}, now)
			if err == nil && out == nil {
				err = fmt.Errorf("intents: %s changed under its row lock", in.ID)
			}
			s.m.moved(out)
			return out, nil, err
		case StateVoiding, StateVoided:
			return in, nil, nil
		}
		return in, &StateError{Op: "cancel", State: in.State}, nil
	})
}

// MarkDelivered records that the payee's device received INCOMING.
func (s *Service) MarkDelivered(ctx context.Context, userID, id uuid.UUID) (*Intent, error) {
	return s.locked(ctx, id, func(tx pgx.Tx, in *Intent, now time.Time) (*Intent, error, error) {
		if in.PayeeID != userID || in.PayeeID == uuid.Nil {
			return nil, ErrNotFound, nil
		}
		switch in.State {
		case StateCreated:
			return in, &StateError{Op: "deliver", State: in.State}, nil
		case StateHeld:
			out, err := s.db.apply(ctx, tx, in.ID, change{From: []State{StateHeld}, To: StateDelivered, Topic: TopicDelivered}, now)
			if err == nil && out == nil {
				err = fmt.Errorf("intents: %s changed under its row lock", in.ID)
			}
			s.m.moved(out)
			return out, nil, err
		}
		return in, nil, nil // a late acknowledgement changes nothing
	})
}

// SweepResult counts one sweep's work.
type SweepResult struct {
	Uncaught int // live TTL over: now claims, or returning
	Expired  int // claim windows over: returning
	Finished int // pending ledger steps completed
	Failed   int // pending steps that failed again; retried next sweep
}

// Sweep applies due timeouts and finishes intents whose ledger step has
// been pending for RedriveAfter. Concurrent sweepers skip each other's
// rows, and every step is idempotent.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	now := s.now()
	var returning []*Intent
	for _, q := range []struct {
		states   []State
		deadline string
		count    *int
		kind     string
	}{
		{[]State{StateHeld, StateDelivered}, "live_until", &res.Uncaught, "uncaught"},
		{[]State{StateAsyncPending}, "claim_until", &res.Expired, "claim_expired"},
	} {
		for {
			var batch []*Intent
			err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
				due, err := s.db.due(ctx, tx, q.states, q.deadline, now, s.cfg.SweepBatch)
				if err != nil {
					return err
				}
				batch = batch[:0]
				for _, in := range due {
					out, err := s.expire(ctx, tx, in, now)
					if err != nil {
						return err
					}
					batch = append(batch, out)
				}
				return nil
			})
			if err != nil {
				return res, err
			}
			for _, in := range batch {
				*q.count++
				s.m.moved(in)
				s.m.swept.WithLabelValues(q.kind).Inc()
				if in.State == StateVoiding {
					returning = append(returning, in)
				}
			}
			if len(batch) < s.cfg.SweepBatch {
				break
			}
		}
	}
	finish := func(in *Intent) {
		if _, err := s.advance(ctx, in); err != nil {
			res.Failed++
			s.cfg.Logger.Warn("intents: pending step failed; retrying next sweep", "intent", in.ID, "state", in.State,
				"err", err)
			return
		}
		res.Finished++
		s.m.swept.WithLabelValues("finished").Inc()
	}
	for _, in := range returning {
		finish(in)
	}
	ids, err := s.db.unfinished(ctx, now.Add(-s.cfg.RedriveAfter), s.cfg.SweepBatch)
	if err != nil {
		return res, err
	}
	for _, id := range ids {
		in, err := s.db.get(ctx, s.pool, id)
		if err != nil {
			return res, err
		}
		finish(in)
	}
	return res, nil
}
