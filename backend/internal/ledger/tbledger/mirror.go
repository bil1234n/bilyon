package tbledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	tb "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// ErrDiverged reports that TigerBeetle cannot apply an event the PostgreSQL
// ledger committed: a prerequisite is missing or a balance is short. The
// event is not submitted, because TigerBeetle permanently records transient
// failures against transfer ids and the event could never be replayed; the
// shadow stops and retries until an operator resolves the divergence.
var ErrDiverged = errors.New("tbledger: TigerBeetle diverged from the ledger")

// Mirror applies ledger events to TigerBeetle. Events must arrive in an
// order consistent with the ledger's serialization order (Tailer guarantees
// it), may repeat, and must come from a single writer: every prerequisite is
// verified before a write, so TigerBeetle is only asked to do what it must
// accept.
type Mirror struct {
	d *Driver
}

// NewMirror returns a Mirror writing through d.
func NewMirror(d *Driver) *Mirror { return &Mirror{d: d} }

// Apply mirrors one event. Events without a balance effect in TigerBeetle
// (hold.posted, account.frozen, reserve events) are accepted as no-ops: the
// entry events that accompany them carry the money movement.
func (m *Mirror) Apply(_ context.Context, env outbox.Envelope) error {
	switch env.Type {
	case ledger.TopicAccountCreated:
		var a ledger.Account
		if err := json.Unmarshal(env.Data, &a); err != nil {
			return fmt.Errorf("decode account: %w", err)
		}
		return m.d.CreateAccount(a)
	case ledger.TopicEntryPosted:
		var en ledger.Entry
		if err := json.Unmarshal(env.Data, &en); err != nil {
			return fmt.Errorf("decode entry: %w", err)
		}
		if en.HoldID != nil {
			return m.applyHoldEntry(en)
		}
		return m.applyEntry(en)
	case ledger.TopicHoldPlaced:
		var h ledger.Hold
		if err := json.Unmarshal(env.Data, &h); err != nil {
			return fmt.Errorf("decode hold: %w", err)
		}
		return m.placeHold(h)
	case ledger.TopicHoldVoided, ledger.TopicHoldExpired:
		var h ledger.Hold
		if err := json.Unmarshal(env.Data, &h); err != nil {
			return fmt.Errorf("decode hold: %w", err)
		}
		return m.voidHold(h)
	default:
		return nil
	}
}

// replayed reports whether the chain was applied before: chains are atomic,
// so its first transfer exists exactly when all of them do.
func (m *Mirror) replayed(plan []tb.Transfer) (bool, error) {
	found, err := m.d.lookupTransfers([]tb.Uint128{plan[0].ID})
	if err != nil || len(found) == 0 {
		return false, err
	}
	ids := make([]tb.Uint128, len(plan))
	for i, t := range plan {
		ids[i] = t.ID
	}
	all, err := m.d.lookupTransfers(ids)
	if err != nil {
		return false, err
	}
	if len(all) != len(plan) {
		return false, fmt.Errorf("%w: chain only partly exists (%d of %d transfers)", ledger.ErrIdempotencyConflict, len(all), len(plan))
	}
	return true, nil
}

// checkLegs verifies that every account an entry touches exists and, unless
// debitsSettled, that each limited account can cover its net debit.
func (m *Mirror) checkLegs(en ledger.Entry, debitsSettled bool) error {
	legs, err := netPostings(en.Postings)
	if err != nil {
		return err
	}
	ids := make([]uuid.UUID, len(legs))
	for i, l := range legs {
		ids[i] = l.account
	}
	accts, err := m.d.Accounts(ids)
	if err != nil {
		return err
	}
	for _, l := range legs {
		acct, ok := accts[l.account]
		if !ok {
			return fmt.Errorf("%w: entry %s: account %s does not exist", ErrDiverged, en.ID, l.account)
		}
		if l.amount > 0 || debitsSettled {
			continue
		}
		if avail, limited := available(acct); limited && avail.Cmp(big.NewInt(-l.amount)) < 0 {
			return fmt.Errorf("%w: entry %s debits %d from %s, which has %s available", ErrDiverged, en.ID,
				-l.amount, l.account, avail)
		}
	}
	return nil
}

func (m *Mirror) applyEntry(en ledger.Entry) error {
	plan, err := entryPlan(en)
	if err != nil || len(plan) == 0 {
		return err
	}
	if done, err := m.replayed(plan); err != nil || done {
		return err
	}
	if err := m.checkLegs(en, false); err != nil {
		return err
	}
	return m.d.submit(plan)
}

func (m *Mirror) applyHoldEntry(en ledger.Entry) error {
	post, err := holdPostPlan(en)
	if err != nil {
		return err
	}
	fallback, err := fallbackPlan(en)
	if err != nil {
		return err
	}
	if done, err := m.replayed(post); err != nil || done {
		return err
	}
	if done, err := m.replayed(fallback); err != nil || done {
		return err
	}
	pending, err := m.d.lookupTransfers([]tb.Uint128{ToU128(*en.HoldID)})
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return fmt.Errorf("%w: entry %s settles hold %s, which was never mirrored", ErrDiverged, en.ID, *en.HoldID)
	}
	// Posting only converts reserved funds, so no balance check applies.
	if err := m.checkLegs(en, true); err != nil {
		return err
	}
	err = m.d.submit(post)
	switch {
	case errors.Is(err, ledger.ErrHoldExpired):
		// TigerBeetle expired the hold (the shadow lagged past the grace),
		// releasing the reservation: settle with plain transfers instead.
		if err := m.checkLegs(en, false); err != nil {
			return err
		}
		return m.d.submit(fallback)
	case errors.Is(err, ledger.ErrHoldNotPending):
		return fmt.Errorf("%w: hold %s is already resolved in TigerBeetle: %v", ErrDiverged, *en.HoldID, err)
	default:
		return err
	}
}

func (m *Mirror) placeHold(h ledger.Hold) error {
	found, err := m.d.lookupTransfers([]tb.Uint128{ToU128(h.ID)})
	if err != nil {
		return err
	}
	if t, ok := found[ToU128(h.ID)]; ok {
		return matchHold(t, h)
	}
	accts, err := m.d.Accounts([]uuid.UUID{h.AccountID})
	if err != nil {
		return err
	}
	acct, ok := accts[h.AccountID]
	if !ok {
		return fmt.Errorf("%w: hold %s: account %s does not exist", ErrDiverged, h.ID, h.AccountID)
	}
	if avail, limited := available(acct); limited && avail.Cmp(big.NewInt(h.Amount)) < 0 {
		return fmt.Errorf("%w: hold %s reserves %d from %s, which has %s available", ErrDiverged, h.ID, h.Amount,
			h.AccountID, avail)
	}
	return m.d.createHold(h)
}

func (m *Mirror) voidHold(h ledger.Hold) error {
	void := derivedID(h.ID, "void", 0)
	found, err := m.d.lookupTransfers([]tb.Uint128{ToU128(h.ID), void})
	if err != nil {
		return err
	}
	if _, ok := found[void]; ok {
		return nil
	}
	if _, ok := found[ToU128(h.ID)]; !ok {
		return fmt.Errorf("%w: hold %s was never mirrored", ErrDiverged, h.ID)
	}
	return m.d.VoidHold(h)
}
