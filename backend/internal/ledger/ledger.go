package ledger

import (
	"context"

	"github.com/google/uuid"
)

// Ledger is the contract every storage engine implements. Methods are safe
// for concurrent use. Mutations are atomic and idempotent per key.
type Ledger interface {
	CreateAccount(ctx context.Context, cmd CreateAccount) (Account, error)
	SetFrozen(ctx context.Context, cmd SetFrozen) (Account, error)
	Account(ctx context.Context, id uuid.UUID) (Account, error)
	Balance(ctx context.Context, id uuid.UUID) (Balance, error)

	Transfer(ctx context.Context, cmd Transfer) (Entry, error)
	Reverse(ctx context.Context, cmd Reverse) (Entry, error)
	Entry(ctx context.Context, id uuid.UUID) (Entry, error)
	History(ctx context.Context, q HistoryQuery) (HistoryPage, error)

	PlaceHold(ctx context.Context, cmd PlaceHold) (Hold, error)
	PostHold(ctx context.Context, cmd PostHold) (PostHoldResult, error)
	VoidHold(ctx context.Context, cmd VoidHold) (Hold, error)
	Hold(ctx context.Context, id uuid.UUID) (Hold, error)
	// ExpireHolds resolves up to limit pending holds whose expiry has passed
	// and returns them. Workers call it until it returns fewer than limit.
	ExpireHolds(ctx context.Context, limit int) ([]Hold, error)

	OpenReserve(ctx context.Context, cmd OpenReserve) (OpenReserveResult, error)
	ReleaseReserve(ctx context.Context, cmd ReleaseReserve) (ReleaseReserveResult, error)
	Reserve(ctx context.Context, id uuid.UUID) (Reserve, error)
}

// Event topics written to the outbox by engines.
const (
	TopicAccountCreated  = "ledger.account.created"
	TopicAccountFrozen   = "ledger.account.frozen"
	TopicEntryPosted     = "ledger.entry.posted"
	TopicHoldPlaced      = "ledger.hold.placed"
	TopicHoldPosted      = "ledger.hold.posted"
	TopicHoldVoided      = "ledger.hold.voided"
	TopicHoldExpired     = "ledger.hold.expired"
	TopicReserveOpened   = "ledger.reserve.opened"
	TopicReserveReleased = "ledger.reserve.released"
)
