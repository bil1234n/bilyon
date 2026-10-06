package ledgerapi

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	ledgerv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/ledger/v1"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// Client is a ledger.Ledger backed by a remote LedgerService. Errors are
// the same typed ledger errors the local engine returns.
type Client struct {
	c ledgerv1.LedgerServiceClient
}

var _ ledger.Ledger = (*Client)(nil)

// NewClient wraps a connection, typically created with grpc.NewClient,
// mutual TLS credentials and grpc.WithDefaultServiceConfig(grpcx.RetryServiceConfig).
func NewClient(conn grpc.ClientConnInterface) *Client {
	return &Client{c: ledgerv1.NewLedgerServiceClient(conn)}
}

// CreateAccount implements ledger.Ledger.
func (c *Client) CreateAccount(ctx context.Context, cmd ledger.CreateAccount) (ledger.Account, error) {
	a, err := c.c.CreateAccount(ctx, &ledgerv1.CreateAccountRequest{IdempotencyKey: cmd.IdempotencyKey,
		AccountId: idString(cmd.AccountID), OwnerId: idPtrString(cmd.OwnerID), Kind: string(cmd.Kind),
		Currency: cmd.Currency, Floor: cmd.Floor, Stripes: int32(cmd.Stripes), Label: cmd.Label})
	if err != nil {
		return ledger.Account{}, FromStatus(err)
	}
	return AccountFromPB(a), nil
}

// SetFrozen implements ledger.Ledger.
func (c *Client) SetFrozen(ctx context.Context, cmd ledger.SetFrozen) (ledger.Account, error) {
	a, err := c.c.SetFrozen(ctx, &ledgerv1.SetFrozenRequest{IdempotencyKey: cmd.IdempotencyKey,
		AccountId: idString(cmd.AccountID), Frozen: cmd.Frozen, Reason: cmd.Reason})
	if err != nil {
		return ledger.Account{}, FromStatus(err)
	}
	return AccountFromPB(a), nil
}

// Account implements ledger.Ledger.
func (c *Client) Account(ctx context.Context, id uuid.UUID) (ledger.Account, error) {
	a, err := c.c.GetAccount(ctx, &ledgerv1.GetAccountRequest{AccountId: idString(id)})
	if err != nil {
		return ledger.Account{}, FromStatus(err)
	}
	return AccountFromPB(a), nil
}

// Balance implements ledger.Ledger.
func (c *Client) Balance(ctx context.Context, id uuid.UUID) (ledger.Balance, error) {
	b, err := c.c.GetBalance(ctx, &ledgerv1.GetBalanceRequest{AccountId: idString(id)})
	if err != nil {
		return ledger.Balance{}, FromStatus(err)
	}
	return BalanceFromPB(b), nil
}

// Transfer implements ledger.Ledger.
func (c *Client) Transfer(ctx context.Context, cmd ledger.Transfer) (ledger.Entry, error) {
	e, err := c.c.Transfer(ctx, &ledgerv1.TransferRequest{IdempotencyKey: cmd.IdempotencyKey, Kind: cmd.Kind,
		RefType: cmd.RefType, RefId: cmd.RefID, Memo: cmd.Memo, Postings: postingsToPB(cmd.Postings)})
	if err != nil {
		return ledger.Entry{}, FromStatus(err)
	}
	return EntryFromPB(e), nil
}

// Reverse implements ledger.Ledger.
func (c *Client) Reverse(ctx context.Context, cmd ledger.Reverse) (ledger.Entry, error) {
	e, err := c.c.Reverse(ctx, &ledgerv1.ReverseRequest{IdempotencyKey: cmd.IdempotencyKey,
		EntryId: idString(cmd.EntryID), Memo: cmd.Memo})
	if err != nil {
		return ledger.Entry{}, FromStatus(err)
	}
	return EntryFromPB(e), nil
}

// Entry implements ledger.Ledger.
func (c *Client) Entry(ctx context.Context, id uuid.UUID) (ledger.Entry, error) {
	e, err := c.c.GetEntry(ctx, &ledgerv1.GetEntryRequest{EntryId: idString(id)})
	if err != nil {
		return ledger.Entry{}, FromStatus(err)
	}
	return EntryFromPB(e), nil
}

// History implements ledger.Ledger.
func (c *Client) History(ctx context.Context, q ledger.HistoryQuery) (ledger.HistoryPage, error) {
	p, err := c.c.ListHistory(ctx, &ledgerv1.ListHistoryRequest{AccountId: idString(q.AccountID),
		Before: idPtrString(q.Before), Limit: int32(q.Limit)})
	if err != nil {
		return ledger.HistoryPage{}, FromStatus(err)
	}
	page := ledger.HistoryPage{Next: mustIDPtr(p.GetNext())}
	for _, e := range p.GetEntries() {
		page.Entries = append(page.Entries, EntryFromPB(e))
	}
	return page, nil
}

// PlaceHold implements ledger.Ledger.
func (c *Client) PlaceHold(ctx context.Context, cmd ledger.PlaceHold) (ledger.Hold, error) {
	h, err := c.c.PlaceHold(ctx, &ledgerv1.PlaceHoldRequest{IdempotencyKey: cmd.IdempotencyKey,
		AccountId: idString(cmd.AccountID), Amount: cmd.Amount, Reason: cmd.Reason, ExpiresAt: ts(cmd.ExpiresAt),
		RefType: cmd.RefType, RefId: cmd.RefID})
	if err != nil {
		return ledger.Hold{}, FromStatus(err)
	}
	return HoldFromPB(h), nil
}

// PostHold implements ledger.Ledger.
func (c *Client) PostHold(ctx context.Context, cmd ledger.PostHold) (ledger.PostHoldResult, error) {
	r, err := c.c.PostHold(ctx, &ledgerv1.PostHoldRequest{IdempotencyKey: cmd.IdempotencyKey,
		HoldId: idString(cmd.HoldID), Kind: cmd.Kind, Memo: cmd.Memo, Credits: postingsToPB(cmd.Credits)})
	if err != nil {
		return ledger.PostHoldResult{}, FromStatus(err)
	}
	return ledger.PostHoldResult{Hold: HoldFromPB(r.GetHold()), Entry: EntryFromPB(r.GetEntry())}, nil
}

// VoidHold implements ledger.Ledger.
func (c *Client) VoidHold(ctx context.Context, cmd ledger.VoidHold) (ledger.Hold, error) {
	h, err := c.c.VoidHold(ctx, &ledgerv1.VoidHoldRequest{IdempotencyKey: cmd.IdempotencyKey,
		HoldId: idString(cmd.HoldID), Reason: cmd.Reason})
	if err != nil {
		return ledger.Hold{}, FromStatus(err)
	}
	return HoldFromPB(h), nil
}

// Hold implements ledger.Ledger.
func (c *Client) Hold(ctx context.Context, id uuid.UUID) (ledger.Hold, error) {
	h, err := c.c.GetHold(ctx, &ledgerv1.GetHoldRequest{HoldId: idString(id)})
	if err != nil {
		return ledger.Hold{}, FromStatus(err)
	}
	return HoldFromPB(h), nil
}

// ExpireHolds implements ledger.Ledger.
func (c *Client) ExpireHolds(ctx context.Context, limit int) ([]ledger.Hold, error) {
	r, err := c.c.ExpireHolds(ctx, &ledgerv1.ExpireHoldsRequest{Limit: int32(limit)})
	if err != nil {
		return nil, FromStatus(err)
	}
	out := make([]ledger.Hold, 0, len(r.GetHolds()))
	for _, h := range r.GetHolds() {
		out = append(out, HoldFromPB(h))
	}
	return out, nil
}

// OpenReserve implements ledger.Ledger.
func (c *Client) OpenReserve(ctx context.Context, cmd ledger.OpenReserve) (ledger.OpenReserveResult, error) {
	r, err := c.c.OpenReserve(ctx, &ledgerv1.OpenReserveRequest{IdempotencyKey: cmd.IdempotencyKey,
		ReserveId: idString(cmd.ReserveID), Kind: string(cmd.Kind), FundingAccountId: idString(cmd.FundingAccountID),
		Amount: cmd.Amount, Purpose: cmd.Purpose, RefType: cmd.RefType, RefId: cmd.RefID,
		ExpiresAt: tsPtr(cmd.ExpiresAt), Memo: cmd.Memo})
	if err != nil {
		return ledger.OpenReserveResult{}, FromStatus(err)
	}
	return ledger.OpenReserveResult{Reserve: ReserveFromPB(r.GetReserve()), Entry: EntryFromPB(r.GetEntry())}, nil
}

// ReleaseReserve implements ledger.Ledger.
func (c *Client) ReleaseReserve(ctx context.Context, cmd ledger.ReleaseReserve) (ledger.ReleaseReserveResult, error) {
	r, err := c.c.ReleaseReserve(ctx, &ledgerv1.ReleaseReserveRequest{IdempotencyKey: cmd.IdempotencyKey,
		ReserveId: idString(cmd.ReserveID), Memo: cmd.Memo})
	if err != nil {
		return ledger.ReleaseReserveResult{}, FromStatus(err)
	}
	out := ledger.ReleaseReserveResult{Reserve: ReserveFromPB(r.GetReserve())}
	if r.GetEntry() != nil {
		e := EntryFromPB(r.GetEntry())
		out.Entry = &e
	}
	return out, nil
}

// Reserve implements ledger.Ledger.
func (c *Client) Reserve(ctx context.Context, id uuid.UUID) (ledger.Reserve, error) {
	r, err := c.c.GetReserve(ctx, &ledgerv1.GetReserveRequest{ReserveId: idString(id)})
	if err != nil {
		return ledger.Reserve{}, FromStatus(err)
	}
	return ReserveFromPB(r), nil
}
