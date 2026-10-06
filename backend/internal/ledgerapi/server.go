package ledgerapi

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ledgerv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/ledger/v1"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// Server serves bilyon.ledger.v1.LedgerService from a ledger.Ledger.
type Server struct {
	ledgerv1.UnimplementedLedgerServiceServer
	l ledger.Ledger
}

var _ ledgerv1.LedgerServiceServer = (*Server)(nil)

// NewServer returns a server backed by l.
func NewServer(l ledger.Ledger) *Server { return &Server{l: l} }

func optionalTime(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime().UTC()
	return &v
}

// CreateAccount implements LedgerServiceServer.
func (s *Server) CreateAccount(ctx context.Context, r *ledgerv1.CreateAccountRequest) (*ledgerv1.Account, error) {
	cmd := ledger.CreateAccount{IdempotencyKey: r.GetIdempotencyKey(), Kind: ledger.AccountKind(r.GetKind()),
		Currency: r.GetCurrency(), Floor: r.Floor, Stripes: int(r.GetStripes()), Label: r.GetLabel()}
	if id, err := parseOptionalID("account_id", r.GetAccountId()); err != nil {
		return nil, ToStatus(err)
	} else if id != nil {
		cmd.AccountID = *id
	}
	owner, err := parseOptionalID("owner_id", r.GetOwnerId())
	if err != nil {
		return nil, ToStatus(err)
	}
	cmd.OwnerID = owner
	a, err := s.l.CreateAccount(ctx, cmd)
	if err != nil {
		return nil, ToStatus(err)
	}
	return AccountToPB(a), nil
}

// SetFrozen implements LedgerServiceServer.
func (s *Server) SetFrozen(ctx context.Context, r *ledgerv1.SetFrozenRequest) (*ledgerv1.Account, error) {
	id, err := parseID("account_id", r.GetAccountId())
	if err != nil {
		return nil, ToStatus(err)
	}
	a, err := s.l.SetFrozen(ctx, ledger.SetFrozen{IdempotencyKey: r.GetIdempotencyKey(), AccountID: id,
		Frozen: r.GetFrozen(), Reason: r.GetReason()})
	if err != nil {
		return nil, ToStatus(err)
	}
	return AccountToPB(a), nil
}

// GetAccount implements LedgerServiceServer.
func (s *Server) GetAccount(ctx context.Context, r *ledgerv1.GetAccountRequest) (*ledgerv1.Account, error) {
	id, err := parseID("account_id", r.GetAccountId())
	if err != nil {
		return nil, ToStatus(err)
	}
	a, err := s.l.Account(ctx, id)
	if err != nil {
		return nil, ToStatus(err)
	}
	return AccountToPB(a), nil
}

// GetBalance implements LedgerServiceServer.
func (s *Server) GetBalance(ctx context.Context, r *ledgerv1.GetBalanceRequest) (*ledgerv1.Balance, error) {
	id, err := parseID("account_id", r.GetAccountId())
	if err != nil {
		return nil, ToStatus(err)
	}
	b, err := s.l.Balance(ctx, id)
	if err != nil {
		return nil, ToStatus(err)
	}
	return BalanceToPB(b), nil
}

// Transfer implements LedgerServiceServer.
func (s *Server) Transfer(ctx context.Context, r *ledgerv1.TransferRequest) (*ledgerv1.Entry, error) {
	postings, err := postingsFromPB("postings", r.GetPostings())
	if err != nil {
		return nil, ToStatus(err)
	}
	e, err := s.l.Transfer(ctx, ledger.Transfer{IdempotencyKey: r.GetIdempotencyKey(), Kind: r.GetKind(),
		RefType: r.GetRefType(), RefID: r.GetRefId(), Memo: r.GetMemo(), Postings: postings})
	if err != nil {
		return nil, ToStatus(err)
	}
	return EntryToPB(e), nil
}

// Reverse implements LedgerServiceServer.
func (s *Server) Reverse(ctx context.Context, r *ledgerv1.ReverseRequest) (*ledgerv1.Entry, error) {
	id, err := parseID("entry_id", r.GetEntryId())
	if err != nil {
		return nil, ToStatus(err)
	}
	e, err := s.l.Reverse(ctx, ledger.Reverse{IdempotencyKey: r.GetIdempotencyKey(), EntryID: id, Memo: r.GetMemo()})
	if err != nil {
		return nil, ToStatus(err)
	}
	return EntryToPB(e), nil
}

// GetEntry implements LedgerServiceServer.
func (s *Server) GetEntry(ctx context.Context, r *ledgerv1.GetEntryRequest) (*ledgerv1.Entry, error) {
	id, err := parseID("entry_id", r.GetEntryId())
	if err != nil {
		return nil, ToStatus(err)
	}
	e, err := s.l.Entry(ctx, id)
	if err != nil {
		return nil, ToStatus(err)
	}
	return EntryToPB(e), nil
}

// ListHistory implements LedgerServiceServer.
func (s *Server) ListHistory(ctx context.Context, r *ledgerv1.ListHistoryRequest) (*ledgerv1.HistoryPage, error) {
	id, err := parseID("account_id", r.GetAccountId())
	if err != nil {
		return nil, ToStatus(err)
	}
	before, err := parseOptionalID("before", r.GetBefore())
	if err != nil {
		return nil, ToStatus(err)
	}
	page, err := s.l.History(ctx, ledger.HistoryQuery{AccountID: id, Before: before, Limit: int(r.GetLimit())})
	if err != nil {
		return nil, ToStatus(err)
	}
	out := &ledgerv1.HistoryPage{Next: idPtrString(page.Next)}
	for _, e := range page.Entries {
		out.Entries = append(out.Entries, EntryToPB(e))
	}
	return out, nil
}

// PlaceHold implements LedgerServiceServer.
func (s *Server) PlaceHold(ctx context.Context, r *ledgerv1.PlaceHoldRequest) (*ledgerv1.Hold, error) {
	id, err := parseID("account_id", r.GetAccountId())
	if err != nil {
		return nil, ToStatus(err)
	}
	cmd := ledger.PlaceHold{IdempotencyKey: r.GetIdempotencyKey(), AccountID: id, Amount: r.GetAmount(),
		Reason: r.GetReason(), RefType: r.GetRefType(), RefID: r.GetRefId()}
	if exp := optionalTime(r.GetExpiresAt()); exp != nil {
		cmd.ExpiresAt = *exp
	}
	h, err := s.l.PlaceHold(ctx, cmd)
	if err != nil {
		return nil, ToStatus(err)
	}
	return HoldToPB(h), nil
}

// PostHold implements LedgerServiceServer.
func (s *Server) PostHold(ctx context.Context, r *ledgerv1.PostHoldRequest) (*ledgerv1.PostHoldResponse, error) {
	id, err := parseID("hold_id", r.GetHoldId())
	if err != nil {
		return nil, ToStatus(err)
	}
	credits, err := postingsFromPB("credits", r.GetCredits())
	if err != nil {
		return nil, ToStatus(err)
	}
	res, err := s.l.PostHold(ctx, ledger.PostHold{IdempotencyKey: r.GetIdempotencyKey(), HoldID: id, Kind: r.GetKind(),
		Memo: r.GetMemo(), Credits: credits})
	if err != nil {
		return nil, ToStatus(err)
	}
	return &ledgerv1.PostHoldResponse{Hold: HoldToPB(res.Hold), Entry: EntryToPB(res.Entry)}, nil
}

// VoidHold implements LedgerServiceServer.
func (s *Server) VoidHold(ctx context.Context, r *ledgerv1.VoidHoldRequest) (*ledgerv1.Hold, error) {
	id, err := parseID("hold_id", r.GetHoldId())
	if err != nil {
		return nil, ToStatus(err)
	}
	h, err := s.l.VoidHold(ctx, ledger.VoidHold{IdempotencyKey: r.GetIdempotencyKey(), HoldID: id, Reason: r.GetReason()})
	if err != nil {
		return nil, ToStatus(err)
	}
	return HoldToPB(h), nil
}

// GetHold implements LedgerServiceServer.
func (s *Server) GetHold(ctx context.Context, r *ledgerv1.GetHoldRequest) (*ledgerv1.Hold, error) {
	id, err := parseID("hold_id", r.GetHoldId())
	if err != nil {
		return nil, ToStatus(err)
	}
	h, err := s.l.Hold(ctx, id)
	if err != nil {
		return nil, ToStatus(err)
	}
	return HoldToPB(h), nil
}

// ExpireHolds implements LedgerServiceServer.
func (s *Server) ExpireHolds(ctx context.Context, r *ledgerv1.ExpireHoldsRequest) (*ledgerv1.ExpireHoldsResponse, error) {
	holds, err := s.l.ExpireHolds(ctx, int(r.GetLimit()))
	if err != nil {
		return nil, ToStatus(err)
	}
	out := &ledgerv1.ExpireHoldsResponse{}
	for _, h := range holds {
		out.Holds = append(out.Holds, HoldToPB(h))
	}
	return out, nil
}

// OpenReserve implements LedgerServiceServer.
func (s *Server) OpenReserve(ctx context.Context, r *ledgerv1.OpenReserveRequest) (*ledgerv1.OpenReserveResponse, error) {
	funding, err := parseID("funding_account_id", r.GetFundingAccountId())
	if err != nil {
		return nil, ToStatus(err)
	}
	cmd := ledger.OpenReserve{IdempotencyKey: r.GetIdempotencyKey(), Kind: ledger.AccountKind(r.GetKind()),
		FundingAccountID: funding, Amount: r.GetAmount(), Purpose: r.GetPurpose(), RefType: r.GetRefType(),
		RefID: r.GetRefId(), ExpiresAt: optionalTime(r.GetExpiresAt()), Memo: r.GetMemo()}
	if id, err := parseOptionalID("reserve_id", r.GetReserveId()); err != nil {
		return nil, ToStatus(err)
	} else if id != nil {
		cmd.ReserveID = *id
	}
	res, err := s.l.OpenReserve(ctx, cmd)
	if err != nil {
		return nil, ToStatus(err)
	}
	return &ledgerv1.OpenReserveResponse{Reserve: ReserveToPB(res.Reserve), Entry: EntryToPB(res.Entry)}, nil
}

// ReleaseReserve implements LedgerServiceServer.
func (s *Server) ReleaseReserve(ctx context.Context, r *ledgerv1.ReleaseReserveRequest) (*ledgerv1.ReleaseReserveResponse, error) {
	id, err := parseID("reserve_id", r.GetReserveId())
	if err != nil {
		return nil, ToStatus(err)
	}
	res, err := s.l.ReleaseReserve(ctx, ledger.ReleaseReserve{IdempotencyKey: r.GetIdempotencyKey(), ReserveID: id,
		Memo: r.GetMemo()})
	if err != nil {
		return nil, ToStatus(err)
	}
	out := &ledgerv1.ReleaseReserveResponse{Reserve: ReserveToPB(res.Reserve)}
	if res.Entry != nil {
		out.Entry = EntryToPB(*res.Entry)
	}
	return out, nil
}

// GetReserve implements LedgerServiceServer.
func (s *Server) GetReserve(ctx context.Context, r *ledgerv1.GetReserveRequest) (*ledgerv1.Reserve, error) {
	id, err := parseID("reserve_id", r.GetReserveId())
	if err != nil {
		return nil, ToStatus(err)
	}
	res, err := s.l.Reserve(ctx, id)
	if err != nil {
		return nil, ToStatus(err)
	}
	return ReserveToPB(res), nil
}
