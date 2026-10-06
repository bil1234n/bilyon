// Package ledgerapi exposes the ledger over gRPC (bilyon.ledger.v1) and
// provides a client that implements ledger.Ledger on top of it, so services
// use the same interface whether the ledger is local or remote.
package ledgerapi

import (
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	ledgerv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/ledger/v1"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

func idString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

func idPtrString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// parseID parses a required UUID field.
func parseID(field, s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil || id.String() != s {
		return uuid.Nil, &ledger.ValidationError{Field: field, Reason: "must be a canonical UUID"}
	}
	return id, nil
}

// parseOptionalID parses a UUID field that may be empty.
func parseOptionalID(field, s string) (*uuid.UUID, error) {
	if s == "" {
		return nil, nil
	}
	id, err := parseID(field, s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func tsPtr(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func fromTS(t *timestamppb.Timestamp) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.AsTime().UTC()
}

func fromTSPtr(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime().UTC()
	return &v
}

// mustID parses an id the server produced; a malformed one is a protocol
// violation and becomes uuid.Nil (callers never see a zero id from a
// correct server).
func mustID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}

func mustIDPtr(s string) *uuid.UUID {
	if s == "" {
		return nil
	}
	id := mustID(s)
	return &id
}

// AccountToPB converts an account.
func AccountToPB(a ledger.Account) *ledgerv1.Account {
	return &ledgerv1.Account{Id: idString(a.ID), OwnerId: idPtrString(a.OwnerID), Kind: string(a.Kind),
		Currency: a.Currency, Floor: a.Floor, Stripes: int32(a.Stripes), Frozen: a.Frozen, Label: a.Label,
		CreatedAt: ts(a.CreatedAt)}
}

// AccountFromPB converts an account.
func AccountFromPB(p *ledgerv1.Account) ledger.Account {
	return ledger.Account{ID: mustID(p.GetId()), OwnerID: mustIDPtr(p.GetOwnerId()), Kind: ledger.AccountKind(p.GetKind()),
		Currency: p.GetCurrency(), Floor: p.Floor, Stripes: int(p.GetStripes()), Frozen: p.GetFrozen(),
		Label: p.GetLabel(), CreatedAt: fromTS(p.GetCreatedAt())}
}

// BalanceToPB converts a balance.
func BalanceToPB(b ledger.Balance) *ledgerv1.Balance {
	return &ledgerv1.Balance{AccountId: idString(b.AccountID), Currency: b.Currency, Posted: b.Posted,
		Pending: b.Pending, Available: b.Available, Floor: b.Floor, Frozen: b.Frozen}
}

// BalanceFromPB converts a balance.
func BalanceFromPB(p *ledgerv1.Balance) ledger.Balance {
	return ledger.Balance{AccountID: mustID(p.GetAccountId()), Currency: p.GetCurrency(), Posted: p.GetPosted(),
		Pending: p.GetPending(), Available: p.GetAvailable(), Floor: p.Floor, Frozen: p.GetFrozen()}
}

// EntryToPB converts an entry.
func EntryToPB(e ledger.Entry) *ledgerv1.Entry {
	out := &ledgerv1.Entry{Id: idString(e.ID), IdempotencyKey: e.IdempotencyKey, Kind: e.Kind, RefType: e.RefType,
		RefId: e.RefID, Memo: e.Memo, Reverses: idPtrString(e.Reverses), HoldId: idPtrString(e.HoldID),
		CreatedAt: ts(e.CreatedAt)}
	for _, p := range e.Postings {
		out.Postings = append(out.Postings, &ledgerv1.PostingRecord{Seq: int32(p.Seq), AccountId: idString(p.AccountID),
			Stripe: int32(p.Stripe), Currency: p.Currency, Amount: p.Amount})
	}
	return out
}

// EntryFromPB converts an entry.
func EntryFromPB(p *ledgerv1.Entry) ledger.Entry {
	e := ledger.Entry{ID: mustID(p.GetId()), IdempotencyKey: p.GetIdempotencyKey(), Kind: p.GetKind(),
		RefType: p.GetRefType(), RefID: p.GetRefId(), Memo: p.GetMemo(), Reverses: mustIDPtr(p.GetReverses()),
		HoldID: mustIDPtr(p.GetHoldId()), CreatedAt: fromTS(p.GetCreatedAt())}
	for _, r := range p.GetPostings() {
		e.Postings = append(e.Postings, ledger.PostingRecord{Seq: int(r.GetSeq()), AccountID: mustID(r.GetAccountId()),
			Stripe: int(r.GetStripe()), Currency: r.GetCurrency(), Amount: r.GetAmount()})
	}
	return e
}

// HoldToPB converts a hold.
func HoldToPB(h ledger.Hold) *ledgerv1.Hold {
	return &ledgerv1.Hold{Id: idString(h.ID), IdempotencyKey: h.IdempotencyKey, AccountId: idString(h.AccountID),
		Currency: h.Currency, Amount: h.Amount, Reason: h.Reason, State: string(h.State), ExpiresAt: ts(h.ExpiresAt),
		PostedAmount: h.PostedAmount, EntryId: idPtrString(h.EntryID), RefType: h.RefType, RefId: h.RefID,
		ResolutionNote: h.ResolutionNote, CreatedAt: ts(h.CreatedAt), ResolvedAt: tsPtr(h.ResolvedAt)}
}

// HoldFromPB converts a hold.
func HoldFromPB(p *ledgerv1.Hold) ledger.Hold {
	return ledger.Hold{ID: mustID(p.GetId()), IdempotencyKey: p.GetIdempotencyKey(), AccountID: mustID(p.GetAccountId()),
		Currency: p.GetCurrency(), Amount: p.GetAmount(), Reason: p.GetReason(), State: ledger.HoldState(p.GetState()),
		ExpiresAt: fromTS(p.GetExpiresAt()), PostedAmount: p.GetPostedAmount(), EntryID: mustIDPtr(p.GetEntryId()),
		RefType: p.GetRefType(), RefID: p.GetRefId(), ResolutionNote: p.GetResolutionNote(),
		CreatedAt: fromTS(p.GetCreatedAt()), ResolvedAt: fromTSPtr(p.GetResolvedAt())}
}

// ReserveToPB converts a reserve.
func ReserveToPB(r ledger.Reserve) *ledgerv1.Reserve {
	return &ledgerv1.Reserve{Id: idString(r.ID), FundingAccountId: idString(r.FundingAccountID), Currency: r.Currency,
		Purpose: r.Purpose, RefType: r.RefType, RefId: r.RefID, State: string(r.State),
		OpenedEntryId: idString(r.OpenedEntryID), ClosedEntryId: idPtrString(r.ClosedEntryID),
		ExpiresAt: tsPtr(r.ExpiresAt), CreatedAt: ts(r.CreatedAt), ClosedAt: tsPtr(r.ClosedAt)}
}

// ReserveFromPB converts a reserve.
func ReserveFromPB(p *ledgerv1.Reserve) ledger.Reserve {
	return ledger.Reserve{ID: mustID(p.GetId()), FundingAccountID: mustID(p.GetFundingAccountId()),
		Currency: p.GetCurrency(), Purpose: p.GetPurpose(), RefType: p.GetRefType(), RefID: p.GetRefId(),
		State: ledger.ReserveState(p.GetState()), OpenedEntryID: mustID(p.GetOpenedEntryId()),
		ClosedEntryID: mustIDPtr(p.GetClosedEntryId()), ExpiresAt: fromTSPtr(p.GetExpiresAt()),
		CreatedAt: fromTS(p.GetCreatedAt()), ClosedAt: fromTSPtr(p.GetClosedAt())}
}

func postingsToPB(ps []ledger.Posting) []*ledgerv1.Posting {
	out := make([]*ledgerv1.Posting, len(ps))
	for i, p := range ps {
		out[i] = &ledgerv1.Posting{AccountId: idString(p.AccountID), Amount: p.Amount}
	}
	return out
}

func postingsFromPB(field string, ps []*ledgerv1.Posting) ([]ledger.Posting, error) {
	out := make([]ledger.Posting, len(ps))
	for i, p := range ps {
		id, err := parseID(field+".account_id", p.GetAccountId())
		if err != nil {
			return nil, err
		}
		out[i] = ledger.Posting{AccountID: id, Amount: p.GetAmount()}
	}
	return out, nil
}
