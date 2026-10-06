package fxapi

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	fxv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/fx/v1"
	"github.com/bil1234n/bilyon/backend/internal/fx"
)

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func fromTS(t *timestamppb.Timestamp) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.AsTime().UTC()
}

func optUUID(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// parseUUID parses a required or optional id field.
func parseUUID(field, s string, required bool) (uuid.UUID, error) {
	if s == "" && !required {
		return uuid.Nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: %s is not a UUID", fx.ErrRequest, field)
	}
	return id, nil
}

func quoteToPB(q *fx.Quote) *fxv1.Quote {
	out := &fxv1.Quote{Id: q.ID.String(), UserId: q.UserID.String(), From: q.From, To: q.To, AmountIn: q.AmountIn,
		AmountOut: q.AmountOut, ExecOut: q.ExecOut, MidRate: q.MidRate, MidOut: q.MidOut, ExecCostBps: q.ExecCostBps,
		BufferBps: q.BufferBps, MarginBps: q.MarginBps, FeeBps: q.FeeBps, State: q.State, CreatedAt: ts(q.CreatedAt),
		ExpiresAt: ts(q.ExpiresAt), KeyId: q.KeyID, Signature: q.Signature}
	for _, a := range q.Allocations {
		out.Allocations = append(out.Allocations, &fxv1.Allocation{EdgeIds: a.EdgeIDs, Venues: a.Venues, In: a.In, Out: a.Out})
	}
	return out
}

func quoteFromPB(p *fxv1.Quote) (*fx.Quote, error) {
	id, err := parseUUID("id", p.GetId(), true)
	if err != nil {
		return nil, err
	}
	user, err := parseUUID("user_id", p.GetUserId(), true)
	if err != nil {
		return nil, err
	}
	q := &fx.Quote{ID: id, UserID: user, From: p.GetFrom(), To: p.GetTo(), AmountIn: p.GetAmountIn(),
		AmountOut: p.GetAmountOut(), ExecOut: p.GetExecOut(), MidRate: p.GetMidRate(), MidOut: p.GetMidOut(),
		ExecCostBps: p.GetExecCostBps(), BufferBps: p.GetBufferBps(), MarginBps: p.GetMarginBps(), FeeBps: p.GetFeeBps(),
		State: p.GetState(), CreatedAt: fromTS(p.GetCreatedAt()), ExpiresAt: fromTS(p.GetExpiresAt()), KeyID: p.GetKeyId(),
		Signature: p.GetSignature()}
	for _, a := range p.GetAllocations() {
		q.Allocations = append(q.Allocations, fx.Allocation{EdgeIDs: a.GetEdgeIds(), Venues: a.GetVenues(), In: a.GetIn(), Out: a.GetOut()})
	}
	return q, nil
}

func executionToPB(x fx.Execution) *fxv1.Execution {
	out := &fxv1.Execution{QuoteId: x.QuoteID.String(), AmountIn: x.AmountIn, AmountOut: x.AmountOut,
		MarketOut: x.MarketOut, Pnl: x.PnL, State: x.State, Failure: x.Failure, ExecutedAt: ts(x.ExecutedAt)}
	if x.BookedAt != nil {
		out.BookedAt = ts(*x.BookedAt)
	}
	for _, id := range x.EntryIDs {
		out.EntryIds = append(out.EntryIds, id.String())
	}
	return out
}

func executionFromPB(p *fxv1.Execution) (fx.Execution, error) {
	id, err := parseUUID("quote_id", p.GetQuoteId(), true)
	if err != nil {
		return fx.Execution{}, err
	}
	x := fx.Execution{QuoteID: id, AmountIn: p.GetAmountIn(), AmountOut: p.GetAmountOut(), MarketOut: p.GetMarketOut(),
		PnL: p.GetPnl(), State: p.GetState(), Failure: p.GetFailure(), ExecutedAt: fromTS(p.GetExecutedAt())}
	if p.GetBookedAt() != nil {
		b := fromTS(p.GetBookedAt())
		x.BookedAt = &b
	}
	for _, s := range p.GetEntryIds() {
		e, err := parseUUID("entry_ids", s, true)
		if err != nil {
			return fx.Execution{}, err
		}
		x.EntryIDs = append(x.EntryIDs, e)
	}
	return x, nil
}

func edgeToPB(e fx.EdgeState) *fxv1.Edge {
	out := &fxv1.Edge{Id: e.Spec.ID, From: e.Spec.From, To: e.Spec.To, Venue: e.Spec.Venue, Depth: e.Depth,
		Reserved: e.Reserved, Executed: e.Executed, UpdatedAt: ts(e.UpdatedAt), Enabled: e.Enabled, Stale: e.Stale,
		QuarantineCycle: e.Quarantined}
	for _, l := range e.Ladder {
		out.Ladder = append(out.Ladder, &fxv1.Level{Size: l.Size, Rate: l.Rate})
	}
	return out
}
