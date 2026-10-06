package intentsapi

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	intentsv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/intents/v1"
	"github.com/bil1234n/bilyon/backend/internal/intents"
)

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func fromTS(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime().UTC()
	return &v
}

func optUUID(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// parseUUID parses a required or optional id field in canonical form.
func parseUUID(field, s string, required bool) (uuid.UUID, error) {
	if s == "" && !required {
		return uuid.Nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil || id.String() != s {
		return uuid.Nil, fmt.Errorf("%w: %s is not a canonical UUID", intents.ErrRequest, field)
	}
	return id, nil
}

func trajectoryToPB(t *intents.Trajectory) *intentsv1.Trajectory {
	if t == nil {
		return nil
	}
	return &intentsv1.Trajectory{Azimuth: t.Azimuth, Speed: t.Speed, Distance: t.Distance}
}

func trajectoryFromPB(t *intentsv1.Trajectory) *intents.Trajectory {
	if t == nil {
		return nil
	}
	return &intents.Trajectory{Azimuth: t.GetAzimuth(), Speed: t.GetSpeed(), Distance: t.GetDistance()}
}

// IntentToPB converts an intent for the wire.
func IntentToPB(in *intents.Intent) *intentsv1.Intent {
	out := &intentsv1.Intent{Id: in.ID.String(), State: string(in.State), Reason: in.Reason, Gesture: string(in.Gesture),
		PayerId: in.PayerID.String(), PayerSubject: in.PayerSubject, PayerDeviceId: in.PayerDeviceID.String(),
		PayeeId: optUUID(in.PayeeID), PayeeSubject: in.PayeeSubject, ParVersion: in.PARVersion, Amount: in.Amount,
		Currency: in.Currency, PayeeAmount: in.PayeeAmount, PayeeCurrency: in.PayeeCurrency, QuoteId: optUUID(in.QuoteID),
		OnTimeout: string(in.OnTimeout), HoldId: optUUID(in.HoldID), SignedAt: ts(&in.SignedAt), TLand: ts(in.TLand),
		LiveUntil: ts(in.LiveUntil), ClaimUntil: ts(in.ClaimUntil), Trajectory: trajectoryToPB(in.Trajectory),
		CreatedAt: ts(&in.CreatedAt), UpdatedAt: ts(&in.UpdatedAt), ResolvedAt: ts(in.ResolvedAt)}
	for _, e := range in.EntryIDs {
		out.EntryIds = append(out.EntryIds, e.String())
	}
	return out
}

// IntentFromPB is the inverse of IntentToPB, for clients. Fields the wire
// does not carry (the TxAuth evidence, per-step timestamps) stay empty.
func IntentFromPB(p *intentsv1.Intent) (*intents.Intent, error) {
	in := &intents.Intent{State: intents.State(p.GetState()), Reason: p.GetReason(), Gesture: intents.Gesture(p.GetGesture()),
		PayerSubject: p.GetPayerSubject(), PayeeSubject: p.GetPayeeSubject(), PARVersion: p.GetParVersion(),
		Amount: p.GetAmount(), Currency: p.GetCurrency(), PayeeAmount: p.GetPayeeAmount(),
		PayeeCurrency: p.GetPayeeCurrency(), OnTimeout: intents.Timeout(p.GetOnTimeout()), TLand: fromTS(p.GetTLand()),
		LiveUntil: fromTS(p.GetLiveUntil()), ClaimUntil: fromTS(p.GetClaimUntil()),
		Trajectory: trajectoryFromPB(p.GetTrajectory()), ResolvedAt: fromTS(p.GetResolvedAt()), EntryIDs: []uuid.UUID{}}
	var err error
	ids := []struct {
		dst      *uuid.UUID
		field, v string
		required bool
	}{{&in.ID, "id", p.GetId(), true}, {&in.PayerID, "payer_id", p.GetPayerId(), true},
		{&in.PayerDeviceID, "payer_device_id", p.GetPayerDeviceId(), true}, {&in.PayeeID, "payee_id", p.GetPayeeId(), false},
		{&in.QuoteID, "quote_id", p.GetQuoteId(), false}, {&in.HoldID, "hold_id", p.GetHoldId(), false}}
	for _, id := range ids {
		if *id.dst, err = parseUUID(id.field, id.v, id.required); err != nil {
			return nil, err
		}
	}
	for _, e := range p.GetEntryIds() {
		id, err := parseUUID("entry_ids", e, true)
		if err != nil {
			return nil, err
		}
		in.EntryIDs = append(in.EntryIDs, id)
	}
	for _, t := range []struct {
		dst *time.Time
		src *timestamppb.Timestamp
	}{{&in.SignedAt, p.GetSignedAt()}, {&in.CreatedAt, p.GetCreatedAt()}, {&in.UpdatedAt, p.GetUpdatedAt()}} {
		if v := fromTS(t.src); v != nil {
			*t.dst = *v
		}
	}
	return in, nil
}
