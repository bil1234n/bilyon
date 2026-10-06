package intents

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// Event topics. The realtime gateway turns them into frames (§4.4.5):
// held → THROW_ACK(held) to the payer's device and the authoritative
// INCOMING to the payee; aborted → THROW_ACK(rejected); settled → SETTLED;
// voided → ABORTED (the boomerang).
const (
	EventSource       = "bilyon.gateway"
	TopicHeld         = "gateway.intent.held"
	TopicDelivered    = "gateway.intent.delivered"
	TopicCaught       = "gateway.intent.caught"
	TopicSettled      = "gateway.intent.settled"
	TopicAsyncPending = "gateway.intent.async_pending"
	TopicVoided       = "gateway.intent.voided"
	TopicAborted      = "gateway.intent.aborted"
)

func ms(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}

// EventData is an intent as events carry it. Times are Unix milliseconds
// in server time, which is what the realtime protocol schedules against.
func EventData(in *Intent) map[string]any {
	d := map[string]any{
		"intent_id": in.ID, "state": in.State, "gesture": in.Gesture, "payer_id": in.PayerID,
		"payer_subject": in.PayerSubject, "payer_device_id": in.PayerDeviceID, "amount": in.Amount,
		"currency": in.Currency, "payee_amount": in.PayeeAmount, "payee_currency": in.PayeeCurrency,
		"t_land_ms": ms(in.TLand), "live_until_ms": ms(in.LiveUntil), "claim_until_ms": ms(in.ClaimUntil),
		"entry_ids": in.EntryIDs, "at_ms": in.UpdatedAt.UnixMilli(),
	}
	if in.Reason != "" {
		d["reason"] = in.Reason
	}
	if in.PayeeSubject != "" {
		d["payee_id"], d["payee_subject"] = nullUUID(in.PayeeID), in.PayeeSubject
	}
	if in.QuoteID != [16]byte{} {
		d["quote_id"] = in.QuoteID
	}
	if in.Trajectory != nil {
		d["trajectory"] = in.Trajectory
	}
	return d
}

func emit(ctx context.Context, tx pgx.Tx, topic string, in *Intent) error {
	_, err := outbox.Write(ctx, tx, outbox.Event{Source: EventSource, Topic: topic, Key: "intent:" + in.ID.String(),
		Subject: in.ID.String(), Data: EventData(in)})
	return err
}
