package intentsapi

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	intentsv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/intents/v1"
	"github.com/bil1234n/bilyon/backend/internal/intents"
)

// Client calls the intent service.
type Client struct {
	c intentsv1.IntentServiceClient
}

// NewClient wraps a connection to the gateway's internal gRPC listener.
func NewClient(conn grpc.ClientConnInterface) *Client {
	return &Client{c: intentsv1.NewIntentServiceClient(conn)}
}

// RetryServiceConfig retries UNAVAILABLE: every call is idempotent, and an
// intent whose ledger step was interrupted completes on the retry.
var RetryServiceConfig = func() string {
	cfg := map[string]any{"methodConfig": []any{map[string]any{
		"name": []any{map[string]any{"service": intentsv1.IntentService_ServiceDesc.ServiceName}},
		"retryPolicy": map[string]any{"maxAttempts": 4, "initialBackoff": "0.05s", "maxBackoff": "1s",
			"backoffMultiplier": 2.0, "retryableStatusCodes": []string{"UNAVAILABLE"}},
	}}}
	raw, _ := json.Marshal(cfg)
	return string(raw)
}()

func pbActor(user, device uuid.UUID) *intentsv1.Actor {
	return &intentsv1.Actor{UserId: user.String(), DeviceId: optUUID(device)}
}

func (c *Client) intent(p *intentsv1.Intent, err error) (*intents.Intent, error) {
	if err != nil {
		return nil, FromStatus(err)
	}
	return IntentFromPB(p)
}

// IssueNonces fetches a batch of server nonces for the user's device.
func (c *Client) IssueNonces(ctx context.Context, user, device uuid.UUID, n int) ([]intents.Nonce, error) {
	p, err := c.c.IssueNonces(ctx, &intentsv1.IssueNoncesRequest{Actor: pbActor(user, device), Count: int32(n)})
	if err != nil {
		return nil, FromStatus(err)
	}
	out := make([]intents.Nonce, 0, len(p.GetNonces()))
	for _, n := range p.GetNonces() {
		if len(n.GetValue()) != 16 || n.GetExpiresAt() == nil {
			return nil, fmt.Errorf("intents: malformed nonce in response")
		}
		var v intents.Nonce
		copy(v.Value[:], n.GetValue())
		v.ExpiresAt = n.GetExpiresAt().AsTime().UTC()
		out = append(out, v)
	}
	return out, nil
}

// Create submits a signed intent.
func (c *Client) Create(ctx context.Context, r intents.CreateRequest) (*intents.Intent, error) {
	req := &intentsv1.CreateIntentRequest{Actor: pbActor(r.SubmitterID, uuid.Nil), Txauth: r.TxAuth,
		Gesture: string(r.Gesture), PayeeSubject: r.PayeeSubject, Amount: r.Amount, Currency: r.Currency,
		QuoteId: optUUID(r.QuoteID), Trajectory: trajectoryToPB(r.Trajectory), OnTimeout: string(r.OnTimeout)}
	if !r.TLand.IsZero() {
		req.TLandMs = r.TLand.UnixMilli()
	}
	return c.intent(c.c.CreateIntent(ctx, req))
}

// Get returns an intent the user is party to.
func (c *Client) Get(ctx context.Context, user, id uuid.UUID) (*intents.Intent, error) {
	return c.intent(c.c.GetIntent(ctx, &intentsv1.IntentRef{Actor: pbActor(user, uuid.Nil), IntentId: id.String()}))
}

// List returns a page of the user's intents.
func (c *Client) List(ctx context.Context, q intents.ListQuery) ([]*intents.Intent, error) {
	req := &intentsv1.ListIntentsRequest{Actor: pbActor(q.UserID, uuid.Nil), Role: string(q.Role),
		Before: optUUID(q.Before), Limit: int32(q.Limit)}
	for _, st := range q.States {
		req.States = append(req.States, string(st))
	}
	p, err := c.c.ListIntents(ctx, req)
	if err != nil {
		return nil, FromStatus(err)
	}
	out := make([]*intents.Intent, 0, len(p.GetIntents()))
	for _, pi := range p.GetIntents() {
		in, err := IntentFromPB(pi)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, nil
}

// MarkDelivered records that INCOMING reached the payee's device.
func (c *Client) MarkDelivered(ctx context.Context, user, id uuid.UUID) (*intents.Intent, error) {
	return c.intent(c.c.MarkDelivered(ctx, &intentsv1.IntentRef{Actor: pbActor(user, uuid.Nil), IntentId: id.String()}))
}

// Catch accepts, declines or grabs an intent.
func (c *Client) Catch(ctx context.Context, r intents.CatchRequest) (*intents.Intent, error) {
	return c.intent(c.c.Catch(ctx, &intentsv1.CatchRequest{Actor: pbActor(r.UserID, uuid.Nil), IntentId: r.IntentID.String(),
		Accept: r.Accept, Proximity: r.Proximity}))
}

// Cancel returns an uncaught intent to its payer.
func (c *Client) Cancel(ctx context.Context, user, id uuid.UUID) (*intents.Intent, error) {
	return c.intent(c.c.Cancel(ctx, &intentsv1.IntentRef{Actor: pbActor(user, uuid.Nil), IntentId: id.String()}))
}
