package fxapi

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	fxv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/fx/v1"
	"github.com/bil1234n/bilyon/backend/internal/fx"
)

// Client calls the FX service.
type Client struct {
	c fxv1.FXServiceClient
}

// NewClient wraps a connection to fxd.
func NewClient(conn grpc.ClientConnInterface) *Client {
	return &Client{c: fxv1.NewFXServiceClient(conn)}
}

// RetryServiceConfig retries UNAVAILABLE (a standby answered, or the
// leader is failing over) for the read and quote calls; ExecuteQuote is
// idempotent per quote and retried too.
var RetryServiceConfig = func() string {
	cfg := map[string]any{"methodConfig": []any{map[string]any{
		"name": []any{map[string]any{"service": fxv1.FXService_ServiceDesc.ServiceName}},
		"retryPolicy": map[string]any{"maxAttempts": 5, "initialBackoff": "0.1s", "maxBackoff": "2s",
			"backoffMultiplier": 2.0, "retryableStatusCodes": []string{"UNAVAILABLE"}},
	}}}
	raw, _ := json.Marshal(cfg)
	return string(raw)
}()

// CreateQuote asks for a firm quote.
func (c *Client) CreateQuote(ctx context.Context, r fx.QuoteRequest) (*fx.Quote, error) {
	p, err := c.c.CreateQuote(ctx, &fxv1.CreateQuoteRequest{UserId: r.UserID.String(), From: r.From, To: r.To,
		AmountIn: r.AmountIn, TtlMs: r.TTL.Milliseconds()})
	if err != nil {
		return nil, FromStatus(err)
	}
	return quoteFromPB(p)
}

// GetQuote returns a quote and its execution, if any.
func (c *Client) GetQuote(ctx context.Context, userID, quoteID uuid.UUID) (*fx.Quote, *fx.Execution, error) {
	p, err := c.c.GetQuote(ctx, &fxv1.GetQuoteRequest{UserId: userID.String(), QuoteId: quoteID.String()})
	if err != nil {
		return nil, nil, FromStatus(err)
	}
	q, err := quoteFromPB(p.GetQuote())
	if err != nil {
		return nil, nil, err
	}
	if p.GetExecution() == nil {
		return q, nil, nil
	}
	x, err := executionFromPB(p.GetExecution())
	if err != nil {
		return nil, nil, err
	}
	return q, &x, nil
}

// ExecuteQuote executes a quote (idempotent per quote).
func (c *Client) ExecuteQuote(ctx context.Context, r fx.ExecuteRequest) (fx.Execution, error) {
	p, err := c.c.ExecuteQuote(ctx, &fxv1.ExecuteQuoteRequest{QuoteId: r.QuoteID.String(), Signature: r.Signature,
		UserId: r.UserID.String(), HoldId: optUUID(r.HoldID), SourceAccount: optUUID(r.SourceAccount),
		DestinationAccount: r.DestinationAccount.String()})
	if err != nil {
		return fx.Execution{}, FromStatus(err)
	}
	return executionFromPB(p)
}
