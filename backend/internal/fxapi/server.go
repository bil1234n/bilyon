package fxapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	fxv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/fx/v1"
	"github.com/bil1234n/bilyon/backend/internal/fx"
)

// Server implements bilyon.fx.v1 over an engine. Only the elected
// instance serves: until ready reports true, every call fails with
// UNAVAILABLE (reason STANDBY) so clients retry against the leader.
type Server struct {
	fxv1.UnimplementedFXServiceServer
	fxv1.UnimplementedFXAdminServiceServer
	eng   *fx.Engine
	ready func() bool
	log   *slog.Logger
}

// NewServer returns a server; ready gates service (nil: always ready).
func NewServer(eng *fx.Engine, ready func() bool, log *slog.Logger) *Server {
	if ready == nil {
		ready = func() bool { return true }
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{eng: eng, ready: ready, log: log}
}

func (s *Server) gate() error {
	if !s.ready() {
		return ToStatus(ErrUnavailable)
	}
	return nil
}

// CreateQuote implements FXService.
func (s *Server) CreateQuote(ctx context.Context, r *fxv1.CreateQuoteRequest) (*fxv1.Quote, error) {
	if err := s.gate(); err != nil {
		return nil, err
	}
	user, err := parseUUID("user_id", r.GetUserId(), true)
	if err != nil {
		return nil, ToStatus(err)
	}
	q, err := s.eng.Quote(ctx, fx.QuoteRequest{UserID: user, From: r.GetFrom(), To: r.GetTo(), AmountIn: r.GetAmountIn(),
		TTL: time.Duration(r.GetTtlMs()) * time.Millisecond})
	if err != nil {
		return nil, ToStatus(err)
	}
	return quoteToPB(q), nil
}

// GetQuote implements FXService.
func (s *Server) GetQuote(ctx context.Context, r *fxv1.GetQuoteRequest) (*fxv1.GetQuoteResponse, error) {
	if err := s.gate(); err != nil {
		return nil, err
	}
	user, err := parseUUID("user_id", r.GetUserId(), true)
	if err != nil {
		return nil, ToStatus(err)
	}
	id, err := parseUUID("quote_id", r.GetQuoteId(), true)
	if err != nil {
		return nil, ToStatus(err)
	}
	q, x, err := s.eng.Get(ctx, user, id)
	if err != nil {
		return nil, ToStatus(err)
	}
	out := &fxv1.GetQuoteResponse{Quote: quoteToPB(q)}
	if x != nil {
		out.Execution = executionToPB(*x)
	}
	return out, nil
}

// ExecuteQuote implements FXService.
func (s *Server) ExecuteQuote(ctx context.Context, r *fxv1.ExecuteQuoteRequest) (*fxv1.Execution, error) {
	if err := s.gate(); err != nil {
		return nil, err
	}
	req := fx.ExecuteRequest{Signature: r.GetSignature()}
	var err error
	ids := []struct {
		field    string
		value    string
		dst      *uuid.UUID
		required bool
	}{{"quote_id", r.GetQuoteId(), &req.QuoteID, true}, {"user_id", r.GetUserId(), &req.UserID, true},
		{"hold_id", r.GetHoldId(), &req.HoldID, false}, {"source_account", r.GetSourceAccount(), &req.SourceAccount, false},
		{"destination_account", r.GetDestinationAccount(), &req.DestinationAccount, true}}
	for _, f := range ids {
		if *f.dst, err = parseUUID(f.field, f.value, f.required); err != nil {
			return nil, ToStatus(err)
		}
	}
	x, err := s.eng.Execute(ctx, req)
	if err != nil {
		return nil, ToStatus(err)
	}
	return executionToPB(x), nil
}

// ListEdges implements FXAdminService.
func (s *Server) ListEdges(context.Context, *fxv1.ListEdgesRequest) (*fxv1.ListEdgesResponse, error) {
	out := &fxv1.ListEdgesResponse{}
	for _, e := range s.eng.Graph().Edges() {
		out.Edges = append(out.Edges, edgeToPB(e))
	}
	return out, nil
}

// SetEdgeEnabled implements FXAdminService (corridor halts and resumptions;
// the reason is logged for the audit trail).
func (s *Server) SetEdgeEnabled(ctx context.Context, r *fxv1.SetEdgeEnabledRequest) (*fxv1.Edge, error) {
	if r.GetReason() == "" {
		return nil, ToStatus(fx.ErrRequest)
	}
	if err := s.eng.Graph().SetEnabled(r.GetEdgeId(), r.GetEnabled()); err != nil {
		return nil, ToStatus(err)
	}
	s.log.InfoContext(ctx, "edge switched", slog.String("edge", r.GetEdgeId()), slog.Bool("enabled", r.GetEnabled()),
		slog.String("reason", r.GetReason()))
	for _, e := range s.eng.Graph().Edges() {
		if e.Spec.ID == r.GetEdgeId() {
			return edgeToPB(e), nil
		}
	}
	return nil, ToStatus(fx.ErrUnknownEdge)
}
