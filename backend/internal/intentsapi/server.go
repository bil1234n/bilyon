package intentsapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	intentsv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/intents/v1"
	"github.com/bil1234n/bilyon/backend/internal/intents"
)

// Server implements bilyon.intents.v1 over the orchestrator. It trusts the
// actor its caller names: register it only behind the mTLS ACL that admits
// the realtime gateway.
type Server struct {
	intentsv1.UnimplementedIntentServiceServer
	svc *intents.Service
	log *slog.Logger
}

// NewServer returns a server over svc.
func NewServer(svc *intents.Service, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{svc: svc, log: log}
}

func actor(a *intentsv1.Actor, needDevice bool) (uuid.UUID, uuid.UUID, error) {
	if a == nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%w: actor is required", intents.ErrRequest)
	}
	user, err := parseUUID("actor.user_id", a.GetUserId(), true)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	device, err := parseUUID("actor.device_id", a.GetDeviceId(), needDevice)
	return user, device, err
}

func (s *Server) reply(in *intents.Intent, err error) (*intentsv1.Intent, error) {
	if err != nil {
		return nil, ToStatus(err)
	}
	return IntentToPB(in), nil
}

// IssueNonces implements IntentService.
func (s *Server) IssueNonces(ctx context.Context, r *intentsv1.IssueNoncesRequest) (*intentsv1.IssueNoncesResponse, error) {
	user, device, err := actor(r.GetActor(), true)
	if err != nil {
		return nil, ToStatus(err)
	}
	ns, err := s.svc.IssueNonces(ctx, user, device, int(r.GetCount()))
	if err != nil {
		return nil, ToStatus(err)
	}
	out := &intentsv1.IssueNoncesResponse{}
	for _, n := range ns {
		out.Nonces = append(out.Nonces, &intentsv1.Nonce{Value: n.Value[:], ExpiresAt: timestamppb.New(n.ExpiresAt)})
	}
	return out, nil
}

// CreateIntent implements IntentService.
func (s *Server) CreateIntent(ctx context.Context, r *intentsv1.CreateIntentRequest) (*intentsv1.Intent, error) {
	user, _, err := actor(r.GetActor(), false)
	if err != nil {
		return nil, ToStatus(err)
	}
	quote, err := parseUUID("quote_id", r.GetQuoteId(), false)
	if err != nil {
		return nil, ToStatus(err)
	}
	req := intents.CreateRequest{SubmitterID: user, TxAuth: r.GetTxauth(), Gesture: intents.Gesture(r.GetGesture()),
		PayeeSubject: r.GetPayeeSubject(), Amount: r.GetAmount(), Currency: r.GetCurrency(), QuoteID: quote,
		Trajectory: trajectoryFromPB(r.GetTrajectory()), OnTimeout: intents.Timeout(r.GetOnTimeout())}
	if ms := r.GetTLandMs(); ms != 0 {
		req.TLand = time.UnixMilli(ms).UTC()
	}
	in, err := s.svc.Create(ctx, req)
	if err != nil {
		s.log.InfoContext(ctx, "intent refused", "err", err)
	}
	return s.reply(in, err)
}

func (s *Server) ref(r *intentsv1.IntentRef) (uuid.UUID, uuid.UUID, error) {
	user, _, err := actor(r.GetActor(), false)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	id, err := parseUUID("intent_id", r.GetIntentId(), true)
	return user, id, err
}

// GetIntent implements IntentService.
func (s *Server) GetIntent(ctx context.Context, r *intentsv1.IntentRef) (*intentsv1.Intent, error) {
	user, id, err := s.ref(r)
	if err != nil {
		return nil, ToStatus(err)
	}
	return s.reply(s.svc.Get(ctx, user, id))
}

// ListIntents implements IntentService.
func (s *Server) ListIntents(ctx context.Context, r *intentsv1.ListIntentsRequest) (*intentsv1.ListIntentsResponse, error) {
	user, _, err := actor(r.GetActor(), false)
	if err != nil {
		return nil, ToStatus(err)
	}
	before, err := parseUUID("before", r.GetBefore(), false)
	if err != nil {
		return nil, ToStatus(err)
	}
	q := intents.ListQuery{UserID: user, Role: intents.Role(r.GetRole()), Before: before, Limit: int(r.GetLimit())}
	for _, st := range r.GetStates() {
		q.States = append(q.States, intents.State(st))
	}
	list, err := s.svc.List(ctx, q)
	if err != nil {
		return nil, ToStatus(err)
	}
	out := &intentsv1.ListIntentsResponse{}
	for _, in := range list {
		out.Intents = append(out.Intents, IntentToPB(in))
	}
	return out, nil
}

// MarkDelivered implements IntentService.
func (s *Server) MarkDelivered(ctx context.Context, r *intentsv1.IntentRef) (*intentsv1.Intent, error) {
	user, id, err := s.ref(r)
	if err != nil {
		return nil, ToStatus(err)
	}
	return s.reply(s.svc.MarkDelivered(ctx, user, id))
}

// Catch implements IntentService.
func (s *Server) Catch(ctx context.Context, r *intentsv1.CatchRequest) (*intentsv1.Intent, error) {
	user, _, err := actor(r.GetActor(), false)
	if err != nil {
		return nil, ToStatus(err)
	}
	id, err := parseUUID("intent_id", r.GetIntentId(), true)
	if err != nil {
		return nil, ToStatus(err)
	}
	return s.reply(s.svc.Catch(ctx, intents.CatchRequest{IntentID: id, UserID: user, Accept: r.GetAccept(),
		Proximity: r.GetProximity()}))
}

// Cancel implements IntentService.
func (s *Server) Cancel(ctx context.Context, r *intentsv1.IntentRef) (*intentsv1.Intent, error) {
	user, id, err := s.ref(r)
	if err != nil {
		return nil, ToStatus(err)
	}
	return s.reply(s.svc.Cancel(ctx, user, id))
}
