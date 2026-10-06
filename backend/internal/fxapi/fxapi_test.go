package fxapi_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	fxv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/fx/v1"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/fxapi"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/fxdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, fxdb.Setup, &srv)) }

func TestErrorRoundTrip(t *testing.T) {
	t.Parallel()
	for _, sentinel := range []error{fx.ErrUnknownQuote, fx.ErrUnknownEdge, fx.ErrTampered, fx.ErrExpired, fx.ErrRequote,
		fx.ErrFailed, fx.ErrPayoutPending, fx.ErrConflict, fx.ErrFunding, fx.ErrRequest, fx.ErrUnknownCurrency,
		fx.ErrInvalidEdge, fx.ErrPairNotConfigured, fx.ErrNoMid, fx.ErrNoRoute, ledger.ErrUnavailable} {
		wrapped := fmt.Errorf("context: %w", sentinel)
		back := fxapi.FromStatus(fxapi.ToStatus(wrapped))
		if !errors.Is(back, sentinel) {
			t.Errorf("%v did not survive the round trip: %v", sentinel, back)
		}
		if back.Error() != wrapped.Error() {
			t.Errorf("message %q, want %q", back.Error(), wrapped.Error())
		}
	}
	if st := status.Convert(fxapi.ToStatus(errors.New("pq: secret detail"))); st.Code() != codes.Internal || st.Message() != "internal error" {
		t.Errorf("unknown errors leak: %v", st)
	}
	if code := status.Code(fxapi.ToStatus(context.Canceled)); code != codes.Canceled {
		t.Errorf("cancellation: %v", code)
	}
	if code := status.Code(fxapi.ToStatus(context.DeadlineExceeded)); code != codes.DeadlineExceeded {
		t.Errorf("deadline: %v", code)
	}
	if err := fxapi.FromStatus(status.Error(codes.Unavailable, "connection refused")); !errors.Is(err, fxapi.ErrUnavailable) {
		t.Errorf("transport failure: %v", err)
	}
	if err := fxapi.FromStatus(fxapi.ToStatus(fxapi.ErrUnavailable)); !errors.Is(err, fxapi.ErrUnavailable) {
		t.Errorf("standby: %v", err)
	}
	if err := fxapi.FromStatus(errors.New("not a status")); !errors.Is(err, fxapi.ErrUnavailable) {
		t.Errorf("non-status error: %v", err)
	}
	if err := fxapi.FromStatus(status.Error(codes.Canceled, "x")); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled status: %v", err)
	}
	if fxapi.ToStatus(nil) != nil || fxapi.FromStatus(nil) != nil {
		t.Error("nil errors must stay nil")
	}
}

type harness struct {
	client *fxapi.Client
	admin  fxv1.FXAdminServiceClient
	raw    fxv1.FXServiceClient
	ready  *atomic.Bool
	led    *pgledger.Engine
	user   uuid.UUID
	src    uuid.UUID
	dst    uuid.UUID
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Parallel()
	led := pgledger.New(srv.DatabaseWith(t, "ledger", ledgerdb.Setup))
	g, err := fx.NewGraph(fx.GraphConfig{}, fx.Currency{Code: "EUR", Exp: 2}, fx.Currency{Code: "USD", Exp: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(fx.EdgeSpec{ID: "eur-usd", From: "EUR", To: "USD", Venue: "internal"},
		[]fx.Level{{Size: 1_000_000_00, Rate: "1.0850"}}); err != nil {
		t.Fatal(err)
	}
	h := &harness{led: led, user: uuid.New(), ready: &atomic.Bool{}}
	h.ready.Store(true)
	acct := func(kind ledger.AccountKind, cur string, owner *uuid.UUID) uuid.UUID {
		a, err := led.CreateAccount(context.Background(), ledger.CreateAccount{IdempotencyKey: uuid.NewString(), Kind: kind,
			Currency: cur, OwnerID: owner})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	books := map[string]uuid.UUID{"EUR": acct(ledger.KindFXBook, "EUR", nil), "USD": acct(ledger.KindFXBook, "USD", nil)}
	nostro := acct(ledger.KindNostro, "EUR", nil)
	h.src, h.dst = acct(ledger.KindUser, "EUR", &h.user), acct(ledger.KindUser, "USD", &h.user)
	if _, err := led.Transfer(context.Background(), ledger.Transfer{IdempotencyKey: uuid.NewString(), Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: nostro, Amount: -10_000_00}, {AccountID: h.src, Amount: 10_000_00}}}); err != nil {
		t.Fatal(err)
	}
	eng, err := fx.NewEngine(fx.Config{Risk: map[string]fx.PairRisk{"EUR/USD": {SigmaAnnual: 0.07}},
		Keys: []fx.QuoteKey{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, FXBooks: books},
		g, srv.Database(t), led)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.SetMid("EUR", "USD", "1.0850", time.Now()); err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	api := fxapi.NewServer(eng, h.ready.Load, nil)
	fxv1.RegisterFXServiceServer(gs, api)
	fxv1.RegisterFXAdminServiceServer(gs, api)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	h.client, h.admin, h.raw = fxapi.NewClient(conn), fxv1.NewFXAdminServiceClient(conn), fxv1.NewFXServiceClient(conn)
	return h
}

func TestQuoteAndExecuteOverGRPC(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	q, err := h.client.CreateQuote(ctx, fx.QuoteRequest{UserID: h.user, From: "EUR", To: "USD", AmountIn: 1_000_00,
		TTL: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if q.AmountOut <= 0 || q.ExpiresAt.Sub(q.CreatedAt) != 20*time.Second || len(q.Allocations) != 1 ||
		q.Allocations[0].Venues[0] != "internal" || len(q.Signature) != 32 {
		t.Fatalf("quote %+v", q)
	}
	got, x, err := h.client.GetQuote(ctx, h.user, q.ID)
	if err != nil || x != nil || got.AmountOut != q.AmountOut || got.MidRate != "1.0850" {
		t.Fatalf("GetQuote = %+v %v %v", got, x, err)
	}
	req := fx.ExecuteRequest{QuoteID: q.ID, Signature: q.Signature, UserID: h.user, SourceAccount: h.src, DestinationAccount: h.dst}
	ex, err := h.client.ExecuteQuote(ctx, req)
	if err != nil || ex.State != fx.StateBooked || ex.BookedAt == nil || len(ex.EntryIDs) != 1 {
		t.Fatalf("execution %+v %v", ex, err)
	}
	_, x, err = h.client.GetQuote(ctx, h.user, q.ID)
	if err != nil || x == nil || x.EntryIDs[0] != ex.EntryIDs[0] {
		t.Fatalf("execution after GetQuote = %+v %v", x, err)
	}
	req.Signature = make([]byte, 32)
	if _, err := h.client.ExecuteQuote(ctx, req); !errors.Is(err, fx.ErrTampered) {
		t.Fatalf("tampered: %v", err)
	}
	if _, _, err := h.client.GetQuote(ctx, uuid.New(), q.ID); !errors.Is(err, fx.ErrUnknownQuote) {
		t.Fatalf("another user's quote: %v", err)
	}
	if _, err := h.client.CreateQuote(ctx, fx.QuoteRequest{UserID: h.user, From: "EUR", To: "JPY", AmountIn: 1}); !errors.Is(err, fx.ErrUnknownCurrency) {
		t.Fatalf("unknown currency: %v", err)
	}
	// Malformed ids are invalid arguments, not internal errors.
	for _, r := range []*fxv1.ExecuteQuoteRequest{
		{QuoteId: "x", UserId: h.user.String(), DestinationAccount: h.dst.String()},
		{QuoteId: q.ID.String(), UserId: h.user.String(), HoldId: "nope", DestinationAccount: h.dst.String()},
		{QuoteId: q.ID.String(), UserId: h.user.String()},
	} {
		if _, err := h.raw.ExecuteQuote(ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Errorf("request %v: %v", r, err)
		}
	}
	if _, err := h.raw.CreateQuote(ctx, &fxv1.CreateQuoteRequest{UserId: "00000000-0000-0000-0000-000000000000"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil user: %v", err)
	}
	// A standby answers UNAVAILABLE.
	h.ready.Store(false)
	if _, err := h.client.CreateQuote(ctx, fx.QuoteRequest{UserID: h.user, From: "EUR", To: "USD", AmountIn: 1}); !errors.Is(err, fxapi.ErrUnavailable) {
		t.Fatalf("standby: %v", err)
	}
}

func TestAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	edges, err := h.admin.ListEdges(ctx, &fxv1.ListEdgesRequest{})
	if err != nil || len(edges.GetEdges()) != 1 || edges.GetEdges()[0].GetDepth() != 1_000_000_00 || !edges.GetEdges()[0].GetEnabled() {
		t.Fatalf("ListEdges = %v, %v", edges, err)
	}
	if _, err := h.admin.SetEdgeEnabled(ctx, &fxv1.SetEdgeEnabledRequest{EdgeId: "eur-usd", Enabled: false}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("switch without a reason: %v", err)
	}
	e, err := h.admin.SetEdgeEnabled(ctx, &fxv1.SetEdgeEnabledRequest{EdgeId: "eur-usd", Enabled: false, Reason: "corridor halted"})
	if err != nil || e.GetEnabled() {
		t.Fatalf("SetEdgeEnabled = %v, %v", e, err)
	}
	if _, err := h.client.CreateQuote(ctx, fx.QuoteRequest{UserID: h.user, From: "EUR", To: "USD", AmountIn: 100}); !errors.Is(err, fx.ErrNoRoute) {
		t.Fatalf("quote over a halted corridor: %v", err)
	}
	if _, err := h.admin.SetEdgeEnabled(ctx, &fxv1.SetEdgeEnabledRequest{EdgeId: "missing", Enabled: true, Reason: "x"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown edge: %v", err)
	}
}
