package intentsapi_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	intentsv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/intents/v1"
	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/intentsapi"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/intentsenv"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

type harness struct {
	env                    *intentsenv.Env
	client                 *intentsapi.Client
	raw                    intentsv1.IntentServiceClient
	payer, payee, outsider *intentsenv.Person
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Parallel()
	env := intentsenv.New(t, srv, nil)
	gs := grpc.NewServer()
	intentsv1.RegisterIntentServiceServer(gs, intentsapi.NewServer(env.Intents, nil))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(intentsapi.RetryServiceConfig))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	h := &harness{env: env, client: intentsapi.NewClient(conn), raw: intentsv1.NewIntentServiceClient(conn),
		payer: env.Person("alicia", true), payee: env.Person("bruno", false), outsider: env.Person("carmen", false)}
	env.Fund(h.payer, "EUR", 500_00)
	return h
}

func TestThrowCatchOverGRPC(t *testing.T) {
	h := newHarness(t)
	nonces, err := h.client.IssueNonces(ctx(t), h.payer.User, h.payer.Device, 3)
	if err != nil || len(nonces) != 3 || !nonces[0].ExpiresAt.After(time.Now()) {
		t.Fatalf("nonces %v %v", nonces, err)
	}
	p := h.env.Flick(h.payer, h.payee, 42_00)
	p.Auth.Nonce = nonces[1].Value
	req := h.env.Sign(p)
	in, err := h.client.Create(ctx(t), req)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case in.State != intents.StateHeld || in.ID != p.Auth.IntentID || in.PayeeID != h.payee.User:
		t.Fatalf("intent %+v", in)
	case in.TLand == nil || !in.TLand.Equal(p.Req.TLand.UTC()) || in.Trajectory == nil || in.Trajectory.Speed != 1.8:
		t.Fatalf("flight %+v %+v", in.TLand, in.Trajectory)
	case in.HoldID == uuid.Nil || in.PayerDeviceID != h.payer.Device || in.PARVersion != p.Auth.PARVersion:
		t.Fatalf("intent %+v", in)
	}
	if again, err := h.client.Create(ctx(t), req); err != nil || again.ID != in.ID {
		t.Fatalf("replay %v %v", again, err)
	}
	if d, err := h.client.MarkDelivered(ctx(t), h.payee.User, in.ID); err != nil || d.State != intents.StateDelivered {
		t.Fatalf("delivered %v %v", d, err)
	}
	got, err := h.client.Get(ctx(t), h.payer.User, in.ID)
	if err != nil || got.State != intents.StateDelivered {
		t.Fatalf("get %v %v", got, err)
	}
	c, err := h.client.Catch(ctx(t), intents.CatchRequest{IntentID: in.ID, UserID: h.payee.User, Accept: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.State != intents.StateSettled || len(c.EntryIDs) != 1 || c.ResolvedAt == nil {
		t.Fatalf("settled %+v", c)
	}
	if posted, _ := h.env.Balance(h.payee, "EUR"); posted != 42_00 {
		t.Fatalf("payee balance %d", posted)
	}
	list, err := h.client.List(ctx(t), intents.ListQuery{UserID: h.payee.User, Role: intents.RolePayee,
		States: []intents.State{intents.StateSettled}})
	if err != nil || len(list) != 1 || list[0].ID != in.ID {
		t.Fatalf("list %v %v", list, err)
	}
	// A state error names the state across the wire.
	_, err = h.client.Cancel(ctx(t), h.payer.User, in.ID)
	var se *intents.StateError
	if !errors.As(err, &se) || se.State != intents.StateSettled || se.Op != "cancel" || !errors.Is(err, intents.ErrState) {
		t.Fatalf("cancel after settlement: %v", err)
	}
}

func TestErrorsOverGRPC(t *testing.T) {
	h := newHarness(t)
	p := h.env.Flick(h.payer, h.payee, 10_00)
	req := h.env.Sign(p)
	req.Amount++
	if _, err := h.client.Create(ctx(t), req); !errors.Is(err, intents.ErrMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	req.Amount--
	req.TxAuth = []byte{1, 2, 3}
	if _, err := h.client.Create(ctx(t), req); !errors.Is(err, intents.ErrTxAuth) {
		t.Fatalf("garbage TxAuth: %v", err)
	}
	if _, err := h.client.Get(ctx(t), h.payer.User, uuid.New()); !errors.Is(err, intents.ErrNotFound) {
		t.Fatalf("unknown intent: %v", err)
	}
	if _, err := h.client.IssueNonces(ctx(t), h.outsider.User, h.payer.Device, 1); !errors.Is(err, intents.ErrForbidden) {
		t.Fatalf("foreign device: %v", err)
	}
	in, err := h.client.Create(ctx(t), h.env.Sign(h.env.Flick(h.payer, h.payee, 10_00)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Catch(ctx(t), intents.CatchRequest{IntentID: in.ID, UserID: h.outsider.User, Accept: true}); !errors.Is(err, intents.ErrNotFound) {
		t.Fatalf("outsider catching: %v", err)
	}
	if out, err := h.client.Cancel(ctx(t), h.payer.User, in.ID); err != nil || out.State != intents.StateVoided ||
		out.Reason != intents.ReasonCancelled {
		t.Fatalf("cancel %v %v", out, err)
	}
	// Malformed requests never reach the orchestrator.
	for name, call := range map[string]func() error{
		"no actor": func() error {
			_, err := h.raw.GetIntent(ctx(t), &intentsv1.IntentRef{IntentId: in.ID.String()})
			return err
		},
		"bad actor": func() error {
			_, err := h.raw.GetIntent(ctx(t), &intentsv1.IntentRef{Actor: &intentsv1.Actor{UserId: "alice"}, IntentId: in.ID.String()})
			return err
		},
		"non-canonical id": func() error {
			_, err := h.raw.GetIntent(ctx(t), &intentsv1.IntentRef{Actor: &intentsv1.Actor{UserId: h.payer.User.String()},
				IntentId: "{" + in.ID.String() + "}"})
			return err
		},
		"nonces without device": func() error {
			_, err := h.raw.IssueNonces(ctx(t), &intentsv1.IssueNoncesRequest{Actor: &intentsv1.Actor{UserId: h.payer.User.String()},
				Count: 1})
			return err
		},
		"bad quote id": func() error {
			_, err := h.raw.CreateIntent(ctx(t), &intentsv1.CreateIntentRequest{Actor: &intentsv1.Actor{UserId: h.payer.User.String()},
				QuoteId: "q1"})
			return err
		},
		"bad cursor": func() error {
			_, err := h.raw.ListIntents(ctx(t), &intentsv1.ListIntentsRequest{Actor: &intentsv1.Actor{UserId: h.payer.User.String()},
				Before: "x"})
			return err
		},
	} {
		err := call()
		if status.Code(err) != codes.InvalidArgument || !errors.Is(intentsapi.FromStatus(err), intents.ErrRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStatusMapping(t *testing.T) {
	for _, err := range []error{intents.ErrTxAuth, intents.ErrNonce, intents.ErrStale, intents.ErrMismatch,
		intents.ErrConflict, intents.ErrNotFound, intents.ErrForbidden, intents.ErrRequest, intents.ErrUnavailable} {
		wrapped := errors.Join(errors.New("detail"), err)
		back := intentsapi.FromStatus(intentsapi.ToStatus(wrapped))
		if !errors.Is(back, err) {
			t.Errorf("%v → %v", err, back)
		}
	}
	se := &intents.StateError{Op: "accept", State: intents.StateVoided}
	var got *intents.StateError
	if back := intentsapi.FromStatus(intentsapi.ToStatus(se)); !errors.As(back, &got) || *got != *se {
		t.Fatalf("state error → %v", back)
	}
	if st := status.Convert(intentsapi.ToStatus(errors.New("pq: password=secret"))); st.Code() != codes.Internal ||
		st.Message() != "internal error" {
		t.Fatalf("unknown error leaked: %v", st)
	}
	if status.Code(intentsapi.ToStatus(context.Canceled)) != codes.Canceled ||
		status.Code(intentsapi.ToStatus(context.DeadlineExceeded)) != codes.DeadlineExceeded {
		t.Fatal("context errors")
	}
	if intentsapi.ToStatus(nil) != nil || intentsapi.FromStatus(nil) != nil {
		t.Fatal("nil")
	}
	if !errors.Is(intentsapi.FromStatus(errors.New("dial tcp: refused")), intents.ErrUnavailable) {
		t.Fatal("transport error")
	}
	if !errors.Is(intentsapi.FromStatus(status.Error(codes.Unavailable, "down")), intents.ErrUnavailable) {
		t.Fatal("bare unavailable")
	}
	if !errors.Is(intentsapi.FromStatus(status.Error(codes.Canceled, "x")), context.Canceled) {
		t.Fatal("bare cancel")
	}
	if err := intentsapi.FromStatus(status.Error(codes.Internal, "boom")); err == nil ||
		errors.Is(err, intents.ErrUnavailable) {
		t.Fatalf("internal: %v", err)
	}
}

func TestIntentConversionRoundTrip(t *testing.T) {
	land := time.UnixMilli(1790000000123).UTC()
	live, claim, now := land.Add(30*time.Second), land.Add(7*24*time.Hour), land.Add(time.Second)
	in := &intents.Intent{ID: uuid.Must(uuid.NewV7()), PayerID: uuid.New(), PayerSubject: "bil_0123456789ABCDEFGHJK",
		PayerDeviceID: uuid.New(), PayeeID: uuid.New(), PayeeSubject: "bil_ZYXWVTSRQPNMKJHGFEDC", PARVersion: 4,
		Gesture: intents.GestureFlick, Amount: 1234, Currency: "EUR", PayeeAmount: 1338, PayeeCurrency: "USD",
		QuoteID: uuid.New(), State: intents.StateAsyncPending, OnTimeout: intents.TimeoutAsync, SignedAt: land.Truncate(time.Second),
		HoldID: uuid.New(), EntryIDs: []uuid.UUID{uuid.New(), uuid.New()}, TLand: &land, LiveUntil: &live, ClaimUntil: &claim,
		Trajectory: &intents.Trajectory{Azimuth: 1, Speed: 2, Distance: 3}, CreatedAt: now, UpdatedAt: now, ResolvedAt: &now}
	back, err := intentsapi.IntentFromPB(intentsapi.IntentToPB(in))
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case back.ID != in.ID || back.PayerID != in.PayerID || back.PayeeID != in.PayeeID || back.QuoteID != in.QuoteID ||
		back.HoldID != in.HoldID || back.PayerDeviceID != in.PayerDeviceID:
		t.Fatalf("ids %+v", back)
	case back.State != in.State || back.Gesture != in.Gesture || back.OnTimeout != in.OnTimeout || back.PARVersion != 4 ||
		back.PayerSubject != in.PayerSubject || back.PayeeSubject != in.PayeeSubject:
		t.Fatalf("fields %+v", back)
	case back.Amount != 1234 || back.PayeeAmount != 1338 || back.Currency != "EUR" || back.PayeeCurrency != "USD":
		t.Fatalf("amounts %+v", back)
	case len(back.EntryIDs) != 2 || back.EntryIDs[1] != in.EntryIDs[1] || *back.Trajectory != *in.Trajectory:
		t.Fatalf("entries %+v", back)
	case !back.TLand.Equal(land) || !back.LiveUntil.Equal(live) || !back.ClaimUntil.Equal(claim) ||
		!back.SignedAt.Equal(in.SignedAt) || !back.CreatedAt.Equal(now) || !back.ResolvedAt.Equal(now):
		t.Fatalf("times %+v", back)
	}
	// Optional ids stay empty; a malformed id is refused.
	in.PayeeID, in.QuoteID, in.HoldID, in.TLand, in.Trajectory = uuid.Nil, uuid.Nil, uuid.Nil, nil, nil
	pb := intentsapi.IntentToPB(in)
	if pb.PayeeId != "" || pb.QuoteId != "" || pb.HoldId != "" || pb.TLand != nil || pb.Trajectory != nil {
		t.Fatalf("optional fields %+v", pb)
	}
	pb.EntryIds = append(pb.EntryIds, "nope")
	if _, err := intentsapi.IntentFromPB(pb); !errors.Is(err, intents.ErrRequest) {
		t.Fatalf("malformed entry id: %v", err)
	}
}
