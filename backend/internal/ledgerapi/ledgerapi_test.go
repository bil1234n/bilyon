package ledgerapi_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	ledgerv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/ledger/v1"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/ledgerapi"
	"github.com/bil1234n/bilyon/backend/internal/platform/grpcx"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/certs"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, ledgerdb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

type fixture struct {
	ca     *certs.CA
	addr   string
	client *ledgerapi.Client
	eng    *pgledger.Engine
	keys   atomic.Int64
}

const gatewayID = "spiffe://bilyon/gateway"

// start serves a fresh ledger database over mutual TLS with acl.
func start(t *testing.T, acl grpcx.ACL) *fixture {
	t.Helper()
	t.Parallel()
	pool := srv.Database(t)
	f := &fixture{ca: certs.NewCA(t, "bilyon-test"), eng: pgledger.New(pool)}
	creds, err := grpcx.ServerTLS(f.ca.Leaf("ledger", "spiffe://bilyon/ledger", "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	s := grpc.NewServer(grpc.Creds(creds), grpc.ChainUnaryInterceptor(grpcx.RecoverUnary(log),
		grpcx.ObserveUnary(log, grpcx.NewMetrics(prometheus.NewRegistry())), grpcx.AuthorizeUnary(acl, false)))
	ledgerv1.RegisterLedgerServiceServer(s, ledgerapi.NewServer(f.eng))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)
	f.addr = l.Addr().String()
	f.client = f.dial(t, f.ca.Leaf("gateway", gatewayID, "gateway"))
	return f
}

func (f *fixture) dial(t *testing.T, files grpcx.TLSFiles) *ledgerapi.Client {
	t.Helper()
	creds, err := grpcx.ClientTLS(files)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(creds),
		grpc.WithDefaultServiceConfig(grpcx.RetryServiceConfig))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return ledgerapi.NewClient(conn)
}

func (f *fixture) key(p string) string {
	return fmt.Sprintf("%s-%d-%s", p, f.keys.Add(1), uuid.NewString()[:8])
}

func (f *fixture) account(t *testing.T, kind ledger.AccountKind, floor *int64) ledger.Account {
	t.Helper()
	a, err := f.client.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: f.key("a"), Kind: kind,
		Currency: "EUR", Floor: floor})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestClientDrivesEveryLedgerCommand(t *testing.T) {
	f := start(t, grpcx.ACL{gatewayID: {"*"}})
	c := f.client
	owner := uuid.New()
	bank := f.account(t, ledger.KindNostro, nil)
	alice, err := c.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: f.key("a"), Kind: ledger.KindUser,
		Currency: "EUR", OwnerID: &owner, Label: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	direct, err := f.eng.Account(ctx(t), alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if alice.OwnerID == nil || *alice.OwnerID != owner || alice.Floor == nil || *alice.Floor != 0 ||
		!alice.CreatedAt.Equal(direct.CreatedAt) || alice.Label != "alice" {
		t.Fatalf("account over the wire %+v, direct %+v", alice, direct)
	}
	bob := f.account(t, ledger.KindUser, nil)
	if got, err := c.Account(ctx(t), bob.ID); err != nil || got.ID != bob.ID {
		t.Fatalf("get account: %+v %v", got, err)
	}

	deposit := ledger.Transfer{IdempotencyKey: f.key("t"), Kind: "deposit", RefType: "rail", RefID: "sepa-1",
		Memo: "top-up", Postings: []ledger.Posting{{AccountID: bank.ID, Amount: -10_000}, {AccountID: alice.ID, Amount: 10_000}}}
	en, err := c.Transfer(ctx(t), deposit)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Transfer(ctx(t), deposit) // idempotent replay over the wire
	if err != nil || again.ID != en.ID || len(again.Postings) != 2 || again.RefID != "sepa-1" {
		t.Fatalf("replay: %+v %v", again, err)
	}
	if got, err := c.Entry(ctx(t), en.ID); err != nil || got.ID != en.ID || got.Memo != "top-up" {
		t.Fatalf("get entry: %+v %v", got, err)
	}

	h, err := c.PlaceHold(ctx(t), ledger.PlaceHold{IdempotencyKey: f.key("h"), AccountID: alice.ID, Amount: 3_000,
		Reason: "throw_intent", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := c.Balance(ctx(t), alice.ID); err != nil || b.Posted != 10_000 || b.Pending != 3_000 || b.Available != 7_000 {
		t.Fatalf("balance with hold: %+v %v", b, err)
	}
	posted, err := c.PostHold(ctx(t), ledger.PostHold{IdempotencyKey: f.key("p"), HoldID: h.ID, Kind: "capture",
		Credits: []ledger.Posting{{AccountID: bob.ID, Amount: 2_500}}})
	if err != nil || posted.Hold.State != ledger.HoldPosted || posted.Entry.HoldID == nil || *posted.Entry.HoldID != h.ID {
		t.Fatalf("post hold: %+v %v", posted, err)
	}
	if got, err := c.Hold(ctx(t), h.ID); err != nil || got.PostedAmount != 2_500 || got.ResolvedAt == nil {
		t.Fatalf("get hold: %+v %v", got, err)
	}
	h2, _ := c.PlaceHold(ctx(t), ledger.PlaceHold{IdempotencyKey: f.key("h"), AccountID: alice.ID, Amount: 100,
		Reason: "throw_intent", ExpiresAt: time.Now().Add(time.Minute)})
	if v, err := c.VoidHold(ctx(t), ledger.VoidHold{IdempotencyKey: f.key("v"), HoldID: h2.ID, Reason: "boomerang"}); err != nil || v.State != ledger.HoldVoided {
		t.Fatalf("void: %+v %v", v, err)
	}
	if expired, err := c.ExpireHolds(ctx(t), 10); err != nil || len(expired) != 0 {
		t.Fatalf("expire holds: %v %v", expired, err)
	}

	rev, err := c.Reverse(ctx(t), ledger.Reverse{IdempotencyKey: f.key("r"), EntryID: posted.Entry.ID, Memo: "refund"})
	if err != nil || rev.Reverses == nil || *rev.Reverses != posted.Entry.ID {
		t.Fatalf("reverse: %+v %v", rev, err)
	}
	page, err := c.History(ctx(t), ledger.HistoryQuery{AccountID: alice.ID, Limit: 2})
	if err != nil || len(page.Entries) != 2 || page.Next == nil {
		t.Fatalf("history page 1: %+v %v", page, err)
	}
	rest, err := c.History(ctx(t), ledger.HistoryQuery{AccountID: alice.ID, Before: page.Next, Limit: 10})
	if err != nil || len(rest.Entries) != 1 || rest.Next != nil {
		t.Fatalf("history page 2: %+v %v", rest, err)
	}

	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	opened, err := c.OpenReserve(ctx(t), ledger.OpenReserve{IdempotencyKey: f.key("o"), FundingAccountID: alice.ID,
		Amount: 1_000, Purpose: "offline", ExpiresAt: &exp})
	if err != nil || opened.Reserve.State != ledger.ReserveOpen || opened.Reserve.ExpiresAt == nil || !opened.Reserve.ExpiresAt.Equal(exp) {
		t.Fatalf("open reserve: %+v %v", opened, err)
	}
	if got, err := c.Reserve(ctx(t), opened.Reserve.ID); err != nil || got.ID != opened.Reserve.ID {
		t.Fatalf("get reserve: %+v %v", got, err)
	}
	released, err := c.ReleaseReserve(ctx(t), ledger.ReleaseReserve{IdempotencyKey: f.key("rr"), ReserveID: opened.Reserve.ID})
	if err != nil || released.Reserve.State != ledger.ReserveClosed || released.Entry == nil {
		t.Fatalf("release reserve: %+v %v", released, err)
	}
	frozen, err := c.SetFrozen(ctx(t), ledger.SetFrozen{IdempotencyKey: f.key("f"), AccountID: bob.ID, Frozen: true, Reason: "review"})
	if err != nil || !frozen.Frozen {
		t.Fatalf("freeze: %+v %v", frozen, err)
	}
	b, err := c.Balance(ctx(t), alice.ID)
	if err != nil || b.Posted != 10_000 || b.Pending != 0 {
		t.Fatalf("final balance %+v %v", b, err)
	}
}

func TestTypedErrorsSurviveTheWire(t *testing.T) {
	f := start(t, grpcx.ACL{gatewayID: {"*"}})
	c := f.client
	bank := f.account(t, ledger.KindNostro, nil)
	alice := f.account(t, ledger.KindUser, nil)

	_, err := c.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: f.key("t"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: alice.ID, Amount: -5}, {AccountID: bank.ID, Amount: 5}}})
	var ife *ledger.InsufficientFundsError
	if !errors.As(err, &ife) || ife.AccountID != alice.ID || ife.Required != 5 || ife.Available != 0 {
		t.Fatalf("insufficient funds: %v", err)
	}
	_, err = c.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: "has space", Kind: "p2p"})
	var ve *ledger.ValidationError
	if !errors.As(err, &ve) || ve.Field != "idempotency_key" {
		t.Fatalf("validation: %v", err)
	}
	missing := uuid.New()
	_, err = c.Hold(ctx(t), missing)
	var nf *ledger.NotFoundError
	if !errors.As(err, &nf) || nf.Object != "hold" || nf.ID != missing {
		t.Fatalf("not found: %v", err)
	}
	key := f.key("dup")
	if _, err := c.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: key, Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: bank.ID, Amount: -5}, {AccountID: alice.ID, Amount: 5}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: key, Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: bank.ID, Amount: -6}, {AccountID: alice.ID, Amount: 6}}}); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := c.SetFrozen(ctx(t), ledger.SetFrozen{IdempotencyKey: f.key("f"), AccountID: alice.ID, Frozen: true, Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: f.key("t"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: alice.ID, Amount: -1}, {AccountID: bank.ID, Amount: 1}}})
	var fe *ledger.FrozenError
	if !errors.As(err, &fe) || fe.AccountID != alice.ID {
		t.Fatalf("frozen: %v", err)
	}
	if _, err := c.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: f.key("t"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: bank.ID, Amount: -1}, {AccountID: alice.ID, Amount: 2}}}); !errors.Is(err, ledger.ErrUnbalanced) && !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("unbalanced: %v", err)
	}

	// Ids are validated before reaching the engine.
	raw := ledgerv1.NewLedgerServiceClient(dialRaw(t, f))
	_, err = raw.GetAccount(ctx(t), &ledgerv1.GetAccountRequest{AccountId: "not-a-uuid"})
	if !errors.As(ledgerapi.FromStatus(err), &ve) || ve.Field != "account_id" || status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed id: %v", err)
	}
	_, err = raw.GetAccount(ctx(t), &ledgerv1.GetAccountRequest{AccountId: strings.ToUpper(alice.ID.String())})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("non-canonical id accepted: %v", err)
	}
}

func dialRaw(t *testing.T, f *fixture) *grpc.ClientConn {
	t.Helper()
	creds, err := grpcx.ClientTLS(f.ca.Leaf("raw", gatewayID, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestMutualTLSAndPerMethodAuthorisation(t *testing.T) {
	f := start(t, grpcx.ACL{gatewayID: {"*"}, "spiffe://bilyon/support": {"GetAccount", "GetBalance"}})
	bank := f.account(t, ledger.KindNostro, nil)

	support := f.dial(t, f.ca.Leaf("support", "spiffe://bilyon/support", "support"))
	if _, err := support.Account(ctx(t), bank.ID); err != nil {
		t.Fatalf("support reading an account: %v", err)
	}
	_, err := support.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: f.key("t"), Kind: "p2p",
		Postings: []ledger.Posting{{AccountID: bank.ID, Amount: -1}, {AccountID: bank.ID, Amount: 1}}})
	if err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("support moving money: %v", err)
	}
	stranger := f.dial(t, f.ca.Leaf("stranger", "spiffe://bilyon/stranger", "stranger"))
	if _, err := stranger.Account(ctx(t), bank.ID); err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("unknown identity: %v", err)
	}

	// A certificate from another CA never completes the handshake.
	other := certs.NewCA(t, "rogue")
	rogue := f.dial(t, other.Leaf("rogue", gatewayID, "gateway"))
	shortCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := rogue.Account(shortCtx, bank.ID); !errors.Is(err, ledger.ErrUnavailable) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rogue CA: %v", err)
	}
	// Neither does a client without a certificate.
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	shortCtx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if _, err := ledgerapi.NewClient(conn).Account(shortCtx2, bank.ID); err == nil {
		t.Fatal("plaintext client served")
	}
}

func TestErrorMappingRoundTrip(t *testing.T) {
	id := uuid.New()
	cases := []error{
		&ledger.ValidationError{Field: "amount", Reason: "must be positive"},
		&ledger.NotFoundError{Object: "reserve", ID: id},
		&ledger.InsufficientFundsError{AccountID: id, Available: 7, Required: 9, Floor: -3},
		&ledger.FrozenError{AccountID: id},
		fmt.Errorf("wrapped: %w", ledger.ErrHoldExpired),
		ledger.ErrHoldNotPending, ledger.ErrIdempotencyConflict, ledger.ErrOverflow, ledger.ErrAlreadyReversed,
		ledger.ErrNotReversible, ledger.ErrReserveClosed, ledger.ErrCurrencyMismatch, ledger.ErrUnbalanced,
		ledger.ErrUnavailable,
	}
	for _, in := range cases {
		out := ledgerapi.FromStatus(ledgerapi.ToStatus(in))
		var target error
		for _, s := range []error{ledger.ErrInvalid, ledger.ErrNotFound, ledger.ErrInsufficientFunds, ledger.ErrAccountFrozen,
			ledger.ErrHoldExpired, ledger.ErrHoldNotPending, ledger.ErrIdempotencyConflict, ledger.ErrOverflow,
			ledger.ErrAlreadyReversed, ledger.ErrNotReversible, ledger.ErrReserveClosed, ledger.ErrCurrencyMismatch,
			ledger.ErrUnbalanced, ledger.ErrUnavailable} {
			if errors.Is(in, s) {
				target = s
			}
		}
		if !errors.Is(out, target) {
			t.Errorf("%v came back as %v", in, out)
		}
		if out.Error() != in.Error() && !strings.Contains(out.Error(), in.Error()) {
			t.Errorf("message lost: %q -> %q", in, out)
		}
	}
	if st := status.Convert(ledgerapi.ToStatus(errors.New("pq: secret table details"))); st.Code() != codes.Internal ||
		strings.Contains(st.Message(), "secret") {
		t.Fatalf("internal error leaked: %v", st)
	}
	if got := ledgerapi.FromStatus(status.Error(codes.Unavailable, "down")); !errors.Is(got, ledger.ErrUnavailable) {
		t.Fatalf("transport failure: %v", got)
	}
	if got := ledgerapi.FromStatus(ledgerapi.ToStatus(context.DeadlineExceeded)); !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", got)
	}
}
