package accounts_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

type fixture struct {
	pool   *pgxpool.Pool
	ledger *pgledger.Engine
	r      *accounts.Resolver
	user   uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Parallel()
	f := &fixture{pool: srv.Database(t), ledger: pgledger.New(srv.DatabaseWith(t, "ledger", ledgerdb.Setup))}
	f.r = accounts.New(f.pool, f.ledger)
	u, err := webauthn.NewPGStore(f.pool).CreateUser(ctx(t), "user")
	if err != nil {
		t.Fatal(err)
	}
	f.user = u.ID
	return f
}

func TestEnsureOpensOnceAndResolves(t *testing.T) {
	f := newFixture(t)
	if _, err := f.r.Get(ctx(t), f.user, "EUR"); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("before opening: %v", err)
	}
	a, err := f.r.Ensure(ctx(t), f.user, "EUR")
	if err != nil {
		t.Fatal(err)
	}
	la, err := f.ledger.Account(ctx(t), a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if la.Kind != ledger.KindUser || la.Currency != "EUR" || la.OwnerID == nil || *la.OwnerID != f.user ||
		la.Floor == nil || *la.Floor != 0 || a.UserID != f.user || a.Currency != "EUR" {
		t.Fatalf("account %+v / %+v", a, la)
	}
	again, err := f.r.Ensure(ctx(t), f.user, "EUR")
	if err != nil || again != a {
		t.Fatalf("second Ensure %+v %v", again, err)
	}
	if got, err := f.r.Get(ctx(t), f.user, "EUR"); err != nil || got != a {
		t.Fatalf("Get %+v %v", got, err)
	}
}

func TestConcurrentEnsureAgrees(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	ids := make([]uuid.UUID, 10)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := f.r.Ensure(ctx(t), f.user, "USD")
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = a.AccountID
		}(i)
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("accounts %v", ids)
		}
	}
	var n int
	if err := f.pool.QueryRow(ctx(t), `SELECT count(*) FROM user_accounts WHERE user_id = $1`, f.user).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d rows, %v", n, err)
	}
}

func TestEnsureAfterACrashFindsTheLedgerAccount(t *testing.T) {
	f := newFixture(t)
	// The ledger opened the account, but the gateway crashed before
	// recording it.
	owner := f.user
	la, err := f.ledger.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: accounts.IdempotencyKey(f.user, "GBP"),
		OwnerID: &owner, Kind: ledger.KindUser, Currency: "GBP", Label: "user"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.r.Ensure(ctx(t), f.user, "GBP")
	if err != nil || a.AccountID != la.ID {
		t.Fatalf("Ensure %+v %v, want %s", a, err, la.ID)
	}
}

func TestEnsureRefusals(t *testing.T) {
	f := newFixture(t)
	if _, err := f.r.Ensure(ctx(t), f.user, "XXX"); !errors.Is(err, accounts.ErrCurrency) {
		t.Fatalf("unsupported currency: %v", err)
	}
	if _, err := f.r.Ensure(ctx(t), uuid.New(), "EUR"); !errors.Is(err, accounts.ErrUnknownUser) {
		t.Fatalf("unknown user: %v", err)
	}
	// A ledger answering with someone else's account is caught.
	other := accounts.New(f.pool, &lyingLedger{Ledger: f.ledger})
	if _, err := other.Ensure(ctx(t), f.user, "CHF"); !errors.Is(err, accounts.ErrMismatch) {
		t.Fatalf("wrong owner: %v", err)
	}
	// So is a row that appeared meanwhile and names another account.
	racing := accounts.New(f.pool, &racingLedger{Ledger: f.ledger, pool: f.pool, user: f.user})
	if _, err := racing.Ensure(ctx(t), f.user, "SEK"); !errors.Is(err, accounts.ErrMismatch) {
		t.Fatalf("racing row: %v", err)
	}
}

// lyingLedger opens accounts for another owner.
type lyingLedger struct{ ledger.Ledger }

func (l *lyingLedger) CreateAccount(ctx context.Context, cmd ledger.CreateAccount) (ledger.Account, error) {
	stranger := uuid.New()
	cmd.OwnerID = &stranger
	return l.Ledger.CreateAccount(ctx, cmd)
}

// racingLedger records a different account for the user while opening one.
type racingLedger struct {
	ledger.Ledger
	pool *pgxpool.Pool
	user uuid.UUID
}

func (l *racingLedger) CreateAccount(ctx context.Context, cmd ledger.CreateAccount) (ledger.Account, error) {
	if _, err := l.pool.Exec(ctx, `INSERT INTO user_accounts (user_id, currency, account_id) VALUES ($1, $2, $3)`,
		l.user, cmd.Currency, uuid.New()); err != nil {
		return ledger.Account{}, err
	}
	return l.Ledger.CreateAccount(ctx, cmd)
}

func TestListAndBalances(t *testing.T) {
	f := newFixture(t)
	for _, cur := range []string{"USD", "EUR", "JPY"} {
		if _, err := f.r.Ensure(ctx(t), f.user, cur); err != nil {
			t.Fatal(err)
		}
	}
	list, err := f.r.List(ctx(t), f.user)
	if err != nil || len(list) != 3 || list[0].Currency != "EUR" || list[1].Currency != "JPY" || list[2].Currency != "USD" {
		t.Fatalf("list %+v %v", list, err)
	}
	eur := list[0]
	nostro, err := f.ledger.CreateAccount(ctx(t), ledger.CreateAccount{IdempotencyKey: "nostro", Kind: ledger.KindNostro,
		Currency: "EUR"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ledger.Transfer(ctx(t), ledger.Transfer{IdempotencyKey: "deposit", Kind: "deposit",
		Postings: []ledger.Posting{{AccountID: nostro.ID, Amount: -12_34}, {AccountID: eur.AccountID, Amount: 12_34}}}); err != nil {
		t.Fatal(err)
	}
	bals, err := f.r.Balances(ctx(t), f.user)
	if err != nil || len(bals) != 3 {
		t.Fatalf("balances %+v %v", bals, err)
	}
	if bals[0].Currency != "EUR" || bals[0].Posted != 12_34 || bals[0].Available != 12_34 || bals[1].Posted != 0 {
		t.Fatalf("balances %+v", bals)
	}
	if empty, err := f.r.List(ctx(t), uuid.New()); err != nil || len(empty) != 0 {
		t.Fatalf("unknown user %v %v", empty, err)
	}
}
