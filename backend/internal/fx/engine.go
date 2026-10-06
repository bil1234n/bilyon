package fx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// Engine errors.
var (
	ErrPairNotConfigured = errors.New("fx: pair risk not configured")
	ErrNoMid             = errors.New("fx: no fresh mid rate for the pair")
	ErrUnknownQuote      = errors.New("fx: unknown quote")
	ErrTampered          = errors.New("fx: quote signature mismatch")
	ErrExpired           = errors.New("fx: quote expired, requote")
	ErrRequote           = errors.New("fx: extreme market move, requote")
	ErrFailed            = errors.New("fx: quote execution failed")
	ErrConflict          = errors.New("fx: quote is being executed with other accounts")
	ErrPayoutPending     = errors.New("fx: payout pending; the execution will complete on retry")
	ErrFunding           = errors.New("fx: invalid funding or destination")
	ErrRequest           = errors.New("fx: invalid request")
)

// Quote states.
const (
	StateOpen      = "open"
	StateExecuting = "executing"
	StateBooked    = "booked"
	StateExpired   = "expired"
	StateRequoted  = "requoted"
	StateFailed    = "failed"
)

// Event topics.
const (
	TopicQuoteBooked   = "fx.quote.booked"
	TopicQuoteRequoted = "fx.quote.requoted"
	TopicQuoteFailed   = "fx.quote.failed"
	EventSource        = "bilyon.fx"
)

// Config configures the engine.
type Config struct {
	Route         RouteOptions
	Z             float64       // buffer confidence (default 2.33, 99 %)
	MarginBps     float64       // disclosed margin (default 8)
	MaxAdverseBps float64       // breaker (default 150)
	Overbook      float64       // ρ: reservations count 1/ρ of their size (default 1.5)
	DefaultTTL    time.Duration // default 30 s
	MinTTL        time.Duration // default 5 s
	MidStaleAfter time.Duration // default 5 s
	Risk          map[string]PairRisk
	Keys          []QuoteKey
	// FXBooks are the platform's fx_book accounts per currency.
	FXBooks map[string]uuid.UUID
	// Quote sniping (§3.C.4): a user with more than SnipingRatio quotes
	// per trade in SnipingWindow gets half the TTL and twice the buffer.
	SnipingRatio  float64       // default 20
	SnipingWindow time.Duration // default 24 h
	Now           func() time.Time
	Logger        *slog.Logger
}

// Engine issues and executes firm quotes. One engine per region holds the
// liquidity state (fxd elects it); quotes are persisted, so a successor
// rebuilds reservations with Recover.
type Engine struct {
	cfg    Config
	g      *Graph
	db     *store
	ledger ledger.Ledger
	signer *quoteSigner

	mu       sync.Mutex
	mids     map[string]midRate
	reserved map[uuid.UUID][]Leg // reservations of open quotes
}

type midRate struct {
	rate float64
	raw  string
	at   time.Time
}

// NewEngine validates the configuration.
func NewEngine(cfg Config, g *Graph, pool *pgxpool.Pool, l ledger.Ledger) (*Engine, error) {
	if g == nil || pool == nil || l == nil {
		return nil, errors.New("fx: graph, database and ledger are required")
	}
	signer, err := newQuoteSigner(cfg.Keys)
	if err != nil {
		return nil, err
	}
	for pair, r := range cfg.Risk {
		if r.SigmaAnnual < 0 || r.JumpBps < 0 || r.MaxTTL < 0 {
			return nil, fmt.Errorf("fx: pair %s risk is negative", pair)
		}
	}
	for code := range cfg.FXBooks {
		if _, ok := g.Currency(code); !ok {
			return nil, fmt.Errorf("%w: fx book for %s", ErrUnknownCurrency, code)
		}
	}
	if cfg.Z == 0 {
		cfg.Z = 2.33
	}
	if cfg.MarginBps == 0 {
		cfg.MarginBps = 8
	}
	if cfg.MaxAdverseBps == 0 {
		cfg.MaxAdverseBps = 150
	}
	if cfg.Overbook == 0 {
		cfg.Overbook = 1.5
	}
	if cfg.Overbook < 1 {
		return nil, errors.New("fx: the overbooking factor is at least 1")
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 30 * time.Second
	}
	if cfg.MinTTL == 0 {
		cfg.MinTTL = 5 * time.Second
	}
	if cfg.MidStaleAfter == 0 {
		cfg.MidStaleAfter = 5 * time.Second
	}
	if cfg.SnipingRatio == 0 {
		cfg.SnipingRatio = 20
	}
	if cfg.SnipingWindow == 0 {
		cfg.SnipingWindow = 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	cfg.Route = cfg.Route.withDefaults()
	return &Engine{cfg: cfg, g: g, db: &store{pool: pool}, ledger: l, signer: signer,
		mids: map[string]midRate{}, reserved: map[uuid.UUID][]Leg{}}, nil
}

// Graph returns the engine's liquidity graph.
func (e *Engine) Graph() *Graph { return e.g }

// SetMid records the mid-market rate of a pair (target major units per
// source major unit) from the market-data feed.
func (e *Engine) SetMid(from, to, rate string, at time.Time) error {
	r, ok := new(big.Rat).SetString(rate)
	if !ok || r.Sign() <= 0 {
		return fmt.Errorf("%w: mid rate %q", ErrRequest, rate)
	}
	if _, ok := e.g.Currency(from); !ok {
		return ErrUnknownCurrency
	}
	if _, ok := e.g.Currency(to); !ok {
		return ErrUnknownCurrency
	}
	f, _ := r.Float64()
	e.mu.Lock()
	defer e.mu.Unlock()
	if cur, ok := e.mids[from+"/"+to]; ok && at.Before(cur.at) {
		return nil
	}
	e.mids[from+"/"+to] = midRate{rate: f, raw: rate, at: at}
	return nil
}

func (e *Engine) mid(pair string, now time.Time) (midRate, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m, ok := e.mids[pair]
	return m, ok && now.Sub(m.at) <= e.cfg.MidStaleAfter
}

// QuoteRequest asks for a firm price.
type QuoteRequest struct {
	UserID   uuid.UUID
	From, To string
	AmountIn int64         // source minor units
	TTL      time.Duration // 0: the default
}

// Quote is a firm, signed offer: the customer receives exactly AmountOut
// for AmountIn if they execute before ExpiresAt, whatever the market does
// in between, except for the disclosed extreme-move breaker.
type Quote struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	From, To    string
	AmountIn    int64
	AmountOut   int64
	ExecOut     int64   // what the planned routes deliver
	MidRate     string  // shown for transparency
	MidOut      float64 // the mid-market equivalent of AmountIn
	ExecCostBps float64 // spread, depth and venue fees against mid
	BufferBps   float64 // lock buffer: volatility over the TTL plus jump premium
	MarginBps   float64
	FeeBps      float64 // all-in cost against mid
	Allocations []Allocation
	State       string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	KeyID       string
	Signature   []byte
}

func (q *Quote) message() []byte {
	return quoteMessage(q.ID, q.From, q.To, q.AmountIn, q.AmountOut, q.ExpiresAt)
}

// Quote prices a conversion with a rate lock and soft-reserves its
// liquidity (§3.C.4-3.C.5).
func (e *Engine) Quote(ctx context.Context, req QuoteRequest) (*Quote, error) {
	if req.UserID == uuid.Nil || req.AmountIn <= 0 || req.From == req.To {
		return nil, fmt.Errorf("%w: user, amount and distinct currencies are required", ErrRequest)
	}
	from, ok1 := e.g.Currency(req.From)
	to, ok2 := e.g.Currency(req.To)
	if !ok1 || !ok2 {
		return nil, ErrUnknownCurrency
	}
	pair := req.From + "/" + req.To
	risk, ok := e.cfg.Risk[pair]
	if !ok {
		return nil, ErrPairNotConfigured
	}
	now := e.cfg.Now().UTC().Truncate(time.Millisecond)
	m, ok := e.mid(pair, now)
	if !ok {
		return nil, ErrNoMid
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = e.cfg.DefaultTTL
	}
	if risk.MaxTTL > 0 && ttl > risk.MaxTTL {
		ttl = risk.MaxTTL
	}
	if ttl < e.cfg.MinTTL {
		return nil, fmt.Errorf("%w: a lock shorter than %s", ErrRequest, e.cfg.MinTTL)
	}
	buffer := LockBufferBps(risk.SigmaAnnual, ttl, e.cfg.Z) + risk.JumpBps
	quotes, trades, err := e.db.activity(ctx, req.UserID, now.Add(-e.cfg.SnipingWindow))
	if err != nil {
		return nil, err
	}
	if float64(quotes) > e.cfg.SnipingRatio*math.Max(float64(trades), 1) {
		ttl = max(ttl/2, e.cfg.MinTTL)
		buffer = 2 * (LockBufferBps(risk.SigmaAnnual, ttl, e.cfg.Z) + risk.JumpBps)
	}
	keep, err := KeepPPM(buffer, e.cfg.MarginBps)
	if err != nil {
		return nil, err
	}
	plan, reserved, err := e.planAndReserve(req.From, req.To, req.AmountIn, now)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		e.g.Release(reserved)
		return nil, err
	}
	scale := math.Pow10(to.Exp - from.Exp)
	midOut := float64(req.AmountIn) * m.rate * scale
	q := &Quote{ID: id, UserID: req.UserID, From: req.From, To: req.To, AmountIn: req.AmountIn,
		AmountOut: CustomerAmount(plan.Out, keep), ExecOut: plan.Out, MidRate: m.raw, MidOut: midOut,
		BufferBps: buffer, MarginBps: e.cfg.MarginBps, Allocations: plan.Allocations, State: StateOpen,
		CreatedAt: now, ExpiresAt: now.Add(ttl)}
	q.ExecCostBps = (midOut - float64(plan.Out)) / midOut * 1e4
	q.FeeBps = (midOut - float64(q.AmountOut)) / midOut * 1e4
	if q.AmountOut <= 0 {
		e.g.Release(reserved)
		return nil, ErrNoRoute
	}
	q.KeyID, q.Signature = e.signer.sign(q.message())
	if err := e.db.insert(ctx, q, reserved); err != nil {
		e.g.Release(reserved)
		return nil, err
	}
	e.mu.Lock()
	e.reserved[q.ID] = reserved
	e.mu.Unlock()
	return q, nil
}

// planAndReserve routes under the read lock, then revalidates the plan and
// reserves its depth under the write lock, retrying when concurrent quotes
// took the liquidity in between.
func (e *Engine) planAndReserve(from, to string, amount int64, now time.Time) (Plan, []Leg, error) {
	for range 3 {
		e.g.mu.RLock()
		plan, ok := e.g.splitRoute(from, to, amount, e.cfg.Route, now)
		e.g.mu.RUnlock()
		if !ok || plan.Out <= 0 {
			return Plan{}, nil, ErrNoRoute
		}
		e.g.mu.Lock()
		fresh, ok := e.g.revalidate(plan, now)
		if !ok {
			e.g.mu.Unlock()
			continue
		}
		var reserved []Leg
		for _, l := range fresh.legs() {
			reserved = append(reserved, Leg{EdgeID: l.EdgeID, Amount: l.Amount / e.cfg.Overbook})
		}
		e.g.reserve(reserved)
		e.g.mu.Unlock()
		return fresh, reserved, nil
	}
	return Plan{}, nil, ErrNoRoute
}

func (e *Engine) dropReservation(id uuid.UUID) {
	e.mu.Lock()
	legs, ok := e.reserved[id]
	delete(e.reserved, id)
	e.mu.Unlock()
	if ok {
		e.g.Release(legs)
	}
}

// ExecuteRequest accepts a quote. Funding is exactly one of HoldID (a
// pending hold of at least AmountIn on the user's From account, placed by
// the orchestrator) or SourceAccount (debited directly).
type ExecuteRequest struct {
	QuoteID            uuid.UUID
	Signature          []byte
	UserID             uuid.UUID
	HoldID             uuid.UUID
	SourceAccount      uuid.UUID
	DestinationAccount uuid.UUID
}

// Execution is an executed quote.
type Execution struct {
	QuoteID    uuid.UUID
	AmountIn   int64
	AmountOut  int64 // delivered to the destination (the quoted amount)
	MarketOut  int64 // what the market yielded at execution
	PnL        int64 // MarketOut − AmountOut, target minor units, to treasury
	EntryIDs   []uuid.UUID
	State      string
	Failure    string // why a failed execution failed
	ExecutedAt time.Time
	BookedAt   *time.Time
}

func (r ExecuteRequest) sameAccounts(q *storedQuote) bool {
	return r.HoldID == q.HoldID && r.SourceAccount == q.SourceAccount && r.DestinationAccount == q.DestinationAccount
}

// Execute accepts a quote (§3.C.6). It is idempotent per quote: a booked
// quote returns its execution, and an execution interrupted between the
// market check and the ledger is resumed. Expired quotes and moves beyond
// the breaker are refused; any smaller adverse move is honoured.
func (e *Engine) Execute(ctx context.Context, req ExecuteRequest) (Execution, error) {
	if req.DestinationAccount == uuid.Nil || (req.HoldID == uuid.Nil) == (req.SourceAccount == uuid.Nil) {
		return Execution{}, fmt.Errorf("%w: a destination and exactly one of hold or source account", ErrRequest)
	}
	tx, q, err := e.db.lock(ctx, req.QuoteID)
	if err != nil {
		return Execution{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if q.UserID != req.UserID {
		return Execution{}, ErrUnknownQuote
	}
	if !e.signer.verify(q.KeyID, q.Quote.message(), req.Signature) {
		return Execution{}, ErrTampered
	}
	switch q.State {
	case StateBooked, StateExecuting:
		if !req.sameAccounts(q) {
			return Execution{}, ErrConflict
		}
		committed = true
		if err := tx.Commit(ctx); err != nil {
			return Execution{}, err
		}
		if q.State == StateBooked {
			return q.execution(), nil
		}
		return e.book(ctx, q)
	case StateExpired:
		return Execution{}, ErrExpired
	case StateRequoted:
		return Execution{}, ErrRequote
	case StateFailed:
		return Execution{}, fmt.Errorf("%w: %s", ErrFailed, q.Failure)
	}
	now := e.cfg.Now().UTC().Truncate(time.Microsecond)
	if now.After(q.ExpiresAt) {
		if err := e.db.setState(ctx, tx, q.ID, StateExpired, ""); err != nil {
			return Execution{}, err
		}
		committed = true
		if err := tx.Commit(ctx); err != nil {
			return Execution{}, err
		}
		e.dropReservation(q.ID)
		return Execution{}, ErrExpired
	}
	if err := e.checkFunding(ctx, q, req); err != nil {
		return Execution{}, err
	}
	// Market check: release this quote's reservation and price the amount
	// now; the quote is firm unless the market moved beyond the breaker.
	e.mu.Lock()
	legs := e.reserved[q.ID]
	delete(e.reserved, q.ID)
	e.mu.Unlock()
	e.g.mu.Lock()
	e.g.release(legs)
	plan, ok := e.g.splitRoute(q.From, q.To, q.AmountIn, e.cfg.Route, now)
	floor := float64(q.AmountOut) * (1 - e.cfg.MaxAdverseBps/1e4)
	if !ok || float64(plan.Out) < floor {
		e.g.mu.Unlock()
		err := e.db.setState(ctx, tx, q.ID, StateRequoted, "")
		if err == nil {
			err = e.db.emit(ctx, tx, TopicQuoteRequoted, q, map[string]any{"market_out": plan.Out, "floor": int64(floor)})
		}
		if err == nil {
			committed = true
			err = tx.Commit(ctx)
		}
		if err != nil {
			e.restore(q.ID, legs)
			return Execution{}, err
		}
		return Execution{}, ErrRequote
	}
	executed := plan.legs()
	e.g.consume(executed)
	e.g.mu.Unlock()
	q.State, q.HoldID, q.SourceAccount, q.DestinationAccount = StateExecuting, req.HoldID, req.SourceAccount, req.DestinationAccount
	q.MarketOut, q.PnL, q.ExecutedAt = plan.Out, plan.Out-q.AmountOut, &now
	q.Executed = executed
	if err := e.db.markExecuting(ctx, tx, q); err != nil {
		e.unconsume(executed)
		e.restore(q.ID, legs)
		return Execution{}, err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		e.unconsume(executed)
		e.restore(q.ID, legs)
		return Execution{}, err
	}
	return e.book(ctx, q)
}

// restore puts back the reservation of a quote that stays open because its
// execution did not commit.
func (e *Engine) restore(id uuid.UUID, legs []Leg) {
	if legs == nil {
		return
	}
	e.mu.Lock()
	e.reserved[id] = legs
	e.mu.Unlock()
	e.g.Reserve(legs)
}

// unconsume reverses executed depth after an execution that did not
// commit or failed to book.
func (e *Engine) unconsume(legs []Leg) {
	e.g.mu.Lock()
	defer e.g.mu.Unlock()
	for _, l := range legs {
		if ed := e.g.edges[l.EdgeID]; ed != nil {
			ed.executed = math.Max(ed.executed-l.Amount, 0)
		}
	}
}

// checkFunding validates the accounts before any depth is taken: the
// funding belongs to the user, holds at least AmountIn in From, and the
// destination is in To; both fx books exist.
func (e *Engine) checkFunding(ctx context.Context, q *storedQuote, req ExecuteRequest) error {
	if _, ok := e.cfg.FXBooks[q.From]; !ok {
		return fmt.Errorf("%w: no fx book for %s", ErrFunding, q.From)
	}
	if _, ok := e.cfg.FXBooks[q.To]; !ok {
		return fmt.Errorf("%w: no fx book for %s", ErrFunding, q.To)
	}
	source := req.SourceAccount
	if req.HoldID != uuid.Nil {
		h, err := e.ledger.Hold(ctx, req.HoldID)
		if err != nil {
			return fmt.Errorf("%w: hold: %w", ErrFunding, err)
		}
		if h.State != ledger.HoldPending || h.Currency != q.From || h.Amount < q.AmountIn {
			return fmt.Errorf("%w: hold %s is %s %d %s", ErrFunding, h.ID, h.State, h.Amount, h.Currency)
		}
		source = h.AccountID
	}
	src, err := e.ledger.Account(ctx, source)
	if err != nil {
		return fmt.Errorf("%w: source: %w", ErrFunding, err)
	}
	if src.Currency != q.From || src.OwnerID == nil || *src.OwnerID != q.UserID {
		return fmt.Errorf("%w: source account %s is not the user's %s account", ErrFunding, src.ID, q.From)
	}
	dst, err := e.ledger.Account(ctx, req.DestinationAccount)
	if err != nil {
		return fmt.Errorf("%w: destination: %w", ErrFunding, err)
	}
	if dst.Currency != q.To {
		return fmt.Errorf("%w: destination account is %s, not %s", ErrFunding, dst.Currency, q.To)
	}
	return nil
}

// Sweep expires open quotes past their expiry and releases their
// reservations; it returns how many it expired.
func (e *Engine) Sweep(ctx context.Context) (int, error) {
	ids, err := e.db.expire(ctx, e.cfg.Now())
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		e.dropReservation(id)
	}
	return len(ids), nil
}

// Recover rebuilds reservations from the open quotes in the database (a
// newly elected engine) and returns the executing quotes whose booking
// must be resumed.
func (e *Engine) Recover(ctx context.Context) ([]uuid.UUID, error) {
	if _, err := e.Sweep(ctx); err != nil {
		return nil, err
	}
	open, executing, err := e.db.recoverable(ctx)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	for id, legs := range open {
		if _, known := e.reserved[id]; !known {
			e.reserved[id] = legs
			e.g.Reserve(legs)
		}
	}
	e.mu.Unlock()
	return executing, nil
}

// Resume completes the booking of an executing quote (recovery sweeper).
func (e *Engine) Resume(ctx context.Context, id uuid.UUID) (Execution, error) {
	tx, q, err := e.db.lock(ctx, id)
	if err != nil {
		return Execution{}, err
	}
	state := q.State
	if err := tx.Commit(ctx); err != nil {
		return Execution{}, err
	}
	switch state {
	case StateExecuting:
		return e.book(ctx, q)
	case StateBooked:
		return q.execution(), nil
	default:
		return Execution{}, fmt.Errorf("%w: quote %s is %s", ErrRequest, id, state)
	}
}

// Get returns a quote and, once executed, its execution.
func (e *Engine) Get(ctx context.Context, userID, id uuid.UUID) (*Quote, *Execution, error) {
	q, err := e.db.get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if q.UserID != userID {
		return nil, nil, ErrUnknownQuote
	}
	if q.State == StateExecuting || q.State == StateBooked || q.State == StateFailed {
		x := q.execution()
		return &q.Quote, &x, nil
	}
	return &q.Quote, nil, nil
}

// Pending lists executing quotes whose booking has been pending longer than
// age; the recovery sweeper resumes them.
func (e *Engine) Pending(ctx context.Context, age time.Duration) ([]uuid.UUID, error) {
	return e.db.stale(ctx, e.cfg.Now().Add(-age))
}
