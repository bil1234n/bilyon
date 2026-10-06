package fx

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"
)

const secondsPerYear = 365 * 24 * 3600

// LockBufferBps prices a rate lock: the platform carries the pair's move for
// the lock window, and z standard deviations of a Brownian move over ttl is
// the buffer, z*sigma*sqrt(ttl/year). EUR/USD (sigma ~7%) locked for 30 s
// needs ~1.6 bp at z=2.33 (99%).
func LockBufferBps(sigmaAnnual, ttlSeconds, z float64) float64 {
	return z * sigmaAnnual * math.Sqrt(ttlSeconds/secondsPerYear) * 1e4
}

// PairRisk is per-pair risk configuration.
type PairRisk struct {
	SigmaAnnual float64 // realised/implied volatility
	JumpBps     float64 // gap-risk premium for pairs with jumps or thin liquidity
	MaxTTL      time.Duration
}

// Errors returned by the quote engine.
var (
	ErrNoRoute       = errors.New("fx: no route with enough liquidity")
	ErrPairNotConfig = errors.New("fx: pair risk not configured")
	ErrUnknownQuote  = errors.New("fx: unknown quote")
	ErrTampered      = errors.New("fx: quote signature mismatch")
	ErrExpired       = errors.New("fx: quote expired, requote")
	ErrRequote       = errors.New("fx: extreme market move, requote")
)

// Quote is a firm, signed offer: the customer receives exactly AmountOut if
// they accept before ExpiresAt, whatever the market does in between (except
// the documented extreme-move breaker).
type Quote struct {
	ID          string
	From, To    string
	AmountIn    int64
	AmountOut   int64
	MidOut      float64 // mid-market equivalent, shown for transparency
	ExecCostBps float64 // spread/depth/fee cost of the chosen routes vs mid
	BufferBps   float64 // lock buffer (volatility over TTL + jump premium)
	MarginBps   float64
	Allocations []Allocation
	ExpiresAt   time.Time
	Sig         []byte
}

func (q *Quote) canonical() []byte {
	return []byte(fmt.Sprintf("bilyon/fxq/v1|%s|%s|%s|%d|%d|%d", q.ID, q.From, q.To, q.AmountIn,
		q.AmountOut, q.ExpiresAt.UnixMilli()))
}

// Execution records an accepted quote.
type Execution struct {
	QuoteID   string
	AmountOut int64 // delivered to the customer (= quote)
	MarketOut int64 // what executing now actually yields
	PnL       int64 // MarketOut - AmountOut, target minor units
}

type reservation struct {
	e   *Edge
	amt float64
}

type quoteState struct {
	q        Quote
	reserved []reservation
	executed *Execution
}

// QuoteEngine issues and executes firm quotes.
type QuoteEngine struct {
	G             *Graph
	Mid           map[string]float64 // "EUR/USD" -> target major per source major
	Risk          map[string]PairRisk
	Z             float64 // buffer confidence (2.33 = 99%)
	MarginBps     float64
	MaxAdverseBps float64 // breaker: requote only beyond this adverse move
	Overbook      float64 // reservations count 1/Overbook of their size (quote-to-trade < 1)
	MaxHops       int
	MaxLatency    float64
	Splits        int
	Chunks        int
	Now           func() time.Time

	key    []byte
	quotes map[string]*quoteState
	seq    int
}

// NewQuoteEngine returns an engine with production defaults.
func NewQuoteEngine(g *Graph, mid map[string]float64, risk map[string]PairRisk, key []byte, now func() time.Time) *QuoteEngine {
	return &QuoteEngine{G: g, Mid: mid, Risk: risk, Z: 2.33, MarginBps: 8, MaxAdverseBps: 150, Overbook: 1.5,
		MaxHops: 3, MaxLatency: 60, Splits: 3, Chunks: 20, Now: now, key: key, quotes: map[string]*quoteState{}}
}

func (qe *QuoteEngine) sign(q *Quote) []byte {
	m := hmac.New(sha256.New, qe.key)
	m.Write(q.canonical())
	return m.Sum(nil)
}

// legInputs returns the input amount entering each leg of a route.
func legInputs(r Route, in float64) []float64 {
	out := make([]float64, len(r))
	for i, e := range r {
		out[i] = in
		in, _ = e.Out(in)
	}
	return out
}

// Quote prices AmountIn of From into To with a TTL-long rate lock.
func (qe *QuoteEngine) Quote(from, to string, amountIn int64, ttl time.Duration) (*Quote, error) {
	pair := from + "/" + to
	risk, ok := qe.Risk[pair]
	if !ok {
		return nil, ErrPairNotConfig
	}
	if risk.MaxTTL > 0 && ttl > risk.MaxTTL {
		ttl = risk.MaxTTL
	}
	allocs, execOut, ok := qe.G.SplitRoute(from, to, amountIn, qe.MaxHops, qe.MaxLatency, qe.Splits, qe.Chunks)
	if !ok || execOut <= 0 {
		return nil, ErrNoRoute
	}
	scale := math.Pow10(qe.G.Currencies[to].Exp - qe.G.Currencies[from].Exp)
	midOut := float64(amountIn) * qe.Mid[pair] * scale
	buffer := LockBufferBps(risk.SigmaAnnual, ttl.Seconds(), qe.Z) + risk.JumpBps
	// Customer amount = executable output less buffer and margin, in exact
	// integer ppm arithmetic, rounded down once.
	keepPPM := int64(math.Floor(1e6 * (1 - (buffer+qe.MarginBps)/1e4)))
	out := new(big.Int).Mul(big.NewInt(execOut), big.NewInt(keepPPM))
	out.Quo(out, big.NewInt(1_000_000))

	qe.seq++
	q := Quote{ID: fmt.Sprintf("q-%06d", qe.seq), From: from, To: to, AmountIn: amountIn, AmountOut: out.Int64(),
		MidOut: midOut, ExecCostBps: (midOut - float64(execOut)) / midOut * 1e4, BufferBps: buffer,
		MarginBps: qe.MarginBps, Allocations: allocs, ExpiresAt: qe.Now().Add(ttl)}
	q.Sig = qe.sign(&q)

	// Soft-reserve depth so concurrent quotes do not promise the same
	// liquidity; overbooked because most quotes are never accepted.
	st := &quoteState{q: q}
	for _, a := range allocs {
		for i, in := range legInputs(a.Route, float64(a.In)) {
			r := reservation{a.Route[i], in / qe.Overbook}
			r.e.consumed += r.amt
			st.reserved = append(st.reserved, r)
		}
	}
	qe.quotes[q.ID] = st
	return &q, nil
}

func (qe *QuoteEngine) release(st *quoteState) {
	for _, r := range st.reserved {
		r.e.consumed = math.Max(r.e.consumed-r.amt, 0)
	}
	st.reserved = nil
}

// Execute accepts a quote the client presents (ID + signature). It is
// idempotent per quote ID. The rate is honoured even if the market moved
// against the platform, unless the move exceeds MaxAdverseBps.
func (qe *QuoteEngine) Execute(id string, sig []byte) (*Execution, error) {
	st, ok := qe.quotes[id]
	if !ok {
		return nil, ErrUnknownQuote
	}
	if !hmac.Equal(sig, qe.sign(&st.q)) {
		return nil, ErrTampered
	}
	if st.executed != nil {
		return st.executed, nil
	}
	if qe.Now().After(st.q.ExpiresAt) {
		qe.release(st)
		return nil, ErrExpired
	}
	qe.release(st)
	allocs, marketOut, ok := qe.G.SplitRoute(st.q.From, st.q.To, st.q.AmountIn, qe.MaxHops, qe.MaxLatency, qe.Splits, qe.Chunks)
	floor := float64(st.q.AmountOut) * (1 - qe.MaxAdverseBps/1e4)
	if !ok || float64(marketOut) < floor {
		return nil, ErrRequote
	}
	for _, a := range allocs { // consume the depth for real
		for i, in := range legInputs(a.Route, float64(a.In)) {
			a.Route[i].consumed += in
		}
	}
	st.executed = &Execution{QuoteID: id, AmountOut: st.q.AmountOut, MarketOut: marketOut, PnL: marketOut - st.q.AmountOut}
	return st.executed, nil
}

// SetLadder replaces an edge's depth (streaming LP update) and clears the
// depth consumed against the previous ladder.
func (g *Graph) SetLadder(edgeID string, ladder []Level) error {
	e, ok := g.edges[edgeID]
	if !ok {
		return fmt.Errorf("unknown edge %s", edgeID)
	}
	tmp := *e
	tmp.Ladder = ladder
	if err := g.prepare(&tmp); err != nil {
		return err
	}
	e.Ladder, e.consumed = tmp.Ladder, 0
	return nil
}
