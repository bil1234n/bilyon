// Package fx is Bilyon's FX engine (RFC 0001 §3.C): a liquidity graph of
// depth ladders, a hop-bounded max-output router with water-filling split
// routing, rate-lock pricing, soft reservations with overbooking, firm
// HMAC-signed quotes and idempotent, crash-safe execution booked on the
// ledger.
//
// The search runs in float64, which only ranks routes. Every amount a
// customer sees or the ledger books is recomputed in exact rationals and
// floored once per leg (§3.C.9), so replicas agree to the minor unit.
package fx

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"slices"
	"sync"
	"time"
)

// Errors.
var (
	ErrUnknownCurrency = errors.New("fx: unknown currency")
	ErrUnknownEdge     = errors.New("fx: unknown edge")
	ErrInvalidEdge     = errors.New("fx: invalid edge")
	ErrNoRoute         = errors.New("fx: no route with enough liquidity")
)

var (
	codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{2,7}$`)
	idPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
)

// Currency is an ISO 4217 code (or a normalised stablecoin code) with its
// minor-unit exponent: USD 2, JPY 0, KWD 3, USDC 6.
type Currency struct {
	Code string
	Exp  int
}

// Level is one rung of executable depth: up to Size minor units of the
// source currency convert at Rate (target major units per source major
// unit), a decimal string parsed exactly.
type Level struct {
	Size int64  `json:"size"`
	Rate string `json:"rate"`
}

// EdgeSpec configures a venue between two currencies: the netting book,
// an LP stream, a stablecoin ramp or a rail.
type EdgeSpec struct {
	ID       string
	From, To string
	Venue    string        // e.g. "internal", "lp:alpha", "l2:usdc", "rail:sepa-inst"
	FeeFixed int64         // source minor units per use
	FeePPM   int64         // proportional fee, parts per million (100 ppm = 1 bp)
	Latency  time.Duration // settlement time, for the SLA filter
	// StaleAfter disables the edge for new quotes when its ladder is older
	// (LP streams: 2 s). Zero means the ladder never goes stale.
	StaleAfter time.Duration
}

type level struct {
	size int64
	rate float64
	rat  *big.Rat
	raw  string
}

type edge struct {
	spec     EdgeSpec
	scale    float64  // 10^(exp(to) − exp(from))
	scaleRat *big.Rat // the same, exact
	fee      float64  // 1 − FeePPM/10⁶
	feeRat   *big.Rat

	ladder    []level
	depth     int64
	updatedAt time.Time
	enabled   bool
	// Quarantine: the edge closed a negative cycle (an arbitrage, usually a
	// bad or crossed price). It stays out of routing until the cycle is gone.
	quarantine []string

	reserved float64 // source minor units promised to open quotes (overbooked)
	executed float64 // source minor units executed against the current ladder
}

func (e *edge) consumed() float64 { return e.reserved + e.executed }

// usable reports whether the router may use the edge at now.
func (e *edge) usable(now time.Time) bool {
	if !e.enabled || e.quarantine != nil || len(e.ladder) == 0 {
		return false
	}
	return e.spec.StaleAfter == 0 || now.Sub(e.updatedAt) <= e.spec.StaleAfter
}

// out is the float output (target minor units) for x source minor units,
// or ok=false when x exceeds the remaining depth. Non-decreasing and, past
// the fixed fee, concave in x (§3.C.1).
func (e *edge) out(x float64) (float64, bool) {
	if x -= float64(e.spec.FeeFixed); x <= 0 {
		return 0, true
	}
	skip, got := e.consumed(), 0.0
	for _, l := range e.ladder {
		avail := float64(l.size)
		if skip >= avail {
			skip -= avail
			continue
		}
		avail -= skip
		skip = 0
		take := math.Min(x, avail)
		got += take * l.rate
		if x -= take; x <= 0 {
			return got * e.scale * e.fee, true
		}
	}
	return 0, false
}

// outExact is the settlement amount for an integer input in exact rational
// arithmetic, floored once (a venue never delivers fractional minor units).
func (e *edge) outExact(x int64) (int64, bool) {
	if x -= e.spec.FeeFixed; x <= 0 {
		return 0, true
	}
	skip := int64(math.Ceil(e.consumed()))
	got := new(big.Rat)
	for _, l := range e.ladder {
		avail := l.size
		if skip >= avail {
			skip -= avail
			continue
		}
		avail -= skip
		skip = 0
		take := min(x, avail)
		got.Add(got, new(big.Rat).Mul(new(big.Rat).SetInt64(take), l.rat))
		if x -= take; x == 0 {
			got.Mul(got, e.scaleRat)
			got.Mul(got, e.feeRat)
			v := new(big.Int).Quo(got.Num(), got.Denom()) // floor: got ≥ 0
			if !v.IsInt64() {
				return 0, false
			}
			return v.Int64(), true
		}
	}
	return 0, false
}

// topRate is the edge's best effective major-unit rate, r₁·(1 − φ): the
// weight the arbitrage check uses (exponents cancel around a cycle).
func (e *edge) topRate() float64 {
	if len(e.ladder) == 0 {
		return 0
	}
	return e.ladder[0].rate * e.fee
}

// Quarantine reports an edge excluded because it closed a negative cycle.
type Quarantine struct {
	EdgeID  string
	Cycle   []string // edge ids around the cycle, starting with EdgeID
	Product float64  // product of effective top-of-book rates (> 1)
}

// GraphConfig configures a graph.
type GraphConfig struct {
	// ArbitrageTolerance: a cycle whose rate product exceeds 1 + tolerance
	// is an arbitrage (default 1e-6, a hundredth of a basis point).
	ArbitrageTolerance float64
	// CycleHops bounds the length of the cycles the check looks for
	// (default 4: every cycle a ≤3-hop route could close).
	CycleHops int
	// OnQuarantine and OnRelease observe quarantine changes (treasury
	// alerts, metrics). They run with the graph locked and must not call
	// back into it.
	OnQuarantine func(Quarantine)
	OnRelease    func(edgeID string)
	Now          func() time.Time
}

// Graph is the liquidity graph. It is safe for concurrent use: routing
// takes a read lock; ladder updates, switches and reservations take the
// write lock.
type Graph struct {
	mu         sync.RWMutex
	cfg        GraphConfig
	currencies map[string]Currency
	edges      map[string]*edge
	out        map[string][]*edge // per source currency, in edge id order
}

// NewGraph creates a graph over the given currencies.
func NewGraph(cfg GraphConfig, currencies ...Currency) (*Graph, error) {
	if cfg.ArbitrageTolerance == 0 {
		cfg.ArbitrageTolerance = 1e-6
	}
	if cfg.CycleHops == 0 {
		cfg.CycleHops = 4
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	g := &Graph{cfg: cfg, currencies: map[string]Currency{}, edges: map[string]*edge{}, out: map[string][]*edge{}}
	for _, c := range currencies {
		if !codePattern.MatchString(c.Code) || c.Exp < 0 || c.Exp > 18 {
			return nil, fmt.Errorf("%w: %q (exponent %d)", ErrUnknownCurrency, c.Code, c.Exp)
		}
		if _, dup := g.currencies[c.Code]; dup {
			return nil, fmt.Errorf("fx: currency %s listed twice", c.Code)
		}
		g.currencies[c.Code] = c
	}
	return g, nil
}

// Currency returns a registered currency.
func (g *Graph) Currency(code string) (Currency, bool) {
	c, ok := g.currencies[code]
	return c, ok
}

func pow10(n int) *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil) }

func parseLadder(id string, ladder []Level) ([]level, int64, error) {
	out := make([]level, len(ladder))
	prev := math.Inf(1)
	var depth int64
	for i, l := range ladder {
		r, ok := new(big.Rat).SetString(l.Rate)
		if !ok || r.Sign() <= 0 || l.Size <= 0 {
			return nil, 0, fmt.Errorf("%w: %s level %d (%d at %q)", ErrInvalidEdge, id, i, l.Size, l.Rate)
		}
		f, _ := r.Float64()
		if f > prev {
			return nil, 0, fmt.Errorf("%w: %s ladder must worsen monotonically", ErrInvalidEdge, id)
		}
		if depth > math.MaxInt64-l.Size {
			return nil, 0, fmt.Errorf("%w: %s ladder depth overflows", ErrInvalidEdge, id)
		}
		prev, depth = f, depth+l.Size
		out[i] = level{size: l.Size, rate: f, rat: r, raw: l.Rate}
	}
	return out, depth, nil
}

// AddEdge registers a venue. It starts enabled with the given ladder (which
// may be empty until its feed delivers one).
func (g *Graph) AddEdge(spec EdgeSpec, ladder []Level) error {
	if !idPattern.MatchString(spec.ID) {
		return fmt.Errorf("%w: id %q", ErrInvalidEdge, spec.ID)
	}
	from, ok1 := g.currencies[spec.From]
	to, ok2 := g.currencies[spec.To]
	if !ok1 || !ok2 || spec.From == spec.To {
		return fmt.Errorf("%w: %s from %s to %s", ErrInvalidEdge, spec.ID, spec.From, spec.To)
	}
	if spec.FeeFixed < 0 || spec.FeePPM < 0 || spec.FeePPM >= 1_000_000 || spec.Latency < 0 || spec.StaleAfter < 0 {
		return fmt.Errorf("%w: %s fees, latency or staleness", ErrInvalidEdge, spec.ID)
	}
	levels, depth, err := parseLadder(spec.ID, ladder)
	if err != nil {
		return err
	}
	e := &edge{spec: spec, ladder: levels, depth: depth, enabled: true,
		scale:    math.Pow10(to.Exp - from.Exp),
		scaleRat: new(big.Rat).SetFrac(pow10(max(to.Exp-from.Exp, 0)), pow10(max(from.Exp-to.Exp, 0))),
		fee:      1 - float64(spec.FeePPM)/1e6, feeRat: big.NewRat(1_000_000-spec.FeePPM, 1_000_000)}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.edges[spec.ID]; dup {
		return fmt.Errorf("%w: %s already exists", ErrInvalidEdge, spec.ID)
	}
	if len(levels) > 0 {
		e.updatedAt = g.cfg.Now()
	}
	g.edges[spec.ID] = e
	list := append(g.out[spec.From], e)
	slices.SortFunc(list, func(a, b *edge) int {
		switch {
		case a.spec.ID < b.spec.ID:
			return -1
		case a.spec.ID > b.spec.ID:
			return 1
		}
		return 0
	})
	g.out[spec.From] = list
	g.afterUpdate(e)
	return nil
}

// SetLadder replaces an edge's depth (a streaming LP update or a treasury
// inventory change). Depth executed against the previous ladder is
// forgotten (the venue's new ladder reflects it); reservations for open
// quotes still count. The arbitrage check runs on every update.
func (g *Graph) SetLadder(id string, ladder []Level, at time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.edges[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownEdge, id)
	}
	levels, depth, err := parseLadder(id, ladder)
	if err != nil {
		return err
	}
	if at.Before(e.updatedAt) {
		return nil // an out-of-order update is older than what we have
	}
	e.ladder, e.depth, e.updatedAt, e.executed = levels, depth, at, 0
	g.afterUpdate(e)
	return nil
}

// SetEnabled switches an edge on or off (sanctions, licensing, venue halt).
func (g *Graph) SetEnabled(id string, enabled bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.edges[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownEdge, id)
	}
	e.enabled = enabled
	g.afterUpdate(e)
	return nil
}

// EdgeState is a snapshot of one edge for operators and metrics.
type EdgeState struct {
	Spec        EdgeSpec
	Ladder      []Level
	Depth       int64
	Reserved    float64
	Executed    float64
	UpdatedAt   time.Time
	Enabled     bool
	Stale       bool
	Quarantined []string // the cycle, when quarantined
}

// Edges returns every edge's state, in id order.
func (g *Graph) Edges() []EdgeState {
	g.mu.RLock()
	defer g.mu.RUnlock()
	now := g.cfg.Now()
	out := make([]EdgeState, 0, len(g.edges))
	for _, e := range g.edges {
		lad := make([]Level, len(e.ladder))
		for i, l := range e.ladder {
			lad[i] = Level{Size: l.size, Rate: l.raw}
		}
		out = append(out, EdgeState{Spec: e.spec, Ladder: lad, Depth: e.depth, Reserved: e.reserved, Executed: e.executed,
			UpdatedAt: e.updatedAt, Enabled: e.enabled,
			Stale:       e.spec.StaleAfter > 0 && len(e.ladder) > 0 && now.Sub(e.updatedAt) > e.spec.StaleAfter,
			Quarantined: slices.Clone(e.quarantine)})
	}
	slices.SortFunc(out, func(a, b EdgeState) int {
		switch {
		case a.Spec.ID < b.Spec.ID:
			return -1
		case a.Spec.ID > b.Spec.ID:
			return 1
		}
		return 0
	})
	return out
}

// afterUpdate maintains quarantines after edge e changed (§3.C.2): cycles
// that no longer pay release their edge (unless another cycle still runs
// through it), then a cycle closed by e quarantines e. Quarantined edges do
// not take part in the search for new cycles, so one bad price quarantines
// one edge rather than every edge on its cycles. Called with g.mu held.
func (g *Graph) afterUpdate(e *edge) {
	for _, q := range g.sortedEdges() {
		if q.quarantine == nil || (q != e && g.cycleProduct(q.quarantine) > 1+g.cfg.ArbitrageTolerance) {
			continue
		}
		prev := q.quarantine
		q.quarantine = nil
		if cycle, product := g.cycleThrough(q); cycle != nil {
			q.quarantine = cycle
			if !slices.Equal(prev, cycle) && g.cfg.OnQuarantine != nil {
				g.cfg.OnQuarantine(Quarantine{EdgeID: q.spec.ID, Cycle: slices.Clone(cycle), Product: product})
			}
		} else if g.cfg.OnRelease != nil {
			g.cfg.OnRelease(q.spec.ID)
		}
	}
	if e.quarantine == nil {
		if cycle, product := g.cycleThrough(e); cycle != nil {
			e.quarantine = cycle
			if g.cfg.OnQuarantine != nil {
				g.cfg.OnQuarantine(Quarantine{EdgeID: e.spec.ID, Cycle: slices.Clone(cycle), Product: product})
			}
		}
	}
}

func (g *Graph) sortedEdges() []*edge {
	all := make([]*edge, 0, len(g.edges))
	for _, e := range g.edges {
		all = append(all, e)
	}
	slices.SortFunc(all, func(a, b *edge) int {
		switch {
		case a.spec.ID < b.spec.ID:
			return -1
		case a.spec.ID > b.spec.ID:
			return 1
		}
		return 0
	})
	return all
}

// cycleProduct is the effective rate product around a recorded cycle.
func (g *Graph) cycleProduct(cycle []string) float64 {
	p := 1.0
	for _, id := range cycle {
		e := g.edges[id]
		if e == nil || !e.enabled {
			return 0
		}
		p *= e.topRate()
	}
	return p
}

// cycleThrough looks for an arbitrage cycle of at most CycleHops edges
// closed by e = u→v: the best rate product of a walk from v back to u over
// enabled, unquarantined edges with ladders, times e's own rate. It is the
// hop-bounded Bellman–Ford check on w = −ln r, written multiplicatively.
func (g *Graph) cycleThrough(e *edge) ([]string, float64) {
	if !e.enabled || len(e.ladder) == 0 {
		return nil, 0
	}
	type label struct {
		product float64
		path    []string
	}
	u, v := e.spec.From, e.spec.To
	frontier := map[string]label{v: {product: e.topRate(), path: []string{e.spec.ID}}}
	var best label
	for hop := 1; hop < g.cfg.CycleHops && len(frontier) > 0; hop++ {
		next := map[string]label{}
		nodes := make([]string, 0, len(frontier))
		for n := range frontier {
			nodes = append(nodes, n)
		}
		slices.Sort(nodes)
		for _, n := range nodes {
			lab := frontier[n]
			for _, f := range g.out[n] {
				if f == e || !f.enabled || f.quarantine != nil || len(f.ladder) == 0 {
					continue
				}
				p := lab.product * f.topRate()
				if f.spec.To == u {
					if p > best.product {
						best = label{p, append(slices.Clone(lab.path), f.spec.ID)}
					}
					continue
				}
				if cur, seen := next[f.spec.To]; !seen || p > cur.product {
					next[f.spec.To] = label{p, append(slices.Clone(lab.path), f.spec.ID)}
				}
			}
		}
		frontier = next
	}
	if best.product > 1+g.cfg.ArbitrageTolerance {
		return best.path, best.product
	}
	return nil, 0
}

// Leg is depth taken on one edge.
type Leg struct {
	EdgeID string  `json:"edge"`
	Amount float64 `json:"amount"` // source minor units
}

// reserve adds overbooked reservations; release removes them; consume
// records execution. Called with g.mu held for writing.
func (g *Graph) reserve(legs []Leg) {
	for _, l := range legs {
		if e := g.edges[l.EdgeID]; e != nil {
			e.reserved += l.Amount
		}
	}
}

func (g *Graph) release(legs []Leg) {
	for _, l := range legs {
		if e := g.edges[l.EdgeID]; e != nil {
			e.reserved = math.Max(e.reserved-l.Amount, 0)
		}
	}
}

func (g *Graph) consume(legs []Leg) {
	for _, l := range legs {
		if e := g.edges[l.EdgeID]; e != nil {
			e.executed += l.Amount
		}
	}
}

// Reserve, Release and Consume are the locked forms of the reservation
// operations, used when recovering open quotes and in tests.
func (g *Graph) Reserve(legs []Leg) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reserve(legs)
}

// Release removes reservations.
func (g *Graph) Release(legs []Leg) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.release(legs)
}

// Consume records executed depth.
func (g *Graph) Consume(legs []Leg) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.consume(legs)
}
