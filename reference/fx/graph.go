// Package fx is the reference implementation of Algorithm C (RFC 0001
// §3.C): liquidity routing over depth ladders, marginal-rate split routing,
// rate-lock pricing and the firm-quote lifecycle.
//
// Search runs in float64 (it only ranks candidate routes); every amount a
// customer sees or the ledger books is recomputed exactly with big.Rat and
// rounded once per settlement leg, so all replicas agree to the minor unit.
package fx

import (
	"fmt"
	"math"
	"math/big"
)

// Currency is an ISO 4217 code with its minor-unit exponent (USD 2, JPY 0,
// KWD 3; USDC on-chain is normalised to 6).
type Currency struct {
	Code string
	Exp  int
}

// Level is one rung of executable depth: up to Size minor units of the
// source currency convert at Rate (target major units per source major unit).
type Level struct {
	Size int64
	Rate string // decimal string, parsed once; e.g. "1.08512"

	rate float64
	rat  *big.Rat
}

// Edge is a conversion or transfer venue between two currencies.
type Edge struct {
	ID       string
	From, To string
	Venue    string  // "internal", "lp:alpha", "l2:usdc", "rail:sepa-inst", ...
	Ladder   []Level // ordered best rate first (concave execution)
	FeeFixed int64   // source minor units, charged per use
	FeePPM   int64   // proportional fee, parts per million (100 ppm = 1 bp)
	Latency  float64 // seconds to settle; routes exceeding the SLA are excluded
	Disabled bool    // corridor switched off (sanctions, licence, venue halt)

	consumed float64 // depth taken by executions and (overbooked) reservations
	scale    float64 // 10^(exp(To) - exp(From))
	scaleRat *big.Rat
}

// Graph is the liquidity graph.
type Graph struct {
	Currencies map[string]Currency
	out        map[string][]*Edge
	edges      map[string]*Edge
}

// NewGraph creates a graph over the given currencies.
func NewGraph(cs ...Currency) *Graph {
	g := &Graph{Currencies: map[string]Currency{}, out: map[string][]*Edge{}, edges: map[string]*Edge{}}
	for _, c := range cs {
		g.Currencies[c.Code] = c
	}
	return g
}

// AddEdge validates and inserts an edge.
func (g *Graph) AddEdge(e *Edge) error {
	if err := g.prepare(e); err != nil {
		return err
	}
	g.out[e.From] = append(g.out[e.From], e)
	g.edges[e.ID] = e
	return nil
}

// prepare validates an edge and parses its ladder.
func (g *Graph) prepare(e *Edge) error {
	from, ok1 := g.Currencies[e.From]
	to, ok2 := g.Currencies[e.To]
	if !ok1 || !ok2 || e.From == e.To {
		return fmt.Errorf("edge %s: unknown or identical currencies", e.ID)
	}
	prev := math.Inf(1)
	for i := range e.Ladder {
		l := &e.Ladder[i]
		r, ok := new(big.Rat).SetString(l.Rate)
		if !ok || r.Sign() <= 0 || l.Size <= 0 {
			return fmt.Errorf("edge %s: bad level %d", e.ID, i)
		}
		l.rat = r
		l.rate, _ = r.Float64()
		if l.rate > prev {
			return fmt.Errorf("edge %s: ladder must worsen monotonically", e.ID)
		}
		prev = l.rate
	}
	e.scale = math.Pow10(to.Exp - from.Exp)
	e.scaleRat = new(big.Rat).SetFrac(pow10(max(to.Exp-from.Exp, 0)), pow10(max(from.Exp-to.Exp, 0)))
	return nil
}

func pow10(n int) *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil) }

// Depth is the remaining executable input in source minor units.
func (e *Edge) Depth() float64 {
	var d float64
	for _, l := range e.Ladder {
		d += float64(l.Size)
	}
	return math.Max(d-e.consumed, 0)
}

// Out is the float output (target minor units) for x source minor units, or
// ok=false when x exceeds the remaining depth. Out is non-decreasing and,
// past the fixed fee, concave in x: the properties the router relies on.
func (e *Edge) Out(x float64) (float64, bool) {
	if e.Disabled {
		return 0, false
	}
	if x -= float64(e.FeeFixed); x <= 0 {
		return 0, true // feasible, but the fixed fee eats everything
	}
	skip, got := e.consumed, 0.0
	for _, l := range e.Ladder {
		avail := float64(l.Size)
		if skip >= avail {
			skip -= avail
			continue
		}
		avail -= skip
		skip = 0
		take := math.Min(x, avail)
		got += take * l.rate
		if x -= take; x <= 0 {
			return got * e.scale * (1 - float64(e.FeePPM)/1e6), true
		}
	}
	return 0, false
}

// OutExact is the settlement amount for an integer input: exact rational
// arithmetic, rounded down once at the end of the leg (the venue never
// delivers fractional minor units).
func (e *Edge) OutExact(x int64) (int64, bool) {
	if e.Disabled {
		return 0, false
	}
	if x -= e.FeeFixed; x <= 0 {
		return 0, true
	}
	skip := int64(math.Ceil(e.consumed))
	got := new(big.Rat)
	for _, l := range e.Ladder {
		avail := l.Size
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
			got.Mul(got, big.NewRat(1_000_000-e.FeePPM, 1_000_000))
			return new(big.Int).Quo(got.Num(), got.Denom()).Int64(), true // floor (got >= 0)
		}
	}
	return 0, false
}

// Route is a path of edges.
type Route []*Edge

// Out chains float outputs along the route.
func (r Route) Out(x float64) (float64, bool) {
	for _, e := range r {
		var ok bool
		if x, ok = e.Out(x); !ok {
			return 0, false
		}
	}
	return x, true
}

// OutExact chains exact outputs, rounding down at every leg.
func (r Route) OutExact(x int64) (int64, bool) {
	for _, e := range r {
		var ok bool
		if x, ok = e.OutExact(x); !ok {
			return 0, false
		}
	}
	return x, true
}

// Latency is the sum of leg settlement times.
func (r Route) Latency() (s float64) {
	for _, e := range r {
		s += e.Latency
	}
	return s
}

func (r Route) String() string {
	s := ""
	for i, e := range r {
		if i == 0 {
			s = e.From
		}
		s += fmt.Sprintf(" -[%s]-> %s", e.Venue, e.To)
	}
	return s
}
