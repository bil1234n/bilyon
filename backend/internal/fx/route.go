package fx

import (
	"math"
	"slices"
	"time"
)

// RouteOptions bound the search.
type RouteOptions struct {
	MaxHops    int           // legs per route (default 3)
	MaxLatency time.Duration // settlement SLA; 0 means none
	Splits     int           // candidate routes for splitting (default 3)
	Chunks     int           // water-filling increments (default 20)
}

func (o RouteOptions) withDefaults() RouteOptions {
	if o.MaxHops == 0 {
		o.MaxHops = 3
	}
	if o.Splits == 0 {
		o.Splits = 3
	}
	if o.Chunks == 0 {
		o.Chunks = 20
	}
	return o
}

type route []*edge

func (r route) out(x float64) (float64, bool) {
	for _, e := range r {
		var ok bool
		if x, ok = e.out(x); !ok {
			return 0, false
		}
	}
	return x, true
}

// exact chains exact outputs, flooring at every leg, and returns the amount
// entering each leg.
func (r route) exact(x int64) (inputs []int64, out int64, ok bool) {
	inputs = make([]int64, len(r))
	for i, e := range r {
		inputs[i] = x
		if x, ok = e.outExact(x); !ok {
			return nil, 0, false
		}
	}
	return inputs, x, true
}

func (r route) latency() time.Duration {
	var d time.Duration
	for _, e := range r {
		d += e.spec.Latency
	}
	return d
}

func (r route) visits(c string) bool {
	for _, e := range r {
		if e.spec.From == c || e.spec.To == c {
			return true
		}
	}
	return false
}

// legs is the depth a route takes for exact leg inputs: what passes the
// fixed fee and fills the ladder.
func (r route) legs(inputs []int64) []Leg {
	out := make([]Leg, len(r))
	for i, e := range r {
		out[i] = Leg{EdgeID: e.spec.ID, Amount: float64(max(inputs[i]-e.spec.FeeFixed, 0))}
	}
	return out
}

// bestRoute is the hop-bounded max-output dynamic programme (§3.C.2) over
// usable edges not in hidden. Labels per (hop, currency) keep the largest
// amount; frontier currencies and edges are visited in sorted order and
// ties keep the first label, so the result is deterministic. Requires g.mu.
func (g *Graph) bestRoute(src, dst string, x float64, o RouteOptions, now time.Time, hidden map[*edge]bool) (route, float64, bool) {
	type label struct {
		amt float64
		r   route
	}
	frontier := map[string]label{src: {amt: x}}
	best := label{amt: -1}
	for h := 1; h <= o.MaxHops && len(frontier) > 0; h++ {
		next := map[string]label{}
		nodes := make([]string, 0, len(frontier))
		for n := range frontier {
			nodes = append(nodes, n)
		}
		slices.Sort(nodes)
		for _, n := range nodes {
			lab := frontier[n]
			for _, e := range g.out[n] {
				if hidden[e] || !e.usable(now) || e.spec.To == src || lab.r.visits(e.spec.To) {
					continue
				}
				if o.MaxLatency > 0 && lab.r.latency()+e.spec.Latency > o.MaxLatency {
					continue
				}
				amt, ok := e.out(lab.amt)
				if !ok {
					continue
				}
				if cur, seen := next[e.spec.To]; !seen || amt > cur.amt {
					next[e.spec.To] = label{amt, append(slices.Clone(lab.r), e)}
				}
			}
		}
		if l, ok := next[dst]; ok && l.amt > best.amt {
			best = l
		}
		delete(next, dst) // never route through the destination
		frontier = next
	}
	return best.r, best.amt, best.amt >= 0
}

// Allocation is one slice of a (possibly split) conversion.
type Allocation struct {
	EdgeIDs []string `json:"edges"`
	Venues  []string `json:"venues"`
	In      int64    `json:"in"`  // source minor units
	Out     int64    `json:"out"` // exact target minor units
	Legs    []Leg    `json:"legs"`

	r route
}

// Plan is a priced conversion.
type Plan struct {
	Allocations []Allocation
	Out         int64 // Σ exact outputs
}

func (p Plan) legs() []Leg {
	var out []Leg
	for _, a := range p.Allocations {
		out = append(out, a.Legs...)
	}
	return out
}

func newAllocation(r route, in int64) (Allocation, bool) {
	inputs, out, ok := r.exact(in)
	if !ok {
		return Allocation{}, false
	}
	a := Allocation{In: in, Out: out, Legs: r.legs(inputs), r: r}
	for _, e := range r {
		a.EdgeIDs = append(a.EdgeIDs, e.spec.ID)
		a.Venues = append(a.Venues, e.spec.Venue)
	}
	return a, true
}

// splitRoute spreads amount over up to Splits edge-disjoint routes by
// water-filling (§3.C.3): each of Chunks increments goes to the route with
// the largest marginal output. The result is compared with the single best
// route, which guards the fixed-fee non-concavity. Requires g.mu.
func (g *Graph) splitRoute(src, dst string, amount int64, o RouteOptions, now time.Time) (Plan, bool) {
	var routes []route
	hidden := map[*edge]bool{}
	for len(routes) < o.Splits {
		r, _, ok := g.bestRoute(src, dst, float64(amount)/float64(o.Splits), o, now, hidden)
		if !ok {
			break
		}
		routes = append(routes, r)
		for _, e := range r {
			hidden[e] = true
		}
	}
	alloc := make([]int64, len(routes))
	outF := func(i int, x int64) float64 {
		if x == 0 {
			return 0
		}
		v, ok := routes[i].out(float64(x))
		if !ok {
			return math.Inf(-1)
		}
		return v
	}
	step := amount / int64(o.Chunks)
	for left := amount; left > 0 && len(routes) > 0; {
		d := min(max(step, 1), left)
		if left-d < step { // fold the remainder into the last chunk
			d = left
		}
		bestI, bestGain := -1, math.Inf(-1)
		for i := range routes {
			if gain := outF(i, alloc[i]+d) - outF(i, alloc[i]); gain > bestGain {
				bestI, bestGain = i, gain
			}
		}
		if bestI < 0 || math.IsInf(bestGain, -1) {
			alloc = nil
			break
		}
		alloc[bestI] += d
		left -= d
	}
	var split Plan
	splitOK := alloc != nil && len(routes) > 0
	for i, in := range alloc {
		if in == 0 {
			continue
		}
		a, ok := newAllocation(routes[i], in)
		if !ok {
			splitOK = false
			break
		}
		split.Allocations = append(split.Allocations, a)
		split.Out += a.Out
	}
	if r, _, ok := g.bestRoute(src, dst, float64(amount), o, now, nil); ok {
		if a, ok := newAllocation(r, amount); ok && (!splitOK || a.Out >= split.Out) {
			return Plan{Allocations: []Allocation{a}, Out: a.Out}, true
		}
	}
	return split, splitOK
}

// revalidate recomputes a plan's exact amounts against the current depth;
// ok is false when a leg no longer has the liquidity. Requires g.mu.
func (g *Graph) revalidate(p Plan, now time.Time) (Plan, bool) {
	var out Plan
	for _, a := range p.Allocations {
		for _, e := range a.r {
			if !e.usable(now) {
				return Plan{}, false
			}
		}
		fresh, ok := newAllocation(a.r, a.In)
		if !ok {
			return Plan{}, false
		}
		out.Allocations = append(out.Allocations, fresh)
		out.Out += fresh.Out
	}
	return out, len(out.Allocations) > 0
}

// RouteInfo describes a route.
type RouteInfo struct {
	EdgeIDs []string
	Venues  []string
	Latency time.Duration
}

func (r route) info() RouteInfo {
	ri := RouteInfo{Latency: r.latency()}
	for _, e := range r {
		ri.EdgeIDs = append(ri.EdgeIDs, e.spec.ID)
		ri.Venues = append(ri.Venues, e.spec.Venue)
	}
	return ri
}

// BestRoute returns the single route delivering the most dst for amount
// minor units of src, and its exact output.
func (g *Graph) BestRoute(src, dst string, amount int64, o RouteOptions) (RouteInfo, int64, error) {
	if _, ok := g.currencies[src]; !ok {
		return RouteInfo{}, 0, ErrUnknownCurrency
	}
	if _, ok := g.currencies[dst]; !ok || src == dst || amount <= 0 {
		return RouteInfo{}, 0, ErrUnknownCurrency
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	r, _, ok := g.bestRoute(src, dst, float64(amount), o.withDefaults(), g.cfg.Now(), nil)
	if !ok {
		return RouteInfo{}, 0, ErrNoRoute
	}
	_, out, ok := r.exact(amount)
	if !ok {
		return RouteInfo{}, 0, ErrNoRoute
	}
	return r.info(), out, nil
}

// SplitRoute plans a conversion over up to o.Splits routes.
func (g *Graph) SplitRoute(src, dst string, amount int64, o RouteOptions) (Plan, error) {
	if _, ok := g.currencies[src]; !ok {
		return Plan{}, ErrUnknownCurrency
	}
	if _, ok := g.currencies[dst]; !ok || src == dst || amount <= 0 {
		return Plan{}, ErrUnknownCurrency
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	p, ok := g.splitRoute(src, dst, amount, o.withDefaults(), g.cfg.Now())
	if !ok || p.Out <= 0 {
		return Plan{}, ErrNoRoute
	}
	return p, nil
}
