package fx

import "math"

// BestRoute maximises the amount of dst delivered for x minor units of src
// over simple paths of at most maxHops legs within maxLatency seconds.
//
// Dynamic programme over (hop count, currency): every leg's Out is
// non-decreasing in its input, so the largest amount that reaches a currency
// in h hops dominates every smaller amount for any continuation (principle
// of optimality). Cost is O(maxHops*|E|) leg evaluations. Paths never
// revisit a currency, so cycles created by stale quotes are never routed.
// Exactness holds when legs do not share liquidity and the graph is
// arbitrage-free; reconciliation catches the rest (RFC 0001 §3.C.2).
func (g *Graph) BestRoute(src, dst string, x float64, maxHops int, maxLatency float64) (Route, float64, bool) {
	type label struct {
		amt   float64
		route Route
	}
	frontier := map[string]label{src: {amt: x}}
	best := label{amt: -1}
	for h := 1; h <= maxHops && len(frontier) > 0; h++ {
		next := map[string]label{}
		for u, lab := range frontier {
			for _, e := range g.out[u] {
				if e.To == src || visits(lab.route, e.To) {
					continue
				}
				r := append(append(Route(nil), lab.route...), e)
				if r.Latency() > maxLatency {
					continue
				}
				amt, ok := e.Out(lab.amt)
				if !ok {
					continue
				}
				if cur, seen := next[e.To]; !seen || amt > cur.amt {
					next[e.To] = label{amt, r}
				}
			}
		}
		if l, ok := next[dst]; ok && l.amt > best.amt {
			best = l
		}
		delete(next, dst) // never route through the destination
		frontier = next
	}
	return best.route, best.amt, best.amt >= 0
}

func visits(r Route, c string) bool {
	for _, e := range r {
		if e.From == c || e.To == c {
			return true
		}
	}
	return false
}

// Allocation is one slice of a split payment.
type Allocation struct {
	Route Route
	In    int64 // source minor units
	Out   int64 // exact target minor units
}

// SplitRoute spreads amount over up to k edge-disjoint routes. Each of
// `chunks` increments goes to the route with the best marginal output given
// what it already carries (water-filling); for concave route outputs this
// greedy allocation is optimal up to the chunk size. The result is compared
// with the single best route, which guards the one non-concavity (a fixed
// fee) and ensures splitting is never worse.
func (g *Graph) SplitRoute(src, dst string, amount int64, maxHops int, maxLatency float64, k, chunks int) ([]Allocation, int64, bool) {
	// Candidate routes: best route, then best route avoiding the edges already used.
	var routes []Route
	var hidden []*Edge
	for len(routes) < k {
		r, _, ok := g.BestRoute(src, dst, float64(amount)/float64(k), maxHops, maxLatency)
		if !ok {
			break
		}
		routes = append(routes, r)
		for _, e := range r {
			if !e.Disabled {
				e.Disabled = true
				hidden = append(hidden, e)
			}
		}
	}
	for _, e := range hidden {
		e.Disabled = false
	}

	alloc := make([]int64, len(routes))
	outF := func(i int, x int64) float64 {
		if x == 0 {
			return 0
		}
		v, ok := routes[i].Out(float64(x))
		if !ok {
			return math.Inf(-1)
		}
		return v
	}
	step := amount / int64(chunks)
	for left := amount; left > 0; {
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

	var split []Allocation
	var splitOut int64
	for i, in := range alloc {
		if in == 0 {
			continue
		}
		out, ok := routes[i].OutExact(in)
		if !ok {
			split, splitOut = nil, 0
			break
		}
		split = append(split, Allocation{routes[i], in, out})
		splitOut += out
	}

	if r, _, ok := g.BestRoute(src, dst, float64(amount), maxHops, maxLatency); ok {
		if out, ok := r.OutExact(amount); ok && out >= splitOut {
			return []Allocation{{r, amount, out}}, out, true
		}
	}
	return split, splitOut, split != nil
}
