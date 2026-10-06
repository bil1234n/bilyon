package fx

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var currencies = []Currency{{"EUR", 2}, {"USD", 2}, {"NGN", 2}, {"JPY", 0}, {"USDC", 6}}

// market is the RFC 0001 §3.C example market.
func market(t *testing.T, c *clock, cfg GraphConfig) *Graph {
	t.Helper()
	cfg.Now = c.now
	g, err := NewGraph(cfg, currencies...)
	if err != nil {
		t.Fatal(err)
	}
	edges := []struct {
		spec   EdgeSpec
		ladder []Level
	}{
		{EdgeSpec{ID: "eur-usd-net", From: "EUR", To: "USD", Venue: "internal"}, []Level{{50_000_00, "1.0850"}}},
		{EdgeSpec{ID: "eur-usd-a", From: "EUR", To: "USD", Venue: "lp:alpha", StaleAfter: 2 * time.Second},
			[]Level{{1_000_000_00, "1.0847"}, {4_000_000_00, "1.0843"}}},
		{EdgeSpec{ID: "eur-usd-b", From: "EUR", To: "USD", Venue: "lp:beta", StaleAfter: 2 * time.Second},
			[]Level{{500_000_00, "1.0846"}, {2_000_000_00, "1.0841"}}},
		{EdgeSpec{ID: "usd-ngn", From: "USD", To: "NGN", Venue: "lp:lagos", FeePPM: 500},
			[]Level{{200_000_00, "1548.00"}, {800_000_00, "1544.50"}}},
		{EdgeSpec{ID: "eur-ngn", From: "EUR", To: "NGN", Venue: "lp:direct"}, []Level{{100_000_00, "1665.00"}}},
		{EdgeSpec{ID: "usd-usdc", From: "USD", To: "USDC", Venue: "l2:onramp", FeeFixed: 50, Latency: 2 * time.Second},
			[]Level{{10_000_000_00, "0.9999"}}},
		{EdgeSpec{ID: "usdc-ngn", From: "USDC", To: "NGN", Venue: "l2:offramp", FeePPM: 1000, Latency: 5 * time.Second},
			[]Level{{300_000_000000, "1549.20"}}},
		{EdgeSpec{ID: "usd-jpy", From: "USD", To: "JPY", Venue: "lp:tokyo"}, []Level{{5_000_000_00, "149.45"}}},
	}
	for _, e := range edges {
		if err := g.AddEdge(e.spec, e.ladder); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func venues(r RouteInfo) string { return strings.Join(r.Venues, ",") }

func TestNettingFirstAndExactAmounts(t *testing.T) {
	g := market(t, newClock(), GraphConfig{})
	r, out, err := g.BestRoute("EUR", "USD", 10_000_00, RouteOptions{})
	if err != nil || venues(r) != "internal" || out != 10_850_00 {
		t.Fatalf("route %v out %d err %v", r, out, err)
	}
	if _, out, _ := g.BestRoute("USD", "JPY", 100_00, RouteOptions{}); out != 14945 {
		t.Fatalf("USD->JPY exponent handling: %d", out)
	}
	if _, out, _ := g.BestRoute("USD", "JPY", 1, RouteOptions{}); out != 1 { // 0.01 USD = 1.4945 JPY, floored
		t.Fatalf("floor rounding: %d", out)
	}
}

func TestMultiHopAndLatencySLA(t *testing.T) {
	g := market(t, newClock(), GraphConfig{})
	r, _, _ := g.BestRoute("EUR", "NGN", 1_000_00, RouteOptions{})
	if venues(r) != "internal,lp:lagos" {
		t.Fatalf("EUR->NGN via %s, want netting then Lagos (beats the 1%% direct spread)", venues(r))
	}
	if err := g.SetEnabled("usd-ngn", false); err != nil {
		t.Fatal(err)
	}
	if r, _, _ = g.BestRoute("EUR", "NGN", 1_000_00, RouteOptions{}); venues(r) != "internal,l2:onramp,l2:offramp" {
		t.Fatalf("with the Lagos LP halted: %s", venues(r))
	}
	if r.Latency != 7*time.Second {
		t.Fatalf("latency %s", r.Latency)
	}
	if r, _, _ = g.BestRoute("EUR", "NGN", 1_000_00, RouteOptions{MaxLatency: 3 * time.Second}); venues(r) != "lp:direct" {
		t.Fatalf("a 3 s SLA must exclude the 7 s stablecoin path: %s", venues(r))
	}
	if _, _, err := g.BestRoute("USD", "JPY", 6_000_000_00, RouteOptions{}); err != ErrNoRoute {
		t.Fatalf("routed beyond the available depth: %v", err)
	}
	if _, _, err := g.BestRoute("EUR", "XXX", 1, RouteOptions{}); err != ErrUnknownCurrency {
		t.Fatalf("unknown currency: %v", err)
	}
}

func TestSplitBeatsSingleRoute(t *testing.T) {
	g := market(t, newClock(), GraphConfig{})
	p, err := g.SplitRoute("EUR", "USD", 80_000_00, RouteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, single, _ := g.BestRoute("EUR", "USD", 80_000_00, RouteOptions{})
	if p.Out <= single {
		t.Fatalf("split %d does not beat the single route %d", p.Out, single)
	}
	byVenue := map[string]int64{}
	for _, a := range p.Allocations {
		byVenue[a.Venues[0]] += a.In
	}
	// The exact optimum is 50 000 netting + 30 000 LP; water-filling lands
	// within one 4 000 chunk of it.
	if byVenue["internal"] != 48_000_00 || byVenue["internal"]+byVenue["lp:alpha"]+byVenue["lp:beta"] != 80_000_00 {
		t.Fatalf("allocation %v", byVenue)
	}
	optimum := 50_000_00*1.0850 + 30_000_00*1.0847
	if rel := (optimum - float64(p.Out)) / optimum; rel > 1e-4 || rel < 0 {
		t.Fatalf("split %d is %.2e below the optimum", p.Out, rel)
	}
}

// randomGraph builds an arbitrage-free market: every currency has a true
// value and every rate is value_from/value_to less a positive spread, so
// no cycle pays.
func randomGraph(t *testing.T, r *rand.Rand, c *clock) *Graph {
	t.Helper()
	n := 4 + r.IntN(4)
	var cs []Currency
	value := map[string]float64{}
	for i := range n {
		code := fmt.Sprintf("C%02d", i)
		cs = append(cs, Currency{code, r.IntN(4)})
		value[code] = math.Exp(r.Float64()*6 - 3)
	}
	g, err := NewGraph(GraphConfig{Now: c.now}, cs...)
	if err != nil {
		t.Fatal(err)
	}
	id := 0
	for _, a := range cs {
		for _, b := range cs {
			if a == b || r.Float64() < 0.4 {
				continue
			}
			for range 1 + r.IntN(2) {
				id++
				rate := value[a.Code] / value[b.Code] * (1 - 0.0005 - r.Float64()*0.02)
				var ladder []Level
				for k := range 1 + r.IntN(3) {
					rk := rate * (1 - 0.001*float64(k))
					ladder = append(ladder, Level{Size: int64(1+r.IntN(50)) * 1000, Rate: strconv.FormatFloat(rk, 'f', 10, 64)})
				}
				spec := EdgeSpec{ID: fmt.Sprintf("e%03d", id), From: a.Code, To: b.Code, Venue: fmt.Sprintf("v%d", id),
					FeeFixed: int64(r.IntN(3)), FeePPM: int64(r.IntN(300))}
				if err := g.AddEdge(spec, ladder); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return g
}

// bruteForce enumerates every simple path of at most hops legs.
func bruteForce(g *Graph, src, dst string, x float64, hops int, now time.Time) float64 {
	best := -1.0
	var walk func(at string, amt float64, r route)
	walk = func(at string, amt float64, r route) {
		if len(r) == hops {
			return
		}
		for _, e := range g.out[at] {
			if !e.usable(now) || e.spec.To == src || r.visits(e.spec.To) {
				continue
			}
			y, ok := e.out(amt)
			if !ok {
				continue
			}
			next := append(slices.Clone(r), e)
			if e.spec.To == dst {
				best = math.Max(best, y)
				continue
			}
			walk(e.spec.To, y, next)
		}
	}
	walk(src, x, nil)
	return best
}

func TestDPMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 141))
	c := newClock()
	for i := range 300 {
		g := randomGraph(t, r, c)
		codes := make([]string, 0, len(g.currencies))
		for code := range g.currencies {
			codes = append(codes, code)
		}
		slices.Sort(codes)
		src, dst := codes[r.IntN(len(codes))], codes[r.IntN(len(codes))]
		if src == dst {
			continue
		}
		x := float64(1000 + r.IntN(60_000))
		g.mu.RLock()
		_, got, ok := g.bestRoute(src, dst, x, RouteOptions{}.withDefaults(), c.now(), nil)
		want := bruteForce(g, src, dst, x, 3, c.now())
		g.mu.RUnlock()
		if !ok {
			got = -1
		}
		if math.Abs(got-want) > 1e-9*math.Max(1, want) {
			t.Fatalf("graph %d %s->%s %.0f: DP %.6f, exhaustive %.6f", i, src, dst, x, got, want)
		}
		for _, q := range g.edges {
			if q.quarantine != nil {
				t.Fatalf("graph %d: arbitrage-free market quarantined %s (%v)", i, q.spec.ID, q.quarantine)
			}
		}
	}
}

func TestStaleLPsAreSkipped(t *testing.T) {
	c := newClock()
	g := market(t, c, GraphConfig{})
	if err := g.SetEnabled("eur-usd-net", false); err != nil {
		t.Fatal(err)
	}
	r, _, _ := g.BestRoute("EUR", "USD", 10_000_00, RouteOptions{})
	if venues(r) != "lp:alpha" {
		t.Fatalf("route %s", venues(r))
	}
	c.advance(3 * time.Second) // both LP streams fall silent
	if _, _, err := g.BestRoute("EUR", "USD", 10_000_00, RouteOptions{}); err != ErrNoRoute {
		t.Fatalf("stale LPs still routed: %v", err)
	}
	if err := g.SetLadder("eur-usd-b", []Level{{500_000_00, "1.0846"}}, c.now()); err != nil {
		t.Fatal(err)
	}
	if r, _, _ = g.BestRoute("EUR", "USD", 10_000_00, RouteOptions{}); venues(r) != "lp:beta" {
		t.Fatalf("refreshed LP not used: %s", venues(r))
	}
	// An out-of-order update older than the current ladder is ignored.
	if err := g.SetLadder("eur-usd-b", []Level{{1, "9.9"}}, c.now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, e := range g.Edges() {
		if e.Spec.ID == "eur-usd-b" && e.Ladder[0].Rate != "1.0846" {
			t.Fatalf("out-of-order ladder applied: %+v", e.Ladder)
		}
		if e.Spec.ID == "eur-usd-a" && !e.Stale {
			t.Fatal("silent LP not reported stale")
		}
	}
}

func TestArbitrageQuarantine(t *testing.T) {
	c := newClock()
	var quarantined []Quarantine
	var released []string
	g := market(t, c, GraphConfig{OnQuarantine: func(q Quarantine) { quarantined = append(quarantined, q) },
		OnRelease: func(id string) { released = append(released, id) }})
	// A USD->EUR LP; at 0.9200 the EUR->USD->EUR cycle pays nothing.
	if err := g.AddEdge(EdgeSpec{ID: "usd-eur-c", From: "USD", To: "EUR", Venue: "lp:gamma"}, []Level{{1_000_000_00, "0.9200"}}); err != nil {
		t.Fatal(err)
	}
	if len(quarantined) != 0 {
		t.Fatalf("no arbitrage, but %v", quarantined)
	}
	// A crossed price: 1.0850 · 0.9300 = 1.009 > 1.
	if err := g.SetLadder("usd-eur-c", []Level{{1_000_000_00, "0.9300"}}, c.now()); err != nil {
		t.Fatal(err)
	}
	if len(quarantined) != 1 || quarantined[0].EdgeID != "usd-eur-c" || quarantined[0].Product <= 1 {
		t.Fatalf("quarantine %+v", quarantined)
	}
	if cyc := quarantined[0].Cycle; len(cyc) != 2 || cyc[0] != "usd-eur-c" || cyc[1] != "eur-usd-net" {
		t.Fatalf("cycle %v", cyc)
	}
	if _, _, err := g.BestRoute("USD", "EUR", 1_000_00, RouteOptions{}); err != ErrNoRoute {
		t.Fatalf("quarantined edge routed: %v", err)
	}
	// The netting edge keeps working: one bad price quarantines one edge.
	if r, _, _ := g.BestRoute("EUR", "USD", 1_000_00, RouteOptions{}); venues(r) != "internal" {
		t.Fatalf("netting edge affected: %s", venues(r))
	}
	// Updating the netting edge does not quarantine it as well.
	if err := g.SetLadder("eur-usd-net", []Level{{50_000_00, "1.0851"}}, c.now()); err != nil {
		t.Fatal(err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("second quarantine %+v", quarantined)
	}
	// Fixing the price releases the edge.
	if err := g.SetLadder("usd-eur-c", []Level{{1_000_000_00, "0.9210"}}, c.now()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(released, []string{"usd-eur-c"}) {
		t.Fatalf("released %v", released)
	}
	if r, _, err := g.BestRoute("USD", "EUR", 1_000_00, RouteOptions{}); err != nil || venues(r) != "lp:gamma" {
		t.Fatalf("released edge not routed: %v %v", r, err)
	}
	// A cycle that stops paying because another edge was switched off
	// releases its edge too.
	if err := g.SetLadder("usd-eur-c", []Level{{1_000_000_00, "0.9300"}}, c.now()); err != nil {
		t.Fatal(err)
	}
	if err := g.SetEnabled("eur-usd-net", false); err != nil {
		t.Fatal(err)
	}
	// Alpha (1.0847 · 0.93 = 1.0088) still closes a cycle with the new
	// price, so the edge stays quarantined, now on the alpha cycle.
	if q := quarantined[len(quarantined)-1]; q.EdgeID != "usd-eur-c" || q.Cycle[1] != "eur-usd-a" {
		t.Fatalf("re-quarantine %+v", q)
	}
	for _, id := range []string{"eur-usd-a", "eur-usd-b"} {
		if err := g.SetEnabled(id, false); err != nil {
			t.Fatal(err)
		}
	}
	if released[len(released)-1] != "usd-eur-c" {
		t.Fatalf("released %v", released)
	}
}

func TestEdgeValidation(t *testing.T) {
	g, err := NewGraph(GraphConfig{}, currencies...)
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]struct {
		spec   EdgeSpec
		ladder []Level
	}{
		"bad id":          {EdgeSpec{ID: "Bad ID", From: "EUR", To: "USD"}, nil},
		"unknown":         {EdgeSpec{ID: "x", From: "EUR", To: "XXX"}, nil},
		"same currencies": {EdgeSpec{ID: "x", From: "EUR", To: "EUR"}, nil},
		"negative fee":    {EdgeSpec{ID: "x", From: "EUR", To: "USD", FeeFixed: -1}, nil},
		"whole fee":       {EdgeSpec{ID: "x", From: "EUR", To: "USD", FeePPM: 1_000_000}, nil},
		"zero size":       {EdgeSpec{ID: "x", From: "EUR", To: "USD"}, []Level{{0, "1.08"}}},
		"zero rate":       {EdgeSpec{ID: "x", From: "EUR", To: "USD"}, []Level{{1, "0"}}},
		"bad rate":        {EdgeSpec{ID: "x", From: "EUR", To: "USD"}, []Level{{1, "1,08"}}},
		"improving":       {EdgeSpec{ID: "x", From: "EUR", To: "USD"}, []Level{{1, "1.08"}, {1, "1.09"}}},
		"overflow":        {EdgeSpec{ID: "x", From: "EUR", To: "USD"}, []Level{{math.MaxInt64, "1.08"}, {1, "1.07"}}},
	}
	for name, c := range bad {
		if err := g.AddEdge(c.spec, c.ladder); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := g.AddEdge(EdgeSpec{ID: "ok", From: "EUR", To: "USD"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(EdgeSpec{ID: "ok", From: "EUR", To: "USD"}, nil); err == nil {
		t.Error("duplicate edge accepted")
	}
	if err := g.SetLadder("missing", nil, time.Now()); err == nil {
		t.Error("unknown edge updated")
	}
	if _, _, err := g.BestRoute("EUR", "USD", 100, RouteOptions{}); err != ErrNoRoute {
		t.Errorf("an edge without a ladder routed: %v", err)
	}
	for _, cs := range [][]Currency{{{"eur", 2}}, {{"EUR", -1}}, {{"EUR", 2}, {"EUR", 2}}} {
		if _, err := NewGraph(GraphConfig{}, cs...); err == nil {
			t.Errorf("currencies %v accepted", cs)
		}
	}
}

func TestDeterministicRoutes(t *testing.T) {
	g := market(t, newClock(), GraphConfig{})
	first, err := g.SplitRoute("EUR", "NGN", 250_000_00, RouteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		p, err := g.SplitRoute("EUR", "NGN", 250_000_00, RouteOptions{})
		if err != nil || p.Out != first.Out || len(p.Allocations) != len(first.Allocations) {
			t.Fatalf("plan changed: %+v vs %+v (%v)", p, first, err)
		}
		for i := range p.Allocations {
			if !slices.Equal(p.Allocations[i].EdgeIDs, first.Allocations[i].EdgeIDs) || p.Allocations[i].In != first.Allocations[i].In {
				t.Fatalf("allocation %d changed", i)
			}
		}
	}
}

func TestConcurrentRoutingAndUpdates(t *testing.T) {
	c := newClock()
	g := market(t, c, GraphConfig{})
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Go(func() {
			for i := range 200 {
				if w%2 == 0 {
					rate := strconv.FormatFloat(1.0840+float64(i%5)/10000, 'f', 4, 64)
					if err := g.SetLadder("eur-usd-a", []Level{{1_000_000_00, rate}}, c.now()); err != nil {
						t.Error(err)
						return
					}
					g.Reserve([]Leg{{EdgeID: "eur-usd-net", Amount: 10}})
					g.Release([]Leg{{EdgeID: "eur-usd-net", Amount: 10}})
				} else if _, err := g.SplitRoute("EUR", "USD", 120_000_00, RouteOptions{}); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	for _, e := range g.Edges() {
		if e.Spec.ID == "eur-usd-net" && e.Reserved != 0 {
			t.Fatalf("reservations leaked: %v", e.Reserved)
		}
	}
}

func TestLockBuffer(t *testing.T) {
	for _, c := range []struct {
		sigma float64
		ttl   time.Duration
		jump  float64
		want  float64
	}{
		{0.07, 30 * time.Second, 0, 1.59},
		{0.07, 24 * time.Hour, 0, 85.37},
		{0.35, 30 * time.Second, 15, 22.95},
	} {
		got := LockBufferBps(c.sigma, c.ttl, 2.33) + c.jump
		if math.Abs(got-c.want) > 0.01 {
			t.Errorf("σ %.2f ttl %s: %.3f bp, want %.2f", c.sigma, c.ttl, got, c.want)
		}
	}
	keep, err := KeepPPM(LockBufferBps(0.07, 30*time.Second, 2.33), 8)
	if err != nil || keep != 999_040 {
		t.Fatalf("keep %d, %v", keep, err)
	}
	if out := CustomerAmount(10_850_00, keep); out != 10_839_58 {
		t.Fatalf("customer amount %d", out)
	}
	if _, err := KeepPPM(9_000, 1_000); err == nil {
		t.Fatal("a 100 % markup produced a quote")
	}
	if out := CustomerAmount(math.MaxInt64/2, 999_999); out <= 0 {
		t.Fatalf("large amounts overflow: %d", out)
	}
}

// TestExactRespectsConsumedDepth: reserved and executed depth is skipped at
// the top of the ladder, by the float search and the exact amounts alike.
func TestExactRespectsConsumedDepth(t *testing.T) {
	g, err := NewGraph(GraphConfig{}, Currency{"AAA", 0}, Currency{"BBB", 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(EdgeSpec{ID: "ab", From: "AAA", To: "BBB"}, []Level{{100, "2"}, {100, "1"}}); err != nil {
		t.Fatal(err)
	}
	if _, out, _ := g.BestRoute("AAA", "BBB", 100, RouteOptions{}); out != 200 {
		t.Fatalf("fresh ladder: %d", out)
	}
	g.Reserve([]Leg{{EdgeID: "ab", Amount: 50}})
	if _, out, _ := g.BestRoute("AAA", "BBB", 100, RouteOptions{}); out != 150 {
		t.Fatalf("after reserving 50: %d, want 50·2 + 50·1", out)
	}
	g.Consume([]Leg{{EdgeID: "ab", Amount: 49.5}}) // fractional consumption rounds up for exact amounts
	if _, out, _ := g.BestRoute("AAA", "BBB", 100, RouteOptions{}); out != 100 {
		t.Fatalf("after consuming 99.5: %d, want 100·1", out)
	}
	if _, _, err := g.BestRoute("AAA", "BBB", 101, RouteOptions{}); err != ErrNoRoute {
		t.Fatalf("beyond the remaining depth: %v", err)
	}
	g.mu.RLock()
	f, ok := g.edges["ab"].out(100)
	g.mu.RUnlock()
	if !ok || math.Abs(f-100.5) > 1e-9 {
		t.Fatalf("float output %.3f", f)
	}
}
