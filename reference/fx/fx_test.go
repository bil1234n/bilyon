package fx

import (
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

func market(t *testing.T) *Graph {
	t.Helper()
	g := NewGraph(Currency{"EUR", 2}, Currency{"USD", 2}, Currency{"NGN", 2}, Currency{"JPY", 0}, Currency{"USDC", 6})
	edges := []*Edge{
		{ID: "eur-usd-net", From: "EUR", To: "USD", Venue: "internal", Ladder: []Level{{Size: 50_000_00, Rate: "1.0850"}}},
		{ID: "eur-usd-a", From: "EUR", To: "USD", Venue: "lp:alpha",
			Ladder: []Level{{Size: 1_000_000_00, Rate: "1.0847"}, {Size: 4_000_000_00, Rate: "1.0843"}}},
		{ID: "eur-usd-b", From: "EUR", To: "USD", Venue: "lp:beta",
			Ladder: []Level{{Size: 500_000_00, Rate: "1.0846"}, {Size: 2_000_000_00, Rate: "1.0841"}}},
		{ID: "usd-ngn", From: "USD", To: "NGN", Venue: "lp:lagos", FeePPM: 500,
			Ladder: []Level{{Size: 200_000_00, Rate: "1548.00"}, {Size: 800_000_00, Rate: "1544.50"}}},
		{ID: "eur-ngn", From: "EUR", To: "NGN", Venue: "lp:direct", Ladder: []Level{{Size: 100_000_00, Rate: "1665.00"}}},
		{ID: "usd-usdc", From: "USD", To: "USDC", Venue: "l2:onramp", FeeFixed: 50, Latency: 2,
			Ladder: []Level{{Size: 10_000_000_00, Rate: "0.9999"}}},
		{ID: "usdc-ngn", From: "USDC", To: "NGN", Venue: "l2:offramp", FeePPM: 1000, Latency: 5,
			Ladder: []Level{{Size: 300_000_000000, Rate: "1549.20"}}},
		{ID: "usd-jpy", From: "USD", To: "JPY", Venue: "lp:tokyo", Ladder: []Level{{Size: 5_000_000_00, Rate: "149.45"}}},
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func venues(r Route) string {
	var v []string
	for _, e := range r {
		v = append(v, e.Venue)
	}
	return strings.Join(v, ",")
}

func TestNettingFirstAndExactAmounts(t *testing.T) {
	g := market(t)
	r, _, ok := g.BestRoute("EUR", "USD", 10_000_00, 3, 60)
	if !ok || venues(r) != "internal" {
		t.Fatalf("route %v", r)
	}
	if out, _ := r.OutExact(10_000_00); out != 10_850_00 {
		t.Fatalf("exact out %d", out)
	}
	jpy := Route{g.edges["usd-jpy"]}
	if out, _ := jpy.OutExact(100_00); out != 14945 {
		t.Fatalf("USD->JPY exponent handling: %d", out)
	}
	if out, _ := jpy.OutExact(1); out != 1 { // 0.01 USD = 1.4945 JPY -> floor 1
		t.Fatalf("floor rounding: %d", out)
	}
}

func TestMultiHopAndLatencySLA(t *testing.T) {
	g := market(t)
	r, _, _ := g.BestRoute("EUR", "NGN", 1_000_00, 3, 60)
	if venues(r) != "internal,lp:lagos" {
		t.Fatalf("EUR->NGN via %s, want netting then Lagos LP (beats the 1%% direct spread)", venues(r))
	}
	g.edges["usd-ngn"].Disabled = true // corridor halted
	if r, _, _ = g.BestRoute("EUR", "NGN", 1_000_00, 3, 60); venues(r) != "internal,l2:onramp,l2:offramp" {
		t.Fatalf("with LP halted: %s", venues(r))
	}
	if r, _, _ = g.BestRoute("EUR", "NGN", 1_000_00, 3, 3); venues(r) != "lp:direct" {
		t.Fatalf("with a 3 s SLA the 7 s stablecoin path must be excluded: %s", venues(r))
	}
	if _, _, ok := g.BestRoute("USD", "JPY", 6_000_000_00, 3, 60); ok {
		t.Fatal("routed beyond available depth")
	}
}

func TestSplitBeatsSingleRoute(t *testing.T) {
	g := market(t)
	single := Route{g.edges["eur-usd-a"]}
	singleOut, _ := single.OutExact(80_000_00)
	allocs, out, ok := g.SplitRoute("EUR", "USD", 80_000_00, 3, 60, 3, 20)
	if !ok || len(allocs) < 2 {
		t.Fatalf("expected a split, got %+v", allocs)
	}
	optimum := int64(50_000_00*1.0850 + 30_000_00*1.0847)
	if out <= singleOut || float64(optimum-out)/float64(optimum) > 1e-4 {
		t.Fatalf("split out %d, single %d, optimum %d", out, singleOut, optimum)
	}
	var in int64
	for _, a := range allocs {
		in += a.In
	}
	if in != 80_000_00 {
		t.Fatalf("allocations sum to %d", in)
	}
}

// TestDPMatchesBruteForce checks the hop-bounded DP against exhaustive
// enumeration of simple paths on random arbitrage-free graphs.
func TestDPMatchesBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	codes := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
	for trial := 0; trial < 300; trial++ {
		g := NewGraph()
		value := map[string]float64{}
		for _, c := range codes {
			g.Currencies[c] = Currency{c, 2}
			value[c] = math.Exp(rng.Float64()*6 - 3)
		}
		for i := 0; i < 22; i++ {
			from, to := codes[rng.Intn(len(codes))], codes[rng.Intn(len(codes))]
			if from == to {
				continue
			}
			var ladder []Level
			rate := value[from] / value[to] * (1 - 0.0005 - rng.Float64()*0.01) // spread > 0: no arbitrage
			for l := 0; l < 1+rng.Intn(3); l++ {
				ladder = append(ladder, Level{Size: int64(1 + rng.Intn(50_000)), Rate: ftoa(rate)})
				rate *= 1 - rng.Float64()*0.003
			}
			_ = g.AddEdge(&Edge{ID: strconv.Itoa(i), From: from, To: to, Ladder: ladder, FeePPM: int64(rng.Intn(300))})
		}
		x := float64(1 + rng.Intn(30_000))
		_, dp, okDP := g.BestRoute("A", "H", x, 3, 60)
		bf, okBF := bruteForce(g, "A", "H", x, 3)
		if okDP != okBF || (okDP && math.Abs(dp-bf) > 1e-9*math.Max(1, bf)) {
			t.Fatalf("trial %d: dp=%v(%v) brute=%v(%v)", trial, dp, okDP, bf, okBF)
		}
	}
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 12, 64) }

func bruteForce(g *Graph, src, dst string, x float64, hops int) (float64, bool) {
	best, found := -1.0, false
	var walk func(node string, amt float64, seen map[string]bool, depth int)
	walk = func(node string, amt float64, seen map[string]bool, depth int) {
		if depth == hops {
			return
		}
		for _, e := range g.out[node] {
			if seen[e.To] {
				continue
			}
			out, ok := e.Out(amt)
			if !ok {
				continue
			}
			if e.To == dst {
				if out > best {
					best, found = out, true
				}
				continue
			}
			seen[e.To] = true
			walk(e.To, out, seen, depth+1)
			delete(seen, e.To)
		}
	}
	walk(src, x, map[string]bool{src: true}, 0)
	return best, found
}

func TestLockBuffer(t *testing.T) {
	if b := LockBufferBps(0.07, 30, 2.33); math.Abs(b-1.591) > 0.01 {
		t.Fatalf("EUR/USD 30 s buffer %.3f bp", b)
	}
	if b := LockBufferBps(0.35, 30, 2.33); math.Abs(b-7.95) > 0.02 {
		t.Fatalf("NGN 30 s buffer %.3f bp", b)
	}
	if b := LockBufferBps(0.07, 24*3600, 2.33); math.Abs(b-85.2) > 0.2 {
		t.Fatalf("24 h invoice lock %.2f bp", b) // why long locks are priced separately
	}
}

func engine(t *testing.T, now *time.Time) *QuoteEngine {
	g := market(t)
	mid := map[string]float64{"EUR/USD": 1.0850, "EUR/NGN": 1681.75}
	risk := map[string]PairRisk{"EUR/USD": {SigmaAnnual: 0.07}, "EUR/NGN": {SigmaAnnual: 0.35, JumpBps: 15}}
	return NewQuoteEngine(g, mid, risk, []byte("test-hmac-key"), func() time.Time { return *now })
}

func TestQuoteLifecycle(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	qe := engine(t, &now)
	q, err := qe.Quote("EUR", "USD", 10_000_00, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if q.AmountOut != 10_839_58 { // floor(10_850_00 * 999040 ppm)
		t.Fatalf("customer amount %d", q.AmountOut)
	}
	if total := (q.MidOut - float64(q.AmountOut)) / q.MidOut * 1e4; total > 10 {
		t.Fatalf("all-in cost %.2f bp exceeds the 10 bp majors target", total)
	}
	before := qe.G.edges["eur-usd-net"].consumed
	ex, err := qe.Execute(q.ID, q.Sig)
	if err != nil || ex.AmountOut != q.AmountOut || ex.PnL != 10_850_00-10_839_58 {
		t.Fatalf("execute: %+v %v", ex, err)
	}
	again, _ := qe.Execute(q.ID, q.Sig)
	if again != ex || qe.G.edges["eur-usd-net"].consumed > before+10_000_00 {
		t.Fatal("execution not idempotent")
	}
	bad := append([]byte(nil), q.Sig...)
	bad[0] ^= 1
	if _, err := qe.Execute(q.ID, bad); err != ErrTampered {
		t.Fatalf("tampered: %v", err)
	}
	q2, _ := qe.Quote("EUR", "USD", 5_000_00, 30*time.Second)
	now = now.Add(31 * time.Second)
	if _, err := qe.Execute(q2.ID, q2.Sig); err != ErrExpired {
		t.Fatalf("expired: %v", err)
	}
	if c := qe.G.edges["eur-usd-net"].consumed; math.Abs(c-10_000_00) > 1e-6 {
		t.Fatalf("expired quote reservation not released: consumed %.2f", c)
	}
	if _, err := qe.Quote("USD", "JPY", 100, time.Second); err != ErrPairNotConfig {
		t.Fatalf("unconfigured pair: %v", err)
	}
}

func TestFirmQuoteAndBreaker(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	shift := func(qe *QuoteEngine, factor string) {
		for _, id := range []string{"eur-usd-net", "eur-usd-a", "eur-usd-b"} {
			if err := qe.G.SetLadder(id, []Level{{Size: 1_000_000_00, Rate: factor}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	qe := engine(t, &now)
	q, _ := qe.Quote("EUR", "USD", 10_000_00, 30*time.Second)
	shift(qe, "1.0796") // ~50 bp adverse move within the lock: honoured at a loss
	ex, err := qe.Execute(q.ID, q.Sig)
	if err != nil || ex.PnL >= 0 || ex.AmountOut != q.AmountOut {
		t.Fatalf("firm quote not honoured: %+v %v", ex, err)
	}
	qe = engine(t, &now)
	q, _ = qe.Quote("EUR", "USD", 10_000_00, 30*time.Second)
	shift(qe, "1.0500") // ~3% gap: beyond MaxAdverseBps
	if _, err := qe.Execute(q.ID, q.Sig); err != ErrRequote {
		t.Fatalf("breaker: %v", err)
	}
}

func TestReservationsPreventOverpromising(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	qe := engine(t, &now)
	netting := func(q *Quote) (in int64) {
		for _, a := range q.Allocations {
			if a.Route[0].Venue == "internal" {
				in += a.In
			}
		}
		return in
	}
	q1, _ := qe.Quote("EUR", "USD", 60_000_00, 30*time.Second)
	q2, _ := qe.Quote("EUR", "USD", 60_000_00, 30*time.Second)
	if q2.AmountOut >= q1.AmountOut {
		t.Fatalf("second quote promised the same netting liquidity: %d vs %d", q2.AmountOut, q1.AmountOut)
	}
	// q1 holds netting depth at 1/Overbook of its size; q2 may only use the rest.
	if limit := 50_000_00 - float64(netting(q1))/qe.Overbook; float64(netting(q2)) > limit {
		t.Fatalf("q2 used %d of netting depth, limit %.0f", netting(q2), limit)
	}
}
