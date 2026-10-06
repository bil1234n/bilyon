package kinetic

import (
	"math"
	"math/rand"
	"testing"
)

const hz = 200.0

type flickSpec struct {
	az, vPeak, dur float64 // world azimuth of the throw, peak speed, accel+decel duration
	yawDrift       float64 // wrist rotation during the gesture, rad
	elev           float64 // elevation of the throw direction, rad
	sweep          float64 // rotation of the push direction during the accelerating half, rad
	hold           float64 // constant-velocity plateau between the halves, s
}

// synthFlick: 0.3 s steady aim (top edge pointing at az), then a push whose
// accelerating half follows v = vPeak*sin^2(pi*t/dur), an optional plateau,
// and a decelerating half that brings the phone back to rest along the
// achieved velocity. Noise 0.15 m/s^2 per axis plus a device-frame bias.
func synthFlick(fs flickSpec, rng *rand.Rand) []IMUSample {
	bias := Vec3{0.05, -0.04, 0.03}
	half := fs.dur / 2
	mag := func(tau float64) float64 { return fs.vPeak * math.Pi / fs.dur * math.Sin(2*math.Pi*tau/fs.dur) }
	var out []IMUSample
	var vel Vec3 // achieved velocity at the end of the accelerating half
	for i := 0; ; i++ {
		t := float64(i) / hz
		tau := t - 0.3
		if tau > fs.dur+fs.hold+0.3 {
			return out
		}
		var aW Vec3
		switch {
		case tau >= 0 && tau < half:
			az := fs.az + fs.sweep*(tau/half-0.5)
			u := Vec3{math.Cos(fs.elev) * math.Cos(az), math.Cos(fs.elev) * math.Sin(az), math.Sin(fs.elev)}
			aW = u.Scale(mag(tau))
			vel = vel.Add(aW.Scale(1 / hz))
		case tau >= half+fs.hold && tau < fs.dur+fs.hold:
			aW = vel.Unit().Scale(mag(tau-fs.hold) * vel.Norm() / fs.vPeak) // mag < 0: decelerate
		}
		frac := math.Min(math.Max(tau/(fs.dur+fs.hold), 0), 1)
		att := AxisAngle(Vec3{0, 0, 1}, fs.az-math.Pi/2+fs.yawDrift*frac)
		noise := Vec3{rng.NormFloat64() * 0.15, rng.NormFloat64() * 0.15, rng.NormFloat64() * 0.15}
		yawRate := 0.0
		if frac > 0 && frac < 1 {
			yawRate = fs.yawDrift / (fs.dur + fs.hold)
		}
		out = append(out, IMUSample{T: t, UserAccel: att.Conj().Rotate(aW).Add(noise).Add(bias),
			Gyro: Vec3{0, 0, yawRate}, Attitude: att, SpecificForce: 9.81})
	}
}

func detect(samples []IMUSample) (*FlickEvent, []Reject) {
	d := NewFlickDetector(DefaultFlickParams())
	var rejects []Reject
	for _, s := range samples {
		ev, r := d.Push(s)
		if ev != nil {
			return ev, rejects
		}
		if r != Accepted {
			rejects = append(rejects, r)
		}
	}
	return nil, rejects
}

func TestFlickDetectedWithDirectionAndSpeed(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	ev, rej := detect(synthFlick(flickSpec{az: deg(30), vPeak: 1.5, dur: 0.3}, rng))
	if ev == nil {
		t.Fatalf("flick not detected, rejects %v", rej)
	}
	if e := math.Abs(wrap(ev.Azimuth - deg(30))); e > deg(3) {
		t.Errorf("azimuth error %.1f deg", e*180/math.Pi)
	}
	if s := ev.PeakVelocity.Horizontal().Norm(); math.Abs(s-1.5)/1.5 > 0.08 {
		t.Errorf("peak speed %.3f m/s, want 1.5 +/- 8%%", s)
	}
	if math.Abs(wrap(ev.AimAzimuth-deg(30))) > deg(1) {
		t.Errorf("aim azimuth %.1f deg", ev.AimAzimuth*180/math.Pi)
	}
	if ev.TEnd-ev.TOnset < 0.15 || ev.TEnd-ev.TOnset > 0.3 {
		t.Errorf("gesture duration %.3f s", ev.TEnd-ev.TOnset)
	}
}

func TestFlickDirectionSurvivesWristRotation(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	ev, rej := detect(synthFlick(flickSpec{az: deg(-70), vPeak: 1.4, dur: 0.25, yawDrift: deg(25)}, rng))
	if ev == nil {
		t.Fatalf("flick not detected, rejects %v", rej)
	}
	if e := math.Abs(wrap(ev.Azimuth - deg(-70))); e > deg(3) {
		t.Errorf("device rotation leaked into the world-frame azimuth: error %.1f deg", e*180/math.Pi)
	}
}

func TestNonFlicksRejected(t *testing.T) {
	cases := []struct {
		name string
		spec flickSpec
		want Reject // Accepted here means "never became a candidate"
	}{
		{"steep upward throw", flickSpec{vPeak: 2.5, dur: 0.3, elev: deg(60)}, RejectVertical},
		{"short jab", flickSpec{vPeak: 0.7, dur: 0.15}, RejectSlow},
		{"arm sweep", flickSpec{vPeak: 1.5, dur: 0.3, hold: 0.5}, RejectDuration},
		{"hooked push", flickSpec{vPeak: 2.2, dur: 0.3, sweep: deg(200)}, RejectCurved},
		{"slow ramp", flickSpec{vPeak: 3, dur: 1.0}, Accepted},
		{"gentle push", flickSpec{vPeak: 0.5, dur: 0.3}, Accepted},
		{"pure lift", flickSpec{vPeak: 1.5, dur: 0.3, elev: deg(90)}, Accepted},
	}
	for _, c := range cases {
		ev, rej := detect(synthFlick(c.spec, rand.New(rand.NewSource(3))))
		if ev != nil {
			t.Errorf("%s: detected as a flick", c.name)
			continue
		}
		if c.want == Accepted && len(rej) != 0 || c.want != Accepted && (len(rej) == 0 || rej[0] != c.want) {
			t.Errorf("%s: rejects %v, want %v", c.name, rej, c.want)
		}
	}
}

func TestNoSteadyAimNoFlick(t *testing.T) {
	// Walking: continuous 2 Hz bounce, the phone is never steady, never armed.
	d := NewFlickDetector(DefaultFlickParams())
	for i := 0; i < 600; i++ {
		tt := float64(i) / hz
		a := Vec3{2 * math.Sin(2*math.Pi*2*tt), 0, 3 * math.Sin(2*math.Pi*4*tt)}
		if ev, _ := d.Push(IMUSample{T: tt, UserAccel: a, Attitude: Identity, SpecificForce: 9.81}); ev != nil {
			t.Fatal("walking produced a flick")
		}
	}
}

func TestFreeFallAborts(t *testing.T) {
	d := NewFlickDetector(DefaultFlickParams())
	var got Reject
	for i := 0; i < 100; i++ {
		f := 9.81
		if i > 50 {
			f = 0.3 // dropped phone
		}
		if _, r := d.Push(IMUSample{T: float64(i) / hz, Attitude: Identity, SpecificForce: f}); r != Accepted {
			got = r
		}
	}
	if got != RejectFreeFall {
		t.Fatalf("got %v", got)
	}
}

// observe feeds 10 Hz UWB updates for a peer at world azimuth az. The thrower
// is yawed by thrYaw, so the device-frame direction differs from the world one.
func observe(l *TargetLocker, peer string, az, rng, t0, t1, thrYaw float64) {
	att := AxisAngle(Vec3{0, 0, 1}, thrYaw)
	for t := t0; t <= t1+1e-9; t += 0.1 {
		world := Vec3{math.Cos(az), math.Sin(az), -0.2}.Unit()
		l.Observe(UWBMeasurement{Peer: peer, T: t, Range: rng, Direction: att.Conj().Rotate(world), FoM: 0.9}, att)
	}
}

func flickAt(az, aim, t float64) FlickEvent {
	return FlickEvent{Azimuth: az, AimAzimuth: aim, SigmaAz: deg(6), TPeak: t}
}

func TestTargetLockPicksAlignedPeer(t *testing.T) {
	l := NewTargetLocker(DefaultLockParams())
	l.SetReady("alice", true)
	l.SetReady("bob", true)
	observe(l, "alice", deg(30), 1.5, 0, 1, deg(-40))
	observe(l, "bob", deg(60), 2.0, 0, 1, deg(-40))
	res := l.Resolve(flickAt(deg(33), deg(28), 1.05))
	if res.Peer != "alice" || res.Candidates[0].Posterior < 0.9 {
		t.Fatalf("got %+v", res)
	}
	t.Logf("P(alice)=%.4f P(bob)=%.4f P(null)=%.5f", res.Candidates[0].Posterior, res.Candidates[1].Posterior, res.NullPosterior)
}

func TestTargetLockAmbiguousGoesToPicker(t *testing.T) {
	l := NewTargetLocker(DefaultLockParams())
	l.SetReady("alice", true)
	l.SetReady("bob", true)
	observe(l, "alice", deg(30), 1.5, 0, 1, 0)
	observe(l, "bob", deg(45), 1.5, 0, 1, 0)
	res := l.Resolve(flickAt(deg(38), deg(37), 1.05))
	if res.Peer != "" || !res.Ambiguous || len(res.Candidates) != 2 {
		t.Fatalf("expected picker, got %+v", res)
	}
}

func TestTargetLockNullAndStaleness(t *testing.T) {
	l := NewTargetLocker(DefaultLockParams())
	l.SetReady("alice", true)
	observe(l, "alice", deg(30), 1.5, 0, 1, 0)
	if res := l.Resolve(flickAt(deg(150), deg(150), 1.05)); !res.NoTarget {
		t.Fatalf("throw away from everyone should bounce back: %+v", res)
	}
	if res := l.Resolve(flickAt(deg(30), deg(30), 2.5)); !res.NoTarget || len(res.Candidates) != 0 {
		t.Fatalf("1.5 s old track must not be locked: %+v", res)
	}
	observe(l, "carol", deg(30), 9, 2, 3, 0) // out of throwing range
	if res := l.Resolve(flickAt(deg(30), deg(30), 3.05)); res.Peer == "carol" {
		t.Fatal("locked a peer 9 m away")
	}
}

func TestHighlighterHysteresis(t *testing.T) {
	l := NewTargetLocker(DefaultLockParams())
	l.SetReady("alice", true)
	l.SetReady("bob", true)
	observe(l, "alice", deg(0), 1.5, 0, 2, 0)
	observe(l, "bob", deg(20), 1.5, 0, 2, 0)
	h := &Highlighter{L: l, Hold: 0.15, Margin: 0.15}
	var got string
	for tt := 1.0; tt < 1.3; tt += 0.02 {
		got = h.Update(deg(-2), tt)
	}
	if got != "alice" {
		t.Fatalf("highlight %q", got)
	}
	// A brief swing towards bob (< Hold) must not switch the highlight.
	for tt := 1.3; tt < 1.38; tt += 0.02 {
		got = h.Update(deg(22), tt)
	}
	if got != "alice" {
		t.Fatalf("highlight flickered to %q", got)
	}
	for tt := 1.38; tt < 1.7; tt += 0.02 {
		got = h.Update(deg(22), tt)
	}
	if got != "bob" {
		t.Fatalf("sustained aim did not switch: %q", got)
	}
}

func TestShakeDetectAndGroup(t *testing.T) {
	d := NewShakeDetector("p1", DefaultShakeParams())
	var ev *ShakeEvent
	for i := 0; i < 400 && ev == nil; i++ {
		tt := float64(i) / hz
		ev = d.Push(IMUSample{T: tt, UserAccel: Vec3{15 * math.Sin(2*math.Pi*5*tt), 0, 0}, Attitude: Identity})
	}
	if ev == nil || math.Abs(ev.Freq-5) > 0.6 {
		t.Fatalf("shake: %+v", ev)
	}
	// Two tables shake at the same moment; proximity separates them.
	table := map[string]int{"a1": 1, "a2": 1, "a3": 1, "b1": 2, "b2": 2}
	prox := func(x, y string) float64 {
		if table[x] == table[y] {
			return 0.9
		}
		if (x == "a3" && y == "b1") || (x == "b1" && y == "a3") {
			return 0.7 // adjacent seats across the gap: would chain the tables
		}
		return 0.1
	}
	evs := []ShakeEvent{{Device: "a2", TStart: 10.2}, {Device: "a3", TStart: 10.9}, {Device: "b1", TStart: 10.1},
		{Device: "b2", TStart: 10.3}, {Device: "a2", TStart: 3}}
	group := GroupFrom(ShakeEvent{Device: "a1", TStart: 10}, evs, prox, DefaultGroupParams())
	var names []string
	for _, g := range group {
		names = append(names, g.Device)
	}
	if len(names) != 3 || names[0] != "a1" || !contains(names, "a2") || !contains(names, "a3") {
		t.Fatalf("group %v", names)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestSplitLargestRemainder(t *testing.T) {
	got, _ := SplitLargestRemainder(100_00, []int64{1, 1, 1}, []string{"c", "a", "b"})
	if got[0]+got[1]+got[2] != 100_00 || got[1] != 33_34 {
		t.Fatalf("equal split %v", got) // the leftover cent goes to the smallest key, "a"
	}
	got, _ = SplitLargestRemainder(1_000, []int64{2, 1, 1}, []string{"x", "y", "z"})
	if got[0] != 500 || got[1]+got[2] != 500 {
		t.Fatalf("weighted split %v", got)
	}
	got, _ = SplitLargestRemainder(math.MaxInt64/2, []int64{math.MaxInt32, 1}, []string{"p", "q"})
	if got[0]+got[1] != math.MaxInt64/2 {
		t.Fatal("overflow in split")
	}
}

func TestClockSyncWithinBound(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	theta := func(local float64) float64 { return 0.137 + 30e-6*local } // truth: server - local
	cs := NewClockSync()
	for local := 0.0; local < 600; local += 2 { // heartbeat every 2 s for 10 min
		up := 0.008 + 0.005 + rng.ExpFloat64()*0.015 // uplink 5 ms slower: asymmetry
		down := 0.008 + rng.ExpFloat64()*0.015
		t2 := local + theta(local) + up
		t3 := t2 + 0.0004
		t4 := t3 - theta(local) + down
		cs.Add(ClockSample{T1: local, T2: t2, T3: t3, T4: t4})
	}
	off, bound := cs.Offset(600)
	errMs := math.Abs(off-theta(600)) * 1000
	if errMs > 4 || errMs > bound*1000+0.5 {
		t.Fatalf("offset error %.2f ms (bound %.2f ms)", errMs, bound*1000)
	}
	t.Logf("clock offset error %.2f ms, bound %.2f ms", errMs, bound*1000)
}

func TestTimelineHidesLatency(t *testing.T) {
	tl := DefaultTimeline()
	land := tl.Landing(100, 1.5, 1.5)
	if b := tl.LatencyBudget(100, land); math.Abs(b-0.2533) > 1e-3 {
		t.Fatalf("budget %.4f", b)
	}
	if start, rate := tl.ReceiverPlan(land, 100.1); start != land-tl.Entry || rate != 1 {
		t.Fatalf("on-time plan %.3f %.2f", start, rate)
	}
	if start, rate := tl.ReceiverPlan(land, land-0.1); start != land-0.1 || math.Abs(rate-2) > 1e-9 {
		t.Fatalf("late plan %.3f %.2f", start, rate)
	}
}
