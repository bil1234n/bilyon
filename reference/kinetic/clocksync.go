package kinetic

import "math"

// ClockSample is one NTP-style exchange piggybacked on the WebSocket
// heartbeat: T1 client send and T4 client receive (client monotonic clock),
// T2 server receive and T3 server send (server clock).
type ClockSample struct{ T1, T2, T3, T4 float64 }

// Offset estimates server - client; its error is at most Delay()/2 and
// equals half the path asymmetry.
func (s ClockSample) Offset() float64 { return ((s.T2 - s.T1) + (s.T3 - s.T4)) / 2 }

// Delay is the round-trip time excluding server processing.
func (s ClockSample) Delay() float64 { return (s.T4 - s.T1) - (s.T3 - s.T2) }

func (s ClockSample) mid() float64 { return (s.T1 + s.T4) / 2 }

// ClockSync keeps the minimum-delay sample of each epoch (queuing only ever
// adds delay, so the fastest exchange is the most accurate) and fits
// offset(t) = a + b*t over recent epochs; b absorbs oscillator drift
// (typically 10-50 ppm, i.e. 0.6-3 ms per minute).
type ClockSync struct {
	Epoch    float64 // s
	Keep     int     // epochs in the fit
	best     []ClockSample
	cur      *ClockSample
	curEpoch float64
}

// NewClockSync returns an estimator with 30 s epochs over 5 minutes.
func NewClockSync() *ClockSync { return &ClockSync{Epoch: 30, Keep: 10} }

// Add records one exchange.
func (c *ClockSync) Add(s ClockSample) {
	e := math.Floor(s.T1 / c.Epoch)
	if c.cur != nil && e != c.curEpoch {
		c.best = append(c.best, *c.cur)
		if len(c.best) > c.Keep {
			c.best = c.best[1:]
		}
		c.cur = nil
	}
	if c.cur == nil || s.Delay() < c.cur.Delay() {
		s := s
		c.cur, c.curEpoch = &s, e
	}
}

// Offset returns the estimated server-client offset at local time t and an
// error bound (half the delay of the best recent sample).
func (c *ClockSync) Offset(t float64) (offset, bound float64) {
	pts := append([]ClockSample(nil), c.best...)
	if c.cur != nil {
		pts = append(pts, *c.cur)
	}
	if len(pts) == 0 {
		return 0, math.Inf(1)
	}
	bound = math.Inf(1)
	for _, p := range pts[max(len(pts)-2, 0):] {
		bound = math.Min(bound, p.Delay()/2)
	}
	if len(pts) == 1 {
		return pts[0].Offset(), bound
	}
	// Weighted least squares, weight 1/delay^2: clean samples dominate.
	var sw, st, so float64
	for _, p := range pts {
		w := 1 / math.Pow(p.Delay()+1e-4, 2)
		sw, st, so = sw+w, st+w*p.mid(), so+w*p.Offset()
	}
	tm, om := st/sw, so/sw
	var num, den float64
	for _, p := range pts {
		w := 1 / math.Pow(p.Delay()+1e-4, 2)
		num += w * (p.mid() - tm) * (p.Offset() - om)
		den += w * (p.mid() - tm) * (p.mid() - tm)
	}
	slope := 0.0
	if den > 0 {
		slope = num / den
	}
	return om + slope*(t-tm), bound
}

// ToServer maps a local monotonic time to server time.
func (c *ClockSync) ToServer(t float64) float64 { o, _ := c.Offset(t); return t + o }

// ToLocal maps a server time to the local monotonic clock.
func (c *ClockSync) ToLocal(ts float64) float64 { o, _ := c.Offset(ts); return ts - o }

// Timeline schedules a throw so both screens render the landing at the same
// server time. The coin's flight is a deliberate animation, and the network
// delivery of the THROW event is hidden inside it (RFC 0001 §4.4).
type Timeline struct {
	Exit      float64 // coin leaves the thrower's screen, s
	Entry     float64 // coin enters the receiver's screen, s
	MinFlight float64
	MaxFlight float64
	Gain      float64 // virtual coin speed / measured flick speed
}

// DefaultTimeline returns production animation constants.
func DefaultTimeline() Timeline {
	return Timeline{Exit: 0.12, Entry: 0.20, MinFlight: 0.25, MaxFlight: 0.70, Gain: 3}
}

// Landing returns the server time at which the coin lands, from the flick
// time, the UWB distance and the flick's peak speed (a harder throw flies
// faster).
func (tl Timeline) Landing(tFlick, distance, peakSpeed float64) float64 {
	flight := math.Min(math.Max(distance/(tl.Gain*math.Max(peakSpeed, 0.1)), tl.MinFlight), tl.MaxFlight)
	return tFlick + tl.Exit + flight
}

// LatencyBudget is how long the THROW event may take to reach the receiver
// while still starting the entry animation on time.
func (tl Timeline) LatencyBudget(tFlick, tLand float64) float64 { return tLand - tl.Entry - tFlick }

// ReceiverPlan returns when (local clock) to start the entry animation and
// at what playback rate. A late event compresses the animation up to 3x to
// keep the landing on time; beyond that the coin lands as soon as possible.
func (tl Timeline) ReceiverPlan(tLandLocal, arrivalLocal float64) (start, rate float64) {
	want := tLandLocal - tl.Entry
	if arrivalLocal <= want {
		return want, 1
	}
	if remaining := tLandLocal - arrivalLocal; remaining >= tl.Entry/3 {
		return arrivalLocal, tl.Entry / remaining
	}
	return arrivalLocal, 3
}
