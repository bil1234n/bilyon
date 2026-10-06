package kinetic

import (
	"errors"
	"math"
	"math/big"
	"sort"
)

// ShakeParams tune the on-device shake detector.
type ShakeParams struct {
	Window       float64 // analysis window, s
	MinRMS       float64 // m/s^2
	MinFreq      float64 // Hz
	MaxFreq      float64 // Hz
	MinCrossings int     // zero crossings of the dominant axis (2 per cycle)
	Cooldown     float64 // s between events
}

// DefaultShakeParams: at least three vigorous 2.5-8 Hz cycles within 1 s.
func DefaultShakeParams() ShakeParams {
	return ShakeParams{Window: 1.0, MinRMS: 8, MinFreq: 2.5, MaxFreq: 8, MinCrossings: 6, Cooldown: 2}
}

// ShakeEvent is reported to the server with timestamps already mapped to
// server time through ClockSync.
type ShakeEvent struct {
	Device              string
	TStart, TEnd        float64
	Freq, RMS           float64
	ProximityConfidence float64 // filled by the server, for diagnostics
}

// ShakeDetector finds shakes in a sliding window of world-frame acceleration.
type ShakeDetector struct {
	P         ShakeParams
	Device    string
	buf       []timedVec
	lastEvent float64
}

// NewShakeDetector returns a detector for one device.
func NewShakeDetector(device string, p ShakeParams) *ShakeDetector {
	return &ShakeDetector{P: p, Device: device, lastEvent: math.Inf(-1)}
}

// Push consumes one sample and returns an event when a shake completes.
func (d *ShakeDetector) Push(s IMUSample) *ShakeEvent {
	d.buf = append(d.buf, timedVec{s.T, s.Attitude.Rotate(s.UserAccel)})
	for len(d.buf) > 0 && s.T-d.buf[0].t > d.P.Window {
		d.buf = d.buf[1:]
	}
	span := s.T - d.buf[0].t
	if s.T-d.lastEvent < d.P.Cooldown || span < 0.9*d.P.Window {
		return nil
	}
	var sumSq float64
	var mean Vec3
	for _, tv := range d.buf {
		sumSq += tv.a.Dot(tv.a)
		mean = mean.Add(tv.a)
	}
	n := float64(len(d.buf))
	rms := math.Sqrt(sumSq / n)
	mean = mean.Scale(1 / n)
	// Dominant axis: the world axis with the largest variance.
	var vx, vy, vz float64
	for _, tv := range d.buf {
		c := tv.a.Sub(mean)
		vx, vy, vz = vx+c.X*c.X, vy+c.Y*c.Y, vz+c.Z*c.Z
	}
	axis := func(v Vec3) float64 { return v.X }
	if vy > vx && vy >= vz {
		axis = func(v Vec3) float64 { return v.Y }
	} else if vz > vx && vz > vy {
		axis = func(v Vec3) float64 { return v.Z }
	}
	// Count sign changes with hysteresis so sensor noise is not a "cycle".
	h := 0.3 * rms
	crossings, sign := 0, 0
	for _, tv := range d.buf {
		x := axis(tv.a.Sub(mean))
		switch {
		case x > h && sign <= 0:
			if sign < 0 {
				crossings++
			}
			sign = 1
		case x < -h && sign >= 0:
			if sign > 0 {
				crossings++
			}
			sign = -1
		}
	}
	freq := float64(crossings) / (2 * span)
	if rms < d.P.MinRMS || crossings < d.P.MinCrossings || freq < d.P.MinFreq || freq > d.P.MaxFreq {
		return nil
	}
	ev := &ShakeEvent{Device: d.Device, TStart: d.buf[0].t, TEnd: s.T, Freq: freq, RMS: rms}
	d.lastEvent, d.buf = s.T, nil
	return ev
}

// Proximity returns evidence in [0,1] that two devices are co-located: BLE
// mutual sighting of rotating ephemeral IDs, UWB range, Wi-Fi BSSID overlap.
type Proximity func(a, b string) float64

// GroupParams tune server-side shake grouping.
type GroupParams struct {
	MaxSkew      float64 // max |TStart difference|, s (after clock sync)
	MinProximity float64
	MaxSize      int
}

// DefaultGroupParams returns production defaults.
func DefaultGroupParams() GroupParams {
	return GroupParams{MaxSkew: 1.5, MinProximity: 0.6, MaxSize: 12}
}

// GroupFrom grows a clique around the initiator's shake. Every member must
// be time-compatible and proximate with every other member, not merely
// connected through a chain, which keeps neighbouring tables in a crowded
// room apart. The result is only a proposal: each member confirms the
// group on screen before any share is charged.
func GroupFrom(init ShakeEvent, events []ShakeEvent, prox Proximity, p GroupParams) []ShakeEvent {
	compatible := func(a, b ShakeEvent) bool {
		return math.Abs(a.TStart-b.TStart) <= p.MaxSkew && prox(a.Device, b.Device) >= p.MinProximity
	}
	latest := map[string]ShakeEvent{}
	for _, e := range events {
		if e.Device != init.Device && compatible(init, e) {
			if prev, ok := latest[e.Device]; !ok || e.TStart > prev.TStart {
				latest[e.Device] = e
			}
		}
	}
	cands := make([]ShakeEvent, 0, len(latest))
	for _, e := range latest {
		e.ProximityConfidence = prox(init.Device, e.Device)
		cands = append(cands, e)
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].ProximityConfidence != cands[j].ProximityConfidence {
			return cands[i].ProximityConfidence > cands[j].ProximityConfidence
		}
		return cands[i].Device < cands[j].Device
	})
	group := []ShakeEvent{init}
	for _, c := range cands {
		if len(group) >= p.MaxSize {
			break
		}
		ok := true
		for _, m := range group[1:] {
			if !compatible(m, c) {
				ok = false
				break
			}
		}
		if ok {
			group = append(group, c)
		}
	}
	return group
}

// SplitLargestRemainder divides total minor units in proportion to weights so
// the shares sum exactly to total (Hamilton / largest-remainder method).
// Leftover units go to the largest remainders, ties to the smaller key, so
// every replica computes the identical split. Products use big integers.
func SplitLargestRemainder(total int64, weights []int64, keys []string) ([]int64, error) {
	if len(weights) == 0 || len(weights) != len(keys) || total < 0 {
		return nil, errors.New("invalid split input")
	}
	var w big.Int
	for _, x := range weights {
		if x <= 0 {
			return nil, errors.New("weights must be positive")
		}
		w.Add(&w, big.NewInt(x))
	}
	type part struct {
		i     int
		share int64
		rem   *big.Int
	}
	parts := make([]part, len(weights))
	var assigned int64
	for i, x := range weights {
		q, r := new(big.Int).QuoRem(new(big.Int).Mul(big.NewInt(total), big.NewInt(x)), &w, new(big.Int))
		parts[i] = part{i, q.Int64(), r}
		assigned += q.Int64()
	}
	sort.Slice(parts, func(a, b int) bool {
		if c := parts[a].rem.Cmp(parts[b].rem); c != 0 {
			return c > 0
		}
		return keys[parts[a].i] < keys[parts[b].i]
	})
	for k := int64(0); k < total-assigned; k++ {
		parts[k].share++
	}
	out := make([]int64, len(weights))
	for _, pt := range parts {
		out[pt.i] = pt.share
	}
	return out, nil
}
