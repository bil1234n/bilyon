package kinetic

import (
	"math"
	"sort"
)

// UWBMeasurement is one ranging result for a peer (NINearbyObject on iOS,
// androidx.core.uwb RangingResultPosition on Android).
type UWBMeasurement struct {
	Peer      string
	T         float64 // monotonic seconds, same clock as the IMU
	Range     float64 // metres
	Direction Vec3    // unit vector in the device frame; zero outside the AoA field of view
	FoM       float64 // figure of merit, 0..1
}

// LockParams tune the Bayesian target lock (RFC 0001 §3.B.3).
type LockParams struct {
	SigmaAoA0     float64 // AoA std at boresight with FoM=1, rad
	SigmaAttitude float64 // attitude error folded into each bearing, rad
	ProcessNoise  float64 // random-walk variance of a peer's bearing, rad^2/s
	MaxStaleness  float64 // drop a track older than this at flick time, s
	SigmaFlickMin float64 // floor on throw-direction error (human intent), rad
	SigmaAim      float64 // pointing error before the flick, rad
	AimWeight     float64 // tempering exponent of the aim likelihood, 0..1
	RangeMu       float64 // preferred throwing distance, m
	RangeSigma    float64
	RangeMin      float64
	RangeMax      float64
	NotReadyPrior float64 // prior multiplier for peers not in "catch" mode
	NullPrior     float64 // prior weight of "aimed at nobody"
	MinPosterior  float64
	MinOdds       float64 // best / runner-up (including the null hypothesis)
	Gate          float64 // max |flick - bearing| for an automatic lock, rad
}

// DefaultLockParams returns production defaults.
func DefaultLockParams() LockParams {
	return LockParams{SigmaAoA0: deg(4), SigmaAttitude: deg(2), ProcessNoise: deg(20) * deg(20),
		MaxStaleness: 1.0, SigmaFlickMin: deg(8), SigmaAim: deg(10), AimWeight: 0.5, RangeMu: 1.2,
		RangeSigma: 1.5, RangeMin: 0.15, RangeMax: 6, NotReadyPrior: 0.25, NullPrior: 0.15,
		MinPosterior: 0.9, MinOdds: 4, Gate: deg(25)}
}

type track struct {
	az, varAz float64 // world-frame bearing estimate and its variance
	rng, t    float64
}

// TargetLocker keeps one bearing filter per peer and resolves flicks.
type TargetLocker struct {
	P      LockParams
	tracks map[string]*track
	ready  map[string]bool
}

// NewTargetLocker returns an empty locker.
func NewTargetLocker(p LockParams) *TargetLocker {
	return &TargetLocker{P: p, tracks: map[string]*track{}, ready: map[string]bool{}}
}

// SetReady records whether a peer is advertising "ready to catch".
func (l *TargetLocker) SetReady(peer string, ready bool) { l.ready[peer] = ready }

// Observe fuses one measurement. att is the thrower's attitude interpolated
// (slerp) to m.T, so the thrower's own rotation never moves a bearing.
func (l *TargetLocker) Observe(m UWBMeasurement, att Quat) {
	tr := l.tracks[m.Peer]
	if m.Direction.Norm() == 0 { // out of AoA field of view: range only
		if tr != nil {
			tr.rng = 0.7*tr.rng + 0.3*m.Range
		}
		return
	}
	d := m.Direction.Unit()
	b := att.Rotate(d)
	if b.Horizontal().Norm() < 0.2 { // peer almost straight above/below: azimuth undefined
		return
	}
	// Phase-difference AoA error grows as 1/cos(off-boresight angle); the
	// antenna boresight is the rear (-Z) axis.
	cosOff := math.Max(d.Dot(Vec3{0, 0, -1}), 0.25)
	sigma := l.P.SigmaAoA0 / cosOff / math.Max(m.FoM, 0.2)
	r := sigma*sigma + l.P.SigmaAttitude*l.P.SigmaAttitude
	z := b.Azimuth()
	if tr == nil {
		l.tracks[m.Peer] = &track{az: z, varAz: r, rng: m.Range, t: m.T}
		return
	}
	tr.varAz += l.P.ProcessNoise * math.Max(m.T-tr.t, 0) // predict
	k := tr.varAz / (tr.varAz + r)                       // 1-D Kalman update on the circle
	tr.az = wrap(tr.az + k*wrap(z-tr.az))
	tr.varAz *= 1 - k
	tr.rng = 0.7*tr.rng + 0.3*m.Range
	tr.t = m.T
}

// Candidate is one hypothesis in a lock decision.
type Candidate struct {
	Peer      string
	Posterior float64
	AngleErr  float64 // flick azimuth minus bearing, rad
	Range     float64
}

// LockResult is the outcome of Resolve.
type LockResult struct {
	Peer          string // locked target; empty unless the lock is unambiguous
	Ambiguous     bool   // show a picker with the top Candidates
	NoTarget      bool   // the null hypothesis won: the coin bounces back
	Candidates    []Candidate
	NullPosterior float64
}

// posteriors scores every live track against a throw azimuth (weight 1)
// and an aim azimuth (weight AimWeight), including the null hypothesis.
func (l *TargetLocker) posteriors(throwAz, sigmaThrow, aimAz, aimWeight, t float64) ([]Candidate, float64) {
	p := l.P
	logNull := math.Log(p.NullPrior) - (1+aimWeight)*math.Log(2*math.Pi)
	type scored struct {
		c    Candidate
		logp float64
	}
	var all []scored
	for peer, tr := range l.tracks {
		age := t - tr.t
		if age > p.MaxStaleness || tr.rng < p.RangeMin || tr.rng > p.RangeMax {
			continue
		}
		v := tr.varAz + p.ProcessNoise*math.Max(age, 0) // bearing variance at flick time
		prior := math.Exp(-(tr.rng - p.RangeMu) * (tr.rng - p.RangeMu) / (2 * p.RangeSigma * p.RangeSigma))
		if !l.ready[peer] {
			prior *= p.NotReadyPrior
		}
		logp := math.Log(prior) + logVonMises(throwAz, tr.az, 1/(sigmaThrow*sigmaThrow+v)) +
			aimWeight*logVonMises(aimAz, tr.az, 1/(p.SigmaAim*p.SigmaAim+v))
		all = append(all, scored{Candidate{Peer: peer, AngleErr: wrap(throwAz - tr.az), Range: tr.rng}, logp})
	}
	maxLog := logNull
	for _, s := range all {
		maxLog = math.Max(maxLog, s.logp)
	}
	z := math.Exp(logNull - maxLog)
	for _, s := range all {
		z += math.Exp(s.logp - maxLog)
	}
	out := make([]Candidate, len(all))
	for i, s := range all {
		out[i] = s.c
		out[i].Posterior = math.Exp(s.logp-maxLog) / z
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Posterior > out[j].Posterior })
	return out, math.Exp(logNull-maxLog) / z
}

// Resolve decides the target of a flick: lock only when the posterior,
// the odds over the runner-up and the angular gate all agree; otherwise
// fall back to a picker. Money never moves on an ambiguous lock.
func (l *TargetLocker) Resolve(ev FlickEvent) LockResult {
	p := l.P
	sigma := math.Max(ev.SigmaAz, p.SigmaFlickMin)
	cands, null := l.posteriors(ev.Azimuth, sigma, ev.AimAzimuth, p.AimWeight, ev.TPeak)
	res := LockResult{Candidates: cands, NullPosterior: null}
	if len(cands) == 0 || null >= cands[0].Posterior {
		res.NoTarget = true
		return res
	}
	runnerUp := null
	if len(cands) > 1 {
		runnerUp = math.Max(runnerUp, cands[1].Posterior)
	}
	best := cands[0]
	if best.Posterior >= p.MinPosterior && best.Posterior >= p.MinOdds*runnerUp && math.Abs(best.AngleErr) <= p.Gate {
		res.Peer = best.Peer
	} else {
		res.Ambiguous = true
	}
	return res
}

// Highlighter drives the pre-flick "target lock" UI from the aim direction
// alone, with hysteresis so the highlighted avatar does not flicker between
// neighbours: a challenger must lead by Margin for Hold seconds.
type Highlighter struct {
	L          *TargetLocker
	Hold       float64
	Margin     float64
	Current    string
	challenger string
	since      float64
}

// Update returns the peer to highlight (and trigger a haptic tick on change).
func (h *Highlighter) Update(aimAz, t float64) string {
	cands, _ := h.L.posteriors(aimAz, h.L.P.SigmaAim, 0, 0, t)
	post := map[string]float64{}
	for _, c := range cands {
		post[c.Peer] = c.Posterior
	}
	if len(cands) == 0 {
		h.Current, h.challenger = "", ""
		return ""
	}
	best := cands[0].Peer
	switch {
	case best == h.Current:
		h.challenger = ""
	case best != h.challenger:
		h.challenger, h.since = best, t
	case t-h.since >= h.Hold && post[best] >= post[h.Current]+h.Margin:
		h.Current, h.challenger = best, ""
	}
	return h.Current
}
