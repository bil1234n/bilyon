package kinetic

import "math"

// IMUSample is one fused motion sample (100-200 Hz).
type IMUSample struct {
	T             float64 // seconds, monotonic clock
	UserAccel     Vec3    // device frame, gravity removed, m/s^2
	Gyro          Vec3    // device frame, rad/s
	Attitude      Quat    // device -> world
	SpecificForce float64 // |raw accelerometer|, m/s^2: ~9.81 at rest, ~0 in free fall
}

// FlickParams are the detector thresholds (RFC 0001 §3.B.2). Defaults are
// population values; onboarding "practice throws" personalise MinPeakVel to
// the 20th percentile of the user's own flicks.
type FlickParams struct {
	QuietAccel, QuietGyro, QuietDur float64 // steady-aim gate: m/s^2, rad/s, s
	OnsetAccel                      float64 // horizontal accel that opens a gesture, m/s^2
	MinPeakVel                      float64 // horizontal peak speed, m/s
	MinPeakAccel                    float64 // m/s^2
	MinDur, MaxDur                  float64 // onset -> back to rest, s
	MinHorizRatio                   float64 // |v_h| / |v| at the peak
	MinResultant                    float64 // directional consistency of the push, 0..1
	RestFrac                        float64 // gesture ends when |v_h| < RestFrac * peak
	FreeFallForce, FreeFallDur      float64 // m/s^2, s
}

// DefaultFlickParams returns the population defaults.
func DefaultFlickParams() FlickParams {
	return FlickParams{QuietAccel: 1.0, QuietGyro: 0.6, QuietDur: 0.12, OnsetAccel: 6, MinPeakVel: 0.9,
		MinPeakAccel: 12, MinDur: 0.08, MaxDur: 0.45, MinHorizRatio: 0.7, MinResultant: 0.8,
		RestFrac: 0.3, FreeFallForce: 2, FreeFallDur: 0.08}
}

// Reject explains why a candidate gesture was not a flick.
type Reject int

// Rejection reasons.
const (
	Accepted Reject = iota
	RejectDuration
	RejectSlow
	RejectWeak
	RejectVertical
	RejectCurved
	RejectFreeFall
)

// FlickEvent is a detected flick in the world frame.
type FlickEvent struct {
	TOnset, TPeak, TEnd float64
	PeakVelocity        Vec3    // world-frame velocity at the horizontal speed peak
	Azimuth             float64 // azimuth of the horizontal peak velocity, rad
	SigmaAz             float64 // per-throw direction uncertainty, rad
	PeakAccel           float64 // m/s^2
	AimAzimuth          float64 // pointing azimuth when the gesture began, rad
}

type phase int

const (
	idle phase = iota
	armed
	active
)

const (
	rampGrace  = 0.06 // s between the last steady sample and onset
	preSamples = 32   // armed-phase history kept for backfill (160 ms at 200 Hz)
)

type timedVec struct {
	t float64
	a Vec3
}

// FlickDetector is a streaming state machine: IDLE -> ARMED (phone held
// steady) -> ACTIVE (integrating) -> event or rejection -> IDLE.
type FlickDetector struct {
	P FlickParams

	ph         phase
	quietSince float64
	biasSum    Vec3
	biasN      int
	bias       Vec3       // mean residual accel while steady (attitude/bias leakage)
	pre        []timedVec // recent armed-phase samples, to backfill the ramp before onset
	lastQuiet  float64
	ffSince    float64

	onset, prevT, tPeak float64
	prevA, vel, peakVel Vec3
	peakSpeed, peakAcc  float64
	sumAH               Vec3
	sumAHNorm, aim      float64
}

// NewFlickDetector returns a detector with the given parameters.
func NewFlickDetector(p FlickParams) *FlickDetector { return &FlickDetector{P: p, ffSince: -1} }

func (d *FlickDetector) reset() {
	*d = FlickDetector{P: d.P, ffSince: -1}
}

// aimAzimuth is the pointing direction: the top edge when the phone is held
// flat-ish, the rear camera axis when it is held upright.
func aimAzimuth(att Quat) float64 {
	top := att.Rotate(Vec3{0, 1, 0})
	if math.Abs(top.Z) > math.Sin(deg(50)) {
		return att.Rotate(Vec3{0, 0, -1}).Azimuth()
	}
	return top.Azimuth()
}

// Push consumes one sample. It returns a non-nil event when a flick
// completes, or a non-zero Reject when a candidate gesture is discarded.
func (d *FlickDetector) Push(s IMUSample) (*FlickEvent, Reject) {
	p := d.P
	if s.SpecificForce < p.FreeFallForce { // the phone itself is falling or thrown
		if d.ffSince < 0 {
			d.ffSince = s.T
		}
		if s.T-d.ffSince >= p.FreeFallDur {
			d.reset()
			return nil, RejectFreeFall
		}
	} else {
		d.ffSince = -1
	}
	aW := s.Attitude.Rotate(s.UserAccel)
	switch d.ph {
	case idle, armed:
		if aW.Norm() < p.QuietAccel && s.Gyro.Norm() < p.QuietGyro {
			if d.biasN == 0 {
				d.quietSince = s.T
			}
			d.biasSum, d.biasN, d.lastQuiet = d.biasSum.Add(aW), d.biasN+1, s.T
			if s.T-d.quietSince >= p.QuietDur {
				d.ph, d.bias = armed, d.biasSum.Scale(1/float64(d.biasN))
			}
			if d.ph == armed {
				d.buffer(s.T, aW)
			}
			return nil, Accepted
		}
		if d.ph == armed {
			if aW.Sub(d.bias).Horizontal().Norm() > p.OnsetAccel {
				d.buffer(s.T, aW)
				d.begin(s.Attitude)
				return nil, Accepted
			}
			if s.T-d.lastQuiet <= rampGrace { // ramp-up below the onset threshold
				d.buffer(s.T, aW)
				return nil, Accepted
			}
		}
		d.reset() // movement without a steady aim first: not a flick
		return nil, Accepted
	default:
		return d.integrate(s.T, aW.Sub(d.bias))
	}
}

func (d *FlickDetector) buffer(t float64, a Vec3) {
	d.pre = append(d.pre, timedVec{t, a})
	if len(d.pre) > preSamples {
		d.pre = d.pre[1:]
	}
}

func (d *FlickDetector) begin(att Quat) {
	d.ph, d.aim = active, aimAzimuth(att)
	// Integrate from the last steady sample so the ramp below OnsetAccel is
	// counted too (skipping it under-estimates peak speed by ~10%).
	start := len(d.pre) - 1
	for start > 0 && d.pre[start].a.Sub(d.bias).Norm() >= d.P.QuietAccel {
		start--
	}
	d.onset, d.prevT, d.prevA = d.pre[start].t, d.pre[start].t, d.pre[start].a.Sub(d.bias)
	for _, tv := range d.pre[start+1:] {
		d.integrate(tv.t, tv.a.Sub(d.bias))
	}
}

func (d *FlickDetector) integrate(t float64, a Vec3) (*FlickEvent, Reject) {
	d.vel = d.vel.Add(a.Add(d.prevA).Scale((t - d.prevT) / 2)) // trapezoidal
	d.prevT, d.prevA = t, a
	ah := a.Horizontal()
	d.peakAcc = math.Max(d.peakAcc, ah.Norm())
	speed := d.vel.Horizontal().Norm()
	switch {
	case speed > d.peakSpeed: // accelerating phase: accumulate direction statistics
		d.peakSpeed, d.peakVel, d.tPeak = speed, d.vel, t
		d.sumAH, d.sumAHNorm = d.sumAH.Add(ah), d.sumAHNorm+ah.Norm()
	case speed < d.P.RestFrac*d.peakSpeed:
		return d.finish(t)
	}
	if t-d.onset > d.P.MaxDur {
		d.reset()
		return nil, RejectDuration // never came back to rest: walking, swinging
	}
	return nil, Accepted
}

func (d *FlickDetector) finish(tEnd float64) (*FlickEvent, Reject) {
	p := d.P
	dur := tEnd - d.onset
	resultant := 0.0
	if d.sumAHNorm > 0 {
		resultant = d.sumAH.Norm() / d.sumAHNorm
	}
	ev := &FlickEvent{TOnset: d.onset, TPeak: d.tPeak, TEnd: tEnd, PeakVelocity: d.peakVel,
		Azimuth: d.peakVel.Azimuth(), PeakAccel: d.peakAcc, AimAzimuth: d.aim,
		SigmaAz: math.Sqrt(-2 * math.Log(math.Max(resultant, 1e-9)))}
	reason := Accepted
	switch {
	case dur < p.MinDur || dur > p.MaxDur:
		reason = RejectDuration
	case d.peakSpeed < p.MinPeakVel:
		reason = RejectSlow
	case d.peakAcc < p.MinPeakAccel:
		reason = RejectWeak
	case d.peakSpeed < p.MinHorizRatio*d.peakVel.Norm():
		reason = RejectVertical
	case resultant < p.MinResultant:
		reason = RejectCurved
	}
	d.reset()
	if reason != Accepted {
		return nil, reason
	}
	return ev, Accepted
}
