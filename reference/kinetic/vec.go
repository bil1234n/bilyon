// Package kinetic is the reference implementation of Algorithm B (RFC 0001
// §3.B): world-frame flick detection, Bayesian UWB target lock, shake
// grouping, exact bill splitting and the clock synchronisation that keeps
// thrower and receiver animations aligned.
//
// Frames: the world frame is gravity-aligned with Z up and an arbitrary but
// fixed yaw (CMAttitudeReferenceFrame.xArbitraryZVertical on iOS,
// TYPE_GAME_ROTATION_VECTOR on Android). Flick velocity and target bearings
// are both measured by the thrower's own sensors in this frame, so the two
// devices never need a shared compass heading.
package kinetic

import "math"

// Vec3 is a 3-vector.
type Vec3 struct{ X, Y, Z float64 }

func (a Vec3) Add(b Vec3) Vec3      { return Vec3{a.X + b.X, a.Y + b.Y, a.Z + b.Z} }
func (a Vec3) Sub(b Vec3) Vec3      { return Vec3{a.X - b.X, a.Y - b.Y, a.Z - b.Z} }
func (a Vec3) Scale(k float64) Vec3 { return Vec3{a.X * k, a.Y * k, a.Z * k} }
func (a Vec3) Dot(b Vec3) float64   { return a.X*b.X + a.Y*b.Y + a.Z*b.Z }
func (a Vec3) Norm() float64        { return math.Sqrt(a.Dot(a)) }
func (a Vec3) Horizontal() Vec3     { return Vec3{a.X, a.Y, 0} }
func (a Vec3) Azimuth() float64     { return math.Atan2(a.Y, a.X) }
func (a Vec3) Cross(b Vec3) Vec3 {
	return Vec3{a.Y*b.Z - a.Z*b.Y, a.Z*b.X - a.X*b.Z, a.X*b.Y - a.Y*b.X}
}
func (a Vec3) Unit() Vec3 {
	n := a.Norm()
	if n == 0 {
		return Vec3{}
	}
	return a.Scale(1 / n)
}

// Quat is a unit quaternion rotating device-frame vectors into the world frame.
type Quat struct{ W, X, Y, Z float64 }

// Identity is the device frame coinciding with the world frame (phone flat,
// screen up, top edge along world +Y).
var Identity = Quat{W: 1}

// AxisAngle builds the rotation of angle radians about axis.
func AxisAngle(axis Vec3, angle float64) Quat {
	u := axis.Unit()
	s := math.Sin(angle / 2)
	return Quat{math.Cos(angle / 2), u.X * s, u.Y * s, u.Z * s}
}

// Mul composes rotations: (q.Mul(r)).Rotate(v) == q.Rotate(r.Rotate(v)).
func (q Quat) Mul(r Quat) Quat {
	return Quat{
		q.W*r.W - q.X*r.X - q.Y*r.Y - q.Z*r.Z,
		q.W*r.X + q.X*r.W + q.Y*r.Z - q.Z*r.Y,
		q.W*r.Y - q.X*r.Z + q.Y*r.W + q.Z*r.X,
		q.W*r.Z + q.X*r.Y - q.Y*r.X + q.Z*r.W,
	}
}

// Conj is the inverse rotation (world -> device for a unit quaternion).
func (q Quat) Conj() Quat { return Quat{q.W, -q.X, -q.Y, -q.Z} }

// Rotate maps a device-frame vector into the world frame.
func (q Quat) Rotate(v Vec3) Vec3 {
	u := Vec3{q.X, q.Y, q.Z}
	t := u.Cross(v).Scale(2)
	return v.Add(t.Scale(q.W)).Add(u.Cross(t))
}

// wrap maps an angle to (-pi, pi].
func wrap(a float64) float64 {
	a = math.Mod(a+math.Pi, 2*math.Pi)
	if a <= 0 {
		a += 2 * math.Pi
	}
	return a - math.Pi
}

func deg(d float64) float64 { return d * math.Pi / 180 }

// logI0 is log of the modified Bessel function of the first kind, order 0
// (Abramowitz & Stegun 9.8.1 / 9.8.2), used to normalise von Mises densities.
func logI0(k float64) float64 {
	k = math.Abs(k)
	if k < 3.75 {
		t := (k / 3.75) * (k / 3.75)
		return math.Log(1 + t*(3.5156229+t*(3.0899424+t*(1.2067492+t*(0.2659732+t*(0.0360768+t*0.0045813))))))
	}
	t := 3.75 / k
	p := 0.39894228 + t*(0.01328592+t*(0.00225319+t*(-0.00157565+t*(0.00916281+
		t*(-0.02057706+t*(0.02635537+t*(-0.01647633+t*0.00392377)))))))
	return k - 0.5*math.Log(k) + math.Log(p)
}

// logVonMises is the log density of a von Mises distribution with mean mu and
// concentration kappa, evaluated at x.
func logVonMises(x, mu, kappa float64) float64 {
	return kappa*math.Cos(x-mu) - math.Log(2*math.Pi) - logI0(kappa)
}
