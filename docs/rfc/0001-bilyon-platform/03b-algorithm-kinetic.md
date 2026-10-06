# §3.B Algorithm B: UWB + IMU Spatial Target Lock, "Flick to Throw", Shake, Grab

[← RFC index](README.md) · Code: [`reference/kinetic`](../../../reference/kinetic)

## 3.B.0 Safety principle

A gesture **selects** a counterparty and **initiates** an intent. It never authorises one. Money moves
only after a hardware-gated signature (`K_gest` within the gesture limit, `K_dev` above it, §2.2.5) and,
for transfers, the receiver's catch. An ambiguous lock opens a one-tap picker, and a throw at nobody
bounces back. A spoofed or accidental gesture can therefore cost at most a dismissed sheet.

## 3.B.1 Sensors, frames and timing

| Input | iOS | Android | Rate |
|---|---|---|---|
| Attitude `q(t)` (device→world) | `CMDeviceMotion.attitude`, frame `.xArbitraryZVertical` | `TYPE_GAME_ROTATION_VECTOR` (no magnetometer) | 100–200 Hz |
| Linear acceleration `u(t)` | `userAcceleration` × 9.80665 | `TYPE_LINEAR_ACCELERATION` | 100–200 Hz (Android caps at 200 Hz without `HIGH_SAMPLING_RATE_SENSORS`) |
| Specific force ‖f‖ (free-fall guard) | raw accelerometer | `TYPE_ACCELEROMETER` | same |
| UWB range + direction | `NINearbyObject.distance`, `.direction` (unit vector, device frame, `nil` outside the field of view) | Jetpack `RangingResultPosition.distance/azimuth/elevation`, converted to a device-frame unit vector | ~5–30 Hz, device-dependent |

The **world frame** `W` is gravity-aligned (Z up) with an arbitrary yaw that stays fixed for the session.
Design decision D5 rests on one observation: *the flick velocity and the target bearings are both measured
by the thrower's own sensors*, so they can be compared directly in the thrower's `W`. The two phones
never need a common compass heading, and magnetometer disturbance indoors does not matter. Every sample
carries a monotonic timestamp. Attitudes sit in a 2 s ring buffer and are slerp-interpolated to each UWB
timestamp, which keeps the thrower's own rotation out of the bearings.

## 3.B.2 Flick detection

**Model.** World-frame linear acceleration with on-line bias removal, integrated from a zero-velocity
start (the hand holds the phone steady while aiming):

```text
a(t)   = R(q(t)) · u(t) − b̂            b̂ = mean of R(q)·u over the steady-aim window
                                        (absorbs accelerometer bias and gravity leakage g·sin δ ≈ 0.34 m/s² at δ = 2°)
v(t)   = Σ ½ (a_k + a_{k−1}) Δt_k       trapezoidal, from the last steady sample t_s
v_h    = (v_x, v_y, 0)
t*     = argmax_t |v_h(t)|              peak of the push
φ_f    = atan2(v_y(t*), v_x(t*))        throw azimuth in W
R̄      = |Σ_{t_s..t*} a_h| / Σ_{t_s..t*} |a_h|      mean resultant length of the push direction
σ_f    = sqrt(−2 ln R̄)                  per-throw circular std, estimated from the data itself
t_end  = first t > t* with |v_h(t)| < 0.3 |v_h(t*)|  return to rest: the phone stays in the hand
```

Drift bound: a residual bias of 0.05 m/s² over the 0.45 s maximum window adds at most 0.023 m/s, or
2.5 % of the speed threshold. That is why no ZUPT smoother is needed.

| Gate | Default | Rejects |
|---|---|---|
| Steady aim: \|a\| < 1.0 m/s², \|ω\| < 0.6 rad/s for ≥ 120 ms | arms the detector | Gestures without aiming; walking (never armed) |
| Onset: \|a_h − b̂_h\| > 6 m/s² within 60 ms of the last steady sample | implicit jerk ≳ 80 m/s³ | Slow pushes, slow ramps (never candidates) |
| Duration onset → rest | 80–450 ms | Arm sweeps (`DURATION`) |
| Peak horizontal speed | ≥ 0.9 m/s (personalised to the 20th percentile of the user's practice throws) | Short jabs (`SLOW`) |
| Peak horizontal acceleration | ≥ 12 m/s² | Weak shoves (`WEAK`) |
| Horizontal ratio \|v_h\|/\|v\| at peak | ≥ 0.7 | Upward tosses (`VERTICAL`) |
| Directional consistency R̄ | ≥ 0.8 | Hooks and circular motions (`CURVED`) |
| Free fall: \|f\| < 2 m/s² for ≥ 80 ms | abort, any state | A dropped or actually thrown phone (`FREE_FALL`) |

```text
FlickDetector.Push(s):                                   # streaming, O(1) per sample
  if |s.f| < 2 for ≥ 80 ms: Reset(); return FREE_FALL
  a ← R(s.q)·s.u
  IDLE/ARMED:
    if |a| < 1.0 ∧ |s.ω| < 0.6: accumulate b̂; if steady ≥ 120 ms: state ← ARMED; buffer (t, a)
    elif ARMED ∧ |a − b̂|_h > 6: buffer; Begin()        # integrate from the last steady buffered sample
    elif ARMED ∧ t − t_last_steady ≤ 60 ms: buffer      # ramp below the onset threshold
    else: Reset()
  ACTIVE:
    v += ½(a − b̂ + a_prev)·Δt
    if |v_h| > peak: peak ← |v_h|, v* ← v, t* ← t, accumulate a_h into R̄
    elif |v_h| < 0.3·peak: return Finish(t)              # evaluate the gates above, in order
    if t − t_onset > 450 ms: Reset(); return DURATION
```

**Latency.** A provisional decision at `t* + 30 ms` may start the exit animation speculatively. The flick
is **confirmed at return to rest**, about 90–100 ms after the peak for a 300 ms gesture, and the THROW
event is sent then. A speculative start that fails confirmation is cancelled with a short "wobble" animation.
The Phase 2 beta measures how often that happens (exit criterion in §5).

**Measured (reference, synthetic 1.5 m/s flick at 200 Hz, noise σ = 0.15 m/s² per axis, constant bias):**
azimuth error −0.15°, peak speed 1.500 m/s, σ_f = 1.8°, duration 245 ms, confirmed 95 ms after the peak.
A 25° wrist rotation during the flick moves the world-frame azimuth by less than 3°. Computing the
same thing in the device frame fails the test (mutation-checked). Every rejection class in the table above has a
test.

## 3.B.3 Spatial target lock (Bayesian)

**Per-peer bearing filter.** Each UWB direction `d_k` (device frame) becomes a world bearing
`z_k = azimuth(R(q(t_k))·d_k)` with measurement variance

```text
σ_z² = ( σ0 / (max(cos θ_off, 0.25) · max(FoM, 0.2)) )² + σ_att²,   σ0 = 4°, σ_att = 2°
θ_off = angle between d_k and the antenna boresight (rear axis): phase-difference AoA error ∝ 1/cos θ
```

A 1-D Kalman filter on the circle tracks `ψ_i`:
`P += q·Δt` (q = (20°)²/s, people move); `K = P/(P+σ_z²)`; `ψ ← wrap(ψ + K·wrap(z − ψ))`;
`P ← (1−K)·P`. Range uses an EMA (α = 0.3). Measurements with `|horizontal(b)| < 0.2`, i.e. a peer
almost directly above or below, are ignored, because the azimuth is undefined there.

**Hypotheses.** `H_0`: the throw is aimed at nobody. `H_i`: it is aimed at peer `i`. At flick time `t*`,
each live track has bearing variance `V_i = P_i + q·(t* − t_i)`. A track is excluded if
`t* − t_i > 1 s` or `r_i ∉ [0.15, 6] m`.

```text
L_i  = vM(φ_f ; ψ_i, κ_f,i) · vM(φ_aim ; ψ_i, κ_a,i)^w      vM(x; μ, κ) = e^{κ cos(x−μ)} / (2π I0(κ))
κ_f,i = 1 / (max(σ_f, 8°)² + V_i)      κ_a,i = 1 / (σ_aim² + V_i)      σ_aim = 10°,  w = 0.5
L_0  = (2π)^−(1+w)                                                    uniform over directions
π_i  = exp(−(r_i − 1.2)² / (2·1.5²)) · (ready_i ? 1 : 0.25)          π_0 = 0.15
P_i  = π_i L_i / (π_0 L_0 + Σ_j π_j L_j)                              in log space; log I0 per A&S 9.8.1/9.8.2
```

The 8° floor on `σ_f` models human intent error. A clean push does not mean a precise aim.
`φ_aim` is the pointing azimuth when the gesture began: the top edge when the phone is held flat-ish,
the rear-camera axis when its pitch exceeds 50°.

**Decision.**

```text
if no candidates ∨ P_0 ≥ max_i P_i:                        NO_TARGET  → coin bounces back
i* ← argmax P_i;  runner_up ← max(P_0, second-best P_i)
if P_i* ≥ 0.90 ∧ P_i* ≥ 4·runner_up ∧ |wrap(φ_f − ψ_i*)| ≤ 25°:  LOCK(i*)
else:                                                      AMBIGUOUS → picker with the top 3 candidates
```

**Worked example (`TestTargetLockPicksAlignedPeer`).** Alice is at 30° and 1.5 m, Bob at 60° and 2.0 m,
and both are in catch mode. The thrower is yawed −40° (device-frame directions differ from world bearings).
The flick goes at 33° with the aim at 28°: **P(Alice) = 0.958, P(Bob) = 0.037, P₀ = 0.005 → lock Alice.**
With Bob moved to 45° and a flick at 38°, no hypothesis clears the odds test, so the picker opens. A throw
at 150° gives `NO_TARGET`. A track last updated 1.5 s ago is excluded. A peer 9 m away is never locked.

**Pre-flick highlight (hysteresis).** While the user aims, the same posterior is computed from `φ_aim`
alone. The highlighted avatar switches only when a challenger leads the current target by ≥ 0.15
posterior for ≥ 150 ms. A haptic tick marks each switch. This stops flicker between neighbours
(`TestHighlighterHysteresis`).

## 3.B.4 Shake to split

**On device.** In a 1.0 s window of world-frame acceleration, the detector requires RMS ≥ 8 m/s². It
picks the dominant axis (largest variance) and counts zero crossings around its mean with ±0.3·RMS
hysteresis, so sensor noise is not counted as cycles. The frequency is `f = crossings / (2·span)`, which
must lie in 2.5–8 Hz with at least 6 crossings (three full shakes). There is a 2 s cooldown. A detection
emits `SHAKE{t_start, t_end}` in **server time** (§4.4 clock sync) together with the proximity evidence the
phone has: BLE ephemeral IDs seen in the last 10 s with RSSI, UWB ranges, and hashed Wi-Fi BSSIDs.

**On the server.** Grouping runs around the initiator, the phone holding the bill (an amount typed in or a merchant QR scanned).

```text
prox(a, b)  = 1 − Π_k (1 − p_k)    evidence p_k: mutual BLE sighting, RSSI > −75 dBm → 0.9;
                                    UWB range < 3 m → 0.95; BSSID Jaccard ≥ 0.5 ∧ same /24 → 0.6;
                                    same geohash-7 only → 0.3
compatible(a, b) ⇔ |t_a − t_b| ≤ 1.5 s ∧ prox(a, b) ≥ 0.6

GroupFrom(init, events):
  C ← latest event per device with compatible(init, e), sorted by prox(init, e) desc
  G ← [init]
  for c in C while |G| < 12: if ∀ m ∈ G \ {init}: compatible(m, c): G ← G ∪ {c}
  return G                                  # a clique, never a chain
```

Insisting on a clique rather than connected components stops two adjacent restaurant tables shaking at the
same moment from merging through the two people sitting back to back (`TestShakeDetectAndGroup`). The
group is only a **proposal**. Every member sees the avatars and their share and confirms with a
biometric. Anyone who has not confirmed after 30 s is dropped and the shares are recomputed.

**Exact split.** The largest-remainder (Hamilton) method splits `T` minor units with weights `w_i`:

```text
q_i = ⌊T·w_i / W⌋,   r_i = T·w_i mod W,   W = Σ w_i         (128-bit or big-integer products)
give one extra unit to each of the (T − Σ q_i) members with the largest r_i; ties → smallest member key
```

`Σ shares = T` exactly, and every replica computes the same result: 100.00 / 3 → 33.34, 33.33, 33.33.
Each confirmed share becomes an independent intent from the member to the bill payer, or straight to
the merchant for a merchant QR. Atomicity across members is not needed, and the group screen shows
progress.

## 3.B.5 Proximity grab / drop

- **Drop.** The payer creates a *drop*: a hold plus an intent with no payee yet. It is advertised through
  the payer's BLE ephemeral ID and is grabbable only within 0.5 m (UWB) for 60 s.
- **Grab.** The receiver brings their phone within **0.10 m**, measured as filtered UWB range held for
  ≥ 300 ms, or within the NFC field (Android HCE ↔ reader; an iPhone can read an Android HCE AID). The
  receiver then makes a *pull-back* motion: the range rate `ṙ` (finite differences of the filtered range)
  goes from approach (≤ −0.3 m/s) to retreat (≥ +0.4 m/s) within 600 ms. That sends `CATCH`. Receiving
  never needs a biometric. The app must be unlocked and in the foreground.
- **Haptics.** Lock-on is a sharp transient, the flight a rising continuous texture, the catch a thud.
  iOS uses Core Haptics AHAP patterns. Android uses `VibrationEffect.Composition` with `PRIMITIVE_CLICK`,
  `PRIMITIVE_QUICK_RISE` and `PRIMITIVE_THUD`, falling back to predefined effects where composition
  primitives are unsupported.

## 3.B.6 Platform realities and fallbacks

| Constraint | Design response |
|---|---|
| UWB exists only on recent devices (iPhone 11+, selected Android flagships) | Capability flags in presence. Without UWB, the throw targets a **picker** sorted by BLE proximity. The flick still triggers the send, but the direction is not used |
| iPhone ↔ Android UWB needs FiRa interoperability through the Nearby Interaction accessory protocol | Experimental, behind a feature flag (Phase 4). Same-ecosystem ranging is the production path |
| UWB sessions need out-of-band parameter exchange | NI discovery tokens or FiRa session parameters are exchanged over the realtime channel, or BLE when offline. This happens only between peers in a mutual proximity session (§4.4) |
| Ranging reveals a person's precise relative location | Catch mode is opt-in, auto-expires after 2 min, and uses rotating BLE IDs. Strangers cannot range you unless you are in catch mode |
| Accessibility and reduced motion | Every gesture has a button equivalent (VoiceOver/TalkBack labels). The reduced-motion setting replaces flight animations with fades |

## 3.B.7 Sensor-level edge cases

| Case | Behaviour |
|---|---|
| UWB dropout during the flick (body blocking, NLOS) | The last bearing is used with variance inflated by its age. Older than 1 s → excluded → picker |
| Two peers on the same bearing | The range prior mildly favours the nearer one. If the odds test fails, the picker opens |
| Peer walking | Process noise keeps the filter responsive. Bearings refresh at UWB rate |
| Thrower turns while aiming | The world frame compensates. Tested with a 25° yaw during the flick |
| Phone upright vs flat | The aim axis switches between the rear camera and the top edge at 50° pitch |
| Different throwing styles, handedness | Direction comes from velocity, not device orientation. `MinPeakVel` is personalised |
| Pocket or bag motion | Requires the app in the foreground, throw mode armed by a biometric, and a steady aim. Screen-off input is ignored |
| Injected sensor data on a rooted device | Can only choose a target. The signature and the catch are still required |
| Several throws arrive at one receiver | Independent intents. The receiver UI queues the catches |
