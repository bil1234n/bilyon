# §4.4 Realtime Sync Engine: Synchronising Thrower and Receiver Animations Below 50 ms

[← RFC index](README.md) · Code: [`reference/kinetic/clocksync.go`](../../../reference/kinetic/clocksync.go)

## 4.4.1 Reframing the requirement

Phone-to-edge round trips are 30–60 ms on LTE, 10–20 ms on 5G SA and 5–20 ms on good Wi-Fi. A
thrower → edge → receiver relay is therefore ~25–40 ms at p50 and well over 100 ms at p99 on cellular. **No
design can guarantee < 50 ms delivery** of every event over public mobile networks.

What people actually perceive is whether the coin leaves one screen and lands on the other *at the same
moment*. The engine therefore guarantees:

> **The landing is rendered on both devices within 50 ms of each other (p95; design target ≤ 20 ms),
> independent of network latency, as long as delivery beats the flight budget (≥ 170 ms by construction).**

Three mechanisms provide this:

1. **A shared clock.** NTP-style exchanges over the WebSocket, minimum-delay filtering and drift regression
   map server time onto each phone's monotonic clock. The error is at most half the path asymmetry.
2. **A scheduled timeline.** At the flick, the thrower fixes `t_land` in server time. Both devices render
   against `t_land`, not against message arrival.
3. **Dual-path delivery.** The THROW travels both peer-to-peer (BLE L2CAP / Multipeer / Wi-Fi Aware) and
   via the server. The first arrival renders, and duplicates are dropped by `intent_id`.

## 4.4.2 Clock synchronisation

```text
client: PING{t1}  ─────────▶  server stamps t2 (receive) and t3 (send)  ─────────▶  client: PONG at t4
θ̂ = ((t2 − t1) + (t3 − t4)) / 2          offset estimate (server − client)
δ = (t4 − t1) − (t3 − t2)                round trip without server processing
|θ̂ − θ| ≤ δ / 2                          error = half the up/down asymmetry
```

| Aspect | Specification |
|---|---|
| Sampling | Burst of 8 (100 ms apart) on connect and on network change (Wi-Fi ↔ cellular). One sample per heartbeat (15 s). A burst of 4 when entering throw or catch mode |
| Filtering | Keep the **minimum-delay** sample of each 30 s epoch, because queuing only adds delay. Fit `offset(t) = a + b·t` by weighted least squares (`w = 1/δ²`) over the last 10 epochs. `b` absorbs oscillator drift (10–50 ppm ≈ 0.6–3 ms/min) |
| Clocks | Client: monotonic only (`CACurrentMediaTime` / `CADisplayLink.targetTimestamp`; `SystemClock.elapsedRealtimeNanos` / `Choreographer` frame time), so wall-clock jumps cannot move the schedule. Server: chrony/PTP-disciplined (sub-ms across a region's gateways), with t2/t3 stamped as close to the socket as possible (`SO_TIMESTAMPING` where available) |
| Health | `bound = δ_min/2` of the freshest samples. If `bound > 25 ms` or no sample in 5 min, the device falls back to arrival-triggered rendering (§4.4.6) |
| Pair refinement | When both phones share a BLE link (catch mode), they run the same exchange **directly**. The two devices only need a *common* clock, not the server's. If the P2P and server-derived offsets disagree by > 15 ms, the pair uses the P2P offset |

Measured in the reference (`TestClockSyncWithinBound`): 10 minutes of samples every 2 s (throw-mode density), a 5 ms up/down asymmetry
and exponential jitter (mean 15 ms per direction) give an **offset error of 2.16 ms** (bound 11.5 ms).

## 4.4.3 The animation timeline

```text
t_flick  = server time at flick confirmation                 (thrower: monotonic + θ̂)
T_flight = clamp(d / (3 · v_peak), 250 ms, 700 ms)            d = UWB distance; a harder flick flies faster
t_land   = t_flick + T_exit (120 ms) + T_flight
budget   = t_land − T_entry (200 ms) − t_flick  ≥ 120 + 250 − 200 = 170 ms
```

- **Thrower:** the exit animation starts locally at once. The coin leaves the screen toward the locked
  bearing, and a "release" haptic fires at `t_land`.
- **Receiver:** on `INCOMING{t_land, trajectory}` it schedules the entry animation at
  `local(t_land) − T_entry`. Poses are computed for each frame's **presentation time**
  (`targetTimestamp` / `frameTimeNanos` plus the display pipeline delay), not the callback time. This
  removes most of the 8.3 ms (120 Hz) / 16.7 ms (60 Hz) frame quantisation.
- **Late arrival** (`ReceiverPlan`): if the event arrives after the scheduled start, the entry animation is
  compressed (`rate = T_entry / remaining`, up to 3×) so it still lands at `t_land`. Beyond that it lands
  immediately, and the skew equals the residual lateness.

Example (`TestTimelineHidesLatency`): d = 1.5 m and v = 1.5 m/s → T_flight = 333 ms, `t_land = t_flick +
453 ms`, **budget 253 ms**. An event arriving 100 ms before landing plays at 2× and still lands on time.

## 4.4.4 Budgets

**Delivery (thrower → receiver), cellular, against the ≥ 170 ms flight budget.** Animation frames are
forwarded **optimistically**, gateway to gateway, *in parallel with* risk scoring and the ledger hold. A failed
authorisation turns the landed coin into a "fizzle" and never into a settled payment.

| Stage | p50 | p99 |
|---|---:|---:|
| Uplink thrower → PoP | 20 ms | 60 ms |
| Gateway → NATS → receiver's gateway (same region) | 2 ms | 8 ms |
| Downlink PoP → receiver | 20 ms | 60 ms |
| **Total, server path** | **~42 ms** | **~128 ms** |
| P2P path (BLE L2CAP, link already up) | 10–30 ms | 45 ms |

**Landing skew (what users see).**

| Component | p95 |
|---|---:|
| Thrower clock error | ≤ 5 ms |
| Receiver clock error | ≤ 5 ms |
| Residual frame quantisation after presentation-time poses (each device) | ≤ 4 ms |
| Lateness beyond budget | 0 while delivery < 170 ms |
| **Total** | **≤ 20 ms design; SLO < 50 ms** |

The SLO is **measured, not inferred**: both devices report the server-time instant at which they presented
the landing frame, and the server builds the skew distribution per region, network type and device class.

## 4.4.5 Wire protocol

WSS (RFC 6455) over TLS 1.3 with binary frames. Each frame is a CBOR array `[v, type, seq, ack, body]` with
per-direction sequence numbers and acknowledgements (at-least-once). Sessions are **resumable** for 120 s:
`HELLO{session, last_ack}` replays from the per-device outbox (a Redis stream). Durable state such as
intents and settlements is also re-derivable from the ledger outbox.

| Type | Dir. | Body | Notes |
|---|---|---|---|
| `HELLO` / `WELCOME` | C↔S | device, token + PoP proof, resume `{session, ack}`, capabilities / session, server time, heartbeat | |
| `PING` / `PONG` | C↔S | `t1` / `t1, t2, t3` | Clock samples, piggybacked on heartbeats |
| `PRESENCE` | C→S | mode (off, catch, throw), rotating BLE EIDs, TTL ≤ 120 s | Catch mode is opt-in and auto-expires |
| `PEER_SEEN` | C→S | EID, RSSI, UWB range | Server resolves EID → device. A *mutual* sighting creates a proximity session |
| `PEER` | S→C | peer ref, avatar/handle, capabilities, UWB OOB data (NI discovery token / FiRa params), ready | Proximity sessions only |
| `THROW` | C→S, P2P | `intent_id` (UUIDv7), to, amount, currency, `t_flick`, `t_land`, trajectory `{az, v, d}`, TxAuth | Same bytes on both paths |
| `THROW_ACK` | S→C | `intent_id`, state (held / rejected), reason | |
| `INCOMING` | S→C | `intent_id`, from, amount, currency, `t_land`, trajectory | Preview first, authoritative state follows |
| `CATCH` | C→S, P2P | `intent_id`, accept | |
| `SETTLED` / `ABORTED` | S→C | `intent_id`, entry ID / reason | `ABORTED` plays the boomerang |
| `SHAKE` / `GROUP` / `GROUP_CONFIRM` | C↔S | §3.B.4 | |
| `ERROR` | S→C | code, `retry_after` | |

**Server intent state machine** (durable in `payment_intents`):

```text
CREATED ──risk ok + hold──▶ HELD ──INCOMING delivered──▶ DELIVERED ──CATCH(accept)──▶ CAUGHT ──post──▶ SETTLED
   │ risk / limits fail       │ live TTL (30 s) without a catch        │ CATCH(decline)
   ▼                          ▼                                         ▼
ABORTED (no hold)        ASYNC_PENDING (claimable 7 d) ──expiry / decline──▶ VOIDED (hold voided, boomerang)
```

**Client UI state machine:** `AIMING → LOCKED → THROWN (local) → IN_FLIGHT (ack or P2P echo) → LANDED →
CAUGHT → SETTLED`, or `→ BOOMERANG` on `ABORTED` / `VOIDED`.

## 4.4.6 Network drop mid-gesture

| Failure point | What the user sees | Protocol |
|---|---|---|
| No network when the flick confirms | Coin hovers at the screen edge: "waiting for connection" | THROW goes to the device outbox with its fixed `intent_id`. The P2P path is tried. Retries back off 250 ms → 4 s within the 30 s live TTL. After that: offline payment if both phones are near (§3.A), otherwise async or cancel, as the user prefers |
| THROW sent, no ACK | Coin in flight; spinner after `t_land` | Retransmit the same `intent_id` (idempotent). After reconnecting, `HELLO` resume replays the ACK or current state |
| Receiver offline when INCOMING is sent | "Delivering…" | Per-device outbox. If `t_land` has passed on replay, the receiver gets a catch prompt without a fake flight |
| Only the P2P path worked | Normal animation | The receiver relays the signed THROW to the server when it reconnects (dual-path submission). The server deduplicates |
| Clock unhealthy (bound > 25 ms or stale) | Animation still plays | Arrival-triggered rendering: skew equals delivery latency, typically < 50 ms on Wi-Fi |
| Gateway or region failover | Sub-second reconnect | Session resumes on another gateway. Intents are durable in the ledger database, and outbox streams are replicated |
| Duplicate THROW or CATCH | n/a | Idempotent by `intent_id` |
| Catch after the live TTL | Receiver sees "claim" | The intent is `ASYNC_PENDING`, so the claim posts the hold |

## 4.4.7 Scale

- **Connections:** the Rust gateway holds ~250 k concurrent WSS connections per node (≈ 30–40 KB each for
  TLS state and buffers), so 1 M per cell takes 4–6 nodes. Heartbeats run every 15 s, under mobile NAT
  timeouts. Backgrounded iOS/Android apps drop the socket and are woken through APNs/FCM for `INCOMING`.
- **Routing:** the device → gateway map lives in Redis (TTL refreshed by heartbeat). Cross-gateway delivery
  uses NATS subjects `dev.<device>`, and both gateways of a proximity session subscribe to
  `prox.<session>`, so a throw costs a single in-region hop.
- **Backpressure:** per-connection send queues are bounded (64 frames). Tip bursts are coalesced (§4.3.3).
  Slow consumers are disconnected and resume from their outbox.
- **Tracing:** one trace ID runs from the flick through the ledger posting to both landing reports.
