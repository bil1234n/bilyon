# §5 Strategic Implementation Roadmap

[← RFC index](README.md)

**Sequencing principle:** trust layer first (ledger, identity, keys), then the delight layer (kinetic,
realtime), then the hard layer (offline), then global scale. Each phase has exit criteria that gate the
next. Every capability ships behind feature flags and regional pilots.

| Phase | Months | Theme | Gate to next phase |
|---|---|---|---|
| 1 | 0–6 | Trusted online payments | Ledger invariants hold with zero breaks; pentest and crypto review passed |
| 2 | 6–12 | Kinetic UX and realtime | Gesture accuracy and landing-skew SLOs met in beta |
| 3 | 12–20 | Offline and settlement depth | Offline loss < 2 bp in pilot; 10k TPS per region game-day verified |
| 4 | 20–30 | Global scale | 99.99 %, 50k TPS peak, SDK GA |

## Phase 1: Foundation, trusted online payments (M0–M6)

**Scope**
- KYC'd accounts in two launch markets with 2–3 currencies. P2P by handle, payment links, merchant QR.
- Passkey login (§2.2.2–2.2.3). `K_dev`/`K_gest` binding with App Attest, Android Key Attestation and Play
  Integrity (§2.2.4). TxAuth with dynamic linking (§2.2.5).
- Double-entry ledger on PostgreSQL with holds, outbox and invariant triggers (§2.3). The ledger service
  interface is frozen for the later TigerBeetle swap.
- FX v1: netting book, one LP, 30 s firm quotes (§3.C.4–3.C.6).
- ISO 20022 gateway v1 through a sponsor bank (SEPA Instant / UK Faster Payments). Daily 3-way reconciliation.
- Risk rules v1, sanctions screening, KYC vendor integration, transaction monitoring.

**Stack**

| Layer | Technology |
|---|---|
| Services | Go 1.24: API gateway (`net/http` + Connect/gRPC), orchestrator, ledger service, FIDO2 RP on a vetted WebAuthn library |
| Data | PostgreSQL 17 (primary + synchronous standby + async DR replica), Redis/Valkey 8, NATS JetStream, Kafka/Redpanda + Debezium CDC |
| Platform | Kubernetes (2 cells × 3 AZs), Terraform, Argo Rollouts, OpenTelemetry, cloud HSM (PKCS#11) for `K_iss`/`K_dir`, KMS |
| iOS | Swift 6, SwiftUI, CryptoKit / Security framework (Secure Enclave), DeviceCheck (App Attest), AuthenticationServices (passkeys) |
| Android | Kotlin 2, Compose, Credential Manager, Android Keystore (StrongBox), Play Integrity |
| Shared core | Rust: CBOR/COSE, TxAuth, vault, protocol state machines. UniFFI bindings to Swift and Kotlin |

**Exit criteria:** server-side authorisation p99 ≤ 80 ms. Continuous invariant audit with zero breaks.
Zero unexplained reconciliation breaks for 30 consecutive days. External pentest and cryptographic design
review passed. SOC 2 Type I. 99.9 % availability.

## Phase 2: Kinetic UX and realtime (M6–M12)

**Scope**
- Rust realtime gateway (§4.4.5–4.4.7), clock sync (§4.4.2), presence with rotating BLE EIDs, proximity sessions.
- UWB ranging within one ecosystem (Nearby Interaction; Jetpack UWB). The C++20 gesture engine (flick,
  target lock, shake, grab; §3.B) is ported from the reference implementation and checked against its
  tests and recorded sensor traces.
- **Sensor-trace lab:** a motion-capture rig plus recorded corpora from 200+ volunteers across device
  models. Every trace becomes a deterministic replay regression test, which also personalises thresholds.
- Haptics, onboarding calibration ("practice throws"), shake-to-split with group confirmation, proximity grab.
- Mini-App SDK beta (web, iOS, Android) with two design partners (§4.3).
- FX v2: three LPs, six currencies, split routing, reservations (§3.C.3, §3.C.5).

**Stack additions:** Rust (tokio, rustls, tungstenite) for the gateway; C++20 + Eigen gesture core behind
Objective-C++ and JNI bridges; a trace-replay harness in CI.

**Exit criteria:** correct target ≥ 99.5 % of auto-locks. Accidental flicks < 1 per 1 000 active minutes.
Picker fallback ≤ 10 % of throws. Speculative-start cancellations < 2 %. Landing skew p95 < 50 ms, measured
by device telemetry. Event delivery p99 ≤ 250 ms. 99.99 % of SDK webhooks delivered within 1 minute.

## Phase 3: Offline and settlement depth (M12–M20)

**Scope**
- Offline Tier K (iOS and Android) and Tier S (Android) in 1–2 pilot markets, with limits agreed with the
  regulator (§3.A). Includes the guarantee fund, reconciliation service, CRL deltas (Bloom filter plus
  exact list), time-floor beacons, and frozen cross-platform test vectors (§2.1.5). Optional BLE merchant
  mesh radar.
- **TigerBeetle** for balances and holds: shadow writes, then cutover per currency (§2.3.5).
- Multi-region active-active with inter-region clearing (§1.4). Direct scheme access where licensing
  allows. A stablecoin (USDC on an L2) corridor for two corridors (§3.C.8).
- Key transparency directory with an external auditor (§4.1.3). SOC 2 Type II. PCI DSS only if card flows
  are added.

**Exit criteria:** offline loss < 2 bp of offline volume across the pilot. 95 % of offline claims reconciled
within 1 h of the payee's sync. Payee verification ≤ 50 ms on the low-end device class. 10k TPS sustained
per region with RPO 0 and RTO ≤ 60 s, verified in a game day. Key transparency audited by a third party.

## Phase 4: Global scale (M20–M30)

**Scope:** Tier H (secure-element applets on supported devices and wearables, SE-to-SE transitive value with
hop limit 3). Cross-ecosystem UWB through FiRa interoperability, behind a flag. 20+ currencies. Automated
hedging. Livestream tipping at 1 M viewers per stream. SDK GA. Regional data residency. Additional licences.

**Exit criteria:** 99.99 % payments API availability. 50k TPS peak. Median all-in FX cost ≤ 10 bp for majors
and ≤ 60 bp for EM corridors. SDK live in ≥ 10 host apps.

## Team topology (indicative, at Phase 2 peak)

| Squad | Focus | Engineers |
|---|---|---:|
| Ledger & Settlement | Go, PostgreSQL → TigerBeetle, ISO 20022, reconciliation | 8 |
| Identity & Security | FIDO2 RP, attestation, HSM/KMS, key transparency | 6 |
| Mobile Platform | Swift/Kotlin apps, Rust core integration, SDK | 10 |
| Gesture & Sensors | C++ DSP, UWB/BLE, trace lab | 5 |
| Realtime | Rust gateway, clock sync, presence | 5 |
| FX & Treasury | Router, quotes, hedging, LP integrations | 5 |
| Risk & Compliance Eng. | Scoring, monitoring, sanctions, offline fraud | 6 |
| SRE / Platform | Cells, observability, game days | 6 |

## Risks and mitigations

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| UWB coverage and cross-ecosystem interoperability | High / medium | UWB is never mandatory: picker + BLE fallback (§3.B.6) |
| Regulatory treatment of offline value (holding limits, consumer protection) | Medium / high | Early regulator engagement; pilot markets; per-jurisdiction limits are configuration |
| Platform policy changes (NFC/SE entitlements, store payment rules) | Medium / medium | Core flows need no special entitlements; Tier H only where available |
| Tier K fraud above model | Medium / medium | Low default limits, risk-driven dynamic limits, guarantee pricing, kill switch per device model and OS version |
| Thin FX liquidity in emerging-market corridors | Medium / medium | Several LPs, netting, stablecoin corridors, corridor-specific buffers |
| Accidental gestures erode trust | Medium / high | Gestures never authorise; confirmation; telemetry-driven tuning; reduced motion |
| HSM or key-management failure | Low / high | Quorum controls, DR HSM in a second region, rotation drills |
| Ledger migration | Medium / high | Interface frozen in Phase 1; shadow writes; reconciliation; cutover per currency |
| Proximity and identity privacy | Medium / high | Opt-in catch mode, rotating EIDs, OPRF discovery, key transparency |

## Open questions

1. Guarantee fund sizing, and whether the residual offline risk is reinsured externally.
2. Should Tier H devices accept *re-spent* offline value from other Tier H devices only, or also from Tier S? (Current answer: Tier H only.)
3. Cross-currency offline payments: embed a fixed offline FX rate in the OAC, or keep allowances single-currency? (Current answer: single-currency.)
4. Data residency of the handle directory and transparency log across regions.
5. Lab validation that App Attest counters remain monotonic across OS updates and device restores (the iOS rollback detector, §3.A.4).
6. Tier S reach (share of Android devices whose attestation shows hardware-enforced usage limits and rollback resistance) and denomination sets per market, from pilot data.
7. WebTransport/QUIC for the realtime channel (connection migration across Wi-Fi and cellular) in Phase 3.

## Alternatives considered

| Alternative | Decision |
|---|---|
| JWT/JOSE for offline tokens | Rejected: JSON + base64 is ≈ 2× the size, and non-canonical JSON invites parser differentials. COSE is the IETF binary equivalent |
| Chaumian blind-signature e-cash | Deferred: strong payer privacy, but double-spender identification needs heavier constructions and conflicts with AML attribution. Revisit for a small-value tier |
| Public L1 blockchain as system of record | Rejected: latency, fees, privacy, finality. Kept only as a settlement rail |
| Server-side gesture matching (Bump-style accelerometer correlation) | Rejected as the primary mechanism: it needs the network for every gesture and mismatches in crowds. Used only as an auxiliary shake-grouping signal |
| WebRTC data channels for the P2P path | Rejected: ICE setup (1–3 s) is longer than the whole flight. BLE, Multipeer and Wi-Fi Aware are faster for co-located phones |
| A single global ledger | Rejected: cross-region latency on every write. Regional ledgers plus clearing are simpler and satisfy residency |
| Synced passkeys as transaction keys | Rejected: no device binding or attestation, so no offline support and no per-device limits |
