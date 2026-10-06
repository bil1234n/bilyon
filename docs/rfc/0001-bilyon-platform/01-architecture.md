# §1 System Architecture

[← RFC index](README.md)

## 1.1 High-level architecture

```text
 EDGE LAYER: phone (iOS / Android) and the embedded SDK
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Sensors                    Gesture engine (C++20, shared)        Experience (Swift / Kotlin)        │
│ ┌──────────────────────┐   ┌──────────────────────────────┐     ┌────────────────────────────────┐  │
│ │ IMU 100–200 Hz       │──▶│ world-frame transform        │────▶│ throw · catch · split · grab UI│  │
│ │ UWB (NI / Jetpack)   │──▶│ flick detector      (§3.B.2) │     │ vsync animation scheduler      │  │
│ │ BLE 5 (EIDs, L2CAP)  │──▶│ Bayesian target lock (§3.B.3)│     │ Core Haptics / VibrationEffect │  │
│ │ NFC (HCE / reader)   │   │ shake, grab (§3.B.4–§3.B.5)  │     └───────────────┬────────────────┘  │
│ └──────────────────────┘   └──────────────────────────────┘                     │                   │
│ Secure hardware (SE / StrongBox / TEE)     Protocol core (Rust, UniFFI)         │                   │
│ ┌──────────────────────────────────────┐   ┌────────────────────────────────────▼───────────────┐   │
│ │ K_dev   tx key, biometric per use    │◀──│ COSE/CBOR · offline vault + WAL (§3.A) · time floor│   │
│ │ K_off   per-allowance offline key    │   │ CRL filter · clock sync · outbox/inbox · sync agent│   │
│ │ K_coin  single-use coin keys (Tier S)│   │ P2P: BLE L2CAP CoC · Multipeer / Wi-Fi Aware · NFC ┼───┼──▶ peer
│ │ App Attest / Android Key Attestation │   └──────────────────────────┬─────────────────────────┘   │
│ └──────────────────────────────────────┘                              │                             │
└───────────────────────────────────────────────────────────────────────┼─────────────────────────────┘
                 TLS 1.3 + SPKI pinning · WSS (CBOR frames) · HTTPS / gRPC · DPoP-bound tokens
 GATEWAY / ROUTING LAYER: per regional cell, active-active              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Anycast LB → WAF / rate limits → API gateway (Go)              Realtime gateway (Rust, tokio)       │
│        │                                                       presence · throw/catch · clock pong  │
│        ▼                                                                   ▲ events via NATS        │
│ ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐                          │
│ │ FIDO2 Relying Party  │ │ Payment orchestrator │ │ FX engine (§3.C)     │                          │
│ │ attestation verifier │ │ sagas · idempotency  │ │ quotes · router      │                          │
│ │ device registry      │ │ throw-intent FSM     │ │ rate locks · hedger  │                          │
│ └──────────────────────┘ └──────────────────────┘ └──────────────────────┘                          │
│ ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐ │
│ │ Identity: handles,   │ │ Offline service:     │ │ Risk engine: rules + │ │ Compliance: KYC/KYB, │ │
│ │ transparency log,    │ │ allowances, recon-   │ │ ML scoring < 20 ms,  │ │ sanctions, Travel    │ │
│ │ links, social OAuth  │ │ ciliation, CRL       │ │ velocity, graph      │ │ Rule, AML monitoring │ │
│ └──────────────────────┘ └──────────────────────┘ └──────────────────────┘ └──────────────────────┘ │
│ Redis/Valkey: sessions, presence, quotes, rate limits, idempotency     HSM: issuer + directory keys │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
                 ▼ ledger commands (idempotent)                   ▲ outbox events (CDC)
 LEDGER / SETTLEMENT LAYER
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Core ledger: double-entry, append-only (PostgreSQL, then TigerBeetle for balances) · outbox → Kafka │
│ ┌───────────────────────┐ ┌───────────────────────────┐ ┌────────────────────────┐ ┌─────────────┐  │
│ │ Settlement engine     │ │ ISO 20022 gateway         │ │ Stablecoin / L2 rail   │ │ Treasury    │  │
│ │ netting · batching    │ │ pacs.008/002/004, camt.05x│ │ USDC on/off-ramp       │ │ positions,  │  │
│ │ cut-offs · retries    │ │ SEPA Inst · FedNow · PIX  │ │ Travel Rule payloads   │ │ nostro,hedge│  │
│ └───────────────────────┘ └───────────────────────────┘ └────────────────────────┘ └─────────────┘  │
│ Reconciliation (ledger ↔ rails ↔ statements) · data warehouse (CDC) · audit log (WORM storage)      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Layer responsibilities

| Layer | Owns | Never does |
|---|---|---|
| **Edge** | Sensor fusion, gesture detection, target lock, biometric-gated signing, offline vault, P2P transport, optimistic UI | Decide that money has moved (only the ledger or a verified offline token does) |
| **Gateway / routing** | Authentication (FIDO2 RP), device attestation, orchestration, risk, FX pricing, identity resolution, realtime fan-out | Hold balances (all balance mutations go through ledger commands) |
| **Ledger / settlement** | Balanced journal, holds (two-phase), reserves, external settlement, reconciliation | Call out synchronously to devices or LPs inside a ledger transaction |

## 1.2 Trust boundaries

| ID | Boundary | Crossing artefacts | Controls |
|---|---|---|---|
| TB1 | App process ↔ secure hardware | Digest in, signature out; biometric match result never leaves the SE/TEE | Access-control flags `.biometryCurrentSet` (iOS) / `AUTH_BIOMETRIC_STRONG` per-use (Android); keys non-exportable |
| TB2 | Device ↔ device (P2P, offline) | PaymentRequest, Packet (OAC+OST), Receipt (§2.1) | Every message COSE-signed by an issuer-certified key; nonces; payee binding; no trust in transport |
| TB3 | Device ↔ edge gateway | REST/gRPC calls, WSS frames | TLS 1.3, SPKI pinning with backup pins, DPoP-style proof-of-possession of the session key, App Attest / Play Integrity on risky calls |
| TB4 | Host app ↔ Bilyon SDK | PaymentIntent client secret in, signed result out | Confirmation runs in a Bilyon-owned surface (app switch, ASWebAuthenticationSession, Custom Tabs), never in a host WebView (§4.3) |
| TB5 | Services ↔ ledger | Idempotent ledger commands | mTLS, service identity, per-command authorisation; ledger enforces invariants itself |
| TB6 | Platform ↔ external rails / LPs | ISO 20022 messages, LP orders, on-chain txs | Message signing, allow-listed endpoints, independent reconciliation |

## 1.3 Key hierarchy

| Key | Location | Alg. | Protection | Purpose | Rotation |
|---|---|---|---|---|---|
| `K_pass` | Passkey provider (iCloud Keychain, Google PM) | ES256 | Synced, UV required | Account login, recovery | User-managed |
| `K_dev` | Secure Enclave / StrongBox | ES256 (P-256) | Non-exportable, biometric per use, invalidated on biometric change | Online transaction signing (dynamic linking), receipt signing | Per device install; re-bind on biometric change |
| `K_off(aid)` | Secure Enclave / StrongBox | ES256 | As `K_dev` | Tier K offline spend tokens, closing statements | One per allowance (unlinkable across allowances) |
| `K_coin[i]` | Android TEE / StrongBox | ES256 | `USAGE_COUNT_LIMIT=1`, hardware-enforced, rollback-resistant (attested) | Tier S coins | One per coin |
| `K_attest` | App Attest key (iOS) / attestation chain (Android) | ES256 | System-managed | Prove genuine app on genuine device; bind `K_dev`/`K_off` | Per install |
| `K_iss` | HSM (FIPS 140-3 L3) | ES256 | Dual control, quorum for export/rotation | Sign OAC and PayeeCert | 90 days; old `kid`s accepted until their certs expire |
| `K_dir` | HSM | ES256 | As `K_iss` | Sign transparency-log tree heads and PARs | 1 year |
| `K_quote` | KMS (HMAC-SHA256) | HMAC | Envelope-encrypted, per region | Integrity of FX quotes | 30 days, dual-key acceptance window |
| `K_webhook[host]` | KMS | HMAC-SHA256 | Per host app | Webhook signatures to SDK hosts | On demand |

## 1.4 Deployment topology

- **Regions** (e.g., eu-west, us-east, ap-south, sa-east) each hold one **logical ledger** replicated
  synchronously across three availability zones (RPO 0). Users are homed to a region for data
  residency. A cross-region payment is two local journal entries joined by an inter-region clearing
  account and an exactly-once message (transactional outbox on the sender side, idempotent apply on the
  receiver side, daily net settlement between regional treasuries).
- **Cells**: stateless services, realtime gateways and caches are deployed in cells of ~1–2 M users,
  routed by a hash of `user_id`. A failing cell sheds only its own users. The ledger is not cellular.
  It is partitioned internally (Postgres: hot-account striping; TigerBeetle: a single cluster per
  region up to its throughput limit).
- **Realtime affinity**: both parties to a flick are physically co-located and nearly always land in the
  same region, and usually on the same PoP. Throw events therefore cross at most one NATS hop
  (≈ 0.2–1 ms in-region).

## 1.5 End-to-end sequence: "flick to pay" (online)

```text
Thrower app                        Realtime GW      Orchestrator    Risk       Ledger    Realtime GW        Receiver app
     │ aim → lock "Alice" (haptic)      │                 │           │           │           │                   │
     │                                  │                 │           │           │           │     catch mode on │
     │ flick @ t0: exit anim (local)    │                 │           │           │           │                   │
     │─ THROW{id, amt, t_land, sig} ───▶│                 │           │           │           │                   │
     │                                  │─ create intent ▶│           │           │           │                   │
     │                                  │                 │─ score ──▶│           │           │                   │
     │                                  │                 │◀─ allow ──│           │           │                   │
     │                                  │                 │─ HOLD (pending) ─────▶│           │                   │
     │                                  │                 │◀─ held ───────────────│           │                   │
     │◀─ THROW_ACK ───────────────────────────────────────│           │           │           │                   │
     │                                  │                 │─ INCOMING{id, t_land} ───────────▶│                   │
     │                                  │                 │           │           │           │─ frame ──────────▶│
     │                                  │                 │           │           │           │     entry anim at │
     │                                  │                 │           │           │           │   t_land − 200 ms │
     │ ═══ coin lands at t_land on both screens (same server time ± clock error) ═══          │                   │
     │                                  │                 │◀─ CATCH{accept} ──────────────────────────────────────│
     │                                  │                 │─ POST → payee ───────▶│           │                   │
     │◀─ SETTLED (outbox → NATS → gateway) ───────────────────────────────────────│           │                   │
     │                                  │                 │           │           │─ SETTLED ────────────────────▶│
```

Rules this sequence encodes:

1. The flick only *initiates*. Funds are held after the server verifies a `K_dev` signature over
   `(intent_id, amount, currency, receiver, t_flick)` (dynamic linking, §2.2). Below the gesture limit
   (default 100.00), a biometric "arm" when throw mode opens covers 60 s of throws. Above it, the payer
   confirms after the lock.
2. Funds settle only on **CATCH**. If no catch arrives within the live TTL (30 s), the intent becomes an
   ordinary pending transfer the receiver can claim for 7 days, or it is voided, as the payer prefers.
   A void plays the "boomerang" animation.
3. The landing time `t_land` is fixed by the thrower at flick time (§4.4). Delivery latency below the
   flight budget is invisible to both users. The diagram shows the authoritative path. In production the
   animation preview is forwarded to the receiver *in parallel with* risk scoring and the hold (§4.4.4),
   and a failed authorisation turns the landed coin into a "fizzle", never a settled payment.

## 1.6 Technology choices

| Concern | Choice | Why |
|---|---|---|
| Business services | Go 1.24+ | Concurrency model, fast builds, strong ecosystem for gRPC/HTTP, easy to staff |
| Realtime gateway | Rust (tokio, rustls) | Predictable tail latency and memory per connection at 250k+ sockets/node |
| Ledger | PostgreSQL 17 → TigerBeetle (balances) + PostgreSQL (metadata) | ACID and familiarity first; purpose-built double-entry engine with native two-phase transfers at scale |
| Cache / ephemeral state | Redis or Valkey 8 (cluster) | Presence, sessions, quotes, rate limits, idempotency fast path (truth stays in the ledger) |
| Messaging | NATS (realtime fan-out); Kafka / Redpanda (durable event log, CDC via Debezium) | Sub-ms fan-out vs replayable audit stream |
| Mobile | Swift 6 / Kotlin 2 (platform APIs); C++20 + Eigen (gesture DSP); Rust (protocol, crypto, vault) | Sensors and secure hardware need native APIs; DSP and protocol logic must be bit-identical on both platforms |
| Crypto | P-256 ECDSA (ES256), SHA-256, HMAC-SHA256, COSE/CBOR | The only curve the Secure Enclave supports; one suite everywhere |
| HSM / KMS | Cloud HSM (FIPS 140-3 L3) via PKCS#11; cloud KMS for envelope keys | Issuer and directory keys never exist outside an HSM |
| Orchestration | Kubernetes, one cluster per cell; Argo Rollouts canaries | Cell isolation, progressive delivery |
| Observability | OpenTelemetry traces (gesture → settle), RED metrics, exemplars | One trace ID from the flick to the ledger posting |
