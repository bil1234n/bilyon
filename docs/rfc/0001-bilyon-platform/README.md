# RFC 0001 — Bilyon: Kinetic, Offline-Capable, Low-Fee Payment Platform

| | |
|---|---|
| **Status** | Draft, open for review |
| **Created** | 2026-10-06 |
| **Scope** | System architecture, cryptographic protocols, core algorithms, realtime engine, delivery plan |
| **Audience** | Engineering leadership, security, mobile, backend, risk/compliance reviewers |
| **Reference code** | [`/reference`](../../../reference) (Go, stdlib only). The tests make Algorithms A–C executable |

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 / RFC 8174.

## Abstract

Bilyon is a payment platform with four properties that are rarely combined:
low fees (mid-market FX, internal netting, direct clearing), offline payments with bounded and
attributable double-spend risk, hardware-backed biometric authorisation (FIDO2, Secure Enclave,
StrongBox), and a kinetic interface where money is *thrown* to a phone you point at, *split* by
shaking phones together, and *grabbed* from a table. Social handles work as payment addresses,
and an embeddable SDK brings the same flows into third-party social and livestream apps.

This RFC specifies the system end to end. The parts that are novel or easy to get wrong have
normative pseudocode and an executable reference implementation: the offline token protocol
and its reconciliation, the flick/target-lock maths, FX routing and rate locks, and the clock
synchronisation behind the "< 50 ms" animation requirement. Throughout, the RFC distinguishes
what hardware guarantees from what software and risk limits only bound. Where the platforms
impose limits (UWB interoperability, secure-element access, NFC entitlements), the RFC states them
and designs around them.

## 1. Goals and non-goals

**Goals**

1. P2P and merchant payments in any supported currency at an all-in cost of **≤ 10 bp for majors**
   (EUR/USD/GBP/JPY) and **≤ 60 bp for emerging-market corridors**, quoted firm with a rate lock.
2. **Offline payments** between two phones with no network on either side. Overspend is impossible
   on hardware-enforced tiers. On every tier it is cryptographically attributable and capped
   by policy.
3. **Biometric authorisation without biometric data leaving the device**. A FIDO2 / platform-key
   signature is the only proof the server ever sees.
4. **Kinetic gestures** that are safe by construction. A gesture can select a counterparty and start
   a payment. It can never move money without a hardware-gated signature and, for transfers, the
   receiver's catch.
5. **Social reach**: handles as addresses, self-destructing payment links, and an SDK for host apps
   and livestreams.
6. Horizontal scale to **50k TPS peak** with **RPO 0** in-region and **99.99 %** payment API
   availability (Phase 4).

**Non-goals (this RFC)**

- Card issuing/acquiring and card-scheme certification (an integration RFC will cover it).
- Credit products, interest-bearing balances, or a native token.
- A public blockchain as the system of record. Stablecoin L2s are only a settlement *rail* (§3.C.8).
- Fully anonymous offline cash. Offline payments are pseudonymous to merchants and attributable
  to the issuer (AML/CFT, §6).

## 2. Requirements and SLOs

| Area | Requirement | Target | Where |
|---|---|---|---|
| Payments API | Authorisation latency (server, p99) | ≤ 80 ms | §1 |
| Payments API | End-to-end tap-to-confirmation (p99, LTE) | ≤ 300 ms excl. biometric | §1 |
| Ledger | Invariant | Every journal entry balances per currency; no negative user balance | §2.3 |
| Ledger | Durability / failover | RPO 0 in-region, RTO ≤ 60 s | §1.4 |
| Offline | Packet size (Tier K) | ≤ 512 B (measured 463 B) | §2.1 |
| Offline | Payee verification time | ≤ 50 ms on a 2021 mid-range phone | §3.A |
| Offline | Loss rate (fraud net of recovery) | < 2 bp of offline volume | §3.A.2 |
| Gestures | Correct target when auto-locked | ≥ 99.5 % | §3.B |
| Gestures | Accidental flick detections | < 1 per 1,000 active minutes | §3.B |
| Realtime | Landing animation skew between devices (p95) | **< 50 ms** (design ≤ 20 ms) | §4.4 |
| Realtime | Event delivery thrower→receiver (p99) | ≤ 250 ms | §4.4 |
| FX | Quote latency (p99) | ≤ 30 ms | §3.C |
| FX | Lock TTL | 30 s in-app (10 s volatile pairs), ≤ 24 h invoices (priced) | §3.C.4 |

## 3. Design decisions at a glance

| # | Decision | Rationale |
|---|---|---|
| D1 | Offline artefacts are **COSE_Sign1 over deterministic CBOR**, ES256 | Fits one BLE SDU / NFC APDU / QR code; one canonical byte string per payload (§2.1) |
| D2 | **Three offline tiers** (K, S, H) chosen by attestation | iOS cannot enforce single-use keys; Android 12+ can; secure elements can enforce balances (§3.A.1) |
| D3 | Offline value is **escrowed on the ledger** before it can be spent | Payees are paid from a real reserve; overspend draws a capped guarantee fund plus clawback |
| D4 | **Passkeys for login, device-bound keys for money** | Synced passkeys have no device binding or attestation; transaction keys must be hardware-bound and attested (§2.2) |
| D5 | Gestures are resolved **in the thrower's gravity-aligned frame** | Flick velocity and UWB bearings come from the same device, so no shared compass is needed (§3.B) |
| D6 | Target lock is **Bayesian with a null hypothesis and a picker fallback** | Money never moves on an ambiguous lock |
| D7 | Realtime sync schedules a **shared landing time**; it does not race the network | Network latency is hidden inside the animation; skew is set by clock error, not RTT (§4.4) |
| D8 | FX = **netting first**, hop-bounded DP over depth ladders, water-filling splits | Most volume never touches an external LP; the router is exact under stated conditions (§3.C) |
| D9 | Handles resolve to **stable provider IDs** in a **transparency log** | Defends against handle recycling and silent key substitution (§4.1) |
| D10 | Postgres ledger first, **TigerBeetle** for the balance hot path in Phase 3 | Ship fast on known tech; migrate behind a ledger interface when throughput requires (§5) |

## 4. Document map

| § | Document | Covers deliverable |
|---|---|---|
| 1 | [Architecture](01-architecture.md) | High-level diagram, layers, trust boundaries, key hierarchy, flick sequence, deployment |
| 2.1 | [Offline artefacts & encoding](02a-offline-artefacts.md) | CBOR/COSE conventions, OAC/OST/receipt/coin CDDL, handshake, sizes |
| 2.2 | [FIDO2 & device binding](02b-fido2-device-binding.md) | WebAuthn registration/authentication, attestation, transaction signing |
| 2.3 | [Ledger data model](02c-ledger-data-model.md) | Double-entry schema, holds, outbox, invariants |
| 3.A | [Algorithm A: offline double-spend prevention](03a-algorithm-offline.md) | Tiers, payer WAL, payee checks, reconciliation, coins |
| 3.B | [Algorithm B: kinetic gestures](03b-algorithm-kinetic.md) | Flick detection, UWB target lock, shake-to-split, grab/drop |
| 3.C | [Algorithm C: FX routing & rate lock](03c-algorithm-fx.md) | Liquidity graph, router, splits, lock pricing, execution |
| 4.1–4.3 | [Social identity, links, SDK](04a-social-identity.md) | Handle mapping, transparency log, deep links, Mini-App SDK |
| 4.4 | [Realtime sync engine](04b-realtime-sync.md) | WebSocket protocol, clock sync, < 50 ms landing skew |
| 5 | [Roadmap](05-roadmap.md) | Phases 1–4, stack, exit criteria, risks, open questions |
| 6 | [Security & failure modes](06-security-failure-modes.md) | Threat model, consolidated edge-case protocol matrix |

## 5. Glossary

| Term | Meaning |
|---|---|
| **OAC** | Offline Allowance Certificate: issuer-signed grant to spend up to *amt* offline with one device key |
| **OST** | Offline Spend Token: payer-signed, hash-chained transfer of part of an allowance to one payee |
| **Tier K / S / H** | Offline enforcement tiers: Key-bound (app-enforced counter), Single-use coin keys (TEE-enforced), secure-element applet (Hardware-enforced balance) |
| **Equivocation proof** | Two OSTs with the same allowance and sequence number but different content, both validly signed. Proves fraud without trusting anyone's testimony |
| **Time floor** | A device's non-decreasing lower bound on the current time, advanced by every server-signed timestamp it sees |
| **Throw intent** | Server-side state machine of one kinetic transfer (created → held → delivered → caught → settled / aborted) |
| **Landing time** | Server-time instant at which both devices render the coin's arrival |
| **Netting book** | Internal liquidity formed by opposite customer flows, priced at mid-market |
| **Lock buffer** | Spread that prices the platform's market risk during a rate lock, z·σ·√TTL |
| **PAR** | Payment Address Record: signed resolution of a handle to an account reference and payee keys |
