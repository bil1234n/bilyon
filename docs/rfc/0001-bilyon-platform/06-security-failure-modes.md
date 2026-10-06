# §6 Security Model and Consolidated Failure-Mode Protocol

[← RFC index](README.md)

## 6.1 Assets and adversaries

**Assets:** customer balances and holds; offline reserves; issuer, directory and quote keys; device keys;
handle → account mappings; PII and KYC data; proximity and location signals.

| ID | Adversary | Capabilities assumed |
|---|---|---|
| A1 | Remote attacker | Phishing, credential stuffing, SIM swap, social engineering |
| A2 | Malicious device owner | Root/jailbreak, patched app, state rollback, sensor injection; holds a genuine hardware key |
| A3 | Nearby attacker | BLE/NFC sniffing, relay, spoofing, UWB distance manipulation, tracking |
| A4 | Malicious host app | Controls the process embedding the SDK, its WebViews and UI overlays |
| A5 | Malicious payee or merchant | Double claims, false rejections, self-dealing with a colluding payer |
| A6 | Insider or compromised server | Ledger edits, key substitution in the directory, misuse of signing keys |
| A7 | Network attacker | MITM, replay, traffic analysis, DoS |

## 6.2 Threats and controls

| Threat | Adv. | Control | Residual risk |
|---|---|---|---|
| Account takeover by phishing | A1 | Origin-bound passkeys; no SMS OTP; device binding needs passkey + step-up | Social engineering of support; scripted recovery with liveness |
| SIM swap | A1 | A phone number is never an authenticator | n/a |
| Stolen unlocked phone | A1/A3 | Biometric per use (`K_dev`), 60 s window for `K_gest` with velocity limits, `.biometryCurrentSet`, remote revocation, offline allowances on the CRL | Coercion (out of scope; low limits) |
| Overlay or malware tricks the user into confirming | A2/A4 | System biometric prompt shows amount and payee (dynamic linking); `FLAG_SECURE`; integrity signals feed risk | Users approving without reading (limits, warnings) |
| Offline double-spend | A2 | Tiers K/S/H, escrowed reserve, equivocation proofs, guarantee + clawback (§3.A) | Bounded by `(m−1)·A` per Tier K allowance |
| Double claim via signature malleability | A5 | Token ID = payload hash; low-S enforced | n/a |
| Token replay to another payee | A5 | `pye` binding + single-use `pnc` | n/a |
| False "rejected" receipt, then claim | A5 | Payee-signed rejection voids the token (P6) | n/a |
| Self-dealing fork to own merchant accounts | A2+A5 | Guarantee escrow for graph-linked payees; per-allowance cap; KYC attribution | Identity-theft accounts (KYC quality) |
| MITM on the P2P link | A3 | Every artefact signed; ECDH to the certified payee key for confidentiality (§2.1.3) | Traffic metadata (timing) |
| Relay to a distant terminal | A3 | Payer sees the signed payee identity; UWB distance < 1 m where available | Unattended terminals without UWB (lower limits) |
| UWB distance reduction | A3 | 802.15.4z STS secure ranging on supported chips; ranging only selects, never authorises | n/a |
| Gesture/sensor injection | A2 | Selection only; signature and catch still required | n/a |
| Tracking via BLE/UWB | A3 | EIDs rotate every 15 min; catch mode opt-in, 2 min auto-expiry; no ranging outside mutual proximity sessions | Short-window correlation |
| Handle squatting / homoglyphs | A1 | UTS #39 skeleton uniqueness; homoglyph and first-payment warnings | n/a |
| Social handle recycling | A1 | Stable provider UIDs; 24 h re-validation | n/a |
| Directory key/account substitution | A6 | Key transparency, STH gossip, owner self-audit, external auditor | Detection, not prevention |
| Payment-link interception | A1/A7 | Bearer caps, `restrict_to`, rate limits, secret in the URL fragment | Leaked unrestricted links (≤ 250.00) |
| SDK credential capture | A4 | Bilyon-owned surfaces only; never a host WebView | n/a |
| Webhook spoofing / replay | A7 | HMAC with timestamp, 5 min tolerance; hosts dedupe on event ID | n/a |
| FX quote tampering / sniping | A1 | HMAC-signed quotes; single use; quote-to-trade controls | n/a |
| Ledger tampering | A6 | No UPDATE/DELETE grants; append-only rules; hash-chained WORM audit log with daily external anchoring; dual control on manual adjustments | Colluding DBAs (dual control, audits) |
| Signing-key misuse | A6 | HSM quorum, signing-velocity limits (allowance issuance), per-key audit streams | n/a |
| DoS on gateways | A7 | Anycast, WAF, per-device admission with PoP tokens, degradation to async payments | n/a |
| AML evasion through offline payments | A2 | KYC'd payers, per-allowance attribution, limits, monitoring on synced flows | Low-value structuring (limits) |

## 6.3 Privacy

- **Data minimisation:** offline artefacts carry per-allowance account pseudonyms, never names. A merchant
  cannot link two of a payer's allowances.
- **Biometrics** never leave the device. **Location**: no GPS. Proximity evidence (EIDs, RSSI, ranges) is
  kept ≤ 24 h for grouping and fraud analysis, then aggregated.
- **Residency:** user data stays in the home region. Cross-region payments carry only what clearing and the
  Travel Rule require.
- **Retention vs erasure:** transaction records are retained for the statutory period under a legal-obligation
  basis. PII is pseudonymised once that period ends.

## 6.4 Consolidated failure-mode matrix

Domain-specific protocols live in their own sections: offline sync conflicts in **§3.A.10**, network drop
mid-gesture in **§4.4.6**, FX and rail failures in **§3.C.10**. Infrastructure failures:

| Failure | Detection | Behaviour | Recovery |
|---|---|---|---|
| Ledger primary loss | Health checks, replication lag | Synchronous standby promoted (RTO ≤ 60 s, RPO 0); clients retry with idempotency keys | Rebuild old primary as standby |
| Full region outage | Multi-signal (LB, synthetic probes) | Users homed to the region lose online payments. **Offline allowances keep working for in-person payments**, so the offline tier doubles as disaster resilience | Async DR replica promoted manually (RPO seconds) if the outage is prolonged |
| HSM unavailable | Signing errors | New allowances and PAR re-signing pause; existing artefacts stay valid; quotes unaffected (KMS) | DR HSM cluster in a second region |
| CDC / Kafka lag | Consumer lag alerts | `SETTLED` events are delayed and the UI shows "processing"; clients may poll intent state; the ledger stays the source of truth | Catch-up; events are idempotent |
| Redis loss | Cluster alerts | Presence and sessions rebuild from reconnects; idempotency falls back to the database unique key; quotes are re-read from `fx_quotes` | Warm replica |
| NATS partition | Publish errors | Gateway fan-out falls back to the per-device outbox plus push notifications | Partition heals; outbox drains |
| Server clock drift | chrony/PTP alarms | Gateways with offset > 1 ms are drained from rotation | Resync, then readmit |
| Bad deploy | SLO burn-rate alerts | Per-cell canary halts; automatic rollback | Post-incident review |
| Expiry sweeper stalled | Hold-age metric | Holds stay pending (funds safe, UI shows pending) | Restart; idempotent catch-up |
| Device clock wrong | Offset bound / time floor | Rendering falls back to arrival-triggered; offline validity uses the time floor | Automatic |

## 6.5 Security engineering process

Threat modelling for every feature. External cryptographic design review before Phase 1 GA and again before
Phase 3. A penetration test per phase. A bug bounty from Phase 2. A dedicated offline-fraud red team in
Phase 3. Reproducible builds and an SBOM for the mobile crypto core. Pinned dependencies. Secrets only in
KMS/HSM. mTLS with workload identities (SPIFFE) between services. Quarterly key-rotation and DR game days.
