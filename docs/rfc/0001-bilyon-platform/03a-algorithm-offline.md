# §3.A Algorithm A: Offline Double-Spend Prevention and Local Token Deduction

[← RFC index](README.md) · Formats: [§2.1](02a-offline-artefacts.md) · Code: [`reference/offline`](../../../reference/offline)

## 3.A.0 What can and cannot be guaranteed

When neither party can reach a server, double-spending can be **prevented** only by hardware that
enforces state the attacker cannot roll back. Everything else can only **detect** it afterwards. Bilyon
therefore layers five mechanisms and is explicit about which tier gets which guarantee:

1. **Prevention** where the hardware allows it: Tier S single-use coin keys, Tier H secure-element balances.
2. **Bounded exposure**: offline value is escrowed on the ledger before issue, with short validity and per-token caps.
3. **Non-repudiable detection**: two conflicting tokens signed by one key are a self-contained fraud proof.
4. **Recovery**: payers are KYC'd. Overspend becomes a receivable, and the device and allowance are revoked.
5. **Merchant protection**: a capped guarantee fund pays good-faith payees the shortfall immediately.

## 3.A.1 Tiers

| | Tier K: key-bound | Tier S: single-use coins | Tier H: secure element |
|---|---|---|---|
| Eligibility (from attestation, §2.2.4) | Any attested device (iOS App Attest, Android Key Attestation) | Android 12+, coin keys with `usageCountLimit = 1` and rollback resistance **hardware-enforced** | Issuer-provisioned SE applet (eSE where entitlements exist, or an external JavaCard wearable/card) |
| What enforces "spend once" | App code (WAL + counter); key is hardware-bound and biometric-gated | TEE/StrongBox refuses a second signature per coin | Applet enforces balance and counter |
| Attacker must | Root/jailbreak, defeat app integrity, forge state. **Detected at first sync** | Extract keys from the TEE/StrongBox | Break the SE |
| Default limits: allowance / per tx / validity / tokens | 150.00 / 50.00 / 72 h / 32 | 500.00 / 200.00 / 7 d / 64 coins | 1 000.00 / 500.00 / 30 d / n.a. |
| Received funds re-spendable offline | No (payee must sync first) | No | Yes, SE to SE, hop limit 3 (Phase 4) |
| Platforms | iOS + Android | Android only (iOS has no single-use key primitive) | Where available |

Limits are policy (per jurisdiction, KYC level and risk score). Regulators' offline holding limits
override them.

## 3.A.2 Exposure model

Tier K, worst case: an attacker with a compromised device and allowance `A` signs `m` forked chains to
`m` payees who are all offline. Each branch can only reach `cum ≤ A`, so

```text
overspend ≤ (m − 1) · A,      m ≤ number of distinct offline payees reached before exp
expected loss / offline volume = P(compromise) · E[overspend] · (1 − recovery rate) / volume
```

The guarantee premium is set to this ratio and is priced into offline fees (target < 2 bp, SLO §2).
Each extra payee requires being physically present before `exp` (72 h), and the first sync of
*any* two conflicting tokens revokes the allowance. So `m` is small in practice, and `A` caps each step.

## 3.A.3 Provisioning (server, online)

```text
ProvisionAllowance(user, device, req{currency, amount}):
  require device integrity is fresh (App Attest assertion / Play Integrity verdict < 24 h old)
  tier ← EligibleTier(device.attestation)                       # §3.A.1
  (A, txmax, maxtx, ttl) ← Policy(user.kyc, tier, jurisdiction, risk)
  A ← min(req.amount, A, user.available)
  tier K: dpk ← fresh K_off(aid) public key, attested over H(aid ‖ dpk)
  tier S: verify every coin key's attestation; croot ← MerkleRoot(leaf(i, den_i, cpk_i)); A ← Σ den_i
  BEGIN
    Transfer(user → offline_reserve:aid, A)                     # escrow, idempotency key = aid
    INSERT offline_allowances(aid, …, state = active)
  COMMIT
  oac ← HSM.Sign1(K_iss, {aid, dpk, cur, A, txmax, nbf: now, exp: now + ttl, tier,
                          anchor: H("bilyon/anchor/v1", aid), maxtx,
                          acct: Pseudonym(user, aid), iat: now, crl: CRL.epoch, croot?})
  return oac + CRL delta + trust-store update
```

## 3.A.4 Payer: local deduction with a write-ahead log

Crash safety is the subtle requirement. If the app died after signing token `seq = 5` but before
recording it, a restart would sign a *different* `seq = 5`. The honest user would then produce an
equivocation proof against themselves. The WAL ordering below makes that impossible.

```text
Pay(cert_raw, req_raw, wall):
  (cert, req) ← VerifyRequest(cert_raw, req_raw)           # issuer sig on cert, payee sig on request
  now ← TimeFloor.Observe(cert.iat).Now(wall)
  require now ≤ cert.exp ∧ req.cur = oac.cur ∧ oac.nbf ≤ now ≤ oac.exp
  (seq, cum, prv) ← Head(WAL)                              # last durable entry, else (0, 0, anchor)
  require 1 ≤ req.amt ≤ oac.txmax ∧ cum + req.amt ≤ oac.amt ∧ seq + 1 ≤ oac.maxtx    else LIMIT
  tok ← {aid, seq + 1, prv, req.amt, cum + req.amt, pye: H(cert.dpk ‖ cert.acct), req.pnc, wall, req.ref}

  WAL.Append(RESERVED, tok); fsync                         # ① the state advance is durable first
  cose ← SecureHW.Sign1(K_off, tok, "bilyon/ost/v1")       # ② biometric prompt (amount + payee shown)
      on cancel or error: WAL.TruncateLast(); fsync; return CANCELLED   # nothing left the device
  WAL.UpdateLast(SIGNED, cose); fsync                      # ③ only now may the bytes leave the device
  send Packet[1, oac, cose]; await Receipt (3 s)
      receipt r: require Verify(r, cert.dpk) ∧ r.tid = tid(tok); mark DELIVERED or REJECTED (keep r)
      timeout:   entry stays SIGNED (in doubt), counted as spent; Retransmit(seq) resends identical bytes

Recover():                                                 # at every process start
  while WAL.Last().status = RESERVED: WAL.TruncateLast()   # unsigned ⇒ never transmitted ⇒ safe
```

**Lemma A1 (honest wallets never equivocate).** Each `seq` comes from the durable head. A token's bytes
are released only after its `SIGNED` record is durable. Only `RESERVED` records are ever removed, and
those were never transmitted. So every transmitted `seq` stays consumed forever: a crash before ① leaves
no trace, a crash between ① and ③ is rolled back with nothing sent, and after ③ the token is in the log. ∎
Consequently `cum(n) = Σ amt(1..n)` and every `prv` links, so no consistency check in §3.A.6 or §3.A.7
ever fires on an honest wallet. Tests: `TestCrashBetweenReserveAndSignRollsBack`,
`TestHonestFlowSettlesAndReleases`.

### Hardening against state rollback (Tier K)

| Vector | Control |
|---|---|
| Restore vault to another device | Vault is excluded from backups (`isExcludedFromBackup`, Android `dataExtractionRules`). `K_off` is `ThisDeviceOnly`, so a restored vault cannot sign |
| Same-device rollback (old vault file, local backup) | **iOS**: every committed WAL transition is paired with an App Attest assertion over `H(state)`, and its counter `c` is stored in the vault. At start-up a fresh assertion must return exactly `c + 1`, otherwise offline spending locks until the next online sync. **Android**: an epoch-key ratchet. Each committed state is signed with a single-use epoch key that is consumed as its successor is created. An old state references an already-consumed key |
| Both controls defeated | Forked tokens are equivocations. They are detected and attributed at the first sync of either branch, and exposure stays bounded by §3.A.2 |

## 3.A.5 The time floor

Expiry checks on an offline device cannot trust its clock. Each device keeps `floor`, the maximum of
its wall clock and every **server-signed** timestamp it has seen: `oac.iat`, `pcert.iat` and sync
responses. Allowances and certificates are issued continuously, so devices "gossip" signed time to each
other at every handshake. Consequences:

- Winding a clock **back** cannot resurrect an expired allowance once the device has seen any later
  signed timestamp (`TestPayeeTimeFloorRejectsExpiredAllowance`).
- Winding a clock **forward** only makes the device stricter.
- Residual risk is a payee that never sees a newer signed timestamp and also falsifies its clock. That
  payee still cannot extract more than the payer's reserve without a provable overspend, which requires
  payer fraud.

## 3.A.6 Payee verification (offline, ≤ 50 ms)

```text
Accept(packet, wall):
  [kind, oac_raw, item] ← StrictCBOR(packet)                          else MALFORMED
  oac ← Open1(oac_raw, "bilyon/oac/v1", TrustStore[kid])               else UNKNOWN_ISSUER | BAD_SIGNATURE
  TimeFloor.Observe(oac.iat); now ← TimeFloor.Now(wall)
  require oac.nbf ≤ now ≤ oac.exp                                      else NOT_YET_VALID | EXPIRED
  require oac.aid ∉ CRL                                                else REVOKED
  if kind = 2 ∧ oac.tier = S: return AcceptCoins(oac, item)            # §3.A.9
  tok ← Open1(item, "bilyon/ost/v1", oac.dpk) ∧ tok.aid = oac.aid      else BAD_SIGNATURE | MALFORMED
  t ← tid(tok)
  if Held[aid][tok.seq] exists:                                        # local double-spend radar
      if Held[aid][tok.seq].tid = t: return its stored receipt         # idempotent retransmission
      Evidence ← Evidence ∪ {(EQUIVOCATION, Held[aid][tok.seq], tok)}; return EQUIVOCATION
  require tok.pye = H(self.dpk ‖ self.acct)                            else WRONG_PAYEE
  req ← Pending[tok.pnc], require exists ∧ now ≤ req.expires (120 s)   else NONCE
  require req.cur = oac.cur                                            else CURRENCY
  require tok.amt = req.amt ∧ tok.ref = req.ref                        else AMOUNT_MISMATCH
  require 1 ≤ tok.amt ≤ oac.txmax ∧ 1 ≤ tok.seq ≤ oac.maxtx ∧ tok.cum ≤ oac.amt          else LIMIT
  require tok.cum ≥ tok.amt + (tok.seq − 1)                            else CHAIN   # ≥ 1 unit per earlier token
  if tok.seq = 1: require tok.prv = oac.anchor ∧ tok.cum = tok.amt     else CHAIN
  for h in Held[aid]: if ¬Consistent(order(h, tok)): record evidence;  return INCONSISTENT
  delete Pending[tok.pnc]; Held[aid][tok.seq] ← tok; Claims ← Claims ∪ {packet}
  return Sign1(K_dev(payee), {tid: t, status: OK, time: wall}, "bilyon/rcpt/v1")

Consistent(a, b):                     # same allowance and signer, a.seq < b.seq
  if b.seq = a.seq + 1: return b.prv = tid(a) ∧ b.cum = a.cum + b.amt
  return b.cum ≥ a.cum + b.amt + (b.seq − a.seq − 1)
```

Cost: two P-256 verifications (the OAC result is cached per `aid`), one receipt signature, and a few
SHA-256 calls. That is a few milliseconds on CPU plus one secure-hardware signature, well inside the 50 ms budget.
Order matters: the radar runs **before** the nonce check, so a retransmission after the nonce was consumed still
returns the original receipt. Phase 3 option: payee devices in one venue gossip `(aid, seq, tid)` over
BLE, which extends the radar from one merchant to the whole market.

## 3.A.7 Reconciliation (server, on sync)

Payee claims and payer log uploads go through the same idempotent entry point. Credit always goes to the
payee that the token's `pye` binding resolves to, so *who* uploads and *in what order* never changes
who gets paid.

```text
Submit(packet, receipt?):
  verify packet as §3.A.6, without the nonce and own-payee checks
  require tok.pye ∈ PayeeRegistry                          else WRONG_PAYEE (held for review)
  require now ≤ oac.exp + W_claim (14 d)                   else EXPIRED → manual dispute
  if receipt ∧ Verify(receipt, payee.dpk) ∧ receipt.tid = t ∧ receipt.status ≠ OK: Void[t] ← true
  if Void[t]:    return VOIDED                             # the payee itself signed a rejection
  if Settled[t]: return DUPLICATE                          # keyed on tid: immune to signature malleability
  B ← Book[aid]
  if B.tokens[seq] exists:             Flag(B, EQUIVOCATION, B.tokens[seq], tok)
  else: for h in B.tokens: if ¬Consistent(order(h, tok)): Flag(B, INCONSISTENT, h, tok)
        B.tokens[seq] ← tok
  if B.closing ∧ seq > B.closing.final_seq: Flag(B, INCONSISTENT, B.closing, tok)
  return Pay(B, payee, tok.amt, t)

Pay(B, payee, amt, ref):                                   # all-or-nothing
  r ← min(amt, B.cap − B.paid);  s ← amt − r               # an honest chain never needs s > 0
  if s > 0: Flag(B, OVERSPEND); require B.guaranteed + s ≤ GuaranteeCap   else LIMIT (manual dispute)
  Settled[ref] ← true
  if r > 0: Post(offline_reserve:aid → payee, r);  B.paid += r
  if s > 0: Post(offline_guarantee → payee, s);  Post(receivable:payer → offline_guarantee, s);  B.guaranteed += s
  return OK

Flag(B, kind, a, b): B.fraud ← true; CRL.Add(aid); Evidence.Store(kind, a, b); Risk.OpenCase(payer)

SubmitClosing(oac, closing):                               # payer's signed final statement, enables early release
  require Verify(closing, oac.dpk)
  for h in B.tokens: if h.seq > final_seq ∨ (h.seq = final_seq ∧ (tid(h) ≠ last_tid ∨ h.cum ≠ final_cum)): Flag(…)
  if ¬B.fraud: Post(offline_reserve:aid → payer, A − final_cum);  B.cap ← final_cum

Expire(): at oac.exp + W_claim, Post(offline_reserve:aid → (B.fraud ? offline_guarantee : payer), B.cap − B.paid)
```

| Property | Statement | Test |
|---|---|---|
| P1 Good-faith payees are paid | Reserve first; the guarantee covers the shortfall up to the cap and within the claim window | `TestForkFromStateRollbackIsDetectedAndGuaranteed` |
| P2 Order independence | Every upload order yields the same payee credits. Only the reserve/guarantee split depends on arrival order | Payer log resubmission in `TestHonestFlowSettlesAndReleases` |
| P3 No double payment | `Settled` is keyed on the payload hash; high-S signatures are rejected | `TestHighSSignatureAndTamperingRejected` |
| P4 The overspender cannot escape | Every overspend leaves a signed proof plus a receivable and revocation, including after a truncated closing | `TestClosingReleasesEarlyAndExposesLaterTokens` |
| P5 Honest payers are never flagged | Lemma A1 | `TestCrashBetweenReserveAndSignRollsBack` |
| P6 Rejections cannot be claimed | A payee-signed rejection voids the token, even if the payee later claims it | `TestRejectedTokenIsVoidedNotPaid` |

Guarantee eligibility: the payee device must have synced (CRL and trust store) within 72 h before the
claim, and payouts to accounts that the risk graph links to the payer are escrowed during investigation.
This blocks a fraudster forking to their own merchant accounts.

## 3.A.8 Result codes

| Code | Name | Raised by | Payee UI | Payer UI / action |
|---:|---|---|---|---|
| 0 | `OK` | payee, server | ✓ paid | ✓ delivered |
| 1 | `MALFORMED` | both | Reject | Update app |
| 2 | `UNKNOWN_ISSUER` | both | Reject; "sync to refresh trust" | n/a |
| 3 | `BAD_SIGNATURE` | both | Reject | n/a |
| 4 | `EXPIRED` | both | Reject | Go online to refresh the allowance |
| 5 | `NOT_YET_VALID` | payee | Reject; check device clock | n/a |
| 6 | `REVOKED` | payee | Reject | Contact support |
| 7 | `WRONG_PAYEE` | both | Reject (token for someone else) | n/a |
| 8 | `NONCE` | payee | New request | Token voided at sync (payee receipt) |
| 9 | `AMOUNT_MISMATCH` | payee | Reject | Voided at sync |
| 10 | `LIMIT` | both | Reject | Show remaining offline balance |
| 11 | `CHAIN` | both | Reject, keep evidence | n/a |
| 12 | `EQUIVOCATION` | both | **Fraud alert: do not hand over goods** | Account locked |
| 13 | `INCONSISTENT` | both | **Fraud alert** | Account locked |
| 14 | `CURRENCY` | both | Reject | n/a |
| 15 | `DUPLICATE` | server | n/a (idempotent) | n/a |
| 16 | `VOIDED` | server | Claim refused (you rejected it) | Amount refunded |

## 3.A.9 Tier S: single-use coin keys

**Minting (online).** The device generates `N ≤ 64` keys with `setMaxUsageCount(1)`, each with its own
attestation. Denominations follow the user's spending profile. The default is binary-like with
repeats, e.g. cents `1, 2, 4, …, 4096` plus duplicates of the most-used rungs. The server verifies that
every attestation lists the limit as hardware-enforced, rebuilds the Merkle tree (leaves padded to a
power of two with labelled pad hashes) and issues an OAC with `croot` and `amt = Σ den`.

**Coin selection (payer).** Pay exactly, with the fewest coins (smaller packets):

```text
SelectCoins(coins, a):                           # 0/1 subset-sum DP, O(N·a): N ≤ 64, a ≤ 50 000 → ≤ 3.2 M steps
  avail ← [c ∈ coins : ¬c.spent ∧ c.den ≤ a]
  best[0] ← 0; best[1..a] ← ∞
  for i, c in avail:
    for x ← a down to c.den:
      if best[x − c.den] + 1 < best[x]: best[x] ← best[x − c.den] + 1; take[i][x] ← true
  if best[a] = ∞: return NO_EXACT_COMBINATION    # UI: adjust amount, or pay the remainder from a Tier K allowance
  x ← a; for i ← |avail|−1 down to 0: if take[i][x]: pick avail[i]; x ← x − avail[i].den
```

The 2-D `take` table makes reconstruction correct for 0/1 items (a 1-D parent array would reuse items).
**Spend:** mark the selected coins spent (durable), then sign one `CoinSpend` per coin, all bound to the
same `pye` and `pnc`. Even if the bookkeeping were lost, the TEE refuses a second signature
(`ErrKeyExhausted` in the reference). **Payee:** for each coin, verify `idx < maxtx`, the Merkle proof
to `croot`, and the signature under `cpk`. Then check that the nonce is shared, the indices are distinct,
`Σ den = amount ≤ txmax`, and the radar has not seen `(aid, idx)`. **Server:** deduplicate on
`(aid, idx)` and the spend ID. A *second, different* spend of one index proves a TEE compromise. It is
paid like a Tier K overspend and escalated per device model and patch level (attestation policy may
drop that model from Tier S).

## 3.A.10 Edge cases and sync conflicts

| Situation | Protocol behaviour |
|---|---|
| Receipt lost (radio drop after the payee stored the token) | Payer entry stays `SIGNED` (in doubt) and is counted as spent. Retransmission is byte-identical and the payee returns the same receipt. If the payee is gone, the server decides at sync; the UI shows "awaiting confirmation" |
| Payer's phone dies or is lost after paying | Payees still claim: credit follows `pye`, and the payer's log is not needed |
| Payee never syncs | Reminders at exp − 24 h and exp + 7 d. After `exp + W_claim` the reserve is released to the payer and late claims go to manual dispute with the signed token as evidence |
| Payer and payee both upload, in either order | `Settled` deduplicates. P2 guarantees the same outcome |
| Payee uploads a token it rejected | `VOIDED` when the payer attached the payee-signed rejection. If the claim settled before the payer synced, the later rejection upload reverses the credit with a dispute entry (specified here, not modelled in the reference) |
| Clock skew or tampering | Payer clock is irrelevant (advisory `ts`). Payee clock is bounded below by the time floor (§3.A.5) |
| Stale CRL at the payee | The reserve still pays. Guarantee eligibility requires a sync within 72 h (§3.A.7) |
| Allowance expires mid-handshake | Payer refuses before signing (`EXPIRED`). If the payee's floor crosses `exp` between steps, the payee rejects and the payer voids at sync |
| App killed between sign and send | Lemma A1: `RESERVED` is rolled back, `SIGNED` stays in doubt; the user sees "check with the merchant" |
| Biometric cancelled | `RESERVED` entry truncated; no token exists |
| Same token shown to two payees | Bound by `pye` and `pnc`, so only the bound payee can redeem it (`TestReplayToOtherPayeeAndRetransmit`) |
| Payer forks the chain | Radar catches it at one payee immediately, the server catches it across payees at the first sync of each branch (`TestPayeeRadarCatchesEquivocationAndInconsistency`) |
