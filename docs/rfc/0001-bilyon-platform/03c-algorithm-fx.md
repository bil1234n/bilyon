# §3.C Algorithm C: Multi-Currency Liquidity Routing and Exchange-Rate Lock

[← RFC index](README.md) · Code: [`reference/fx`](../../../reference/fx)

## 3.C.0 Where the low fees come from

1. **Internal netting at mid.** Customer flows in opposite directions (EUR→USD against USD→EUR) are matched
   internally at the mid-market rate, with no external spread.
2. **Aggregated hedging.** Only the *net* residual position reaches liquidity providers, in institutional
   size and at institutional spreads.
3. **Direct rails.** ISO 20022 instant schemes and local rails. Stablecoin L2 rails only where correspondent
   banking is the expensive part of a corridor.
4. **Transparent pricing.** Mid-market rate plus a disclosed lock buffer and margin. No hidden spread.

Result for majors: **≤ 10 bp all-in** (the quote test below lands at 9.6 bp).

## 3.C.1 Model

The liquidity graph `G = (V, E)` has currencies as vertices (ISO 4217 plus normalised stablecoins) and venues
as edges: the netting book, LP streams, stablecoin on/off-ramps, and rails. Edge `e` carries:

| Field | Meaning |
|---|---|
| ladder `[(s₁, r₁), (s₂, r₂), …]`, `r₁ ≥ r₂ ≥ …` | Executable depth: `s_k` minor units of the source at rate `r_k` (decimal string, parsed exactly) |
| `f_e`, `φ_e` | Fixed fee (source minor units) and proportional fee (ppm) |
| `τ_e` | Settlement latency, used for the SLA filter |
| `enabled` | Compliance or corridor switch (sanctions, licensing, venue halt, stale stream) |
| `c_e` | Depth already consumed by executions and overbooked reservations |

The execution function fills the ladder from offset `c_e` after the fixed fee and applies exponents and fees:

```text
out_e(x) = 10^(exp_to − exp_from) · (1 − φ_e) · Σ_k r_k · |[0, x − f_e] ∩ [S_{k−1} − c_e, S_k − c_e]|      S_k = s₁+…+s_k
         = infeasible if x − f_e > S_last − c_e
```

`out_e` is non-decreasing, and concave once `x > f_e` because rates only worsen deeper in the book. A
route's output is the composition `out_R = out_{e_n} ∘ … ∘ out_{e_1}`, which is again non-decreasing and
(past fixed fees) concave.

## 3.C.2 Router: hop-bounded max-output dynamic programme

```text
BestRoute(src, dst, x, H = 3, SLA):
  frontier ← {src: (amt = x, route = [])};  best ← none
  for h in 1..H:
    next ← {}
    for (u, (amt, route)) in frontier, for e in out_edges(u):
      if e.to = src ∨ e.to ∈ nodes(route) ∨ ¬e.enabled ∨ latency(route + e) > SLA: continue
      y ← out_e(amt); if infeasible: continue
      if y > next[e.to].amt: next[e.to] ← (y, route + e)
    if next[dst].amt > best.amt: best ← next[dst]
    frontier ← next \ {dst}                       # never route *through* the destination
  return best
```

**Why it is correct.** Every leg is non-decreasing, so the largest amount that reaches a currency in `h` hops
dominates every smaller amount for any continuation. Keeping one label per (hop count, currency) therefore
loses nothing (principle of optimality). The cost is `O(H·|E|)` leg evaluations, about 10⁴ for 150 currencies
with 20 venues each, which fits the 30 ms quote budget. Exactness needs three conditions:

1. Legs on one path do not share liquidity. That holds unless the same venue appears twice, which simple
   paths of three hops or fewer do not do in practice.
2. The graph is arbitrage-free. A Bellman–Ford negative-cycle check (`w = −ln r₁`) runs on every LP update,
   and cycles are quarantined and sent to the treasury desk. Simple paths cannot loop through them anyway.
3. Hops ≤ 3.

Under these conditions the DP equals exhaustive search. `TestDPMatchesBruteForce` checks this on 300 random
arbitrage-free graphs, and a mutation that keeps the first label instead of the best one fails it.

**Why not log-weight shortest path?** `−ln r` turns rates into additive weights, but only for the top of book.
Fixed fees and depth make the cost of a leg depend on the amount flowing through it. Log weights are still
useful as a fast pre-filter on very large graphs.

Examples from `TestMultiHopAndLatencySLA`. EUR→NGN goes **netting → Lagos LP** (two hops), which beats
the direct pair's 1 % spread. With the Lagos LP halted it goes **netting → USDC on-ramp → off-ramp**. With a
3 s SLA the 7 s stablecoin path is excluded and the router falls back to the direct pair. Amounts beyond the
available depth are unroutable.

## 3.C.3 Split routing (water-filling)

```text
SplitRoute(src, dst, X, K = 3, N = 20):
  routes ← []                                     # edge-disjoint candidates
  repeat K times: r ← BestRoute(src, dst, X/K); routes += r; hide edges(r)
  alloc[·] ← 0
  for each of N chunks Δ (remainder folded into the last):
    i* ← argmax_i [out_i(alloc_i + Δ) − out_i(alloc_i)]       # largest marginal output
    alloc_i* += Δ
  split ← Σ_i out_exact_i(alloc_i)
  single ← out_exact(BestRoute(src, dst, X))      # guards the fixed-fee non-concavity
  return the better of split and single
```

For concave route outputs the optimum equalises marginal rates: every used route has `∂out_i/∂x = λ`, and
every unused route has a marginal rate ≤ λ (KKT). Greedy allocation of marginal chunks reaches that point up
to one chunk of granularity. Example (`TestSplitBeatsSingleRoute`): 80 000 EUR→USD with 50 000 of netting at
1.0850 and an LP at 1.0847. The split is 48 000 netting + 32 000 LP, within 1·10⁻⁴ of the exact 50k/30k
optimum and better than the LP alone.

## 3.C.4 Quote and rate-lock pricing

```text
buffer_bp = z · σ_pair · sqrt(TTL / 31 536 000) · 10⁴ + jump_bp          z = 2.33 (99 %)
keep_ppm  = ⌊10⁶ · (1 − (buffer_bp + margin_bp) / 10⁴)⌋
AmountOut = ⌊ execOut · keep_ppm / 10⁶ ⌋                                 exact integer arithmetic
```

| Pair | σ | TTL | Buffer |
|---|---|---|---|
| EUR/USD | 7 % | 30 s | **1.59 bp** |
| EUR/USD | 7 % | 24 h | 85.2 bp. Long locks are priced as forwards or options, not with this buffer |
| USD/NGN | 35 % + 15 bp jump | 30 s | 7.95 + 15 = 22.95 bp |

**Worked quote (`TestQuoteLifecycle`).** 10 000.00 EUR → USD over netting at mid gives execOut = 10 850.00. The
buffer is 1.59 bp and the margin 8 bp, so keep = 999 040 ppm. **AmountOut = 10 839.58 USD**, and the all-in
cost against mid is **9.6 bp**. The quote screen shows the mid rate, the customer's rate and the fee in both bp
and currency.

**Free-option leakage.** A customer may let a quote lapse when the market moves in their favour. That option is
worth about `0.4·σ·√TTL` ≈ 0.27 bp for EUR/USD at 30 s, which the buffer already covers. Abuse ("quote
sniping") is controlled by single-use quotes bound to the user. A user whose quote-to-trade ratio exceeds 20
gets shorter TTLs and larger buffers.

Each quote is HMAC-signed over `id|from|to|amount_in|amount_out|expires_ms` with `K_quote`. The client
presents the ID and signature at execution, and the quote ID doubles as the execution idempotency key.

## 3.C.5 Liquidity reservation (overbooking)

Issuing a quote soft-reserves each leg: `c_e += x_e / ρ`. The overbooking factor `ρ` comes from the observed
quote-to-trade ratio (default 1.5). Reservations are released on execution or expiry. This stops two
concurrent quotes from promising the same netting liquidity while not locking depth for quotes that will
never be accepted. In `TestReservationsPreventOverpromising`, two concurrent 60 000 EUR quotes come back
different: the second sees only the netting depth left after the first one's reservation.

## 3.C.6 Execution and the extreme-move breaker

```text
Execute(id, sig):
  require HMAC(sig) valid                          else TAMPERED
  if already executed: return the stored execution  # idempotent
  if now > expires: release; return EXPIRED        # client requotes
  release reservation; (alloc, marketOut) ← SplitRoute(now)
  if marketOut < AmountOut · (1 − 150 bp): return REQUOTE      # documented breaker: gaps, venue halts
  consume depth; ledger LinkedTransfers(customer debit, fx_book legs, customer credit)
  PnL ← marketOut − AmountOut                      # to treasury attribution
```

The quote is **firm**. A 50 bp adverse move inside the TTL is honoured at a loss to the platform. A 3 % gap
trips the breaker, which is disclosed in the terms (`TestFirmQuoteAndBreaker`).

## 3.C.7 Netting, hedging, treasury

- The netting edge's depth is the opposite-flow inventory the treasury may hold within its per-currency
  position limits `L_c`. Executions change positions: `P_from += in`, `P_to −= out`.
- The hedger runs continuously. When `|P_c · mid_c| > L_c`, it brings the position back into
  `[−L_c/2, L_c/2]` with TWAP slices across LPs. Two-sided flows keep the residual small.
- End of day: positions are reconciled against nostro balances, and P&L is attributed to spread, buffer and
  hedging slippage. The buffer model is recalibrated weekly from realised moves over the lock window.

## 3.C.8 Settlement rails

| Rail | Messages / mechanics | Graph edge properties |
|---|---|---|
| SEPA Instant, FedNow, PIX, UK Faster Payments | ISO 20022: `pacs.008` out, `pacs.002` status, `pacs.004` returns, `camt.056` recalls, `camt.054` notifications, `camt.053` statements. Verification of Payee where mandated (EU Instant Payments Regulation) | Seconds; 24×7; per-transaction limits |
| Cross-border correspondent (SWIFT CBPR+) | ISO 20022 MX since the MT coexistence period ended (Nov 2025) | Hours to days; cut-offs. Used where nothing else exists |
| Stablecoin on an L2 | Mint/redeem or exchange on/off-ramp; transfer to the corridor partner; IVMS101 Travel Rule payloads; chain-analytics screening. Credited on partner attestation after L2 inclusion, with L1 finality as a reconciliation milestone | Seconds to minutes; 24×7; ramp fees |

## 3.C.9 Precision and rounding (normative)

- The search runs in `float64`, which only ranks routes. Settlement amounts are recomputed in exact rationals,
  floored **once per leg** (a venue never delivers fractional minor units), and the customer amount is floored
  once. Sub-unit residue goes to a fee account, so entries stay balanced (I1).
- Exponent differences are exact. 0.01 USD at 149.45 → 1 JPY (floor), and 100.00 USD → 14 945 JPY
  (`TestNettingFirstAndExactAmounts`).
- Quote amounts are deterministic across replicas, which makes audit replay possible.

## 3.C.10 Failure handling

| Failure | Handling |
|---|---|
| LP stream stale (> 2 s without an update) | Edge disabled for new quotes. Open quotes are re-checked at execution (breaker) |
| Corridor halted (sanctions, licence, partner outage) | Edge disabled. The router uses an alternative or reports the corridor unavailable |
| Partial LP fill at execution | The remainder is routed again at once. The customer amount does not change (the platform absorbs the difference) |
| Rail rejects after FX executed (`pacs.002 RJCT`) | Funds wait in destination-currency suspense and an alternative rail is retried automatically. A refund reverses the FX at the current rate, and the platform covers any loss, so the customer is made whole in the source currency |
| Duplicate execute calls | Idempotent per quote ID |
| Client clock wrong | Expiry uses server time only. Clients display a countdown derived from server time (§4.4 clock sync) |
