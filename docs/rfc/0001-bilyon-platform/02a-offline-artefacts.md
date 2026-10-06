# §2.1 Offline Artefacts: Encoding, Schemas, Handshake

[← RFC index](README.md) · Algorithm: [§3.A](03a-algorithm-offline.md) · Code: [`reference/offline`](../../../reference/offline)

## 2.1.1 Encoding conventions (normative)

1. **CBOR, deterministic.** All payloads use CBOR (RFC 8949) with Core Deterministic Encoding
   (§4.2.1): shortest-form integers and lengths, definite lengths only, map keys sorted by the bytewise
   order of their encodings, no duplicate keys, no floats. Verifiers **MUST reject** any input that is
   not the unique deterministic encoding of its value. This removes parser differentials between the
   Swift, Kotlin, Rust and Go implementations. `reference/internal/cbor` rejects ten classes of
   non-canonical input.
2. **Closed schemas.** v1 payloads have a fixed key set. An unknown key, a missing key or a wrong type
   or size is `MALFORMED`. Schemas evolve by bumping key `1` (version), never by adding optional
   fields that old verifiers would ignore.
3. **COSE_Sign1** (RFC 9052, tag 18), algorithm **ES256 only**. The protected header is exactly
   `{1: -7}` (bytes `A1 01 26`), and verifiers compare these bytes instead of parsing them, which rules out
   algorithm confusion. The unprotected header may contain only `kid` (label 4). Signatures are raw
   `r‖s` (64 B) normalised to **low-S**, and verifiers reject `s > n/2`.
4. **Domain separation.** Every artefact type is signed with its own COSE `external_aad`:
   `bilyon/oac/v1`, `bilyon/pcert/v1`, `bilyon/preq/v1`, `bilyon/ost/v1`, `bilyon/rcpt/v1`,
   `bilyon/close/v1`, `bilyon/coin/v1`. A signature made for one type cannot verify as another, and no
   artefact can be confused with a WebAuthn assertion.
5. **Tagged hashes.** `H(label, data…) = SHA-256(label ‖ 0x00 ‖ data…)`:

   | Name | Definition | Purpose |
   |---|---|---|
   | `tid` | `H("bilyon/tid/v1", ost-payload)` | Token ID. **Excludes the signature**, so ECDSA malleability cannot create a second ID for one token |
   | `anchor` | `H("bilyon/anchor/v1", aid)` | `prv` of the first token in a chain |
   | `pye` | `H("bilyon/payee/v1", payee_dpk ‖ payee_acct)` | Binds a token to exactly one payee device and account |
   | coin leaf / node | `H("bilyon/coin-leaf/v1", idx ‖ den ‖ cpk)`, `H("bilyon/coin-node/v1", l ‖ r)` | Tier S Merkle tree (distinct leaf/node labels block second-preimage tricks) |

6. **Money** is an unsigned integer count of ISO 4217 minor units plus an alpha-3 code, never a
   float. **Time** is unsigned epoch seconds. Device clocks are advisory, and validity decisions use the
   *time floor* (§3.A.5).

## 2.1.2 Schemas (CDDL, RFC 8610)

```cddl
; ---------- common ----------
id16       = bstr .size 16            ; UUIDv7 / nonce / account pseudonym
h32        = bstr .size 32            ; SHA-256 output
p256       = bstr .size 33            ; SEC1 compressed P-256 point
minor      = uint                     ; amount in currency minor units
epoch      = uint                     ; seconds since 1970-01-01T00:00:00Z
currency   = tstr .size 3             ; ISO 4217 alpha-3
tier       = 1 / 2 / 3                ; 1 = key-bound (K), 2 = single-use coins (S), 3 = secure element (H)

COSE_Sign1<P> = #6.18([
  protected:   bstr .cbor { 1: -7 },  ; ES256, byte-exact A1 01 26
  unprotected: { ? 4: bstr },         ; kid: present on issuer-signed artefacts only
  payload:     bstr .cbor P,
  signature:   bstr .size 64          ; r || s with s <= n/2
])

; ---------- issuer-signed (HSM, K_iss) ----------
OAC = COSE_Sign1<oac>                 ; external_aad "bilyon/oac/v1"
oac = {
  1  => 1,                            ; version
  2  => id16,                         ; aid: allowance id
  3  => p256,                         ; dpk: K_off(aid) (Tier K) or receipt key (Tier S)
  4  => currency,
  5  => minor,                        ; amt: escrowed in reserve account offline:reserve:<aid>
  6  => minor,                        ; txmax: max per payment
  7  => epoch,                        ; nbf
  8  => epoch,                        ; exp
  9  => tier,
  10 => h32,                          ; anchor = H("bilyon/anchor/v1", aid)
  11 => uint,                         ; maxtx: max tokens (K) / number of coins (S)
  12 => id16,                         ; acct: payer account pseudonym, fresh per allowance
  13 => epoch,                        ; iat: doubles as a signed time beacon
  14 => uint,                         ; crl: revocation-list epoch at issuance
  ? 15 => h32,                        ; croot: Merkle root over coin leaves (Tier S only)
}

PayeeCert = COSE_Sign1<pcert>         ; "bilyon/pcert/v1"
pcert = {
  1 => 1,
  2 => id16,                          ; acct: payee account pseudonym
  3 => p256,                          ; payee device key (K_dev of the payee)
  4 => tstr .size (0..64),            ; verified display name shown to the payer
  5 => uint,                          ; merchant category code, 0 = individual
  6 => epoch,                         ; iat
  7 => epoch,                         ; exp
}

; ---------- payee-signed (payee K_dev) ----------
PaymentRequest = COSE_Sign1<preq>     ; "bilyon/preq/v1"
preq = {
  1 => 1,
  2 => id16,                          ; pnc: single-use nonce, valid 120 s
  3 => minor,                         ; amount
  4 => currency,
  5 => bstr .size (0..32),            ; ref: invoice / order reference
  6 => epoch,                         ; payee time (advisory)
}

Receipt = COSE_Sign1<rcpt>            ; "bilyon/rcpt/v1"
rcpt = {
  1 => 1,
  2 => h32,                           ; tid (Tier K) or coin-payment id (Tier S)
  3 => uint,                          ; status code, §3.A.8 (0 = accepted)
  4 => epoch,                         ; payee time
}

; ---------- payer-signed ----------
OST = COSE_Sign1<ost>                 ; "bilyon/ost/v1", signed by K_off(aid)
ost = {
  1  => 1,
  2  => id16,                         ; aid
  3  => uint,                         ; seq: 1..maxtx, exactly previous + 1
  4  => h32,                          ; prv: tid of seq-1, or anchor when seq = 1
  5  => minor,                        ; amt: 1..txmax
  6  => minor,                        ; cum: total spent including this token, <= OAC.amt
  7  => h32,                          ; pye: payee binding
  8  => id16,                         ; pnc: copied from the PaymentRequest
  9  => epoch,                        ; ts: payer clock (advisory)
  10 => bstr .size (0..32),           ; ref: copied from the PaymentRequest
}

Closing = COSE_Sign1<closing>         ; "bilyon/close/v1", signed by K_off(aid)
closing = { 1 => 1, 2 => id16, 3 => uint, 4 => minor, 5 => h32 }  ; aid, final seq, final cum, last tid

CoinSpend = COSE_Sign1<coin>          ; "bilyon/coin/v1", signed by the coin's single-use key
coin = {
  1 => 1,
  2 => id16,                          ; aid
  3 => uint,                          ; idx < OAC.maxtx
  4 => minor,                         ; denomination
  5 => p256,                          ; coin public key (authenticated by the Merkle proof)
  6 => [0*6 h32],                     ; proof, leaf to root (tree depth <= 6, <= 64 coins)
  7 => h32,                           ; pye
  8 => id16,                          ; pnc (identical across the coins of one payment)
  9 => epoch,
}

; ---------- wire packet, payer -> payee ----------
Packet = [1, bstr .cbor OAC, bstr .cbor OST]
       / [2, bstr .cbor OAC, [+ bstr .cbor CoinSpend]]
```

## 2.1.3 Sizes and transports

Measured by `TestWireSizes` with real P-256 signatures:

| Artefact | Bytes | | Artefact | Bytes |
|---|---:|---|---|---:|
| OAC (Tier K) | 236 | | OST | 221 |
| PayeeCert | 174 | | **Packet (Tier K)** | **463** |
| PaymentRequest | 132 | | Receipt | 121 |
| OAC (Tier S) | 271 | | Packet, one coin (Tier S) | 682 (~410 B per extra coin) |

| Transport | Capacity | Tier K packet |
|---|---|---|
| BLE 5 L2CAP CoC (`CBL2CAPChannel`, `createL2capChannel`) | SDU up to 64 KiB | One SDU, ~10 ms |
| BLE GATT fallback | ATT MTU ≤ 517 B | One long write |
| NFC ISO-DEP (Android HCE ↔ reader; iPhone reads Android HCE via `NFCTagReaderSession`) | Extended APDU ≤ 65 535 B | One APDU (short APDUs: 2 chained) |
| QR code | v15-L carries 520 B | Fits; the merchant can also show `PayeeCert+PaymentRequest` (306 B) as a QR |

Confidentiality on the P2P link: everything is signed, so the transport needs no integrity of its own.
Amounts and pseudonyms are still private. The payer derives `k = HKDF-SHA256(ECDH(e_payer, payee_dpk),
"bilyon/p2p/v1" ‖ pnc)` from an ephemeral key and the payee key in the (verified) PayeeCert, and
protects the Packet and Receipt with AES-128-GCM. No pairing, no PIN, no network.

## 2.1.4 Offline handshake

```text
Payee (merchant or friend)                                   Payer
  │ discovery: BLE EID advert · NFC field · QR on screen     │
  │── PayeeCert + PaymentRequest{pnc, amt, cur, ref} ────────▶│
  │                                                          │ verify PayeeCert (issuer kid), request signature,
  │                                                          │ expiry against the time floor; check UWB range < 1 m
  │                                                          │ show "Pay Corner Cafe · 12.50 EUR" (verified name)
  │                                                          │ biometric → K_off signs OST   (WAL: reserve→sign→commit)
  │◀──────────────────────────── Packet [1, OAC, OST] ───────│
  │ Algorithm A.4 (≤ 50 ms, no network)                      │
  │── Receipt{tid, status} ─────────────────────────────────▶│
  │                                                          │ verify receipt → DELIVERED
  │                                                          │ (no receipt → IN-DOUBT → retransmit identical bytes)
```

Relay resistance: everything the payer approves (payee name, amount, nonce) is signed by a certified
payee key, so a relay can forward messages but cannot change them. Where UWB secure ranging (802.15.4z
STS) is available, the payer additionally requires a measured distance < 1 m before showing the sheet.
This blocks "pay a distant merchant" relay attacks on unattended terminals.

## 2.1.5 Test vectors

The reference tests generate artefacts with fresh keys. Before Phase 3, freeze vectors into
`reference/testdata/` (fixed keys, payloads, expected bytes, plus the ten non-canonical rejections) so
that the Swift, Kotlin and Rust implementations are validated byte for byte in CI.
