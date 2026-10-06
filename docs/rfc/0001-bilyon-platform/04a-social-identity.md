# §4.1–4.3 Social Identity Mapping, Self-Destructing Links, Mini-App SDK

[← RFC index](README.md) · Realtime engine: [§4.4](04b-realtime-sync.md)

## 4.1 Handles as payment addresses

### 4.1.1 Identity model

| Namespace | Example | Source of truth | Mutable? |
|---|---|---|---|
| Bilyon handle | `@alice` | Bilyon (`handles`) | Rate-limited: 1 change per 30 days; the old handle is quarantined for 90 days |
| Linked social identity | `x:2244994945` displayed as `@alice` | Provider's **stable user ID**, proven by OAuth 2.0 / OIDC with PKCE | The display handle is mutable and re-validated; the stable UID never changes |
| Phone / e-mail | `+44…` | Used only for contact discovery (OPRF, §4.1.4) | n/a |

**Normalisation.** Handles are NFKC-normalised, case-folded and stripped of default-ignorable code points.
Uniqueness is enforced on the **UTS #39 confusable skeleton**, so `@аlice` (Cyrillic `а`) collides with
`@alice`. Brand and reserved names are held back.

**Recycling defence.** Social platforms recycle usernames. We store the immutable provider UID and only
*display* the @name. A job re-validates active links every 24 h, and resolution re-validates any link
older than 24 h. If the provider maps the @name to a different UID, the alias is suspended and the owner
notified. A payment to `x:@alice` can therefore never follow the name to a new owner.

### 4.1.2 Payment Address Record (PAR)

Resolution returns a PAR, a COSE_Sign1 signed by `K_dir` (the JSON view is shown here):

```json
{
  "v": 1,
  "subject": "bil_01J9Z7Q3M6R8T2XK4N5P",
  "display": { "handle": "@alice", "name": "Alice M.", "avatar_sha256": "9f2c…", "verified": ["kyc", "x"] },
  "aliases": [ { "provider": "x", "uid": "2244994945", "handle": "@alice", "checked_at": 1791273600 } ],
  "receive": { "currencies": ["EUR", "USD"], "default": "EUR" },
  "keys": [ { "kid": "k7", "use": "p2p-binding", "pub": "A1b2…(33 B)" },
            { "kid": "k8", "use": "memo-encryption", "pub": "A9c4…(33 B)" } ],
  "version": 7,
  "tlog": { "tree_size": 918273645, "leaf_index": 772001, "inclusion": ["…"], "sth": "<COSE_Sign1 K_dir {root, size, ts}>" },
  "iat": 1791273600, "exp": 1791274200
}
```

`subject` is an opaque, stable payee reference: never a bank account number, and only meaningful to
Bilyon. `keys` let a payer verify the payee's device certificate during offline and P2P handshakes and
encrypt payment memos end to end.

### 4.1.3 Key transparency

The directory is an append-only verifiable map in the style of CONIKS, WhatsApp's Auditable Key Directory,
and the IETF KEYTRANS work. Every version of `subject → {aliases, keys}` is committed to a Merkle tree, and a
signed tree head (STH) is published every 10 minutes.

- **Clients** verify the inclusion proof that comes with every PAR and gossip STHs. They check consistency
  proofs between the STHs they have seen, which exposes a server showing different trees to different users.
- **Owners' devices self-audit.** They fetch their own entry on every STH. A key or alias change the user did
  not make raises an alert and freezes the account.
- **External auditors** verify append-only consistency.

Threat addressed: a compromised directory that silently pointed `@alice` at an attacker's keys or account
would have to publish that change in the log, where Alice's own devices see it.

### 4.1.4 Paying a handle

```text
1. Resolve(@alice) → PAR (cached ≤ 10 min, pinned by version); verify the K_dir signature and inclusion proof
2. Show the verified name, avatar and badges, plus warnings: first payment to this payee; handle skeleton
   collides with an existing contact (homoglyph); new account (< 7 days)
3. TxAuth{intent, amount, currency, payee_ref = H(subject), par_version}       (§2.2.5)
4. Server re-resolves at execution. A different version → reject PAYEE_CHANGED (TOCTOU guard)
```

**Privacy and abuse controls.** Lookups require authentication and are rate-limited (60 per minute and
1 000 per day per account and per device), with enumeration anomaly detection. Contact discovery uses a
**rate-limited OPRF**: the client blinds `H(phone)`, the server evaluates its secret key on the blinded value,
and the client unblinds and queries its bucket. The server never sees raw numbers, and offline brute force
is impossible without the OPRF key. Non-contacts see only the handle and avatar unless the owner opts in.

## 4.2 Self-destructing payment links ("drop and catch" by URL)

```text
https://bilyon.example/l/{link_id}#k={secret}
        link_id: 96-bit random, base62        secret: 128-bit random, base64url, in the URL FRAGMENT
```

Browsers never send the fragment in HTTP requests, and link-preview crawlers fetch the URL without it. So
neither servers' access logs nor social-platform unfurlers ever see the secret.

| Step | Mechanics |
|---|---|
| Create | Sender signs a TxAuth (`gesture = link`). The server places a hold (`link_escrow`) and stores `verifier = HMAC(pepper, secret)` with the terms: amount, currency, expiry (default 72 h, max 30 d), `max_claims` (1 by default; `n` for "first n friends" red packets, amounts pre-split with largest remainder), optional `restrict_to` subject, message |
| Preview | `GET /l/{id}` returns Open Graph tags ("Alice sent you a gift"). The amount is hidden unless the sender opts in. **GET never changes state** |
| Claim | Universal link / App Link opens the app; otherwise a web claim with passkey sign-up. `POST /v1/links/{id}/claim {secret}` → constant-time verifier check → the atomic update below plus the hold posting, in one transaction |
| Self-destruct | 0 rows updated → `410 Gone` (claimed, expired or revoked). After a claim the secret is worthless |
| Expire / revoke | The sweeper (or the sender) voids the hold. Funds return and the sender is notified |

```sql
UPDATE payment_links
   SET claims = claims + 1, claimed_by = $claimant,
       state  = CASE WHEN claims + 1 >= max_claims THEN 'claimed' ELSE 'active' END
 WHERE link_id = $id AND state = 'active' AND expires_at > now()
   AND (restrict_to IS NULL OR restrict_to = $claimant)
RETURNING amount_minor, hold_id;
```

A link is a **bearer instrument**: whoever holds the full URL can claim it, like cash in an envelope. The
defaults reflect that. Unrestricted links are capped at 250.00, larger amounts require `restrict_to`, and
claim attempts are limited to 5 per minute per link and per IP. Fragments are never logged (client-only).
A claim plays the catch animation on the claimant's phone, and the sender sees "caught by @bob".

## 4.3 Mini-App SDK and livestream integration

### 4.3.1 Trust model

The host app (a social network, a livestream app) is **untrusted** with credentials and amounts. The SDK
(`BilyonKit` Swift package, `bilyon-android` AAR, `bilyon.js`) always runs confirmation in a
**Bilyon-owned surface**:

1. **Bilyon app installed:** app switch through the universal link `https://pay.bilyon.example/c/{client_secret}`.
   The user confirms in the Bilyon app, and control returns to the host's registered link with a signed result.
2. **Not installed:** `ASWebAuthenticationSession` (iOS) or Custom Tabs (Android) to `pay.bilyon.example`.
   These run in a separate browser context the host cannot script, with passkeys inside, and SPC on Chromium.
3. **Never** a host-controlled `WKWebView` / `WebView` for credentials. The SDK refuses to run there.

Gesture *capture* (flick, shake) may run inside the host process when the host enables the optional sensor
module and declares the motion, Nearby Interaction and Bluetooth usage strings. *Authorisation* still always
happens in a Bilyon surface, because `K_dev` / `K_gest` live in the Bilyon app's keychain access group, which
no host can reach.

### 4.3.2 Payment flow

```text
Host backend ── POST /v1/intents {amount, currency, payee, metadata, idempotency_key}  (API key) ─▶ Bilyon
Host backend ◀─ {intent_id, client_secret (single use, 15 min)}
Host app ─────── BilyonKit.present(client_secret) ─▶ Bilyon surface → biometric → TxAuth → ledger
Host app ◀────── result JWS {intent_id, status}                       (for UX only, not authoritative)
Host backend ◀── webhook intent.succeeded, header Bilyon-Signature: t=<ts>,v1=HMAC-SHA256(K_webhook[host], t ‖ "." ‖ body)
                 (5 min tolerance; retried with backoff for 24 h; authoritative)
```

Host registration covers: `host_id`, bundle IDs and Android package names with signing-certificate
digests, allowed web origins, return links, webhook URL, scopes (`payments.create`, `tips.session`,
`identity.handle.read`) and the payout account.

### 4.3.3 Livestream tipping

| Concern | Design |
|---|---|
| Friction | One biometric opens a **tip session**, for example a 20.00 budget, 2.00 max per tip, 2 h. The server holds the budget and issues a session token scoped to `(host, stream, limits, expiry)` and bound to the device's proof-of-possession key |
| Per-tip cost | `POST /v1/tips` with no biometric. Redis does an atomic budget decrement (`DECRBY` with a floor check) and appends to the tip log |
| Ledger load | A batcher posts **one journal entry per (viewer, creator) every 5 s or 50 tips** against the hold, about 50× fewer ledger writes than one entry per tip |
| Fan-out | Tips publish to NATS `stream.{id}.tips`. Gateways coalesce per 250 ms window into bursts ("Alice ×5") to cap each viewer at ≤ 4 messages/s, even with 1 M viewers |
| End | The unused budget is released (the remaining hold is voided). Creators are paid out daily, net |
