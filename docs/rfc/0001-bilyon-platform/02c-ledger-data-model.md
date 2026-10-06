# §2.3 Ledger and Online Data Model

[← RFC index](README.md)

## 2.3.1 Invariants (enforced by the database, audited continuously)

- **I1 Double entry.** For every journal entry and every currency, `Σ postings.amount_minor = 0`.
  Postings are signed deltas of the account's balance (positive: the balance grows). Enforced by a
  deferred constraint trigger.
- **I2 No overdraft.** `balance − pending ≥ floor` per account. `floor = 0` for customer accounts.
  Platform books (FX, nostro) have negative floors equal to their risk limits.
- **I3 Append-only.** Journal entries and postings are never updated or deleted. Corrections are
  reversal entries that reference the original.
- **I4 Exactly-once.** Every command carries an `idempotency_key` (unique). A replay returns the
  original result.
- **I5 Money is integer.** `bigint` minor units. Stablecoins are normalised to 6 decimals (USDC native),
  which fits comfortably in `bigint`.
- **I6 Events are transactional.** Every committed entry writes its outbox rows in the same transaction
  (no dual writes). CDC publishes them.

## 2.3.2 Schema (PostgreSQL 17, Phase 1–2)

```sql
CREATE TYPE account_kind AS ENUM ('user','merchant','offline_reserve','offline_guarantee',
  'fx_book','nostro','fee','link_escrow','intent_hold','receivable','clearing','suspense');

CREATE TABLE accounts (
  account_id    uuid PRIMARY KEY,                -- UUIDv7
  owner_id      uuid,                            -- user / merchant / null for platform books
  kind          account_kind NOT NULL,
  currency      char(3) NOT NULL,
  stripe        smallint NOT NULL DEFAULT 0,     -- hot-account striping index (§2.3.4)
  balance_minor bigint NOT NULL DEFAULT 0,       -- posted
  pending_minor bigint NOT NULL DEFAULT 0,       -- sum of open holds
  floor_minor   bigint NOT NULL DEFAULT 0,       -- 0 for customers; -limit for platform books
  frozen        boolean NOT NULL DEFAULT false,
  CONSTRAINT no_overdraft CHECK (balance_minor - pending_minor >= floor_minor)      -- I2
);

CREATE TABLE journal_entries (
  entry_id        uuid PRIMARY KEY,              -- UUIDv7 (time-ordered)
  idempotency_key text NOT NULL UNIQUE,          -- I4
  kind            text NOT NULL,                 -- p2p, merchant, fx, offline_provision, offline_settle,
                                                 -- guarantee, clawback, link_claim, reversal, ...
  ref_type        text, ref_id uuid,             -- intent / quote / offline token / link
  reverses        uuid REFERENCES journal_entries,
  created_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE postings (
  entry_id     uuid NOT NULL REFERENCES journal_entries,
  seq          smallint NOT NULL,
  account_id   uuid NOT NULL REFERENCES accounts,
  currency     char(3) NOT NULL,
  amount_minor bigint NOT NULL CHECK (amount_minor <> 0),   -- signed balance delta
  PRIMARY KEY (entry_id, seq)
);
CREATE INDEX postings_account ON postings (account_id, entry_id);

CREATE FUNCTION assert_balanced() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM postings WHERE entry_id = NEW.entry_id
             GROUP BY currency HAVING sum(amount_minor) <> 0) THEN
    RAISE EXCEPTION 'unbalanced journal entry %', NEW.entry_id;          -- I1
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER postings_balanced AFTER INSERT ON postings
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assert_balanced();
CREATE RULE postings_no_update AS ON UPDATE TO postings DO INSTEAD NOTHING;   -- I3
CREATE RULE postings_no_delete AS ON DELETE TO postings DO INSTEAD NOTHING;

CREATE TABLE holds (                              -- two-phase transfers
  hold_id      uuid PRIMARY KEY,
  account_id   uuid NOT NULL REFERENCES accounts,
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  reason       text NOT NULL,                     -- throw_intent, quote_lock, payment_link, tip_session
  state        text NOT NULL CHECK (state IN ('pending','posted','voided','expired')),
  expires_at   timestamptz NOT NULL,
  entry_id     uuid REFERENCES journal_entries    -- set when posted
);
CREATE INDEX holds_expiry ON holds (expires_at) WHERE state = 'pending';

CREATE TABLE payment_intents (                    -- includes kinetic "throw intents"
  intent_id     uuid PRIMARY KEY,
  payer_id uuid NOT NULL, payee_id uuid,          -- payee may be resolved later (links, splits)
  amount_minor  bigint NOT NULL, currency char(3) NOT NULL,
  quote_id      uuid,                             -- FX quote if cross-currency
  gesture       text CHECK (gesture IN ('flick','split','grab','link','handle','qr','sdk')),
  state         text NOT NULL,                    -- created, held, delivered, caught, settled, aborted
  hold_id       uuid REFERENCES holds,
  txauth        bytea NOT NULL,                   -- COSE TxAuth (§2.2.5), kept as evidence
  t_land        timestamptz,                      -- kinetic landing time (§4.4)
  live_until    timestamptz,                      -- catch TTL; then async claim or void
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
  device_id uuid PRIMARY KEY, user_id uuid NOT NULL,
  platform text NOT NULL, security_level text NOT NULL,     -- se, strongbox, tee
  k_dev bytea NOT NULL, k_gest bytea, attest_key bytea,     -- compressed P-256 / App Attest key
  integrity jsonb NOT NULL, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE webauthn_credentials (
  credential_id bytea PRIMARY KEY, user_id uuid NOT NULL, cose_pubkey bytea NOT NULL,
  sign_count bigint NOT NULL, be boolean NOT NULL, bs boolean NOT NULL, aaguid uuid,
  transports text[], last_used_at timestamptz
);

CREATE TABLE offline_allowances (
  aid uuid PRIMARY KEY, device_id uuid NOT NULL REFERENCES devices, tier smallint NOT NULL,
  reserve_account uuid NOT NULL REFERENCES accounts, currency char(3) NOT NULL,
  amount_minor bigint NOT NULL, tx_max bigint NOT NULL, max_tx int NOT NULL,
  nbf timestamptz NOT NULL, exp timestamptz NOT NULL, oac bytea NOT NULL,
  state text NOT NULL,                             -- active, closed, expired, fraud
  closing bytea, paid_minor bigint NOT NULL DEFAULT 0, guaranteed_minor bigint NOT NULL DEFAULT 0
);
CREATE TABLE offline_tokens (                      -- one row per (aid, seq) or (aid, coin idx)
  aid uuid NOT NULL REFERENCES offline_allowances, slot int NOT NULL,
  tid bytea NOT NULL, payee_binding bytea NOT NULL, amount_minor bigint NOT NULL,
  cose bytea NOT NULL, settled_entry uuid REFERENCES journal_entries, voided boolean NOT NULL DEFAULT false,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (aid, slot)
);
CREATE TABLE offline_evidence (                    -- equivocation / inconsistency proofs
  evidence_id uuid PRIMARY KEY, aid uuid NOT NULL, kind text NOT NULL,
  artefact_a bytea, artefact_b bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE fx_quotes (
  quote_id uuid PRIMARY KEY, from_ccy char(3) NOT NULL, to_ccy char(3) NOT NULL,
  amount_in bigint NOT NULL, amount_out bigint NOT NULL, mid_out numeric NOT NULL,
  exec_cost_bps numeric NOT NULL, buffer_bps numeric NOT NULL, margin_bps numeric NOT NULL,
  route jsonb NOT NULL, expires_at timestamptz NOT NULL, state text NOT NULL, sig bytea NOT NULL
);

CREATE TABLE handles (
  handle text PRIMARY KEY,                         -- NFKC + casefold
  skeleton text NOT NULL UNIQUE,                   -- UTS #39 confusable skeleton
  user_id uuid NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE social_links (
  provider text NOT NULL, provider_uid text NOT NULL,       -- stable id, never the @name
  user_id uuid NOT NULL, display_handle text NOT NULL,
  verified_at timestamptz NOT NULL, rechecked_at timestamptz NOT NULL, state text NOT NULL,
  PRIMARY KEY (provider, provider_uid)
);
CREATE TABLE payment_links (
  link_id text PRIMARY KEY, sender_id uuid NOT NULL, verifier bytea NOT NULL,   -- HMAC(pepper, secret)
  amount_minor bigint NOT NULL, currency char(3) NOT NULL, hold_id uuid NOT NULL REFERENCES holds,
  restrict_to uuid, max_claims int NOT NULL DEFAULT 1, claims int NOT NULL DEFAULT 0,
  state text NOT NULL, expires_at timestamptz NOT NULL, claimed_by uuid
);

CREATE TABLE outbox (                              -- I6, drained by CDC (Debezium) into Kafka/NATS
  id bigserial PRIMARY KEY, topic text NOT NULL, key text NOT NULL, payload bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

## 2.3.3 Posting protocol

```text
PostTransfer(cmd):                               -- one SQL transaction, SERIALIZABLE not required
  BEGIN
  IF EXISTS journal_entries WHERE idempotency_key = cmd.key: RETURN stored result      -- I4
  lock accounts: SELECT ... FOR UPDATE ORDER BY account_id                             -- no deadlocks
  check frozen = false; apply deltas (balance / pending)                               -- I2 via CHECK
  INSERT journal_entries; INSERT postings (balanced per currency)                      -- I1 at COMMIT
  INSERT outbox (topic = 'ledger.entry', key = ref_id, payload = entry)                -- I6
  COMMIT                                            -- synchronous replica ack (RPO 0)
```

Holds use the same transaction. *Hold* raises `pending_minor`. *Post* moves the amount to the
counterparty, lowers `pending_minor` and links `entry_id`. *Void* or *expire* only lowers
`pending_minor`. An expiry sweeper (every 1 s, `holds_expiry` index) voids lapsed holds. Each void
emits an outbox event so the UI can play the "boomerang" animation.

## 2.3.4 Hot accounts

Platform accounts (fee income, FX books, the guarantee fund, intent holds) are written by a large share
of all entries. In Postgres a single row would serialise them. Each hot account is therefore striped into
`N = 64` rows (`stripe` column) and the writer picks `stripe = hash(entry_id) mod N`. A sweeper nets
the stripes hourly, and reporting sums them. Customer accounts are never striped, because their no-overdraft
check needs a single row.

## 2.3.5 Phase 3 mapping to TigerBeetle

| Concept | TigerBeetle | Notes |
|---|---|---|
| Account | `Account{id: u128, ledger: ISO 4217 numeric, code: account_kind, flags: debits_must_not_exceed_credits}` | `ledger` partitions currencies; cross-currency moves need an FX book per currency |
| Hold / post / void | Pending transfer with `timeout`, then `post_pending_transfer` / `void_pending_transfer` | The native two-phase transfer replaces the `holds` table; timeouts replace the sweeper |
| Multi-leg FX entry | Linked transfers (`flags.linked`) | All legs commit or none do |
| Idempotency | Transfer `id` = UUIDv7 derived from the idempotency key | Duplicate IDs are rejected as `exists` |
| References | `user_data_128` = intent / quote / token id | Metadata, outbox and reporting stay in Postgres |

The ledger service interface (`Hold`, `Post`, `Void`, `Transfer`, `LinkedTransfers`) is fixed in
Phase 1, so the swap is internal to one service. During migration, shadow writes and
reconciliation run against both engines for at least one full month-end close.

## 2.3.6 Example journal entries

| Flow | Postings (signed balance deltas, minor units) |
|---|---|
| Throw 20.00 EUR, hold | No posting: `user:payer.pending_minor += 2000` |
| Throw caught, post | `user:payer −2000`, `user:payee +2000` (and `pending_minor −= 2000`) |
| FX 10 000.00 EUR → 10 839.58 USD | EUR: `user:EUR −1 000 000`, `fx_book:EUR +1 000 000` · USD: `fx_book:USD −1 083 958`, `user:USD +1 083 958` |
| Offline provision 150.00 | `user −15 000`, `offline_reserve:<aid> +15 000` |
| Offline settle 12.50 | `offline_reserve:<aid> −1 250`, `merchant +1 250` |
| Overspend shortfall 30.00 | `offline_guarantee −3 000`, `payee +3 000` · `receivable:payer −3 000`, `offline_guarantee +3 000` |
| Reserve release at expiry | `offline_reserve:<aid> −X`, `user +X` |
| Link claim | Post the link's hold: `link_escrow −X`, `user:claimant +X` |

The reference reconciler (`reference/offline/reconcile.go`) emits exactly these offline movements as
`Posting{Debit: from, Credit: to, Amount}`, which is equivalent to the deltas `from −Amount`,
`to +Amount`. Its tests assert the amounts. The receivable is a separate account with a negative floor,
so a clawback never breaks I2 on the customer's spendable account.
