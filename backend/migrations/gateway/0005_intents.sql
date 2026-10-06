-- Gateway schema, part 5: people's ledger accounts and payment intents,
-- including kinetic throw intents (RFC 0001 §1.5, §2.2.5, §3.B, §4.4.5).
--
-- An intent is authorised by a TxAuth (COSE_Sign1 by the payer's K_dev or
-- K_gest), kept here as evidence. Funds move only through ledger commands:
-- a hold when the intent is accepted, then a post to the payee on CATCH or
-- a void (boomerang). The states mirror the server state machine of
-- §4.4.5, plus the two durable intermediate states the orchestrator needs
-- to finish a ledger call after a crash: 'caught' (settlement decided, post
-- pending) and 'voiding' (void decided, hold release pending).

-- What happens to a throw nobody caught within the live TTL: it stays
-- claimable by the payee for 7 days ('async') or returns at once ('void').
ALTER TABLE users ADD COLUMN intent_timeout text NOT NULL DEFAULT 'async'
    CHECK (intent_timeout IN ('async', 'void'));

-- One ledger account per person and currency, opened on first use.
CREATE TABLE user_accounts (
    user_id    uuid NOT NULL REFERENCES users,
    currency   text NOT NULL CHECK (currency ~ '^[A-Z][A-Z0-9]{2,7}$'),
    account_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (user_id, currency)
);

CREATE TABLE payment_intents (
    intent_id       uuid PRIMARY KEY,                -- UUIDv7 chosen by the payer's device
    payer_id        uuid NOT NULL REFERENCES users,
    payer_subject   text NOT NULL,
    payer_device_id uuid NOT NULL REFERENCES devices,
    signer_key_id   uuid NOT NULL REFERENCES device_keys,
    signer_role     text NOT NULL CHECK (signer_role IN ('dev', 'gest')),
    -- The payee: a directory subject, pinned at the entry version the payer
    -- verified (TOCTOU guard). A drop has none until someone grabs it.
    payee_id        uuid REFERENCES users,
    payee_subject   text CHECK (payee_subject ~ '^bil_[0-9A-HJKMNP-TV-Z]{20}$'),
    par_version     bigint CHECK (par_version >= 1),
    gesture         text NOT NULL CHECK (gesture IN ('flick', 'split', 'grab', 'handle', 'qr')),
    amount_minor    bigint NOT NULL CHECK (amount_minor > 0),
    currency        text NOT NULL CHECK (currency ~ '^[A-Z][A-Z0-9]{2,7}$'),
    -- What the payee receives: the same amount, or an FX quote's output.
    payee_amount    bigint NOT NULL CHECK (payee_amount > 0),
    payee_currency  text NOT NULL CHECK (payee_currency ~ '^[A-Z][A-Z0-9]{2,7}$'),
    quote_id        uuid,
    quote_signature bytea,
    state           text NOT NULL CHECK (state IN ('created', 'held', 'delivered', 'caught', 'settled',
                        'async_pending', 'voiding', 'voided', 'aborted')),
    reason          text CHECK (reason ~ '^[a-z][a-z0-9_]{1,63}$'),
    on_timeout      text NOT NULL CHECK (on_timeout IN ('async', 'void')),
    server_nonce    bytea NOT NULL UNIQUE CHECK (octet_length(server_nonce) = 16),
    signed_at       timestamptz NOT NULL,
    txauth          bytea NOT NULL,
    hold_id         uuid UNIQUE,
    hold_expires_at timestamptz NOT NULL,
    entry_ids       uuid[] NOT NULL DEFAULT '{}',
    t_land          timestamptz,                     -- kinetic landing time in server time (§4.4.3)
    live_until      timestamptz,                     -- end of the catch window
    claim_until     timestamptz,                     -- end of the asynchronous claim window
    trajectory      jsonb,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    held_at         timestamptz,
    delivered_at    timestamptz,
    caught_at       timestamptz,
    resolved_at     timestamptz,
    -- The quote's signature is needed to execute it; an intent refused
    -- before its quote was verified keeps only the id it was signed with.
    CHECK (quote_signature IS NULL OR quote_id IS NOT NULL),
    CHECK (state = 'aborted' OR (quote_id IS NULL) = (quote_signature IS NULL)),
    CHECK (quote_id IS NOT NULL OR (payee_amount = amount_minor AND payee_currency = currency)),
    CHECK ((state IN ('aborted', 'voiding', 'voided')) = (reason IS NOT NULL)),
    CHECK (state <> 'created' OR hold_id IS NULL),
    CHECK (state IN ('created', 'aborted') OR hold_id IS NOT NULL),
    CHECK (state <> 'async_pending' OR claim_until IS NOT NULL),
    CHECK (state NOT IN ('caught', 'settled') OR payee_id IS NOT NULL),
    CHECK (state <> 'settled' OR cardinality(entry_ids) > 0),
    CHECK (payee_id IS NULL OR payee_subject IS NOT NULL),
    CHECK (gesture = 'grab' OR payee_subject IS NOT NULL),
    CHECK (gesture = 'grab' OR state = 'aborted' OR (payee_id IS NOT NULL AND par_version IS NOT NULL)),
    CHECK ((gesture IN ('flick', 'grab')) = (live_until IS NOT NULL)),
    CHECK ((gesture = 'flick') = (t_land IS NOT NULL)),
    CHECK (trajectory IS NULL OR gesture = 'flick'),
    CHECK ((state IN ('settled', 'voided', 'aborted')) = (resolved_at IS NOT NULL))
);
CREATE INDEX payment_intents_payer ON payment_intents (payer_id, created_at DESC, intent_id DESC);
CREATE INDEX payment_intents_payee ON payment_intents (payee_id, created_at DESC, intent_id DESC)
    WHERE payee_id IS NOT NULL;
-- Sweeper work queues.
CREATE INDEX payment_intents_live ON payment_intents (live_until) WHERE state IN ('held', 'delivered');
CREATE INDEX payment_intents_claims ON payment_intents (claim_until) WHERE state = 'async_pending';
CREATE INDEX payment_intents_unfinished ON payment_intents (updated_at) WHERE state IN ('created', 'caught', 'voiding');
-- Limits: K_gest velocity per device and rolling outflow per payer.
CREATE INDEX payment_intents_gesture ON payment_intents (payer_device_id, created_at)
    WHERE signer_role = 'gest' AND state <> 'aborted';
CREATE INDEX payment_intents_outflow ON payment_intents (payer_id, currency, created_at)
    WHERE state NOT IN ('aborted', 'voiding', 'voided');
