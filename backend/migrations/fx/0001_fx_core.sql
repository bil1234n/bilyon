-- FX engine schema (RFC 0001 §3.C): firm quotes and their execution.
--
-- A quote is created open with its liquidity reservation; executing it
-- moves it to executing once the market check passed and depth was
-- consumed, then to booked once the ledger entries exist. Booking uses
-- idempotency keys derived from the quote id, so a crashed execution is
-- resumed by retrying it. Expired and breaker-refused quotes are terminal.

CREATE TABLE fx_quotes (
    quote_id            uuid PRIMARY KEY,
    user_id             uuid NOT NULL,
    from_ccy            text NOT NULL CHECK (from_ccy ~ '^[A-Z][A-Z0-9]{2,7}$'),
    to_ccy              text NOT NULL CHECK (to_ccy ~ '^[A-Z][A-Z0-9]{2,7}$' AND to_ccy <> from_ccy),
    amount_in           bigint NOT NULL CHECK (amount_in > 0),
    amount_out          bigint NOT NULL CHECK (amount_out > 0),
    exec_out            bigint NOT NULL CHECK (exec_out >= amount_out),
    -- Transparency figures shown with the quote (not money).
    mid_rate            text NOT NULL CHECK (mid_rate ~ '^[0-9]+(\.[0-9]+)?$'),
    mid_out             double precision NOT NULL,
    exec_cost_bps       double precision NOT NULL,
    buffer_bps          double precision NOT NULL CHECK (buffer_bps >= 0),
    margin_bps          double precision NOT NULL CHECK (margin_bps >= 0),
    allocations         jsonb NOT NULL CHECK (jsonb_typeof(allocations) = 'array'),
    reserved            jsonb NOT NULL CHECK (jsonb_typeof(reserved) = 'array'),
    key_id              text NOT NULL,
    sig                 bytea NOT NULL CHECK (octet_length(sig) = 32),
    state               text NOT NULL CHECK (state IN ('open', 'executing', 'booked', 'expired', 'requoted', 'failed')),
    created_at          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL CHECK (expires_at > created_at),
    -- Execution.
    hold_id             uuid,
    source_account      uuid,
    destination_account uuid,
    market_out          bigint,
    pnl                 bigint,
    entry_ids           uuid[],
    executed_at         timestamptz,
    booked_at           timestamptz,
    failure             text,
    CHECK (state IN ('open', 'expired') OR state = 'requoted' OR executed_at IS NOT NULL),
    CHECK (state NOT IN ('executing', 'booked', 'failed')
        OR (market_out IS NOT NULL AND destination_account IS NOT NULL
            AND (hold_id IS NULL) <> (source_account IS NULL))),
    CHECK (state <> 'booked' OR (booked_at IS NOT NULL AND cardinality(entry_ids) > 0))
);
CREATE INDEX fx_quotes_user_created ON fx_quotes (user_id, created_at);
CREATE INDEX fx_quotes_open ON fx_quotes (expires_at) WHERE state = 'open';
CREATE INDEX fx_quotes_executing ON fx_quotes (executed_at) WHERE state = 'executing';

-- Transactional outbox, identical in shape to the ledger's and gateway's.
CREATE TABLE outbox (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    topic        text NOT NULL CHECK (topic ~ '^[a-z][a-z0-9_.]{1,127}$'),
    msg_key      text NOT NULL CHECK (char_length(msg_key) BETWEEN 1 AND 200),
    partition    smallint NOT NULL CHECK (partition BETWEEN 0 AND 15),
    payload      jsonb NOT NULL,
    headers      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error   text,
    published_at timestamptz,
    dead_at      timestamptz,
    txid         xid8 NOT NULL DEFAULT pg_current_xact_id(),
    CONSTRAINT outbox_terminal CHECK (published_at IS NULL OR dead_at IS NULL)
);
CREATE INDEX outbox_pending ON outbox (partition, id)
    WHERE published_at IS NULL AND dead_at IS NULL;
CREATE INDEX outbox_pending_key ON outbox (partition, msg_key, id)
    WHERE published_at IS NULL AND dead_at IS NULL;
CREATE INDEX outbox_published ON outbox (published_at) WHERE published_at IS NOT NULL;

CREATE TABLE outbox_cursors (
    consumer   text PRIMARY KEY CHECK (consumer ~ '^[a-z][a-z0-9_.-]{0,62}$'),
    state      text NOT NULL CHECK (state IN ('bootstrapping', 'tailing')),
    last_id    bigint NOT NULL DEFAULT 0 CHECK (last_id >= 0),
    horizon    bigint NOT NULL DEFAULT 0 CHECK (horizon >= 0 AND horizon <= last_id),
    gaps       jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(gaps) = 'array'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION fx_outbox_notify() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_notify('bilyon_outbox', '');
    RETURN NULL;
END $$;
CREATE TRIGGER outbox_notify AFTER INSERT ON outbox
    FOR EACH STATEMENT EXECUTE FUNCTION fx_outbox_notify();
