-- Gateway schema, part 1: accounts of people, their WebAuthn credentials
-- (RFC 0001 §2.2) and the gateway's transactional outbox.
--
-- The gateway owns this database. It never holds balances: money moves only
-- through ledger commands (§1.1 layer responsibilities).

CREATE TABLE users (
    user_id         uuid PRIMARY KEY,
    -- WebAuthn user handle: 32 random bytes, never PII (§2.2.2).
    webauthn_handle bytea NOT NULL UNIQUE CHECK (octet_length(webauthn_handle) = 32),
    display_name    text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen', 'closed')),
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Passkeys (K_pass). Step R10 persists exactly these fields.
CREATE TABLE webauthn_credentials (
    credential_id     bytea PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    user_id           uuid NOT NULL REFERENCES users,
    public_key        bytea NOT NULL,   -- COSE_Key, deterministic encoding
    alg               integer NOT NULL CHECK (alg IN (-7, -257)),
    sign_count        bigint NOT NULL CHECK (sign_count >= 0 AND sign_count <= 4294967295),
    transports        text[] NOT NULL DEFAULT '{}',
    backup_eligible   boolean NOT NULL,
    backed_up         boolean NOT NULL,
    aaguid            uuid NOT NULL,
    attestation_fmt   text NOT NULL,
    attestation_trust text NOT NULL
        CHECK (attestation_trust IN ('none', 'self', 'basic', 'attca', 'anonca', 'anchored')),
    created_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_used_at      timestamptz,
    revoked_at        timestamptz,
    CHECK (backed_up = false OR backup_eligible)
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);

-- Transactional outbox, identical in shape to the ledger's (see
-- migrations/ledger): the gateway publishes its events through the same
-- relay code to its own stream.
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

CREATE FUNCTION gateway_outbox_notify() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_notify('bilyon_outbox', '');
    RETURN NULL;
END $$;
CREATE TRIGGER outbox_notify AFTER INSERT ON outbox
    FOR EACH STATEMENT EXECUTE FUNCTION gateway_outbox_notify();
