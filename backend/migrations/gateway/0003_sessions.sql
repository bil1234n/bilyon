-- Gateway schema, part 3: device sessions (RFC 0001 §2.2.3 A7).
--
-- A session starts at passkey login and is bound to the device's DPoP key
-- (RFC 9449) through its JWK thumbprint. Access tokens are short-lived
-- JWTs that are never stored; refresh tokens rotate on every use and are
-- kept only as SHA-256 hashes. Presenting a used refresh token outside the
-- retry grace revokes the session (reuse detection).

CREATE TABLE sessions (
    session_id      uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users,
    device_id       uuid REFERENCES devices,
    client_id       text NOT NULL CHECK (client_id ~ '^[a-z][a-z0-9._-]{1,63}$'),
    -- RFC 7638 SHA-256 thumbprint of the session's DPoP key, base64url.
    jkt             text NOT NULL CHECK (jkt ~ '^[A-Za-z0-9_-]{43}$'),
    amr             text[] NOT NULL CHECK (cardinality(amr) BETWEEN 1 AND 8),
    -- Time of the latest user authentication: login or step-up.
    auth_time       timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at      timestamptz NOT NULL,
    last_refresh_at timestamptz,
    revoked_at      timestamptz,
    revoke_reason   text,
    CHECK (expires_at > created_at),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX sessions_user ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_device ON sessions (device_id) WHERE revoked_at IS NULL AND device_id IS NOT NULL;
CREATE INDEX sessions_expiry ON sessions (expires_at);

CREATE TABLE refresh_tokens (
    token_hash  bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    session_id  uuid NOT NULL REFERENCES sessions ON DELETE CASCADE,
    generation  integer NOT NULL CHECK (generation >= 0),
    issued_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz NOT NULL,
    -- used_at: exchanged for a successor. retired_at: superseded unused,
    -- when a lost response was retried within the grace.
    used_at     timestamptz,
    retired_at  timestamptz,
    UNIQUE (session_id, generation),
    CHECK (used_at IS NULL OR retired_at IS NULL)
);
