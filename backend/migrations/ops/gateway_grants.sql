-- Least-privilege grants for the gateway runtime role (gatewayd).
--
-- Run as the role that owns the gateway schema (the migration role), after
-- migrations:
--   psql "$BILYON_GATEWAY_MIGRATION_DATABASE_URL" -f migrations/ops/gateway_grants.sql
-- then run gatewayd as bilyon_gateway (or a login role that is a member of
-- it, with options=-c role=bilyon_gateway).
--
-- The runtime role drives the state machines it owns and appends to the
-- transparency log, but it cannot rewrite the log, delete intents or
-- passkeys, change an intent's amount, payee or evidence, or change an
-- account's status (support tooling does that under its own role).
-- Locking reads (SELECT ... FOR UPDATE / FOR SHARE) need UPDATE on at least
-- one column, which every locked table has below.

DO $$
BEGIN
    CREATE ROLE bilyon_gateway NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
END $$;

GRANT USAGE ON SCHEMA public TO bilyon_gateway;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM bilyon_gateway;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO bilyon_gateway;

-- People and passkeys. Abandoned sign-ups (no passkey, nothing else) are
-- purged; passkeys are never deleted.
GRANT INSERT, DELETE ON users TO bilyon_gateway;
GRANT UPDATE (intent_timeout) ON users TO bilyon_gateway;
GRANT INSERT ON webauthn_credentials TO bilyon_gateway;
GRANT UPDATE (sign_count, backed_up, last_used_at) ON webauthn_credentials TO bilyon_gateway;

-- Attested devices and their keys: integrity refreshes and revocation.
GRANT INSERT ON devices, device_keys TO bilyon_gateway;
GRANT UPDATE (app_attest_counter, os_patch_level, integrity, integrity_at, revoked_at, revoke_reason)
    ON devices TO bilyon_gateway;
GRANT UPDATE (revoked_at, revoke_reason) ON device_keys TO bilyon_gateway;

-- Sessions and rotating refresh tokens; expired sessions are purged.
GRANT INSERT, DELETE ON sessions, refresh_tokens TO bilyon_gateway;
GRANT UPDATE (last_refresh_at, auth_time, amr, revoked_at, revoke_reason) ON sessions TO bilyon_gateway;
GRANT UPDATE (used_at, retired_at) ON refresh_tokens TO bilyon_gateway;

-- The directory. Leaves, subtree hashes and signed tree heads are
-- append-only: no UPDATE or DELETE.
GRANT INSERT ON subjects, reserved_handles, tlog_leaves, tlog_nodes, tlog_sths TO bilyon_gateway;
GRANT INSERT, DELETE ON handles, handle_quarantine TO bilyon_gateway;
GRANT UPDATE (display) ON handles TO bilyon_gateway;
GRANT UPDATE (handle, user_id, released_at) ON handle_quarantine TO bilyon_gateway;
GRANT INSERT ON directory_entries TO bilyon_gateway;
GRANT UPDATE (version, entry, leaf_index, updated_at) ON directory_entries TO bilyon_gateway;
GRANT UPDATE (size) ON tlog_head TO bilyon_gateway;

-- Payments: account resolution and the intent state machine. Amounts,
-- parties, the quote and the TxAuth evidence are insert-only.
GRANT INSERT ON user_accounts, payment_intents TO bilyon_gateway;
GRANT UPDATE (state, reason, updated_at, hold_id, entry_ids, payee_id, payee_subject, claim_until,
    held_at, delivered_at, caught_at, resolved_at) ON payment_intents TO bilyon_gateway;

-- Transactional outbox and its retention.
GRANT INSERT, DELETE ON outbox TO bilyon_gateway;
GRANT UPDATE (attempts, last_error, available_at, published_at, dead_at) ON outbox TO bilyon_gateway;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bilyon_gateway;
