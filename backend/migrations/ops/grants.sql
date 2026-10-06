-- Least-privilege grants for the ledger runtime role (RFC 0001 §6.2 "ledger tampering").
--
-- Run as the role that owns the schema (the migration role), after migrations:
--   psql "$BILYON_MIGRATION_DATABASE_URL" -f migrations/ops/grants.sql
-- then run services as bilyon_app (or a login role that is a member of it).
--
-- The runtime role can append to the journal and drive state machines, but it
-- has no UPDATE on balance amounts and no UPDATE/DELETE on history: balances
-- change only through the SECURITY DEFINER triggers installed by migrations.

DO $$
BEGIN
    CREATE ROLE bilyon_app NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
END $$;

GRANT USAGE ON SCHEMA public TO bilyon_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM bilyon_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO bilyon_app;

GRANT INSERT ON accounts, journal_entries, postings, holds, reserves, idempotency_keys, outbox TO bilyon_app;

-- State-machine columns only. Triggers maintain every derived column.
GRANT UPDATE (frozen, label) ON accounts TO bilyon_app;
GRANT UPDATE (state, posted_minor, entry_id, resolution_note) ON holds TO bilyon_app;
GRANT UPDATE (state, closed_entry_id) ON reserves TO bilyon_app;
GRANT UPDATE (response, completed_at) ON idempotency_keys TO bilyon_app;
GRANT UPDATE (attempts, last_error, available_at, published_at, dead_at) ON outbox TO bilyon_app;

-- SELECT ... FOR UPDATE needs UPDATE on at least one column. updated_at is
-- the only column granted on balances; amounts stay trigger-only.
GRANT UPDATE (updated_at) ON account_balances TO bilyon_app;

-- Retention jobs.
GRANT DELETE ON idempotency_keys, outbox TO bilyon_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bilyon_app;
