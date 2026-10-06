-- Ordered outbox tailing (RFC 0001 §2.3.5).
--
-- Some consumers read the outbox table directly instead of the event bus,
-- because they need an order consistent with the ledger's serialization
-- order: the TigerBeetle shadow replays entries into accounts that enforce
-- balance limits, and an early debit could otherwise consume funds that a
-- later-published entry needed.
--
-- Outbox ids are assigned after a ledger transaction has taken all of its
-- locks, so for any two transactions where one observed the other, the
-- observed one has the smaller ids and committed first. Reading the rows of
-- one snapshot in id order therefore yields a valid serialization; ids not
-- yet visible (gaps) belong to transactions still in flight, which tailers
-- revisit once those transactions finish.

-- The writing transaction's id. outbox.Write assigns it before the row id,
-- so a transaction holding an outbox id is always listed as in flight in
-- concurrent snapshots, which is what lets a tailer resolve gaps exactly.
ALTER TABLE outbox ADD COLUMN txid xid8 NOT NULL DEFAULT pg_current_xact_id();

-- Positions of table-reading consumers.
--   last_id  highest id the consumer has examined
--   horizon  every id <= horizon is consumed or proven never to commit;
--            retention may delete published rows up to the lowest horizon
--   gaps     ids <= last_id not yet visible, grouped by the snapshot in
--            which they were first missing: [{"snapshot": "...", "ids": [...]}]
CREATE TABLE outbox_cursors (
    consumer   text PRIMARY KEY CHECK (consumer ~ '^[a-z][a-z0-9_.-]{0,62}$'),
    state      text NOT NULL CHECK (state IN ('bootstrapping', 'tailing')),
    last_id    bigint NOT NULL DEFAULT 0 CHECK (last_id >= 0),
    horizon    bigint NOT NULL DEFAULT 0 CHECK (horizon >= 0 AND horizon <= last_id),
    gaps       jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(gaps) = 'array'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
