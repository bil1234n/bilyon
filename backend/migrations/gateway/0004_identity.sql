-- Gateway schema, part 4: handles, the payee directory and its
-- transparency log (RFC 0001 §4.1).
--
-- Handles are stored in NFKC_Casefold form and unique on their UTS #39
-- confusable skeleton. Every directory change appends the new entry to an
-- RFC 9162 Merkle log in the same transaction; complete subtree hashes are
-- kept so that roots and proofs cost one query.

CREATE TABLE subjects (
    user_id    uuid PRIMARY KEY REFERENCES users,
    subject    text NOT NULL UNIQUE CHECK (subject ~ '^bil_[0-9A-HJKMNP-TV-Z]{20}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE handles (
    handle     text PRIMARY KEY CHECK (char_length(handle) BETWEEN 3 AND 30),
    skeleton   text NOT NULL UNIQUE,
    display    text NOT NULL,
    user_id    uuid NOT NULL UNIQUE REFERENCES users,
    claimed_at timestamptz NOT NULL
);

-- A released handle's skeleton stays reserved for its previous owner
-- until released_at (90 days), so nobody else can claim a lookalike.
CREATE TABLE handle_quarantine (
    skeleton    text PRIMARY KEY,
    handle      text NOT NULL,
    user_id     uuid NOT NULL REFERENCES users,
    released_at timestamptz NOT NULL
);

-- Brand, system and impersonation-prone names nobody can claim.
CREATE TABLE reserved_handles (
    skeleton text PRIMARY KEY,
    handle   text NOT NULL,
    reason   text NOT NULL
);

-- The current version of each subject's directory entry. The entry bytes
-- are the deterministic CBOR committed to the log at leaf_index.
CREATE TABLE directory_entries (
    subject    text PRIMARY KEY REFERENCES subjects (subject),
    version    bigint NOT NULL CHECK (version >= 1),
    entry      bytea NOT NULL,
    leaf_index bigint NOT NULL UNIQUE,
    updated_at timestamptz NOT NULL
);

CREATE TABLE tlog_head (
    id   smallint PRIMARY KEY CHECK (id = 1),
    size bigint NOT NULL CHECK (size >= 0)
);
INSERT INTO tlog_head (id, size) VALUES (1, 0);

CREATE TABLE tlog_leaves (
    idx        bigint PRIMARY KEY CHECK (idx >= 0),
    data       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Complete subtree hashes: (level, idx) covers leaves
-- [idx·2^level, (idx+1)·2^level); level 0 holds the leaf hashes.
CREATE TABLE tlog_nodes (
    level smallint NOT NULL CHECK (level BETWEEN 0 AND 62),
    idx   bigint NOT NULL CHECK (idx >= 0),
    hash  bytea NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (level, idx)
);

-- Signed tree heads (COSE_Sign1 under K_dir), newest last.
CREATE TABLE tlog_sths (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    size       bigint NOT NULL CHECK (size >= 0),
    root       bytea NOT NULL CHECK (octet_length(root) = 32),
    signed_at  timestamptz NOT NULL,
    sth        bytea NOT NULL
);
CREATE INDEX tlog_sths_size ON tlog_sths (size);
