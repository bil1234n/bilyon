-- Bilyon ledger core schema (RFC 0001 §2.3).
--
-- The invariants live in the database, not only in application code:
--   I1  every journal entry balances per currency          (deferred constraint trigger)
--   I2  no account goes below its floor                     (CHECK on account_balances)
--   I3  journal entries and postings are append-only        (row + truncate triggers)
--   I4  exactly-once commands                               (idempotency_keys + unique keys)
--   I5  money is integer minor units                        (bigint everywhere)
--   I6  events are written in the same transaction          (outbox + NOTIFY)
-- Balances are maintained by triggers on postings and holds, so a posting can
-- never exist without its balance effect. Trigger functions are SECURITY
-- DEFINER with a pinned search_path: deployments grant the application role
-- INSERT on postings/journal_entries/holds but no UPDATE on account_balances,
-- so balances can only change through these triggers (see migrations/ops/grants.sql).
--
-- Custom SQLSTATEs raised here (mapped by the Go engine):
--   BL001 account frozen          BL002 account immutable field changed
--   BL003 entry does not balance  BL004 append-only violation
--   BL005 invalid hold transition BL006 missing balance row
--   BL007 hold on striped account BL008 invalid reserve transition

CREATE TABLE currencies (
    code        text PRIMARY KEY CHECK (code ~ '^[A-Z][A-Z0-9]{2,7}$'),
    exponent    smallint NOT NULL CHECK (exponent BETWEEN 0 AND 18),
    ledger_code integer NOT NULL UNIQUE CHECK (ledger_code > 0),
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64)
);

COMMENT ON COLUMN currencies.ledger_code IS
    'Stable numeric ledger id: ISO 4217 numeric code for fiat, >= 100000 for digital assets (TigerBeetle ledger field)';

INSERT INTO currencies (code, exponent, ledger_code, name) VALUES
    ('USD', 2, 840, 'US Dollar'),            ('EUR', 2, 978, 'Euro'),
    ('GBP', 2, 826, 'Pound Sterling'),       ('JPY', 0, 392, 'Yen'),
    ('CHF', 2, 756, 'Swiss Franc'),          ('CAD', 2, 124, 'Canadian Dollar'),
    ('AUD', 2, 36,  'Australian Dollar'),    ('NZD', 2, 554, 'New Zealand Dollar'),
    ('SEK', 2, 752, 'Swedish Krona'),        ('NOK', 2, 578, 'Norwegian Krone'),
    ('DKK', 2, 208, 'Danish Krone'),         ('PLN', 2, 985, 'Zloty'),
    ('CZK', 2, 203, 'Czech Koruna'),         ('HUF', 2, 348, 'Forint'),
    ('CNY', 2, 156, 'Yuan Renminbi'),        ('HKD', 2, 344, 'Hong Kong Dollar'),
    ('SGD', 2, 702, 'Singapore Dollar'),     ('INR', 2, 356, 'Indian Rupee'),
    ('IDR', 2, 360, 'Rupiah'),               ('KRW', 0, 410, 'Won'),
    ('THB', 2, 764, 'Baht'),                 ('PHP', 2, 608, 'Philippine Peso'),
    ('MYR', 2, 458, 'Malaysian Ringgit'),    ('VND', 0, 704, 'Dong'),
    ('BRL', 2, 986, 'Brazilian Real'),       ('MXN', 2, 484, 'Mexican Peso'),
    ('ARS', 2, 32,  'Argentine Peso'),       ('CLP', 0, 152, 'Chilean Peso'),
    ('COP', 2, 170, 'Colombian Peso'),       ('PEN', 2, 604, 'Sol'),
    ('NGN', 2, 566, 'Naira'),                ('KES', 2, 404, 'Kenyan Shilling'),
    ('GHS', 2, 936, 'Ghana Cedi'),           ('ZAR', 2, 710, 'Rand'),
    ('EGP', 2, 818, 'Egyptian Pound'),       ('MAD', 2, 504, 'Moroccan Dirham'),
    ('ETB', 2, 230, 'Ethiopian Birr'),       ('UGX', 0, 800, 'Uganda Shilling'),
    ('TZS', 2, 834, 'Tanzanian Shilling'),   ('RWF', 0, 646, 'Rwanda Franc'),
    ('XOF', 0, 952, 'CFA Franc BCEAO'),      ('XAF', 0, 950, 'CFA Franc BEAC'),
    ('AED', 2, 784, 'UAE Dirham'),           ('SAR', 2, 682, 'Saudi Riyal'),
    ('QAR', 2, 634, 'Qatari Riyal'),         ('KWD', 3, 414, 'Kuwaiti Dinar'),
    ('BHD', 3, 48,  'Bahraini Dinar'),       ('OMR', 3, 512, 'Rial Omani'),
    ('JOD', 3, 400, 'Jordanian Dinar'),      ('TRY', 2, 949, 'Turkish Lira'),
    ('ILS', 2, 376, 'New Israeli Sheqel'),   ('PKR', 2, 586, 'Pakistan Rupee'),
    ('BDT', 2, 50,  'Taka'),                 ('LKR', 2, 144, 'Sri Lanka Rupee'),
    ('USDC', 6, 100001, 'USD Coin'),         ('EURC', 6, 100002, 'Euro Coin');

CREATE TYPE account_kind AS ENUM (
    'user', 'merchant', 'offline_reserve', 'offline_guarantee', 'fx_book', 'nostro', 'fee',
    'link_escrow', 'intent_hold', 'receivable', 'clearing', 'suspense', 'tip_session', 'system'
);
CREATE TYPE hold_state AS ENUM ('pending', 'posted', 'voided', 'expired');
CREATE TYPE reserve_state AS ENUM ('open', 'closed');

-- ---------------------------------------------------------------------------
-- Accounts and materialised balances
-- ---------------------------------------------------------------------------

CREATE TABLE accounts (
    account_id      uuid PRIMARY KEY,
    owner_id        uuid,
    kind            account_kind NOT NULL,
    currency        text NOT NULL REFERENCES currencies (code),
    floor_minor     bigint CHECK (floor_minor IS NULL OR floor_minor <= 0),
    stripes         smallint NOT NULL DEFAULT 1 CHECK (stripes BETWEEN 1 AND 64),
    frozen          boolean NOT NULL DEFAULT false,
    label           text CHECK (char_length(label) <= 128),
    idempotency_key text NOT NULL UNIQUE,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accounts_account_currency UNIQUE (account_id, currency),
    -- Striping spreads writes over several balance rows; a per-row floor would
    -- reject debits that the aggregate could cover, so striped accounts are
    -- unbounded and their limits are enforced on the aggregate by treasury.
    CONSTRAINT accounts_striped_unbounded CHECK (stripes = 1 OR floor_minor IS NULL)
);
CREATE INDEX accounts_owner ON accounts (owner_id) WHERE owner_id IS NOT NULL;

CREATE TABLE account_balances (
    account_id    uuid NOT NULL REFERENCES accounts (account_id),
    stripe        smallint NOT NULL CHECK (stripe BETWEEN 0 AND 63),
    balance_minor bigint NOT NULL DEFAULT 0,
    pending_minor bigint NOT NULL DEFAULT 0 CHECK (pending_minor >= 0),
    floor_minor   bigint,
    frozen        boolean NOT NULL DEFAULT false,
    version       bigint NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, stripe),
    CONSTRAINT account_balances_floor
        CHECK (floor_minor IS NULL OR balance_minor - pending_minor >= floor_minor)
);

CREATE FUNCTION ledger_accounts_after_insert() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    INSERT INTO account_balances (account_id, stripe, floor_minor, frozen)
    SELECT NEW.account_id, s, NEW.floor_minor, NEW.frozen
      FROM generate_series(0, NEW.stripes - 1) AS s;
    RETURN NULL;
END $$;
CREATE TRIGGER accounts_after_insert AFTER INSERT ON accounts
    FOR EACH ROW EXECUTE FUNCTION ledger_accounts_after_insert();

CREATE FUNCTION ledger_accounts_before_update() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.account_id <> OLD.account_id OR NEW.kind <> OLD.kind OR NEW.currency <> OLD.currency
       OR NEW.stripes <> OLD.stripes OR NEW.floor_minor IS DISTINCT FROM OLD.floor_minor
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'account % immutable field changed', OLD.account_id USING ERRCODE = 'BL002';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER accounts_before_update BEFORE UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION ledger_accounts_before_update();

CREATE FUNCTION ledger_accounts_after_update() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.frozen <> OLD.frozen THEN
        UPDATE account_balances SET frozen = NEW.frozen, updated_at = clock_timestamp()
         WHERE account_id = NEW.account_id;
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER accounts_after_update AFTER UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION ledger_accounts_after_update();

-- ---------------------------------------------------------------------------
-- Journal entries and postings (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE journal_entries (
    entry_id        uuid PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    kind            text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{1,63}$'),
    ref_type        text CHECK (ref_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    ref_id          text CHECK (char_length(ref_id) BETWEEN 1 AND 128),
    memo            text CHECK (char_length(memo) <= 512),
    reverses        uuid UNIQUE REFERENCES journal_entries (entry_id),
    hold_id         uuid,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT journal_entries_ref_pair CHECK ((ref_type IS NULL) = (ref_id IS NULL))
);
CREATE INDEX journal_entries_ref ON journal_entries (ref_type, ref_id) WHERE ref_type IS NOT NULL;
CREATE INDEX journal_entries_hold ON journal_entries (hold_id) WHERE hold_id IS NOT NULL;

CREATE TABLE postings (
    entry_id     uuid NOT NULL REFERENCES journal_entries (entry_id),
    seq          smallint NOT NULL CHECK (seq >= 0),
    account_id   uuid NOT NULL,
    stripe       smallint NOT NULL DEFAULT 0,
    currency     text NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor <> 0),
    PRIMARY KEY (entry_id, seq),
    CONSTRAINT postings_account_currency FOREIGN KEY (account_id, currency)
        REFERENCES accounts (account_id, currency),
    CONSTRAINT postings_balance_row FOREIGN KEY (account_id, stripe)
        REFERENCES account_balances (account_id, stripe)
);
CREATE INDEX postings_account ON postings (account_id, entry_id DESC);

CREATE FUNCTION ledger_postings_apply() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_frozen boolean;
BEGIN
    UPDATE account_balances
       SET balance_minor = balance_minor + NEW.amount_minor,
           version = version + 1,
           updated_at = clock_timestamp()
     WHERE account_id = NEW.account_id AND stripe = NEW.stripe
    RETURNING frozen INTO v_frozen;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no balance row for account % stripe %', NEW.account_id, NEW.stripe
            USING ERRCODE = 'BL006';
    END IF;
    IF v_frozen AND NEW.amount_minor < 0 AND NOT EXISTS (
           SELECT 1 FROM journal_entries
            WHERE entry_id = NEW.entry_id AND kind IN ('reversal', 'compliance.release')) THEN
        RAISE EXCEPTION 'account % is frozen', NEW.account_id USING ERRCODE = 'BL001';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER postings_apply BEFORE INSERT ON postings
    FOR EACH ROW EXECUTE FUNCTION ledger_postings_apply();

CREATE FUNCTION ledger_entry_balanced() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_currency text;
    v_sum      numeric;
BEGIN
    SELECT currency, sum(amount_minor) INTO v_currency, v_sum
      FROM postings
     WHERE entry_id = NEW.entry_id
     GROUP BY currency
    HAVING sum(amount_minor) <> 0
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'journal entry % does not balance in %: %', NEW.entry_id, v_currency, v_sum
            USING ERRCODE = 'BL003';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER postings_balanced AFTER INSERT ON postings
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger_entry_balanced();

CREATE FUNCTION ledger_entry_min_postings() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF (SELECT count(*) FROM postings WHERE entry_id = NEW.entry_id) < 2 THEN
        RAISE EXCEPTION 'journal entry % has fewer than two postings', NEW.entry_id
            USING ERRCODE = 'BL003';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER journal_entries_min_postings AFTER INSERT ON journal_entries
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger_entry_min_postings();

CREATE FUNCTION ledger_append_only() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION '% is append-only (% rejected)', TG_TABLE_NAME, TG_OP USING ERRCODE = 'BL004';
END $$;
CREATE TRIGGER journal_entries_append_only BEFORE UPDATE OR DELETE ON journal_entries
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER journal_entries_no_truncate BEFORE TRUNCATE ON journal_entries
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER postings_append_only BEFORE UPDATE OR DELETE ON postings
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER postings_no_truncate BEFORE TRUNCATE ON postings
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER accounts_no_delete BEFORE DELETE ON accounts
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER accounts_no_truncate BEFORE TRUNCATE ON accounts
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER account_balances_no_delete BEFORE DELETE ON account_balances
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER account_balances_no_truncate BEFORE TRUNCATE ON account_balances
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_append_only();

-- ---------------------------------------------------------------------------
-- Holds (two-phase transfers)
-- ---------------------------------------------------------------------------

CREATE TABLE holds (
    hold_id         uuid PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    account_id      uuid NOT NULL,
    currency        text NOT NULL,
    amount_minor    bigint NOT NULL CHECK (amount_minor > 0),
    reason          text NOT NULL CHECK (reason ~ '^[a-z][a-z0-9_]{1,63}$'),
    state           hold_state NOT NULL DEFAULT 'pending',
    expires_at      timestamptz NOT NULL,
    posted_minor    bigint NOT NULL DEFAULT 0,
    entry_id        uuid REFERENCES journal_entries (entry_id),
    ref_type        text CHECK (ref_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    ref_id          text CHECK (char_length(ref_id) BETWEEN 1 AND 128),
    resolution_note text CHECK (char_length(resolution_note) <= 256),
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_at     timestamptz,
    CONSTRAINT holds_account_currency FOREIGN KEY (account_id, currency)
        REFERENCES accounts (account_id, currency),
    CONSTRAINT holds_posted_range CHECK (posted_minor BETWEEN 0 AND amount_minor),
    CONSTRAINT holds_resolution CHECK ((state = 'pending') = (resolved_at IS NULL)),
    CONSTRAINT holds_posted_entry CHECK ((state = 'posted') = (entry_id IS NOT NULL)),
    CONSTRAINT holds_posted_amount CHECK ((state = 'posted') = (posted_minor > 0)),
    CONSTRAINT holds_ref_pair CHECK ((ref_type IS NULL) = (ref_id IS NULL)),
    CONSTRAINT holds_expiry CHECK (expires_at > created_at)
);
CREATE INDEX holds_pending_expiry ON holds (expires_at) WHERE state = 'pending';
CREATE INDEX holds_account ON holds (account_id, created_at DESC);
CREATE INDEX holds_ref ON holds (ref_type, ref_id) WHERE ref_type IS NOT NULL;

ALTER TABLE journal_entries
    ADD CONSTRAINT journal_entries_hold FOREIGN KEY (hold_id) REFERENCES holds (hold_id);

CREATE FUNCTION ledger_holds_after_insert() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_frozen  boolean;
    v_stripes smallint;
BEGIN
    IF NEW.state <> 'pending' THEN
        RAISE EXCEPTION 'hold % must be created pending', NEW.hold_id USING ERRCODE = 'BL005';
    END IF;
    SELECT stripes INTO v_stripes FROM accounts WHERE account_id = NEW.account_id;
    IF v_stripes <> 1 THEN
        RAISE EXCEPTION 'holds are not allowed on striped account %', NEW.account_id
            USING ERRCODE = 'BL007';
    END IF;
    UPDATE account_balances
       SET pending_minor = pending_minor + NEW.amount_minor,
           version = version + 1,
           updated_at = clock_timestamp()
     WHERE account_id = NEW.account_id AND stripe = 0
    RETURNING frozen INTO v_frozen;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no balance row for account %', NEW.account_id USING ERRCODE = 'BL006';
    END IF;
    IF v_frozen THEN
        RAISE EXCEPTION 'account % is frozen', NEW.account_id USING ERRCODE = 'BL001';
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER holds_after_insert AFTER INSERT ON holds
    FOR EACH ROW EXECUTE FUNCTION ledger_holds_after_insert();

CREATE FUNCTION ledger_holds_before_update() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF OLD.state <> 'pending' THEN
        RAISE EXCEPTION 'hold % is already %', OLD.hold_id, OLD.state USING ERRCODE = 'BL005';
    END IF;
    IF NEW.state NOT IN ('posted', 'voided', 'expired') THEN
        RAISE EXCEPTION 'hold % cannot move to %', OLD.hold_id, NEW.state USING ERRCODE = 'BL005';
    END IF;
    IF NEW.hold_id <> OLD.hold_id OR NEW.account_id <> OLD.account_id OR NEW.currency <> OLD.currency
       OR NEW.amount_minor <> OLD.amount_minor OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.reason <> OLD.reason OR NEW.expires_at <> OLD.expires_at
       OR NEW.created_at <> OLD.created_at OR NEW.ref_type IS DISTINCT FROM OLD.ref_type
       OR NEW.ref_id IS DISTINCT FROM OLD.ref_id THEN
        RAISE EXCEPTION 'hold % immutable field changed', OLD.hold_id USING ERRCODE = 'BL005';
    END IF;
    NEW.resolved_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER holds_before_update BEFORE UPDATE ON holds
    FOR EACH ROW EXECUTE FUNCTION ledger_holds_before_update();

CREATE FUNCTION ledger_holds_after_update() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    UPDATE account_balances
       SET pending_minor = pending_minor - OLD.amount_minor,
           version = version + 1,
           updated_at = clock_timestamp()
     WHERE account_id = OLD.account_id AND stripe = 0;
    RETURN NULL;
END $$;
CREATE TRIGGER holds_after_update AFTER UPDATE ON holds
    FOR EACH ROW EXECUTE FUNCTION ledger_holds_after_update();
CREATE TRIGGER holds_no_delete BEFORE DELETE ON holds
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();
CREATE TRIGGER holds_no_truncate BEFORE TRUNCATE ON holds
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_append_only();

-- ---------------------------------------------------------------------------
-- Reserves (escrowed value, e.g. offline allowances §3.A.3)
-- ---------------------------------------------------------------------------

CREATE TABLE reserves (
    reserve_id         uuid PRIMARY KEY REFERENCES accounts (account_id),
    funding_account_id uuid NOT NULL,
    currency           text NOT NULL,
    purpose            text NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_]{1,63}$'),
    ref_type           text CHECK (ref_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    ref_id             text CHECK (char_length(ref_id) BETWEEN 1 AND 128),
    state              reserve_state NOT NULL DEFAULT 'open',
    opened_entry_id    uuid NOT NULL REFERENCES journal_entries (entry_id),
    closed_entry_id    uuid REFERENCES journal_entries (entry_id),
    expires_at         timestamptz,
    idempotency_key    text NOT NULL UNIQUE,
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at          timestamptz,
    CONSTRAINT reserves_account_currency FOREIGN KEY (reserve_id, currency)
        REFERENCES accounts (account_id, currency),
    CONSTRAINT reserves_funding_currency FOREIGN KEY (funding_account_id, currency)
        REFERENCES accounts (account_id, currency),
    CONSTRAINT reserves_closed CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
    CONSTRAINT reserves_ref_pair CHECK ((ref_type IS NULL) = (ref_id IS NULL)),
    CONSTRAINT reserves_distinct CHECK (reserve_id <> funding_account_id)
);
CREATE INDEX reserves_open_expiry ON reserves (expires_at) WHERE state = 'open';
CREATE INDEX reserves_ref ON reserves (ref_type, ref_id) WHERE ref_type IS NOT NULL;

CREATE FUNCTION ledger_reserves_before_update() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF OLD.state <> 'open' OR NEW.state <> 'closed' THEN
        RAISE EXCEPTION 'reserve % cannot move from % to %', OLD.reserve_id, OLD.state, NEW.state
            USING ERRCODE = 'BL008';
    END IF;
    IF NEW.reserve_id <> OLD.reserve_id OR NEW.funding_account_id <> OLD.funding_account_id
       OR NEW.currency <> OLD.currency OR NEW.purpose <> OLD.purpose
       OR NEW.opened_entry_id <> OLD.opened_entry_id OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'reserve % immutable field changed', OLD.reserve_id USING ERRCODE = 'BL008';
    END IF;
    NEW.closed_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER reserves_before_update BEFORE UPDATE ON reserves
    FOR EACH ROW EXECUTE FUNCTION ledger_reserves_before_update();
CREATE TRIGGER reserves_no_delete BEFORE DELETE ON reserves
    FOR EACH ROW EXECUTE FUNCTION ledger_append_only();

-- ---------------------------------------------------------------------------
-- Idempotency (I4)
-- ---------------------------------------------------------------------------

CREATE TABLE idempotency_keys (
    idempotency_key text PRIMARY KEY CHECK (char_length(idempotency_key) BETWEEN 1 AND 255),
    scope           text NOT NULL CHECK (scope ~ '^[a-z][a-z0-9_.]{1,63}$'),
    request_hash    bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response        jsonb,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at    timestamptz
);
CREATE INDEX idempotency_keys_created ON idempotency_keys (created_at);

-- ---------------------------------------------------------------------------
-- Transactional outbox (I6)
-- ---------------------------------------------------------------------------

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
    CONSTRAINT outbox_terminal CHECK (published_at IS NULL OR dead_at IS NULL)
);
CREATE INDEX outbox_pending ON outbox (partition, id)
    WHERE published_at IS NULL AND dead_at IS NULL;
CREATE INDEX outbox_pending_key ON outbox (partition, msg_key, id)
    WHERE published_at IS NULL AND dead_at IS NULL;
CREATE INDEX outbox_published ON outbox (published_at) WHERE published_at IS NOT NULL;

CREATE FUNCTION ledger_outbox_notify() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM pg_notify('bilyon_outbox', '');
    RETURN NULL;
END $$;
CREATE TRIGGER outbox_notify AFTER INSERT ON outbox
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_outbox_notify();
