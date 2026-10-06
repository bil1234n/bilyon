-- Gateway schema, part 2: attested devices and their hardware-bound keys
-- (RFC 0001 §2.2.4).
--
-- A device is one attested app install. On iOS it is identified by its App
-- Attest key, which vouches for every key bound later through assertions;
-- on Android every key carries its own Key Attestation chain and the
-- binding is backed by a Play Integrity verdict. K_dev, K_gest and K_off
-- keys live in the Secure Enclave, StrongBox or the TEE; a row exists only
-- after the platform attestation verified.

CREATE TABLE devices (
    device_id          uuid PRIMARY KEY,
    user_id            uuid NOT NULL REFERENCES users,
    platform           text NOT NULL CHECK (platform IN ('ios', 'android')),
    -- iOS: the App Attest key, its assertion counter and the attestation
    -- receipt (kept for Apple's fraud-metric refresh).
    app_attest_key_id  bytea UNIQUE CHECK (octet_length(app_attest_key_id) = 32),
    app_attest_pubkey  bytea CHECK (octet_length(app_attest_pubkey) = 65),
    app_attest_counter bigint CHECK (app_attest_counter BETWEEN 0 AND 4294967295),
    app_attest_receipt bytea,
    -- Android: the attested OS patch level (YYYYMM) of the latest binding.
    os_patch_level     integer,
    -- Latest verified integrity facts and when they were verified: the
    -- attestation, an App Attest assertion or a Play Integrity verdict.
    integrity          jsonb NOT NULL DEFAULT '{}'::jsonb,
    integrity_at       timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at         timestamptz,
    revoke_reason      text,
    CHECK ((platform = 'ios') = (app_attest_key_id IS NOT NULL)),
    CHECK ((app_attest_key_id IS NULL) = (app_attest_pubkey IS NULL)
       AND (app_attest_key_id IS NULL) = (app_attest_counter IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX devices_user ON devices (user_id) WHERE revoked_at IS NULL;

CREATE TABLE device_keys (
    key_id          uuid PRIMARY KEY,
    device_id       uuid NOT NULL REFERENCES devices,
    user_id         uuid NOT NULL REFERENCES users,
    role            text NOT NULL CHECK (role IN ('dev', 'gest', 'off')),
    -- SEC1 uncompressed P-256 point of the bound key; a key is bound once.
    public_key      bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 65),
    security_level  text NOT NULL CHECK (security_level IN ('secure_enclave', 'trusted_environment', 'strongbox')),
    attestation     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at      timestamptz,
    revoke_reason   text,
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
-- One active K_dev and one active K_gest per device: re-binding (after a
-- biometric enrolment change) revokes the previous key in the same
-- transaction. K_off keys are one per allowance, so there may be many.
CREATE UNIQUE INDEX device_keys_active_role ON device_keys (device_id, role)
    WHERE revoked_at IS NULL AND role IN ('dev', 'gest');
CREATE INDEX device_keys_device ON device_keys (device_id) WHERE revoked_at IS NULL;
