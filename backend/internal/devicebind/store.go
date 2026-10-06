package devicebind

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// Evidence sources: what verified a device's integrity or vouched for a key.
const (
	SourceAppAttestation = "app_attest_attestation"
	SourceAppAssertion   = "app_attest_assertion"
	SourceKeyAttestation = "android_key_attestation"
	SourcePlayIntegrity  = "play_integrity"
)

// Event topics (risk features and the offline CRL consume them).
const (
	TopicDeviceRegistered = "gateway.device.registered"
	TopicDeviceRevoked    = "gateway.device.revoked"
	TopicKeyBound         = "gateway.device.key_bound"
	TopicKeyRevoked       = "gateway.device.key_revoked"
	TopicCloneSignal      = "gateway.device.clone_signal"
	EventSource           = "bilyon.gateway"
)

// Integrity is a device's latest verified integrity evidence. Updates merge
// field by field, so an assertion keeps what the attestation recorded.
type Integrity struct {
	Source         string    `json:"source"`
	Environment    string    `json:"environment,omitempty"`   // iOS: App Attest production or development
	VerifiedBoot   string    `json:"verified_boot,omitempty"` // Android root of trust
	DeviceLocked   bool      `json:"device_locked,omitempty"`
	OSVersion      int64     `json:"os_version,omitempty"`
	PatchLevel     int64     `json:"patch_level,omitempty"`
	DeviceVerdicts []string  `json:"device_verdicts,omitempty"` // Play Integrity
	AppRecognition string    `json:"app_recognition,omitempty"`
	VerdictAt      time.Time `json:"verdict_at,omitzero"`
}

// Strong reports whether the latest Play Integrity verdict met strong
// integrity (Tier S eligibility, §3.A.1).
func (in Integrity) Strong() bool { return slices.Contains(in.DeviceVerdicts, MeetsStrongIntegrity) }

// Device is an attested app install.
type Device struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	Platform           string
	AppAttestKeyID     []byte  // iOS
	AppAttestPublicKey []byte  // iOS
	AppAttestCounter   *uint32 // iOS
	AppAttestReceipt   []byte  // iOS
	OSPatchLevel       *int64  // Android, YYYYMM
	Integrity          Integrity
	IntegrityAt        time.Time // when integrity was last verified
	CreatedAt          time.Time
	RevokedAt          *time.Time
	RevokeReason       string
}

// KeyAttestation records how a key was vouched for.
type KeyAttestation struct {
	Method                 string `json:"method"`
	AttestationVersion     int64  `json:"attestation_version,omitempty"`
	KeyMintVersion         int64  `json:"keymint_version,omitempty"`
	OSVersion              int64  `json:"os_version,omitempty"`
	PatchLevel             int64  `json:"patch_level,omitempty"`
	AuthTimeoutSeconds     int64  `json:"auth_timeout_s,omitempty"`
	UnlockedDeviceRequired bool   `json:"unlocked_device_required,omitempty"`
	AppAttestCounter       uint32 `json:"app_attest_counter,omitempty"`
}

// Key is a bound hardware key.
type Key struct {
	ID            uuid.UUID
	DeviceID      uuid.UUID
	UserID        uuid.UUID
	Role          string
	PublicKey     []byte // x963 P-256 point
	SecurityLevel string
	Attestation   KeyAttestation
	CreatedAt     time.Time
	RevokedAt     *time.Time
	RevokeReason  string
}

// deviceUpdate is what a verified proof changes on a device.
type deviceUpdate struct {
	Counter    *uint32 // new App Attest counter (strictly greater)
	PatchLevel *int64
	Integrity  Integrity
	At         time.Time
}

type store struct {
	pool *pgxpool.Pool
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const deviceColumns = `device_id, user_id, platform, app_attest_key_id, app_attest_pubkey, app_attest_counter,
	app_attest_receipt, os_patch_level, integrity, integrity_at, created_at, revoked_at, revoke_reason`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	var counter, patch *int64
	var integrity []byte
	var reason *string
	err := row.Scan(&d.ID, &d.UserID, &d.Platform, &d.AppAttestKeyID, &d.AppAttestPublicKey, &counter,
		&d.AppAttestReceipt, &patch, &integrity, &d.IntegrityAt, &d.CreatedAt, &d.RevokedAt, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	if counter != nil {
		c := uint32(*counter)
		d.AppAttestCounter = &c
	}
	d.OSPatchLevel = patch
	if err := json.Unmarshal(integrity, &d.Integrity); err != nil {
		return Device{}, fmt.Errorf("devicebind: device %s integrity: %w", d.ID, err)
	}
	if reason != nil {
		d.RevokeReason = *reason
	}
	d.IntegrityAt, d.CreatedAt = d.IntegrityAt.UTC(), d.CreatedAt.UTC()
	if d.RevokedAt != nil {
		t := d.RevokedAt.UTC()
		d.RevokedAt = &t
	}
	return d, nil
}

const keyColumns = `key_id, device_id, user_id, role, public_key, security_level, attestation, created_at,
	revoked_at, revoke_reason`

func scanKey(row pgx.Row, extra ...any) (Key, error) {
	var k Key
	var att []byte
	var reason *string
	dest := append([]any{&k.ID, &k.DeviceID, &k.UserID, &k.Role, &k.PublicKey, &k.SecurityLevel, &att,
		&k.CreatedAt, &k.RevokedAt, &reason}, extra...)
	err := row.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	if err != nil {
		return Key{}, err
	}
	if err := json.Unmarshal(att, &k.Attestation); err != nil {
		return Key{}, fmt.Errorf("devicebind: key %s attestation: %w", k.ID, err)
	}
	if reason != nil {
		k.RevokeReason = *reason
	}
	k.CreatedAt = k.CreatedAt.UTC()
	if k.RevokedAt != nil {
		t := k.RevokedAt.UTC()
		k.RevokedAt = &t
	}
	return k, nil
}

func (s *store) device(ctx context.Context, q querier, id uuid.UUID) (Device, error) {
	return scanDevice(q.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE device_id = $1`, id))
}

func (s *store) devicesForUser(ctx context.Context, userID uuid.UUID) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deviceColumns+` FROM devices
		WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at, device_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *store) keysForDevice(ctx context.Context, deviceID uuid.UUID) ([]Key, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+keyColumns+` FROM device_keys
		WHERE device_id = $1 AND revoked_at IS NULL ORDER BY created_at, key_id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// activeRoleKey returns the device's active K_dev or K_gest.
func (s *store) activeRoleKey(ctx context.Context, deviceID uuid.UUID, role string) (Key, error) {
	return scanKey(s.pool.QueryRow(ctx, `SELECT `+keyColumns+` FROM device_keys
		WHERE device_id = $1 AND role = $2 AND revoked_at IS NULL`, deviceID, role))
}

func (s *store) activeKey(ctx context.Context, keyID uuid.UUID) (Key, error) {
	var deviceRevoked bool
	k, err := scanKey(s.pool.QueryRow(ctx, `SELECT `+keyColumns+`,
			(SELECT d.revoked_at IS NOT NULL FROM devices d WHERE d.device_id = device_keys.device_id)
		FROM device_keys WHERE key_id = $1`, keyID), &deviceRevoked)
	if err != nil {
		return Key{}, err
	}
	if k.RevokedAt != nil || deviceRevoked {
		return Key{}, ErrRevoked
	}
	return k, nil
}

// LockActiveKey loads an active key in the caller's transaction, share-locks
// it and locks its device row. Writes that follow serialise with key and
// device revocation, and with each other per device: the intent
// orchestrator counts K_gest velocity under this lock.
func LockActiveKey(ctx context.Context, tx pgx.Tx, keyID uuid.UUID) (Key, error) {
	var deviceRevoked bool
	k, err := scanKey(tx.QueryRow(ctx, `SELECT `+prefixed("k.", keyColumns)+`, d.revoked_at IS NOT NULL
		FROM device_keys k JOIN devices d ON d.device_id = k.device_id
		WHERE k.key_id = $1 FOR NO KEY UPDATE OF d FOR SHARE OF k`, keyID), &deviceRevoked)
	if err != nil {
		return Key{}, err
	}
	if k.RevokedAt != nil || deviceRevoked {
		return Key{}, ErrRevoked
	}
	return k, nil
}

// prefixed qualifies a comma-separated column list with a table alias.
func prefixed(alias, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = alias + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

func emit(ctx context.Context, tx pgx.Tx, topic string, userID uuid.UUID, data map[string]any) error {
	_, err := outbox.Write(ctx, tx, outbox.Event{Source: EventSource, Topic: topic, Key: "user:" + userID.String(),
		Subject: userID.String(), Data: data})
	return err
}

func uniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

func counterArg(c *uint32) *int64 {
	if c == nil {
		return nil
	}
	v := int64(*c)
	return &v
}

// registerDevice stores a new device with its first key.
func (s *store) registerDevice(ctx context.Context, d Device, k Key) (Binding, error) {
	var err error
	if d.ID, err = uuid.NewV7(); err != nil {
		return Binding{}, err
	}
	integrity, err := json.Marshal(d.Integrity)
	if err != nil {
		return Binding{}, err
	}
	var out Binding
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		dev, err := scanDevice(tx.QueryRow(ctx, `INSERT INTO devices (device_id, user_id, platform, app_attest_key_id,
				app_attest_pubkey, app_attest_counter, app_attest_receipt, os_patch_level, integrity, integrity_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING `+deviceColumns,
			d.ID, d.UserID, d.Platform, d.AppAttestKeyID, d.AppAttestPublicKey, counterArg(d.AppAttestCounter),
			d.AppAttestReceipt, d.OSPatchLevel, integrity, d.IntegrityAt))
		if uniqueViolation(err, "devices_app_attest_key_id_key") {
			return reject("ios.attestation", "the App Attest key is already registered")
		}
		if err != nil {
			return err
		}
		if err := emit(ctx, tx, TopicDeviceRegistered, dev.UserID, map[string]any{
			"user_id": dev.UserID, "device_id": dev.ID, "platform": dev.Platform}); err != nil {
			return err
		}
		key, err := insertKey(ctx, tx, dev, k)
		if err != nil {
			return err
		}
		out = Binding{Device: dev, Key: key}
		return nil
	})
	return out, err
}

// lockDevice loads one of the user's active devices and locks its row.
func lockDevice(ctx context.Context, tx pgx.Tx, userID, deviceID uuid.UUID) (Device, error) {
	d, err := scanDevice(tx.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE device_id = $1 FOR UPDATE`, deviceID))
	if err != nil {
		return Device{}, err
	}
	if d.UserID != userID {
		return Device{}, ErrNotFound
	}
	if d.RevokedAt != nil {
		return Device{}, ErrRevoked
	}
	return d, nil
}

// applyUpdate records a verified proof on a locked device.
func applyUpdate(ctx context.Context, tx pgx.Tx, d Device, up deviceUpdate) (Device, error) {
	integrity, err := json.Marshal(up.Integrity)
	if err != nil {
		return Device{}, err
	}
	out, err := scanDevice(tx.QueryRow(ctx, `UPDATE devices SET
			app_attest_counter = coalesce($2, app_attest_counter),
			os_patch_level = coalesce($3, os_patch_level),
			integrity = integrity || $4::jsonb,
			integrity_at = greatest(integrity_at, $5)
		WHERE device_id = $1 AND ($2::bigint IS NULL OR app_attest_counter < $2::bigint)
		RETURNING `+deviceColumns, d.ID, counterArg(up.Counter), up.PatchLevel, integrity, up.At))
	if errors.Is(err, ErrNotFound) {
		return Device{}, reject(checkCounter, "App Attest counter did not advance")
	}
	return out, err
}

// insertKey binds a key to a device; a new K_dev or K_gest supersedes the
// device's previous one.
func insertKey(ctx context.Context, tx pgx.Tx, d Device, k Key) (Key, error) {
	var err error
	if k.ID, err = uuid.NewV7(); err != nil {
		return Key{}, err
	}
	if k.Role == RoleDevice || k.Role == RoleGesture {
		rows, err := tx.Query(ctx, `UPDATE device_keys SET revoked_at = clock_timestamp(), revoke_reason = 'superseded'
			WHERE device_id = $1 AND role = $2 AND revoked_at IS NULL RETURNING key_id`, d.ID, k.Role)
		if err != nil {
			return Key{}, err
		}
		superseded, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return Key{}, err
		}
		for _, id := range superseded {
			if err := emit(ctx, tx, TopicKeyRevoked, d.UserID, map[string]any{"user_id": d.UserID, "device_id": d.ID,
				"key_id": id, "role": k.Role, "reason": "superseded"}); err != nil {
				return Key{}, err
			}
		}
	}
	att, err := json.Marshal(k.Attestation)
	if err != nil {
		return Key{}, err
	}
	key, err := scanKey(tx.QueryRow(ctx, `INSERT INTO device_keys (key_id, device_id, user_id, role, public_key,
			security_level, attestation) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+keyColumns,
		k.ID, d.ID, d.UserID, k.Role, k.PublicKey, k.SecurityLevel, att))
	if uniqueViolation(err, "device_keys_public_key_key") {
		return Key{}, ErrKeyExists
	}
	if err != nil {
		return Key{}, err
	}
	return key, emit(ctx, tx, TopicKeyBound, d.UserID, map[string]any{"user_id": d.UserID, "device_id": d.ID,
		"key_id": key.ID, "role": key.Role, "platform": d.Platform, "security_level": key.SecurityLevel})
}

// addKey verifies a binding against the locked device (check may amend
// the key) and stores the key with the device update, atomically.
func (s *store) addKey(ctx context.Context, userID, deviceID uuid.UUID, k Key,
	check func(d Device, k *Key) (deviceUpdate, error)) (Binding, error) {
	var out Binding
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := lockDevice(ctx, tx, userID, deviceID)
		if err != nil {
			return err
		}
		up, err := check(d, &k)
		if err != nil {
			return err
		}
		if d, err = applyUpdate(ctx, tx, d, up); err != nil {
			return err
		}
		key, err := insertKey(ctx, tx, d, k)
		if err != nil {
			return err
		}
		out = Binding{Device: d, Key: key}
		return nil
	})
	return out, err
}

// refresh verifies a proof against the locked device and records it.
func (s *store) refresh(ctx context.Context, userID, deviceID uuid.UUID, check func(d Device) (deviceUpdate, error)) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := lockDevice(ctx, tx, userID, deviceID)
		if err != nil {
			return err
		}
		up, err := check(d)
		if err != nil {
			return err
		}
		_, err = applyUpdate(ctx, tx, d, up)
		return err
	})
}

func (s *store) revokeDevice(ctx context.Context, userID, deviceID uuid.UUID, reason string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		d, err := scanDevice(tx.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE device_id = $1 FOR UPDATE`, deviceID))
		if err != nil {
			return err
		}
		if d.UserID != userID {
			return ErrNotFound
		}
		if d.RevokedAt != nil {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET revoked_at = clock_timestamp(), revoke_reason = $2
			WHERE device_id = $1`, deviceID, reason); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE device_keys SET revoked_at = clock_timestamp(), revoke_reason = $2
			WHERE device_id = $1 AND revoked_at IS NULL RETURNING key_id`, deviceID, reason)
		if err != nil {
			return err
		}
		keys, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		return emit(ctx, tx, TopicDeviceRevoked, userID, map[string]any{"user_id": userID, "device_id": deviceID,
			"reason": reason, "key_ids": keys})
	})
}

func (s *store) revokeKey(ctx context.Context, userID, keyID uuid.UUID, reason string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var owner, deviceID uuid.UUID
		var role string
		var revoked bool
		err := tx.QueryRow(ctx, `SELECT user_id, device_id, role, revoked_at IS NOT NULL FROM device_keys
			WHERE key_id = $1 FOR UPDATE`, keyID).Scan(&owner, &deviceID, &role, &revoked)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != userID) {
			return ErrNotFound
		}
		if err != nil || revoked {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE device_keys SET revoked_at = clock_timestamp(), revoke_reason = $2
			WHERE key_id = $1`, keyID, reason); err != nil {
			return err
		}
		return emit(ctx, tx, TopicKeyRevoked, userID, map[string]any{"user_id": userID, "device_id": deviceID,
			"key_id": keyID, "role": role, "reason": reason})
	})
}

func (s *store) emitCloneSignal(ctx context.Context, userID, deviceID uuid.UUID, reason string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return emit(ctx, tx, TopicCloneSignal, userID, map[string]any{"user_id": userID, "device_id": deviceID,
			"reason": reason})
	})
}
