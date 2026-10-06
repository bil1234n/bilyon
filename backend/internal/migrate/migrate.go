// Package migrate applies forward-only SQL migrations to PostgreSQL.
//
// Guarantees:
//   - Concurrent migrators are serialised with a session-level advisory lock,
//     so rolling deploys can all run "migrate on start" safely.
//   - Each migration runs in its own transaction together with its
//     bookkeeping row, unless it opts out with "-- bilyon:no-transaction".
//   - An applied migration whose file content changed is a hard error
//     (checksum mismatch): history is never silently rewritten.
//   - A pending migration older than the newest applied one is a hard error,
//     because applying it out of order could invalidate later migrations.
package migrate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultLockKey is the advisory lock key used to serialise migrators
// (an arbitrary constant: "bilyon" in ASCII, as an int64).
const DefaultLockKey int64 = 0x62696c796f6e

const noTxDirective = "-- bilyon:no-transaction"

var (
	fileName  = regexp.MustCompile(`^(\d{4,})_([a-z0-9_]+)\.sql$`)
	tableName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
)

// Migration is one SQL file.
type Migration struct {
	Version       int64
	Name          string
	SQL           string
	Checksum      [32]byte
	NoTransaction bool
}

// Load reads and orders the migrations in dir. Versions must be unique.
func Load(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: read %s: %w", dir, err)
	}
	var out []Migration
	seen := map[int64]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migrate: %q does not match NNNN_name.sql", e.Name())
		}
		version, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migrate: invalid version in %q", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrate: version %d used by both %q and %q", version, prev, e.Name())
		}
		seen[version] = e.Name()
		raw, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("migrate: read %s: %w", e.Name(), err)
		}
		sql := string(raw)
		out = append(out, Migration{
			Version:       version,
			Name:          m[2],
			SQL:           sql,
			Checksum:      sha256.Sum256(raw),
			NoTransaction: strings.HasPrefix(strings.TrimSpace(sql), noTxDirective),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	if len(out) == 0 {
		return nil, fmt.Errorf("migrate: no migrations in %s", dir)
	}
	return out, nil
}

// AppliedMigration is a row of the bookkeeping table.
type AppliedMigration struct {
	Version   int64
	Name      string
	Checksum  []byte
	AppliedAt time.Time
	Duration  time.Duration
}

// Options configures Apply.
type Options struct {
	// Table is the bookkeeping table (default "schema_migrations").
	Table string
	// LockKey is the advisory lock key (default DefaultLockKey).
	LockKey int64
	// Logger receives one line per applied migration (default: discard).
	Logger *slog.Logger
}

func (o *Options) normalise() error {
	if o.Table == "" {
		o.Table = "schema_migrations"
	}
	if !tableName.MatchString(o.Table) {
		return fmt.Errorf("migrate: invalid table name %q", o.Table)
	}
	if o.LockKey == 0 {
		o.LockKey = DefaultLockKey
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return nil
}

// ErrChecksumMismatch reports an applied migration whose file changed.
var ErrChecksumMismatch = errors.New("migrate: applied migration was modified")

// ErrOutOfOrder reports a pending migration older than the newest applied one.
var ErrOutOfOrder = errors.New("migrate: pending migration is older than an applied one")

// Apply runs every pending migration and returns the ones it applied.
func Apply(ctx context.Context, pool *pgxpool.Pool, migrations []Migration, opts Options) ([]Migration, error) {
	if err := opts.normalise(); err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", opts.LockKey); err != nil {
		return nil, fmt.Errorf("migrate: take advisory lock: %w", err)
	}
	defer func() {
		// Use a fresh context: the caller's may already be cancelled, and a
		// leaked session lock would block every future migrator.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", opts.LockKey); err != nil {
			conn.Conn().Close(unlockCtx)
		}
	}()

	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		version      bigint PRIMARY KEY,
		name         text NOT NULL,
		checksum     bytea NOT NULL,
		applied_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
		execution_ms integer NOT NULL
	)`, opts.Table)); err != nil {
		return nil, fmt.Errorf("migrate: create %s: %w", opts.Table, err)
	}

	applied, err := listApplied(ctx, conn.Conn(), opts.Table)
	if err != nil {
		return nil, err
	}
	if err := verify(migrations, applied); err != nil {
		return nil, err
	}

	var done []Migration
	for _, m := range migrations {
		if _, ok := applied[m.Version]; ok {
			continue
		}
		start := time.Now()
		if err := applyOne(ctx, conn.Conn(), opts.Table, m); err != nil {
			return done, err
		}
		elapsed := time.Since(start)
		opts.Logger.InfoContext(ctx, "migration applied",
			slog.Int64("version", m.Version), slog.String("name", m.Name), slog.Duration("took", elapsed))
		done = append(done, m)
	}
	return done, nil
}

func listApplied(ctx context.Context, conn *pgx.Conn, table string) (map[int64]AppliedMigration, error) {
	rows, err := conn.Query(ctx, fmt.Sprintf(
		"SELECT version, name, checksum, applied_at, execution_ms FROM %s ORDER BY version", table))
	if err != nil {
		return nil, fmt.Errorf("migrate: list applied: %w", err)
	}
	defer rows.Close()
	out := map[int64]AppliedMigration{}
	for rows.Next() {
		var a AppliedMigration
		var ms int32
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt, &ms); err != nil {
			return nil, fmt.Errorf("migrate: scan applied: %w", err)
		}
		a.Duration = time.Duration(ms) * time.Millisecond
		out[a.Version] = a
	}
	return out, rows.Err()
}

func verify(migrations []Migration, applied map[int64]AppliedMigration) error {
	known := map[int64]Migration{}
	var newestApplied int64
	for _, m := range migrations {
		known[m.Version] = m
	}
	for v, a := range applied {
		m, ok := known[v]
		if !ok {
			// A newer binary may have applied migrations this one does not
			// know; running older code against a newer schema is the
			// operator's call, but never re-apply or rewrite history.
			continue
		}
		if string(m.Checksum[:]) != string(a.Checksum) {
			return fmt.Errorf("%w: version %d (%s)", ErrChecksumMismatch, v, m.Name)
		}
		newestApplied = max(newestApplied, v)
	}
	for _, m := range migrations {
		if _, ok := applied[m.Version]; !ok && m.Version < newestApplied {
			return fmt.Errorf("%w: version %d (%s) < %d", ErrOutOfOrder, m.Version, m.Name, newestApplied)
		}
	}
	return nil
}

func applyOne(ctx context.Context, conn *pgx.Conn, table string, m Migration) error {
	record := fmt.Sprintf("INSERT INTO %s (version, name, checksum, execution_ms) VALUES ($1, $2, $3, $4)", table)
	start := time.Now()
	if m.NoTransaction {
		if _, err := conn.Exec(ctx, m.SQL); err != nil {
			return fmt.Errorf("migrate: %04d_%s: %w", m.Version, m.Name, err)
		}
		if _, err := conn.Exec(ctx, record, m.Version, m.Name, m.Checksum[:], elapsedMS(start)); err != nil {
			return fmt.Errorf("migrate: record %04d_%s: %w", m.Version, m.Name, err)
		}
		return nil
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate: begin %04d_%s: %w", m.Version, m.Name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("migrate: %04d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.Exec(ctx, record, m.Version, m.Name, m.Checksum[:], elapsedMS(start)); err != nil {
		return fmt.Errorf("migrate: record %04d_%s: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migrate: commit %04d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}

func elapsedMS(start time.Time) int32 {
	ms := time.Since(start).Milliseconds()
	if ms > int64(^uint32(0)>>1) {
		return int32(^uint32(0) >> 1)
	}
	return int32(ms)
}

// Status reports, for every known migration, whether it is applied.
func Status(ctx context.Context, pool *pgxpool.Pool, migrations []Migration, table string) ([]StatusLine, error) {
	if table == "" {
		table = "schema_migrations"
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil {
		return nil, err
	}
	applied := map[int64]AppliedMigration{}
	if exists {
		if applied, err = listApplied(ctx, conn.Conn(), table); err != nil {
			return nil, err
		}
	}
	out := make([]StatusLine, 0, len(migrations))
	for _, m := range migrations {
		line := StatusLine{Version: m.Version, Name: m.Name}
		if a, ok := applied[m.Version]; ok {
			line.Applied = true
			line.AppliedAt = a.AppliedAt
			line.Modified = string(a.Checksum) != string(m.Checksum[:])
		}
		out = append(out, line)
	}
	return out, nil
}

// StatusLine describes one migration for operators.
type StatusLine struct {
	Version   int64
	Name      string
	Applied   bool
	Modified  bool
	AppliedAt time.Time
}
