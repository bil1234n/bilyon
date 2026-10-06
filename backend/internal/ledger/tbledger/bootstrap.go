package tbledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
)

// ErrAlreadyBootstrapped means the shadow's cursor already exists.
var ErrAlreadyBootstrapped = errors.New("tbledger: the shadow is already bootstrapped")

// BootstrapStats summarises a bootstrap.
type BootstrapStats struct {
	Accounts int   `json:"accounts"`
	Balances int   `json:"opening_balances"`
	Holds    int   `json:"pending_holds"`
	Position int64 `json:"position"`
	CatchUp  int   `json:"catch_up_rows"`
}

// bootstrapPage is the page size of the snapshot import.
const bootstrapPage = 2000

// Bootstrap imports the ledger's current state into an empty TigerBeetle
// cluster and registers the shadow's cursor, so that the tailer continues
// exactly where the imported state ends.
//
// Every account, balance and pending hold is read in one REPEATABLE READ
// snapshot S and mirrored: accounts (with their limits), one opening transfer
// per non-zero posted balance, and the pending holds. Outbox rows visible in
// S are therefore already reflected; rows of transactions in flight at S are
// collected once those transactions finish and handed to the tailer as gaps,
// and tailing resumes after the highest id visible in S.
//
// A bootstrap that fails part-way leaves the cursor in the bootstrapping
// state. TigerBeetle then holds part of an import from a snapshot that can
// never be read again, so the cluster must be reformatted and ResetBootstrap
// called before retrying.
//
// Bootstrap fails with ErrLocked while a tailer of the consumer runs.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, d *Driver, consumer string, log *slog.Logger) (BootstrapStats, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	lock, err := lockSession(ctx, pool, consumer, time.Nanosecond, time.Millisecond, log)
	if err != nil {
		return BootstrapStats{}, err
	}
	defer func() { _ = lock.Close(context.WithoutCancel(ctx)) }()
	return bootstrap(ctx, pool, d, consumer, log)
}

// bootstrap runs a bootstrap; the caller holds the consumer's lock.
func bootstrap(ctx context.Context, pool *pgxpool.Pool, d *Driver, consumer string, log *slog.Logger) (BootstrapStats, error) {
	var stats BootstrapStats
	if _, err := pool.Exec(ctx, `INSERT INTO outbox_cursors (consumer, state) VALUES ($1, 'bootstrapping')`, consumer); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			_, state, lerr := loadCursor(ctx, pool, consumer)
			if lerr != nil {
				return stats, lerr
			}
			if state == stateTailing {
				return stats, ErrAlreadyBootstrapped
			}
			return stats, ErrBootstrapIncomplete
		}
		return stats, fmt.Errorf("tbledger: claim cursor: %w", err)
	}

	snap, err := importSnapshot(ctx, pool, d, &stats, log)
	if err != nil {
		return stats, err
	}
	if err := awaitSnapshot(ctx, pool, snap); err != nil {
		return stats, err
	}
	// Rows at or below the position that the snapshot did not show belong to
	// transactions that were in flight; they have all finished now, so the
	// set is final. The tailer applies them before anything newer.
	rows, err := pool.Query(ctx, `SELECT id FROM outbox
		WHERE id <= $1 AND txid >= pg_snapshot_xmin($2::pg_snapshot) AND NOT pg_visible_in_snapshot(txid, $2::pg_snapshot)
		ORDER BY id`, stats.Position, snap)
	if err != nil {
		return stats, fmt.Errorf("tbledger: catch-up rows: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return stats, fmt.Errorf("tbledger: catch-up rows: %w", err)
	}
	stats.CatchUp = len(ids)
	cur := cursor{lastID: stats.Position}
	if len(ids) > 0 {
		cur.gaps = []gapSet{{Snapshot: snap, Ranges: toRanges(ids)}}
	}
	raw, err := json.Marshal(append([]gapSet{}, cur.gaps...))
	if err != nil {
		return stats, err
	}
	tag, err := pool.Exec(ctx, `UPDATE outbox_cursors SET state = 'tailing', last_id = $2, horizon = $3, gaps = $4,
			updated_at = clock_timestamp()
		WHERE consumer = $1 AND state = 'bootstrapping'`, consumer, cur.lastID, cur.horizon(), raw)
	if err != nil {
		return stats, fmt.Errorf("tbledger: register cursor: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return stats, fmt.Errorf("tbledger: cursor %q changed during bootstrap", consumer)
	}
	log.InfoContext(ctx, "shadow bootstrapped", slog.Int("accounts", stats.Accounts), slog.Int("balances", stats.Balances),
		slog.Int("holds", stats.Holds), slog.Int64("position", stats.Position), slog.Int("catch_up", stats.CatchUp))
	return stats, nil
}

// importSnapshot mirrors the state visible in one snapshot and returns it.
func importSnapshot(ctx context.Context, pool *pgxpool.Pool, d *Driver, stats *BootstrapStats, log *slog.Logger) (string, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var snap string
	if err := tx.QueryRow(ctx, `SELECT pg_current_snapshot()::text, coalesce((SELECT max(id) FROM outbox), 0)`).
		Scan(&snap, &stats.Position); err != nil {
		return "", err
	}
	after := uuid.Nil
	for {
		accts, err := pgledger.ListAccountsIn(ctx, tx, after, bootstrapPage)
		if err != nil {
			return "", err
		}
		if len(accts) == 0 {
			break
		}
		if err := d.CreateAccounts(accts); err != nil {
			return "", fmt.Errorf("tbledger: import accounts: %w", err)
		}
		ids := make([]uuid.UUID, len(accts))
		for i, a := range accts {
			ids[i] = a.ID
		}
		bals, err := pgledger.BalancesIn(ctx, tx, ids)
		if err != nil {
			return "", err
		}
		var openings []Opening
		for _, a := range accts {
			if b := bals[a.ID]; b.Posted != 0 {
				openings = append(openings, Opening{Account: a, Posted: b.Posted})
			}
		}
		if err := d.OpenBalances(openings); err != nil {
			return "", fmt.Errorf("tbledger: import balances: %w", err)
		}
		stats.Accounts += len(accts)
		stats.Balances += len(openings)
		after = accts[len(accts)-1].ID
		log.DebugContext(ctx, "bootstrap progress", slog.Int("accounts", stats.Accounts))
	}
	after = uuid.Nil
	for {
		holds, err := pgledger.PendingHoldsIn(ctx, tx, after, bootstrapPage)
		if err != nil {
			return "", err
		}
		if len(holds) == 0 {
			break
		}
		if err := d.placeHolds(holds); err != nil {
			return "", fmt.Errorf("tbledger: import holds: %w", err)
		}
		stats.Holds += len(holds)
		after = holds[len(holds)-1].ID
	}
	return snap, tx.Commit(ctx)
}

// awaitSnapshot waits until every transaction in flight at snap has ended.
func awaitSnapshot(ctx context.Context, pool *pgxpool.Pool, snap string) error {
	for {
		var done bool
		if err := pool.QueryRow(ctx, `SELECT NOT EXISTS (
				SELECT 1 FROM pg_snapshot_xip($1::pg_snapshot) AS x WHERE pg_xact_status(x) = 'in progress')`,
			snap).Scan(&done); err != nil {
			return fmt.Errorf("tbledger: in-flight transactions: %w", err)
		}
		if done {
			return nil
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// toRanges compresses ascending ids into inclusive ranges.
func toRanges(ids []int64) [][2]int64 {
	var out [][2]int64
	for _, id := range ids {
		if n := len(out); n > 0 && out[n-1][1] == id-1 {
			out[n-1][1] = id
			continue
		}
		out = append(out, [2]int64{id, id})
	}
	return out
}

// ResetBootstrap removes the cursor of a bootstrap that did not finish. The
// TigerBeetle cluster must be reformatted as well before bootstrapping again.
func ResetBootstrap(ctx context.Context, pool *pgxpool.Pool, consumer string) error {
	tag, err := pool.Exec(ctx, `DELETE FROM outbox_cursors WHERE consumer = $1 AND state = 'bootstrapping'`, consumer)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: no unfinished bootstrap for %q", ledger.ErrNotFound, consumer)
	}
	return nil
}
