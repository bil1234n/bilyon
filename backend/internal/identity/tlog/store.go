package tlog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/cose"
)

// Log is the PostgreSQL-backed log (tables tlog_head, tlog_leaves,
// tlog_nodes and tlog_sths of the gateway schema).
type Log struct {
	pool *pgxpool.Pool
}

// New returns the log over a migrated gateway database.
func New(pool *pgxpool.Pool) *Log { return &Log{pool: pool} }

// Append adds a leaf inside the caller's transaction, so the leaf commits
// with the change it records, and returns its index. Appends serialise on
// the log head row.
func (l *Log) Append(ctx context.Context, tx pgx.Tx, leaf []byte) (uint64, error) {
	var size int64
	if err := tx.QueryRow(ctx, `SELECT size FROM tlog_head WHERE id = 1 FOR UPDATE`).Scan(&size); err != nil {
		return 0, fmt.Errorf("tlog: head: %w", err)
	}
	idx := uint64(size)
	if _, err := tx.Exec(ctx, `INSERT INTO tlog_leaves (idx, data) VALUES ($1, $2)`, size, leaf); err != nil {
		return 0, err
	}
	h := LeafHash(leaf)
	if _, err := tx.Exec(ctx, `INSERT INTO tlog_nodes (level, idx, hash) VALUES (0, $1, $2)`, size, h[:]); err != nil {
		return 0, err
	}
	// Each time the new leaf completes a subtree, store the subtree's hash.
	for level, i := 0, idx; i&1 == 1; level, i = level+1, i>>1 {
		var left []byte
		if err := tx.QueryRow(ctx, `SELECT hash FROM tlog_nodes WHERE level = $1 AND idx = $2`, level, int64(i-1)).Scan(&left); err != nil {
			return 0, fmt.Errorf("tlog: subtree (%d, %d): %w", level, i-1, err)
		}
		h = NodeHash(Hash(left), h)
		if _, err := tx.Exec(ctx, `INSERT INTO tlog_nodes (level, idx, hash) VALUES ($1, $2, $3)`,
			level+1, int64(i>>1), h[:]); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE tlog_head SET size = $1 WHERE id = 1`, size+1); err != nil {
		return 0, err
	}
	return idx, nil
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Size is the number of leaves.
func (l *Log) Size(ctx context.Context) (uint64, error) {
	var size int64
	err := l.pool.QueryRow(ctx, `SELECT size FROM tlog_head WHERE id = 1`).Scan(&size)
	return uint64(size), err
}

// fetch loads complete subtree hashes in one query.
func fetch(ctx context.Context, q querier, nodes []node) (map[node]Hash, error) {
	levels := make([]int16, len(nodes))
	idxs := make([]int64, len(nodes))
	for i, n := range nodes {
		levels[i], idxs[i] = int16(n.Level), int64(n.Index)
	}
	rows, err := q.Query(ctx, `SELECT n.level, n.idx, n.hash FROM tlog_nodes n
		JOIN unnest($1::smallint[], $2::bigint[]) AS w(level, idx) ON n.level = w.level AND n.idx = w.idx`, levels, idxs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[node]Hash, len(nodes))
	for rows.Next() {
		var level int16
		var idx int64
		var h []byte
		if err := rows.Scan(&level, &idx, &h); err != nil {
			return nil, err
		}
		out[node{uint8(level), uint64(idx)}] = Hash(h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(nodes) {
		return nil, fmt.Errorf("tlog: %d of %d subtree hashes missing", len(nodes)-len(out), len(nodes))
	}
	return out, nil
}

func (l *Log) checkSize(ctx context.Context, sizes ...uint64) error {
	cur, err := l.Size(ctx)
	if err != nil {
		return err
	}
	for _, s := range sizes {
		if s > cur {
			return fmt.Errorf("%w: size %d beyond the log's %d", ErrRange, s, cur)
		}
	}
	return nil
}

// Root is the root of the first size leaves.
func (l *Log) Root(ctx context.Context, size uint64) (Hash, error) {
	if err := l.checkSize(ctx, size); err != nil {
		return Hash{}, err
	}
	return root(ctx, l.pool, size)
}

func root(ctx context.Context, q querier, size uint64) (Hash, error) {
	got, err := fetch(ctx, q, pieces(0, size))
	if err != nil {
		return Hash{}, err
	}
	return rangeHash(0, size, func(n node) Hash { return got[n] }), nil
}

func (l *Log) proof(ctx context.Context, ranges [][2]uint64) ([]Hash, error) {
	got, err := fetch(ctx, l.pool, rangesNodes(ranges))
	if err != nil {
		return nil, err
	}
	out := make([]Hash, len(ranges))
	for i, r := range ranges {
		out[i] = rangeHash(r[0], r[1], func(n node) Hash { return got[n] })
	}
	return out, nil
}

// InclusionProof proves leaf index in the tree of the first size leaves.
func (l *Log) InclusionProof(ctx context.Context, index, size uint64) ([]Hash, error) {
	if index >= size {
		return nil, ErrRange
	}
	if err := l.checkSize(ctx, size); err != nil {
		return nil, err
	}
	return l.proof(ctx, inclusionRanges(index, 0, size))
}

// ConsistencyProof proves that the first size2 leaves extend the first size1.
func (l *Log) ConsistencyProof(ctx context.Context, size1, size2 uint64) ([]Hash, error) {
	if size1 > size2 {
		return nil, ErrRange
	}
	if err := l.checkSize(ctx, size2); err != nil {
		return nil, err
	}
	if size1 == 0 || size1 == size2 {
		return nil, nil
	}
	return l.proof(ctx, consistencyRanges(size1, 0, size2, true))
}

// Leaves returns up to limit leaves from index from (auditors replay them).
func (l *Log) Leaves(ctx context.Context, from uint64, limit int) ([][]byte, error) {
	rows, err := l.pool.Query(ctx, `SELECT data FROM tlog_leaves WHERE idx >= $1 ORDER BY idx LIMIT $2`, int64(from), limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[[]byte])
}

// SignedTreeHead is a tree head with its K_dir signature.
type SignedTreeHead struct {
	TreeHead
	Raw []byte // COSE_Sign1
}

// Publish signs the current tree head and records it.
func (l *Log) Publish(ctx context.Context, s cose.Signer, kid []byte, now time.Time) (SignedTreeHead, error) {
	var out SignedTreeHead
	err := pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		var size int64
		// Hold the head so the signed root is the root of a size that no
		// concurrent append can extend mid-computation.
		if err := tx.QueryRow(ctx, `SELECT size FROM tlog_head WHERE id = 1 FOR SHARE`).Scan(&size); err != nil {
			return err
		}
		r, err := root(ctx, tx, uint64(size))
		if err != nil {
			return err
		}
		th := TreeHead{Size: uint64(size), Root: r, Time: now.UTC().Truncate(time.Millisecond)}
		raw, err := SignTreeHead(s, kid, th)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tlog_sths (size, root, signed_at, sth) VALUES ($1, $2, $3, $4)`,
			size, r[:], th.Time, raw); err != nil {
			return err
		}
		out = SignedTreeHead{TreeHead: th, Raw: raw}
		return nil
	})
	return out, err
}

// ErrNoTreeHead means no tree head has been published yet.
var ErrNoTreeHead = errors.New("tlog: no signed tree head")

// Latest returns the newest signed tree head.
func (l *Log) Latest(ctx context.Context) (SignedTreeHead, error) {
	var out SignedTreeHead
	var size int64
	var r []byte
	err := l.pool.QueryRow(ctx, `SELECT size, root, signed_at, sth FROM tlog_sths ORDER BY id DESC LIMIT 1`).
		Scan(&size, &r, &out.Time, &out.Raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNoTreeHead
	}
	if err != nil {
		return out, err
	}
	out.Size, out.Root, out.Time = uint64(size), Hash(r), out.Time.UTC()
	return out, nil
}
