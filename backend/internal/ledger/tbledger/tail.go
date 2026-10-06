package tbledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// Cursor states (outbox_cursors.state).
const (
	stateBootstrapping = "bootstrapping"
	stateTailing       = "tailing"
)

// DefaultConsumer is the shadow's cursor name.
const DefaultConsumer = "tbshadow"

var (
	// ErrNoCursor means the shadow has not been bootstrapped.
	ErrNoCursor = errors.New("tbledger: the shadow has no cursor; run bootstrap first")
	// ErrBootstrapIncomplete means a bootstrap started but never finished.
	ErrBootstrapIncomplete = errors.New("tbledger: a previous bootstrap did not finish; " +
		"reformat the TigerBeetle cluster and reset the bootstrap")
	// ErrLocked means another shadow instance holds the consumer's lock.
	ErrLocked = errors.New("tbledger: another shadow instance holds this consumer")
)

// lockKey is the advisory lock that makes one process the consumer's only
// writer to TigerBeetle: the mirror's checks assume no concurrent writer.
func lockKey(consumer string) int64 {
	h := fnv.New64a()
	h.Write([]byte("bilyon/tbshadow/" + consumer))
	return int64(h.Sum64())
}

// lockSession takes the consumer's advisory lock on a dedicated connection.
// With wait <= 0 it waits indefinitely (a standby instance); otherwise it
// gives up with ErrLocked after wait.
func lockSession(ctx context.Context, pool *pgxpool.Pool, consumer string, wait, retry time.Duration, log *slog.Logger) (*pgx.Conn, error) {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return nil, fmt.Errorf("tbledger: lock session: %w", err)
	}
	var deadline time.Time
	if wait > 0 {
		deadline = time.Now().Add(wait)
	}
	standby := false
	for {
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey(consumer)).Scan(&got); err != nil {
			_ = conn.Close(context.WithoutCancel(ctx))
			return nil, fmt.Errorf("tbledger: lock: %w", err)
		}
		if got {
			if standby {
				log.InfoContext(ctx, "shadow lock acquired", slog.String("consumer", consumer))
			}
			return conn, nil
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			_ = conn.Close(context.WithoutCancel(ctx))
			return nil, ErrLocked
		}
		if !standby {
			standby = true
			log.InfoContext(ctx, "another instance holds the shadow lock; standing by", slog.String("consumer", consumer))
		}
		select {
		case <-ctx.Done():
			_ = conn.Close(context.WithoutCancel(ctx))
			return nil, ctx.Err()
		case <-time.After(retry):
		}
	}
}

// gapSet is a group of outbox ids that were not visible in Snapshot even
// though larger ids were. Their writers, if any are still running, are among
// the snapshot's in-flight transactions; once those have all finished, ids
// that are still invisible will never appear.
type gapSet struct {
	Snapshot string     `json:"snapshot"`
	Ranges   [][2]int64 `json:"ranges"` // inclusive, ascending, disjoint
}

// cursor is a consumer's position in the outbox.
type cursor struct {
	lastID int64
	gaps   []gapSet
}

// horizon is the highest id at or below which nothing is left to read.
func (c cursor) horizon() int64 {
	h := c.lastID
	for _, g := range c.gaps {
		for _, r := range g.Ranges {
			h = min(h, r[0]-1)
		}
	}
	return h
}

func (c cursor) gapCount() int64 {
	var n int64
	for _, g := range c.gaps {
		for _, r := range g.Ranges {
			n += r[1] - r[0] + 1
		}
	}
	return n
}

// without returns rs minus ids (ascending).
func without(rs [][2]int64, ids []int64) [][2]int64 {
	var out [][2]int64
	for _, r := range rs {
		lo := r[0]
		start := sort.Search(len(ids), func(i int) bool { return ids[i] >= r[0] })
		for _, id := range ids[start:] {
			if id > r[1] {
				break
			}
			if id > lo {
				out = append(out, [2]int64{lo, id - 1})
			}
			lo = id + 1
		}
		if lo <= r[1] {
			out = append(out, [2]int64{lo, r[1]})
		}
	}
	return out
}

// only returns the members of ids (ascending) that fall inside rs, as
// single-id ranges.
func only(rs [][2]int64, ids []int64) [][2]int64 {
	var out [][2]int64
	for _, id := range ids {
		for _, r := range rs {
			if id >= r[0] && id <= r[1] {
				out = append(out, [2]int64{id, id})
				break
			}
		}
	}
	return out
}

// missing returns the ranges of ids in (after, upto] absent from ids
// (ascending).
func missing(after int64, ids []int64, upto int64) [][2]int64 {
	var out [][2]int64
	next := after + 1
	for _, id := range ids {
		if id > upto {
			break
		}
		if id > next {
			out = append(out, [2]int64{next, id - 1})
		}
		next = id + 1
	}
	if next <= upto {
		out = append(out, [2]int64{next, upto})
	}
	return out
}

func loadCursor(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, consumer string) (cursor, string, error) {
	var c cursor
	var state string
	var gaps []byte
	err := q.QueryRow(ctx, `SELECT state, last_id, gaps FROM outbox_cursors WHERE consumer = $1`, consumer).
		Scan(&state, &c.lastID, &gaps)
	if errors.Is(err, pgx.ErrNoRows) {
		return cursor{}, "", ErrNoCursor
	}
	if err != nil {
		return cursor{}, "", err
	}
	if err := json.Unmarshal(gaps, &c.gaps); err != nil {
		return cursor{}, "", fmt.Errorf("tbledger: cursor gaps: %w", err)
	}
	return c, state, nil
}

func saveCursor(ctx context.Context, pool *pgxpool.Pool, consumer string, c cursor) error {
	gaps := c.gaps
	if gaps == nil {
		gaps = []gapSet{}
	}
	raw, err := json.Marshal(gaps)
	if err != nil {
		return err
	}
	tag, err := pool.Exec(ctx, `UPDATE outbox_cursors SET last_id = $2, horizon = $3, gaps = $4, updated_at = clock_timestamp()
		WHERE consumer = $1 AND state = 'tailing'`, consumer, c.lastID, c.horizon(), raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("tbledger: cursor %q disappeared or left the tailing state", consumer)
	}
	return nil
}

// TailerConfig tunes a Tailer.
type TailerConfig struct {
	Consumer      string        // cursor name, default DefaultConsumer
	AutoBootstrap bool          // bootstrap when the consumer has no cursor yet
	LockWait      time.Duration // <= 0: stand by until the lock is free; else give up with ErrLocked
	LockRetry     time.Duration // lock polling interval, default 2s
	BatchSize     int           // rows per batch, default 500
	PollInterval  time.Duration // fallback poll when no NOTIFY arrives, default 1s
	RetryMin      time.Duration // first retry delay after a failure, default 100ms
	RetryMax      time.Duration // retry delay cap, default 30s
	ReconcilePage int           // accounts per reconciliation page, default 2000
	Logger        *slog.Logger
	Registerer    prometheus.Registerer // nil: no metrics
}

func (c *TailerConfig) normalise() {
	if c.Consumer == "" {
		c.Consumer = DefaultConsumer
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 500
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.RetryMin <= 0 {
		c.RetryMin = 100 * time.Millisecond
	}
	if c.RetryMax <= 0 {
		c.RetryMax = 30 * time.Second
	}
	if c.ReconcilePage <= 0 {
		c.ReconcilePage = 2000
	}
	if c.LockRetry <= 0 {
		c.LockRetry = 2 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
}

type tailerMetrics struct {
	applied  *prometheus.CounterVec
	failures *prometheus.CounterVec
	blocked  prometheus.Gauge
	position prometheus.Gauge
	gaps     prometheus.Gauge
	lag      prometheus.Gauge
}

// Tailer replays ledger events from the PostgreSQL outbox table into a
// Mirror in an order consistent with the ledger's serialization order.
//
// Each batch reads, in one REPEATABLE READ snapshot, the rows above the
// cursor and the still-open gaps, and applies them in id order. That order
// is a valid serialization: an outbox id is drawn after the writing
// transaction has taken its locks, so a transaction that observed another
// (a balance it locked, an account it read) has larger ids, and a snapshot
// that shows the observer also shows the observed. Ids missing from a
// snapshot are remembered as gaps and applied once they commit; they cannot
// precede anything already applied, because nothing visible depended on
// them.
//
// An event that fails blocks the tailer (head-of-line) and is retried with
// backoff: skipping it would make every later balance check meaningless.
type Tailer struct {
	pool   *pgxpool.Pool
	mirror *Mirror
	cfg    TailerConfig
	m      tailerMetrics
	reqs   chan reconcileReq

	mu      sync.Mutex
	pending []reconcileReq
}

// NewTailer returns a tailer applying to mirror.
func NewTailer(pool *pgxpool.Pool, mirror *Mirror, cfg TailerConfig) *Tailer {
	cfg.normalise()
	t := &Tailer{pool: pool, mirror: mirror, cfg: cfg, reqs: make(chan reconcileReq),
		m: tailerMetrics{
			applied: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_tbshadow_events_total",
				Help: "Ledger events mirrored into TigerBeetle."}, []string{"type"}),
			failures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_tbshadow_failures_total",
				Help: "Failed attempts to mirror a ledger event (retried)."}, []string{"type"}),
			blocked: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_tbshadow_blocked",
				Help: "1 while an event keeps failing and blocks the shadow (alert)."}),
			position: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_tbshadow_position",
				Help: "Highest outbox id examined by the shadow."}),
			gaps: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_tbshadow_gap_ids",
				Help: "Outbox ids below the position not yet visible."}),
			lag: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_tbshadow_lag_rows",
				Help: "Outbox rows between the shadow's position and the head."}),
		}}
	if cfg.Registerer != nil {
		cfg.Registerer.MustRegister(t.m.applied, t.m.failures, t.m.blocked, t.m.position, t.m.gaps, t.m.lag)
	}
	return t
}

type reconcileReq struct {
	resp chan reconcileResult
}

type reconcileResult struct {
	mismatches []Mismatch
	err        error
}

// Reconcile compares every account's balance in TigerBeetle with PostgreSQL
// at an exact cut: the next time the running tailer has applied every row
// visible in its batch snapshot, it reads the PostgreSQL balances in that
// same snapshot, so in-flight events cannot cause false mismatches. It blocks
// until then (or ctx is done); Run must be running.
func (t *Tailer) Reconcile(ctx context.Context) ([]Mismatch, error) {
	req := reconcileReq{resp: make(chan reconcileResult, 1)}
	select {
	case t.reqs <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r := <-req.resp:
		return r.mismatches, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Run tails until ctx is cancelled (returning nil). It first takes the
// consumer's advisory lock (standing by while another instance holds it)
// and, with AutoBootstrap, bootstraps a consumer that has no cursor. It
// fails when the shadow has not been bootstrapped, a bootstrap is
// incomplete, or the lock session is lost.
func (t *Tailer) Run(ctx context.Context) error {
	lock, err := lockSession(ctx, t.pool, t.cfg.Consumer, t.cfg.LockWait, t.cfg.LockRetry, t.cfg.Logger)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		// Losing the session releases the lock: stop writing at once.
		for {
			select {
			case <-runCtx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			if err := lock.Ping(runCtx); err != nil && runCtx.Err() == nil {
				cancel(fmt.Errorf("tbledger: shadow lock session lost: %w", err))
				return
			}
		}
	})
	err = t.tail(runCtx)
	cause := context.Cause(runCtx)
	cancel(nil)
	wg.Wait()
	_ = lock.Close(context.WithoutCancel(ctx))
	if ctx.Err() == nil && cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return err
}

func (t *Tailer) tail(ctx context.Context) error {
	cur, state, err := loadCursor(ctx, t.pool, t.cfg.Consumer)
	if errors.Is(err, ErrNoCursor) && t.cfg.AutoBootstrap {
		if _, err := bootstrap(ctx, t.pool, t.mirror.d, t.cfg.Consumer, t.cfg.Logger); err != nil {
			return err
		}
		cur, state, err = loadCursor(ctx, t.pool, t.cfg.Consumer)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if state != stateTailing {
		return ErrBootstrapIncomplete
	}
	t.m.position.Set(float64(cur.lastID))
	t.m.gaps.Set(float64(cur.gapCount()))

	wake := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Go(func() { outbox.Listen(ctx, t.pool, wake, t.cfg.Logger) })
	defer wg.Wait()
	defer t.failPending(context.Canceled)

	failures := 0
	for {
		full, err := t.step(ctx, &cur)
		if ctx.Err() != nil {
			return nil
		}
		var wait time.Duration
		switch {
		case err != nil:
			failures++
			t.m.blocked.Set(1)
			wait = t.backoff(failures)
			t.cfg.Logger.WarnContext(ctx, "shadow blocked, retrying", slog.Any("error", err),
				slog.Int("attempt", failures), slog.Duration("retry_in", wait))
		case full:
			failures = 0
			t.m.blocked.Set(0)
			continue
		default:
			failures = 0
			t.m.blocked.Set(0)
			wait = t.cfg.PollInterval
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
			if err != nil {
				// Keep the backoff when blocked: new rows do not unblock.
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return nil
				}
			}
		case req := <-t.reqs:
			t.mu.Lock()
			t.pending = append(t.pending, req)
			t.mu.Unlock()
		case <-time.After(wait):
		}
	}
}

func (t *Tailer) backoff(failures int) time.Duration {
	d := t.cfg.RetryMin << min(failures-1, 20)
	if d <= 0 || d > t.cfg.RetryMax {
		d = t.cfg.RetryMax
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (t *Tailer) takePending() []reconcileReq {
	t.mu.Lock()
	defer t.mu.Unlock()
	reqs := t.pending
	t.pending = nil
	return reqs
}

func (t *Tailer) failPending(err error) {
	for _, r := range t.takePending() {
		r.resp <- reconcileResult{err: err}
	}
}

// row is one outbox row read by a batch.
type row struct {
	id      int64
	topic   string
	payload []byte // nil for non-ledger topics
	gap     bool   // read through a gap range
}

// settled reports, per gap set, whether every transaction in flight when the
// set was recorded has finished.
func (t *Tailer) settled(ctx context.Context, gaps []gapSet) ([]bool, error) {
	out := make([]bool, len(gaps))
	if len(gaps) == 0 {
		return out, nil
	}
	snaps := make([]string, len(gaps))
	for i, g := range gaps {
		snaps[i] = g.Snapshot
	}
	rows, err := t.pool.Query(ctx, `SELECT s.ord, NOT EXISTS (
			SELECT 1 FROM pg_snapshot_xip(s.snap::pg_snapshot) AS x WHERE pg_xact_status(x) = 'in progress')
		FROM unnest($1::text[]) WITH ORDINALITY AS s(snap, ord)`, snaps)
	if err != nil {
		return nil, fmt.Errorf("tbledger: gap status: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ord int64
		var done bool
		if err := rows.Scan(&ord, &done); err != nil {
			return nil, err
		}
		out[ord-1] = done
	}
	return out, rows.Err()
}

func scanRows(rows pgx.Rows, gap bool) ([]row, error) {
	defer rows.Close()
	var out []row
	for rows.Next() {
		r := row{gap: gap}
		if err := rows.Scan(&r.id, &r.topic, &r.payload); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// step runs one batch and saves the cursor. full reports a full batch (more
// rows are likely waiting).
func (t *Tailer) step(ctx context.Context, cur *cursor) (full bool, err error) {
	settled, err := t.settled(ctx, cur.gaps)
	if err != nil {
		return false, err
	}
	tx, err := t.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var snap string
	var head int64
	if err := tx.QueryRow(ctx, `SELECT pg_current_snapshot()::text, coalesce((SELECT max(id) FROM outbox), 0)`).
		Scan(&snap, &head); err != nil {
		return false, err
	}
	var los, his []int64
	for _, g := range cur.gaps {
		for _, r := range g.Ranges {
			los, his = append(los, r[0]), append(his, r[1])
		}
	}
	const cols = `o.id, o.topic, CASE WHEN o.topic LIKE 'ledger.%' THEN o.payload END`
	var gapRows []row
	if len(los) > 0 {
		rs, err := tx.Query(ctx, `SELECT `+cols+` FROM outbox o
			JOIN unnest($1::bigint[], $2::bigint[]) AS g(lo, hi) ON o.id BETWEEN g.lo AND g.hi ORDER BY o.id`, los, his)
		if err != nil {
			return false, err
		}
		if gapRows, err = scanRows(rs, true); err != nil {
			return false, err
		}
	}
	rs, err := tx.Query(ctx, `SELECT `+cols+` FROM outbox o WHERE o.id > $1 ORDER BY o.id LIMIT $2`,
		cur.lastID, t.cfg.BatchSize)
	if err != nil {
		return false, err
	}
	newRows, err := scanRows(rs, false)
	if err != nil {
		return false, err
	}
	batch := append(append([]row{}, gapRows...), newRows...)
	sort.Slice(batch, func(i, j int) bool { return batch[i].id < batch[j].id })

	// Apply in id order; stop at the first failure and keep the progress.
	var applyErr error
	done := 0
	for _, r := range batch {
		if err := t.apply(ctx, r); err != nil {
			applyErr = err
			break
		}
		done++
	}

	next := cursor{lastID: cur.lastID}
	var appliedGaps, visibleGaps, newIDs []int64
	for i, r := range batch {
		switch {
		case r.gap && i < done:
			appliedGaps = append(appliedGaps, r.id)
		case r.gap:
			visibleGaps = append(visibleGaps, r.id)
		case i < done:
			newIDs = append(newIDs, r.id)
			next.lastID = r.id
		}
	}
	for i, g := range cur.gaps {
		var rest [][2]int64
		if settled[i] {
			// Writers are done: ids absent from this snapshot never commit.
			rest = only(g.Ranges, visibleGaps)
		} else {
			rest = without(g.Ranges, appliedGaps)
		}
		if len(rest) > 0 {
			next.gaps = append(next.gaps, gapSet{Snapshot: g.Snapshot, Ranges: rest})
		}
	}
	if fresh := missing(cur.lastID, newIDs, next.lastID); len(fresh) > 0 {
		next.gaps = append(next.gaps, gapSet{Snapshot: snap, Ranges: fresh})
	}

	full = len(newRows) == t.cfg.BatchSize
	var reqs []reconcileReq
	if applyErr == nil && !full {
		reqs = t.takePending()
	}
	if len(reqs) > 0 {
		// Every row visible in this snapshot is applied: TigerBeetle now
		// holds exactly the effects PostgreSQL shows in it.
		mismatches, err := reconcileIn(ctx, tx, t.mirror.d, t.cfg.ReconcilePage)
		for _, r := range reqs {
			r.resp <- reconcileResult{mismatches: mismatches, err: err}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	if err := saveCursor(ctx, t.pool, t.cfg.Consumer, next); err != nil {
		return false, err
	}
	*cur = next
	t.m.position.Set(float64(next.lastID))
	t.m.gaps.Set(float64(next.gapCount()))
	t.m.lag.Set(float64(max(head-next.lastID, 0)))
	return full, applyErr
}

func (t *Tailer) apply(ctx context.Context, r row) error {
	if !strings.HasPrefix(r.topic, "ledger.") {
		return nil
	}
	var env outbox.Envelope
	if err := json.Unmarshal(r.payload, &env); err != nil {
		return fmt.Errorf("outbox row %d: decode envelope: %w", r.id, err)
	}
	if err := t.mirror.Apply(ctx, env); err != nil {
		t.m.failures.WithLabelValues(env.Type).Inc()
		return fmt.Errorf("outbox row %d (%s %s): %w", r.id, env.Type, env.ID, err)
	}
	t.m.applied.WithLabelValues(env.Type).Inc()
	return nil
}
