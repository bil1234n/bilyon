package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// Message is one outbox row handed to a Publisher.
type Message struct {
	ID        int64
	Topic     string
	Key       string
	Partition int16
	Payload   []byte
	Headers   map[string]string
	CreatedAt time.Time
	Attempts  int
}

// Publisher delivers messages to the event bus. Publish must return only
// after the bus has durably accepted the message (e.g. a JetStream ack).
// Delivery is at-least-once: consumers deduplicate by Message.ID or the
// CloudEvents id inside the payload.
type Publisher interface {
	Publish(ctx context.Context, msg Message) error
}

// RelayConfig tunes a Relay.
type RelayConfig struct {
	BatchSize      int           // rows per partition batch, default 200
	PollInterval   time.Duration // fallback poll when no NOTIFY arrives, default 1s
	LockInterval   time.Duration // how often unowned partitions are re-tried, default 5s
	PublishTimeout time.Duration // per message, default 5s
	MaxAttempts    int           // then dead-lettered, default 25
	BaseBackoff    time.Duration // default 500ms, doubled per attempt
	MaxBackoff     time.Duration // default 5m
	Retention      time.Duration // published rows kept this long, default 72h
	LockNamespace  int32         // advisory lock class id, default 0x0b17
	Partitions     []int16       // partitions this relay may own, default all
	Logger         *slog.Logger
	Registerer     prometheus.Registerer // nil: no metrics
}

func (c *RelayConfig) normalise() {
	if c.BatchSize <= 0 {
		c.BatchSize = 200
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.LockInterval <= 0 {
		c.LockInterval = 5 * time.Second
	}
	if c.PublishTimeout <= 0 {
		c.PublishTimeout = 5 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 25
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = 500 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 5 * time.Minute
	}
	if c.Retention <= 0 {
		c.Retention = 72 * time.Hour
	}
	if c.LockNamespace == 0 {
		c.LockNamespace = 0x0b17
	}
	if len(c.Partitions) == 0 {
		for p := range int16(Partitions) {
			c.Partitions = append(c.Partitions, p)
		}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
}

type relayMetrics struct {
	published *prometheus.CounterVec
	failed    *prometheus.CounterVec
	dead      *prometheus.CounterVec
	owned     prometheus.Gauge
	lag       prometheus.Gauge
}

func newRelayMetrics(reg prometheus.Registerer) *relayMetrics {
	m := &relayMetrics{
		published: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_outbox_published_total",
			Help: "Outbox messages published."}, []string{"topic"}),
		failed: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_outbox_publish_failures_total",
			Help: "Failed publish attempts."}, []string{"topic"}),
		dead: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_outbox_dead_lettered_total",
			Help: "Messages dead-lettered after MaxAttempts."}, []string{"topic"}),
		owned: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_outbox_partitions_owned",
			Help: "Outbox partitions owned by this relay."}),
		lag: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_outbox_oldest_pending_seconds",
			Help: "Age of the oldest pending message in owned partitions."}),
	}
	if reg != nil {
		reg.MustRegister(m.published, m.failed, m.dead, m.owned, m.lag)
	}
	return m
}

// Relay publishes outbox rows. Run any number of relays: each partition is
// owned by exactly one of them at a time through a session advisory lock,
// and ownership moves automatically when a relay dies.
type Relay struct {
	pool *pgxpool.Pool
	pub  Publisher
	cfg  RelayConfig
	m    *relayMetrics

	mu    sync.Mutex
	owned map[int16]bool
}

// NewRelay returns a relay; call Run to start it.
func NewRelay(pool *pgxpool.Pool, pub Publisher, cfg RelayConfig) *Relay {
	cfg.normalise()
	return &Relay{pool: pool, pub: pub, cfg: cfg, m: newRelayMetrics(cfg.Registerer), owned: map[int16]bool{}}
}

// Owned returns the partitions currently owned (for tests and diagnostics).
func (r *Relay) Owned() []int16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int16, 0, len(r.owned))
	for _, p := range r.cfg.Partitions {
		if r.owned[p] {
			out = append(out, p)
		}
	}
	return out
}

// Run publishes until ctx is cancelled. It returns nil on cancellation.
func (r *Relay) Run(ctx context.Context) error {
	wake := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Go(func() { Listen(ctx, r.pool, wake, r.cfg.Logger) })
	defer wg.Wait()

	for ctx.Err() == nil {
		err := r.ownAndPublish(ctx, wake)
		r.setOwned(nil)
		if ctx.Err() != nil {
			return nil
		}
		r.cfg.Logger.WarnContext(ctx, "outbox relay restarting", slog.Any("error", err))
		select {
		case <-time.After(time.Second + time.Duration(rand.Int64N(int64(time.Second)))):
		case <-ctx.Done():
		}
	}
	return nil
}

func (r *Relay) setOwned(ps map[int16]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.owned = map[int16]bool{}
	for p, ok := range ps {
		if ok {
			r.owned[p] = true
		}
	}
	r.m.owned.Set(float64(len(r.owned)))
}

// ownAndPublish holds the partition locks on one dedicated session for as
// long as that session lives; losing it releases every lock at once, so the
// relay must stop publishing immediately.
func (r *Relay) ownAndPublish(ctx context.Context, wake <-chan struct{}) error {
	lockConn, err := pgx.ConnectConfig(ctx, r.pool.Config().ConnConfig.Copy())
	if err != nil {
		return fmt.Errorf("outbox: lock session: %w", err)
	}
	defer lockConn.Close(context.WithoutCancel(ctx))
	owned := map[int16]bool{}
	nextLockAttempt := time.Time{}
	lastCleanup := time.Time{}
	for {
		if time.Now().After(nextLockAttempt) {
			if err := lockConn.Ping(ctx); err != nil {
				return fmt.Errorf("outbox: lock session lost: %w", err)
			}
			for _, p := range r.cfg.Partitions {
				if owned[p] {
					continue
				}
				var got bool
				if err := lockConn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", r.cfg.LockNamespace, int32(p)).Scan(&got); err != nil {
					return fmt.Errorf("outbox: lock partition %d: %w", p, err)
				}
				if got {
					owned[p] = true
					r.cfg.Logger.InfoContext(ctx, "outbox partition acquired", slog.Int("partition", int(p)))
				}
			}
			r.setOwned(owned)
			nextLockAttempt = time.Now().Add(r.cfg.LockInterval)
		}
		for _, p := range r.cfg.Partitions {
			if !owned[p] {
				continue
			}
			for {
				n, err := r.publishBatch(ctx, p)
				if err != nil {
					return err
				}
				if n < r.cfg.BatchSize {
					break
				}
			}
		}
		if len(owned) > 0 {
			r.recordLag(ctx, owned)
			if time.Since(lastCleanup) > time.Minute {
				if err := r.cleanup(ctx); err != nil {
					r.cfg.Logger.WarnContext(ctx, "outbox cleanup failed", slog.Any("error", err))
				}
				lastCleanup = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		case <-time.After(r.cfg.PollInterval):
		}
	}
}

// publishBatch publishes one batch of partition p and returns its size.
// A message is eligible only when every older pending message with the same
// key is eligible too, so a key in backoff blocks only itself.
func (r *Relay) publishBatch(ctx context.Context, p int16) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	rows, err := tx.Query(ctx, `
		SELECT o.id, o.topic, o.msg_key, o.payload, o.headers, o.created_at, o.attempts
		  FROM outbox o
		 WHERE o.partition = $1 AND o.published_at IS NULL AND o.dead_at IS NULL
		   AND o.available_at <= clock_timestamp()
		   AND NOT EXISTS (
		       SELECT 1 FROM outbox b
		        WHERE b.partition = o.partition AND b.msg_key = o.msg_key AND b.id < o.id
		          AND b.published_at IS NULL AND b.dead_at IS NULL AND b.available_at > clock_timestamp())
		 ORDER BY o.id
		 LIMIT $2
		 FOR UPDATE SKIP LOCKED`, p, r.cfg.BatchSize)
	if err != nil {
		return 0, err
	}
	var batch []Message
	for rows.Next() {
		var m Message
		var headers []byte
		if err := rows.Scan(&m.ID, &m.Topic, &m.Key, &m.Payload, &headers, &m.CreatedAt, &m.Attempts); err != nil {
			rows.Close()
			return 0, err
		}
		if err := json.Unmarshal(headers, &m.Headers); err != nil {
			rows.Close()
			return 0, fmt.Errorf("outbox: headers of %d: %w", m.ID, err)
		}
		m.Partition = p
		batch = append(batch, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, tx.Commit(ctx)
	}
	var published []int64
	blocked := map[string]bool{}
	for _, m := range batch {
		if blocked[m.Key] {
			continue // an older message with this key failed in this batch
		}
		pctx, cancel := context.WithTimeout(ctx, r.cfg.PublishTimeout)
		err := r.pub.Publish(pctx, m)
		cancel()
		if err == nil {
			published = append(published, m.ID)
			r.m.published.WithLabelValues(m.Topic).Inc()
			continue
		}
		if ctx.Err() != nil {
			break // shutting down: leave the rest for the next owner
		}
		blocked[m.Key] = true
		r.m.failed.WithLabelValues(m.Topic).Inc()
		if err := r.recordFailure(ctx, tx, m, err); err != nil {
			return 0, err
		}
	}
	if len(published) > 0 {
		if _, err := tx.Exec(context.WithoutCancel(ctx), `UPDATE outbox SET published_at = clock_timestamp(), last_error = NULL
			WHERE id = ANY($1)`, published); err != nil {
			return 0, err
		}
	}
	return len(batch), tx.Commit(context.WithoutCancel(ctx))
}

func (r *Relay) recordFailure(ctx context.Context, tx pgx.Tx, m Message, cause error) error {
	attempts := m.Attempts + 1
	backoff := r.cfg.BaseBackoff << min(attempts-1, 20)
	if backoff <= 0 || backoff > r.cfg.MaxBackoff {
		backoff = r.cfg.MaxBackoff
	}
	backoff += time.Duration(rand.Int64N(int64(backoff)/5 + 1)) // jitter
	dead := attempts >= r.cfg.MaxAttempts
	msg := cause.Error()
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	if dead {
		r.m.dead.WithLabelValues(m.Topic).Inc()
		r.cfg.Logger.ErrorContext(ctx, "outbox message dead-lettered", slog.Int64("id", m.ID),
			slog.String("topic", m.Topic), slog.String("error", msg))
	}
	_, err := tx.Exec(context.WithoutCancel(ctx), `UPDATE outbox
		SET attempts = $2, last_error = $3,
		    available_at = clock_timestamp() + make_interval(secs => $4),
		    dead_at = CASE WHEN $5 THEN clock_timestamp() END
		WHERE id = $1`, m.ID, attempts, msg, backoff.Seconds(), dead)
	return err
}

func (r *Relay) recordLag(ctx context.Context, owned map[int16]bool) {
	parts := make([]int16, 0, len(owned))
	for p := range owned {
		parts = append(parts, p)
	}
	var age float64
	err := r.pool.QueryRow(ctx, `SELECT coalesce(extract(epoch FROM clock_timestamp() - min(created_at)), 0)::float8
		FROM outbox WHERE partition = ANY($1) AND published_at IS NULL AND dead_at IS NULL`, parts).Scan(&age)
	if err == nil {
		r.m.lag.Set(age)
	}
}

// cleanup deletes published rows older than the retention, in small batches.
func (r *Relay) cleanup(ctx context.Context) error {
	for {
		// Rows above the lowest table-tailer horizon may still be unread.
		tag, err := r.pool.Exec(ctx, `DELETE FROM outbox WHERE id IN (
			SELECT id FROM outbox WHERE published_at < clock_timestamp() - make_interval(secs => $1)
			   AND id <= coalesce((SELECT min(horizon) FROM outbox_cursors), 9223372036854775807)
			ORDER BY id LIMIT 1000 FOR UPDATE SKIP LOCKED)`, r.cfg.Retention.Seconds())
		if err != nil || tag.RowsAffected() < 1000 {
			return err
		}
	}
}

// Channel is the NOTIFY channel the outbox insert trigger signals.
const Channel = "bilyon_outbox"

// Listen turns NOTIFY bilyon_outbox into non-blocking sends on wake until
// ctx is cancelled, reconnecting on failure. It uses its own connection
// built from pool's configuration, because LISTEN pins a session.
func Listen(ctx context.Context, pool *pgxpool.Pool, wake chan<- struct{}, log *slog.Logger) {
	for ctx.Err() == nil {
		err := listenOnce(ctx, pool, wake)
		if ctx.Err() != nil {
			return
		}
		log.WarnContext(ctx, "outbox listener reconnecting", slog.Any("error", err))
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
		}
	}
}

func listenOnce(ctx context.Context, pool *pgxpool.Pool, wake chan<- struct{}) error {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return err
	}
	for {
		if _, err := conn.WaitForNotification(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
