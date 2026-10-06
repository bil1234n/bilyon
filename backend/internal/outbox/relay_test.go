package outbox_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, ledgerdb.Setup, &srv)) }

// recorder is a Publisher that remembers what it published and can be told
// to fail specific messages.
type recorder struct {
	mu        sync.Mutex
	published []outbox.Message
	byRelay   map[string]int
	fail      func(m outbox.Message, attempt int) error
	attempts  map[int64]int
	name      string
	shared    *recorder
}

func newRecorder() *recorder { return &recorder{byRelay: map[string]int{}, attempts: map[int64]int{}} }

func (r *recorder) as(name string) *recorder { return &recorder{name: name, shared: r} }

func (r *recorder) Publish(_ context.Context, m outbox.Message) error {
	root := r
	if r.shared != nil {
		root = r.shared
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	root.attempts[m.ID]++
	if root.fail != nil {
		if err := root.fail(m, root.attempts[m.ID]); err != nil {
			return err
		}
	}
	root.published = append(root.published, m)
	root.byRelay[r.name]++
	return nil
}

func (r *recorder) snapshot() []outbox.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]outbox.Message(nil), r.published...)
}

func bg(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func write(t *testing.T, pool *pgxpool.Pool, topic, key string, data any) {
	t.Helper()
	if err := pgx.BeginFunc(bg(t), pool, func(tx pgx.Tx) error {
		_, err := outbox.Write(bg(t), tx, outbox.Event{Topic: topic, Key: key, Data: data})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, r *outbox.Relay) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return cancel
}

func eventually(t *testing.T, within time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func pending(t *testing.T, pool *pgxpool.Pool) int {
	var n int
	if err := pool.QueryRow(bg(t), `SELECT count(*) FROM outbox WHERE published_at IS NULL AND dead_at IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRelayPublishesEveryKeyInOrder(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	for i := range 60 {
		write(t, pool, "ledger.entry.posted", fmt.Sprintf("intent:%d", i%7), map[string]int{"seq": i})
	}
	rec := newRecorder()
	run(t, outbox.NewRelay(pool, rec, outbox.RelayConfig{BatchSize: 8, PollInterval: 20 * time.Millisecond}))
	eventually(t, 10*time.Second, func() bool { return len(rec.snapshot()) == 60 }, "60 publications")
	last := map[string]int64{}
	for _, m := range rec.snapshot() {
		if m.ID <= last[m.Key] {
			t.Fatalf("key %s published out of order: %d after %d", m.Key, m.ID, last[m.Key])
		}
		last[m.Key] = m.ID
		if m.Partition != outbox.Partition(m.Key) || m.Topic != "ledger.entry.posted" || len(m.Payload) == 0 {
			t.Fatalf("message fields: %+v", m)
		}
	}
	eventually(t, 5*time.Second, func() bool { return pending(t, pool) == 0 }, "rows marked published")
}

func TestRelayWakesOnNotify(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	rec := newRecorder()
	r := outbox.NewRelay(pool, rec, outbox.RelayConfig{PollInterval: time.Hour})
	run(t, r)
	eventually(t, 5*time.Second, func() bool { return len(r.Owned()) == outbox.Partitions }, "partition ownership")
	time.Sleep(100 * time.Millisecond) // let the listener subscribe
	start := time.Now()
	write(t, pool, "ledger.hold.placed", "intent:x", map[string]string{"a": "b"})
	eventually(t, 3*time.Second, func() bool { return len(rec.snapshot()) == 1 }, "notify-driven publish")
	if took := time.Since(start); took > time.Second {
		t.Fatalf("NOTIFY wake-up took %s with a 1h poll interval", took)
	}
}

func TestRelayBackoffKeepsPerKeyOrder(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	write(t, pool, "t.a", "k", 1)     // fails twice
	write(t, pool, "t.a", "k", 2)     // must wait for the first
	write(t, pool, "t.a", "other", 3) // unaffected
	var firstID int64
	if err := pool.QueryRow(bg(t), `SELECT min(id) FROM outbox WHERE msg_key = 'k'`).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	rec.fail = func(m outbox.Message, attempt int) error {
		if m.ID == firstID && attempt <= 2 {
			return errors.New("bus unavailable")
		}
		return nil
	}
	run(t, outbox.NewRelay(pool, rec, outbox.RelayConfig{PollInterval: 10 * time.Millisecond,
		BaseBackoff: 50 * time.Millisecond, MaxBackoff: 100 * time.Millisecond}))
	eventually(t, 10*time.Second, func() bool { return len(rec.snapshot()) == 3 }, "all three published")
	var order []string
	for _, m := range rec.snapshot() {
		order = append(order, fmt.Sprintf("%s:%d", m.Key, m.ID))
	}
	got := rec.snapshot()
	if got[0].Key != "other" {
		t.Fatalf("the healthy key waited behind the failing one: %v", order)
	}
	if got[1].ID != firstID || got[2].ID <= firstID {
		t.Fatalf("per-key order broken: %v", order)
	}
	var attempts int
	var lastErr *string
	if err := pool.QueryRow(bg(t), `SELECT attempts, last_error FROM outbox WHERE id = $1`, firstID).Scan(&attempts, &lastErr); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || lastErr != nil {
		t.Fatalf("bookkeeping: attempts=%d last_error=%v", attempts, lastErr)
	}
}

func TestRelayDeadLettersPoisonMessages(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	write(t, pool, "t.poison", "k", "bad")
	write(t, pool, "t.poison", "k", "good")
	rec := newRecorder()
	rec.fail = func(m outbox.Message, _ int) error {
		if string(m.Payload) != "" && contains(m.Payload, `"bad"`) {
			return errors.New("schema rejected by bus")
		}
		return nil
	}
	run(t, outbox.NewRelay(pool, rec, outbox.RelayConfig{PollInterval: 10 * time.Millisecond,
		BaseBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond, MaxAttempts: 3}))
	eventually(t, 10*time.Second, func() bool { return len(rec.snapshot()) == 1 }, "successor published after dead-letter")
	var dead, attempts int
	if err := pool.QueryRow(bg(t), `SELECT count(*) FILTER (WHERE dead_at IS NOT NULL), max(attempts) FROM outbox`).Scan(&dead, &attempts); err != nil {
		t.Fatal(err)
	}
	if dead != 1 || attempts != 3 {
		t.Fatalf("dead=%d attempts=%d", dead, attempts)
	}
}

func contains(b []byte, s string) bool {
	return len(s) > 0 && len(b) >= len(s) && indexOf(string(b), s) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestPartitionsFailOverBetweenRelays(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	rec := newRecorder()
	cfg := outbox.RelayConfig{PollInterval: 10 * time.Millisecond, LockInterval: 50 * time.Millisecond}
	a := outbox.NewRelay(pool, rec.as("a"), cfg)
	b := outbox.NewRelay(pool, rec.as("b"), cfg)
	stopA := run(t, a)
	eventually(t, 5*time.Second, func() bool { return len(a.Owned()) == outbox.Partitions }, "relay a owns everything")
	run(t, b)
	time.Sleep(200 * time.Millisecond)
	if len(b.Owned()) != 0 {
		t.Fatalf("relay b took partitions still locked by a: %v", b.Owned())
	}
	for i := range 40 {
		write(t, pool, "t.f", fmt.Sprintf("k%d", i), i)
	}
	eventually(t, 5*time.Second, func() bool { return len(rec.snapshot()) == 40 }, "first wave")
	stopA()
	eventually(t, 5*time.Second, func() bool { return len(b.Owned()) == outbox.Partitions }, "failover to b")
	for i := range 40 {
		write(t, pool, "t.f", fmt.Sprintf("k%d", i), 100+i)
	}
	eventually(t, 5*time.Second, func() bool { return len(rec.snapshot()) == 80 }, "second wave")
	seen := map[int64]bool{}
	for _, m := range rec.snapshot() {
		if seen[m.ID] {
			t.Fatalf("message %d published twice", m.ID)
		}
		seen[m.ID] = true
	}
	if rec.byRelay["a"] != 40 || rec.byRelay["b"] != 40 {
		t.Fatalf("publications by relay: %v", rec.byRelay)
	}
}

func TestRelayCleansUpOldPublishedRows(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	for i := range 5 {
		write(t, pool, "t.c", "k", i)
	}
	if _, err := pool.Exec(bg(t), `UPDATE outbox SET published_at = clock_timestamp() - interval '4 days'`); err != nil {
		t.Fatal(err)
	}
	write(t, pool, "t.c", "k", "fresh")
	rec := newRecorder()
	run(t, outbox.NewRelay(pool, rec, outbox.RelayConfig{PollInterval: 10 * time.Millisecond}))
	eventually(t, 5*time.Second, func() bool {
		var n int
		_ = pool.QueryRow(bg(t), `SELECT count(*) FROM outbox`).Scan(&n)
		return n == 1
	}, "old rows deleted, fresh row kept")
}

func TestWriteValidatesAndPartitionIsStable(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	err := pgx.BeginFunc(bg(t), pool, func(tx pgx.Tx) error {
		_, err := outbox.Write(bg(t), tx, outbox.Event{Topic: "", Key: "k", Data: 1})
		return err
	})
	if err == nil {
		t.Fatal("empty topic accepted")
	}
	if outbox.Partition("intent:42") != outbox.Partition("intent:42") || outbox.Partition("a") < 0 || outbox.Partition("a") >= outbox.Partitions {
		t.Fatal("partition function unstable or out of range")
	}
	if p := outbox.Partition("intent:42"); p != 5 { // pinned: changing the hash would reorder in-flight keys
		t.Fatalf("partition of intent:42 changed to %d", p)
	}
}

func TestCleanupKeepsRowsAboveTailerHorizon(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	for i := range 6 {
		write(t, pool, "t.h", "k", i)
	}
	var ids []int64
	rows, err := pool.Query(bg(t), `SELECT id FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// A table tailer has consumed the first three rows only.
	if _, err := pool.Exec(bg(t), `INSERT INTO outbox_cursors (consumer, state, last_id, horizon) VALUES ('tail-a', 'tailing', $1, $1)`,
		ids[2]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(bg(t), `UPDATE outbox SET published_at = clock_timestamp() - interval '4 days'`); err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	run(t, outbox.NewRelay(pool, rec, outbox.RelayConfig{PollInterval: 10 * time.Millisecond}))
	eventually(t, 5*time.Second, func() bool {
		var n int
		_ = pool.QueryRow(bg(t), `SELECT count(*) FROM outbox`).Scan(&n)
		return n == 3
	}, "rows up to the horizon deleted")
	var lowest int64
	if err := pool.QueryRow(bg(t), `SELECT min(id) FROM outbox`).Scan(&lowest); err != nil {
		t.Fatal(err)
	}
	if lowest != ids[3] {
		t.Fatalf("lowest remaining id %d, want %d", lowest, ids[3])
	}
}

func TestWriteRecordsWritingTransaction(t *testing.T) {
	t.Parallel()
	pool := srv.Database(t)
	var want, got string
	err := pgx.BeginFunc(bg(t), pool, func(tx pgx.Tx) error {
		// Write is the transaction's first statement: the row must still carry
		// the transaction's id.
		if _, err := outbox.Write(bg(t), tx, outbox.Event{Topic: "t.x", Key: "k", Data: 1}); err != nil {
			return err
		}
		if err := tx.QueryRow(bg(t), `SELECT pg_current_xact_id()::text`).Scan(&want); err != nil {
			return err
		}
		return tx.QueryRow(bg(t), `SELECT txid::text FROM outbox WHERE topic = 't.x'`).Scan(&got)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("row txid %s, transaction %s", got, want)
	}
}
