package idempotency_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/bil1234n/bilyon/backend/internal/idempotency"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
)

func hash(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestBeginCompleteReplayConflict(t *testing.T) {
	g := idempotency.New(redistest.Start(t), idempotency.Config{})
	out, claim, _, err := g.Begin(ctx(t), "k1", hash("a"))
	if err != nil || out != idempotency.Claimed || claim == nil {
		t.Fatalf("begin: %v %v", out, err)
	}
	if out, _, _, err := g.Begin(ctx(t), "k1", hash("a")); err != nil || out != idempotency.InProgress {
		t.Fatalf("duplicate while in flight: %v %v", out, err)
	}
	if _, _, _, err := g.Begin(ctx(t), "k1", hash("b")); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("different payload while in flight: %v", err)
	}
	if err := g.Complete(ctx(t), claim, []byte(`{"id":1}`)); err != nil {
		t.Fatal(err)
	}
	out, _, resp, err := g.Begin(ctx(t), "k1", hash("a"))
	if err != nil || out != idempotency.Replayed || string(resp) != `{"id":1}` {
		t.Fatalf("replay: %v %q %v", out, resp, err)
	}
	if _, _, _, err := g.Begin(ctx(t), "k1", hash("b")); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("different payload after completion: %v", err)
	}
}

func TestAbortAllowsRetryAndFencesExpiredClaims(t *testing.T) {
	rdb := redistest.Start(t)
	g := idempotency.New(rdb, idempotency.Config{LockTTL: 200 * time.Millisecond})
	_, claim, _, _ := g.Begin(ctx(t), "k2", hash("x"))
	if err := g.Abort(ctx(t), claim); err != nil {
		t.Fatal(err)
	}
	out, stale, _, err := g.Begin(ctx(t), "k2", hash("x"))
	if err != nil || out != idempotency.Claimed {
		t.Fatalf("claim after abort: %v %v", out, err)
	}
	time.Sleep(300 * time.Millisecond) // the claim's lock expires
	out, fresh, _, err := g.Begin(ctx(t), "k2", hash("x"))
	if err != nil || out != idempotency.Claimed {
		t.Fatalf("claim after expiry: %v %v", out, err)
	}
	if err := g.Complete(ctx(t), stale, []byte("stale")); !errors.Is(err, idempotency.ErrLost) {
		t.Fatalf("expired claim completed: %v", err)
	}
	if err := g.Abort(ctx(t), stale); err != nil {
		t.Fatal(err)
	}
	if err := g.Complete(ctx(t), fresh, []byte("fresh")); err != nil {
		t.Fatalf("stale abort removed the fresh claim: %v", err)
	}
	_, _, resp, _ := g.Begin(ctx(t), "k2", hash("x"))
	if string(resp) != "fresh" {
		t.Fatalf("stored response %q", resp)
	}
	ttl, err := rdb.PTTL(ctx(t), "bilyon:idem:k2").Result()
	if err != nil || ttl < 23*time.Hour {
		t.Fatalf("result TTL %v %v", ttl, err)
	}
}

func TestDoCollapsesConcurrentDuplicates(t *testing.T) {
	g := idempotency.New(redistest.Start(t), idempotency.Config{})
	var calls atomic.Int32
	const n = 32
	results := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			results[i], errs[i] = g.Do(ctx(t), "k3", hash("same"), func(context.Context) ([]byte, error) {
				calls.Add(1)
				time.Sleep(50 * time.Millisecond)
				return []byte("done"), nil
			})
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("command executed %d times", calls.Load())
	}
	for i := range n {
		if errs[i] != nil || string(results[i]) != "done" {
			t.Fatalf("caller %d: %q %v", i, results[i], errs[i])
		}
	}
}

func TestDoReleasesKeyOnFailureAndReportsLongInFlight(t *testing.T) {
	g := idempotency.New(redistest.Start(t), idempotency.Config{WaitTimeout: 100 * time.Millisecond})
	boom := errors.New("insufficient funds")
	if _, err := g.Do(ctx(t), "k4", hash("p"), func(context.Context) ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("error not propagated: %v", err)
	}
	resp, err := g.Do(ctx(t), "k4", hash("p"), func(context.Context) ([]byte, error) { return []byte("ok"), nil })
	if err != nil || string(resp) != "ok" {
		t.Fatalf("retry after failure: %q %v", resp, err)
	}
	_, held, _, _ := g.Begin(ctx(t), "k5", hash("slow"))
	if _, err := g.Do(ctx(t), "k5", hash("slow"), func(context.Context) ([]byte, error) {
		return nil, errors.New("must not run")
	}); !errors.Is(err, idempotency.ErrInProgress) {
		t.Fatalf("waiting on a stuck duplicate: %v", err)
	}
	_ = g.Abort(ctx(t), held)
}

func TestFailOpenWhenRedisIsDown(t *testing.T) {
	down := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond, MaxRetries: -1})
	defer down.Close()
	open := idempotency.New(down, idempotency.Config{FailOpen: true})
	resp, err := open.Do(ctx(t), "k6", hash("z"), func(context.Context) ([]byte, error) { return []byte("db"), nil })
	if err != nil || string(resp) != "db" {
		t.Fatalf("fail-open: %q %v", resp, err)
	}
	closed := idempotency.New(down, idempotency.Config{FailOpen: false})
	if _, err := closed.Do(ctx(t), "k6", hash("z"), func(context.Context) ([]byte, error) { return []byte("db"), nil }); err == nil {
		t.Fatal("fail-closed guard ran the command without Redis")
	}
}
