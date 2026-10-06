package leader

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, nil, &srv)) }

func TestOneLeaderAtATime(t *testing.T) {
	pool := srv.Database(t)
	var leaders, maxLeaders atomic.Int32
	var transitions atomic.Int32
	ctxs := make([]context.CancelFunc, 3)
	var wg sync.WaitGroup
	started := make(chan int, 3)
	for i := range ctxs {
		ctx, cancel := context.WithCancel(context.Background())
		ctxs[i] = cancel
		wg.Go(func() {
			err := Run(ctx, pool, Config{Name: "test", Retry: 20 * time.Millisecond, Ping: 50 * time.Millisecond,
				OnState: func(bool) { transitions.Add(1) }},
				func(ctx context.Context) error {
					n := leaders.Add(1)
					for {
						if m := maxLeaders.Load(); n <= m || maxLeaders.CompareAndSwap(m, n) {
							break
						}
					}
					started <- i
					<-ctx.Done()
					leaders.Add(-1)
					return nil
				})
			if err != nil {
				t.Errorf("instance %d: %v", i, err)
			}
		})
	}
	// Cancel each leader in turn; a standby must take over every time.
	for range ctxs {
		select {
		case i := <-started:
			time.Sleep(100 * time.Millisecond) // give a would-be second leader time to appear
			ctxs[i]()
		case <-time.After(10 * time.Second):
			t.Fatal("no leader elected")
		}
	}
	wg.Wait()
	if maxLeaders.Load() != 1 {
		t.Fatalf("%d concurrent leaders", maxLeaders.Load())
	}
	if transitions.Load() != 6 {
		t.Fatalf("%d leadership transitions, want 3 up and 3 down", transitions.Load())
	}
}

func TestLeadErrorAndSessionLoss(t *testing.T) {
	pool := srv.Database(t)
	boom := errors.New("boom")
	if err := Run(context.Background(), pool, Config{Name: "err"}, func(context.Context) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("lead error: %v", err)
	}
	// Losing the session cancels the leader's context.
	err := Run(context.Background(), pool, Config{Name: "lost", Ping: 20 * time.Millisecond}, func(ctx context.Context) error {
		if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_locks
			WHERE locktype = 'advisory' AND objid = ($1::bigint & 4294967295)::oid AND granted`, Key("lost")); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	})
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("session loss: %v", err)
	}
	// After the loss the lock is free again.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Run(ctx, pool, Config{Name: "lost"}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("relock: %v", err)
	}
	if err := Run(context.Background(), pool, Config{}, nil); err == nil {
		t.Fatal("an unnamed election ran")
	}
	// Cancelling while standing by returns nil.
	hold, release := context.WithCancel(context.Background())
	held := make(chan struct{})
	go func() {
		_ = Run(hold, pool, Config{Name: "busy"}, func(ctx context.Context) error { close(held); <-ctx.Done(); return nil })
	}()
	<-held
	waiting, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stop()
	if err := Run(waiting, pool, Config{Name: "busy", Retry: 20 * time.Millisecond}, func(context.Context) error {
		t.Error("a second instance led while the lock was held")
		return nil
	}); err != nil {
		t.Fatalf("standby cancelled: %v", err)
	}
	release()
}
