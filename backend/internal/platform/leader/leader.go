// Package leader elects one active instance among replicas with a
// PostgreSQL session-level advisory lock held on a dedicated connection.
// The leader's work runs under a context cancelled as soon as the lock
// session is lost, so a partitioned former leader stops within one ping
// interval of the server releasing the lock to a successor.
package leader

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSessionLost means the lock session failed while leading.
var ErrSessionLost = errors.New("leader: lock session lost")

// Config configures an election.
type Config struct {
	Name   string        // what is elected, e.g. "fxd"; hashed into the lock key
	Retry  time.Duration // standby polling interval (default 2 s)
	Ping   time.Duration // lock session watchdog interval (default 2 s)
	Logger *slog.Logger
	// OnState observes leadership changes (metrics, readiness).
	OnState func(leading bool)
}

// Key is the advisory lock key of an election name.
func Key(name string) int64 {
	h := fnv.New64a()
	h.Write([]byte("bilyon/leader/" + name))
	return int64(h.Sum64())
}

// Run stands by until it holds the lock, then runs lead. It returns nil
// when ctx is cancelled, lead's error when lead fails, and ErrSessionLost
// (wrapped) when the lock session fails while leading. Either way the lock
// is released; callers exit and let the supervisor restart them.
func Run(ctx context.Context, pool *pgxpool.Pool, cfg Config, lead func(ctx context.Context) error) error {
	if cfg.Name == "" {
		return errors.New("leader: a name is required")
	}
	if cfg.Retry == 0 {
		cfg.Retry = 2 * time.Second
	}
	if cfg.Ping == 0 {
		cfg.Ping = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	conn, err := acquire(ctx, pool, cfg)
	if err != nil || conn == nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	cfg.Logger.InfoContext(ctx, "leadership acquired", slog.String("election", cfg.Name))
	if cfg.OnState != nil {
		cfg.OnState(true)
		defer cfg.OnState(false)
	}
	leadCtx, cancel := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(cfg.Ping)
		defer t.Stop()
		for {
			select {
			case <-leadCtx.Done():
				return
			case <-t.C:
			}
			pingCtx, done := context.WithTimeout(leadCtx, cfg.Ping)
			err := conn.Ping(pingCtx)
			done()
			if err != nil && leadCtx.Err() == nil {
				cancel(fmt.Errorf("%w: %v", ErrSessionLost, err))
				return
			}
		}
	})
	err = lead(leadCtx)
	cause := context.Cause(leadCtx)
	cancel(nil)
	wg.Wait()
	cfg.Logger.InfoContext(ctx, "leadership released", slog.String("election", cfg.Name))
	if errors.Is(cause, ErrSessionLost) {
		return cause
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// acquire opens a dedicated session and polls for the lock; it returns a
// nil connection when ctx is cancelled first.
func acquire(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*pgx.Conn, error) {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil
		}
		return nil, fmt.Errorf("leader: session: %w", err)
	}
	standby := false
	for {
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, Key(cfg.Name)).Scan(&got); err != nil {
			_ = conn.Close(context.WithoutCancel(ctx))
			if ctx.Err() != nil {
				return nil, nil
			}
			return nil, fmt.Errorf("leader: lock: %w", err)
		}
		if got {
			return conn, nil
		}
		if !standby {
			standby = true
			cfg.Logger.InfoContext(ctx, "another instance leads; standing by", slog.String("election", cfg.Name))
		}
		select {
		case <-ctx.Done():
			_ = conn.Close(context.WithoutCancel(ctx))
			return nil, nil
		case <-time.After(cfg.Retry):
		}
	}
}
