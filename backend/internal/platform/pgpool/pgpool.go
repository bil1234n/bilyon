// Package pgpool creates PostgreSQL connection pools with production defaults.
package pgpool

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Options tune a pool.
type Options struct {
	MaxConns         int32         // default 20
	MinConns         int32         // default 2
	AppName          string        // shown in pg_stat_activity
	StatementTimeout time.Duration // server-side per statement, default 30s
	IdleInTxTimeout  time.Duration // kills sessions stuck in a transaction, default 60s
}

// New parses url, applies opts and verifies connectivity.
func New(ctx context.Context, url string, opts Options) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("pgpool: parse url: %w", err)
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 20
	}
	if opts.MinConns <= 0 {
		opts.MinConns = 2
	}
	if opts.StatementTimeout <= 0 {
		opts.StatementTimeout = 30 * time.Second
	}
	if opts.IdleInTxTimeout <= 0 {
		opts.IdleInTxTimeout = 60 * time.Second
	}
	cfg.MaxConns, cfg.MinConns = opts.MaxConns, min(opts.MinConns, opts.MaxConns)
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnLifetimeJitter = 5 * time.Minute
	cfg.MaxConnIdleTime = 10 * time.Minute
	cfg.HealthCheckPeriod = 15 * time.Second
	rp := cfg.ConnConfig.RuntimeParams
	if opts.AppName != "" {
		rp["application_name"] = opts.AppName
	}
	rp["statement_timeout"] = strconv.FormatInt(opts.StatementTimeout.Milliseconds(), 10)
	rp["idle_in_transaction_session_timeout"] = strconv.FormatInt(opts.IdleInTxTimeout.Milliseconds(), 10)
	rp["timezone"] = "UTC"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgpool: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgpool: ping: %w", err)
	}
	return pool, nil
}
