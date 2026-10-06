// Package tbshadow is the TigerBeetle shadow daemon (RFC 0001 §2.3.5): it
// replays the PostgreSQL ledger into TigerBeetle in serialization order and
// reconciles both at exact cuts, behind health and metrics endpoints.
// cmd/tbshadow is a thin wrapper around Main.
//
// The daemon is the consumer's only TigerBeetle writer: it holds a
// PostgreSQL advisory lock while tailing, and further instances stand by
// until the lock frees up.
package tbshadow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/bil1234n/bilyon/backend/internal/ledger/tbledger"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/httpserver"
	"github.com/bil1234n/bilyon/backend/internal/platform/lifecycle"
	"github.com/bil1234n/bilyon/backend/internal/platform/logging"
	"github.com/bil1234n/bilyon/backend/internal/platform/pgpool"
)

// Config is the daemon's configuration (environment variables in brackets).
type Config struct {
	DatabaseURL       string        // BILYON_DATABASE_URL (required)
	DBMaxConns        int           // BILYON_DB_MAX_CONNS
	TBAddresses       []string      // BILYON_TIGERBEETLE_ADDRESSES (required, comma-separated)
	TBClusterID       uint64        // BILYON_TIGERBEETLE_CLUSTER_ID
	Consumer          string        // BILYON_SHADOW_CONSUMER
	BatchSize         int           // BILYON_SHADOW_BATCH
	HoldGrace         time.Duration // BILYON_SHADOW_HOLD_GRACE
	AutoBootstrap     bool          // BILYON_SHADOW_AUTO_BOOTSTRAP
	ReconcileInterval time.Duration // BILYON_RECONCILE_INTERVAL (0 disables)
	HTTPAddr          string        // BILYON_HTTP_ADDR
	LogLevel          string        // BILYON_LOG_LEVEL
	LogFormat         string        // BILYON_LOG_FORMAT
}

// LoadConfig reads and validates the configuration.
func LoadConfig(env *config.Env) (Config, error) {
	c := Config{
		DatabaseURL:       env.Required("BILYON_DATABASE_URL"),
		DBMaxConns:        env.Int("BILYON_DB_MAX_CONNS", 8, 4, 200),
		Consumer:          env.String("BILYON_SHADOW_CONSUMER", tbledger.DefaultConsumer),
		BatchSize:         env.Int("BILYON_SHADOW_BATCH", 500, 1, 10_000),
		HoldGrace:         env.Duration("BILYON_SHADOW_HOLD_GRACE", tbledger.DefaultHoldGrace),
		AutoBootstrap:     env.Bool("BILYON_SHADOW_AUTO_BOOTSTRAP", true),
		ReconcileInterval: env.Duration("BILYON_RECONCILE_INTERVAL", time.Hour),
		HTTPAddr:          env.String("BILYON_HTTP_ADDR", ":9091"),
		LogLevel:          env.OneOf("BILYON_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:         env.OneOf("BILYON_LOG_FORMAT", "json", "json", "text"),
	}
	for _, a := range strings.Split(env.Required("BILYON_TIGERBEETLE_ADDRESSES"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			c.TBAddresses = append(c.TBAddresses, a)
		}
	}
	errs := []error{env.Err()}
	if raw := env.String("BILYON_TIGERBEETLE_CLUSTER_ID", "0"); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("BILYON_TIGERBEETLE_CLUSTER_ID: %w", err))
		}
		c.TBClusterID = id
	}
	if len(c.TBAddresses) == 0 && env.Err() == nil {
		errs = append(errs, errors.New("BILYON_TIGERBEETLE_ADDRESSES: no address given"))
	}
	if c.HoldGrace < 0 {
		errs = append(errs, errors.New("BILYON_SHADOW_HOLD_GRACE: must not be negative"))
	}
	if c.ReconcileInterval < 0 {
		errs = append(errs, errors.New("BILYON_RECONCILE_INTERVAL: must not be negative"))
	}
	return c, errors.Join(errs...)
}

// Hooks lets tests observe the running daemon.
type Hooks struct {
	// OnListening receives the bound address of the operational server.
	OnListening func(addr string)
	// OnReconciled receives each periodic reconciliation's result.
	OnReconciled func(mismatches []tbledger.Mismatch, err error)
}

const usage = `usage: tbshadow <command>

commands:
  run              tail the ledger into TigerBeetle and reconcile periodically (default)
  bootstrap        import the ledger into an empty TigerBeetle cluster and exit
  reconcile        catch up, compare every balance once, print mismatches; exit 1 on any
  reset-bootstrap  forget an unfinished bootstrap (reformat the cluster as well)
`

// Main runs a command and returns the process exit code.
func Main(ctx context.Context, args []string, env *config.Env, stdout, stderr io.Writer, hooks Hooks) int {
	cmd := "run"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "run", "bootstrap", "reconcile", "reset-bootstrap":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	cfg, err := LoadConfig(env)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return 2
	}
	log, err := logging.New(stderr, cfg.LogLevel, cfg.LogFormat, "tbshadow")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	pool, err := pgpool.New(ctx, cfg.DatabaseURL, pgpool.Options{MaxConns: int32(cfg.DBMaxConns), AppName: "tbshadow"})
	if err != nil {
		log.ErrorContext(ctx, "database unavailable", slog.Any("error", err))
		return 1
	}
	defer pool.Close()
	if cmd == "reset-bootstrap" {
		if err := tbledger.ResetBootstrap(ctx, pool, cfg.Consumer); err != nil {
			log.ErrorContext(ctx, "reset failed", slog.Any("error", err))
			return 1
		}
		fmt.Fprintf(stdout, "bootstrap of %q reset; reformat the TigerBeetle cluster before bootstrapping again\n", cfg.Consumer)
		return 0
	}
	d, err := tbledger.Open(cfg.TBClusterID, cfg.TBAddresses, tbledger.WithHoldGrace(cfg.HoldGrace))
	if err != nil {
		log.ErrorContext(ctx, "TigerBeetle unavailable", slog.Any("error", err))
		return 1
	}
	defer d.Close()
	// A request to an unreachable cluster blocks until the client closes.
	stopClose := context.AfterFunc(ctx, d.Close)
	defer stopClose()

	switch cmd {
	case "bootstrap":
		stats, err := tbledger.Bootstrap(ctx, pool, d, cfg.Consumer, log)
		if err != nil {
			log.ErrorContext(ctx, "bootstrap failed", slog.Any("error", err))
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(stats)
		return 0
	case "reconcile":
		return reconcileOnce(ctx, cfg, pool, d, log, stdout)
	}
	if err := Run(ctx, cfg, pool, d, log, hooks); err != nil {
		log.ErrorContext(ctx, "tbshadow stopped with an error", slog.Any("error", err))
		return 1
	}
	return 0
}

// reconcileOnce runs a tailer just long enough for one exact comparison. It
// refuses to wait for the lock: a running daemon reconciles on its own.
func reconcileOnce(ctx context.Context, cfg Config, pool *pgxpool.Pool, d *tbledger.Driver, log *slog.Logger, stdout io.Writer) int {
	tl := tbledger.NewTailer(pool, tbledger.NewMirror(d), tbledger.TailerConfig{Consumer: cfg.Consumer,
		BatchSize: cfg.BatchSize, LockWait: 5 * time.Second, Logger: log})
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- tl.Run(runCtx) }()
	type result struct {
		ms  []tbledger.Mismatch
		err error
	}
	res := make(chan result, 1)
	go func() {
		ms, err := tl.Reconcile(runCtx)
		res <- result{ms, err}
	}()
	select {
	case err := <-runErr:
		if err == nil {
			err = ctx.Err()
		}
		log.ErrorContext(ctx, "reconcile could not run", slog.Any("error", err))
		return 1
	case r := <-res:
		cancel()
		<-runErr
		if r.err != nil {
			log.ErrorContext(ctx, "reconcile failed", slog.Any("error", r.err))
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(map[string]any{"mismatches": nonNil(r.ms)})
		if len(r.ms) > 0 {
			return 1
		}
		return 0
	}
}

func nonNil(ms []tbledger.Mismatch) []tbledger.Mismatch {
	if ms == nil {
		return []tbledger.Mismatch{}
	}
	return ms
}

// Run tails and reconciles until ctx is cancelled or a component fails.
func Run(ctx context.Context, cfg Config, pool *pgxpool.Pool, d *tbledger.Driver, log *slog.Logger, hooks Hooks) error {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	tl := tbledger.NewTailer(pool, tbledger.NewMirror(d), tbledger.TailerConfig{Consumer: cfg.Consumer,
		BatchSize: cfg.BatchSize, AutoBootstrap: cfg.AutoBootstrap, Logger: log, Registerer: reg})
	rec := &reconciler{tl: tl, interval: cfg.ReconcileInterval, log: log, hook: hooks.OnReconciled,
		mismatches: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_tbshadow_reconcile_mismatches",
			Help: "Accounts whose TigerBeetle balance differed at the last reconciliation (alert when > 0)."}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_tbshadow_reconcile_last_success_timestamp_seconds",
			Help: "Unix time of the last completed reconciliation."}),
		duration: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_tbshadow_reconcile_duration_seconds",
			Help: "Duration of the last reconciliation."}),
	}
	reg.MustRegister(rec.mismatches, rec.lastSuccess, rec.duration)

	ping := &tbPinger{d: d}
	ops := httpserver.New(cfg.HTTPAddr, reg, log)
	ops.AddCheck("postgres", func(ctx context.Context) error { return pool.Ping(ctx) })
	ops.AddCheck("tigerbeetle", ping.check)
	addr, err := ops.Listen()
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.HTTPAddr, err)
	}
	log.InfoContext(ctx, "tbshadow listening", slog.String("addr", addr), slog.String("consumer", cfg.Consumer))
	if hooks.OnListening != nil {
		hooks.OnListening(addr)
	}
	return lifecycle.Run(ctx, log,
		lifecycle.Component{Name: "ops-http", Run: ops.Run},
		lifecycle.Component{Name: "tailer", Run: tl.Run},
		lifecycle.Component{Name: "reconciler", Run: rec.Run},
	)
}

// reconciler asks the tailer for an exact reconciliation every interval.
type reconciler struct {
	tl          *tbledger.Tailer
	interval    time.Duration
	log         *slog.Logger
	hook        func([]tbledger.Mismatch, error)
	mismatches  prometheus.Gauge
	lastSuccess prometheus.Gauge
	duration    prometheus.Gauge
}

func (r *reconciler) Run(ctx context.Context) error {
	if r.interval == 0 {
		<-ctx.Done()
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(r.interval):
		}
		start := time.Now()
		rctx, cancel := context.WithTimeout(ctx, max(r.interval, time.Minute))
		ms, err := r.tl.Reconcile(rctx)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if r.hook != nil {
			r.hook(ms, err)
		}
		if err != nil {
			r.log.WarnContext(ctx, "reconciliation did not complete", slog.Any("error", err))
			continue
		}
		r.duration.Set(time.Since(start).Seconds())
		r.mismatches.Set(float64(len(ms)))
		r.lastSuccess.SetToCurrentTime()
		if len(ms) == 0 {
			r.log.InfoContext(ctx, "reconciliation clean", slog.Duration("took", time.Since(start)))
			continue
		}
		for i, m := range ms {
			if i == 20 {
				r.log.ErrorContext(ctx, "further mismatches omitted", slog.Int("total", len(ms)))
				break
			}
			r.log.ErrorContext(ctx, "reconciliation mismatch", slog.String("account", m.AccountID.String()),
				slog.String("detail", m.String()))
		}
	}
}

// tbPinger keeps at most one no-op request in flight: a request to an
// unreachable cluster blocks, and readiness probes must not pile them up.
type tbPinger struct {
	d    *tbledger.Driver
	busy atomic.Bool
}

func (p *tbPinger) check(ctx context.Context) error {
	if !p.busy.CompareAndSwap(false, true) {
		return errors.New("previous ping still waiting for the cluster")
	}
	done := make(chan error, 1)
	go func() {
		defer p.busy.Store(false)
		done <- p.d.Ping()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
