// Package ledgerd is the ledger daemon: it applies migrations and runs the
// ledger's background machinery (outbox relay to NATS JetStream, hold
// expiry, continuous audit, idempotency retention) behind health and
// metrics endpoints. cmd/ledgerd is a thin wrapper around Main.
package ledgerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
	"github.com/bil1234n/bilyon/backend/internal/migrate"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
	"github.com/bil1234n/bilyon/backend/internal/outbox/natspub"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/httpserver"
	"github.com/bil1234n/bilyon/backend/internal/platform/lifecycle"
	"github.com/bil1234n/bilyon/backend/internal/platform/logging"
	"github.com/bil1234n/bilyon/backend/internal/platform/pgpool"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// Config is the daemon's configuration (environment variables in brackets).
type Config struct {
	DatabaseURL          string        // BILYON_DATABASE_URL (required)
	DBMaxConns           int           // BILYON_DB_MAX_CONNS
	NATSURL              string        // BILYON_NATS_URL (required for run)
	StreamName           string        // BILYON_NATS_STREAM
	SubjectPrefix        string        // BILYON_NATS_SUBJECT_PREFIX
	StreamReplicas       int           // BILYON_NATS_STREAM_REPLICAS
	HTTPAddr             string        // BILYON_HTTP_ADDR
	MigrateOnStart       bool          // BILYON_MIGRATE_ON_START
	LogLevel             string        // BILYON_LOG_LEVEL
	LogFormat            string        // BILYON_LOG_FORMAT
	HoldSweepInterval    time.Duration // BILYON_HOLD_SWEEP_INTERVAL
	AuditInterval        time.Duration // BILYON_AUDIT_INTERVAL
	IdempotencyRetention time.Duration // BILYON_IDEMPOTENCY_RETENTION
	OutboxRetention      time.Duration // BILYON_OUTBOX_RETENTION
}

// LoadConfig reads and validates the configuration.
func LoadConfig(env *config.Env, needNATS bool) (Config, error) {
	c := Config{
		DatabaseURL:          env.Required("BILYON_DATABASE_URL"),
		DBMaxConns:           env.Int("BILYON_DB_MAX_CONNS", 20, 2, 1000),
		StreamName:           env.String("BILYON_NATS_STREAM", "BILYON_LEDGER"),
		SubjectPrefix:        env.String("BILYON_NATS_SUBJECT_PREFIX", "bilyon"),
		StreamReplicas:       env.Int("BILYON_NATS_STREAM_REPLICAS", 1, 1, 5),
		HTTPAddr:             env.String("BILYON_HTTP_ADDR", ":9090"),
		MigrateOnStart:       env.Bool("BILYON_MIGRATE_ON_START", false),
		LogLevel:             env.OneOf("BILYON_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:            env.OneOf("BILYON_LOG_FORMAT", "json", "json", "text"),
		HoldSweepInterval:    env.Duration("BILYON_HOLD_SWEEP_INTERVAL", time.Second),
		AuditInterval:        env.Duration("BILYON_AUDIT_INTERVAL", 15*time.Minute),
		IdempotencyRetention: env.Duration("BILYON_IDEMPOTENCY_RETENTION", 30*24*time.Hour),
		OutboxRetention:      env.Duration("BILYON_OUTBOX_RETENTION", 72*time.Hour),
	}
	if needNATS {
		c.NATSURL = env.Required("BILYON_NATS_URL")
	} else {
		c.NATSURL = env.String("BILYON_NATS_URL", "")
	}
	return c, env.Err()
}

// Hooks lets tests observe the running daemon.
type Hooks struct {
	// OnListening receives the bound address of the operational server.
	OnListening func(addr string)
}

const usage = `usage: ledgerd <command>

commands:
  run      run the ledger workers (default)
  migrate  apply pending migrations and exit
  status   print migration status
  audit    verify every ledger invariant; exit 1 on any discrepancy
`

// Main runs a command and returns the process exit code.
func Main(ctx context.Context, args []string, env *config.Env, stdout, stderr io.Writer, hooks Hooks) int {
	cmd := "run"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if cmd != "run" && cmd != "migrate" && cmd != "status" && cmd != "audit" {
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	cfg, err := LoadConfig(env, cmd == "run")
	if err != nil {
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return 2
	}
	log, err := logging.New(stderr, cfg.LogLevel, cfg.LogFormat, "ledgerd")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	pool, err := pgpool.New(ctx, cfg.DatabaseURL, pgpool.Options{MaxConns: int32(cfg.DBMaxConns), AppName: "ledgerd"})
	if err != nil {
		log.ErrorContext(ctx, "database unavailable", slog.Any("error", err))
		return 1
	}
	defer pool.Close()
	ms, err := migrate.Load(migrations.Ledger, migrations.LedgerDir)
	if err != nil {
		log.ErrorContext(ctx, "load migrations", slog.Any("error", err))
		return 1
	}
	switch cmd {
	case "migrate":
		applied, err := migrate.Apply(ctx, pool, ms, migrate.Options{Logger: log})
		if err != nil {
			log.ErrorContext(ctx, "migration failed", slog.Any("error", err))
			return 1
		}
		fmt.Fprintf(stdout, "applied %d migration(s)\n", len(applied))
		return 0
	case "status":
		lines, err := migrate.Status(ctx, pool, ms, "")
		if err != nil {
			log.ErrorContext(ctx, "status failed", slog.Any("error", err))
			return 1
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "VERSION\tNAME\tAPPLIED\tMODIFIED")
		for _, l := range lines {
			fmt.Fprintf(tw, "%04d\t%s\t%v\t%v\n", l.Version, l.Name, l.Applied, l.Modified)
		}
		_ = tw.Flush()
		return 0
	case "audit":
		report, err := pgledger.New(pool, pgledger.WithLogger(log)).Audit(ctx)
		if err != nil {
			log.ErrorContext(ctx, "audit failed to run", slog.Any("error", err))
			return 1
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		if !report.OK() {
			return 1
		}
		return 0
	}
	if err := Run(ctx, cfg, pool, ms, log, hooks); err != nil {
		log.ErrorContext(ctx, "ledgerd stopped with an error", slog.Any("error", err))
		return 1
	}
	return 0
}

// Run starts every worker and blocks until ctx is cancelled or one fails.
func Run(ctx context.Context, cfg Config, pool *pgxpool.Pool, ms []migrate.Migration, log *slog.Logger, hooks Hooks) error {
	if cfg.MigrateOnStart {
		if _, err := migrate.Apply(ctx, pool, ms, migrate.Options{Logger: log}); err != nil {
			return fmt.Errorf("migrate on start: %w", err)
		}
	}
	nc, err := nats.Connect(cfg.NATSURL, nats.Name("ledgerd"), nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond), nats.Timeout(5*time.Second))
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}
	defer nc.Close()
	pub, err := natspub.New(ctx, nc, natspub.StreamConfig{Name: cfg.StreamName, SubjectPrefix: cfg.SubjectPrefix,
		Replicas: cfg.StreamReplicas, EnsureOnConnect: true})
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	eng := pgledger.New(pool, pgledger.WithLogger(log))
	relay := outbox.NewRelay(pool, pub, outbox.RelayConfig{Retention: cfg.OutboxRetention, Logger: log, Registerer: reg})

	expirer := &holdExpirer{eng: eng, interval: cfg.HoldSweepInterval, batch: 500, log: log,
		expired: prometheus.NewCounter(prometheus.CounterOpts{Name: "bilyon_ledger_holds_expired_total", Help: "Holds expired by the sweeper."})}
	aud := &auditor{eng: eng, interval: cfg.AuditInterval, log: log,
		discrepancies: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_ledger_audit_discrepancies",
			Help: "Invariant violations found by the last audit (alert when > 0)."}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_ledger_audit_last_success_timestamp_seconds",
			Help: "Unix time of the last completed audit."})}
	pruner := &idempotencyPruner{pool: pool, retention: cfg.IdempotencyRetention, interval: time.Hour, log: log,
		pruned: prometheus.NewCounter(prometheus.CounterOpts{Name: "bilyon_ledger_idempotency_pruned_total", Help: "Idempotency keys pruned."})}
	reg.MustRegister(expirer.expired, aud.discrepancies, aud.lastSuccess, pruner.pruned)

	ops := httpserver.New(cfg.HTTPAddr, reg, log)
	ops.AddCheck("postgres", func(ctx context.Context) error { return pool.Ping(ctx) })
	ops.AddCheck("nats", func(context.Context) error {
		if !nc.IsConnected() {
			return errors.New("not connected")
		}
		return nil
	})
	addr, err := ops.Listen()
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.HTTPAddr, err)
	}
	log.InfoContext(ctx, "ledgerd listening", slog.String("addr", addr))
	if hooks.OnListening != nil {
		hooks.OnListening(addr)
	}
	return lifecycle.Run(ctx, log,
		lifecycle.Component{Name: "ops-http", Run: ops.Run},
		lifecycle.Component{Name: "outbox-relay", Run: relay.Run},
		lifecycle.Component{Name: "hold-expirer", Run: expirer.Run},
		lifecycle.Component{Name: "auditor", Run: aud.Run},
		lifecycle.Component{Name: "idempotency-pruner", Run: pruner.Run},
	)
}
