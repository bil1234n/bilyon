// Package fxd is the FX engine daemon (RFC 0001 §3.C). Every replica keeps
// a warm liquidity graph from the NATS market-data feed; one replica, the
// leader elected through a PostgreSQL advisory lock, recovers the open
// quotes' reservations and serves quotes and executions. Standbys answer
// UNAVAILABLE and report not ready, so traffic reaches the leader only.
// cmd/fxd is a thin wrapper around Main.
package fxd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	fxv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/fx/v1"
	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/fxapi"
	"github.com/bil1234n/bilyon/backend/internal/ledgerapi"
	"github.com/bil1234n/bilyon/backend/internal/migrate"
	"github.com/bil1234n/bilyon/backend/internal/outbox"
	"github.com/bil1234n/bilyon/backend/internal/outbox/natspub"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/grpcx"
	"github.com/bil1234n/bilyon/backend/internal/platform/httpserver"
	"github.com/bil1234n/bilyon/backend/internal/platform/leader"
	"github.com/bil1234n/bilyon/backend/internal/platform/lifecycle"
	"github.com/bil1234n/bilyon/backend/internal/platform/logging"
	"github.com/bil1234n/bilyon/backend/internal/platform/pgpool"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// MigrationsTable records the FX schema's applied migrations.
const MigrationsTable = "fx_schema_migrations"

// Config is the daemon's configuration (environment variables in brackets).
type Config struct {
	DatabaseURL    string // BILYON_DATABASE_URL (required)
	DBMaxConns     int    // BILYON_DB_MAX_CONNS
	NATSURL        string // BILYON_NATS_URL (required for run)
	StreamName     string // BILYON_NATS_STREAM
	SubjectPrefix  string // BILYON_NATS_SUBJECT_PREFIX
	StreamReplicas int    // BILYON_NATS_STREAM_REPLICAS
	// MarketSubject prefixes the market-data subjects: <prefix>.ladder
	// carries {"edge", "ladder", "at"}, <prefix>.mid {"from", "to", "rate", "at"}.
	MarketSubject   string        // BILYON_FX_MARKET_SUBJECT
	MarketFile      string        // BILYON_FX_MARKET_FILE (required for run)
	QuoteKeysFile   string        // BILYON_FX_QUOTE_KEYS_FILE (required for run)
	HTTPAddr        string        // BILYON_HTTP_ADDR
	MigrateOnStart  bool          // BILYON_MIGRATE_ON_START
	LogLevel        string        // BILYON_LOG_LEVEL
	LogFormat       string        // BILYON_LOG_FORMAT
	SweepInterval   time.Duration // BILYON_FX_SWEEP_INTERVAL: expiry of open quotes
	ResumeInterval  time.Duration // BILYON_FX_RESUME_INTERVAL: retries of pending bookings
	ResumeAfter     time.Duration // BILYON_FX_RESUME_AFTER: how long a booking may pend first
	LockRetry       time.Duration // BILYON_FX_LOCK_RETRY: standby polling
	OutboxRetention time.Duration // BILYON_OUTBOX_RETENTION

	GRPCAddr     string         // BILYON_GRPC_ADDR (required for run)
	GRPCTLS      grpcx.TLSFiles // BILYON_GRPC_TLS_CERT, BILYON_GRPC_TLS_KEY, BILYON_GRPC_TLS_CA
	GRPCACL      grpcx.ACL      // BILYON_GRPC_ACL
	GRPCInsecure bool           // BILYON_GRPC_INSECURE (development only)

	LedgerAddr     string         // BILYON_LEDGER_ADDR (required for run)
	LedgerTLS      grpcx.TLSFiles // BILYON_LEDGER_TLS_CERT, BILYON_LEDGER_TLS_KEY, BILYON_LEDGER_TLS_CA
	LedgerInsecure bool           // BILYON_LEDGER_INSECURE (development only)
}

// LoadConfig reads and validates the configuration.
func LoadConfig(env *config.Env, run bool) (Config, error) {
	c := Config{
		DatabaseURL:     env.Required("BILYON_DATABASE_URL"),
		DBMaxConns:      env.Int("BILYON_DB_MAX_CONNS", 20, 2, 1000),
		StreamName:      env.String("BILYON_NATS_STREAM", "BILYON_FX"),
		SubjectPrefix:   env.String("BILYON_NATS_SUBJECT_PREFIX", "bilyon"),
		StreamReplicas:  env.Int("BILYON_NATS_STREAM_REPLICAS", 1, 1, 5),
		MarketSubject:   env.String("BILYON_FX_MARKET_SUBJECT", "bilyon.market"),
		HTTPAddr:        env.String("BILYON_HTTP_ADDR", ":9090"),
		MigrateOnStart:  env.Bool("BILYON_MIGRATE_ON_START", false),
		LogLevel:        env.OneOf("BILYON_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:       env.OneOf("BILYON_LOG_FORMAT", "json", "json", "text"),
		SweepInterval:   env.Duration("BILYON_FX_SWEEP_INTERVAL", time.Second),
		ResumeInterval:  env.Duration("BILYON_FX_RESUME_INTERVAL", 10*time.Second),
		ResumeAfter:     env.Duration("BILYON_FX_RESUME_AFTER", 30*time.Second),
		LockRetry:       env.Duration("BILYON_FX_LOCK_RETRY", 2*time.Second),
		OutboxRetention: env.Duration("BILYON_OUTBOX_RETENTION", 72*time.Hour),
	}
	errs := []error{}
	if run {
		c.NATSURL = env.Required("BILYON_NATS_URL")
		c.MarketFile = env.Required("BILYON_FX_MARKET_FILE")
		c.QuoteKeysFile = env.Required("BILYON_FX_QUOTE_KEYS_FILE")
		c.GRPCAddr = env.Required("BILYON_GRPC_ADDR")
		c.GRPCInsecure = env.Bool("BILYON_GRPC_INSECURE", false)
		if !c.GRPCInsecure {
			c.GRPCTLS = grpcx.TLSFiles{CertFile: env.Required("BILYON_GRPC_TLS_CERT"),
				KeyFile: env.Required("BILYON_GRPC_TLS_KEY"), CAFile: env.Required("BILYON_GRPC_TLS_CA")}
			acl, err := grpcx.ParseACL(env.Required("BILYON_GRPC_ACL"))
			if err != nil {
				errs = append(errs, fmt.Errorf("BILYON_GRPC_ACL: %w", err))
			}
			c.GRPCACL = acl
		}
		c.LedgerAddr = env.Required("BILYON_LEDGER_ADDR")
		c.LedgerInsecure = env.Bool("BILYON_LEDGER_INSECURE", false)
		if !c.LedgerInsecure {
			c.LedgerTLS = grpcx.TLSFiles{CertFile: env.Required("BILYON_LEDGER_TLS_CERT"),
				KeyFile: env.Required("BILYON_LEDGER_TLS_KEY"), CAFile: env.Required("BILYON_LEDGER_TLS_CA")}
		}
	}
	return c, errors.Join(append([]error{env.Err()}, errs...)...)
}

// Hooks lets tests observe the running daemon.
type Hooks struct {
	OnListening     func(addr string) // operational HTTP server
	OnGRPCListening func(addr string) // FX API
	OnLeading       func(leading bool)
}

const usage = `usage: fxd <command>

commands:
  run      run the FX engine (default)
  migrate  apply pending migrations and exit
  status   print migration status
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
	if cmd != "run" && cmd != "migrate" && cmd != "status" {
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	cfg, err := LoadConfig(env, cmd == "run")
	if err != nil {
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return 2
	}
	log, err := logging.New(stderr, cfg.LogLevel, cfg.LogFormat, "fxd")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	pool, err := pgpool.New(ctx, cfg.DatabaseURL, pgpool.Options{MaxConns: int32(cfg.DBMaxConns), AppName: "fxd"})
	if err != nil {
		log.ErrorContext(ctx, "database unavailable", slog.Any("error", err))
		return 1
	}
	defer pool.Close()
	ms, err := migrate.Load(migrations.FX, migrations.FXDir)
	if err != nil {
		log.ErrorContext(ctx, "load migrations", slog.Any("error", err))
		return 1
	}
	switch cmd {
	case "migrate":
		applied, err := migrate.Apply(ctx, pool, ms, migrate.Options{Table: MigrationsTable, Logger: log})
		if err != nil {
			log.ErrorContext(ctx, "migration failed", slog.Any("error", err))
			return 1
		}
		fmt.Fprintf(stdout, "applied %d migration(s)\n", len(applied))
		return 0
	case "status":
		lines, err := migrate.Status(ctx, pool, ms, MigrationsTable)
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
	}
	if err := Run(ctx, cfg, pool, ms, log, hooks); err != nil {
		log.ErrorContext(ctx, "fxd stopped with an error", slog.Any("error", err))
		return 1
	}
	return 0
}

type metrics struct {
	leading     prometheus.Gauge
	quarantined prometheus.Gauge
	feed        *prometheus.CounterVec
	swept       prometheus.Counter
	resumed     *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		leading: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_fx_leader",
			Help: "1 while this instance is the elected FX engine."}),
		quarantined: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_fx_edges_quarantined",
			Help: "Edges quarantined for closing an arbitrage cycle (alert when > 0)."}),
		feed: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_fx_market_updates_total",
			Help: "Market-data updates by kind and outcome."}, []string{"kind", "outcome"}),
		swept: prometheus.NewCounter(prometheus.CounterOpts{Name: "bilyon_fx_quotes_expired_total",
			Help: "Open quotes expired by the sweeper."}),
		resumed: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_fx_bookings_resumed_total",
			Help: "Pending bookings resumed by the recovery sweeper, by outcome."}, []string{"outcome"}),
	}
	reg.MustRegister(m.leading, m.quarantined, m.feed, m.swept, m.resumed)
	return m
}

// Run starts the daemon and blocks until ctx is cancelled or a component fails.
func Run(ctx context.Context, cfg Config, pool *pgxpool.Pool, ms []migrate.Migration, log *slog.Logger, hooks Hooks) error {
	if cfg.MigrateOnStart {
		if _, err := migrate.Apply(ctx, pool, ms, migrate.Options{Table: MigrationsTable, Logger: log}); err != nil {
			return fmt.Errorf("migrate on start: %w", err)
		}
	}
	market, err := LoadMarket(cfg.MarketFile)
	if err != nil {
		return err
	}
	keys, err := LoadQuoteKeys(cfg.QuoteKeysFile)
	if err != nil {
		return err
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := newMetrics(reg)

	var leading atomic.Bool
	notes := newNotifier(pool, &leading, m, log)
	g, err := market.Graph(fx.GraphConfig{OnQuarantine: notes.quarantine, OnRelease: notes.release})
	if err != nil {
		return err
	}
	ledgerConn, err := dialLedger(cfg)
	if err != nil {
		return err
	}
	defer ledgerConn.Close()
	ecfg := market.EngineConfig(keys)
	ecfg.Logger = log
	eng, err := fx.NewEngine(ecfg, g, pool, ledgerapi.NewClient(ledgerConn))
	if err != nil {
		return err
	}

	nc, err := nats.Connect(cfg.NATSURL, nats.Name("fxd"), nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond), nats.Timeout(5*time.Second))
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}
	defer nc.Close()
	if err := subscribeMarket(nc, cfg.MarketSubject, eng, m, log); err != nil {
		return err
	}
	pub, err := natspub.New(ctx, nc, natspub.StreamConfig{Name: cfg.StreamName, SubjectPrefix: cfg.SubjectPrefix,
		Subjects: []string{cfg.SubjectPrefix + ".fx.>"}, Replicas: cfg.StreamReplicas, EnsureOnConnect: true})
	if err != nil {
		return err
	}
	relay := outbox.NewRelay(pool, pub, outbox.RelayConfig{Retention: cfg.OutboxRetention, Logger: log, Registerer: reg})

	hs := health.NewServer()
	setLeading := func(l bool) {
		leading.Store(l)
		status := healthpb.HealthCheckResponse_NOT_SERVING
		if l {
			status = healthpb.HealthCheckResponse_SERVING
			m.leading.Set(1)
		} else {
			m.leading.Set(0)
		}
		hs.SetServingStatus(fxv1.FXService_ServiceDesc.ServiceName, status)
		if hooks.OnLeading != nil {
			hooks.OnLeading(l)
		}
	}
	setLeading(false)
	serve, err := grpcServer(cfg, eng, leading.Load, hs, log, reg, hooks)
	if err != nil {
		return err
	}

	ops := httpserver.New(cfg.HTTPAddr, reg, log)
	ops.AddCheck("postgres", func(ctx context.Context) error { return pool.Ping(ctx) })
	ops.AddCheck("nats", func(context.Context) error {
		if !nc.IsConnected() {
			return errors.New("not connected")
		}
		return nil
	})
	ops.AddCheck("leader", func(context.Context) error {
		if !leading.Load() {
			return errors.New("standby")
		}
		return nil
	})
	addr, err := ops.Listen()
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.HTTPAddr, err)
	}
	log.InfoContext(ctx, "fxd listening", slog.String("addr", addr))
	if hooks.OnListening != nil {
		hooks.OnListening(addr)
	}
	lead := func(ctx context.Context) error {
		executing, err := eng.Recover(ctx)
		if err != nil {
			return fmt.Errorf("recover: %w", err)
		}
		setLeading(true)
		defer setLeading(false)
		log.InfoContext(ctx, "FX engine leading", slog.Int("pending_bookings", len(executing)))
		w := &workers{eng: eng, cfg: cfg, m: m, log: log}
		w.resume(ctx, executing)
		return w.run(ctx)
	}
	return lifecycle.Run(ctx, log,
		lifecycle.Component{Name: "ops-http", Run: ops.Run},
		lifecycle.Component{Name: "outbox-relay", Run: relay.Run},
		lifecycle.Component{Name: "notifier", Run: notes.run},
		lifecycle.Component{Name: "grpc", Run: serve},
		lifecycle.Component{Name: "leader", Run: func(ctx context.Context) error {
			return leader.Run(ctx, pool, leader.Config{Name: "fxd", Retry: cfg.LockRetry, Logger: log}, lead)
		}},
	)
}

func dialLedger(cfg Config) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if cfg.LedgerInsecure {
		creds = insecure.NewCredentials()
	} else {
		c, err := grpcx.ClientTLS(cfg.LedgerTLS)
		if err != nil {
			return nil, err
		}
		creds = c
	}
	return grpc.NewClient(cfg.LedgerAddr, grpc.WithTransportCredentials(creds),
		grpc.WithDefaultServiceConfig(grpcx.RetryServiceConfig))
}

// grpcServer binds the FX API; it answers UNAVAILABLE until leading.
func grpcServer(cfg Config, eng *fx.Engine, ready func() bool, hs *health.Server, log *slog.Logger,
	reg prometheus.Registerer, hooks Hooks) (func(context.Context) error, error) {
	var creds credentials.TransportCredentials
	if cfg.GRPCInsecure {
		log.Warn("gRPC FX API served WITHOUT TLS or authorisation (BILYON_GRPC_INSECURE); development only")
		creds = insecure.NewCredentials()
	} else {
		c, err := grpcx.ServerTLS(cfg.GRPCTLS)
		if err != nil {
			return nil, err
		}
		creds = c
	}
	s := grpc.NewServer(grpc.Creds(creds), grpc.ChainUnaryInterceptor(
		grpcx.RecoverUnary(log),
		grpcx.ObserveUnary(log, grpcx.NewMetrics(reg)),
		grpcx.AuthorizeUnary(cfg.GRPCACL, cfg.GRPCInsecure),
	))
	api := fxapi.NewServer(eng, ready, log)
	fxv1.RegisterFXServiceServer(s, api)
	fxv1.RegisterFXAdminServiceServer(s, api)
	healthpb.RegisterHealthServer(s, hs)
	l, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.GRPCAddr, err)
	}
	log.Info("FX gRPC API listening", slog.String("addr", l.Addr().String()), slog.Bool("mtls", !cfg.GRPCInsecure))
	if hooks.OnGRPCListening != nil {
		hooks.OnGRPCListening(l.Addr().String())
	}
	return func(ctx context.Context) error {
		errCh := make(chan error, 1)
		go func() { errCh <- s.Serve(l) }()
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			hs.Shutdown()
			stopped := make(chan struct{})
			go func() { s.GracefulStop(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(10 * time.Second):
				s.Stop()
			}
			return nil
		}
	}, nil
}

// LadderUpdate is a market-data message on <MarketSubject>.ladder.
type LadderUpdate struct {
	Edge   string     `json:"edge"`
	Ladder []fx.Level `json:"ladder"`
	At     time.Time  `json:"at"`
}

// MidUpdate is a market-data message on <MarketSubject>.mid.
type MidUpdate struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	Rate string    `json:"rate"`
	At   time.Time `json:"at"`
}

// subscribeMarket applies streamed ladders and mid rates; every replica
// subscribes, so a standby's graph is warm when it takes over.
func subscribeMarket(nc *nats.Conn, prefix string, eng *fx.Engine, m *metrics, log *slog.Logger) error {
	apply := func(kind string, fn func([]byte) error) nats.MsgHandler {
		return func(msg *nats.Msg) {
			if err := fn(msg.Data); err != nil {
				m.feed.WithLabelValues(kind, "rejected").Inc()
				log.Warn("market update rejected", slog.String("kind", kind), slog.Any("error", err))
				return
			}
			m.feed.WithLabelValues(kind, "applied").Inc()
		}
	}
	if _, err := nc.Subscribe(prefix+".ladder", apply("ladder", func(b []byte) error {
		var u LadderUpdate
		if err := json.Unmarshal(b, &u); err != nil {
			return err
		}
		if u.At.IsZero() {
			return errors.New("ladder update without a timestamp")
		}
		return eng.Graph().SetLadder(u.Edge, u.Ladder, u.At)
	})); err != nil {
		return fmt.Errorf("subscribe %s.ladder: %w", prefix, err)
	}
	if _, err := nc.Subscribe(prefix+".mid", apply("mid", func(b []byte) error {
		var u MidUpdate
		if err := json.Unmarshal(b, &u); err != nil {
			return err
		}
		if u.At.IsZero() {
			return errors.New("mid update without a timestamp")
		}
		return eng.SetMid(u.From, u.To, u.Rate, u.At)
	})); err != nil {
		return fmt.Errorf("subscribe %s.mid: %w", prefix, err)
	}
	return nc.Flush()
}

// notifier turns quarantine changes into outbox events for the treasury
// desk. Graph hooks run under the graph lock, so they only enqueue; the
// leader writes the events (standbys see the same feed and would only
// duplicate them).
type notifier struct {
	pool    *pgxpool.Pool
	leading *atomic.Bool
	m       *metrics
	log     *slog.Logger
	ch      chan quarantineEvent

	mu          sync.Mutex
	quarantined map[string]bool
}

type quarantineEvent struct {
	topic string
	data  map[string]any
}

func newNotifier(pool *pgxpool.Pool, leading *atomic.Bool, m *metrics, log *slog.Logger) *notifier {
	return &notifier{pool: pool, leading: leading, m: m, log: log, ch: make(chan quarantineEvent, 1024),
		quarantined: map[string]bool{}}
}

func (n *notifier) track(id string, on bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if on {
		n.quarantined[id] = true
	} else {
		delete(n.quarantined, id)
	}
	n.m.quarantined.Set(float64(len(n.quarantined)))
}

func (n *notifier) quarantine(q fx.Quarantine) {
	n.track(q.EdgeID, true)
	n.enqueue(quarantineEvent{topic: "fx.edge.quarantined", data: map[string]any{"edge_id": q.EdgeID,
		"cycle": q.Cycle, "product": q.Product}})
}

func (n *notifier) release(id string) {
	n.track(id, false)
	n.enqueue(quarantineEvent{topic: "fx.edge.released", data: map[string]any{"edge_id": id}})
}

func (n *notifier) enqueue(ev quarantineEvent) {
	select {
	case n.ch <- ev:
	default:
		n.log.Error("quarantine notification dropped: queue full", slog.String("topic", ev.topic))
	}
}

func (n *notifier) run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-n.ch:
			n.log.Warn("FX edge "+ev.topic[len("fx.edge."):], slog.Any("detail", ev.data))
			if !n.leading.Load() {
				continue
			}
			if err := pgx.BeginFunc(ctx, n.pool, func(tx pgx.Tx) error {
				_, err := outbox.Write(ctx, tx, outbox.Event{Source: fx.EventSource, Topic: ev.topic,
					Key: "edge:" + fmt.Sprint(ev.data["edge_id"]), Data: ev.data})
				return err
			}); err != nil && ctx.Err() == nil {
				n.log.Error("quarantine event not written", slog.String("topic", ev.topic), slog.Any("error", err))
			}
		}
	}
}

// workers are the leader's background loops: quote expiry and the
// recovery sweeper for bookings left pending.
type workers struct {
	eng *fx.Engine
	cfg Config
	m   *metrics
	log *slog.Logger
}

func (w *workers) resume(ctx context.Context, ids []uuid.UUID) {
	for _, id := range ids {
		if _, err := w.eng.Resume(ctx, id); err != nil {
			w.m.resumed.WithLabelValues("pending").Inc()
			w.log.WarnContext(ctx, "booking still pending", slog.String("quote", id.String()), slog.Any("error", err))
			continue
		}
		w.m.resumed.WithLabelValues("booked").Inc()
	}
}

func (w *workers) run(ctx context.Context) error {
	sweep := time.NewTicker(w.cfg.SweepInterval)
	defer sweep.Stop()
	resume := time.NewTicker(w.cfg.ResumeInterval)
	defer resume.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sweep.C:
			n, err := w.eng.Sweep(ctx)
			if err != nil && ctx.Err() == nil {
				w.log.ErrorContext(ctx, "quote expiry failed", slog.Any("error", err))
			}
			w.m.swept.Add(float64(n))
		case <-resume.C:
			ids, err := w.eng.Pending(ctx, w.cfg.ResumeAfter)
			if err != nil {
				if ctx.Err() == nil {
					w.log.ErrorContext(ctx, "listing pending bookings failed", slog.Any("error", err))
				}
				continue
			}
			w.resume(ctx, ids)
		}
	}
}
