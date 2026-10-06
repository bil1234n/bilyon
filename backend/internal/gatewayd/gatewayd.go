// Package gatewayd is the API gateway daemon (RFC 0001 §1.1): the public
// REST API the apps call, the internal gRPC API the realtime gateway calls
// for THROW and CATCH, the payment orchestrator's sweeper, signed tree head
// publication and session housekeeping, and the outbox relay that streams
// gateway events to NATS. Every replica serves; one replica, elected
// through a PostgreSQL advisory lock, runs the singleton jobs.
// cmd/gatewayd is a thin wrapper around Main.
package gatewayd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	intentsv1 "github.com/bil1234n/bilyon/backend/gen/bilyon/intents/v1"
	"github.com/bil1234n/bilyon/backend/internal/accounts"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/devicebind"
	"github.com/bil1234n/bilyon/backend/internal/dpop"
	"github.com/bil1234n/bilyon/backend/internal/fxapi"
	"github.com/bil1234n/bilyon/backend/internal/gatewayapi"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/intents"
	"github.com/bil1234n/bilyon/backend/internal/intentsapi"
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
	"github.com/bil1234n/bilyon/backend/internal/session"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// MigrationsTable records the gateway schema's applied migrations.
const MigrationsTable = "gateway_schema_migrations"

// Config is the daemon's configuration (environment variables in brackets).
type Config struct {
	DatabaseURL    string // BILYON_DATABASE_URL (required)
	DBMaxConns     int    // BILYON_DB_MAX_CONNS
	RedisURL       string // BILYON_REDIS_URL (required for run)
	NATSURL        string // BILYON_NATS_URL (required for run)
	StreamName     string // BILYON_NATS_STREAM
	SubjectPrefix  string // BILYON_NATS_SUBJECT_PREFIX
	StreamReplicas int    // BILYON_NATS_STREAM_REPLICAS
	HTTPAddr       string // BILYON_HTTP_ADDR: operational endpoints
	MigrateOnStart bool   // BILYON_MIGRATE_ON_START
	LogLevel       string // BILYON_LOG_LEVEL
	LogFormat      string // BILYON_LOG_FORMAT

	APIAddr     string   // BILYON_API_ADDR: the public API
	APIOrigin   string   // BILYON_API_ORIGIN (required for run): https origin the apps call; DPoP htu and token issuer
	APITLSCert  string   // BILYON_API_TLS_CERT, BILYON_API_TLS_KEY: serve TLS here instead of at the load balancer
	APITLSKey   string   //
	APIClients  []string // BILYON_API_CLIENTS (required for run): client ids, e.g. bilyon-ios,bilyon-android
	ProxyHops   int      // BILYON_API_TRUSTED_PROXY_HOPS
	RateLimits  gatewayapi.RateLimits
	RecentAuth  time.Duration // BILYON_API_RECENT_AUTH
	Audience    []string      // BILYON_SESSION_AUDIENCE (default: the API origin)
	SessionKey  string        // BILYON_SESSION_KEY_FILE (required for run): PEM P-256 private key
	SessionOld  []string      // BILYON_SESSION_PREVIOUS_KEY_FILES: PEM public keys still accepted
	DPoPKeys    string        // BILYON_DPOP_NONCE_KEYS_FILE (required for run)
	IntentKeys  string        // BILYON_INTENT_NONCE_KEYS_FILE (required for run)
	LimitsFile  string        // BILYON_INTENT_LIMITS_FILE (optional)
	DirKeyFile  string        // BILYON_DIRECTORY_KEY_FILE (required for run): K_dir, PEM P-256 private key
	DirKeyID    string        // BILYON_DIRECTORY_KEY_ID (required for run)
	RPID        string        // BILYON_WEBAUTHN_RP_ID (required for run)
	RPName      string        // BILYON_WEBAUTHN_RP_NAME
	RPOrigins   []string      // BILYON_WEBAUTHN_ORIGINS (required for run)
	Apple       AppleFiles
	Android     AndroidFiles
	FXAddr      string         // BILYON_FX_ADDR (optional: without it cross-currency payments are off)
	FXTLS       grpcx.TLSFiles // BILYON_FX_TLS_CERT, BILYON_FX_TLS_KEY, BILYON_FX_TLS_CA
	FXInsecure  bool           // BILYON_FX_INSECURE (development only)
	LedgerAddr  string         // BILYON_LEDGER_ADDR (required for run)
	LedgerTLS   grpcx.TLSFiles // BILYON_LEDGER_TLS_CERT, BILYON_LEDGER_TLS_KEY, BILYON_LEDGER_TLS_CA
	LedgerInsec bool           // BILYON_LEDGER_INSECURE (development only)

	GRPCAddr     string         // BILYON_GRPC_ADDR (required for run): internal API for the realtime gateway
	GRPCTLS      grpcx.TLSFiles // BILYON_GRPC_TLS_CERT, BILYON_GRPC_TLS_KEY, BILYON_GRPC_TLS_CA
	GRPCACL      grpcx.ACL      // BILYON_GRPC_ACL
	GRPCInsecure bool           // BILYON_GRPC_INSECURE (development only)

	SweepInterval   time.Duration // BILYON_INTENT_SWEEP_INTERVAL
	STHInterval     time.Duration // BILYON_STH_INTERVAL
	PurgeInterval   time.Duration // BILYON_PURGE_INTERVAL: sessions and abandoned sign-ups
	SessionRetain   time.Duration // BILYON_SESSION_RETENTION
	SignupAbandon   time.Duration // BILYON_SIGNUP_ABANDON_AFTER
	LockRetry       time.Duration // BILYON_LOCK_RETRY
	OutboxRetention time.Duration // BILYON_OUTBOX_RETENTION
}

// AppleFiles configures iOS binding; empty TeamID disables it.
type AppleFiles struct {
	TeamID           string // BILYON_APPLE_TEAM_ID
	BundleID         string // BILYON_APPLE_BUNDLE_ID
	RootsFile        string // BILYON_APPLE_ROOTS_FILE: Apple App Attestation Root CA (PEM)
	AllowDevelopment bool   // BILYON_APPLE_ALLOW_DEVELOPMENT (never in production)
}

// AndroidFiles configures Android binding; empty Package disables it.
type AndroidFiles struct {
	Package          string   // BILYON_ANDROID_PACKAGE
	CertDigests      [][]byte // BILYON_ANDROID_CERT_DIGESTS: hex SHA-256 of the signing certificates
	RootsFile        string   // BILYON_ANDROID_ROOTS_FILE: Google hardware attestation roots (PEM)
	DecryptionKey    string   // BILYON_PLAY_INTEGRITY_DECRYPTION_KEY_FILE: base64 AES-256 key
	VerificationKey  string   // BILYON_PLAY_INTEGRITY_VERIFICATION_KEY_FILE: PEM P-256 public key
	MaxPatchAgeMonth int      // BILYON_ANDROID_MAX_PATCH_AGE_MONTHS
}

// LoadConfig reads and validates the configuration.
func LoadConfig(env *config.Env, run bool) (Config, error) {
	c := Config{
		DatabaseURL:     env.Required("BILYON_DATABASE_URL"),
		DBMaxConns:      env.Int("BILYON_DB_MAX_CONNS", 30, 4, 1000),
		StreamName:      env.String("BILYON_NATS_STREAM", "BILYON_GATEWAY"),
		SubjectPrefix:   env.String("BILYON_NATS_SUBJECT_PREFIX", "bilyon"),
		StreamReplicas:  env.Int("BILYON_NATS_STREAM_REPLICAS", 1, 1, 5),
		HTTPAddr:        env.String("BILYON_HTTP_ADDR", ":9090"),
		MigrateOnStart:  env.Bool("BILYON_MIGRATE_ON_START", false),
		LogLevel:        env.OneOf("BILYON_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:       env.OneOf("BILYON_LOG_FORMAT", "json", "json", "text"),
		APIAddr:         env.String("BILYON_API_ADDR", ":8080"),
		ProxyHops:       env.Int("BILYON_API_TRUSTED_PROXY_HOPS", 0, 0, 5),
		RecentAuth:      env.Duration("BILYON_API_RECENT_AUTH", 5*time.Minute),
		RPName:          env.String("BILYON_WEBAUTHN_RP_NAME", "Bilyon"),
		SweepInterval:   env.Duration("BILYON_INTENT_SWEEP_INTERVAL", time.Second),
		STHInterval:     env.Duration("BILYON_STH_INTERVAL", 10*time.Minute),
		PurgeInterval:   env.Duration("BILYON_PURGE_INTERVAL", time.Hour),
		SessionRetain:   env.Duration("BILYON_SESSION_RETENTION", 30*24*time.Hour),
		SignupAbandon:   env.Duration("BILYON_SIGNUP_ABANDON_AFTER", 24*time.Hour),
		LockRetry:       env.Duration("BILYON_LOCK_RETRY", 2*time.Second),
		OutboxRetention: env.Duration("BILYON_OUTBOX_RETENTION", 72*time.Hour),
		RateLimits: gatewayapi.RateLimits{
			Auth:         gatewayapi.Limit{N: env.Int("BILYON_RATE_AUTH_PER_MINUTE", 30, 0, 1_000_000), Per: time.Minute},
			LookupMinute: gatewayapi.Limit{N: env.Int("BILYON_RATE_LOOKUPS_PER_MINUTE", 60, 0, 1_000_000), Per: time.Minute},
			LookupDay:    gatewayapi.Limit{N: env.Int("BILYON_RATE_LOOKUPS_PER_DAY", 1000, 0, 100_000_000), Per: 24 * time.Hour},
			Calls:        gatewayapi.Limit{N: env.Int("BILYON_RATE_CALLS_PER_MINUTE", 600, 0, 1_000_000), Per: time.Minute},
		},
	}
	errs := []error{}
	if !run {
		return c, errors.Join(append([]error{env.Err()}, errs...)...)
	}
	c.RedisURL = env.Required("BILYON_REDIS_URL")
	c.NATSURL = env.Required("BILYON_NATS_URL")
	c.APIOrigin = env.Required("BILYON_API_ORIGIN")
	if u, err := url.Parse(c.APIOrigin); c.APIOrigin != "" && (err != nil || u.Scheme != "https" || u.Host == "" ||
		u.Path != "" || u.RawQuery != "") {
		errs = append(errs, fmt.Errorf("BILYON_API_ORIGIN: %q must be https://host[:port]", c.APIOrigin))
	}
	c.APITLSCert, c.APITLSKey = env.String("BILYON_API_TLS_CERT", ""), env.String("BILYON_API_TLS_KEY", "")
	if (c.APITLSCert == "") != (c.APITLSKey == "") {
		errs = append(errs, errors.New("BILYON_API_TLS_CERT and BILYON_API_TLS_KEY go together"))
	}
	c.APIClients = splitList(env.Required("BILYON_API_CLIENTS"))
	c.Audience = splitList(env.String("BILYON_SESSION_AUDIENCE", c.APIOrigin))
	c.SessionKey = env.Required("BILYON_SESSION_KEY_FILE")
	c.SessionOld = splitList(env.String("BILYON_SESSION_PREVIOUS_KEY_FILES", ""))
	c.DPoPKeys = env.Required("BILYON_DPOP_NONCE_KEYS_FILE")
	c.IntentKeys = env.Required("BILYON_INTENT_NONCE_KEYS_FILE")
	c.LimitsFile = env.String("BILYON_INTENT_LIMITS_FILE", "")
	c.DirKeyFile = env.Required("BILYON_DIRECTORY_KEY_FILE")
	c.DirKeyID = env.Required("BILYON_DIRECTORY_KEY_ID")
	c.RPID = env.Required("BILYON_WEBAUTHN_RP_ID")
	c.RPOrigins = splitList(env.Required("BILYON_WEBAUTHN_ORIGINS"))
	c.Apple = AppleFiles{TeamID: env.String("BILYON_APPLE_TEAM_ID", ""), BundleID: env.String("BILYON_APPLE_BUNDLE_ID", ""),
		RootsFile: env.String("BILYON_APPLE_ROOTS_FILE", ""), AllowDevelopment: env.Bool("BILYON_APPLE_ALLOW_DEVELOPMENT", false)}
	c.Android = AndroidFiles{Package: env.String("BILYON_ANDROID_PACKAGE", ""), RootsFile: env.String("BILYON_ANDROID_ROOTS_FILE", ""),
		DecryptionKey:    env.String("BILYON_PLAY_INTEGRITY_DECRYPTION_KEY_FILE", ""),
		VerificationKey:  env.String("BILYON_PLAY_INTEGRITY_VERIFICATION_KEY_FILE", ""),
		MaxPatchAgeMonth: env.Int("BILYON_ANDROID_MAX_PATCH_AGE_MONTHS", 12, 1, 60)}
	if c.Apple.TeamID == "" && c.Android.Package == "" {
		errs = append(errs, errors.New("configure iOS (BILYON_APPLE_TEAM_ID ...) or Android (BILYON_ANDROID_PACKAGE ...) device binding"))
	}
	if c.Apple.TeamID != "" && (c.Apple.BundleID == "" || c.Apple.RootsFile == "") {
		errs = append(errs, errors.New("iOS binding needs BILYON_APPLE_BUNDLE_ID and BILYON_APPLE_ROOTS_FILE"))
	}
	if c.Android.Package != "" {
		if c.Android.RootsFile == "" || c.Android.DecryptionKey == "" || c.Android.VerificationKey == "" {
			errs = append(errs, errors.New("Android binding needs BILYON_ANDROID_ROOTS_FILE and the Play Integrity key files"))
		}
		d, err := ParseDigests(env.String("BILYON_ANDROID_CERT_DIGESTS", ""))
		if err != nil {
			errs = append(errs, fmt.Errorf("BILYON_ANDROID_CERT_DIGESTS: %w", err))
		}
		c.Android.CertDigests = d
	}
	c.FXAddr = env.String("BILYON_FX_ADDR", "")
	if c.FXAddr != "" {
		c.FXInsecure = env.Bool("BILYON_FX_INSECURE", false)
		if !c.FXInsecure {
			c.FXTLS = grpcx.TLSFiles{CertFile: env.Required("BILYON_FX_TLS_CERT"), KeyFile: env.Required("BILYON_FX_TLS_KEY"),
				CAFile: env.Required("BILYON_FX_TLS_CA")}
		}
	}
	c.LedgerAddr = env.Required("BILYON_LEDGER_ADDR")
	c.LedgerInsec = env.Bool("BILYON_LEDGER_INSECURE", false)
	if !c.LedgerInsec {
		c.LedgerTLS = grpcx.TLSFiles{CertFile: env.Required("BILYON_LEDGER_TLS_CERT"),
			KeyFile: env.Required("BILYON_LEDGER_TLS_KEY"), CAFile: env.Required("BILYON_LEDGER_TLS_CA")}
	}
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
	return c, errors.Join(append([]error{env.Err()}, errs...)...)
}

// Hooks lets tests observe the running daemon.
type Hooks struct {
	OnListening     func(addr string) // operational HTTP server
	OnAPIListening  func(addr string) // public API
	OnGRPCListening func(addr string) // internal gRPC API
	OnLeading       func(leading bool)
}

const usage = `usage: gatewayd <command>

commands:
  run      run the API gateway (default)
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
	log, err := logging.New(stderr, cfg.LogLevel, cfg.LogFormat, "gatewayd")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	pool, err := pgpool.New(ctx, cfg.DatabaseURL, pgpool.Options{MaxConns: int32(cfg.DBMaxConns), AppName: "gatewayd"})
	if err != nil {
		log.ErrorContext(ctx, "database unavailable", slog.Any("error", err))
		return 1
	}
	defer pool.Close()
	ms, err := migrate.Load(migrations.Gateway, migrations.GatewayDir)
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
		log.ErrorContext(ctx, "gatewayd stopped with an error", slog.Any("error", err))
		return 1
	}
	return 0
}

// services are the assembled domain services.
type services struct {
	users     *webauthn.PGStore
	sessions  *session.Service
	keys      *session.KeySet
	auth      *session.Authenticator
	devices   *devicebind.Service
	directory *identity.Service
	dirKey    *cose.KeySigner
	accounts  *accounts.Resolver
	intents   *intents.Service
	api       *gatewayapi.API
}

func dial(addr string, files grpcx.TLSFiles, plaintext bool, serviceConfig string) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if plaintext {
		creds = insecure.NewCredentials()
	} else {
		c, err := grpcx.ClientTLS(files)
		if err != nil {
			return nil, err
		}
		creds = c
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds), grpc.WithDefaultServiceConfig(serviceConfig))
}

// build loads the secrets and assembles every service.
func build(cfg Config, pool *pgxpool.Pool, rdb redis.UniversalClient, ledger *ledgerapi.Client, fxc *fxapi.Client,
	log *slog.Logger, reg prometheus.Registerer) (*services, error) {
	s := &services{users: webauthn.NewPGStore(pool)}
	var err error
	if s.keys, err = session.LoadKeySet(cfg.SessionKey, cfg.SessionOld...); err != nil {
		return nil, err
	}
	if s.sessions, err = session.New(session.Config{Issuer: cfg.APIOrigin, Audience: cfg.Audience}, s.keys, pool, rdb); err != nil {
		return nil, err
	}
	dpopKeys, err := LoadSymmetricKeys(cfg.DPoPKeys, 32)
	if err != nil {
		return nil, err
	}
	proofs, err := dpop.NewVerifier(dpop.Config{Origins: []string{cfg.APIOrigin}, NonceKeys: dpopKeys}, rdb)
	if err != nil {
		return nil, err
	}
	s.auth = session.NewAuthenticator(s.sessions, proofs)
	rp, err := webauthn.New(webauthn.Config{RPID: cfg.RPID, RPName: cfg.RPName, Origins: cfg.RPOrigins},
		webauthn.NewRedisChallenges(rdb), s.users)
	if err != nil {
		return nil, err
	}
	dcfg := devicebind.Config{}
	if cfg.Apple.TeamID != "" {
		roots, err := LoadCertPool(cfg.Apple.RootsFile)
		if err != nil {
			return nil, err
		}
		dcfg.Apple = devicebind.AppleConfig{TeamID: cfg.Apple.TeamID, BundleID: cfg.Apple.BundleID, Roots: roots,
			AllowDevelopment: cfg.Apple.AllowDevelopment}
	}
	if cfg.Android.Package != "" {
		roots, err := LoadCertPool(cfg.Android.RootsFile)
		if err != nil {
			return nil, err
		}
		dk, err := LoadAESKey(cfg.Android.DecryptionKey, 32)
		if err != nil {
			return nil, err
		}
		vk, err := LoadPublicKey(cfg.Android.VerificationKey)
		if err != nil {
			return nil, err
		}
		dcfg.Android = devicebind.AndroidConfig{PackageName: cfg.Android.Package, SigningCertDigests: cfg.Android.CertDigests,
			Roots: roots, MaxPatchAgeMonths: cfg.Android.MaxPatchAgeMonth}
		dcfg.Integrity = &devicebind.IntegrityConfig{DecryptionKey: dk, VerificationKey: vk, PackageName: cfg.Android.Package}
	}
	if s.devices, err = devicebind.New(dcfg, rdb, pool); err != nil {
		return nil, err
	}
	dirPriv, err := LoadPrivateKey(cfg.DirKeyFile)
	if err != nil {
		return nil, err
	}
	if s.dirKey, err = cose.NewKeySigner(dirPriv); err != nil {
		return nil, err
	}
	if s.directory, err = identity.New(identity.Config{Signer: s.dirKey, KeyID: []byte(cfg.DirKeyID)}, pool); err != nil {
		return nil, err
	}
	s.accounts = accounts.New(pool, ledger)
	intentKeys, err := LoadSymmetricKeys(cfg.IntentKeys, 32)
	if err != nil {
		return nil, err
	}
	icfg := intents.Config{NonceKeys: intentKeys, Logger: log, Registerer: reg}
	if cfg.LimitsFile != "" {
		if icfg.Limits, err = LoadLimits(cfg.LimitsFile); err != nil {
			return nil, err
		}
	}
	var fxs intents.FX
	var quotes gatewayapi.FXQuotes
	if fxc != nil {
		fxs, quotes = fxc, fxc
	}
	if s.intents, err = intents.New(icfg, pool, s.devices, s.directory, fxs, ledger, s.accounts); err != nil {
		return nil, err
	}
	s.api, err = gatewayapi.New(gatewayapi.Config{Clients: cfg.APIClients, RecentAuth: cfg.RecentAuth,
		RateLimits: cfg.RateLimits, TrustedProxyHops: cfg.ProxyHops},
		gatewayapi.Deps{Users: s.users, WebAuthn: rp, Sessions: s.sessions, SessionKeys: s.keys, Auth: s.auth,
			Devices: s.devices, Directory: s.directory,
			DirectoryKeys: []gatewayapi.DirectoryKey{{KID: []byte(cfg.DirKeyID), Public: s.dirKey.Public()}},
			Accounts:      s.accounts, Intents: s.intents, FX: quotes, Limiter: gatewayapi.NewLimiter(rdb, nil),
			Logger: log, Registerer: reg})
	return s, err
}

// Run starts the daemon and blocks until ctx is cancelled or a component fails.
func Run(ctx context.Context, cfg Config, pool *pgxpool.Pool, ms []migrate.Migration, log *slog.Logger, hooks Hooks) error {
	if cfg.MigrateOnStart {
		if _, err := migrate.Apply(ctx, pool, ms, migrate.Options{Table: MigrationsTable, Logger: log}); err != nil {
			return fmt.Errorf("migrate on start: %w", err)
		}
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := newMetrics(reg)

	ropts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("BILYON_REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(ropts)
	defer rdb.Close()
	ledgerConn, err := dial(cfg.LedgerAddr, cfg.LedgerTLS, cfg.LedgerInsec, grpcx.RetryServiceConfig)
	if err != nil {
		return err
	}
	defer ledgerConn.Close()
	var fxc *fxapi.Client
	if cfg.FXAddr != "" {
		fxConn, err := dial(cfg.FXAddr, cfg.FXTLS, cfg.FXInsecure, fxapi.RetryServiceConfig)
		if err != nil {
			return err
		}
		defer fxConn.Close()
		fxc = fxapi.NewClient(fxConn)
	} else {
		log.Warn("BILYON_FX_ADDR is not set: cross-currency payments are disabled")
	}
	svc, err := build(cfg, pool, rdb, ledgerapi.NewClient(ledgerConn), fxc, log, reg)
	if err != nil {
		return err
	}
	if err := svc.directory.EnsureReserved(ctx); err != nil {
		return fmt.Errorf("reserve handles: %w", err)
	}

	nc, err := nats.Connect(cfg.NATSURL, nats.Name("gatewayd"), nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond), nats.Timeout(5*time.Second))
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}
	defer nc.Close()
	pub, err := natspub.New(ctx, nc, natspub.StreamConfig{Name: cfg.StreamName, SubjectPrefix: cfg.SubjectPrefix,
		Subjects: []string{cfg.SubjectPrefix + ".gateway.>"}, Replicas: cfg.StreamReplicas, EnsureOnConnect: true})
	if err != nil {
		return err
	}
	relay := outbox.NewRelay(pool, pub, outbox.RelayConfig{Retention: cfg.OutboxRetention, Logger: log, Registerer: reg})

	serveAPI, err := apiServer(cfg, svc.api, log, hooks)
	if err != nil {
		return err
	}
	hs := health.NewServer()
	serveGRPC, err := grpcServer(cfg, svc.intents, hs, log, reg, hooks)
	if err != nil {
		return err
	}
	ops := httpserver.New(cfg.HTTPAddr, reg, log)
	ops.AddCheck("postgres", func(ctx context.Context) error { return pool.Ping(ctx) })
	ops.AddCheck("redis", func(ctx context.Context) error { return rdb.Ping(ctx).Err() })
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
	log.InfoContext(ctx, "gatewayd operational endpoints listening", slog.String("addr", addr))
	if hooks.OnListening != nil {
		hooks.OnListening(addr)
	}
	w := &workers{cfg: cfg, pool: pool, svc: svc, m: m, log: log}
	return lifecycle.Run(ctx, log,
		lifecycle.Component{Name: "ops-http", Run: ops.Run},
		lifecycle.Component{Name: "api", Run: serveAPI},
		lifecycle.Component{Name: "grpc", Run: serveGRPC},
		lifecycle.Component{Name: "outbox-relay", Run: relay.Run},
		lifecycle.Component{Name: "intent-sweeper", Run: w.sweep},
		lifecycle.Component{Name: "leader", Run: func(ctx context.Context) error {
			return leader.Run(ctx, pool, leader.Config{Name: "gatewayd", Retry: cfg.LockRetry, Logger: log,
				OnState: func(l bool) {
					if l {
						m.leading.Set(1)
					} else {
						m.leading.Set(0)
					}
					if hooks.OnLeading != nil {
						hooks.OnLeading(l)
					}
				}}, w.lead)
		}},
	)
}

// apiServer binds the public API.
func apiServer(cfg Config, h http.Handler, log *slog.Logger, hooks Hooks) (func(context.Context) error, error) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	if cfg.APITLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.APITLSCert, cfg.APITLSKey)
		if err != nil {
			return nil, fmt.Errorf("API TLS: %w", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	}
	l, err := net.Listen("tcp", cfg.APIAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.APIAddr, err)
	}
	log.Info("public API listening", slog.String("addr", l.Addr().String()), slog.Bool("tls", srv.TLSConfig != nil),
		slog.String("origin", cfg.APIOrigin))
	if hooks.OnAPIListening != nil {
		hooks.OnAPIListening(l.Addr().String())
	}
	return func(ctx context.Context) error {
		errCh := make(chan error, 1)
		go func() {
			if srv.TLSConfig != nil {
				errCh <- srv.ServeTLS(l, "", "")
			} else {
				errCh <- srv.Serve(l)
			}
		}()
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdown); err != nil {
				return err
			}
			if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		}
	}, nil
}

// grpcServer binds the internal intent API for the realtime gateway.
func grpcServer(cfg Config, svc *intents.Service, hs *health.Server, log *slog.Logger, reg prometheus.Registerer,
	hooks Hooks) (func(context.Context) error, error) {
	var creds credentials.TransportCredentials
	if cfg.GRPCInsecure {
		log.Warn("internal gRPC API served WITHOUT TLS or authorisation (BILYON_GRPC_INSECURE); development only")
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
	intentsv1.RegisterIntentServiceServer(s, intentsapi.NewServer(svc, log))
	healthpb.RegisterHealthServer(s, hs)
	hs.SetServingStatus(intentsv1.IntentService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	l, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.GRPCAddr, err)
	}
	log.Info("internal gRPC API listening", slog.String("addr", l.Addr().String()), slog.Bool("mtls", !cfg.GRPCInsecure))
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
