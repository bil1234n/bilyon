package gatewayd

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/identity/tlog"
)

type metrics struct {
	leading  prometheus.Gauge
	sweeps   *prometheus.CounterVec
	sths     prometheus.Counter
	purged   *prometheus.CounterVec
	lastSTH  prometheus.Gauge
	failures *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		leading: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_gateway_leader",
			Help: "1 while this instance runs the gateway's singleton jobs."}),
		sweeps: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_gateway_intent_sweeps_total",
			Help: "Intent sweeps by outcome."}, []string{"outcome"}),
		sths: prometheus.NewCounter(prometheus.CounterOpts{Name: "bilyon_gateway_tree_heads_published_total",
			Help: "Signed tree heads of the directory's transparency log published."}),
		purged: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_gateway_purged_total",
			Help: "Expired sessions and abandoned sign-ups deleted."}, []string{"kind"}),
		lastSTH: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bilyon_gateway_tree_head_timestamp_seconds",
			Help: "When the latest signed tree head was published (alert when older than twice the interval)."}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_gateway_job_failures_total",
			Help: "Background job failures by job."}, []string{"job"}),
	}
	reg.MustRegister(m.leading, m.sweeps, m.sths, m.purged, m.lastSTH, m.failures)
	return m
}

type workers struct {
	cfg  Config
	pool *pgxpool.Pool
	svc  *services
	m    *metrics
	log  *slog.Logger
}

// sweep runs the intent sweeper on every replica: timeouts and pending
// ledger steps are claimed row by row (SKIP LOCKED), so replicas share the
// work.
func (w *workers) sweep(ctx context.Context) error {
	t := time.NewTicker(w.cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		res, err := w.svc.intents.Sweep(ctx)
		switch {
		case err != nil && ctx.Err() != nil:
			return nil
		case err != nil:
			w.m.sweeps.WithLabelValues("error").Inc()
			w.log.WarnContext(ctx, "intent sweep failed", slog.Any("error", err))
		case res.Failed > 0:
			w.m.sweeps.WithLabelValues("partial").Inc()
		default:
			w.m.sweeps.WithLabelValues("ok").Inc()
		}
	}
}

// lead runs the singleton jobs while this replica holds the election:
// signed tree heads every STHInterval (RFC 0001 §4.1.3) and housekeeping.
func (w *workers) lead(ctx context.Context) error {
	w.log.InfoContext(ctx, "gatewayd leading: running singleton jobs")
	if err := w.publishIfDue(ctx); err != nil && ctx.Err() == nil {
		w.m.failures.WithLabelValues("sth").Inc()
		w.log.ErrorContext(ctx, "publish tree head", slog.Any("error", err))
	}
	sth := time.NewTicker(w.cfg.STHInterval)
	defer sth.Stop()
	purge := time.NewTicker(w.cfg.PurgeInterval)
	defer purge.Stop()
	w.purge(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sth.C:
			if err := w.publish(ctx); err != nil && ctx.Err() == nil {
				w.m.failures.WithLabelValues("sth").Inc()
				w.log.ErrorContext(ctx, "publish tree head", slog.Any("error", err))
			}
		case <-purge.C:
			w.purge(ctx)
		}
	}
}

// publishIfDue signs a tree head unless a fresh one exists (a restart or
// failover must not wait a full interval, nor sign twice in a row).
func (w *workers) publishIfDue(ctx context.Context) error {
	latest, err := w.svc.directory.Log().Latest(ctx)
	if err == nil && time.Since(latest.Time) < w.cfg.STHInterval {
		w.m.lastSTH.Set(float64(latest.Time.Unix()))
		return nil
	}
	if err != nil && !errors.Is(err, tlog.ErrNoTreeHead) {
		return err
	}
	return w.publish(ctx)
}

func (w *workers) publish(ctx context.Context) error {
	sth, err := w.svc.directory.PublishTreeHead(ctx)
	if err != nil {
		return err
	}
	w.m.sths.Inc()
	w.m.lastSTH.Set(float64(sth.Time.Unix()))
	w.log.InfoContext(ctx, "published signed tree head", slog.Uint64("size", sth.Size))
	return nil
}

func (w *workers) purge(ctx context.Context) {
	if n, err := w.svc.sessions.Purge(ctx, w.cfg.SessionRetain); err != nil {
		if ctx.Err() == nil {
			w.m.failures.WithLabelValues("session_purge").Inc()
			w.log.ErrorContext(ctx, "purge sessions", slog.Any("error", err))
		}
	} else {
		w.m.purged.WithLabelValues("sessions").Add(float64(n))
	}
	if n, err := purgeAbandonedSignups(ctx, w.pool, time.Now().Add(-w.cfg.SignupAbandon)); err != nil {
		if ctx.Err() == nil {
			w.m.failures.WithLabelValues("signup_purge").Inc()
			w.log.ErrorContext(ctx, "purge abandoned sign-ups", slog.Any("error", err))
		}
	} else {
		w.m.purged.WithLabelValues("signups").Add(float64(n))
	}
}

// purgeAbandonedSignups deletes accounts created by a registration that
// never completed: no passkey, and nothing else refers to them.
func purgeAbandonedSignups(ctx context.Context, pool *pgxpool.Pool, before time.Time) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM users u WHERE u.created_at < $1
		AND NOT EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.user_id = u.user_id)
		AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = u.user_id)
		AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.user_id)
		AND NOT EXISTS (SELECT 1 FROM subjects s WHERE s.user_id = u.user_id)
		AND NOT EXISTS (SELECT 1 FROM user_accounts a WHERE a.user_id = u.user_id)
		AND NOT EXISTS (SELECT 1 FROM payment_intents i WHERE i.payer_id = u.user_id OR i.payee_id = u.user_id)`,
		before)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
