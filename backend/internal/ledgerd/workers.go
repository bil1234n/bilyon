package ledgerd

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
)

// holdExpirer resolves expired holds so reserved funds return to customers
// promptly. It drains in batches until a batch comes back short.
type holdExpirer struct {
	eng      *pgledger.Engine
	interval time.Duration
	batch    int
	log      *slog.Logger
	expired  prometheus.Counter
}

func (h *holdExpirer) Run(ctx context.Context) error {
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		for {
			holds, err := h.eng.ExpireHolds(ctx, h.batch)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				h.log.ErrorContext(ctx, "hold expiry failed", slog.Any("error", err))
				break
			}
			h.expired.Add(float64(len(holds)))
			if len(holds) > 0 {
				h.log.InfoContext(ctx, "holds expired", slog.Int("count", len(holds)))
			}
			if len(holds) < h.batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// auditor re-verifies every ledger invariant on a schedule and exports the
// number of discrepancies, which alerting pages on when non-zero.
type auditor struct {
	eng           *pgledger.Engine
	interval      time.Duration
	log           *slog.Logger
	discrepancies prometheus.Gauge
	lastSuccess   prometheus.Gauge
}

func (a *auditor) Run(ctx context.Context) error {
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		report, err := a.eng.Audit(ctx)
		switch {
		case err != nil && ctx.Err() != nil:
			return nil
		case err != nil:
			a.log.ErrorContext(ctx, "ledger audit failed to run", slog.Any("error", err))
		default:
			a.discrepancies.Set(float64(len(report.Discrepancies)))
			a.lastSuccess.SetToCurrentTime()
			for _, d := range report.Discrepancies {
				a.log.ErrorContext(ctx, "LEDGER INVARIANT VIOLATED", slog.String("discrepancy", d.String()))
			}
			a.log.InfoContext(ctx, "ledger audit finished", slog.Int64("entries", report.Entries),
				slog.Int("discrepancies", len(report.Discrepancies)), slog.Duration("took", report.Duration))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// idempotencyPruner deletes idempotency records past their retention. The
// unique keys on journal_entries, holds and accounts still reject reuse of a
// pruned key, so pruning never re-enables a duplicate.
type idempotencyPruner struct {
	pool      *pgxpool.Pool
	retention time.Duration
	interval  time.Duration
	log       *slog.Logger
	pruned    prometheus.Counter
}

func (p *idempotencyPruner) Run(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		total, err := p.pruneOnce(ctx)
		if err != nil && ctx.Err() == nil {
			p.log.ErrorContext(ctx, "idempotency pruning failed", slog.Any("error", err))
		}
		if total > 0 {
			p.log.InfoContext(ctx, "idempotency keys pruned", slog.Int64("count", total))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (p *idempotencyPruner) pruneOnce(ctx context.Context) (int64, error) {
	var total int64
	for {
		tag, err := p.pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE idempotency_key IN (
			SELECT idempotency_key FROM idempotency_keys
			 WHERE created_at < clock_timestamp() - make_interval(secs => $1)
			 LIMIT 5000 FOR UPDATE SKIP LOCKED)`, p.retention.Seconds())
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		p.pruned.Add(float64(tag.RowsAffected()))
		if tag.RowsAffected() < 5000 {
			return total, nil
		}
	}
}
