package pgledger

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Discrepancy is one invariant violation found by Audit.
type Discrepancy struct {
	Check     string     `json:"check"`
	AccountID *uuid.UUID `json:"account_id,omitempty"`
	Stripe    *int       `json:"stripe,omitempty"`
	EntryID   *uuid.UUID `json:"entry_id,omitempty"`
	HoldID    *uuid.UUID `json:"hold_id,omitempty"`
	Currency  string     `json:"currency,omitempty"`
	Expected  int64      `json:"expected"`
	Actual    int64      `json:"actual"`
}

func (d Discrepancy) String() string {
	return fmt.Sprintf("%s account=%v stripe=%v entry=%v hold=%v currency=%s expected=%d actual=%d",
		d.Check, deref(d.AccountID), derefInt(d.Stripe), deref(d.EntryID), deref(d.HoldID), d.Currency, d.Expected, d.Actual)
}

func deref(id *uuid.UUID) string {
	if id == nil {
		return "-"
	}
	return id.String()
}

func derefInt(i *int) string {
	if i == nil {
		return "-"
	}
	return fmt.Sprint(*i)
}

// AuditReport is the outcome of a full audit.
type AuditReport struct {
	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"duration"`
	Entries       int64         `json:"entries"`
	Accounts      int64         `json:"accounts"`
	Discrepancies []Discrepancy `json:"discrepancies"`
}

// OK reports whether every invariant held.
func (r AuditReport) OK() bool { return len(r.Discrepancies) == 0 }

// Audit recomputes every materialised value from the append-only journal and
// re-checks every invariant, independently of the triggers that maintain
// them. It runs in a REPEATABLE READ snapshot so concurrent writes cannot
// produce false positives.
func (e *Engine) Audit(ctx context.Context) (AuditReport, error) {
	report := AuditReport{StartedAt: time.Now().UTC()}
	err := pgx.BeginTxFunc(ctx, e.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM journal_entries), (SELECT count(*) FROM accounts)`).
			Scan(&report.Entries, &report.Accounts); err != nil {
			return err
		}
		checks := []struct {
			name string
			sql  string
			scan func(pgx.Rows) (Discrepancy, error)
		}{
			{"balance_matches_postings", `
				SELECT b.account_id, b.stripe, coalesce(p.total, 0)::bigint, b.balance_minor
				  FROM account_balances b
				  LEFT JOIN (SELECT account_id, stripe, sum(amount_minor) AS total
				               FROM postings GROUP BY account_id, stripe) p
				    ON p.account_id = b.account_id AND p.stripe = b.stripe
				 WHERE b.balance_minor <> coalesce(p.total, 0)`, scanAccountStripe},
			{"pending_matches_holds", `
				SELECT b.account_id, b.stripe, coalesce(h.total, 0)::bigint, b.pending_minor
				  FROM account_balances b
				  LEFT JOIN (SELECT account_id, sum(amount_minor) AS total
				               FROM holds WHERE state = 'pending' GROUP BY account_id) h
				    ON h.account_id = b.account_id AND b.stripe = 0
				 WHERE b.pending_minor <> coalesce(h.total, 0)`, scanAccountStripe},
			{"floor_respected", `
				SELECT account_id, stripe, floor_minor, balance_minor - pending_minor
				  FROM account_balances
				 WHERE floor_minor IS NOT NULL AND balance_minor - pending_minor < floor_minor`, scanAccountStripe},
			{"entry_balances_per_currency", `
				SELECT entry_id, currency, 0::bigint, sum(amount_minor)::bigint
				  FROM postings GROUP BY entry_id, currency HAVING sum(amount_minor) <> 0`, scanEntryCurrency},
			{"entry_has_two_postings", `
				SELECT e.entry_id, '', 2::bigint, count(p.seq)::bigint
				  FROM journal_entries e LEFT JOIN postings p ON p.entry_id = e.entry_id
				 GROUP BY e.entry_id HAVING count(p.seq) < 2`, scanEntryCurrency},
			{"currency_sums_to_zero", `
				SELECT a.currency, 0::bigint, sum(b.balance_minor)::bigint
				  FROM account_balances b JOIN accounts a ON a.account_id = b.account_id
				 GROUP BY a.currency HAVING sum(b.balance_minor) <> 0`, scanCurrency},
			{"posted_hold_matches_entry", `
				SELECT h.hold_id, -h.posted_minor, coalesce(sum(p.amount_minor), 0)::bigint
				  FROM holds h
				  LEFT JOIN postings p ON p.entry_id = h.entry_id AND p.account_id = h.account_id
				 WHERE h.state = 'posted'
				 GROUP BY h.hold_id, h.posted_minor
				HAVING coalesce(sum(p.amount_minor), 0) <> -h.posted_minor`, scanHoldCheck},
			{"frozen_flag_in_sync", `
				SELECT b.account_id, b.stripe, a.frozen::int::bigint, b.frozen::int::bigint
				  FROM account_balances b JOIN accounts a ON a.account_id = b.account_id
				 WHERE a.frozen <> b.frozen`, scanAccountStripe},
		}
		for _, c := range checks {
			rows, err := tx.Query(ctx, c.sql)
			if err != nil {
				return fmt.Errorf("audit %s: %w", c.name, err)
			}
			for rows.Next() {
				d, err := c.scan(rows)
				if err != nil {
					rows.Close()
					return fmt.Errorf("audit %s: %w", c.name, err)
				}
				d.Check = c.name
				report.Discrepancies = append(report.Discrepancies, d)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("audit %s: %w", c.name, err)
			}
		}
		return nil
	})
	report.Duration = time.Since(report.StartedAt)
	return report, err
}

func scanAccountStripe(rows pgx.Rows) (Discrepancy, error) {
	var d Discrepancy
	var id uuid.UUID
	var stripe int16
	var expected *int64
	if err := rows.Scan(&id, &stripe, &expected, &d.Actual); err != nil {
		return d, err
	}
	s := int(stripe)
	d.AccountID, d.Stripe = &id, &s
	if expected != nil {
		d.Expected = *expected
	}
	return d, nil
}

func scanEntryCurrency(rows pgx.Rows) (Discrepancy, error) {
	var d Discrepancy
	var id uuid.UUID
	if err := rows.Scan(&id, &d.Currency, &d.Expected, &d.Actual); err != nil {
		return d, err
	}
	d.EntryID = &id
	return d, nil
}

func scanCurrency(rows pgx.Rows) (Discrepancy, error) {
	var d Discrepancy
	err := rows.Scan(&d.Currency, &d.Expected, &d.Actual)
	return d, err
}

func scanHoldCheck(rows pgx.Rows) (Discrepancy, error) {
	var d Discrepancy
	var id uuid.UUID
	if err := rows.Scan(&id, &d.Expected, &d.Actual); err != nil {
		return d, err
	}
	d.HoldID = &id
	return d, nil
}
