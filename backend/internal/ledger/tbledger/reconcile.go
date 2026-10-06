package tbledger

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/ledger/pgledger"
)

// Mismatch is an account whose TigerBeetle balance differs from PostgreSQL.
type Mismatch struct {
	AccountID      uuid.UUID `json:"account_id"`
	Currency       string    `json:"currency"`
	MissingInTB    bool      `json:"missing_in_tigerbeetle"`
	PostgresPosted int64     `json:"postgres_posted"`
	PostgresPend   int64     `json:"postgres_pending"`
	TBPosted       int64     `json:"tigerbeetle_posted"`
	TBPending      int64     `json:"tigerbeetle_pending"`
}

func (m Mismatch) String() string {
	if m.MissingInTB {
		return fmt.Sprintf("%s (%s): missing in TigerBeetle", m.AccountID, m.Currency)
	}
	return fmt.Sprintf("%s (%s): posted %d vs %d, pending %d vs %d", m.AccountID, m.Currency,
		m.PostgresPosted, m.TBPosted, m.PostgresPend, m.TBPending)
}

// reconcileIn compares every account visible in q's snapshot with
// TigerBeetle, page by page. Callers make the comparison exact by holding
// TigerBeetle at the state that snapshot implies (see Tailer.Reconcile).
func reconcileIn(ctx context.Context, q pgledger.Querier, d *Driver, page int) ([]Mismatch, error) {
	var out []Mismatch
	after := uuid.Nil
	for {
		accts, err := pgledger.ListAccountsIn(ctx, q, after, page)
		if err != nil {
			return nil, fmt.Errorf("postgres accounts: %w", err)
		}
		if len(accts) == 0 {
			return out, nil
		}
		ids := make([]uuid.UUID, len(accts))
		for i, a := range accts {
			ids[i] = a.ID
		}
		pg, err := pgledger.BalancesIn(ctx, q, ids)
		if err != nil {
			return nil, fmt.Errorf("postgres balances: %w", err)
		}
		tbb, err := d.Balances(accts)
		if err != nil {
			return nil, fmt.Errorf("tigerbeetle balances: %w", err)
		}
		for _, a := range accts {
			p := pg[a.ID]
			t, ok := tbb[a.ID]
			if ok && t.Posted == p.Posted && t.Pending == p.Pending {
				continue
			}
			out = append(out, Mismatch{AccountID: a.ID, Currency: a.Currency, MissingInTB: !ok,
				PostgresPosted: p.Posted, PostgresPend: p.Pending, TBPosted: t.Posted, TBPending: t.Pending})
		}
		after = accts[len(accts)-1].ID
	}
}
