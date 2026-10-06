// Package ledgerdb wires pgtest to the ledger schema: test databases are
// cloned from a template with every ledger migration applied.
package ledgerdb

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/migrate"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// Setup applies the ledger migrations to the template database.
func Setup(ctx context.Context, pool *pgxpool.Pool) error {
	ms, err := migrate.Load(migrations.Ledger, migrations.LedgerDir)
	if err != nil {
		return err
	}
	_, err = migrate.Apply(ctx, pool, ms, migrate.Options{})
	return err
}
