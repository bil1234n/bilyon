// Package gatewaydb wires pgtest to the gateway schema: test databases are
// cloned from a template with every gateway migration applied.
package gatewaydb

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/migrate"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// MigrationsTable records the gateway schema's applied migrations.
const MigrationsTable = "gateway_schema_migrations"

// Setup applies the gateway migrations to the template database.
func Setup(ctx context.Context, pool *pgxpool.Pool) error {
	ms, err := migrate.Load(migrations.Gateway, migrations.GatewayDir)
	if err != nil {
		return err
	}
	_, err = migrate.Apply(ctx, pool, ms, migrate.Options{Table: MigrationsTable})
	return err
}
