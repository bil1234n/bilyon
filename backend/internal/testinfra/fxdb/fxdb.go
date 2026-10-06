// Package fxdb wires pgtest to the FX engine schema: test databases are
// cloned from a template with every FX migration applied.
package fxdb

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/migrate"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// MigrationsTable records the FX schema's applied migrations.
const MigrationsTable = "fx_schema_migrations"

// Setup applies the FX migrations to the template database.
func Setup(ctx context.Context, pool *pgxpool.Pool) error {
	ms, err := migrate.Load(migrations.FX, migrations.FXDir)
	if err != nil {
		return err
	}
	_, err = migrate.Apply(ctx, pool, ms, migrate.Options{Table: MigrationsTable})
	return err
}
