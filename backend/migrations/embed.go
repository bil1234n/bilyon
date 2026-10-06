// Package migrations embeds Bilyon's forward-only SQL migrations.
//
// Files are named NNNN_description.sql and applied in version order by
// internal/migrate. A file whose first line is "-- bilyon:no-transaction"
// runs outside a transaction (needed for CREATE INDEX CONCURRENTLY).
package migrations

import "embed"

// Ledger holds the ledger schema migrations.
//
//go:embed ledger/*.sql
var Ledger embed.FS

// LedgerDir is the directory inside Ledger that contains the files.
const LedgerDir = "ledger"

// Grants is the least-privilege script for the runtime role. It is not a
// migration: operators run it as the schema owner (see the file header).
//
//go:embed ops/grants.sql
var Grants string
