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

// Gateway holds the gateway schema migrations.
//
//go:embed gateway/*.sql
var Gateway embed.FS

// GatewayDir is the directory inside Gateway that contains the files.
const GatewayDir = "gateway"

// FX holds the FX engine schema migrations.
//
//go:embed fx/*.sql
var FX embed.FS

// FXDir is the directory inside FX that contains the files.
const FXDir = "fx"

// Grants is the least-privilege script for the runtime role. It is not a
// migration: operators run it as the schema owner (see the file header).
//
//go:embed ops/grants.sql
var Grants string
