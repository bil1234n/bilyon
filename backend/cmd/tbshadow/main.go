// Command tbshadow mirrors the Bilyon ledger into TigerBeetle and reconciles
// the two. See internal/tbshadow.
package main

import (
	"context"
	"os"

	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/lifecycle"
	"github.com/bil1234n/bilyon/backend/internal/tbshadow"
)

func main() {
	ctx, stop := lifecycle.SignalContext(context.Background())
	code := tbshadow.Main(ctx, os.Args[1:], config.FromOS(), os.Stdout, os.Stderr, tbshadow.Hooks{})
	stop()
	os.Exit(code)
}
