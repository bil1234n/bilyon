// Command ledgerd runs the Bilyon ledger daemon. See internal/ledgerd.
package main

import (
	"context"
	"os"

	"github.com/bil1234n/bilyon/backend/internal/ledgerd"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/lifecycle"
)

func main() {
	ctx, stop := lifecycle.SignalContext(context.Background())
	code := ledgerd.Main(ctx, os.Args[1:], config.FromOS(), os.Stdout, os.Stderr, ledgerd.Hooks{})
	stop()
	os.Exit(code)
}
