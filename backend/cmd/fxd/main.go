// Command fxd runs the Bilyon FX engine daemon. See internal/fxd.
package main

import (
	"context"
	"os"

	"github.com/bil1234n/bilyon/backend/internal/fxd"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/lifecycle"
)

func main() {
	ctx, stop := lifecycle.SignalContext(context.Background())
	code := fxd.Main(ctx, os.Args[1:], config.FromOS(), os.Stdout, os.Stderr, fxd.Hooks{})
	stop()
	os.Exit(code)
}
