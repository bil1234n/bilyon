// Command gatewayd runs the Bilyon API gateway. See internal/gatewayd.
package main

import (
	"context"
	"os"

	"github.com/bil1234n/bilyon/backend/internal/gatewayd"
	"github.com/bil1234n/bilyon/backend/internal/platform/config"
	"github.com/bil1234n/bilyon/backend/internal/platform/lifecycle"
)

func main() {
	ctx, stop := lifecycle.SignalContext(context.Background())
	code := gatewayd.Main(ctx, os.Args[1:], config.FromOS(), os.Stdout, os.Stderr, gatewayd.Hooks{})
	stop()
	os.Exit(code)
}
