// Package lifecycle runs a service's long-lived components together: when
// one fails (or the context ends) the others are cancelled and awaited, so a
// service never keeps running half-broken.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

// Component is a long-running unit. It returns nil when ctx is cancelled.
type Component struct {
	Name string
	Run  func(ctx context.Context) error
}

// Run starts every component and blocks until all have returned. The first
// failure cancels the rest and is returned (wrapped with the component name).
func Run(ctx context.Context, log *slog.Logger, components ...Component) error {
	g, gctx := errgroup.WithContext(ctx)
	for _, c := range components {
		g.Go(func() error {
			log.InfoContext(gctx, "component started", slog.String("component", c.Name))
			err := c.Run(gctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.ErrorContext(gctx, "component failed", slog.String("component", c.Name), slog.Any("error", err))
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			log.InfoContext(gctx, "component stopped", slog.String("component", c.Name))
			return nil
		})
	}
	return g.Wait()
}

// SignalContext is cancelled on SIGINT or SIGTERM.
func SignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
