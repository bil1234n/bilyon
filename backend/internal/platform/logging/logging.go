// Package logging builds the structured logger every Bilyon service uses.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New returns a logger writing JSON (production) or text (local) records at
// the given level ("debug", "info", "warn", "error").
func New(w io.Writer, level, format, service string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		return nil, fmt.Errorf("logging: level %q: %w", level, err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("logging: format %q must be json or text", format)
	}
	return slog.New(h).With(slog.String("service", service)), nil
}
