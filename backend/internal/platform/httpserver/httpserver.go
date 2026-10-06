// Package httpserver serves the operational endpoints every service exposes:
// /livez (process is alive), /readyz (dependencies reachable) and /metrics
// (Prometheus).
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Check reports whether one dependency is healthy.
type Check func(ctx context.Context) error

// Server is the operational HTTP server.
type Server struct {
	addr     string
	mux      *http.ServeMux
	log      *slog.Logger
	mu       sync.Mutex
	checks   map[string]Check
	listener net.Listener
}

// New builds the server. gatherer may be nil (no /metrics).
func New(addr string, gatherer prometheus.Gatherer, log *slog.Logger) *Server {
	s := &Server{addr: addr, mux: http.NewServeMux(), log: log, checks: map[string]Check{}}
	s.mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("GET /readyz", s.ready)
	if gatherer != nil {
		s.mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{EnableOpenMetrics: true}))
	}
	return s
}

// AddCheck registers a readiness check.
func (s *Server) AddCheck(name string, c Check) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks[name] = c
}

// Handle mounts an extra handler (e.g. an internal API).
func (s *Server) Handle(pattern string, h http.Handler) { s.mux.Handle(pattern, h) }

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	names := make([]string, 0, len(s.checks))
	for n := range s.checks {
		names = append(names, n)
	}
	checks := make(map[string]Check, len(s.checks))
	for n, c := range s.checks {
		checks[n] = c
	}
	s.mu.Unlock()
	sort.Strings(names)
	status := map[string]string{}
	healthy := true
	for _, n := range names {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		err := checks[n](ctx)
		cancel()
		if err != nil {
			healthy = false
			status[n] = err.Error()
			continue
		}
		status[n] = "ok"
	}
	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(status)
}

// Listen binds the address (":0" picks a free port) and returns it.
func (s *Server) Listen() (string, error) {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", err
	}
	s.listener = l
	return l.Addr().String(), nil
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	if s.listener == nil {
		if _, err := s.Listen(); err != nil {
			return err
		}
	}
	srv := &http.Server{Handler: s.mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(s.listener) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			return err
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
