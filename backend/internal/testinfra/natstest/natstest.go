// Package natstest runs a real NATS server with JetStream for tests: the
// server at BILYON_TEST_NATS_URL, or an in-process nats-server (the same
// server binary code, embedded) with a throwaway store directory.
package natstest

import (
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// Server is a running NATS server.
type Server struct {
	URL      string
	embedded *server.Server
}

// Start launches (or attaches to) a JetStream-enabled server for the test.
func Start(t testing.TB) *Server {
	t.Helper()
	if url := os.Getenv("BILYON_TEST_NATS_URL"); url != "" {
		return &Server{URL: url}
	}
	opts := &server.Options{
		Host:      "127.0.0.1",
		Port:      server.RANDOM_PORT,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("natstest: new server: %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("natstest: server not ready")
	}
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	return &Server{URL: s.ClientURL(), embedded: s}
}

// Connect opens a client connection closed at test end.
func (s *Server) Connect(t testing.TB) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(s.URL, nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatalf("natstest: connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// Shutdown stops an embedded server early (to test failure handling).
func (s *Server) Shutdown() {
	if s.embedded != nil {
		s.embedded.Shutdown()
		s.embedded.WaitForShutdown()
	}
}
