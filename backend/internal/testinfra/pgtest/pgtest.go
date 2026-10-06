// Package pgtest provides real PostgreSQL servers for integration tests.
//
// Resolution order:
//  1. BILYON_TEST_DATABASE_URL: an existing server (CI uses a PostgreSQL 17
//     service container). The role needs CREATEDB.
//  2. Local PostgreSQL binaries (BILYON_PG_BINDIR, pg_config on PATH, or
//     /usr/lib/postgresql/<major>/bin): a throwaway cluster is initialised in
//     a temp dir and started on a free loopback port. When the test process
//     runs as root, the server runs as the "postgres" OS user, because
//     PostgreSQL refuses to run as root.
//  3. Neither: tests are skipped, or fail if BILYON_REQUIRE_INFRA=1 (CI).
//
// Every test gets its own database cloned from a migrated template, so tests
// can run in parallel without sharing state.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Setup prepares a freshly created database (typically: apply migrations).
type Setup func(ctx context.Context, pool *pgxpool.Pool) error

// Server is a PostgreSQL server usable by tests.
type Server struct {
	adminURL string // connects to the maintenance database
	cmd      *exec.Cmd
	dir      string
	setup    Setup

	tplOnce sync.Once
	tplName string
	tplErr  error
}

// ErrUnavailable means no PostgreSQL could be found or started.
var ErrUnavailable = errors.New("pgtest: no PostgreSQL available (set BILYON_TEST_DATABASE_URL or install PostgreSQL)")

// Start returns an external server (BILYON_TEST_DATABASE_URL) or launches a
// local one. setup runs once on the template database.
func Start(ctx context.Context, setup Setup) (*Server, error) {
	if raw := os.Getenv("BILYON_TEST_DATABASE_URL"); raw != "" {
		s := &Server{adminURL: raw, setup: setup}
		if err := s.ping(ctx); err != nil {
			return nil, fmt.Errorf("pgtest: BILYON_TEST_DATABASE_URL unreachable: %w", err)
		}
		return s, nil
	}
	bin, err := findBinDir()
	if err != nil {
		return nil, ErrUnavailable
	}
	return launch(ctx, bin, setup)
}

// Main is a TestMain helper: it starts a server, stores it in *srv, runs the
// tests and stops the server. When no server is available, tests run and
// skip (or fail under BILYON_REQUIRE_INFRA=1) through Server.Database.
func Main(m *testing.M, setup Setup, srv **Server) int {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	s, err := Start(ctx, setup)
	cancel()
	if err != nil {
		if os.Getenv("BILYON_REQUIRE_INFRA") == "1" {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "pgtest:", err, "- database tests will be skipped")
	}
	*srv = s
	code := m.Run()
	if s != nil {
		s.Stop()
	}
	return code
}

func findBinDir() (string, error) {
	if dir := os.Getenv("BILYON_PG_BINDIR"); dir != "" {
		return dir, nil
	}
	if out, err := exec.Command("pg_config", "--bindir").Output(); err == nil {
		dir := strings.TrimSpace(string(out))
		if _, err := os.Stat(filepath.Join(dir, "initdb")); err == nil {
			return dir, nil
		}
	}
	matches, _ := filepath.Glob("/usr/lib/postgresql/*/bin/initdb")
	if len(matches) == 0 {
		return "", ErrUnavailable
	}
	sort.Slice(matches, func(i, j int) bool { return majorOf(matches[i]) > majorOf(matches[j]) })
	return filepath.Dir(matches[0]), nil
}

func majorOf(initdbPath string) int {
	major, _ := strconv.Atoi(filepath.Base(filepath.Dir(filepath.Dir(initdbPath))))
	return major
}

func launch(ctx context.Context, bin string, setup Setup) (*Server, error) {
	dir, err := os.MkdirTemp("", "bilyon-pg-*")
	if err != nil {
		return nil, err
	}
	cred, err := serverCredential(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	data := filepath.Join(dir, "data")
	initdb := exec.CommandContext(ctx, filepath.Join(bin, "initdb"),
		"-D", data, "-U", "bilyon", "--auth=trust", "-E", "UTF8", "--no-locale", "--no-sync")
	initdb.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	if out, err := initdb.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("pgtest: initdb: %w: %s", err, out)
	}
	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	cmd := exec.Command(filepath.Join(bin, "postgres"),
		"-D", data, "-p", strconv.Itoa(port), "-k", dir,
		"-c", "listen_addresses=127.0.0.1",
		"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
		"-c", "max_connections=300", "-c", "shared_buffers=128MB",
		"-c", "log_min_messages=warning", "-c", "log_min_error_statement=panic")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setpgid: true}
	logFile, err := os.Create(filepath.Join(dir, "postgres.log"))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("pgtest: start postgres: %w", err)
	}
	s := &Server{
		adminURL: fmt.Sprintf("postgres://bilyon@127.0.0.1:%d/postgres?sslmode=disable", port),
		cmd:      cmd,
		dir:      dir,
		setup:    setup,
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := s.ping(ctx); err == nil {
			return s, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			logs, _ := os.ReadFile(filepath.Join(dir, "postgres.log"))
			s.Stop()
			return nil, fmt.Errorf("pgtest: postgres did not become ready: %s", logs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// serverCredential returns the identity to run the server as. Root must drop
// to the "postgres" user; other users run as themselves.
func serverCredential(dir string) (*syscall.Credential, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	u, err := user.Lookup("postgres")
	if err != nil {
		return nil, fmt.Errorf("pgtest: running as root needs a 'postgres' OS user: %w", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.Chown(dir, uid, gid); err != nil {
		return nil, err
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (s *Server) ping(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, s.adminURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	return conn.Ping(ctx)
}

// Stop shuts a launched server down (fast shutdown) and removes its files.
// It is a no-op for external servers.
func (s *Server) Stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGINT)
	done := make(chan struct{})
	go func() { _ = s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	_ = os.RemoveAll(s.dir)
}

func (s *Server) dbURL(name string) string {
	u, err := url.Parse(s.adminURL)
	if err != nil {
		panic(fmt.Sprintf("pgtest: bad admin URL: %v", err))
	}
	u.Path = "/" + name
	return u.String()
}

func (s *Server) template(ctx context.Context) (string, error) {
	s.tplOnce.Do(func() {
		name := "bilyon_tpl_" + randomSuffix()
		if err := s.adminExec(ctx, fmt.Sprintf("CREATE DATABASE %s", pgx.Identifier{name}.Sanitize())); err != nil {
			s.tplErr = err
			return
		}
		if s.setup != nil {
			pool, err := pgxpool.New(ctx, s.dbURL(name))
			if err != nil {
				s.tplErr = err
				return
			}
			err = s.setup(ctx, pool)
			pool.Close()
			if err != nil {
				s.tplErr = fmt.Errorf("pgtest: template setup: %w", err)
				return
			}
		}
		s.tplName = name
	})
	return s.tplName, s.tplErr
}

func (s *Server) adminExec(ctx context.Context, sql string) error {
	conn, err := pgx.Connect(ctx, s.adminURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql)
	return err
}

// Database returns a connection pool on a fresh database cloned from the
// migrated template. It is dropped when the test ends. A nil server skips
// the test (or fails it under BILYON_REQUIRE_INFRA=1).
func (s *Server) Database(t testing.TB) *pgxpool.Pool {
	t.Helper()
	if s == nil {
		if os.Getenv("BILYON_REQUIRE_INFRA") == "1" {
			t.Fatal(ErrUnavailable)
		}
		t.Skip(ErrUnavailable.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tpl, err := s.template(ctx)
	if err != nil {
		t.Fatalf("pgtest: template: %v", err)
	}
	name := "bilyon_test_" + randomSuffix()
	if err := s.adminExec(ctx, fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s",
		pgx.Identifier{name}.Sanitize(), pgx.Identifier{tpl}.Sanitize())); err != nil {
		t.Fatalf("pgtest: create database: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(s.dbURL(name))
	if err != nil {
		t.Fatalf("pgtest: parse url: %v", err)
	}
	cfg.MaxConns = 32
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgtest: connect: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.adminExec(dropCtx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", pgx.Identifier{name}.Sanitize()))
	})
	return pool
}

// URL returns the connection URL of a database created by Database's pool.
func URL(pool *pgxpool.Pool) string { return pool.Config().ConnString() }

func randomSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
