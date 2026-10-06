// Package tbtest provides a real TigerBeetle cluster for integration tests.
//
// Resolution order:
//  1. BILYON_TIGERBEETLE_ADDRESSES: an existing cluster (CI starts the
//     official container); BILYON_TIGERBEETLE_CLUSTER_ID selects the
//     cluster (default 0).
//  2. A tigerbeetle binary (BILYON_TIGERBEETLE_BIN, or tigerbeetle on PATH):
//     a single-replica cluster is formatted in a temp dir and started on a
//     free loopback port with --development.
//  3. Neither: tests are skipped, or fail if BILYON_REQUIRE_INFRA=1 (CI).
//
// TigerBeetle has no databases or schemas, so tests sharing a cluster must
// use fresh random ids (UUIDv7 ids already are).
package tbtest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Cluster is a TigerBeetle cluster usable by tests.
type Cluster struct {
	ID        uint64
	Addresses []string

	cmd *exec.Cmd
	dir string
}

// ErrUnavailable means no TigerBeetle could be found or started.
var ErrUnavailable = errors.New("tbtest: no TigerBeetle available (set BILYON_TIGERBEETLE_ADDRESSES or BILYON_TIGERBEETLE_BIN)")

// Start returns the external cluster or launches a local replica.
func Start() (*Cluster, error) {
	if raw := os.Getenv("BILYON_TIGERBEETLE_ADDRESSES"); raw != "" {
		var id uint64
		if s := os.Getenv("BILYON_TIGERBEETLE_CLUSTER_ID"); s != "" {
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("tbtest: BILYON_TIGERBEETLE_CLUSTER_ID: %w", err)
			}
			id = v
		}
		return &Cluster{ID: id, Addresses: strings.Split(raw, ",")}, nil
	}
	bin := os.Getenv("BILYON_TIGERBEETLE_BIN")
	if bin == "" {
		p, err := exec.LookPath("tigerbeetle")
		if err != nil {
			return nil, ErrUnavailable
		}
		bin = p
	}
	return launch(bin)
}

func launch(bin string) (*Cluster, error) {
	dir, err := os.MkdirTemp("", "bilyon-tb-*")
	if err != nil {
		return nil, err
	}
	data := filepath.Join(dir, "0_0.tigerbeetle")
	format := exec.Command(bin, "format", "--cluster=0", "--replica=0", "--replica-count=1", "--development", data)
	if out, err := format.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("tbtest: format: %w: %s", err, out)
	}
	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	cmd := exec.Command(bin, "start", "--addresses="+addr, "--development", "--cache-grid=256MiB", data)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("tbtest: start: %w", err)
	}
	c := &Cluster{ID: 0, Addresses: []string{addr}, cmd: cmd, dir: dir}
	ready := make(chan error, 1)
	go func() {
		// The replica logs "listening on" once it accepts clients; keep
		// draining afterwards so the pipe never blocks it.
		sc := bufio.NewScanner(stderr)
		var tail []string
		signalled := false
		for sc.Scan() {
			line := sc.Text()
			if !signalled {
				tail = append(tail, line)
				if len(tail) > 20 {
					tail = tail[1:]
				}
				if strings.Contains(line, "listening on") {
					signalled = true
					ready <- nil
				}
			}
		}
		if !signalled {
			ready <- fmt.Errorf("tbtest: replica exited before listening:\n%s", strings.Join(tail, "\n"))
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			c.Stop()
			return nil, err
		}
	case <-time.After(60 * time.Second):
		c.Stop()
		return nil, errors.New("tbtest: replica did not start within 60s")
	}
	return c, nil
}

// Stop terminates a launched replica and removes its data. It is a no-op for
// external clusters.
func (c *Cluster) Stop() {
	if c == nil || c.cmd == nil {
		return
	}
	_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = c.cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	_ = os.RemoveAll(c.dir)
}

// Main is a TestMain helper: it starts a cluster, stores it in *c, runs the
// tests and stops the cluster. When none is available, tests run and skip
// (or fail under BILYON_REQUIRE_INFRA=1) through Require.
func Main(m *testing.M, c **Cluster) int {
	cl, err := Start()
	if err != nil {
		if os.Getenv("BILYON_REQUIRE_INFRA") == "1" {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintln(os.Stderr, err, "- TigerBeetle tests will be skipped")
	}
	*c = cl
	code := m.Run()
	cl.Stop()
	return code
}

// Require skips (or fails, under BILYON_REQUIRE_INFRA=1) when c is nil.
func Require(t testing.TB, c *Cluster) *Cluster {
	t.Helper()
	if c != nil {
		return c
	}
	if os.Getenv("BILYON_REQUIRE_INFRA") == "1" {
		t.Fatal(ErrUnavailable)
	}
	t.Skip(ErrUnavailable)
	return nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
