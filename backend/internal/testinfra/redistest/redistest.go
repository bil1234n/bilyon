// Package redistest provides a real Redis server for tests: the server at
// BILYON_TEST_REDIS_URL, or a throwaway redis-server process on a free
// loopback port. Without either, tests skip (or fail when
// BILYON_REQUIRE_INFRA=1).
package redistest

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Start returns a client connected to an isolated logical database. The
// database is flushed before the test and the client closed after it.
func Start(t testing.TB) *redis.Client {
	t.Helper()
	if raw := os.Getenv("BILYON_TEST_REDIS_URL"); raw != "" {
		opts, err := redis.ParseURL(raw)
		if err != nil {
			t.Fatalf("redistest: BILYON_TEST_REDIS_URL: %v", err)
		}
		return connect(t, opts)
	}
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		if os.Getenv("BILYON_REQUIRE_INFRA") == "1" {
			t.Fatal("redistest: redis-server not found and BILYON_TEST_REDIS_URL unset")
		}
		t.Skip("redistest: no Redis available (install redis-server or set BILYON_TEST_REDIS_URL)")
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command(bin, "--port", strconv.Itoa(port), "--bind", "127.0.0.1", "--save", "",
		"--appendonly", "no", "--dir", dir, "--protected-mode", "yes", "--loglevel", "warning")
	if err := cmd.Start(); err != nil {
		t.Fatalf("redistest: start redis-server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return connect(t, &redis.Options{Addr: fmt.Sprintf("127.0.0.1:%d", port)})
}

func connect(t testing.TB, opts *redis.Options) *redis.Client {
	t.Helper()
	client := redis.NewClient(opts)
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := client.Ping(ctx).Err()
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("redistest: redis not ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("redistest: flush: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
