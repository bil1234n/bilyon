// Package idempotency is the Redis fast path in front of the ledger's
// authoritative PostgreSQL idempotency (RFC 0001 §2.3.1 I4).
//
// PostgreSQL alone already guarantees exactly-once execution. The guard adds:
//   - collapsing of concurrent duplicates (client retries racing the original)
//     before they queue on database row locks;
//   - replay of completed responses without a database round trip.
//
// Every transition is a single Lua script, so it is atomic in Redis. Claims
// carry a random fence: a request whose claim expired cannot overwrite the
// result of the request that took over. When Redis is unreachable the guard
// fails open and the call goes straight to the database, which remains
// correct on its own.
package idempotency

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// Errors returned by the guard.
var (
	ErrConflict   = errors.New("idempotency: key reused with a different request")
	ErrInProgress = errors.New("idempotency: an identical request is still in progress")
	ErrLost       = errors.New("idempotency: claim expired before completion")
)

// Outcome of Begin.
type Outcome int

// Outcomes.
const (
	Claimed    Outcome = iota + 1 // the caller owns the key and must Complete or Abort
	Replayed                      // a completed response is returned
	InProgress                    // an identical request holds the claim
)

// Claim is ownership of a key until Complete, Abort or lock expiry.
type Claim struct {
	Key   string
	Fence string
}

// Config tunes a Guard.
type Config struct {
	Prefix      string        // key prefix, default "bilyon:idem:"
	LockTTL     time.Duration // claim lifetime, default 30s (must exceed the slowest command)
	ResultTTL   time.Duration // replay window, default 24h
	WaitTimeout time.Duration // how long Do waits for an in-flight duplicate, default 5s
	FailOpen    bool          // run the command when Redis errors (recommended: true)
	Logger      *slog.Logger
}

// Guard is safe for concurrent use.
type Guard struct {
	rdb redis.UniversalClient
	cfg Config
}

// New returns a guard with defaults applied.
func New(rdb redis.UniversalClient, cfg Config) *Guard {
	if cfg.Prefix == "" {
		cfg.Prefix = "bilyon:idem:"
	}
	if cfg.LockTTL <= 0 {
		cfg.LockTTL = 30 * time.Second
	}
	if cfg.ResultTTL <= 0 {
		cfg.ResultTTL = 24 * time.Hour
	}
	if cfg.WaitTimeout <= 0 {
		cfg.WaitTimeout = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Guard{rdb: rdb, cfg: cfg}
}

var beginScript = redis.NewScript(`
local cur = redis.call('HMGET', KEYS[1], 'state', 'hash', 'resp')
if not cur[1] then
  redis.call('HSET', KEYS[1], 'state', 'inflight', 'fence', ARGV[1], 'hash', ARGV[2])
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
  return {'claimed'}
end
if cur[2] ~= ARGV[2] then
  return {'conflict'}
end
if cur[1] == 'done' then
  return {'replay', cur[3]}
end
return {'inflight'}
`)

var completeScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'fence') ~= ARGV[1] then
  return 0
end
redis.call('HSET', KEYS[1], 'state', 'done', 'resp', ARGV[2])
redis.call('HDEL', KEYS[1], 'fence')
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
`)

var abortScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'fence') == ARGV[1] and redis.call('HGET', KEYS[1], 'state') == 'inflight' then
  return redis.call('DEL', KEYS[1])
end
return 0
`)

func (g *Guard) redisKey(key string) string { return g.cfg.Prefix + key }

// Begin claims key for a request whose canonical hash is hash.
func (g *Guard) Begin(ctx context.Context, key string, hash [32]byte) (Outcome, *Claim, []byte, error) {
	fence, err := newFence()
	if err != nil {
		return 0, nil, nil, err
	}
	res, err := beginScript.Run(ctx, g.rdb, []string{g.redisKey(key)},
		fence, hex.EncodeToString(hash[:]), g.cfg.LockTTL.Milliseconds()).Slice()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("idempotency: begin: %w", err)
	}
	switch res[0] {
	case "claimed":
		return Claimed, &Claim{Key: key, Fence: fence}, nil, nil
	case "replay":
		resp, _ := res[1].(string)
		return Replayed, nil, []byte(resp), nil
	case "inflight":
		return InProgress, nil, nil, nil
	case "conflict":
		return 0, nil, nil, ErrConflict
	}
	return 0, nil, nil, fmt.Errorf("idempotency: unexpected script result %v", res)
}

// Complete stores the response for replay. ErrLost means the claim expired
// and another request took over; the response is still valid because the
// database executed the command exactly once.
func (g *Guard) Complete(ctx context.Context, c *Claim, response []byte) error {
	ok, err := completeScript.Run(ctx, g.rdb, []string{g.redisKey(c.Key)},
		c.Fence, response, g.cfg.ResultTTL.Milliseconds()).Int()
	if err != nil {
		return fmt.Errorf("idempotency: complete: %w", err)
	}
	if ok == 0 {
		return ErrLost
	}
	return nil
}

// Abort releases a claim after a failed command so a retry can run.
func (g *Guard) Abort(ctx context.Context, c *Claim) error {
	if err := abortScript.Run(ctx, g.rdb, []string{g.redisKey(c.Key)}, c.Fence).Err(); err != nil {
		return fmt.Errorf("idempotency: abort: %w", err)
	}
	return nil
}

// Do runs fn at most once per key across concurrent callers and returns the
// (possibly replayed) response. fn's errors are returned unchanged and the
// claim is released so the request can be retried.
func (g *Guard) Do(ctx context.Context, key string, hash [32]byte, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	deadline := time.Now().Add(g.cfg.WaitTimeout)
	backoff := 5 * time.Millisecond
	for {
		outcome, claim, resp, err := g.Begin(ctx, key, hash)
		if err != nil {
			if errors.Is(err, ErrConflict) || !g.cfg.FailOpen || ctx.Err() != nil {
				return nil, err
			}
			g.cfg.Logger.WarnContext(ctx, "idempotency guard unavailable, failing open", slog.Any("error", err))
			return fn(ctx)
		}
		switch outcome {
		case Replayed:
			return resp, nil
		case Claimed:
			resp, err := fn(ctx)
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			if err != nil {
				if aerr := g.Abort(cleanup, claim); aerr != nil {
					g.cfg.Logger.WarnContext(ctx, "idempotency abort failed", slog.Any("error", aerr))
				}
				return nil, err
			}
			if cerr := g.Complete(cleanup, claim, resp); cerr != nil {
				g.cfg.Logger.WarnContext(ctx, "idempotency complete failed", slog.String("key", key), slog.Any("error", cerr))
			}
			return resp, nil
		case InProgress:
			if time.Now().After(deadline) {
				return nil, ErrInProgress
			}
			select {
			case <-time.After(backoff):
				backoff = min(backoff*2, 200*time.Millisecond)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
}

func newFence() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("idempotency: fence: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
