// Package onetime stores short-lived, single-use values in Redis: WebAuthn
// ceremonies, device-binding challenges, DPoP nonces. Put refuses to
// overwrite a key; Take reads and deletes atomically (GETDEL), so a value
// can be consumed at most once even under concurrent requests.
package onetime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNotFound means the value never existed, expired or was already taken.
var ErrNotFound = errors.New("onetime: not found, expired or already used")

// ErrExists means Put found the key taken.
var ErrExists = errors.New("onetime: key already exists")

// Store keeps JSON-encoded values of type T under a key prefix.
type Store[T any] struct {
	rdb    redis.UniversalClient
	prefix string
}

// New returns a store whose keys start with prefix (e.g. "bilyon:webauthn:").
func New[T any](rdb redis.UniversalClient, prefix string) *Store[T] {
	return &Store[T]{rdb: rdb, prefix: prefix}
}

// Put stores v under id for ttl.
func (s *Store[T]) Put(ctx context.Context, id string, v T, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ok, err := s.rdb.SetNX(ctx, s.prefix+id, raw, ttl).Result()
	if err != nil {
		return fmt.Errorf("onetime: put: %w", err)
	}
	if !ok {
		return ErrExists
	}
	return nil
}

// Take returns and deletes the value under id.
func (s *Store[T]) Take(ctx context.Context, id string) (T, error) {
	var v T
	raw, err := s.rdb.GetDel(ctx, s.prefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, fmt.Errorf("onetime: take: %w", err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("onetime: corrupt value: %w", err)
	}
	return v, nil
}
