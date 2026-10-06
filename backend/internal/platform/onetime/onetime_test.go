package onetime_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/platform/onetime"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/redistest"
)

type value struct {
	N int    `json:"n"`
	S string `json:"s"`
}

func TestSingleUseUnderConcurrency(t *testing.T) {
	s := onetime.New[value](redistest.Start(t), "test:")
	ctx := context.Background()
	if err := s.Put(ctx, "a", value{1, "x"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "a", value{2, "y"}, time.Minute); !errors.Is(err, onetime.ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if v, err := s.Take(ctx, "a"); err == nil {
				if v != (value{1, "x"}) {
					t.Errorf("value %+v", v)
				}
				wins.Add(1)
			} else if !errors.Is(err, onetime.ErrNotFound) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("taken %d times", wins.Load())
	}
	if err := s.Put(ctx, "b", value{}, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	if _, err := s.Take(ctx, "b"); !errors.Is(err, onetime.ErrNotFound) {
		t.Fatalf("expired value: %v", err)
	}
}
