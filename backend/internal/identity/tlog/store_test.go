package tlog

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

func appendLeaf(t *testing.T, l *Log, leaf []byte) uint64 {
	t.Helper()
	var idx uint64
	err := pgx.BeginFunc(ctx(t), l.pool, func(tx pgx.Tx) error {
		var err error
		idx, err = l.Append(ctx(t), tx, leaf)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestStoredLogMatchesTheReference(t *testing.T) {
	t.Parallel()
	l := New(srv.Database(t))
	ref := NewTree()
	for i := range 45 {
		leaf := []byte(fmt.Sprintf("entry %d", i))
		if got := appendLeaf(t, l, leaf); got != uint64(i) {
			t.Fatalf("index %d, want %d", got, i)
		}
		ref.Append(leaf)
	}
	if size, err := l.Size(ctx(t)); err != nil || size != 45 {
		t.Fatalf("Size = %d, %v", size, err)
	}
	for size := uint64(0); size <= 45; size++ {
		want, _ := ref.Root(size)
		got, err := l.Root(ctx(t), size)
		if err != nil || got != want {
			t.Fatalf("root of %d: %x vs %x (%v)", size, got, want, err)
		}
		for idx := uint64(0); idx < size; idx += 7 {
			proof, err := l.InclusionProof(ctx(t), idx, size)
			if err != nil {
				t.Fatal(err)
			}
			refProof, _ := ref.InclusionProof(idx, size)
			if len(proof) != len(refProof) {
				t.Fatalf("inclusion %d/%d: %d vs %d hashes", idx, size, len(proof), len(refProof))
			}
			for i := range proof {
				if proof[i] != refProof[i] {
					t.Fatalf("inclusion %d/%d differs at %d", idx, size, i)
				}
			}
		}
		for old := uint64(0); old <= size; old += 5 {
			proof, err := l.ConsistencyProof(ctx(t), old, size)
			if err != nil {
				t.Fatal(err)
			}
			r1, _ := ref.Root(old)
			if err := VerifyConsistency(old, size, r1, want, proof); err != nil {
				t.Fatalf("consistency %d->%d: %v", old, size, err)
			}
		}
	}
	leaves, err := l.Leaves(ctx(t), 40, 10)
	if err != nil || len(leaves) != 5 || string(leaves[0]) != "entry 40" {
		t.Fatalf("Leaves = %q, %v", leaves, err)
	}
	for _, bad := range []func() error{
		func() error { _, err := l.Root(ctx(t), 46); return err },
		func() error { _, err := l.InclusionProof(ctx(t), 45, 45); return err },
		func() error { _, err := l.InclusionProof(ctx(t), 3, 50); return err },
		func() error { _, err := l.ConsistencyProof(ctx(t), 10, 50); return err },
		func() error { _, err := l.ConsistencyProof(ctx(t), 10, 5); return err },
	} {
		if err := bad(); !errors.Is(err, ErrRange) {
			t.Fatalf("out of range: %v", err)
		}
	}
}

func TestConcurrentAppends(t *testing.T) {
	t.Parallel()
	l := New(srv.Database(t))
	var wg sync.WaitGroup
	seen := make([]bool, 40)
	var mu sync.Mutex
	for w := range 8 {
		wg.Go(func() {
			for i := range 5 {
				idx := appendLeaf(t, l, []byte(fmt.Sprintf("w%d-%d", w, i)))
				mu.Lock()
				if seen[idx] {
					t.Errorf("index %d handed out twice", idx)
				}
				seen[idx] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	leaves, err := l.Leaves(ctx(t), 0, 100)
	if err != nil || len(leaves) != 40 {
		t.Fatalf("%d leaves, %v", len(leaves), err)
	}
	ref := NewTree()
	for _, leaf := range leaves {
		ref.Append(leaf)
	}
	want, _ := ref.Root(40)
	if got, err := l.Root(ctx(t), 40); err != nil || got != want {
		t.Fatalf("root after concurrent appends: %x vs %x (%v)", got, want, err)
	}
}

func TestSignedTreeHeads(t *testing.T) {
	t.Parallel()
	l := New(srv.Database(t))
	signer, err := cose.GenerateKeySigner()
	if err != nil {
		t.Fatal(err)
	}
	keys := func(kid []byte) (*ecdsa.PublicKey, error) {
		if string(kid) != "dir-1" {
			return nil, cose.ErrUnknownKey
		}
		return signer.Public(), nil
	}
	if _, err := l.Latest(ctx(t)); !errors.Is(err, ErrNoTreeHead) {
		t.Fatalf("Latest before any head: %v", err)
	}
	empty, err := l.Publish(ctx(t), signer, []byte("dir-1"), time.Now())
	if err != nil || empty.Size != 0 || empty.Root != EmptyRoot {
		t.Fatalf("empty head %+v, %v", empty, err)
	}
	for i := range 5 {
		appendLeaf(t, l, []byte{byte(i)})
	}
	now := time.Date(2026, 10, 6, 12, 0, 0, 123_000_000, time.UTC)
	sth, err := l.Publish(ctx(t), signer, []byte("dir-1"), now)
	if err != nil {
		t.Fatal(err)
	}
	th, kid, err := VerifyTreeHead(sth.Raw, keys)
	if err != nil || string(kid) != "dir-1" || th.Size != 5 || th.Root != sth.Root || !th.Time.Equal(now) {
		t.Fatalf("VerifyTreeHead = %+v %s %v", th, kid, err)
	}
	latest, err := l.Latest(ctx(t))
	if err != nil || latest.Size != 5 || string(latest.Raw) != string(sth.Raw) {
		t.Fatalf("Latest = %+v, %v", latest, err)
	}
	other, _ := cose.GenerateKeySigner()
	forged, _ := SignTreeHead(other, []byte("dir-1"), th)
	if _, _, err := VerifyTreeHead(forged, keys); err == nil {
		t.Fatal("a head signed by another key verified")
	}
	// A COSE_Sign1 for another purpose does not pass as a tree head.
	misused, _ := cose.Sign1(signer, []byte("dir-1"), []byte{0xa0}, "bilyon/par/v1")
	if _, _, err := VerifyTreeHead(misused, keys); err == nil {
		t.Fatal("a signature under another context verified")
	}
	wrongShape, _ := cose.Sign1(signer, []byte("dir-1"), []byte{0xa1, 0x01, 0x05}, TreeHeadContext)
	if _, _, err := VerifyTreeHead(wrongShape, keys); !errors.Is(err, ErrTreeHead) {
		t.Fatalf("incomplete head: %v", err)
	}
}
