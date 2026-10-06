package tlog

import (
	"encoding/hex"
	"errors"
	"testing"
)

// RFC 6962 / RFC 9162 reference data: the eight test leaves, the roots of
// every prefix and published inclusion and consistency proofs.
var vectorLeaves = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657",
	"606162636465666768696a6b6c6d6e6f"}

var vectorRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hashes(t *testing.T, ss ...string) []Hash {
	t.Helper()
	out := make([]Hash, len(ss))
	for i, s := range ss {
		copy(out[i][:], mustHex(t, s))
	}
	return out
}

func vectorTree(t *testing.T) *Tree {
	t.Helper()
	tr := NewTree()
	for _, l := range vectorLeaves {
		tr.Append(mustHex(t, l))
	}
	return tr
}

func TestVectors(t *testing.T) {
	tr := vectorTree(t)
	for size := 1; size <= 8; size++ {
		root, err := tr.Root(uint64(size))
		if err != nil || hex.EncodeToString(root[:]) != vectorRoots[size-1] {
			t.Fatalf("root of %d leaves = %x, %v", size, root, err)
		}
	}
	if r, _ := tr.Root(0); r != EmptyRoot || hex.EncodeToString(EmptyRoot[:]) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty root")
	}
	inclusion := []struct {
		index, size uint64
		proof       []string
	}{
		{0, 8, []string{"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"}},
		{5, 8, []string{"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"}},
		{2, 3, []string{"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"}},
		{1, 5, []string{"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"}},
		{0, 1, nil},
	}
	for _, c := range inclusion {
		proof, err := tr.InclusionProof(c.index, c.size)
		if err != nil || len(proof) != len(c.proof) {
			t.Fatalf("inclusion %d/%d: %v %v", c.index, c.size, proof, err)
		}
		want := hashes(t, c.proof...)
		for i := range proof {
			if proof[i] != want[i] {
				t.Fatalf("inclusion %d/%d element %d: %x", c.index, c.size, i, proof[i])
			}
		}
		root, _ := tr.Root(c.size)
		if err := VerifyInclusion(c.index, c.size, LeafHash(mustHex(t, vectorLeaves[c.index])), want, root); err != nil {
			t.Fatalf("published proof %d/%d does not verify: %v", c.index, c.size, err)
		}
	}
	consistency := []struct {
		m, n  uint64
		proof []string
	}{
		{1, 1, nil},
		{1, 8, []string{"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"}},
		{6, 8, []string{"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"}},
		{2, 5, []string{"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"}},
	}
	for _, c := range consistency {
		proof, err := tr.ConsistencyProof(c.m, c.n)
		if err != nil || len(proof) != len(c.proof) {
			t.Fatalf("consistency %d->%d: %v %v", c.m, c.n, proof, err)
		}
		want := hashes(t, c.proof...)
		for i := range proof {
			if proof[i] != want[i] {
				t.Fatalf("consistency %d->%d element %d: %x", c.m, c.n, i, proof[i])
			}
		}
		r1, _ := tr.Root(c.m)
		r2, _ := tr.Root(c.n)
		if err := VerifyConsistency(c.m, c.n, r1, r2, want); err != nil {
			t.Fatalf("published proof %d->%d does not verify: %v", c.m, c.n, err)
		}
	}
}

// TestAllProofs verifies every inclusion and consistency proof of trees up
// to 70 leaves, and that any single change to a proof breaks it.
func TestAllProofs(t *testing.T) {
	tr := NewTree()
	for i := range 70 {
		tr.Append([]byte{byte(i), byte(i >> 8), 0xa5})
	}
	for size := uint64(1); size <= tr.Size(); size++ {
		root, _ := tr.Root(size)
		for idx := uint64(0); idx < size; idx++ {
			proof, err := tr.InclusionProof(idx, size)
			if err != nil {
				t.Fatal(err)
			}
			leaf := LeafHash([]byte{byte(idx), byte(idx >> 8), 0xa5})
			if err := VerifyInclusion(idx, size, leaf, proof, root); err != nil {
				t.Fatalf("leaf %d of %d: %v", idx, size, err)
			}
			if VerifyInclusion(idx, size, LeafHash([]byte("other")), proof, root) == nil {
				t.Fatalf("leaf %d of %d: a different leaf verified", idx, size)
			}
			if size > 1 && VerifyInclusion((idx+1)%size, size, leaf, proof, root) == nil && proofDiffers(tr, idx, (idx+1)%size, size) {
				t.Fatalf("leaf %d of %d verified at another index", idx, size)
			}
			for i := range proof {
				bad := append([]Hash{}, proof...)
				bad[i][0] ^= 1
				if VerifyInclusion(idx, size, leaf, bad, root) == nil {
					t.Fatalf("leaf %d of %d: tampered element %d verified", idx, size, i)
				}
			}
			if len(proof) > 0 && VerifyInclusion(idx, size, leaf, proof[:len(proof)-1], root) == nil {
				t.Fatalf("leaf %d of %d: truncated proof verified", idx, size)
			}
			if VerifyInclusion(idx, size, leaf, append(append([]Hash{}, proof...), Hash{}), root) == nil {
				t.Fatalf("leaf %d of %d: extended proof verified", idx, size)
			}
		}
		for old := uint64(0); old <= size; old++ {
			proof, err := tr.ConsistencyProof(old, size)
			if err != nil {
				t.Fatal(err)
			}
			r1, _ := tr.Root(old)
			if err := VerifyConsistency(old, size, r1, root, proof); err != nil {
				t.Fatalf("consistency %d->%d: %v", old, size, err)
			}
			if old > 0 && old < size {
				if VerifyConsistency(old, size, Hash{1}, root, proof) == nil {
					t.Fatalf("consistency %d->%d: a wrong old root verified", old, size)
				}
				for i := range proof {
					bad := append([]Hash{}, proof...)
					bad[i][31] ^= 0x80
					if VerifyConsistency(old, size, r1, root, bad) == nil {
						t.Fatalf("consistency %d->%d: tampered element %d verified", old, size, i)
					}
				}
			}
		}
	}
	if err := VerifyInclusion(3, 3, Hash{}, nil, Hash{}); !errors.Is(err, ErrRange) {
		t.Fatalf("index beyond size: %v", err)
	}
	if err := VerifyConsistency(5, 4, Hash{}, Hash{}, nil); !errors.Is(err, ErrRange) {
		t.Fatalf("shrinking tree: %v", err)
	}
	if err := VerifyConsistency(3, 5, Hash{}, Hash{}, nil); !errors.Is(err, ErrProof) {
		t.Fatalf("empty proof: %v", err)
	}
	if _, err := tr.InclusionProof(70, 70); !errors.Is(err, ErrRange) {
		t.Fatalf("proof beyond the tree: %v", err)
	}
	if _, err := tr.ConsistencyProof(10, 80); !errors.Is(err, ErrRange) {
		t.Fatalf("consistency beyond the tree: %v", err)
	}
}

// proofDiffers reports whether two leaves' proofs differ (identical leaves
// at mirrored positions can legitimately share a proof structure).
func proofDiffers(tr *Tree, a, b, size uint64) bool {
	pa, _ := tr.InclusionProof(a, size)
	pb, _ := tr.InclusionProof(b, size)
	if len(pa) != len(pb) {
		return true
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return true
		}
	}
	return false
}
