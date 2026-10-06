// Package tlog is the directory's append-only transparency log (RFC 0001
// §4.1.3): a Merkle tree with RFC 9162 (Certificate Transparency v2)
// hashing, inclusion and consistency proofs and their verification, signed
// tree heads (COSE_Sign1 under K_dir), and PostgreSQL storage that keeps
// every complete subtree hash so proofs cost one query.
package tlog

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// Hash is a SHA-256 tree hash.
type Hash [sha256.Size]byte

// Errors.
var (
	ErrProof = errors.New("tlog: proof does not verify")
	ErrRange = errors.New("tlog: index or size out of range")
)

// LeafHash is RFC 9162 §2.1.1: SHA-256(0x00 ‖ leaf).
func LeafHash(leaf []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(leaf)
	return Hash(h.Sum(nil))
}

// NodeHash is RFC 9162 §2.1.1: SHA-256(0x01 ‖ left ‖ right).
func NodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left[:])
	h.Write(right[:])
	return Hash(h.Sum(nil))
}

// EmptyRoot is the root of the empty tree: SHA-256 of the empty string.
var EmptyRoot = Hash(sha256.Sum256(nil))

// split is the largest power of two smaller than n (n ≥ 2).
func split(n uint64) uint64 { return 1 << (bits.Len64(n-1) - 1) }

// node identifies a complete subtree: leaves [index·2^level, (index+1)·2^level).
type node struct {
	Level uint8
	Index uint64
}

// pieces decomposes [lo, hi) into the complete subtrees whose hashes
// determine its MTH, left to right, following RFC 9162's recursive split.
func pieces(lo, hi uint64) []node {
	n := hi - lo
	if n == 0 {
		return nil
	}
	if n&(n-1) == 0 && lo%n == 0 {
		level := uint8(bits.TrailingZeros64(n))
		return []node{{level, lo >> level}}
	}
	k := split(n)
	return append(pieces(lo, lo+k), pieces(lo+k, hi)...)
}

// rangeHash computes MTH(D[lo:hi]) from complete-subtree hashes.
func rangeHash(lo, hi uint64, get func(node) Hash) Hash {
	n := hi - lo
	switch {
	case n == 0:
		return EmptyRoot
	case n&(n-1) == 0 && lo%n == 0:
		level := uint8(bits.TrailingZeros64(n))
		return get(node{level, lo >> level})
	}
	k := split(n)
	return NodeHash(rangeHash(lo, lo+k, get), rangeHash(lo+k, hi, get))
}

// inclusionRanges lists the sibling ranges of an inclusion proof for leaf
// m in [lo, hi), bottom up (RFC 9162 §2.1.3.1 PATH).
func inclusionRanges(m, lo, hi uint64) [][2]uint64 {
	if hi-lo <= 1 {
		return nil
	}
	k := split(hi - lo)
	if m < lo+k {
		return append(inclusionRanges(m, lo, lo+k), [2]uint64{lo + k, hi})
	}
	return append(inclusionRanges(m, lo+k, hi), [2]uint64{lo, lo + k})
}

// consistencyRanges lists the ranges of a consistency proof between the
// trees of size m and hi (RFC 9162 §2.1.4.1 SUBPROOF).
func consistencyRanges(m, lo, hi uint64, complete bool) [][2]uint64 {
	if m == hi {
		if complete {
			return nil
		}
		return [][2]uint64{{lo, hi}}
	}
	k := split(hi - lo)
	if m-lo <= k {
		return append(consistencyRanges(m, lo, lo+k, complete), [2]uint64{lo + k, hi})
	}
	return append(consistencyRanges(m, lo+k, hi, false), [2]uint64{lo, lo + k})
}

// rangesNodes lists every complete subtree the ranges need, without
// duplicates.
func rangesNodes(ranges [][2]uint64) []node {
	seen := map[node]bool{}
	var out []node
	for _, r := range ranges {
		for _, n := range pieces(r[0], r[1]) {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// VerifyInclusion checks that leaf is at index in the tree of size with
// root (RFC 9162 §2.1.3.2).
func VerifyInclusion(index, size uint64, leaf Hash, proof []Hash, root Hash) error {
	if index >= size {
		return fmt.Errorf("%w: leaf %d in a tree of %d", ErrRange, index, size)
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("%w: proof too long", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		return ErrProof
	}
	return nil
}

// VerifyConsistency checks that the tree of size2 with root2 extends the
// tree of size1 with root1 (RFC 9162 §2.1.4.2).
func VerifyConsistency(size1, size2 uint64, root1, root2 Hash, proof []Hash) error {
	switch {
	case size1 > size2:
		return fmt.Errorf("%w: size %d after %d", ErrRange, size2, size1)
	case size1 == size2:
		if len(proof) != 0 || root1 != root2 {
			return ErrProof
		}
		return nil
	case size1 == 0:
		if len(proof) != 0 {
			return ErrProof
		}
		return nil // the empty tree is a prefix of every tree
	case len(proof) == 0:
		return ErrProof
	}
	path := proof
	if size1&(size1-1) == 0 {
		path = append([]Hash{root1}, proof...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: proof too long", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			fr, sr = NodeHash(c, fr), NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if fr != root1 || sr != root2 || sn != 0 {
		return ErrProof
	}
	return nil
}

// Tree is an in-memory log: auditors replay entries with it, and tests use
// it as the reference for the stored log.
type Tree struct {
	nodes map[node]Hash
	size  uint64
}

// NewTree returns an empty tree.
func NewTree() *Tree { return &Tree{nodes: map[node]Hash{}} }

// Append adds a leaf and returns its index.
func (t *Tree) Append(leaf []byte) uint64 {
	idx := t.size
	h := LeafHash(leaf)
	t.nodes[node{0, idx}] = h
	for level, i := uint8(0), idx; i&1 == 1; level, i = level+1, i>>1 {
		h = NodeHash(t.nodes[node{level, i - 1}], h)
		t.nodes[node{level + 1, i >> 1}] = h
	}
	t.size++
	return idx
}

// Size is the number of leaves.
func (t *Tree) Size() uint64 { return t.size }

func (t *Tree) get(n node) Hash { return t.nodes[n] }

// Root is the root of the first size leaves.
func (t *Tree) Root(size uint64) (Hash, error) {
	if size > t.size {
		return Hash{}, ErrRange
	}
	return rangeHash(0, size, t.get), nil
}

// InclusionProof proves leaf index in the tree of the first size leaves.
func (t *Tree) InclusionProof(index, size uint64) ([]Hash, error) {
	if index >= size || size > t.size {
		return nil, ErrRange
	}
	var proof []Hash
	for _, r := range inclusionRanges(index, 0, size) {
		proof = append(proof, rangeHash(r[0], r[1], t.get))
	}
	return proof, nil
}

// ConsistencyProof proves that the first size2 leaves extend the first size1.
func (t *Tree) ConsistencyProof(size1, size2 uint64) ([]Hash, error) {
	if size1 > size2 || size2 > t.size {
		return nil, ErrRange
	}
	if size1 == 0 || size1 == size2 {
		return nil, nil
	}
	var proof []Hash
	for _, r := range consistencyRanges(size1, 0, size2, true) {
		proof = append(proof, rangeHash(r[0], r[1], t.get))
	}
	return proof, nil
}
