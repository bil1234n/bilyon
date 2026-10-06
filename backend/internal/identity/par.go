package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/identity/tlog"
)

// PARContext is the external AAD of Payment Address Records.
const PARContext = "bilyon/par/v1"

// PARVersion is the record format version.
const PARVersion = 1

// MaxClockSkew bounds how far a PAR's issue time may lie in the verifier's
// future.
const MaxClockSkew = time.Minute

// PAR is a Payment Address Record (RFC 0001 §4.1.2): a directory entry with
// the proof that the transparency log contains it, signed by K_dir.
type PAR struct {
	Raw       []byte // COSE_Sign1
	Entry     *Entry
	EntryRaw  []byte // the committed entry bytes
	LeafIndex uint64
	TreeHead  tlog.TreeHead
	STH       []byte // the signed tree head the inclusion proof is against
	Inclusion []tlog.Hash
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// ErrPAR means a PAR failed verification.
var ErrPAR = errors.New("identity: invalid payment address record")

func signPAR(s cose.Signer, kid []byte, entryRaw []byte, leaf uint64, sth tlog.SignedTreeHead, proof []tlog.Hash,
	iat, exp time.Time) ([]byte, error) {
	inclusion := make([]any, len(proof))
	for i, h := range proof {
		inclusion[i] = append([]byte{}, h[:]...)
	}
	payload, err := cbor.Encode(cbor.Map{"v": uint64(PARVersion), "entry": entryRaw,
		"tlog": cbor.Map{"tree_size": sth.Size, "leaf_index": leaf, "inclusion": inclusion, "sth": sth.Raw},
		"iat":  uint64(iat.Unix()), "exp": uint64(exp.Unix())})
	if err != nil {
		return nil, err
	}
	return cose.Sign1(s, kid, payload, PARContext)
}

// VerifyPAR is what a payer's client does with a PAR: check the K_dir
// signature, the signed tree head, that the log contains the entry at the
// stated index, the entry's schema and the record's lifetime.
func VerifyPAR(raw []byte, keys cose.KeyResolver, now time.Time) (*PAR, error) {
	payload, _, err := cose.Verify1(raw, PARContext, keys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPAR, err)
	}
	v, err := cbor.Decode(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPAR, err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, fmt.Errorf("%w: not a map", ErrPAR)
	}
	f := m.Fields()
	if f.Uint("v") != PARVersion {
		f.Fail("v", "unsupported record version")
	}
	p := &PAR{Raw: raw, EntryRaw: f.BytesMax("entry", 8<<10)}
	tl := f.Map("tlog").Fields()
	size, leaf := tl.Uint("tree_size"), tl.Uint("leaf_index")
	var proof []tlog.Hash
	for _, item := range tl.Array("inclusion", 64) {
		b, ok := item.([]byte)
		if !ok || len(b) != len(tlog.Hash{}) {
			tl.Fail("inclusion", "not an array of 32-byte hashes")
			break
		}
		proof = append(proof, tlog.Hash(b))
	}
	p.STH = tl.BytesMax("sth", 1<<10)
	p.IssuedAt, p.ExpiresAt = time.Unix(int64(f.Uint("iat")), 0).UTC(), time.Unix(int64(f.Uint("exp")), 0).UTC()
	for _, sub := range []*cbor.Fields{tl, f} {
		if err := sub.Done(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPAR, err)
		}
	}
	th, _, err := tlog.VerifyTreeHead(p.STH, keys)
	if err != nil {
		return nil, fmt.Errorf("%w: tree head: %v", ErrPAR, err)
	}
	if th.Size != size {
		return nil, fmt.Errorf("%w: tree size %d, signed head %d", ErrPAR, size, th.Size)
	}
	if err := tlog.VerifyInclusion(leaf, size, tlog.LeafHash(p.EntryRaw), proof, th.Root); err != nil {
		return nil, fmt.Errorf("%w: inclusion: %v", ErrPAR, err)
	}
	if p.Entry, err = DecodeEntry(p.EntryRaw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPAR, err)
	}
	switch {
	case !p.ExpiresAt.After(p.IssuedAt):
		return nil, fmt.Errorf("%w: lifetime", ErrPAR)
	case now.After(p.ExpiresAt):
		return nil, fmt.Errorf("%w: expired at %s", ErrPAR, p.ExpiresAt)
	case p.IssuedAt.After(now.Add(MaxClockSkew)):
		return nil, fmt.Errorf("%w: issued in the future", ErrPAR)
	}
	p.LeafIndex, p.TreeHead, p.Inclusion = leaf, th, proof
	return p, nil
}
