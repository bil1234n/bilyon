package tlog

import (
	"errors"
	"fmt"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
)

// TreeHeadContext is the external AAD of signed tree heads.
const TreeHeadContext = "bilyon/sth/v1"

// TreeHead is the state of the log at one time.
type TreeHead struct {
	Size uint64
	Root Hash
	Time time.Time
}

// SignTreeHead signs a tree head with K_dir: COSE_Sign1 over the
// deterministic CBOR map {1: size, 2: root, 3: timestamp in ms}.
func SignTreeHead(s cose.Signer, kid []byte, th TreeHead) ([]byte, error) {
	payload, err := cbor.Encode(cbor.Map{int64(1): th.Size, int64(2): th.Root[:], int64(3): uint64(th.Time.UnixMilli())})
	if err != nil {
		return nil, err
	}
	return cose.Sign1(s, kid, payload, TreeHeadContext)
}

// ErrTreeHead means a signed tree head is malformed.
var ErrTreeHead = errors.New("tlog: malformed signed tree head")

// VerifyTreeHead checks a signed tree head against K_dir keys and returns
// its content and key id.
func VerifyTreeHead(raw []byte, keys cose.KeyResolver) (TreeHead, []byte, error) {
	payload, kid, err := cose.Verify1(raw, TreeHeadContext, keys)
	if err != nil {
		return TreeHead{}, nil, err
	}
	v, err := cbor.Decode(payload)
	if err != nil {
		return TreeHead{}, nil, fmt.Errorf("%w: %v", ErrTreeHead, err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return TreeHead{}, nil, ErrTreeHead
	}
	f := m.Fields()
	size, root, ts := f.Uint(1), f.BytesN(2, len(Hash{})), f.Uint(3)
	if err := f.Done(); err != nil {
		return TreeHead{}, nil, fmt.Errorf("%w: %v", ErrTreeHead, err)
	}
	return TreeHead{Size: size, Root: Hash(root), Time: time.UnixMilli(int64(ts)).UTC()}, kid, nil
}
