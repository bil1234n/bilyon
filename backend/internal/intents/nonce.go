package intents

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Server nonces (TxAuth key 6) are stateless: any gateway node verifies
// them, and none stores them until an intent consumes one (the intent
// table's unique index makes each single-use).
//
//	nonce = issued_ms (6 bytes, big-endian) ‖ random (2 bytes) ‖ mac (8 bytes)
//	mac   = HMAC-SHA256(key, "bilyon/txnonce/v1" ‖ device_id ‖ issued_ms ‖ random)[:8]
//
// Binding the device means a nonce fetched by one device cannot authorise
// another's TxAuth; forging one takes ~2^64 online attempts, each of which
// also needs a valid K_dev signature.
const nonceLabel = "bilyon/txnonce/v1"

// Nonce is a server nonce and the last moment it can be signed with.
type Nonce struct {
	Value     [16]byte
	ExpiresAt time.Time
}

type nonces struct {
	keys [][]byte
	ttl  time.Duration
	skew time.Duration
}

func nonceMAC(key []byte, device uuid.UUID, head []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(nonceLabel))
	m.Write(device[:])
	m.Write(head)
	return m.Sum(nil)[:8]
}

func (n *nonces) issue(device uuid.UUID, now time.Time) (Nonce, error) {
	var v [16]byte
	ms := uint64(now.UnixMilli())
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(v[:6], ts[2:])
	if _, err := rand.Read(v[6:8]); err != nil {
		return Nonce{}, err
	}
	copy(v[8:], nonceMAC(n.keys[0], device, v[:8]))
	return Nonce{Value: v, ExpiresAt: time.UnixMilli(int64(ms)).Add(n.ttl).UTC()}, nil
}

// issuedAt returns when a nonce was issued.
func issuedAt(v [16]byte) time.Time {
	var ts [8]byte
	copy(ts[2:], v[:6])
	return time.UnixMilli(int64(binary.BigEndian.Uint64(ts[:]))).UTC()
}

var errNonceMAC = errors.New("not issued to this device")

// verify checks that v was issued to device, that the TxAuth was signed
// within the nonce's lifetime, and that the nonce is not from the future.
func (n *nonces) verify(v [16]byte, device uuid.UUID, signedAt, now time.Time) error {
	ok := false
	for _, k := range n.keys {
		if hmac.Equal(v[8:], nonceMAC(k, device, v[:8])) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("%w: %v", ErrNonce, errNonceMAC)
	}
	issued := issuedAt(v)
	switch {
	case issued.After(now.Add(n.skew)):
		return fmt.Errorf("%w: issued in the future", ErrNonce)
	case signedAt.Before(issued.Add(-n.skew)):
		return fmt.Errorf("%w: signed before it was issued", ErrNonce)
	case signedAt.After(issued.Add(n.ttl)):
		return fmt.Errorf("%w: expired at %s", ErrNonce, issued.Add(n.ttl))
	}
	return nil
}
