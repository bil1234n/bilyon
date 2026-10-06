package fx

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/google/uuid"
)

const secondsPerYear = 365 * 24 * 3600

// LockBufferBps prices a rate lock (§3.C.4): the platform carries the pair's
// move over the lock window, and z standard deviations of a Brownian move
// over ttl is z·σ·√(ttl/year), in basis points. EUR/USD (σ = 7 %) for 30 s
// at z = 2.33 (99 %) is 1.59 bp.
func LockBufferBps(sigmaAnnual float64, ttl time.Duration, z float64) float64 {
	return z * sigmaAnnual * math.Sqrt(ttl.Seconds()/secondsPerYear) * 1e4
}

// KeepPPM is the share of the executable output the customer receives, in
// parts per million: ⌊10⁶ · (1 − (buffer + margin)/10⁴)⌋.
func KeepPPM(bufferBps, marginBps float64) (int64, error) {
	keep := math.Floor(1e6 * (1 - (bufferBps+marginBps)/1e4))
	if math.IsNaN(keep) || keep <= 0 || keep > 1e6 {
		return 0, fmt.Errorf("fx: buffer %.4f bp and margin %.4f bp leave nothing to quote", bufferBps, marginBps)
	}
	return int64(keep), nil
}

// CustomerAmount is ⌊execOut · keep / 10⁶⌋ in exact integer arithmetic.
func CustomerAmount(execOut, keepPPM int64) int64 {
	v := new(big.Int).Mul(big.NewInt(execOut), big.NewInt(keepPPM))
	return v.Quo(v, big.NewInt(1_000_000)).Int64()
}

// PairRisk is per-pair risk configuration.
type PairRisk struct {
	SigmaAnnual float64       // realised or implied volatility
	JumpBps     float64       // gap premium for pairs with jumps or thin liquidity
	MaxTTL      time.Duration // longest lock offered (longer locks are forwards)
}

// QuoteKey is one K_quote generation (§1.3: 30-day rotation with a
// dual-key acceptance window).
type QuoteKey struct {
	ID     string
	Secret []byte
}

type quoteSigner struct {
	keys []QuoteKey // keys[0] signs
	byID map[string][]byte
}

func newQuoteSigner(keys []QuoteKey) (*quoteSigner, error) {
	if len(keys) == 0 {
		return nil, errors.New("fx: at least one quote key is required")
	}
	s := &quoteSigner{keys: keys, byID: map[string][]byte{}}
	for _, k := range keys {
		if !idPattern.MatchString(k.ID) || len(k.Secret) < 32 {
			return nil, fmt.Errorf("fx: quote key %q needs an id and at least 32 bytes", k.ID)
		}
		if _, dup := s.byID[k.ID]; dup {
			return nil, fmt.Errorf("fx: quote key %q listed twice", k.ID)
		}
		s.byID[k.ID] = k.Secret
	}
	return s, nil
}

// quoteMessage is the signed content (§3.C.4):
// id|from|to|amount_in|amount_out|expires_ms, domain-separated.
func quoteMessage(id uuid.UUID, from, to string, in, out int64, expires time.Time) []byte {
	return fmt.Appendf(nil, "bilyon/fxq/v1|%s|%s|%s|%d|%d|%d", id, from, to, in, out, expires.UnixMilli())
}

func mac(secret, msg []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(msg)
	return m.Sum(nil)
}

func (s *quoteSigner) sign(msg []byte) (string, []byte) {
	k := s.keys[0]
	return k.ID, mac(k.Secret, msg)
}

func (s *quoteSigner) verify(kid string, msg, sig []byte) bool {
	secret, ok := s.byID[kid]
	return ok && hmac.Equal(sig, mac(secret, msg))
}
