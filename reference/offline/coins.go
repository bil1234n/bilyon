package offline

import (
	"errors"
	"math"

	"github.com/bil1234n/bilyon/reference/internal/cbor"
)

// Tier S: value is carried by single-use hardware keys ("coins"). Each coin
// key is generated with KeyMint USAGE_COUNT_LIMIT=1; the server accepts it
// only if the key attestation lists that limit and rollback resistance as
// TEE/StrongBox-enforced. The allowance certifies all coins at once through a
// Merkle root, so a payee can verify any coin with a log2(N)-hash proof, and
// spending a coin twice requires extracting a key from the TEE.

// MaxCoins bounds the coins per allowance (tree depth 6).
const MaxCoins = 64

// CoinSpend is one coin's transfer to a payee, signed by the coin key.
type CoinSpend struct {
	AllowanceID ID128  // 2
	Index       uint64 // 3
	Denom       uint64 // 4
	CoinKey     []byte // 5
	Proof       []Hash // 6
	Payee       Hash   // 7
	Nonce       ID128  // 8
	Time        uint64 // 9
}

func (c *CoinSpend) encode() []byte {
	proof := make([]any, len(c.Proof))
	for i := range c.Proof {
		proof[i] = c.Proof[i][:]
	}
	return cbor.MustEncode(cbor.Map{1: uint64(version), 2: c.AllowanceID[:], 3: c.Index, 4: c.Denom,
		5: c.CoinKey, 6: proof, 7: c.Payee[:], 8: c.Nonce[:], 9: c.Time})
}

// ID identifies a coin spend independently of its signature encoding.
func (c *CoinSpend) ID() Hash { return taggedHash("bilyon/cid/v1", c.encode()) }

func decodeCoinSpend(payload []byte) (*CoinSpend, error) {
	f := parseFields(payload, 2, 3, 4, 5, 6, 7, 8, 9)
	if f.err != nil {
		return nil, f.err
	}
	c := &CoinSpend{AllowanceID: f.id(2), Index: f.uint(3), Denom: f.uint(4), CoinKey: f.bytes(5, 33, 33),
		Payee: f.hash(7), Nonce: f.id(8), Time: f.uint(9)}
	arr, ok := f.m[6].([]any)
	if !ok || len(arr) > 6 {
		return nil, ErrMalformed
	}
	for _, e := range arr {
		b, ok := e.([]byte)
		if !ok || len(b) != 32 {
			return nil, ErrMalformed
		}
		var h Hash
		copy(h[:], b)
		c.Proof = append(c.Proof, h)
	}
	return c, f.err
}

func coinLeaf(idx, denom uint64, key []byte) Hash {
	return taggedHash("bilyon/coin-leaf/v1", u64(idx), u64(denom), key)
}

func coinNode(l, r Hash) Hash { return taggedHash("bilyon/coin-node/v1", l[:], r[:]) }

// buildTree pads the leaves to a power of two and returns every level.
func buildTree(leaves []Hash) [][]Hash {
	n := 1
	for n < len(leaves) {
		n <<= 1
	}
	level := append([]Hash(nil), leaves...)
	for i := len(leaves); i < n; i++ {
		level = append(level, taggedHash("bilyon/coin-pad/v1", u64(uint64(i))))
	}
	levels := [][]Hash{level}
	for len(level) > 1 {
		next := make([]Hash, len(level)/2)
		for i := range next {
			next[i] = coinNode(level[2*i], level[2*i+1])
		}
		levels, level = append(levels, next), next
	}
	return levels
}

func proofFor(levels [][]Hash, idx uint64) []Hash {
	var proof []Hash
	for _, level := range levels[:len(levels)-1] {
		proof = append(proof, level[idx^1])
		idx >>= 1
	}
	return proof
}

func verifyProof(leaf Hash, idx uint64, proof []Hash, root []byte) bool {
	if idx >= 1<<len(proof) {
		return false
	}
	h := leaf
	for k, sib := range proof {
		if (idx>>k)&1 == 0 {
			h = coinNode(h, sib)
		} else {
			h = coinNode(sib, h)
		}
	}
	return string(h[:]) == string(root)
}

// Coin is one minted coin held by the payer.
type Coin struct {
	Index, Denom uint64
	key          Signer
	spent        bool
}

// CoinSet is the output of on-device minting: keys plus the Merkle tree whose
// root the issuer certifies after verifying each key's attestation.
type CoinSet struct {
	Coins  []*Coin
	levels [][]Hash
}

// Root returns the Merkle root to place in the allowance.
func (s *CoinSet) Root() []byte { r := s.levels[len(s.levels)-1][0]; return r[:] }

// Total is the sum of denominations (the allowance amount).
func (s *CoinSet) Total() (t uint64) {
	for _, c := range s.Coins {
		t += c.Denom
	}
	return t
}

// MintCoins generates one single-use key per denomination.
func MintCoins(denoms []uint64) (*CoinSet, error) {
	if len(denoms) == 0 || len(denoms) > MaxCoins {
		return nil, errors.New("coin count out of range")
	}
	set := &CoinSet{}
	var leaves []Hash
	for i, d := range denoms {
		k, err := NewSingleUseKey()
		if err != nil {
			return nil, err
		}
		set.Coins = append(set.Coins, &Coin{Index: uint64(i), Denom: d, key: k})
		leaves = append(leaves, coinLeaf(uint64(i), d, k.PublicKey()))
	}
	set.levels = buildTree(leaves)
	return set, nil
}

// SelectCoins returns unspent coins summing exactly to amount with the fewest
// coins (0/1 subset-sum DP, O(N*amount); N <= 64 so this is ~3M steps for a
// 500.00 payment in cents). It errors if no exact combination exists.
func SelectCoins(coins []*Coin, amount uint64) ([]*Coin, error) {
	var avail []*Coin
	for _, c := range coins {
		if !c.spent && c.Denom <= amount {
			avail = append(avail, c)
		}
	}
	const inf = math.MaxInt32
	best := make([]int32, amount+1)
	for a := range best {
		best[a] = inf
	}
	best[0] = 0
	take := make([][]bool, len(avail))
	for i, c := range avail {
		take[i] = make([]bool, amount+1)
		for a := amount; a >= c.Denom; a-- {
			if best[a-c.Denom] != inf && best[a-c.Denom]+1 < best[a] {
				best[a], take[i][a] = best[a-c.Denom]+1, true
			}
		}
	}
	if best[amount] == inf {
		return nil, errors.New("no exact coin combination")
	}
	var picked []*Coin
	for i, a := len(avail)-1, amount; i >= 0 && a > 0; i-- {
		if take[i][a] {
			picked = append(picked, avail[i])
			a -= avail[i].Denom
		}
	}
	return picked, nil
}

// CoinPurse is the payer side of a Tier S allowance.
type CoinPurse struct {
	oacRaw []byte
	oac    *Allowance
	set    *CoinSet
	trust  TrustStore
	Clock  TimeFloor
}

// OpenCoinPurse binds a minted coin set to its issued allowance.
func OpenCoinPurse(oacRaw []byte, set *CoinSet, trust TrustStore) (*CoinPurse, error) {
	oac, err := openAllowance(oacRaw, trust)
	if err != nil {
		return nil, err
	}
	if oac.Tier != TierS || string(oac.CoinRoot) != string(set.Root()) || oac.Amount != set.Total() {
		return nil, errors.New("allowance does not certify this coin set")
	}
	cp := &CoinPurse{oacRaw: oacRaw, oac: oac, set: set, trust: trust}
	cp.Clock.Observe(oac.IssuedAt)
	return cp, nil
}

// Pay selects coins for the request and signs one CoinSpend per coin. Coins
// are marked spent before signing; even if that bookkeeping were lost, the
// hardware refuses a second signature with the same coin key.
func (cp *CoinPurse) Pay(certRaw, reqRaw []byte, wall uint64) ([]byte, error) {
	cert, req, now, err := verifyRequest(cp.trust, &cp.Clock, certRaw, reqRaw, wall)
	if err != nil {
		return nil, err
	}
	switch {
	case req.Currency != cp.oac.Currency:
		return nil, ErrCurrency
	case now < cp.oac.NotBefore:
		return nil, ErrNotYetValid
	case now > cp.oac.Expiry:
		return nil, ErrExpired
	case req.Amount == 0 || req.Amount > cp.oac.TxMax:
		return nil, ErrLimit
	}
	picked, err := SelectCoins(cp.set.Coins, req.Amount)
	if err != nil {
		return nil, err
	}
	binding := PayeeBinding(cert.DeviceKey, cert.Account)
	spends := make([]any, 0, len(picked))
	for _, c := range picked {
		c.spent = true
		cs := CoinSpend{AllowanceID: cp.oac.ID, Index: c.Index, Denom: c.Denom, CoinKey: c.key.PublicKey(),
			Proof: proofFor(cp.set.levels, c.Index), Payee: binding, Nonce: req.Nonce, Time: wall}
		raw, err := Sign1(c.key, nil, cs.encode(), aadCoin)
		if err != nil {
			return nil, err
		}
		spends = append(spends, raw)
	}
	return cbor.MustEncode([]any{uint64(packetTierS), cp.oacRaw, spends}), nil
}

// verifyCoinSpend checks one coin against its allowance (signature, Merkle
// membership, index range). Payee and server share it.
func verifyCoinSpend(oac *Allowance, raw []byte) (*CoinSpend, Code) {
	payload, err := peekPayload(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	cs, err := decodeCoinSpend(payload)
	if err != nil || cs.AllowanceID != oac.ID || cs.Index >= oac.MaxTx || cs.Denom == 0 {
		return nil, ErrMalformed
	}
	if _, _, err := Open1(raw, aadCoin, fixedKey(cs.CoinKey)); err != nil {
		return nil, ErrBadSignature
	}
	if !verifyProof(coinLeaf(cs.Index, cs.Denom, cs.CoinKey), cs.Index, cs.Proof, oac.CoinRoot) {
		return nil, ErrChain
	}
	return cs, OK
}

// acceptCoins is the Tier S branch of Payee.Accept.
func (p *Payee) acceptCoins(oac *Allowance, oacRaw []byte, item any, wall, now uint64) ([]byte, Code) {
	arr, ok := item.([]any)
	if !ok || len(arr) == 0 || len(arr) > MaxCoins {
		return nil, ErrMalformed
	}
	var spends []*CoinSpend
	var ids [][]byte
	var total uint64
	seen := map[uint64]bool{}
	for _, e := range arr {
		raw, ok := e.([]byte)
		if !ok {
			return nil, ErrMalformed
		}
		cs, code := verifyCoinSpend(oac, raw)
		if code != OK {
			return nil, code
		}
		if seen[cs.Index] || (len(spends) > 0 && cs.Nonce != spends[0].Nonce) {
			return nil, ErrMalformed
		}
		seen[cs.Index] = true
		id := cs.ID()
		spends, ids, total = append(spends, cs), append(ids, id[:]), total+cs.Denom
	}
	pid := taggedHash("bilyon/coinpay/v1", ids...)
	// Radar: a coin index seen before with a different spend is a TEE break.
	dup := 0
	for i, cs := range spends {
		if prior, ok := p.coins[oac.ID][cs.Index]; ok {
			if prior != Hash(ids[i]) {
				p.Evidence = append(p.Evidence, Evidence{Kind: ErrEquivocation, OAC: oacRaw, B: arr[i].([]byte)})
				return p.receipt(pid, ErrEquivocation, wall), ErrEquivocation
			}
			dup++
		}
	}
	if dup == len(spends) { // idempotent retransmission
		return p.receipt(pid, OK, wall), OK
	}
	if spends[0].Payee != PayeeBinding(p.cert.DeviceKey, p.cert.Account) {
		return p.receipt(pid, ErrWrongPayee, wall), ErrWrongPayee
	}
	pr, ok := p.pending[spends[0].Nonce]
	switch {
	case !ok || now > pr.expires:
		return p.receipt(pid, ErrNonce, wall), ErrNonce
	case pr.req.Currency != oac.Currency:
		return p.receipt(pid, ErrCurrency, wall), ErrCurrency
	case total != pr.req.Amount:
		return p.receipt(pid, ErrAmountMismatch, wall), ErrAmountMismatch
	case total > oac.TxMax:
		return p.receipt(pid, ErrLimit, wall), ErrLimit
	}
	delete(p.pending, spends[0].Nonce)
	if p.coins[oac.ID] == nil {
		p.coins[oac.ID] = map[uint64]Hash{}
	}
	for i, cs := range spends {
		p.coins[oac.ID][cs.Index] = Hash(ids[i])
	}
	p.Claims = append(p.Claims, cbor.MustEncode([]any{uint64(packetTierS), oacRaw, arr}))
	return p.receipt(pid, OK, wall), OK
}
