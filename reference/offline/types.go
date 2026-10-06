package offline

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/bil1234n/bilyon/reference/internal/cbor"
)

// Tier is the enforcement class of an offline allowance (RFC 0001 §3.A.1).
type Tier uint64

const (
	// TierK: hardware-bound key, app-enforced counter; overspend is detected
	// and attributed at sync, exposure bounded by allowance limits.
	TierK Tier = 1
	// TierS: value carried by single-use hardware keys (coins); overspend
	// requires breaking the TEE.
	TierS Tier = 2
	// TierH: secure-element applet enforces balance (not modelled here).
	TierH Tier = 3
)

// Domain-separation labels used as COSE external AAD and hash prefixes.
const (
	aadAllowance = "bilyon/oac/v1"
	aadPayeeCert = "bilyon/pcert/v1"
	aadRequest   = "bilyon/preq/v1"
	aadToken     = "bilyon/ost/v1"
	aadReceipt   = "bilyon/rcpt/v1"
	aadClosing   = "bilyon/close/v1"
	aadCoin      = "bilyon/coin/v1"
)

// Code is a verification outcome; non-zero codes are errors and are carried
// in receipts and sync responses.
type Code uint64

// Verification outcomes (RFC 0001 §3.A error table).
const (
	OK Code = iota
	ErrMalformed
	ErrUnknownIssuer
	ErrBadSignature
	ErrExpired
	ErrNotYetValid
	ErrRevoked
	ErrWrongPayee
	ErrNonce
	ErrAmountMismatch
	ErrLimit
	ErrChain
	ErrEquivocation
	ErrInconsistent
	ErrCurrency
	ErrDuplicate
	ErrVoided
)

var codeNames = [...]string{"OK", "MALFORMED", "UNKNOWN_ISSUER", "BAD_SIGNATURE", "EXPIRED",
	"NOT_YET_VALID", "REVOKED", "WRONG_PAYEE", "NONCE", "AMOUNT_MISMATCH", "LIMIT", "CHAIN",
	"EQUIVOCATION", "INCONSISTENT", "CURRENCY", "DUPLICATE", "VOIDED"}

func (c Code) Error() string {
	if int(c) < len(codeNames) {
		return codeNames[c]
	}
	return fmt.Sprintf("CODE_%d", uint64(c))
}

func asCode(err error) Code {
	if c, ok := err.(Code); ok {
		return c
	}
	return ErrMalformed
}

// Hash is a SHA-256 digest.
type Hash [32]byte

// ID128 is a 16-byte identifier (UUIDv7 bytes, nonces, account pseudonyms).
type ID128 [16]byte

func taggedHash(label string, parts ...[]byte) Hash {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	for _, p := range parts {
		h.Write(p)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// AnchorFor is the chain anchor that the first token of an allowance links to.
func AnchorFor(aid ID128) Hash { return taggedHash("bilyon/anchor/v1", aid[:]) }

// PayeeBinding commits a token to one payee device and account pseudonym.
func PayeeBinding(payeeKey []byte, payeeAcct ID128) Hash {
	return taggedHash("bilyon/payee/v1", payeeKey, payeeAcct[:])
}

// Allowance is the Offline Allowance Certificate payload (OAC), signed by the
// issuer HSM after the amount has been reserved on the ledger.
type Allowance struct {
	ID        ID128  // 2
	DeviceKey []byte // 3: Tier K spend key / Tier S receipt key, 33 bytes
	Currency  string // 4: ISO 4217
	Amount    uint64 // 5: minor units reserved on the ledger
	TxMax     uint64 // 6: max per-token amount
	NotBefore uint64 // 7: epoch seconds
	Expiry    uint64 // 8: epoch seconds
	Tier      Tier   // 9
	Anchor    Hash   // 10: AnchorFor(ID)
	MaxTx     uint64 // 11: max token count
	Account   ID128  // 12: payer account pseudonym
	IssuedAt  uint64 // 13: server time, doubles as a signed time beacon
	CRLEpoch  uint64 // 14: revocation-list epoch at issuance
	CoinRoot  []byte // 15: Tier S only, Merkle root over coin leaves
}

// PayeeCert binds a payee device key to a verified display name.
type PayeeCert struct {
	Account   ID128  // 2
	DeviceKey []byte // 3
	Name      string // 4
	MCC       uint64 // 5: merchant category code, 0 for individuals
	IssuedAt  uint64 // 6
	Expiry    uint64 // 7
}

// PaymentRequest is signed by the payee and fixes amount, currency and nonce.
type PaymentRequest struct {
	Nonce     ID128  // 2
	Amount    uint64 // 3
	Currency  string // 4
	Ref       []byte // 5: merchant reference (<= 32 bytes)
	PayeeTime uint64 // 6: advisory
}

// SpendToken is the Offline Spend Token (OST) signed by the payer device.
type SpendToken struct {
	AllowanceID ID128  // 2
	Seq         uint64 // 3: 1..MaxTx, strictly +1 per token
	Prev        Hash   // 4: TokenID of seq-1, or the allowance anchor
	Amount      uint64 // 5
	Cumulative  uint64 // 6: total spent including this token
	Payee       Hash   // 7: PayeeBinding
	Nonce       ID128  // 8: from the PaymentRequest
	Time        uint64 // 9: payer clock, advisory only
	Ref         []byte // 10
}

// Receipt is the payee's signed acknowledgement of a token.
type Receipt struct {
	TokenID   Hash   // 2
	Status    Code   // 3
	PayeeTime uint64 // 4
}

// Closing is the payer's signed final statement for an allowance.
type Closing struct {
	AllowanceID ID128  // 2
	FinalSeq    uint64 // 3
	FinalCum    uint64 // 4
	LastTokenID Hash   // 5
}

const version = 1

func (a *Allowance) encode() []byte {
	m := cbor.Map{1: uint64(version), 2: a.ID[:], 3: a.DeviceKey, 4: a.Currency, 5: a.Amount,
		6: a.TxMax, 7: a.NotBefore, 8: a.Expiry, 9: uint64(a.Tier), 10: a.Anchor[:], 11: a.MaxTx,
		12: a.Account[:], 13: a.IssuedAt, 14: a.CRLEpoch}
	if a.Tier == TierS {
		m[15] = a.CoinRoot
	}
	return cbor.MustEncode(m)
}

func (p *PayeeCert) encode() []byte {
	return cbor.MustEncode(cbor.Map{1: uint64(version), 2: p.Account[:], 3: p.DeviceKey, 4: p.Name,
		5: p.MCC, 6: p.IssuedAt, 7: p.Expiry})
}

func (r *PaymentRequest) encode() []byte {
	return cbor.MustEncode(cbor.Map{1: uint64(version), 2: r.Nonce[:], 3: r.Amount, 4: r.Currency,
		5: r.Ref, 6: r.PayeeTime})
}

func (t *SpendToken) encode() []byte {
	return cbor.MustEncode(cbor.Map{1: uint64(version), 2: t.AllowanceID[:], 3: t.Seq, 4: t.Prev[:],
		5: t.Amount, 6: t.Cumulative, 7: t.Payee[:], 8: t.Nonce[:], 9: t.Time, 10: t.Ref})
}

// ID is the token identifier: a hash of the payload only. Excluding the
// signature makes the ID immune to signature malleability, so a payee cannot
// claim one token twice by re-encoding its signature.
func (t *SpendToken) ID() Hash { return taggedHash("bilyon/tid/v1", t.encode()) }

func (r *Receipt) encode() []byte {
	return cbor.MustEncode(cbor.Map{1: uint64(version), 2: r.TokenID[:], 3: uint64(r.Status), 4: r.PayeeTime})
}

func (c *Closing) encode() []byte {
	return cbor.MustEncode(cbor.Map{1: uint64(version), 2: c.AllowanceID[:], 3: c.FinalSeq,
		4: c.FinalCum, 5: c.LastTokenID[:]})
}

// fields is a strict accessor over a decoded payload map: unknown keys,
// missing keys and wrong types or sizes are all MALFORMED.
type fields struct {
	m   cbor.Map
	err error
}

func parseFields(payload []byte, allowed ...int64) *fields {
	v, err := cbor.Decode(payload)
	if err != nil {
		return &fields{err: ErrMalformed}
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return &fields{err: ErrMalformed}
	}
	permitted := map[int64]bool{1: true}
	for _, k := range allowed {
		permitted[k] = true
	}
	for k := range m {
		if !permitted[k] {
			return &fields{err: ErrMalformed}
		}
	}
	f := &fields{m: m}
	if f.uint(1) != version {
		f.err = ErrMalformed
	}
	return f
}

func (f *fields) uint(k int64) uint64 {
	v, ok := f.m[k].(uint64)
	if !ok && f.err == nil {
		f.err = ErrMalformed
	}
	return v
}

func (f *fields) bytes(k int64, minLen, maxLen int) []byte {
	v, ok := f.m[k].([]byte)
	if (!ok || len(v) < minLen || len(v) > maxLen) && f.err == nil {
		f.err = ErrMalformed
	}
	return v
}

func (f *fields) text(k int64, maxLen int) string {
	v, ok := f.m[k].(string)
	if (!ok || len(v) > maxLen) && f.err == nil {
		f.err = ErrMalformed
	}
	return v
}

func (f *fields) id(k int64) (out ID128)  { copy(out[:], f.bytes(k, 16, 16)); return }
func (f *fields) hash(k int64) (out Hash) { copy(out[:], f.bytes(k, 32, 32)); return }

func decodeAllowance(payload []byte) (*Allowance, error) {
	f := parseFields(payload, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
	if f.err != nil {
		return nil, f.err
	}
	a := &Allowance{ID: f.id(2), DeviceKey: f.bytes(3, 33, 33), Currency: f.text(4, 3),
		Amount: f.uint(5), TxMax: f.uint(6), NotBefore: f.uint(7), Expiry: f.uint(8),
		Tier: Tier(f.uint(9)), Anchor: f.hash(10), MaxTx: f.uint(11), Account: f.id(12),
		IssuedAt: f.uint(13), CRLEpoch: f.uint(14)}
	if a.Tier == TierS {
		a.CoinRoot = f.bytes(15, 32, 32)
	} else if _, present := f.m[15]; present {
		return nil, ErrMalformed
	}
	if f.err != nil || len(a.Currency) != 3 || a.Anchor != AnchorFor(a.ID) {
		return nil, ErrMalformed
	}
	return a, nil
}

func decodePayeeCert(payload []byte) (*PayeeCert, error) {
	f := parseFields(payload, 2, 3, 4, 5, 6, 7)
	if f.err != nil {
		return nil, f.err
	}
	p := &PayeeCert{Account: f.id(2), DeviceKey: f.bytes(3, 33, 33), Name: f.text(4, 64),
		MCC: f.uint(5), IssuedAt: f.uint(6), Expiry: f.uint(7)}
	return p, f.err
}

func decodeRequest(payload []byte) (*PaymentRequest, error) {
	f := parseFields(payload, 2, 3, 4, 5, 6)
	if f.err != nil {
		return nil, f.err
	}
	r := &PaymentRequest{Nonce: f.id(2), Amount: f.uint(3), Currency: f.text(4, 3),
		Ref: f.bytes(5, 0, 32), PayeeTime: f.uint(6)}
	return r, f.err
}

func decodeToken(payload []byte) (*SpendToken, error) {
	f := parseFields(payload, 2, 3, 4, 5, 6, 7, 8, 9, 10)
	if f.err != nil {
		return nil, f.err
	}
	t := &SpendToken{AllowanceID: f.id(2), Seq: f.uint(3), Prev: f.hash(4), Amount: f.uint(5),
		Cumulative: f.uint(6), Payee: f.hash(7), Nonce: f.id(8), Time: f.uint(9), Ref: f.bytes(10, 0, 32)}
	return t, f.err
}

func decodeReceipt(payload []byte) (*Receipt, error) {
	f := parseFields(payload, 2, 3, 4)
	if f.err != nil {
		return nil, f.err
	}
	r := &Receipt{TokenID: f.hash(2), Status: Code(f.uint(3)), PayeeTime: f.uint(4)}
	return r, f.err
}

func decodeClosing(payload []byte) (*Closing, error) {
	f := parseFields(payload, 2, 3, 4, 5)
	if f.err != nil {
		return nil, f.err
	}
	c := &Closing{AllowanceID: f.id(2), FinalSeq: f.uint(3), FinalCum: f.uint(4), LastTokenID: f.hash(5)}
	return c, f.err
}

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
