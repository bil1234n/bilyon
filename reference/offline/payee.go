package offline

import (
	"crypto/rand"
	"errors"

	"github.com/bil1234n/bilyon/reference/internal/cbor"
)

// RequestTTL bounds how long a payee nonce stays redeemable (seconds).
const RequestTTL = 120

// Evidence is a non-repudiable fraud proof: two artefacts signed by the same
// payer key that no honest wallet can produce together.
type Evidence struct {
	Kind Code   // ErrEquivocation or ErrInconsistent
	OAC  []byte // allowance certificate
	A, B []byte // the two conflicting COSE artefacts
}

type pendingRequest struct {
	req     PaymentRequest
	expires uint64
}

type heldToken struct {
	tok     SpendToken
	cose    []byte
	receipt []byte
}

// Payee verifies and stores offline payments. All checks are local: no
// network, no server round trip.
type Payee struct {
	certRaw []byte
	cert    *PayeeCert
	key     Signer
	trust   TrustStore
	Clock   TimeFloor
	Revoked map[ID128]bool // CRL snapshot (allowance IDs) from last sync

	pending map[ID128]pendingRequest
	held    map[ID128]map[uint64]*heldToken // aid -> seq -> token (double-spend radar)
	coins   map[ID128]map[uint64]Hash       // aid -> coin index -> spend hash
	// Claims are accepted packets awaiting upload; Evidence awaits upload.
	Claims   [][]byte
	Evidence []Evidence
}

// NewPayee creates a payee from its issuer-signed certificate and device key.
func NewPayee(certRaw []byte, key Signer, trust TrustStore) (*Payee, error) {
	cert, err := openPayeeCert(certRaw, trust)
	if err != nil {
		return nil, err
	}
	if string(cert.DeviceKey) != string(key.PublicKey()) {
		return nil, errors.New("certificate is not for this device key")
	}
	p := &Payee{certRaw: certRaw, cert: cert, key: key, trust: trust, Revoked: map[ID128]bool{},
		pending: map[ID128]pendingRequest{}, held: map[ID128]map[uint64]*heldToken{},
		coins: map[ID128]map[uint64]Hash{}}
	p.Clock.Observe(cert.IssuedAt)
	return p, nil
}

// Cert returns the payee certificate to send alongside a request.
func (p *Payee) Cert() []byte { return p.certRaw }

// Request creates a signed payment request with a fresh single-use nonce.
func (p *Payee) Request(amount uint64, currency string, ref []byte, wall uint64) ([]byte, error) {
	var nonce ID128
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	req := PaymentRequest{Nonce: nonce, Amount: amount, Currency: currency, Ref: ref, PayeeTime: wall}
	raw, err := Sign1(p.key, nil, req.encode(), aadRequest)
	if err != nil {
		return nil, err
	}
	p.pending[nonce] = pendingRequest{req: req, expires: p.Clock.Now(wall) + RequestTTL}
	return raw, nil
}

func (p *Payee) receipt(tid Hash, code Code, wall uint64) []byte {
	rc := Receipt{TokenID: tid, Status: code, PayeeTime: wall}
	raw, err := Sign1(p.key, nil, rc.encode(), aadReceipt)
	if err != nil {
		return nil
	}
	return raw
}

// Accept runs Algorithm A.4 on a payment packet and returns a signed receipt
// (nil if the packet is too malformed to identify a token) and the outcome.
func (p *Payee) Accept(packet []byte, wall uint64) ([]byte, Code) {
	v, err := cbor.Decode(packet)
	arr, ok := v.([]any)
	if err != nil || !ok || len(arr) != 3 {
		return nil, ErrMalformed
	}
	kind, _ := arr[0].(uint64)
	oacRaw, ok := arr[1].([]byte)
	if !ok {
		return nil, ErrMalformed
	}
	oac, err := openAllowance(oacRaw, p.trust)
	if err != nil {
		return nil, asCode(err)
	}
	p.Clock.Observe(oac.IssuedAt) // signed time beacon
	now := p.Clock.Now(wall)
	switch {
	case now < oac.NotBefore:
		return nil, ErrNotYetValid
	case now > oac.Expiry:
		return nil, ErrExpired
	case p.Revoked[oac.ID]:
		return nil, ErrRevoked
	}
	if kind == packetTierS && oac.Tier == TierS {
		return p.acceptCoins(oac, oacRaw, arr[2], wall, now)
	}
	tokRaw, ok := arr[2].([]byte)
	if kind != packetTierK || oac.Tier != TierK || !ok {
		return nil, ErrMalformed
	}
	payload, _, err := Open1(tokRaw, aadToken, fixedKey(oac.DeviceKey))
	if err != nil {
		return nil, ErrBadSignature
	}
	tok, err := decodeToken(payload)
	if err != nil || tok.AllowanceID != oac.ID {
		return nil, ErrMalformed
	}
	tid := tok.ID()

	// Idempotent retransmission and same-seq equivocation.
	if prior, seen := p.held[oac.ID][tok.Seq]; seen {
		if prior.tok.ID() == tid {
			return prior.receipt, OK
		}
		p.Evidence = append(p.Evidence, Evidence{Kind: ErrEquivocation, OAC: oacRaw, A: prior.cose, B: tokRaw})
		return p.receipt(tid, ErrEquivocation, wall), ErrEquivocation
	}
	if code := p.checkToken(oac, tok, now); code != OK {
		return p.receipt(tid, code, wall), code
	}
	if code, other := p.checkAgainstHeld(oac.ID, tok); code != OK {
		p.Evidence = append(p.Evidence, Evidence{Kind: code, OAC: oacRaw, A: other, B: tokRaw})
		return p.receipt(tid, code, wall), code
	}

	delete(p.pending, tok.Nonce) // consume the nonce
	rc := p.receipt(tid, OK, wall)
	if p.held[oac.ID] == nil {
		p.held[oac.ID] = map[uint64]*heldToken{}
	}
	p.held[oac.ID][tok.Seq] = &heldToken{tok: *tok, cose: tokRaw, receipt: rc}
	p.Claims = append(p.Claims, packet)
	return rc, OK
}

// checkToken: payee binding, nonce, amount and allowance limits.
func (p *Payee) checkToken(oac *Allowance, tok *SpendToken, now uint64) Code {
	if tok.Payee != PayeeBinding(p.cert.DeviceKey, p.cert.Account) {
		return ErrWrongPayee
	}
	pr, ok := p.pending[tok.Nonce]
	if !ok || now > pr.expires {
		return ErrNonce
	}
	if pr.req.Currency != oac.Currency {
		return ErrCurrency
	}
	if tok.Amount != pr.req.Amount || string(tok.Ref) != string(pr.req.Ref) {
		return ErrAmountMismatch
	}
	if tok.Amount == 0 || tok.Amount > oac.TxMax || tok.Seq == 0 || tok.Seq > oac.MaxTx ||
		tok.Cumulative > oac.Amount {
		return ErrLimit
	}
	// Every token moves at least one minor unit, so cum >= amount + (seq-1).
	if tok.Cumulative < tok.Amount+(tok.Seq-1) {
		return ErrChain
	}
	if tok.Seq == 1 && (tok.Prev != oac.Anchor || tok.Cumulative != tok.Amount) {
		return ErrChain
	}
	return OK
}

// chainConsistent reports whether two tokens of one allowance (a.Seq <
// b.Seq) can both come from an honest wallet.
func chainConsistent(a, b *SpendToken) bool {
	if b.Seq == a.Seq+1 {
		return b.Prev == a.ID() && b.Cumulative == a.Cumulative+b.Amount
	}
	return b.Cumulative >= a.Cumulative+b.Amount+(b.Seq-a.Seq-1)
}

func (p *Payee) checkAgainstHeld(aid ID128, tok *SpendToken) (Code, []byte) {
	for _, h := range p.held[aid] {
		a, b := &h.tok, tok
		if a.Seq > b.Seq {
			a, b = b, a
		}
		if !chainConsistent(a, b) {
			return ErrInconsistent, h.cose
		}
	}
	return OK, nil
}
