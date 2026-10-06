package offline

import (
	"encoding/hex"
	"errors"

	"github.com/bil1234n/bilyon/reference/internal/cbor"
)

// GuaranteeFund is the ledger account that pays good-faith payees when an
// allowance is overspent; it holds a receivable against the payer.
const GuaranteeFund = "offline:guarantee_fund"

func reserveAccount(aid ID128) string { return "offline:reserve:" + hex.EncodeToString(aid[:]) }

// Posting is a balanced ledger movement emitted by reconciliation.
type Posting struct {
	Debit, Credit string
	Amount        uint64
	Ref           Hash
	Memo          string
}

type payeeRecord struct {
	account   string
	deviceKey []byte
}

type book struct {
	oac        *Allowance
	payer      string
	cap        uint64 // still payable from the reserve (Amount, lowered by a closing)
	paid       uint64
	guaranteed uint64
	tokens     map[uint64]*heldToken // first-presented token per seq
	coins      map[uint64]Hash
	settled    map[Hash]bool // token / coin-spend IDs already paid
	closing    *Closing
	closingRaw []byte
	fraud      bool
	released   bool
}

// Reconciler is the server side of Algorithm A.5. Anyone may upload a packet
// (payee claim or payer log); credit always goes to the payee the token is
// bound to, so upload order never changes who gets paid.
type Reconciler struct {
	trust        TrustStore
	Now          func() uint64
	ClaimWindow  uint64 // seconds after allowance expiry
	GuaranteeCap uint64 // per-allowance cap on guarantee-fund payouts
	payees       map[Hash]payeeRecord
	payers       map[ID128]string
	books        map[ID128]*book
	voided       map[Hash]bool
	Postings     []Posting
	Proofs       []Evidence
	Revoked      map[ID128]bool // published to devices as CRL deltas
}

// NewReconciler creates an empty reconciler.
func NewReconciler(trust TrustStore, now func() uint64, claimWindow, guaranteeCap uint64) *Reconciler {
	return &Reconciler{trust: trust, Now: now, ClaimWindow: claimWindow, GuaranteeCap: guaranteeCap,
		payees: map[Hash]payeeRecord{}, payers: map[ID128]string{}, books: map[ID128]*book{},
		voided: map[Hash]bool{}, Revoked: map[ID128]bool{}}
}

// RegisterPayee records a payee certificate's binding -> account mapping.
func (r *Reconciler) RegisterPayee(certRaw []byte, account string) error {
	cert, err := openPayeeCert(certRaw, r.trust)
	if err != nil {
		return err
	}
	r.payees[PayeeBinding(cert.DeviceKey, cert.Account)] = payeeRecord{account, cert.DeviceKey}
	return nil
}

// RegisterPayer maps an account pseudonym to the payer's ledger account.
func (r *Reconciler) RegisterPayer(pseudonym ID128, account string) { r.payers[pseudonym] = account }

func (r *Reconciler) bookFor(oac *Allowance) *book {
	b, ok := r.books[oac.ID]
	if !ok {
		b = &book{oac: oac, payer: r.payers[oac.Account], cap: oac.Amount,
			tokens: map[uint64]*heldToken{}, coins: map[uint64]Hash{}, settled: map[Hash]bool{}}
		r.books[oac.ID] = b
	}
	return b
}

// Submit processes one uploaded packet. receiptRaw is optional: a payer
// uploading a token the payee rejected attaches the payee-signed rejection,
// which voids the token instead of paying it.
func (r *Reconciler) Submit(packet, receiptRaw []byte) Code {
	v, err := cbor.Decode(packet)
	arr, ok := v.([]any)
	if err != nil || !ok || len(arr) != 3 {
		return ErrMalformed
	}
	kind, _ := arr[0].(uint64)
	oacRaw, ok := arr[1].([]byte)
	if !ok {
		return ErrMalformed
	}
	oac, err := openAllowance(oacRaw, r.trust)
	if err != nil {
		return asCode(err)
	}
	if r.Now() > oac.Expiry+r.ClaimWindow {
		return ErrExpired // late claims go to manual dispute
	}
	b := r.bookFor(oac)
	switch {
	case kind == packetTierK && oac.Tier == TierK:
		raw, ok := arr[2].([]byte)
		if !ok {
			return ErrMalformed
		}
		return r.submitToken(b, oacRaw, raw, receiptRaw)
	case kind == packetTierS && oac.Tier == TierS:
		items, ok := arr[2].([]any)
		if !ok {
			return ErrMalformed
		}
		return r.submitCoins(b, oacRaw, items)
	}
	return ErrMalformed
}

func (r *Reconciler) submitToken(b *book, oacRaw, raw, receiptRaw []byte) Code {
	oac := b.oac
	payload, _, err := Open1(raw, aadToken, fixedKey(oac.DeviceKey))
	if err != nil {
		return ErrBadSignature
	}
	tok, err := decodeToken(payload)
	if err != nil || tok.AllowanceID != oac.ID {
		return ErrMalformed
	}
	// Limits a payee can check offline: violations are not guaranteed.
	if tok.Amount == 0 || tok.Amount > oac.TxMax || tok.Seq == 0 || tok.Seq > oac.MaxTx ||
		tok.Cumulative > oac.Amount || tok.Cumulative < tok.Amount+(tok.Seq-1) ||
		(tok.Seq == 1 && (tok.Prev != oac.Anchor || tok.Cumulative != tok.Amount)) {
		return ErrLimit
	}
	payee, ok := r.payees[tok.Payee]
	if !ok {
		return ErrWrongPayee
	}
	tid := tok.ID()
	if receiptRaw != nil {
		if p, _, err := Open1(receiptRaw, aadReceipt, fixedKey(payee.deviceKey)); err == nil {
			if rc, err := decodeReceipt(p); err == nil && rc.TokenID == tid && rc.Status != OK {
				r.voided[tid] = true
			}
		}
	}
	if r.voided[tid] {
		return ErrVoided
	}
	if b.settled[tid] {
		return ErrDuplicate
	}
	if prior, seen := b.tokens[tok.Seq]; seen {
		r.flag(b, Evidence{Kind: ErrEquivocation, OAC: oacRaw, A: prior.cose, B: raw})
	} else {
		for _, h := range b.tokens {
			x, y := &h.tok, tok
			if x.Seq > y.Seq {
				x, y = y, x
			}
			if !chainConsistent(x, y) {
				r.flag(b, Evidence{Kind: ErrInconsistent, OAC: oacRaw, A: h.cose, B: raw})
				break
			}
		}
		b.tokens[tok.Seq] = &heldToken{tok: *tok, cose: raw}
	}
	if b.closing != nil && tok.Seq > b.closing.FinalSeq {
		r.flag(b, Evidence{Kind: ErrInconsistent, OAC: oacRaw, A: b.closingRaw, B: raw})
	}
	return r.pay(b, payee.account, tok.Amount, tid)
}

func (r *Reconciler) submitCoins(b *book, oacRaw []byte, items []any) Code {
	type verified struct {
		cs  *CoinSpend
		raw []byte
	}
	var batch []verified
	for _, it := range items {
		raw, ok := it.([]byte)
		if !ok {
			return ErrMalformed
		}
		cs, code := verifyCoinSpend(b.oac, raw)
		if code != OK {
			return code
		}
		if _, ok := r.payees[cs.Payee]; !ok {
			return ErrWrongPayee
		}
		batch = append(batch, verified{cs, raw})
	}
	result := ErrDuplicate
	for _, v := range batch {
		id := v.cs.ID()
		if b.settled[id] {
			continue
		}
		if prior, seen := b.coins[v.cs.Index]; seen {
			if prior != id { // a single-use key signed twice: TEE compromise
				r.flag(b, Evidence{Kind: ErrEquivocation, OAC: oacRaw, B: v.raw})
				result = r.pay(b, r.payees[v.cs.Payee].account, v.cs.Denom, id)
			}
			continue
		}
		b.coins[v.cs.Index] = id
		if code := r.pay(b, r.payees[v.cs.Payee].account, v.cs.Denom, id); code != OK {
			return code
		}
		result = OK
	}
	return result
}

func (r *Reconciler) flag(b *book, e Evidence) {
	b.fraud = true
	r.Revoked[b.oac.ID] = true
	r.Proofs = append(r.Proofs, e)
}

// pay settles from the reserve while it lasts. An honest wallet can never
// exceed its reserve, so overflow is itself proof of overspend: the shortfall
// is paid to the good-faith payee by the guarantee fund and charged to the
// payer as a receivable. All-or-nothing: a claim beyond the guarantee cap
// moves no money and goes to manual dispute.
func (r *Reconciler) pay(b *book, payee string, amount uint64, ref Hash) Code {
	fromReserve := min(amount, b.cap-b.paid)
	shortfall := amount - fromReserve
	if shortfall > 0 {
		b.fraud, r.Revoked[b.oac.ID] = true, true
		if b.guaranteed+shortfall > r.GuaranteeCap {
			return ErrLimit
		}
	}
	b.settled[ref] = true
	if fromReserve > 0 {
		b.paid += fromReserve
		r.Postings = append(r.Postings, Posting{reserveAccount(b.oac.ID), payee, fromReserve, ref, "offline settle"})
	}
	if shortfall > 0 {
		b.guaranteed += shortfall
		r.Postings = append(r.Postings,
			Posting{GuaranteeFund, payee, shortfall, ref, "guarantee payout"},
			Posting{b.payer, GuaranteeFund, shortfall, ref, "overspend clawback"})
	}
	return OK
}

// SubmitClosing applies a payer's signed closing statement and releases the
// unspent reserve early. The reserve keeps FinalCum for outstanding claims.
func (r *Reconciler) SubmitClosing(oacRaw, closingRaw []byte) error {
	oac, err := openAllowance(oacRaw, r.trust)
	if err != nil {
		return err
	}
	payload, _, err := Open1(closingRaw, aadClosing, fixedKey(oac.DeviceKey))
	if err != nil {
		return ErrBadSignature
	}
	c, err := decodeClosing(payload)
	if err != nil || c.AllowanceID != oac.ID || c.FinalCum > oac.Amount {
		return ErrMalformed
	}
	b := r.bookFor(oac)
	if b.closing != nil || b.released {
		return errors.New("allowance already closed")
	}
	for seq, h := range b.tokens {
		if seq > c.FinalSeq || (seq == c.FinalSeq && (h.tok.ID() != c.LastTokenID || h.tok.Cumulative != c.FinalCum)) {
			r.flag(b, Evidence{Kind: ErrInconsistent, OAC: oacRaw, A: closingRaw, B: h.cose})
		}
	}
	b.closing, b.closingRaw = c, closingRaw
	if b.fraud {
		return nil // no early release for an allowance under investigation
	}
	if release := oac.Amount - c.FinalCum; release > 0 {
		r.Postings = append(r.Postings, Posting{reserveAccount(oac.ID), b.payer, release, c.LastTokenID, "early release"})
	}
	b.cap = c.FinalCum
	return nil
}

// Expire releases what is left of each reserve once its claim window ends:
// to the payer normally, to the guarantee fund (offsetting the clawback
// receivable) if the allowance was overspent.
func (r *Reconciler) Expire() {
	now := r.Now()
	for _, b := range r.books {
		if b.released || now <= b.oac.Expiry+r.ClaimWindow {
			continue
		}
		b.released = true
		left := b.cap - b.paid
		if left == 0 {
			continue
		}
		to := b.payer
		if b.fraud {
			to = GuaranteeFund
		}
		r.Postings = append(r.Postings, Posting{reserveAccount(b.oac.ID), to, left, Hash{}, "reserve release"})
	}
}
