package offline

import (
	"errors"

	"github.com/bil1234n/bilyon/reference/internal/cbor"
)

// Packet versions (first element of the CBOR array sent payer -> payee).
const (
	packetTierK = 1 // [1, OAC, OST]
	packetTierS = 2 // [2, OAC, [CoinSpend...]]
)

type walStatus uint8

const (
	// walReserved: chain state advanced, token not yet signed. The token can
	// only leave the device after walSigned is durable, so a reserved entry
	// found at recovery was never transmitted and is rolled back.
	walReserved walStatus = iota + 1
	// walSigned: signed and possibly transmitted. In doubt until a receipt
	// arrives; always counted as spent.
	walSigned
	walDelivered // OK receipt from payee
	walRejected  // payee-signed rejection; refunded at sync
)

type walEntry struct {
	Token    SpendToken
	PayeeKey []byte
	COSE     []byte
	Receipt  []byte
	Status   walStatus
}

// Disk models the wallet's durable store. Write must be atomic (an SQLite
// transaction or write-to-temp + rename in production), and the store is
// excluded from device backups so a restore cannot roll the chain back.
type Disk struct{ entries []walEntry }

func (d *Disk) write(entries []walEntry) { d.entries = append([]walEntry(nil), entries...) }

// Wallet is the payer side of a Tier K allowance.
type Wallet struct {
	oacRaw  []byte
	oac     *Allowance
	key     Signer
	trust   TrustStore
	disk    *Disk
	entries []walEntry
	Clock   TimeFloor

	// crashAfterReserve simulates process death between the durable reserve
	// and the signature (test hook).
	crashAfterReserve bool
}

// ErrCrash is returned by the crash-injection hook.
var ErrCrash = errors.New("offline: simulated crash")

// OpenWallet loads (or recovers) a wallet from disk. Trailing reserved
// entries are rolled back: they were never signed, so nobody holds them.
func OpenWallet(oacRaw []byte, key Signer, trust TrustStore, disk *Disk) (*Wallet, error) {
	oac, err := openAllowance(oacRaw, trust)
	if err != nil {
		return nil, err
	}
	if oac.Tier != TierK || string(oac.DeviceKey) != string(key.PublicKey()) {
		return nil, errors.New("allowance is not a Tier K allowance for this key")
	}
	entries := append([]walEntry(nil), disk.entries...)
	for len(entries) > 0 && entries[len(entries)-1].Status == walReserved {
		entries = entries[:len(entries)-1]
	}
	disk.write(entries)
	w := &Wallet{oacRaw: oacRaw, oac: oac, key: key, trust: trust, disk: disk, entries: entries}
	w.Clock.Observe(oac.IssuedAt)
	return w, nil
}

func (w *Wallet) head() (seq, cum uint64, prev Hash) {
	if len(w.entries) == 0 {
		return 0, 0, w.oac.Anchor
	}
	last := w.entries[len(w.entries)-1].Token
	return last.Seq, last.Cumulative, last.ID()
}

// Remaining is the offline balance still spendable from this allowance.
func (w *Wallet) Remaining() uint64 {
	_, cum, _ := w.head()
	return w.oac.Amount - cum
}

// Pay verifies a payee's signed request and returns the payment packet.
// Order of effects: verify -> durable reserve -> biometric-gated sign ->
// durable signed -> transmit. See RFC 0001 §3.A.3.
func (w *Wallet) Pay(certRaw, reqRaw []byte, wall uint64) ([]byte, *SpendToken, error) {
	cert, req, now, err := verifyRequest(w.trust, &w.Clock, certRaw, reqRaw, wall)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case req.Currency != w.oac.Currency:
		return nil, nil, ErrCurrency
	case now < w.oac.NotBefore:
		return nil, nil, ErrNotYetValid
	case now > w.oac.Expiry:
		return nil, nil, ErrExpired
	}
	seq, cum, prev := w.head()
	if req.Amount == 0 || req.Amount > w.oac.TxMax || cum+req.Amount > w.oac.Amount || seq+1 > w.oac.MaxTx {
		return nil, nil, ErrLimit
	}
	tok := SpendToken{AllowanceID: w.oac.ID, Seq: seq + 1, Prev: prev, Amount: req.Amount,
		Cumulative: cum + req.Amount, Payee: PayeeBinding(cert.DeviceKey, cert.Account),
		Nonce: req.Nonce, Time: wall, Ref: req.Ref}

	// Phase 1: durable reserve. From here the seq is taken.
	w.entries = append(w.entries, walEntry{Token: tok, PayeeKey: cert.DeviceKey, Status: walReserved})
	w.disk.write(w.entries)
	if w.crashAfterReserve {
		return nil, nil, ErrCrash
	}

	// Phase 2: sign (Secure Enclave / StrongBox, biometric prompt).
	cose, err := Sign1(w.key, nil, tok.encode(), aadToken)
	if err != nil { // user cancelled: nothing left the device, roll back
		w.entries = w.entries[:len(w.entries)-1]
		w.disk.write(w.entries)
		return nil, nil, err
	}

	// Phase 3: durable signed, then release to the radio.
	last := &w.entries[len(w.entries)-1]
	last.COSE, last.Status = cose, walSigned
	w.disk.write(w.entries)
	return w.packet(cose), &tok, nil
}

// verifyRequest authenticates the payee certificate and its signed request,
// so the confirmation UI can show a verified name and the exact amount.
func verifyRequest(trust TrustStore, clock *TimeFloor, certRaw, reqRaw []byte, wall uint64) (*PayeeCert, *PaymentRequest, uint64, error) {
	cert, err := openPayeeCert(certRaw, trust)
	if err != nil {
		return nil, nil, 0, err
	}
	clock.Observe(cert.IssuedAt)
	now := clock.Now(wall)
	if now > cert.Expiry {
		return nil, nil, 0, ErrExpired
	}
	payload, _, err := Open1(reqRaw, aadRequest, fixedKey(cert.DeviceKey))
	if err != nil {
		return nil, nil, 0, ErrBadSignature
	}
	req, err := decodeRequest(payload)
	if err != nil {
		return nil, nil, 0, err
	}
	return cert, req, now, nil
}

func (w *Wallet) packet(cose []byte) []byte {
	return cbor.MustEncode([]any{uint64(packetTierK), w.oacRaw, cose})
}

// Retransmit returns the byte-identical packet for an in-doubt token, so a
// payee that already stored it answers with the same receipt.
func (w *Wallet) Retransmit(seq uint64) ([]byte, error) {
	if seq == 0 || seq > uint64(len(w.entries)) || w.entries[seq-1].Status < walSigned {
		return nil, errors.New("no signed token at this seq")
	}
	return w.packet(w.entries[seq-1].COSE), nil
}

// InDoubt lists seqs that are signed but unacknowledged.
func (w *Wallet) InDoubt() []uint64 {
	var out []uint64
	for _, e := range w.entries {
		if e.Status == walSigned {
			out = append(out, e.Token.Seq)
		}
	}
	return out
}

// AcceptReceipt verifies the payee's receipt for seq and records it.
func (w *Wallet) AcceptReceipt(seq uint64, receiptRaw []byte) (Code, error) {
	if seq == 0 || seq > uint64(len(w.entries)) {
		return 0, errors.New("unknown seq")
	}
	e := &w.entries[seq-1]
	payload, _, err := Open1(receiptRaw, aadReceipt, fixedKey(e.PayeeKey))
	if err != nil {
		return 0, ErrBadSignature
	}
	rc, err := decodeReceipt(payload)
	if err != nil {
		return 0, err
	}
	if rc.TokenID != e.Token.ID() {
		return 0, ErrChain
	}
	e.Receipt = receiptRaw
	if rc.Status == OK {
		e.Status = walDelivered
	} else {
		e.Status = walRejected
	}
	w.disk.write(w.entries)
	return rc.Status, nil
}

// SyncLog returns every signed packet for upload on reconnect.
func (w *Wallet) SyncLog() [][]byte {
	var out [][]byte
	for _, e := range w.entries {
		if e.Status >= walSigned {
			out = append(out, w.packet(e.COSE))
		}
	}
	return out
}

// Close signs the final statement that lets the server release the unspent
// reserve before expiry. Any later token with a higher seq is proof of fraud.
func (w *Wallet) Close() ([]byte, error) {
	seq, cum, last := w.head()
	c := Closing{AllowanceID: w.oac.ID, FinalSeq: seq, FinalCum: cum, LastTokenID: last}
	return Sign1(w.key, nil, c.encode(), aadClosing)
}
