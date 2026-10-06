// Package txauth is the transaction authorisation of RFC 0001 §2.2.5: a
// COSE_Sign1 by the payer's hardware-bound K_dev (or K_gest within the
// gesture limit) over an intent's amount, currency, payee and quote. The
// server accepts a money movement only if those fields are byte-identical
// to the intent it holds (dynamic linking, PSD2 RTS Art. 5).
//
//	txauth = { 1 => 1, 2 => id16 (intent_id), 3 => minor (amount), 4 => currency,
//	           5 => h32 (payee_ref), 6 => id16 (server nonce), 7 => epoch,
//	           ? 8 => tstr (fx quote id), ? 9 => uint (gesture kind),
//	           ? 10 => uint (par_version) }
//
// The payload is deterministic CBOR and is decoded against this closed
// schema; the COSE kid is the 16-byte key id the device key was bound under.
package txauth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
)

// Protocol constants.
const (
	// Context is the external AAD: a signature over any other artefact type
	// cannot verify as a TxAuth.
	Context = "bilyon/txauth/v1"
	Version = 1
	// DropDomain tags the payee reference of a drop (§3.B.5), whose payee is
	// whoever grabs it: the payer signs "no particular payee" explicitly.
	DropDomain = "bilyon/drop/v1"
	// MaxQuoteIDLen bounds the FX quote id.
	MaxQuoteIDLen = 64
	// maxEpoch is 9999-12-31T23:59:59Z.
	maxEpoch = 253402300799
)

// Payload keys.
const (
	keyVersion = iota + 1
	keyIntent
	keyAmount
	keyCurrency
	keyPayee
	keyNonce
	keyEpoch
	keyQuote
	keyGesture
	keyPARVersion
)

// Gesture is the kinetic gesture kind (key 9); payments that are not
// gestures (to a handle, a QR code) omit it.
type Gesture uint64

// Gesture kinds.
const (
	GestureNone  Gesture = 0
	GestureFlick Gesture = 1
	GestureSplit Gesture = 2
	GestureGrab  Gesture = 3
)

// Errors.
var (
	ErrMalformed = errors.New("txauth: malformed transaction authorisation")
	ErrKeyID     = errors.New("txauth: kid is not a 16-byte key id")
)

var currencyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{2,7}$`)

// TxAuth is a decoded authorisation.
type TxAuth struct {
	IntentID   uuid.UUID
	Amount     int64 // minor units, > 0
	Currency   string
	PayeeRef   [32]byte
	Nonce      [16]byte  // issued by the server; single use
	SignedAt   time.Time // whole seconds
	QuoteID    string    // FX quote for a cross-currency payment, or empty
	Gesture    Gesture
	PARVersion uint64 // payee directory entry version the payer verified, or 0
}

func (t *TxAuth) validate() error {
	switch {
	case t.IntentID == uuid.Nil:
		return fmt.Errorf("%w: nil intent id", ErrMalformed)
	case t.Amount <= 0:
		return fmt.Errorf("%w: amount %d", ErrMalformed, t.Amount)
	case !currencyPattern.MatchString(t.Currency):
		return fmt.Errorf("%w: currency %q", ErrMalformed, t.Currency)
	case t.SignedAt.Unix() < 0 || t.SignedAt.Unix() > maxEpoch:
		return fmt.Errorf("%w: signing time %s", ErrMalformed, t.SignedAt)
	case len(t.QuoteID) > MaxQuoteIDLen:
		return fmt.Errorf("%w: quote id of %d bytes", ErrMalformed, len(t.QuoteID))
	case t.Gesture > GestureGrab:
		return fmt.Errorf("%w: gesture kind %d", ErrMalformed, t.Gesture)
	}
	return nil
}

// Encode returns the payload's deterministic CBOR.
func (t *TxAuth) Encode() ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	m := cbor.Map{
		int64(keyVersion): uint64(Version), int64(keyIntent): t.IntentID[:], int64(keyAmount): uint64(t.Amount),
		int64(keyCurrency): t.Currency, int64(keyPayee): t.PayeeRef[:], int64(keyNonce): t.Nonce[:],
		int64(keyEpoch): uint64(t.SignedAt.Unix()),
	}
	if t.QuoteID != "" {
		m[int64(keyQuote)] = t.QuoteID
	}
	if t.Gesture != GestureNone {
		m[int64(keyGesture)] = uint64(t.Gesture)
	}
	if t.PARVersion != 0 {
		m[int64(keyPARVersion)] = t.PARVersion
	}
	return cbor.Encode(m)
}

// Decode parses a payload against the closed schema. Optional keys, when
// present, must carry a meaningful value (a non-empty quote id, a gesture
// kind, a version ≥ 1): an encoding has exactly one form.
func Decode(payload []byte) (*TxAuth, error) {
	v, err := cbor.Decode(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, fmt.Errorf("%w: not a map", ErrMalformed)
	}
	f := m.Fields()
	t := &TxAuth{}
	if f.Uint(keyVersion) != Version {
		f.Fail(keyVersion, "unsupported version")
	}
	t.IntentID = uuid.UUID(bytes16(f.BytesN(keyIntent, 16)))
	amount := f.UintRange(keyAmount, 1, math.MaxInt64)
	t.Amount = int64(amount)
	t.Currency = f.Text(keyCurrency, 8)
	copy(t.PayeeRef[:], f.BytesN(keyPayee, 32))
	t.Nonce = bytes16(f.BytesN(keyNonce, 16))
	t.SignedAt = time.Unix(int64(f.UintRange(keyEpoch, 0, maxEpoch)), 0).UTC()
	f.Optional(keyQuote, func() {
		if t.QuoteID = f.Text(keyQuote, MaxQuoteIDLen); t.QuoteID == "" {
			f.Fail(keyQuote, "empty quote id")
		}
	})
	f.Optional(keyGesture, func() { t.Gesture = Gesture(f.UintRange(keyGesture, 1, uint64(GestureGrab))) })
	f.Optional(keyPARVersion, func() { t.PARVersion = f.UintRange(keyPARVersion, 1, math.MaxInt64) })
	if err := f.Done(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}

func bytes16(b []byte) [16]byte {
	var out [16]byte
	copy(out[:], b)
	return out
}

// DropPayeeRef is the payee reference of a drop: a tagged hash of the
// intent id, which no subject's reference can equal.
func DropPayeeRef(intentID uuid.UUID) [32]byte { return cose.TaggedHash(DropDomain, intentID[:]) }

// Sign returns the COSE_Sign1 of t by signer under the device key id.
func Sign(signer cose.Signer, keyID uuid.UUID, t *TxAuth) ([]byte, error) {
	payload, err := t.Encode()
	if err != nil {
		return nil, err
	}
	return cose.Sign1(signer, keyID[:], payload, Context)
}

// Message is a parsed TxAuth whose signature has not been checked yet: the
// verifier needs the kid to find the key.
type Message struct {
	KeyID   uuid.UUID
	Payload []byte // the signed bytes, kept as evidence
	TxAuth  *TxAuth
	msg     *cose.Sign1Message
}

// Parse decodes a COSE_Sign1 TxAuth and its payload. Nothing in it is
// authentic until Verify succeeds.
func Parse(raw []byte) (*Message, error) {
	m, err := cose.Parse1(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(m.KID) != 16 {
		return nil, ErrKeyID
	}
	t, err := Decode(m.Payload)
	if err != nil {
		return nil, err
	}
	return &Message{KeyID: uuid.UUID(bytes16(m.KID)), Payload: m.Payload, TxAuth: t, msg: m}, nil
}

// Verify checks the signature with the device key.
func (m *Message) Verify(pub *ecdsa.PublicKey) error { return m.msg.Verify(pub, Context) }
