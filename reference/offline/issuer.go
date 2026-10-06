package offline

import (
	"crypto/rand"
	"errors"
)

// TrustStore maps issuer key IDs to public keys. It ships with the app and is
// refreshed on every sync; old kids stay until every certificate they signed
// has expired.
type TrustStore map[string][]byte

func (ts TrustStore) resolver() func(kid []byte) ([]byte, error) {
	return func(kid []byte) ([]byte, error) {
		pub, ok := ts[string(kid)]
		if !ok {
			return nil, ErrUnknownIssuer
		}
		return pub, nil
	}
}

// Issuer models the issuer HSM. It signs an allowance only after the ledger
// has moved the amount into the allowance's reserve account.
type Issuer struct {
	KID []byte
	key Signer
	Now func() uint64
}

// NewIssuer creates an issuer with a fresh key.
func NewIssuer(kid string, now func() uint64) (*Issuer, error) {
	k, err := NewSoftwareKey()
	if err != nil {
		return nil, err
	}
	return &Issuer{KID: []byte(kid), key: k, Now: now}, nil
}

// Trust returns a trust store containing this issuer.
func (is *Issuer) Trust() TrustStore { return TrustStore{string(is.KID): is.key.PublicKey()} }

// AllowanceSpec is the policy-checked request for a new allowance.
type AllowanceSpec struct {
	DeviceKey []byte
	Account   ID128
	Currency  string
	Amount    uint64
	TxMax     uint64
	MaxTx     uint64
	Validity  uint64 // seconds
	Tier      Tier
	CoinRoot  []byte
	CRLEpoch  uint64
}

// IssueAllowance signs an Offline Allowance Certificate.
func (is *Issuer) IssueAllowance(spec AllowanceSpec) ([]byte, *Allowance, error) {
	if spec.Amount == 0 || spec.TxMax == 0 || spec.MaxTx == 0 || len(spec.Currency) != 3 {
		return nil, nil, errors.New("invalid allowance spec")
	}
	if spec.Tier == TierS && len(spec.CoinRoot) != 32 {
		return nil, nil, errors.New("tier S allowance needs a coin root")
	}
	var id ID128
	if _, err := rand.Read(id[:]); err != nil {
		return nil, nil, err
	}
	now := is.Now()
	a := &Allowance{ID: id, DeviceKey: spec.DeviceKey, Currency: spec.Currency, Amount: spec.Amount,
		TxMax: spec.TxMax, NotBefore: now, Expiry: now + spec.Validity, Tier: spec.Tier,
		Anchor: AnchorFor(id), MaxTx: spec.MaxTx, Account: spec.Account, IssuedAt: now,
		CRLEpoch: spec.CRLEpoch, CoinRoot: spec.CoinRoot}
	raw, err := Sign1(is.key, is.KID, a.encode(), aadAllowance)
	return raw, a, err
}

// IssuePayeeCert signs a payee certificate for a registered device.
func (is *Issuer) IssuePayeeCert(acct ID128, deviceKey []byte, name string, mcc, validity uint64) ([]byte, error) {
	now := is.Now()
	p := &PayeeCert{Account: acct, DeviceKey: deviceKey, Name: name, MCC: mcc, IssuedAt: now, Expiry: now + validity}
	return Sign1(is.key, is.KID, p.encode(), aadPayeeCert)
}

func openAllowance(raw []byte, trust TrustStore) (*Allowance, error) {
	payload, _, err := Open1(raw, aadAllowance, trust.resolver())
	if err != nil {
		if errors.Is(err, ErrUnknownIssuer) {
			return nil, ErrUnknownIssuer
		}
		return nil, ErrBadSignature
	}
	return decodeAllowance(payload)
}

func openPayeeCert(raw []byte, trust TrustStore) (*PayeeCert, error) {
	payload, _, err := Open1(raw, aadPayeeCert, trust.resolver())
	if err != nil {
		if errors.Is(err, ErrUnknownIssuer) {
			return nil, ErrUnknownIssuer
		}
		return nil, ErrBadSignature
	}
	return decodePayeeCert(payload)
}

func fixedKey(pub []byte) func([]byte) ([]byte, error) {
	return func([]byte) ([]byte, error) { return pub, nil }
}

// TimeFloor is a device's trusted lower bound on the current time. It only
// moves forward: it advances on the wall clock and on every server-signed
// timestamp the device sees (allowance and payee certificates carry one), so
// winding the device clock back cannot resurrect an expired allowance.
type TimeFloor struct{ floor uint64 }

// Observe advances the floor to a signed timestamp.
func (tf *TimeFloor) Observe(signed uint64) {
	if signed > tf.floor {
		tf.floor = signed
	}
}

// Now returns max(floor, wall) and ratchets the floor.
func (tf *TimeFloor) Now(wall uint64) uint64 {
	tf.Observe(wall)
	return tf.floor
}
