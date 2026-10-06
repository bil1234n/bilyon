package offline

import (
	"crypto/elliptic"
	"errors"
	"math/big"
	"testing"

	"github.com/bil1234n/bilyon/reference/internal/cbor"
)

const t0 = 1_760_000_000 // fixed epoch seconds for deterministic tests

type fixture struct {
	now    uint64
	issuer *Issuer
	trust  TrustStore
	key    *SoftwareKey
	acct   ID128
	oacRaw []byte
	oac    *Allowance
	disk   *Disk
	wallet *Wallet
	rec    *Reconciler
}

func newFixture(t *testing.T, amount, txMax, maxTx uint64) *fixture {
	t.Helper()
	f := &fixture{now: t0, disk: &Disk{}, acct: ID128{0xA}}
	var err error
	if f.issuer, err = NewIssuer("iss-2026-10", func() uint64 { return f.now }); err != nil {
		t.Fatal(err)
	}
	f.trust = f.issuer.Trust()
	if f.key, err = NewSoftwareKey(); err != nil {
		t.Fatal(err)
	}
	f.oacRaw, f.oac, err = f.issuer.IssueAllowance(AllowanceSpec{DeviceKey: f.key.PublicKey(), Account: f.acct,
		Currency: "EUR", Amount: amount, TxMax: txMax, MaxTx: maxTx, Validity: 72 * 3600, Tier: TierK})
	if err != nil {
		t.Fatal(err)
	}
	if f.wallet, err = OpenWallet(f.oacRaw, f.key, f.trust, f.disk); err != nil {
		t.Fatal(err)
	}
	f.rec = NewReconciler(f.trust, func() uint64 { return f.now }, 14*24*3600, 100_00)
	f.rec.RegisterPayer(f.acct, "acct:payer")
	return f
}

func (f *fixture) newPayee(t *testing.T, name, account string, acct byte) *Payee {
	t.Helper()
	k, err := NewSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := f.issuer.IssuePayeeCert(ID128{acct}, k.PublicKey(), name, 5812, 365*24*3600)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPayee(cert, k, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rec.RegisterPayee(cert, account); err != nil {
		t.Fatal(err)
	}
	return p
}

// pay runs the full request -> pay -> accept handshake.
func pay(t *testing.T, w *Wallet, p *Payee, amount, wall uint64) ([]byte, []byte, Code) {
	t.Helper()
	req, err := p.Request(amount, "EUR", []byte("inv-1"), wall)
	if err != nil {
		t.Fatal(err)
	}
	packet, _, err := w.Pay(p.Cert(), req, wall)
	if err != nil {
		t.Fatalf("wallet.Pay: %v", err)
	}
	rc, code := p.Accept(packet, wall)
	return packet, rc, code
}

func sum(ps []Posting, debit, credit string) (total uint64) {
	for _, p := range ps {
		if (debit == "" || p.Debit == debit) && (credit == "" || p.Credit == credit) {
			total += p.Amount
		}
	}
	return total
}

func TestHonestFlowSettlesAndReleases(t *testing.T) {
	f := newFixture(t, 150_00, 50_00, 32)
	shop := f.newPayee(t, "Corner Cafe", "acct:cafe", 1)
	for i, amt := range []uint64{12_50, 7_25} {
		packet, rc, code := pay(t, f.wallet, shop, amt, t0+60)
		if code != OK {
			t.Fatalf("payment %d rejected: %v", i, code)
		}
		if st, err := f.wallet.AcceptReceipt(uint64(i+1), rc); err != nil || st != OK {
			t.Fatalf("receipt: %v %v", st, err)
		}
		if got := f.rec.Submit(packet, nil); got != OK {
			t.Fatalf("submit: %v", got)
		}
	}
	if f.wallet.Remaining() != 150_00-19_75 || len(f.wallet.InDoubt()) != 0 {
		t.Fatalf("remaining %d, in doubt %v", f.wallet.Remaining(), f.wallet.InDoubt())
	}
	// The payer's own log upload is idempotent with the payee's claims.
	for _, pkt := range f.wallet.SyncLog() {
		if got := f.rec.Submit(pkt, nil); got != ErrDuplicate {
			t.Fatalf("payer log resubmission = %v, want DUPLICATE", got)
		}
	}
	f.now = t0 + 72*3600 + 14*24*3600 + 1
	f.rec.Expire()
	if got := sum(f.rec.Postings, "", "acct:cafe"); got != 19_75 {
		t.Fatalf("cafe credited %d", got)
	}
	if got := sum(f.rec.Postings, "", "acct:payer"); got != 150_00-19_75 {
		t.Fatalf("payer refunded %d", got)
	}
	if len(f.rec.Proofs) != 0 || f.rec.Revoked[f.oac.ID] {
		t.Fatal("honest allowance flagged")
	}
}

func TestReplayToOtherPayeeAndRetransmit(t *testing.T) {
	f := newFixture(t, 150_00, 50_00, 32)
	a := f.newPayee(t, "A", "acct:a", 1)
	b := f.newPayee(t, "B", "acct:b", 2)
	packet, rc1, code := pay(t, f.wallet, a, 10_00, t0)
	if code != OK {
		t.Fatal(code)
	}
	// B has an outstanding request with the same amount; the token is still bound to A.
	if _, err := b.Request(10_00, "EUR", []byte("inv-1"), t0); err != nil {
		t.Fatal(err)
	}
	if _, code := b.Accept(packet, t0); code != ErrWrongPayee {
		t.Fatalf("replay to B = %v, want WRONG_PAYEE", code)
	}
	// Receipt lost: the token is in doubt; retransmission is byte-identical and idempotent.
	if got := f.wallet.InDoubt(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("in doubt %v", got)
	}
	again, _ := f.wallet.Retransmit(1)
	rc2, code := a.Accept(again, t0+5)
	if code != OK || string(rc2) != string(rc1) || len(a.Claims) != 1 {
		t.Fatalf("retransmit: code %v, same receipt %v, claims %d", code, string(rc2) == string(rc1), len(a.Claims))
	}
}

func TestCrashBetweenReserveAndSignRollsBack(t *testing.T) {
	f := newFixture(t, 150_00, 50_00, 32)
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	req, _ := shop.Request(20_00, "EUR", nil, t0)
	f.wallet.crashAfterReserve = true
	if _, _, err := f.wallet.Pay(shop.Cert(), req, t0); !errors.Is(err, ErrCrash) {
		t.Fatalf("want crash, got %v", err)
	}
	if len(f.disk.entries) != 1 || f.disk.entries[0].Status != walReserved {
		t.Fatal("reserve was not durable before signing")
	}
	w, err := OpenWallet(f.oacRaw, f.key, f.trust, f.disk) // process restart
	if err != nil {
		t.Fatal(err)
	}
	if w.Remaining() != 150_00 {
		t.Fatalf("reserved entry not rolled back: remaining %d", w.Remaining())
	}
	if _, _, code := pay(t, w, shop, 20_00, t0+1); code != OK {
		t.Fatalf("seq 1 reuse after rollback rejected: %v", code)
	}
}

func TestWalletEnforcesLimits(t *testing.T) {
	f := newFixture(t, 30_00, 20_00, 2)
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	req, _ := shop.Request(25_00, "EUR", nil, t0)
	if _, _, err := f.wallet.Pay(shop.Cert(), req, t0); err != ErrLimit {
		t.Fatalf("over txmax: %v", err)
	}
	pay(t, f.wallet, shop, 20_00, t0)
	req, _ = shop.Request(15_00, "EUR", nil, t0)
	if _, _, err := f.wallet.Pay(shop.Cert(), req, t0); err != ErrLimit {
		t.Fatalf("over allowance: %v", err)
	}
	pay(t, f.wallet, shop, 5_00, t0)
	req, _ = shop.Request(1_00, "EUR", nil, t0)
	if _, _, err := f.wallet.Pay(shop.Cert(), req, t0); err != ErrLimit {
		t.Fatalf("over max token count: %v", err)
	}
	req, _ = shop.Request(1_00, "USD", nil, t0)
	if _, _, err := f.wallet.Pay(shop.Cert(), req, t0); err != ErrCurrency {
		t.Fatalf("currency mismatch: %v", err)
	}
}

func TestPayeeTimeFloorRejectsExpiredAllowance(t *testing.T) {
	f := newFixture(t, 50_00, 50_00, 4)
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	req, _ := shop.Request(5_00, "EUR", nil, t0)
	packet, _, err := f.wallet.Pay(shop.Cert(), req, t0)
	if err != nil {
		t.Fatal(err)
	}
	shop.Clock.Observe(f.oac.Expiry + 1) // signed timestamp seen after expiry
	if _, code := shop.Accept(packet, t0); code != ErrExpired {
		t.Fatalf("wound-back clock accepted expired allowance: %v", code)
	}
}

func TestForkFromStateRollbackIsDetectedAndGuaranteed(t *testing.T) {
	f := newFixture(t, 50_00, 50_00, 32)
	a := f.newPayee(t, "A", "acct:a", 1)
	b := f.newPayee(t, "B", "acct:b", 2)
	snapshot := &Disk{entries: append([]walEntry(nil), f.disk.entries...)}
	pa, _, code := pay(t, f.wallet, a, 40_00, t0)
	if code != OK {
		t.Fatal(code)
	}
	// Attacker restores the pre-payment state (or patches the app) and spends again.
	clone, err := OpenWallet(f.oacRaw, f.key, f.trust, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	pb, _, code := pay(t, clone, b, 40_00, t0+10)
	if code != OK {
		t.Fatalf("offline payee B cannot see the fork and should accept: %v", code)
	}
	if got := f.rec.Submit(pa, nil); got != OK {
		t.Fatal(got)
	}
	if got := f.rec.Submit(pb, nil); got != OK {
		t.Fatalf("good-faith payee B not paid: %v", got)
	}
	if !f.rec.Revoked[f.oac.ID] || len(f.rec.Proofs) == 0 || f.rec.Proofs[0].Kind != ErrEquivocation {
		t.Fatal("fork not flagged with an equivocation proof")
	}
	if sum(f.rec.Postings, GuaranteeFund, "acct:b") != 30_00 || sum(f.rec.Postings, "acct:payer", GuaranteeFund) != 30_00 {
		t.Fatalf("guarantee/clawback wrong: %+v", f.rec.Postings)
	}
	if got := f.rec.Submit(pb, nil); got != ErrDuplicate {
		t.Fatalf("conflicting token paid twice: %v", got)
	}
}

func TestPayeeRadarCatchesEquivocationAndInconsistency(t *testing.T) {
	f := newFixture(t, 100_00, 50_00, 32)
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	snapshot := &Disk{entries: append([]walEntry(nil), f.disk.entries...)}
	pay(t, f.wallet, shop, 10_00, t0)
	clone, _ := OpenWallet(f.oacRaw, f.key, f.trust, snapshot)
	if _, _, code := pay(t, clone, shop, 10_00, t0); code != ErrEquivocation {
		t.Fatalf("same-seq fork at one payee = %v", code)
	}
	// A patched wallet signs seq 2 whose cumulative ignores seq 1.
	held := shop.held[f.oac.ID][1].tok
	req, _ := shop.Request(5_00, "EUR", nil, t0)
	reqTok, _ := decodeRequestFromRaw(req)
	bad := SpendToken{AllowanceID: f.oac.ID, Seq: 2, Prev: held.ID(), Amount: 5_00, Cumulative: 5_00 + 1,
		Payee: held.Payee, Nonce: reqTok.Nonce, Time: t0}
	cose, _ := Sign1(f.key, nil, bad.encode(), aadToken)
	pkt := cbor.MustEncode([]any{uint64(packetTierK), f.oacRaw, cose})
	if _, code := shop.Accept(pkt, t0); code != ErrInconsistent {
		t.Fatalf("inconsistent cumulative = %v", code)
	}
	if len(shop.Evidence) != 2 {
		t.Fatalf("evidence %d", len(shop.Evidence))
	}
}

func decodeRequestFromRaw(raw []byte) (*PaymentRequest, error) {
	payload, err := peekPayload(raw)
	if err != nil {
		return nil, err
	}
	return decodeRequest(payload)
}

func TestHighSSignatureAndTamperingRejected(t *testing.T) {
	f := newFixture(t, 100_00, 50_00, 32)
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	req, _ := shop.Request(10_00, "EUR", nil, t0)
	packet, tok, err := f.wallet.Pay(shop.Cert(), req, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Malleate s -> n - s inside the COSE signature.
	v, _ := cbor.Decode(packet)
	arr := v.([]any)
	ct := mustTag(t, arr[2].([]byte))
	parts := ct.Content.([]any)
	sig := append([]byte(nil), parts[3].([]byte)...)
	s := new(big.Int).SetBytes(sig[32:])
	new(big.Int).Sub(elliptic.P256().Params().N, s).FillBytes(sig[32:])
	parts[3] = sig
	mall := cbor.MustEncode([]any{arr[0], arr[1], cbor.MustEncode(cbor.Tag{Number: 18, Content: parts})})
	if _, code := shop.Accept(mall, t0); code != ErrBadSignature {
		t.Fatalf("high-S accepted: %v", code)
	}
	// Tamper with the amount in the payload.
	tok.Amount = 1
	parts[2], parts[3] = tok.encode(), arr[2].([]byte)[len(arr[2].([]byte))-64:]
	tamp := cbor.MustEncode([]any{arr[0], arr[1], cbor.MustEncode(cbor.Tag{Number: 18, Content: parts})})
	if _, code := shop.Accept(tamp, t0); code != ErrBadSignature {
		t.Fatalf("tampered amount accepted: %v", code)
	}
	if _, code := shop.Accept(packet, t0); code != OK {
		t.Fatalf("original rejected: %v", code)
	}
}

func mustTag(t *testing.T, raw []byte) cbor.Tag {
	t.Helper()
	v, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(cbor.Tag)
}

func TestRejectedTokenIsVoidedNotPaid(t *testing.T) {
	f := newFixture(t, 100_00, 50_00, 32)
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	req, _ := shop.Request(10_00, "EUR", nil, t0)
	packet, _, _ := f.wallet.Pay(shop.Cert(), req, t0)
	shop.Accept(packet, t0)
	// The same (now consumed) request is paid again: the payee rejects it.
	packet2, _, err := f.wallet.Pay(shop.Cert(), req, t0)
	if err != nil {
		t.Fatal(err)
	}
	rc, code := shop.Accept(packet2, t0)
	if code != ErrNonce {
		t.Fatalf("consumed nonce = %v", code)
	}
	if st, _ := f.wallet.AcceptReceipt(2, rc); st != ErrNonce {
		t.Fatalf("receipt status %v", st)
	}
	if got := f.rec.Submit(packet2, rc); got != ErrVoided {
		t.Fatalf("rejected token = %v, want VOIDED", got)
	}
	if got := f.rec.Submit(packet2, nil); got != ErrVoided {
		t.Fatalf("payee claim of a token it rejected = %v", got)
	}
}

func TestClosingReleasesEarlyAndExposesLaterTokens(t *testing.T) {
	f := newFixture(t, 100_00, 50_00, 32)
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	other := f.newPayee(t, "Other", "acct:other", 2)
	pkt, _, _ := pay(t, f.wallet, shop, 30_00, t0)
	snapshot := &Disk{entries: append([]walEntry(nil), f.disk.entries...)}
	closing, err := f.wallet.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.rec.Submit(pkt, nil)
	if err := f.rec.SubmitClosing(f.oacRaw, closing); err != nil {
		t.Fatal(err)
	}
	if got := sum(f.rec.Postings, "", "acct:payer"); got != 70_00 {
		t.Fatalf("early release %d", got)
	}
	// After closing, the payer spends again from a restored state.
	clone, _ := OpenWallet(f.oacRaw, f.key, f.trust, snapshot)
	late, _, code := pay(t, clone, other, 20_00, t0+60)
	if code != OK {
		t.Fatal(code)
	}
	if got := f.rec.Submit(late, nil); got != OK {
		t.Fatalf("good-faith payee after closing: %v", got)
	}
	if !f.rec.Revoked[f.oac.ID] || sum(f.rec.Postings, "acct:payer", GuaranteeFund) != 20_00 {
		t.Fatal("post-closing token not treated as provable overspend")
	}
}

func TestTierSCoins(t *testing.T) {
	f := newFixture(t, 1, 1, 1)
	denoms := []uint64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 4096}
	set, err := MintCoins(denoms)
	if err != nil {
		t.Fatal(err)
	}
	oacRaw, _, err := f.issuer.IssueAllowance(AllowanceSpec{DeviceKey: f.key.PublicKey(), Account: f.acct,
		Currency: "EUR", Amount: set.Total(), TxMax: 100_00, MaxTx: uint64(len(denoms)), Validity: 7 * 24 * 3600,
		Tier: TierS, CoinRoot: set.Root()})
	if err != nil {
		t.Fatal(err)
	}
	purse, err := OpenCoinPurse(oacRaw, set, f.trust)
	if err != nil {
		t.Fatal(err)
	}
	shop := f.newPayee(t, "Shop", "acct:shop", 1)
	req, _ := shop.Request(12_34, "EUR", nil, t0)
	packet, err := purse.Pay(shop.Cert(), req, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, code := shop.Accept(packet, t0); code != OK {
		t.Fatalf("coin payment rejected: %v", code)
	}
	if got := f.rec.Submit(packet, nil); got != OK || sum(f.rec.Postings, "", "acct:shop") != 12_34 {
		t.Fatalf("coin settlement: %v %+v", got, f.rec.Postings)
	}
	if f.rec.Submit(packet, nil) != ErrDuplicate {
		t.Fatal("coin packet paid twice")
	}
	// Hardware refuses a second signature even if the purse forgot the coin was spent.
	for _, c := range set.Coins {
		if c.spent {
			c.spent = false
			if _, err := c.key.Sign(make([]byte, 32)); !errors.Is(err, ErrKeyExhausted) {
				t.Fatalf("single-use key signed twice: %v", err)
			}
		}
	}
}

func TestSelectCoinsExactAndMinimal(t *testing.T) {
	mk := func(ds ...uint64) []*Coin {
		var cs []*Coin
		for i, d := range ds {
			cs = append(cs, &Coin{Index: uint64(i), Denom: d})
		}
		return cs
	}
	got, err := SelectCoins(mk(500, 200, 200, 100, 50, 20, 20, 10, 5), 470)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, c := range got {
		total += c.Denom
	}
	if total != 470 || len(got) != 4 { // 200+200+50+20
		t.Fatalf("got %d coins summing to %d", len(got), total)
	}
	if _, err := SelectCoins(mk(500, 200), 300); err == nil {
		t.Fatal("expected no exact combination")
	}
}

// TestWireSizes pins the size budget quoted in RFC 0001 §2.1: a Tier K
// packet must fit one BLE L2CAP SDU, an NFC extended APDU and a QR code.
func TestWireSizes(t *testing.T) {
	f := newFixture(t, 150_00, 50_00, 32)
	shop := f.newPayee(t, "Corner Cafe", "acct:cafe", 1)
	req, _ := shop.Request(12_50, "EUR", []byte("inv-2026-10-06-0001"), t0)
	packet, _, err := f.wallet.Pay(shop.Cert(), req, t0)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := shop.Accept(packet, t0)
	t.Logf("OAC=%dB PayeeCert=%dB Request=%dB OST=%dB Packet=%dB Receipt=%dB",
		len(f.oacRaw), len(shop.Cert()), len(req), len(f.wallet.entries[0].COSE), len(packet), len(rc))
	if len(packet) > 512 {
		t.Fatalf("Tier K packet %d bytes exceeds 512-byte budget", len(packet))
	}
	set, _ := MintCoins(make64(64))
	oacS, _, _ := f.issuer.IssueAllowance(AllowanceSpec{DeviceKey: f.key.PublicKey(), Account: f.acct,
		Currency: "EUR", Amount: set.Total(), TxMax: set.Total(), MaxTx: 64, Validity: 3600, Tier: TierS, CoinRoot: set.Root()})
	purse, _ := OpenCoinPurse(oacS, set, f.trust)
	req, _ = shop.Request(3, "EUR", nil, t0)
	coinPkt, err := purse.Pay(shop.Cert(), req, t0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Tier S: OAC=%dB, single-coin packet=%dB", len(oacS), len(coinPkt))
}

func make64(n int) []uint64 {
	d := make([]uint64, n)
	for i := range d {
		d[i] = uint64(1 + i%8)
	}
	return d
}
