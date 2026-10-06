package txauth_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/txauth"
)

func vector() *txauth.TxAuth {
	t := &txauth.TxAuth{
		IntentID: uuid.MustParse("0192f4a0-7b3c-7d10-8e3f-123456789abc"), Amount: 2500, Currency: "EUR",
		SignedAt: time.Unix(1790000000, 0).UTC(), Gesture: txauth.GestureFlick, PARVersion: 3,
	}
	for i := range t.PayeeRef {
		t.PayeeRef[i] = byte(i)
	}
	for i := range t.Nonce {
		t.Nonce[i] = 0xa0 + byte(i)
	}
	return t
}

// The vectors were computed by an independent encoder (RFC 8949 §4.2.1
// rules applied by hand); the Rust core asserts the same bytes.
const (
	vectorFlick = "a9010102500192f4a07b3c7d108e3f123456789abc031909c40463455552055820000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1f0650a0a1a2a3a4a5a6a7a8a9aaabacadaeaf071a6ab13b8009010a03"
	vectorQuote = "a8010102500192f4a07b3c7d108e3f123456789abc031a075bcd15046455534443055820000102030405060708090a0b0c0d" +
		"0e0f101112131415161718191a1b1c1d1e1f0650a0a1a2a3a4a5a6a7a8a9aaabacadaeaf071a6ab13b800878243031393266" +
		"3461302d303030302d373030302d383030302d303030303030303030303031"
)

func TestEncodingVectors(t *testing.T) {
	v := vector()
	got, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vectorFlick {
		t.Fatalf("flick payload\n got %x\nwant %s", got, vectorFlick)
	}
	q := vector()
	q.Amount, q.Currency, q.Gesture, q.PARVersion = 123456789, "USDC", txauth.GestureNone, 0
	q.QuoteID = "0192f4a0-0000-7000-8000-000000000001"
	if got, err = q.Encode(); err != nil || hex.EncodeToString(got) != vectorQuote {
		t.Fatalf("quote payload %x, %v", got, err)
	}
	for _, h := range []string{vectorFlick, vectorQuote} {
		raw, _ := hex.DecodeString(h)
		d, err := txauth.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := d.Encode()
		if !bytes.Equal(again, raw) {
			t.Fatalf("round trip changed %s", h)
		}
	}
	d, _ := txauth.Decode(mustHex(t, vectorFlick))
	if *d != *v {
		t.Fatalf("decoded %+v, want %+v", d, v)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// payload builds a payload map from the vector so tests can corrupt one key.
func payload(edit func(m cbor.Map)) []byte {
	v := vector()
	m := cbor.Map{int64(1): uint64(1), int64(2): v.IntentID[:], int64(3): uint64(v.Amount), int64(4): v.Currency,
		int64(5): v.PayeeRef[:], int64(6): v.Nonce[:], int64(7): uint64(v.SignedAt.Unix()), int64(9): uint64(1),
		int64(10): uint64(3)}
	edit(m)
	return cbor.MustEncode(m)
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string][]byte{
		"version 2":        payload(func(m cbor.Map) { m[int64(1)] = uint64(2) }),
		"no version":       payload(func(m cbor.Map) { delete(m, int64(1)) }),
		"short intent":     payload(func(m cbor.Map) { m[int64(2)] = make([]byte, 15) }),
		"nil intent":       payload(func(m cbor.Map) { m[int64(2)] = make([]byte, 16) }),
		"zero amount":      payload(func(m cbor.Map) { m[int64(3)] = uint64(0) }),
		"negative amount":  payload(func(m cbor.Map) { m[int64(3)] = int64(-5) }),
		"amount over i64":  payload(func(m cbor.Map) { m[int64(3)] = uint64(math.MaxInt64) + 1 }),
		"lowercase cur":    payload(func(m cbor.Map) { m[int64(4)] = "eur" }),
		"long currency":    payload(func(m cbor.Map) { m[int64(4)] = "ABCDEFGHI" }),
		"short payee":      payload(func(m cbor.Map) { m[int64(5)] = make([]byte, 31) }),
		"nonce as text":    payload(func(m cbor.Map) { m[int64(6)] = "0123456789abcdef" }),
		"epoch negative":   payload(func(m cbor.Map) { m[int64(7)] = int64(-1) }),
		"epoch year 10000": payload(func(m cbor.Map) { m[int64(7)] = uint64(253402300800) }),
		"empty quote":      payload(func(m cbor.Map) { m[int64(8)] = "" }),
		"long quote":       payload(func(m cbor.Map) { m[int64(8)] = string(make([]byte, 65)) }),
		"gesture 0":        payload(func(m cbor.Map) { m[int64(9)] = uint64(0) }),
		"gesture 4":        payload(func(m cbor.Map) { m[int64(9)] = uint64(4) }),
		"par version 0":    payload(func(m cbor.Map) { m[int64(10)] = uint64(0) }),
		"unknown key 11":   payload(func(m cbor.Map) { m[int64(11)] = uint64(1) }),
		"text key":         payload(func(m cbor.Map) { m["amount"] = uint64(1) }),
		"not a map":        cbor.MustEncode([]any{uint64(1)}),
		"trailing byte":    append(mustHex(t, vectorFlick), 0x00),
		// 2500 in a 4-byte head instead of the shortest 2-byte head.
		"non-canonical": mustHex(t, "a9010102500192f4a07b3c7d108e3f123456789abc031a000009c40463455552055820000102030405060708090a0b0c"+
			"0d0e0f101112131415161718191a1b1c1d1e1f0650a0a1a2a3a4a5a6a7a8a9aaabacadaeaf071a6ab13b8009010a03"),
	}
	for name, raw := range cases {
		if _, err := txauth.Decode(raw); !errors.Is(err, txauth.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEncodeRejects(t *testing.T) {
	for name, edit := range map[string]func(*txauth.TxAuth){
		"nil intent":  func(a *txauth.TxAuth) { a.IntentID = uuid.Nil },
		"amount":      func(a *txauth.TxAuth) { a.Amount = 0 },
		"currency":    func(a *txauth.TxAuth) { a.Currency = "E" },
		"gesture":     func(a *txauth.TxAuth) { a.Gesture = 9 },
		"before 1970": func(a *txauth.TxAuth) { a.SignedAt = time.Unix(-1, 0) },
		"long quote":  func(a *txauth.TxAuth) { a.QuoteID = string(make([]byte, 65)) },
	} {
		v := vector()
		edit(v)
		if _, err := v.Encode(); !errors.Is(err, txauth.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSignParseVerify(t *testing.T) {
	signer, err := cose.GenerateKeySigner()
	if err != nil {
		t.Fatal(err)
	}
	keyID := uuid.New()
	raw, err := txauth.Sign(signer, keyID, vector())
	if err != nil {
		t.Fatal(err)
	}
	m, err := txauth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.KeyID != keyID || *m.TxAuth != *vector() || hex.EncodeToString(m.Payload) != vectorFlick {
		t.Fatalf("parsed %+v", m)
	}
	if err := m.Verify(signer.Public()); err != nil {
		t.Fatal(err)
	}
	other, _ := cose.GenerateKeySigner()
	if err := m.Verify(other.Public()); !errors.Is(err, cose.ErrSignature) {
		t.Fatalf("foreign key: %v", err)
	}
	// The same payload signed for another artefact type does not verify.
	payload, _ := vector().Encode()
	foreign, _ := cose.Sign1(signer, keyID[:], payload, "bilyon/ost/v1")
	if fm, err := txauth.Parse(foreign); err != nil || !errors.Is(fm.Verify(signer.Public()), cose.ErrSignature) {
		t.Fatalf("cross-artefact signature: %v", err)
	}
	// kid must be the 16-byte key id.
	for _, kid := range [][]byte{nil, make([]byte, 15), make([]byte, 17)} {
		r, _ := cose.Sign1(signer, kid, payload, txauth.Context)
		if _, err := txauth.Parse(r); !errors.Is(err, txauth.ErrKeyID) {
			t.Fatalf("kid of %d bytes: %v", len(kid), err)
		}
	}
	if _, err := txauth.Parse([]byte{0x01}); !errors.Is(err, txauth.ErrMalformed) {
		t.Fatalf("garbage: %v", err)
	}
	bad, _ := cose.Sign1(signer, keyID[:], payload[:len(payload)-1], txauth.Context)
	if _, err := txauth.Parse(bad); !errors.Is(err, txauth.ErrMalformed) {
		t.Fatalf("truncated payload: %v", err)
	}
}

func TestDropPayeeRef(t *testing.T) {
	id := uuid.MustParse("0192f4a0-7b3c-7d10-8e3f-123456789abc")
	want := cose.TaggedHash("bilyon/drop/v1", id[:])
	if txauth.DropPayeeRef(id) != want {
		t.Fatal("drop payee reference")
	}
	if txauth.DropPayeeRef(id) == txauth.DropPayeeRef(uuid.New()) {
		t.Fatal("drop references must differ per intent")
	}
	// A subject's reference uses another domain, so the two never collide.
	if cose.TaggedHash("bilyon/payee/v1", id[:]) == want {
		t.Fatal("domains collide")
	}
}

// TestRoundTripProperty encodes random authorisations and checks that
// decoding returns them exactly and re-encoding reproduces the bytes.
func TestRoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 11))
	currencies := []string{"EUR", "USD", "JPY", "USDC", "KWD", "EURC"}
	for i := 0; i < 3000; i++ {
		v := &txauth.TxAuth{Amount: 1 + r.Int64N(math.MaxInt64), Currency: currencies[r.IntN(len(currencies))],
			SignedAt: time.Unix(r.Int64N(253402300800), 0).UTC()}
		for j := range v.IntentID {
			v.IntentID[j] = byte(r.Uint32())
		}
		v.IntentID[0] |= 1
		for j := range v.PayeeRef {
			v.PayeeRef[j] = byte(r.Uint32())
		}
		for j := range v.Nonce {
			v.Nonce[j] = byte(r.Uint32())
		}
		if r.IntN(2) == 0 {
			v.QuoteID = uuid.NewString()
		}
		v.Gesture = txauth.Gesture(r.IntN(4))
		if r.IntN(2) == 0 {
			v.PARVersion = 1 + r.Uint64N(math.MaxInt64)
		}
		raw, err := v.Encode()
		if err != nil {
			t.Fatalf("encode %+v: %v", v, err)
		}
		d, err := txauth.Decode(raw)
		if err != nil {
			t.Fatalf("decode %x: %v", raw, err)
		}
		if *d != *v {
			t.Fatalf("round trip %+v → %+v", v, d)
		}
		again, _ := d.Encode()
		if !bytes.Equal(again, raw) {
			t.Fatalf("re-encoding differs for %+v", v)
		}
	}
}
