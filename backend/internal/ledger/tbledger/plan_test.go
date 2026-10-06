package tbledger

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	tb "github.com/tigerbeetle/tigerbeetle-go"
	"pgregory.net/rapid"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

func genUUID() *rapid.Generator[uuid.UUID] {
	return rapid.Custom(func(t *rapid.T) uuid.UUID {
		var id uuid.UUID
		copy(id[:], rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "bytes"))
		return id
	})
}

func TestU128RoundTripAndOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genUUID().Draw(t, "a"), genUUID().Draw(t, "b")
		if FromU128(ToU128(a)) != a {
			t.Fatalf("round trip of %s", a)
		}
		want := bytes.Compare(a[:], b[:])
		if c := ToU128(a).BigInt().Cmp(ToU128(b).BigInt()); c != want {
			t.Fatalf("order of %s vs %s: numeric %d, bytes %d", a, b, c, want)
		}
	})
}

func TestDerivedIDIsDeterministicAndDistinct(t *testing.T) {
	base := ledger.NewID()
	seen := map[tb.Uint128]string{}
	for _, purpose := range []string{"entry", "fallback", "post", "void", "limit", "opening"} {
		for i := range 2000 {
			id := derivedID(base, purpose, i)
			if id != derivedID(base, purpose, i) {
				t.Fatal("derived id is not deterministic")
			}
			key := purpose + "/" + string(rune(i))
			if prev, dup := seen[id]; dup {
				t.Fatalf("collision between %s and %s", prev, key)
			}
			seen[id] = key
			u := FromU128(id)
			if !bytes.Equal(u[:8], base[:8]) {
				t.Fatal("derived id lost the base id's time prefix")
			}
		}
	}
	// The reserved values 0 and 2^128-1 are never produced.
	var zero uuid.UUID
	for _, base := range []uuid.UUID{zero, uuid.Max} {
		for i := range 1000 {
			u := FromU128(derivedID(base, "x", i))
			if u == uuid.Nil || u == uuid.Max {
				t.Fatalf("reserved id produced from %s", base)
			}
		}
	}
}

func TestEntryCodeStaysAboveSystemCodes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kind := rapid.String().Draw(t, "kind")
		c := entryCode(kind)
		if c < entryCodeBase || c != entryCode(kind) {
			t.Fatalf("entry code %d for %q", c, kind)
		}
	})
	for _, c := range []uint16{codeHoldControl, codeLimitControl, codeOpeningControl, codeHold, codeLimitFunding, codeOpening} {
		if c >= entryCodeBase {
			t.Fatalf("system code %d overlaps entry codes", c)
		}
	}
	if uint16(len(ledger.AccountKinds)) >= codeHoldControl {
		t.Fatal("account kind codes overlap system codes")
	}
}

// genEntryPostings draws a balanced multi-currency posting set over a small
// account pool, so accounts repeat and legs partly cancel.
func genEntryPostings(t *rapid.T) []ledger.PostingRecord {
	accounts := rapid.SliceOfNDistinct(genUUID(), 2, 6, func(u uuid.UUID) uuid.UUID { return u }).Draw(t, "accounts")
	currencies := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"EUR", "USD", "JPY", "USDC"}), 1, 3,
		func(s string) string { return s }).Draw(t, "currencies")
	var out []ledger.PostingRecord
	for _, c := range currencies {
		n := rapid.IntRange(1, 6).Draw(t, "moves")
		for range n {
			from := rapid.SampledFrom(accounts).Draw(t, "from")
			to := rapid.SampledFrom(accounts).Draw(t, "to")
			amt := rapid.Int64Range(1, 1_000_000).Draw(t, "amount")
			out = append(out, ledger.PostingRecord{AccountID: from, Currency: c, Amount: -amt},
				ledger.PostingRecord{AccountID: to, Currency: c, Amount: amt})
		}
	}
	return out
}

type acctCur struct {
	account  uuid.UUID
	currency string
}

func netOf(ps []ledger.PostingRecord) map[acctCur]int64 {
	out := map[acctCur]int64{}
	for _, p := range ps {
		out[acctCur{p.AccountID, p.Currency}] += p.Amount
	}
	for k, v := range out {
		if v == 0 {
			delete(out, k)
		}
	}
	return out
}

func TestDecomposePreservesNetDeltas(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		postings := genEntryPostings(t)
		flows, err := decompose(postings)
		if err != nil {
			t.Fatal(err)
		}
		got := map[acctCur]int64{}
		perCurrency := map[string]int{}
		for _, f := range flows {
			if f.amount <= 0 {
				t.Fatalf("non-positive flow %+v", f)
			}
			if f.debit == f.credit {
				t.Fatalf("self flow %+v", f)
			}
			got[acctCur{f.debit, f.currency}] -= f.amount
			got[acctCur{f.credit, f.currency}] += f.amount
			perCurrency[f.currency]++
		}
		want := netOf(postings)
		for k, v := range got {
			if v == 0 {
				delete(got, k)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("flows touch %d accounts, postings net %d", len(got), len(want))
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s/%s: flows net %d, postings net %d", k.account, k.currency, got[k], v)
			}
		}
		accountsPer := map[string]int{}
		for k := range want {
			accountsPer[k.currency]++
		}
		for c, n := range perCurrency {
			if n > accountsPer[c]-1 {
				t.Fatalf("%s: %d flows for %d accounts", c, n, accountsPer[c])
			}
		}
		// The order of postings does not matter.
		shuffled := append([]ledger.PostingRecord{}, postings...)
		perm := rapid.Permutation(shuffled).Draw(t, "perm")
		again, err := decompose(perm)
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(flows) {
			t.Fatal("decomposition depends on posting order")
		}
		for i := range flows {
			if again[i] != flows[i] {
				t.Fatalf("flow %d differs after shuffling: %+v vs %+v", i, again[i], flows[i])
			}
		}
	})
}

func TestDecomposeRejectsMalformedPostings(t *testing.T) {
	a, b := ledger.NewID(), ledger.NewID()
	cases := []struct {
		name     string
		postings []ledger.PostingRecord
		want     error
	}{
		{"unbalanced", []ledger.PostingRecord{{AccountID: a, Currency: "EUR", Amount: -5}, {AccountID: b, Currency: "EUR", Amount: 4}}, ledger.ErrUnbalanced},
		{"balanced across currencies only", []ledger.PostingRecord{{AccountID: a, Currency: "EUR", Amount: -5}, {AccountID: b, Currency: "USD", Amount: 5}}, ledger.ErrUnbalanced},
		{"zero posting", []ledger.PostingRecord{{AccountID: a, Currency: "EUR", Amount: 0}}, ledger.ErrInvalid},
		{"overflow", []ledger.PostingRecord{{AccountID: a, Currency: "EUR", Amount: math.MaxInt64}, {AccountID: a, Currency: "EUR", Amount: 1}}, ledger.ErrOverflow},
	}
	for _, c := range cases {
		if _, err := decompose(c.postings); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	// Legs that cancel out completely leave nothing to transfer.
	flows, err := decompose([]ledger.PostingRecord{{AccountID: a, Currency: "EUR", Amount: -7}, {AccountID: a, Currency: "EUR", Amount: 7}})
	if err != nil || len(flows) != 0 {
		t.Fatalf("self-cancelling entry: %v %v", flows, err)
	}
}

func testEntry(postings ...ledger.PostingRecord) ledger.Entry {
	return ledger.Entry{ID: ledger.NewID(), Kind: "p2p", CreatedAt: time.Now().UTC(), Postings: postings}
}

func TestEntryPlanIsOneLinkedChain(t *testing.T) {
	a, b, c := ledger.NewID(), ledger.NewID(), ledger.NewID()
	en := testEntry(
		ledger.PostingRecord{AccountID: a, Currency: "EUR", Amount: -300},
		ledger.PostingRecord{AccountID: b, Currency: "EUR", Amount: 100},
		ledger.PostingRecord{AccountID: c, Currency: "EUR", Amount: 200},
		ledger.PostingRecord{AccountID: b, Currency: "USD", Amount: -50},
		ledger.PostingRecord{AccountID: c, Currency: "USD", Amount: 50},
	)
	plan, err := entryPlan(en)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 3 {
		t.Fatalf("got %d transfers, want 3", len(plan))
	}
	ids := map[tb.Uint128]bool{}
	for i, tr := range plan {
		if tr.TransferFlags().Linked != (i < len(plan)-1) {
			t.Fatalf("transfer %d linked=%v", i, tr.TransferFlags().Linked)
		}
		if tr.UserData128 != ToU128(en.ID) || tr.Code != entryCode("p2p") || tr.Amount.BigInt().Sign() <= 0 {
			t.Fatalf("transfer %d fields: %+v", i, tr)
		}
		if ids[tr.ID] {
			t.Fatal("duplicate transfer id")
		}
		ids[tr.ID] = true
	}
	if plan[0].Ledger != 978 || plan[2].Ledger != 840 {
		t.Fatalf("ledgers %d, %d", plan[0].Ledger, plan[2].Ledger)
	}
	held := ledger.NewID()
	en.HoldID = &held
	if _, err := entryPlan(en); !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("entry plan accepted a hold entry: %v", err)
	}
	if _, err := fallbackPlan(testEntry()); !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("fallback plan accepted a plain entry: %v", err)
	}
	if _, err := entryPlan(testEntry(ledger.PostingRecord{AccountID: a, Currency: "XXX", Amount: -1},
		ledger.PostingRecord{AccountID: b, Currency: "XXX", Amount: 1})); !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("unknown currency: %v", err)
	}
}

func TestHoldPlanTimeoutCoversExpiryPlusGrace(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	h := ledger.Hold{ID: ledger.NewID(), AccountID: ledger.NewID(), Currency: "EUR", Amount: 900}
	cases := []struct {
		expires time.Time
		grace   time.Duration
		want    uint32
	}{
		{now.Add(90 * time.Second), time.Hour, 3690},
		{now.Add(1500 * time.Millisecond), 0, 2},   // rounded up
		{now.Add(-2 * time.Hour), time.Hour, 3600}, // replaying an old hold still gets the grace
		{now.Add(-2 * time.Hour), 0, 1},
		{now.Add(200 * 365 * 24 * time.Hour), time.Hour, math.MaxUint32},
	}
	for _, c := range cases {
		h.ExpiresAt = c.expires
		tr, err := holdPlan(h, now, c.grace)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Timeout != c.want {
			t.Errorf("expires %s grace %s: timeout %d, want %d", c.expires.Sub(now), c.grace, tr.Timeout, c.want)
		}
		if !tr.TransferFlags().Pending || tr.ID != ToU128(h.ID) || tr.CreditAccountID != HoldControlID("EUR") ||
			tr.DebitAccountID != ToU128(h.AccountID) || tr.Amount != tb.ToUint128(900) || tr.Code != codeHold {
			t.Fatalf("hold transfer fields: %+v", tr)
		}
	}
	h.Amount = 0
	if _, err := holdPlan(h, now, 0); !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("zero hold: %v", err)
	}
}

func TestHoldPostPlanPostsThenPaysFromControl(t *testing.T) {
	payer, merchant, fee := ledger.NewID(), ledger.NewID(), ledger.NewID()
	holdID := ledger.NewID()
	en := testEntry(
		ledger.PostingRecord{AccountID: payer, Currency: "EUR", Amount: -700},
		ledger.PostingRecord{AccountID: merchant, Currency: "EUR", Amount: 650},
		ledger.PostingRecord{AccountID: fee, Currency: "EUR", Amount: 50},
	)
	en.HoldID = &holdID
	plan, err := holdPostPlan(en)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 3 {
		t.Fatalf("got %d transfers", len(plan))
	}
	post := plan[0]
	if !post.TransferFlags().PostPendingTransfer || !post.TransferFlags().Linked || post.PendingID != ToU128(holdID) ||
		post.Amount != tb.ToUint128(700) || post.DebitAccountID != ToU128(payer) || post.CreditAccountID != HoldControlID("EUR") {
		t.Fatalf("post transfer: %+v", post)
	}
	var paid int64
	for i, tr := range plan[1:] {
		if tr.DebitAccountID != HoldControlID("EUR") {
			t.Fatalf("credit %d not paid from the control account", i)
		}
		paid += int64(tr.Amount.BigInt().Uint64())
	}
	if paid != 700 || plan[2].TransferFlags().Linked {
		t.Fatalf("paid %d; last linked=%v", paid, plan[2].TransferFlags().Linked)
	}
	fb, err := fallbackPlan(en)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range fb {
		if tr.DebitAccountID != ToU128(payer) || tr.TransferFlags().PostPendingTransfer {
			t.Fatalf("fallback transfer: %+v", tr)
		}
		for _, p := range plan {
			if p.ID == tr.ID {
				t.Fatal("fallback reuses a post-plan id")
			}
		}
	}

	bad := []ledger.Entry{
		testEntry(ledger.PostingRecord{AccountID: merchant, Currency: "EUR", Amount: 5}),
		testEntry(ledger.PostingRecord{AccountID: payer, Currency: "EUR", Amount: -5}, ledger.PostingRecord{AccountID: fee, Currency: "EUR", Amount: -5},
			ledger.PostingRecord{AccountID: merchant, Currency: "EUR", Amount: 10}),
		testEntry(ledger.PostingRecord{AccountID: payer, Currency: "EUR", Amount: -5}, ledger.PostingRecord{AccountID: merchant, Currency: "USD", Amount: 5}),
	}
	for i, b := range bad {
		b.HoldID = &holdID
		if _, err := holdPostPlan(b); err == nil {
			t.Errorf("malformed hold entry %d accepted", i)
		}
	}
	if _, err := holdPostPlan(testEntry()); !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("plain entry as hold post: %v", err)
	}
}

func TestVoidAndOpeningPlans(t *testing.T) {
	h := ledger.Hold{ID: ledger.NewID(), AccountID: ledger.NewID(), Currency: "USD", Amount: 42}
	v, err := voidPlan(h)
	if err != nil {
		t.Fatal(err)
	}
	if !v.TransferFlags().VoidPendingTransfer || v.PendingID != ToU128(h.ID) || v.Amount != tb.ToUint128(42) || v.ID == ToU128(h.ID) {
		t.Fatalf("void transfer: %+v", v)
	}
	a := ledger.Account{ID: ledger.NewID(), Kind: ledger.KindNostro, Currency: "USD"}
	if plan, err := openingPlan(a, 0); err != nil || plan != nil {
		t.Fatalf("zero opening: %v %v", plan, err)
	}
	pos, err := openingPlan(a, 500)
	if err != nil || pos[0].CreditAccountID != ToU128(a.ID) || pos[0].DebitAccountID != OpeningControlID("USD") {
		t.Fatalf("positive opening: %+v %v", pos, err)
	}
	neg, err := openingPlan(a, -500)
	if err != nil || neg[0].DebitAccountID != ToU128(a.ID) || neg[0].Amount != tb.ToUint128(500) || neg[0].ID != pos[0].ID {
		t.Fatalf("negative opening: %+v %v", neg, err)
	}
	if _, err := openingPlan(a, math.MinInt64); !errors.Is(err, ledger.ErrOverflow) {
		t.Fatalf("min int opening: %v", err)
	}
}

func TestAccountPlanFloorPolicy(t *testing.T) {
	owner := ledger.NewID()
	floor := func(v int64) *int64 { return &v }
	base := ledger.Account{ID: ledger.NewID(), Kind: ledger.KindUser, Currency: "EUR", OwnerID: &owner, CreatedAt: time.Now()}

	a := base
	acct, funding, err := accountPlan(a)
	if err != nil || acct.AccountFlags().DebitsMustNotExceedCredits || len(funding) != 0 {
		t.Fatalf("unbounded account: %+v %v %v", acct, funding, err)
	}
	if acct.UserData128 != ToU128(owner) || acct.Code != ledger.KindUser.Code() || acct.Ledger != 978 || !acct.AccountFlags().History {
		t.Fatalf("account fields: %+v", acct)
	}
	a.Floor = floor(0)
	if acct, funding, err = accountPlan(a); err != nil || !acct.AccountFlags().DebitsMustNotExceedCredits || len(funding) != 0 {
		t.Fatalf("floor 0: %+v %v %v", acct, funding, err)
	}
	a.Floor = floor(-500)
	acct, funding, err = accountPlan(a)
	if err != nil || !acct.AccountFlags().DebitsMustNotExceedCredits || len(funding) != 1 {
		t.Fatalf("floor -500: %+v %v %v", acct, funding, err)
	}
	if funding[0].Amount != tb.ToUint128(500) || funding[0].DebitAccountID != LimitControlID("EUR") || funding[0].CreditAccountID != acct.ID {
		t.Fatalf("limit funding: %+v", funding[0])
	}
	a.Floor = floor(10)
	if _, _, err := accountPlan(a); !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("positive floor: %v", err)
	}
	a = base
	a.Kind = "bogus"
	if _, _, err := accountPlan(a); !errors.Is(err, ledger.ErrInvalid) {
		t.Fatalf("unknown kind: %v", err)
	}
}

func results(statuses ...tb.CreateTransferStatus) []tb.CreateTransferResult {
	out := make([]tb.CreateTransferResult, len(statuses))
	for i, s := range statuses {
		out[i] = tb.CreateTransferResult{Status: s}
	}
	return out
}

func TestClassifyChainResults(t *testing.T) {
	cases := []struct {
		name    string
		in      []tb.CreateTransferResult
		want    chainOutcome
		wantErr error
	}{
		{"created", results(tb.TransferCreated, tb.TransferCreated), chainCreated, nil},
		{"single replay", results(tb.TransferExists), chainReplayed, nil},
		{"chain replay", results(tb.TransferExists, tb.TransferLinkedEventFailed, tb.TransferLinkedEventFailed), chainIndefinite, nil},
		{"replay detected mid-chain", results(tb.TransferLinkedEventFailed, tb.TransferExists, tb.TransferLinkedEventFailed), chainIndefinite, nil},
		{"insufficient funds", results(tb.TransferLinkedEventFailed, tb.TransferExceedsCredits), 0, ledger.ErrInsufficientFunds},
		{"missing account", results(tb.TransferDebitAccountNotFound, tb.TransferLinkedEventFailed), 0, ledger.ErrNotFound},
		{"burned id", results(tb.TransferIDAlreadyFailed), 0, ledger.ErrIdempotencyConflict},
		{"different amount", results(tb.TransferExistsWithDifferentAmount), 0, ledger.ErrIdempotencyConflict},
		{"expired hold", results(tb.TransferPendingTransferExpired), 0, ledger.ErrHoldExpired},
		{"posted hold", results(tb.TransferPendingTransferAlreadyPosted), 0, ledger.ErrHoldNotPending},
		{"currency", results(tb.TransferAccountsMustHaveTheSameLedger), 0, ledger.ErrCurrencyMismatch},
		{"overflow", results(tb.TransferOverflowsCreditsPosted), 0, ledger.ErrOverflow},
		{"void amount", results(tb.TransferPendingTransferHasDifferentAmount), 0, ledger.ErrInvalid},
	}
	for _, c := range cases {
		got, err := classify(c.in)
		if c.wantErr != nil {
			if !errors.Is(err, c.wantErr) {
				t.Errorf("%s: error %v, want %v", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %v %v, want %v", c.name, got, err, c.want)
		}
	}
	if _, err := classify(results(tb.TransferLinkedEventFailed)); err == nil {
		t.Error("a failed chain without a root cause was accepted")
	}
	if err := transferError(tb.TransferIDMustNotBeZero); err == nil {
		t.Error("unmapped status treated as success")
	}
}

func TestAccountErrorMapping(t *testing.T) {
	for _, s := range []tb.CreateAccountStatus{tb.AccountCreated, tb.AccountExists} {
		if err := accountError(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if err := accountError(tb.AccountExistsWithDifferentFlags); !errors.Is(err, ledger.ErrIdempotencyConflict) {
		t.Errorf("different flags: %v", err)
	}
	if err := accountError(tb.AccountLedgerMustNotBeZero); err == nil {
		t.Error("zero ledger accepted")
	}
}

func TestBalanceOfAdjustsForLimitsAndRejectsOverflow(t *testing.T) {
	floor := int64(-500)
	a := ledger.Account{ID: ledger.NewID(), Floor: &floor}
	acct := tb.Account{CreditsPosted: tb.ToUint128(800), DebitsPosted: tb.ToUint128(1000), DebitsPending: tb.ToUint128(40)}
	b, err := balanceOf(acct, a)
	if err != nil || b.Posted != -700 || b.Pending != 40 {
		t.Fatalf("balance %+v %v, want posted -700 pending 40", b, err)
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 70)
	acct = tb.Account{CreditsPosted: tb.BigIntToUint128(huge)}
	if _, err := balanceOf(acct, ledger.Account{}); !errors.Is(err, ledger.ErrOverflow) {
		t.Fatalf("overflow: %v", err)
	}
	limited := tb.Account{Flags: tb.AccountFlags{DebitsMustNotExceedCredits: true}.ToUint16(),
		CreditsPosted: tb.ToUint128(100), DebitsPosted: tb.ToUint128(30), DebitsPending: tb.ToUint128(20)}
	if v, ok := available(limited); !ok || v.Int64() != 50 {
		t.Fatalf("available %v %v", v, ok)
	}
	if _, ok := available(tb.Account{}); ok {
		t.Fatal("unlimited account reported a limit")
	}
}

func TestGapRangeArithmetic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		after := rapid.Int64Range(0, 50).Draw(t, "after")
		upto := after + rapid.Int64Range(0, 60).Draw(t, "span")
		present := map[int64]bool{}
		var ids []int64
		for id := after + 1; id <= upto; id++ {
			if rapid.Bool().Draw(t, "present") {
				present[id] = true
				ids = append(ids, id)
			}
		}
		gaps := missing(after, ids, upto)
		var absent []int64
		for _, r := range gaps {
			if r[0] > r[1] {
				t.Fatalf("empty range %v", r)
			}
			for id := r[0]; id <= r[1]; id++ {
				absent = append(absent, id)
			}
		}
		for id := after + 1; id <= upto; id++ {
			in := sort.Search(len(absent), func(i int) bool { return absent[i] >= id })
			isAbsent := in < len(absent) && absent[in] == id
			if isAbsent == present[id] {
				t.Fatalf("id %d: absent=%v present=%v", id, isAbsent, present[id])
			}
		}
		if len(absent) > 0 && !sort.SliceIsSorted(absent, func(i, j int) bool { return absent[i] < absent[j] }) {
			t.Fatal("gaps out of order")
		}
		if got := toRanges(absent); len(absent) > 0 && !equalRanges(got, gaps) {
			t.Fatalf("toRanges %v, missing %v", got, gaps)
		}
		// Removing a subset of the gap ids leaves exactly the others.
		var remove []int64
		for _, id := range absent {
			if rapid.Bool().Draw(t, "remove") {
				remove = append(remove, id)
			}
		}
		rest := without(gaps, remove)
		kept := only(gaps, remove)
		if count(rest)+count(kept) != int64(len(absent)) {
			t.Fatalf("without/only do not partition: %v %v of %v", rest, kept, gaps)
		}
		c := cursor{lastID: upto, gaps: []gapSet{{Ranges: rest}}}
		wantHorizon := upto
		if len(rest) > 0 {
			wantHorizon = rest[0][0] - 1
		}
		if c.horizon() != wantHorizon || c.gapCount() != count(rest) {
			t.Fatalf("horizon %d (want %d), gap count %d", c.horizon(), wantHorizon, c.gapCount())
		}
	})
}

func equalRanges(a, b [][2]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func count(rs [][2]int64) int64 {
	var n int64
	for _, r := range rs {
		n += r[1] - r[0] + 1
	}
	return n
}
