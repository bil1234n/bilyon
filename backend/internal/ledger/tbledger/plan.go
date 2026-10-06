// Package tbledger is the TigerBeetle driver for the Bilyon ledger
// (RFC 0001 §2.3.5). Phase 3 moves the balance hot path to TigerBeetle
// through shadow writes: committed PostgreSQL ledger events are replayed into
// TigerBeetle in serialization order (Tailer + Mirror), and balances are
// compared at exact snapshot cuts (Reconcile) for at least one month-end
// close before cutover.
//
// Mapping:
//   - account UUID -> TigerBeetle id (big-endian numeric value, so UUIDv7
//     time order becomes id order, which TigerBeetle's LSM tree prefers);
//     currency -> ledger (ISO 4217 numeric code); kind -> code.
//   - floor 0 -> flags.debits_must_not_exceed_credits; floor nil -> no flag;
//     floor -L -> the same flag plus an L pre-funding transfer from a
//     per-currency limit account, subtracted again when reporting balances.
//   - a balanced multi-leg entry -> net amounts per account, decomposed into
//     pairwise transfers per currency, all in one linked chain (atomic), with
//     ids derived from the entry id.
//   - a hold -> a pending transfer to a per-currency hold control account;
//     posting -> post_pending + control-to-credit transfers in one chain;
//     void/expiry -> void_pending.
//   - bootstrap balances -> one opening transfer per account against a
//     per-currency opening account.
//
// Every id is deterministic, so replaying an event is idempotent: TigerBeetle
// answers "exists" for an identical transfer.
package tbledger

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	tb "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
	"github.com/bil1234n/bilyon/backend/internal/money"
)

// Account and transfer codes for system objects. Account kinds use 1..14
// and entry kinds hash into [entryCodeBase, 65535], so the ranges never meet.
const (
	codeHoldControl    uint16 = 100
	codeLimitControl   uint16 = 101
	codeOpeningControl uint16 = 102
	codeHold           uint16 = 200
	codeLimitFunding   uint16 = 201
	codeOpening        uint16 = 202
	entryCodeBase      uint16 = 1000
)

// maxBatch is TigerBeetle's maximum events per request.
const maxBatch = 8189

var systemNamespace = uuid.MustParse("4f7e6a0c-2b1d-4c3e-9f80-1a2b3c4d5e6f")

// ToU128 converts a UUID to a TigerBeetle id, preserving numeric order.
func ToU128(id uuid.UUID) tb.Uint128 {
	var le [16]byte
	for i := range 16 {
		le[i] = id[15-i]
	}
	return tb.BytesToUint128(le)
}

// FromU128 is the inverse of ToU128.
func FromU128(v tb.Uint128) uuid.UUID {
	le := v.Bytes()
	var id uuid.UUID
	for i := range 16 {
		id[i] = le[15-i]
	}
	return id
}

// derivedID returns a deterministic transfer id for (base, purpose, index).
// It keeps the base id's top 64 bits (the UUIDv7 timestamp), so derived ids
// stay roughly time ordered, and hashes the rest.
func derivedID(base uuid.UUID, purpose string, index int) tb.Uint128 {
	h := fnv.New64a()
	h.Write(base[8:])
	h.Write([]byte(purpose))
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(index))
	h.Write(idx[:])
	var id uuid.UUID
	copy(id[:8], base[:8])
	binary.BigEndian.PutUint64(id[8:], h.Sum64())
	if id == uuid.Nil || id == uuid.Max {
		id[15] ^= 1 // 0 and 2^128-1 are reserved by TigerBeetle
	}
	return ToU128(id)
}

func systemAccountID(role, currency string) tb.Uint128 {
	return ToU128(uuid.NewSHA1(systemNamespace, []byte("bilyon/tb/"+role+"/"+currency)))
}

// HoldControlID is the per-currency account that pending holds credit.
func HoldControlID(currency string) tb.Uint128 { return systemAccountID("hold-control", currency) }

// LimitControlID is the per-currency account that pre-funds negative floors.
func LimitControlID(currency string) tb.Uint128 { return systemAccountID("limit-control", currency) }

// OpeningControlID is the per-currency counterparty of bootstrap balances.
func OpeningControlID(currency string) tb.Uint128 {
	return systemAccountID("opening-control", currency)
}

func ledgerOf(currency string) (uint32, error) {
	c, ok := money.Lookup(currency)
	if !ok {
		return 0, fmt.Errorf("%w: unsupported currency %q", ledger.ErrInvalid, currency)
	}
	return c.LedgerCode, nil
}

// entryCode maps a free-form entry kind to a transfer code >= entryCodeBase.
func entryCode(kind string) uint16 {
	h := fnv.New32a()
	h.Write([]byte(kind))
	span := uint32(math.MaxUint16) - uint32(entryCodeBase) + 1
	return entryCodeBase + uint16(h.Sum32()%span)
}

func amount(v int64) (tb.Uint128, error) {
	if v <= 0 {
		return tb.Uint128{}, fmt.Errorf("%w: non-positive amount %d", ledger.ErrInvalid, v)
	}
	return tb.ToUint128(uint64(v)), nil
}

// systemAccounts are the control accounts a currency needs. None has a
// balance limit: they absorb the other side of holds, limits and openings.
func systemAccounts(currency string) ([]tb.Account, error) {
	l, err := ledgerOf(currency)
	if err != nil {
		return nil, err
	}
	return []tb.Account{
		{ID: HoldControlID(currency), Ledger: l, Code: codeHoldControl},
		{ID: LimitControlID(currency), Ledger: l, Code: codeLimitControl},
		{ID: OpeningControlID(currency), Ledger: l, Code: codeOpeningControl},
	}, nil
}

// accountPlan maps a ledger account to TigerBeetle objects. A negative floor
// adds a pre-funding transfer that must commit after the account.
func accountPlan(a ledger.Account) (tb.Account, []tb.Transfer, error) {
	l, err := ledgerOf(a.Currency)
	if err != nil {
		return tb.Account{}, nil, err
	}
	code := a.Kind.Code()
	if code == 0 {
		return tb.Account{}, nil, fmt.Errorf("%w: unknown kind %q", ledger.ErrInvalid, a.Kind)
	}
	if a.Floor != nil && *a.Floor > 0 {
		return tb.Account{}, nil, fmt.Errorf("%w: positive floor %d on %s", ledger.ErrInvalid, *a.Floor, a.ID)
	}
	flags := tb.AccountFlags{History: true}
	if a.Floor != nil {
		flags.DebitsMustNotExceedCredits = true
	}
	acct := tb.Account{ID: ToU128(a.ID), Ledger: l, Code: code, Flags: flags.ToUint16(),
		UserData64: uint64(a.CreatedAt.UnixMicro())}
	if a.OwnerID != nil {
		acct.UserData128 = ToU128(*a.OwnerID)
	}
	var transfers []tb.Transfer
	if a.Floor != nil && *a.Floor < 0 {
		amt, err := amount(-*a.Floor)
		if err != nil {
			return tb.Account{}, nil, err
		}
		transfers = append(transfers, tb.Transfer{ID: derivedID(a.ID, "limit", 0), DebitAccountID: LimitControlID(a.Currency),
			CreditAccountID: acct.ID, Amount: amt, Ledger: l, Code: codeLimitFunding, UserData128: acct.ID})
	}
	return acct, transfers, nil
}

// flow is one pairwise movement produced by decompose.
type flow struct {
	debit, credit uuid.UUID
	currency      string
	amount        int64
}

// netLeg is an account's net delta within one entry.
type netLeg struct {
	account  uuid.UUID
	currency string
	amount   int64
}

// netPostings sums an entry's postings per (account, currency), dropping
// accounts whose legs cancel out. The result is sorted by currency, then
// account.
func netPostings(postings []ledger.PostingRecord) ([]netLeg, error) {
	type key struct {
		account  uuid.UUID
		currency string
	}
	sums := map[key]int64{}
	for _, p := range postings {
		if p.Amount == 0 {
			return nil, fmt.Errorf("%w: zero posting on %s", ledger.ErrInvalid, p.AccountID)
		}
		k := key{p.AccountID, p.Currency}
		v, err := money.Add(sums[k], p.Amount)
		if err != nil {
			return nil, fmt.Errorf("%w: net of %s", ledger.ErrOverflow, p.AccountID)
		}
		sums[k] = v
	}
	legs := make([]netLeg, 0, len(sums))
	for k, v := range sums {
		if v != 0 {
			legs = append(legs, netLeg{k.account, k.currency, v})
		}
	}
	sort.Slice(legs, func(i, j int) bool {
		if legs[i].currency != legs[j].currency {
			return legs[i].currency < legs[j].currency
		}
		return string(legs[i].account[:]) < string(legs[j].account[:])
	})
	return legs, nil
}

// decompose turns balanced postings into pairwise flows: per currency, net
// debit legs are matched greedily against net credit legs (both in account
// order), so n accounts produce at most n-1 flows, no flow has the same
// account on both sides, and the result is deterministic.
func decompose(postings []ledger.PostingRecord) ([]flow, error) {
	legs, err := netPostings(postings)
	if err != nil {
		return nil, err
	}
	var flows []flow
	for start := 0; start < len(legs); {
		end := start
		for end < len(legs) && legs[end].currency == legs[start].currency {
			end++
		}
		c := legs[start].currency
		var debits, credits []netLeg
		var dSum, cSum int64
		for _, l := range legs[start:end] {
			if l.amount < 0 {
				debits = append(debits, netLeg{l.account, c, -l.amount})
				if dSum, err = money.Add(dSum, -l.amount); err != nil {
					return nil, fmt.Errorf("%w: %s debits", ledger.ErrOverflow, c)
				}
			} else {
				credits = append(credits, l)
				if cSum, err = money.Add(cSum, l.amount); err != nil {
					return nil, fmt.Errorf("%w: %s credits", ledger.ErrOverflow, c)
				}
			}
		}
		if dSum != cSum {
			return nil, fmt.Errorf("%w: %s debits %d != credits %d", ledger.ErrUnbalanced, c, dSum, cSum)
		}
		i, j := 0, 0
		for i < len(debits) && j < len(credits) {
			m := min(debits[i].amount, credits[j].amount)
			flows = append(flows, flow{debit: debits[i].account, credit: credits[j].account, currency: c, amount: m})
			debits[i].amount -= m
			credits[j].amount -= m
			if debits[i].amount == 0 {
				i++
			}
			if credits[j].amount == 0 {
				j++
			}
		}
		start = end
	}
	return flows, nil
}

// link marks every transfer but the last as linked: one atomic chain.
func link(ts []tb.Transfer) {
	for i := range ts {
		f := ts[i].TransferFlags()
		f.Linked = i < len(ts)-1
		ts[i].Flags = f.ToUint16()
	}
}

// chainPlan maps an entry's postings to one linked chain of plain transfers
// whose ids are derived from (entry id, purpose).
func chainPlan(en ledger.Entry, purpose string) ([]tb.Transfer, error) {
	flows, err := decompose(en.Postings)
	if err != nil {
		return nil, err
	}
	if len(flows) > maxBatch {
		return nil, fmt.Errorf("%w: entry %s needs %d transfers", ledger.ErrInvalid, en.ID, len(flows))
	}
	ts := make([]tb.Transfer, 0, len(flows))
	for i, f := range flows {
		l, err := ledgerOf(f.currency)
		if err != nil {
			return nil, err
		}
		amt, err := amount(f.amount)
		if err != nil {
			return nil, err
		}
		ts = append(ts, tb.Transfer{ID: derivedID(en.ID, purpose, i), DebitAccountID: ToU128(f.debit),
			CreditAccountID: ToU128(f.credit), Amount: amt, Ledger: l, Code: entryCode(en.Kind),
			UserData128: ToU128(en.ID), UserData64: uint64(en.CreatedAt.UnixMicro())})
	}
	link(ts)
	return ts, nil
}

// entryPlan maps a plain entry (not a hold post) to one linked chain.
func entryPlan(en ledger.Entry) ([]tb.Transfer, error) {
	if en.HoldID != nil {
		return nil, fmt.Errorf("%w: entry %s settles hold %s; use holdPostPlan", ledger.ErrInvalid, en.ID, en.HoldID)
	}
	return chainPlan(en, "entry")
}

// fallbackPlan maps a hold-settling entry to plain transfers. It is used when
// TigerBeetle has already expired the pending transfer (the shadow lagged
// past the hold's grace), which released the reservation: moving the posted
// amount directly then yields the same balances as post_pending would have.
func fallbackPlan(en ledger.Entry) ([]tb.Transfer, error) {
	if en.HoldID == nil {
		return nil, fmt.Errorf("%w: entry %s does not settle a hold", ledger.ErrInvalid, en.ID)
	}
	return chainPlan(en, "fallback")
}

// holdPlan maps a placed hold to a pending transfer. The timeout is the
// hold's remaining life plus grace (and at least grace): PostgreSQL is
// authoritative and voids expired holds explicitly, so TigerBeetle must not
// expire them first, including while the shadow replays old events.
func holdPlan(h ledger.Hold, now time.Time, grace time.Duration) (tb.Transfer, error) {
	l, err := ledgerOf(h.Currency)
	if err != nil {
		return tb.Transfer{}, err
	}
	amt, err := amount(h.Amount)
	if err != nil {
		return tb.Transfer{}, err
	}
	timeout := max(h.ExpiresAt.Sub(now), 0) + grace
	secs := math.Ceil(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	if secs > math.MaxUint32 {
		secs = math.MaxUint32
	}
	return tb.Transfer{ID: ToU128(h.ID), DebitAccountID: ToU128(h.AccountID), CreditAccountID: HoldControlID(h.Currency),
		Amount: amt, Ledger: l, Code: codeHold, Timeout: uint32(secs), UserData128: ToU128(h.ID),
		Flags: tb.TransferFlags{Pending: true}.ToUint16()}, nil
}

// heldLeg returns a hold-settling entry's single debit leg (on the held
// account) after netting.
func heldLeg(en ledger.Entry) (netLeg, []netLeg, error) {
	legs, err := netPostings(en.Postings)
	if err != nil {
		return netLeg{}, nil, err
	}
	var held *netLeg
	var credits []netLeg
	for i := range legs {
		if legs[i].amount < 0 {
			if held != nil {
				return netLeg{}, nil, fmt.Errorf("%w: hold entry %s has several debit legs", ledger.ErrInvalid, en.ID)
			}
			held = &legs[i]
			continue
		}
		credits = append(credits, legs[i])
	}
	if held == nil {
		return netLeg{}, nil, fmt.Errorf("%w: hold entry %s has no debit leg", ledger.ErrInvalid, en.ID)
	}
	for _, c := range credits {
		if c.currency != held.currency {
			return netLeg{}, nil, fmt.Errorf("%w: hold entry %s mixes currencies", ledger.ErrCurrencyMismatch, en.ID)
		}
	}
	return *held, credits, nil
}

// holdPostPlan maps a hold-settling entry (one debit leg on the held
// account, credit legs elsewhere) to post_pending + control-to-credit
// transfers in one chain.
func holdPostPlan(en ledger.Entry) ([]tb.Transfer, error) {
	if en.HoldID == nil {
		return nil, fmt.Errorf("%w: entry %s does not settle a hold", ledger.ErrInvalid, en.ID)
	}
	held, credits, err := heldLeg(en)
	if err != nil {
		return nil, err
	}
	l, err := ledgerOf(held.currency)
	if err != nil {
		return nil, err
	}
	posted, err := amount(-held.amount)
	if err != nil {
		return nil, err
	}
	control := HoldControlID(held.currency)
	ts := []tb.Transfer{{ID: derivedID(*en.HoldID, "post", 0), PendingID: ToU128(*en.HoldID),
		DebitAccountID: ToU128(held.account), CreditAccountID: control, Amount: posted, Ledger: l, Code: codeHold,
		UserData128: ToU128(en.ID), Flags: tb.TransferFlags{PostPendingTransfer: true}.ToUint16()}}
	for i, c := range credits {
		amt, err := amount(c.amount)
		if err != nil {
			return nil, err
		}
		ts = append(ts, tb.Transfer{ID: derivedID(en.ID, "entry", i), DebitAccountID: control,
			CreditAccountID: ToU128(c.account), Amount: amt, Ledger: l, Code: entryCode(en.Kind),
			UserData128: ToU128(en.ID), UserData64: uint64(en.CreatedAt.UnixMicro())})
	}
	link(ts)
	return ts, nil
}

// voidPlan voids a hold's pending transfer.
func voidPlan(h ledger.Hold) (tb.Transfer, error) {
	l, err := ledgerOf(h.Currency)
	if err != nil {
		return tb.Transfer{}, err
	}
	amt, err := amount(h.Amount)
	if err != nil {
		return tb.Transfer{}, err
	}
	return tb.Transfer{ID: derivedID(h.ID, "void", 0), PendingID: ToU128(h.ID), DebitAccountID: ToU128(h.AccountID),
		CreditAccountID: HoldControlID(h.Currency), Amount: amt, Ledger: l, Code: codeHold, UserData128: ToU128(h.ID),
		Flags: tb.TransferFlags{VoidPendingTransfer: true}.ToUint16()}, nil
}

// openingPlan sets an account's bootstrap posted balance with one transfer
// against the currency's opening account. A zero balance needs none.
func openingPlan(a ledger.Account, posted int64) ([]tb.Transfer, error) {
	if posted == 0 {
		return nil, nil
	}
	l, err := ledgerOf(a.Currency)
	if err != nil {
		return nil, err
	}
	t := tb.Transfer{ID: derivedID(a.ID, "opening", 0), Ledger: l, Code: codeOpening, UserData128: ToU128(a.ID)}
	if posted > 0 {
		t.DebitAccountID, t.CreditAccountID = OpeningControlID(a.Currency), ToU128(a.ID)
		t.Amount, err = amount(posted)
	} else {
		if posted == math.MinInt64 {
			return nil, fmt.Errorf("%w: opening balance of %s", ledger.ErrOverflow, a.ID)
		}
		t.DebitAccountID, t.CreditAccountID = ToU128(a.ID), OpeningControlID(a.Currency)
		t.Amount, err = amount(-posted)
	}
	if err != nil {
		return nil, err
	}
	return []tb.Transfer{t}, nil
}
