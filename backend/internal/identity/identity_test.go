package identity_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
	"github.com/bil1234n/bilyon/backend/internal/identity"
	"github.com/bil1234n/bilyon/backend/internal/identity/tlog"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/gatewaydb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
	"github.com/bil1234n/bilyon/backend/internal/webauthn"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, gatewaydb.Setup, &srv)) }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

type fixture struct {
	t      *testing.T
	pool   *pgxpool.Pool
	svc    *identity.Service
	signer *cose.KeySigner
	users  []uuid.UUID

	mu    sync.Mutex
	clock time.Time
}

func (f *fixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(d)
}

func newFixture(t *testing.T, users int) *fixture {
	t.Helper()
	t.Parallel()
	f := &fixture{t: t, pool: srv.Database(t), clock: time.Now().UTC().Truncate(time.Second)}
	signer, err := cose.GenerateKeySigner()
	if err != nil {
		t.Fatal(err)
	}
	f.signer = signer
	if f.svc, err = identity.New(identity.Config{Signer: signer, KeyID: []byte("dir-2026"), Now: f.now}, f.pool); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.EnsureReserved(ctx(t)); err != nil {
		t.Fatal(err)
	}
	store := webauthn.NewPGStore(f.pool)
	for range users {
		u, err := store.CreateUser(ctx(t), "user")
		if err != nil {
			t.Fatal(err)
		}
		f.users = append(f.users, u.ID)
	}
	return f
}

func (f *fixture) verify(par *identity.PAR) *identity.PAR {
	f.t.Helper()
	v, err := identity.VerifyPAR(par.Raw, f.svc.Keys(), f.now())
	if err != nil {
		f.t.Fatalf("PAR does not verify: %v", err)
	}
	return v
}

func compressedKey(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := cose.CompressP256(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestClaimResolveAndVerify(t *testing.T) {
	f := newFixture(t, 3)
	alice, bob, carol := f.users[0], f.users[1], f.users[2]
	h, e, err := f.svc.ClaimHandle(ctx(t), alice, "@Alice")
	if err != nil {
		t.Fatal(err)
	}
	if h.Key != "alice" || e.Version != 1 || e.Handle != "alice" || e.Display.Handle != "Alice" || !identity.ValidSubject(e.Subject) {
		t.Fatalf("claim %+v %+v", h, e)
	}
	avatar := sha256.Sum256([]byte("avatar"))
	keys := []identity.PublicKey{{KID: "k7", Use: identity.UseP2PBinding, Pub: compressedKey(t)},
		{KID: "k8", Use: identity.UseMemoEncryption, Pub: compressedKey(t)}}
	e2, err := f.svc.UpdateProfile(ctx(t), alice, identity.Profile{Name: "Alice M.", AvatarSHA256: avatar[:],
		Currencies: []string{"EUR", "USD"}, DefaultCurrency: "EUR", Keys: keys})
	if err != nil || e2.Version != 2 || e2.Handle != "alice" {
		t.Fatalf("profile %+v, %v", e2, err)
	}
	e3, err := f.svc.SetVerified(ctx(t), alice, []string{"kyc"})
	if err != nil || e3.Version != 3 {
		t.Fatalf("verified %+v, %v", e3, err)
	}
	if again, err := f.svc.SetVerified(ctx(t), alice, []string{"kyc"}); err != nil || again.Version != 3 {
		t.Fatalf("an unchanged entry got a new version: %+v, %v", again, err)
	}

	par, err := f.svc.Resolve(ctx(t), "alice")
	if err != nil {
		t.Fatal(err)
	}
	v := f.verify(par)
	en := v.Entry
	switch {
	case en.Subject != e.Subject || en.Version != 3 || en.Handle != "alice" || en.Display.Name != "Alice M.":
		t.Fatalf("entry %+v", en)
	case len(en.Keys) != 2 || en.Keys[0].KID != "k7" || string(en.Keys[1].Pub) != string(keys[1].Pub):
		t.Fatalf("keys %+v", en.Keys)
	case en.DefaultCurrency != "EUR" || len(en.Currencies) != 2 || len(en.Display.Verified) != 1:
		t.Fatalf("receive %+v", en)
	case v.ExpiresAt.Sub(v.IssuedAt) != 10*time.Minute || v.TreeHead.Size != 3 || v.LeafIndex != 2:
		t.Fatalf("record %+v", v)
	}
	// Lookalikes resolve to the real owner (the only one who can hold them).
	for _, lookalike := range []string{"ALICE", "\u0430lice", "@al\u200dice"} {
		p, err := f.svc.Resolve(ctx(t), lookalike)
		if err != nil || f.verify(p).Entry.Subject != e.Subject {
			t.Fatalf("Resolve(%q) = %v", lookalike, err)
		}
	}
	if _, err := f.svc.Resolve(ctx(t), "nobody"); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("unknown handle: %v", err)
	}
	if _, err := f.svc.Resolve(ctx(t), "@"); !errors.Is(err, identity.ErrRequest) {
		t.Fatalf("invalid handle: %v", err)
	}
	// Nobody else can take a confusable of a held handle, even a whole-script
	// one: all-Cyrillic "ѕсоре" passes the script policy but shares the
	// skeleton of "scope".
	if _, _, err := f.svc.ClaimHandle(ctx(t), bob, "scope"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ClaimHandle(ctx(t), carol, "\u0455\u0441\u043e\u0440\u0435"); !errors.Is(err, identity.ErrTaken) {
		t.Fatalf("whole-script lookalike claim: %v", err)
	}
	if v, err := f.svc.CurrentVersion(ctx(t), e.Subject); err != nil || v != 3 {
		t.Fatalf("CurrentVersion = %d, %v", v, err)
	}
	if identity.PayeeRef(e.Subject) == identity.PayeeRef(e2.Subject+"x") || identity.PayeeRef(e.Subject) != identity.PayeeRef(e.Subject) {
		t.Fatal("PayeeRef must be a function of the subject")
	}
}

func TestPARVerificationFailures(t *testing.T) {
	f := newFixture(t, 1)
	if _, _, err := f.svc.ClaimHandle(ctx(t), f.users[0], "carol"); err != nil {
		t.Fatal(err)
	}
	par, err := f.svc.Resolve(ctx(t), "carol")
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, par.Raw...)
	tampered[len(tampered)-10] ^= 1
	if _, err := identity.VerifyPAR(tampered, f.svc.Keys(), f.now()); !errors.Is(err, identity.ErrPAR) {
		t.Fatalf("tampered PAR: %v", err)
	}
	other, _ := cose.GenerateKeySigner()
	otherKeys := func([]byte) (*ecdsa.PublicKey, error) { return other.Public(), nil }
	if _, err := identity.VerifyPAR(par.Raw, otherKeys, f.now()); !errors.Is(err, identity.ErrPAR) {
		t.Fatalf("PAR under another key: %v", err)
	}
	if _, err := identity.VerifyPAR(par.Raw, f.svc.Keys(), f.now().Add(11*time.Minute)); !errors.Is(err, identity.ErrPAR) {
		t.Fatalf("expired PAR: %v", err)
	}
	if _, err := identity.VerifyPAR(par.Raw, f.svc.Keys(), f.now().Add(-2*time.Minute)); !errors.Is(err, identity.ErrPAR) {
		t.Fatalf("PAR from the future: %v", err)
	}
	// A directory that signs records the log does not back is caught: each
	// forgery below carries a valid K_dir signature.
	f.users = append(f.users, func() uuid.UUID {
		u, err := webauthn.NewPGStore(f.pool).CreateUser(ctx(t), "dan")
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}())
	if _, _, err := f.svc.ClaimHandle(ctx(t), f.users[1], "dan"); err != nil {
		t.Fatal(err)
	}
	danPAR, err := f.svc.Resolve(ctx(t), "dan")
	if err != nil {
		t.Fatal(err)
	}
	payloadOf := func(raw []byte) cbor.Map {
		msg, err := cose.Parse1(raw)
		if err != nil {
			t.Fatal(err)
		}
		v, err := cbor.Decode(msg.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return v.(cbor.Map)
	}
	forge := func(edit func(m cbor.Map)) []byte {
		m := payloadOf(par.Raw)
		edit(m)
		raw, err := cose.Sign1(f.signer, []byte("dir-2026"), cbor.MustEncode(m), identity.PARContext)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	otherSTH, err := tlog.SignTreeHead(other, []byte("dir-2026"), par.TreeHead)
	if err != nil {
		t.Fatal(err)
	}
	forgeries := map[string]func(m cbor.Map){
		"another entry at carol's index": func(m cbor.Map) { m["entry"] = danPAR.EntryRaw },
		"another leaf index": func(m cbor.Map) {
			m["tlog"].(cbor.Map)["leaf_index"] = uint64(1)
		},
		"another tree size": func(m cbor.Map) {
			m["tlog"].(cbor.Map)["tree_size"] = par.TreeHead.Size + 1
		},
		"tree head signed by another key": func(m cbor.Map) { m["tlog"].(cbor.Map)["sth"] = otherSTH },
		"tree head of a later tree": func(m cbor.Map) {
			m["tlog"].(cbor.Map)["sth"] = danPAR.STH
			m["tlog"].(cbor.Map)["tree_size"] = danPAR.TreeHead.Size
		},
		"padded inclusion proof": func(m cbor.Map) { m["tlog"].(cbor.Map)["inclusion"] = []any{make([]byte, 32)} },
		"unknown member":         func(m cbor.Map) { m["note"] = "x" },
	}
	for name, edit := range forgeries {
		if _, err := identity.VerifyPAR(forge(edit), f.svc.Keys(), f.now()); !errors.Is(err, identity.ErrPAR) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := identity.VerifyPAR(forge(func(cbor.Map) {}), f.svc.Keys(), f.now()); err != nil {
		t.Fatalf("an unmodified re-signed record must verify: %v", err)
	}
}

func TestHandleChangePolicy(t *testing.T) {
	f := newFixture(t, 2)
	alice, bob := f.users[0], f.users[1]
	if _, _, err := f.svc.ClaimHandle(ctx(t), alice, "alice"); err != nil {
		t.Fatal(err)
	}
	// A display-case change is always allowed.
	if _, e, err := f.svc.ClaimHandle(ctx(t), alice, "ALICE"); err != nil || e.Display.Handle != "ALICE" || e.Version != 2 {
		t.Fatalf("display change: %+v %v", e, err)
	}
	if _, e, err := f.svc.ClaimHandle(ctx(t), alice, "ALICE"); err != nil || e.Version != 2 {
		t.Fatalf("idempotent claim: %+v %v", e, err)
	}
	if _, _, err := f.svc.ClaimHandle(ctx(t), alice, "alicia"); !errors.Is(err, identity.ErrTooSoon) {
		t.Fatalf("change within 30 days: %v", err)
	}
	f.advance(31 * 24 * time.Hour)
	if _, _, err := f.svc.ClaimHandle(ctx(t), alice, "alicia"); err != nil {
		t.Fatal(err)
	}
	// The old handle is quarantined for alice.
	if _, _, err := f.svc.ClaimHandle(ctx(t), bob, "alice"); !errors.Is(err, identity.ErrTaken) {
		t.Fatalf("quarantined handle claimed by someone else: %v", err)
	}
	if _, err := f.svc.Resolve(ctx(t), "alice"); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("a released handle still resolves: %v", err)
	}
	// alice may reclaim it (after the change interval).
	f.advance(31 * 24 * time.Hour)
	if _, _, err := f.svc.ClaimHandle(ctx(t), alice, "alice"); err != nil {
		t.Fatalf("owner reclaiming a quarantined handle: %v", err)
	}
	// After a release and the quarantine period, anyone may claim it.
	f.advance(31 * 24 * time.Hour)
	if _, err := f.svc.ReleaseHandle(ctx(t), alice); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReleaseHandle(ctx(t), alice); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("second release: %v", err)
	}
	f.advance(89 * 24 * time.Hour)
	if _, _, err := f.svc.ClaimHandle(ctx(t), bob, "alice"); !errors.Is(err, identity.ErrTaken) {
		t.Fatalf("claim during quarantine: %v", err)
	}
	f.advance(2 * 24 * time.Hour)
	if _, _, err := f.svc.ClaimHandle(ctx(t), bob, "alice"); err != nil {
		t.Fatalf("claim after quarantine: %v", err)
	}
	// Reserved names and their lookalikes.
	for _, name := range []string{"admin", "Bilyon", "bi1yon", "supp0rt", "@PAY"} {
		if _, _, err := f.svc.ClaimHandle(ctx(t), alice, name); !errors.Is(err, identity.ErrReserved) {
			t.Errorf("reserved %q: %v", name, err)
		}
	}
	if err := f.svc.Reserve(ctx(t), "acme", "brand"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ClaimHandle(ctx(t), alice, "ACME"); !errors.Is(err, identity.ErrReserved) {
		t.Fatalf("operator reservation: %v", err)
	}
	if err := f.svc.Reserve(ctx(t), "", "x"); !errors.Is(err, identity.ErrRequest) {
		t.Fatalf("empty reservation: %v", err)
	}
	if _, _, err := f.svc.ClaimHandle(ctx(t), uuid.New(), "zed_99"); !errors.Is(err, identity.ErrRequest) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestProfileValidation(t *testing.T) {
	f := newFixture(t, 1)
	u := f.users[0]
	bad := map[string]identity.Profile{
		"default not received": {Currencies: []string{"EUR"}, DefaultCurrency: "USD"},
		"bad currency":         {Currencies: []string{"euro"}},
		"bad avatar hash":      {AvatarSHA256: []byte{1, 2, 3}},
		"bad key use":          {Keys: []identity.PublicKey{{KID: "k1", Use: "signing", Pub: compressedKey(t)}}},
		"uncompressed key":     {Keys: []identity.PublicKey{{KID: "k1", Use: identity.UseP2PBinding, Pub: make([]byte, 65)}}},
		"not a curve point": {Keys: []identity.PublicKey{{KID: "k1", Use: identity.UseP2PBinding,
			Pub: append([]byte{0x02}, bytes.Repeat([]byte{0xff}, 32)...)}}},
		"duplicate kid": {Keys: []identity.PublicKey{{KID: "k1", Use: identity.UseP2PBinding, Pub: compressedKey(t)},
			{KID: "k1", Use: identity.UseMemoEncryption, Pub: compressedKey(t)}}},
		"long name": {Name: string(make([]byte, 65))},
	}
	for name, p := range bad {
		if _, err := f.svc.UpdateProfile(ctx(t), u, p); !errors.Is(err, identity.ErrEntry) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := f.svc.SetVerified(ctx(t), u, []string{"Not A Badge"}); !errors.Is(err, identity.ErrEntry) {
		t.Errorf("bad badge: %v", err)
	}
	// None of the refused updates reached the log.
	if size, err := f.svc.Log().Size(ctx(t)); err != nil || size != 0 {
		t.Fatalf("log size %d, %v", size, err)
	}
	// A subject without a handle still has an entry and a PAR.
	e, err := f.svc.UpdateProfile(ctx(t), u, identity.Profile{Name: "No Handle", Currencies: []string{"NGN"}})
	if err != nil {
		t.Fatal(err)
	}
	par, err := f.svc.ResolveSubject(ctx(t), e.Subject)
	if err != nil || f.verify(par).Entry.Display.Name != "No Handle" {
		t.Fatalf("ResolveSubject = %v", err)
	}
	if _, err := f.svc.ResolveSubject(ctx(t), "bil_AAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("unknown subject: %v", err)
	}
	if _, err := f.svc.ResolveSubject(ctx(t), "user-1"); !errors.Is(err, identity.ErrRequest) {
		t.Fatalf("malformed subject: %v", err)
	}
}

// TestTransparency checks the log a client and an auditor see: every
// change is logged in order, tree heads are consistent, and every PAR's
// inclusion proof is against a published head.
func TestTransparency(t *testing.T) {
	f := newFixture(t, 3)
	var subjects []string
	for i, name := range []string{"dave", "erin", "frank"} {
		_, e, err := f.svc.ClaimHandle(ctx(t), f.users[i], name)
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, e.Subject)
	}
	first, err := f.svc.PublishTreeHead(ctx(t))
	if err != nil || first.Size != 3 {
		t.Fatalf("first head %+v, %v", first, err)
	}
	for i := range 3 {
		if _, err := f.svc.UpdateProfile(ctx(t), f.users[i], identity.Profile{Name: "n", Currencies: []string{"EUR"}}); err != nil {
			t.Fatal(err)
		}
	}
	// Resolving a changed entry signs a newer head that covers it.
	par, err := f.svc.Resolve(ctx(t), "frank")
	if err != nil {
		t.Fatal(err)
	}
	v := f.verify(par)
	if v.TreeHead.Size != 6 || v.LeafIndex != 5 {
		t.Fatalf("PAR head %d leaf %d", v.TreeHead.Size, v.LeafIndex)
	}
	proof, err := f.svc.Log().ConsistencyProof(ctx(t), first.Size, v.TreeHead.Size)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.VerifyConsistency(first.Size, v.TreeHead.Size, first.Root, v.TreeHead.Root, proof); err != nil {
		t.Fatalf("heads are not consistent: %v", err)
	}
	// An auditor replays the log.
	entries, err := f.svc.Entries(ctx(t), 0, 100)
	if err != nil || len(entries) != 6 {
		t.Fatalf("Entries = %d, %v", len(entries), err)
	}
	ref := tlog.NewTree()
	for i, e := range entries {
		raw, err := e.Encode()
		if err != nil {
			t.Fatal(err)
		}
		ref.Append(raw)
		if e.Subject != subjects[i%3] || e.Version != uint64(1+i/3) {
			t.Fatalf("entry %d: %s v%d", i, e.Subject, e.Version)
		}
	}
	if root, _ := ref.Root(6); root != v.TreeHead.Root {
		t.Fatal("the replayed log does not match the signed head")
	}
	var events int
	if err := f.pool.QueryRow(ctx(t), `SELECT count(*) FROM outbox WHERE topic = $1`, identity.TopicEntryUpdated).Scan(&events); err != nil || events != 6 {
		t.Fatalf("%d entry events, %v", events, err)
	}
}

func TestConcurrentClaims(t *testing.T) {
	f := newFixture(t, 6)
	var wg sync.WaitGroup
	errs := make([]error, len(f.users))
	names := []string{"milo", "MILO", "rnilo", "mi1o", "Milo", "rni1o"} // one skeleton
	for i, u := range f.users {
		wg.Go(func() { _, _, errs[i] = f.svc.ClaimHandle(context.Background(), u, names[i]) })
	}
	wg.Wait()
	won := 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, identity.ErrTaken):
			t.Fatalf("claim %d: %v", i, err)
		}
	}
	if won != 1 {
		t.Fatalf("%d users hold the same skeleton", won)
	}
}

func TestSubjects(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 1000 {
		s, err := identity.NewSubject()
		if err != nil || !identity.ValidSubject(s) || seen[s] {
			t.Fatalf("NewSubject = %q, %v", s, err)
		}
		seen[s] = true
	}
	for _, bad := range []string{"bil_", "bil_0123456789ABCDEFGHI", "bil_0123456789ABCDEFGHIL", "usr_0123456789ABCDEFGHJK"} {
		if identity.ValidSubject(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
