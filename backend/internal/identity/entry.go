// Package identity is the payee directory (RFC 0001 §4.1): handles as
// payment addresses, stable opaque subjects, versioned directory entries
// committed to a transparency log, and Payment Address Records signed by
// K_dir that clients verify end to end.
package identity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/bil1234n/bilyon/backend/internal/cbor"
	"github.com/bil1234n/bilyon/backend/internal/cose"
)

// EntryVersion is the directory entry format version.
const EntryVersion = 1

// Key uses a directory entry may publish.
const (
	UseP2PBinding     = "p2p-binding"     // verify the payee's device certificate in offline and P2P handshakes
	UseMemoEncryption = "memo-encryption" // end-to-end encrypted payment memos
)

// crockford is Crockford's base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	subjectPattern  = regexp.MustCompile(`^bil_[0-9A-HJKMNP-TV-Z]{20}$`)
	currencyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{2,7}$`)
	kidPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	badgePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)
)

// NewSubject returns a fresh subject: "bil_" and 100 random bits in
// Crockford base32. A subject is an opaque, stable payee reference that
// never encodes an account number.
func NewSubject() (string, error) {
	raw := make([]byte, 13)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := []byte("bil_")
	var acc uint64
	bitsHeld := 0
	for _, b := range raw {
		acc = acc<<8 | uint64(b)
		bitsHeld += 8
		for bitsHeld >= 5 && len(out) < 24 {
			bitsHeld -= 5
			out = append(out, crockford[(acc>>bitsHeld)&31])
		}
	}
	return string(out), nil
}

// ValidSubject reports whether s is a well-formed subject.
func ValidSubject(s string) bool { return subjectPattern.MatchString(s) }

// PayeeRef is the payee reference a TxAuth binds (RFC 0001 §2.2.5, §4.1.4):
// a tagged hash of the subject.
func PayeeRef(subject string) [32]byte { return cose.TaggedHash("bilyon/payee/v1", []byte(subject)) }

// Display is how the payee is shown.
type Display struct {
	Handle       string   // display form, without "@"; empty without a handle
	Name         string   // display name
	AvatarSHA256 []byte   // hash of the avatar image, or nil
	Verified     []string // badges, e.g. "kyc"
}

// Alias is a linked social identity: the provider's stable id, and the
// @name shown for it (re-validated, never followed).
type Alias struct {
	Provider  string
	UID       string
	Handle    string
	CheckedAt time.Time
}

// PublicKey is a published device key.
type PublicKey struct {
	KID string
	Use string
	Pub []byte // compressed P-256 point (33 bytes)
}

// Entry is one version of a subject's directory entry: everything a PAR
// shows, committed to the transparency log.
type Entry struct {
	Subject         string
	Version         uint64
	Handle          string // the handle key (NFKC_Casefold), or empty
	Display         Display
	Aliases         []Alias
	Currencies      []string
	DefaultCurrency string
	Keys            []PublicKey
	Time            time.Time
}

// ErrEntry means an entry is malformed.
var ErrEntry = errors.New("identity: malformed directory entry")

func (e *Entry) validate() error {
	switch {
	case !ValidSubject(e.Subject):
		return fmt.Errorf("%w: subject %q", ErrEntry, e.Subject)
	case e.Version == 0:
		return fmt.Errorf("%w: version 0", ErrEntry)
	case len(e.Display.Name) > 64 || len(e.Display.Handle) > 128:
		return fmt.Errorf("%w: display fields too long", ErrEntry)
	case e.Display.AvatarSHA256 != nil && len(e.Display.AvatarSHA256) != 32:
		return fmt.Errorf("%w: avatar hash", ErrEntry)
	case len(e.Currencies) > 16 || len(e.Keys) > 8 || len(e.Aliases) > 16 || len(e.Display.Verified) > 8:
		return fmt.Errorf("%w: too many items", ErrEntry)
	}
	for _, c := range e.Currencies {
		if !currencyPattern.MatchString(c) {
			return fmt.Errorf("%w: currency %q", ErrEntry, c)
		}
	}
	if e.DefaultCurrency != "" && !slices.Contains(e.Currencies, e.DefaultCurrency) {
		return fmt.Errorf("%w: default currency %q is not received", ErrEntry, e.DefaultCurrency)
	}
	for _, b := range e.Display.Verified {
		if !badgePattern.MatchString(b) {
			return fmt.Errorf("%w: badge %q", ErrEntry, b)
		}
	}
	seen := map[string]bool{}
	for _, k := range e.Keys {
		if !kidPattern.MatchString(k.KID) || seen[k.KID] {
			return fmt.Errorf("%w: key id %q", ErrEntry, k.KID)
		}
		seen[k.KID] = true
		if k.Use != UseP2PBinding && k.Use != UseMemoEncryption {
			return fmt.Errorf("%w: key use %q", ErrEntry, k.Use)
		}
		if _, err := cose.ParseP256(k.Pub); err != nil || len(k.Pub) != 33 {
			return fmt.Errorf("%w: key %s is not a compressed P-256 point", ErrEntry, k.KID)
		}
	}
	return nil
}

// Encode returns the entry's deterministic CBOR: the bytes the log commits
// to and PARs carry.
func (e *Entry) Encode() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	display := cbor.Map{"handle": e.Display.Handle, "name": e.Display.Name, "verified": textList(e.Display.Verified)}
	if e.Display.AvatarSHA256 != nil {
		display["avatar_sha256"] = e.Display.AvatarSHA256
	}
	aliases := make([]any, len(e.Aliases))
	for i, a := range e.Aliases {
		aliases[i] = cbor.Map{"provider": a.Provider, "uid": a.UID, "handle": a.Handle, "checked_at": uint64(a.CheckedAt.Unix())}
	}
	keys := make([]any, len(e.Keys))
	for i, k := range e.Keys {
		keys[i] = cbor.Map{"kid": k.KID, "use": k.Use, "pub": k.Pub}
	}
	return cbor.Encode(cbor.Map{"v": uint64(EntryVersion), "subject": e.Subject, "version": e.Version, "handle": e.Handle,
		"display": display, "aliases": aliases,
		"receive": cbor.Map{"currencies": textList(e.Currencies), "default": e.DefaultCurrency},
		"keys":    keys, "ts": uint64(e.Time.Unix())})
}

func textList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func textArray(f *cbor.Fields, k string, max, maxLen int) []string {
	arr := f.Array(k, max)
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok || len(s) > maxLen {
			f.Fail(k, "not an array of short text strings")
			return nil
		}
		out = append(out, s)
	}
	return out
}

// DecodeEntry parses an entry's deterministic CBOR against its closed schema.
func DecodeEntry(raw []byte) (*Entry, error) {
	v, err := cbor.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, fmt.Errorf("%w: not a map", ErrEntry)
	}
	f := m.Fields()
	e := &Entry{}
	if f.Uint("v") != EntryVersion {
		f.Fail("v", "unsupported entry version")
	}
	e.Subject, e.Version, e.Handle = f.Text("subject", 64), f.Uint("version"), f.Text("handle", 128)
	d := f.Map("display").Fields()
	e.Display.Handle, e.Display.Name = d.Text("handle", 128), d.Text("name", 64)
	e.Display.Verified = textArray(d, "verified", 8, 32)
	d.Optional("avatar_sha256", func() { e.Display.AvatarSHA256 = d.BytesN("avatar_sha256", 32) })
	for _, item := range f.Array("aliases", 16) {
		am, ok := item.(cbor.Map)
		if !ok {
			f.Fail("aliases", "not a map")
			break
		}
		af := am.Fields()
		a := Alias{Provider: af.Text("provider", 32), UID: af.Text("uid", 128), Handle: af.Text("handle", 128),
			CheckedAt: time.Unix(int64(af.Uint("checked_at")), 0).UTC()}
		if err := af.Done(); err != nil {
			f.Fail("aliases", err.Error())
			break
		}
		e.Aliases = append(e.Aliases, a)
	}
	r := f.Map("receive").Fields()
	e.Currencies, e.DefaultCurrency = textArray(r, "currencies", 16, 8), r.Text("default", 8)
	for _, item := range f.Array("keys", 8) {
		km, ok := item.(cbor.Map)
		if !ok {
			f.Fail("keys", "not a map")
			break
		}
		kf := km.Fields()
		k := PublicKey{KID: kf.Text("kid", 32), Use: kf.Text("use", 32), Pub: kf.BytesN("pub", 33)}
		if err := kf.Done(); err != nil {
			f.Fail("keys", err.Error())
			break
		}
		e.Keys = append(e.Keys, k)
	}
	e.Time = time.Unix(int64(f.Uint("ts")), 0).UTC()
	for _, sub := range []*cbor.Fields{d, r, f} {
		if err := sub.Done(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEntry, err)
		}
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return e, nil
}
