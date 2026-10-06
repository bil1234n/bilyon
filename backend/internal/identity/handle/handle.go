// Package handle normalises Bilyon handles and computes the UTS #39
// confusable skeletons uniqueness is enforced on (RFC 0001 §4.1.1).
//
// A handle's key is its NFKC_Casefold form with default-ignorable code
// points removed; its skeleton maps every character to its confusable
// prototype, so "@аlice" (Cyrillic а) and "@alice" collide. The character
// policy follows the UTS #39 General Security Profile (Identifier_Status
// Allowed) and the Highly Restrictive restriction level.
package handle

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Length bounds of a handle key, in code points.
const (
	MinLength = 3
	MaxLength = 30
)

// ErrInvalid is the root of every policy failure.
var ErrInvalid = errors.New("handle: invalid")

// InvalidError names the rule a handle broke.
type InvalidError struct {
	Rule   string
	Detail string
}

func (e *InvalidError) Error() string { return "handle: " + e.Rule + ": " + e.Detail }

// Unwrap makes errors.Is(err, ErrInvalid) hold.
func (e *InvalidError) Unwrap() error { return ErrInvalid }

func invalid(rule, format string, args ...any) error {
	return &InvalidError{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

//go:embed data/confusables.txt data/IdentifierStatus.txt
var data embed.FS

type span struct{ lo, hi rune }

var (
	loadOnce   sync.Once
	prototypes map[rune]string
	allowed    []span
)

func mustLoad() {
	loadOnce.Do(func() {
		var err error
		if prototypes, err = parseConfusables(); err == nil {
			allowed, err = parseIdentifierStatus()
		}
		if err != nil {
			panic(fmt.Sprintf("handle: embedded Unicode data: %v", err))
		}
	})
}

func dataLines(name string, fn func(fields []string) error) error {
	raw, err := data.ReadFile("data/" + name)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ";")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if err := fn(fields); err != nil {
			return fmt.Errorf("%s:%d: %w", name, n, err)
		}
	}
	return sc.Err()
}

func parseCodePoint(s string) (rune, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil || v > unicode.MaxRune {
		return 0, fmt.Errorf("code point %q", s)
	}
	return rune(v), nil
}

// parseConfusables reads confusables.txt: "source ; prototype... ; MA".
func parseConfusables() (map[rune]string, error) {
	out := map[rune]string{}
	err := dataLines("confusables.txt", func(f []string) error {
		if len(f) < 3 || f[2] != "MA" {
			return fmt.Errorf("unexpected fields %q", f)
		}
		src, err := parseCodePoint(f[0])
		if err != nil {
			return err
		}
		var b strings.Builder
		for _, cp := range strings.Fields(f[1]) {
			r, err := parseCodePoint(cp)
			if err != nil {
				return err
			}
			b.WriteRune(r)
		}
		if _, dup := out[src]; dup {
			return fmt.Errorf("duplicate source %04X", src)
		}
		out[src] = b.String()
		return nil
	})
	return out, err
}

// parseIdentifierStatus reads IdentifierStatus.txt: "lo..hi ; Allowed".
func parseIdentifierStatus() ([]span, error) {
	var out []span
	err := dataLines("IdentifierStatus.txt", func(f []string) error {
		if len(f) < 2 || f[1] != "Allowed" {
			return fmt.Errorf("unexpected fields %q", f)
		}
		lo, hi, isRange := strings.Cut(f[0], "..")
		a, err := parseCodePoint(lo)
		if err != nil {
			return err
		}
		b := a
		if isRange {
			if b, err = parseCodePoint(hi); err != nil {
				return err
			}
		}
		if b < a || (len(out) > 0 && a <= out[len(out)-1].hi) {
			return fmt.Errorf("ranges must ascend")
		}
		out = append(out, span{a, b})
		return nil
	})
	return out, err
}

// identifierAllowed reports Identifier_Status=Allowed (UTS #39 §3.1).
func identifierAllowed(r rune) bool {
	mustLoad()
	_, found := slices.BinarySearchFunc(allowed, r, func(s span, r rune) int {
		switch {
		case s.hi < r:
			return -1
		case s.lo > r:
			return 1
		}
		return 0
	})
	return found
}

// DefaultIgnorable reports the Default_Ignorable_Code_Point property, as
// DerivedCoreProperties.txt derives it: Other_Default_Ignorable_Code_Point
// + Cf + Variation_Selector − White_Space − FFF9..FFFB − Egyptian
// hieroglyph format controls − Prepended_Concatenation_Mark.
func DefaultIgnorable(r rune) bool {
	switch {
	case unicode.Is(unicode.White_Space, r),
		r >= 0xFFF9 && r <= 0xFFFB,
		r >= 0x13430 && r <= 0x1345F,
		unicode.Is(unicode.Prepended_Concatenation_Mark, r):
		return false
	}
	return unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r)
}

func stripIgnorable(s string) string {
	return strings.Map(func(r rune) rune {
		if DefaultIgnorable(r) {
			return -1
		}
		return r
	}, s)
}

var folder = cases.Fold()

// Fold is the handle key mapping: default-ignorables removed, then NFKC,
// full case folding and NFKC again (folding can denormalise).
func Fold(s string) string {
	return norm.NFKC.String(folder.String(norm.NFKC.String(stripIgnorable(s))))
}

// Skeleton is the UTS #39 §4 skeleton: NFD, default-ignorables removed,
// every character replaced by its confusable prototype, NFD again. Two
// strings are confusable exactly when their skeletons are equal.
func Skeleton(s string) string {
	mustLoad()
	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		if DefaultIgnorable(r) {
			continue
		}
		if p, ok := prototypes[r]; ok {
			b.WriteString(p)
		} else {
			b.WriteRune(r)
		}
	}
	return norm.NFD.String(b.String())
}

// HandleSkeleton is the skeleton handles are compared by: the UTS #39
// skeleton of the folded string, case-folded again (prototypes such as "O"
// for "0" are upper case, while handle keys are folded) and in NFD.
func HandleSkeleton(s string) string {
	return norm.NFD.String(folder.String(Skeleton(Fold(s))))
}

// LookupSkeleton is the skeleton of whatever a payer typed, for
// resolution: unlike Parse it applies no character policy, so a lookalike
// of a held handle finds that handle's owner (the only one who can hold
// it) and the record shows the real handle.
func LookupSkeleton(input string) (string, error) {
	s := strings.TrimPrefix(strings.TrimSpace(input), "@")
	if !utf8.ValidString(s) {
		return "", invalid("encoding", "not valid UTF-8")
	}
	key := Fold(s)
	if n := utf8.RuneCountInString(key); n == 0 || n > 2*MaxLength {
		return "", invalid("length", "%d characters", n)
	}
	return HandleSkeleton(key), nil
}

// Handle is a validated handle.
type Handle struct {
	Key      string // NFKC_Casefold form: what is stored and looked up
	Skeleton string // HandleSkeleton: what uniqueness is enforced on
	Display  string // NFKC with case preserved, shown to payers
}

// Parse validates and normalises a handle; a leading "@" is optional.
func Parse(input string) (Handle, error) {
	s := strings.TrimPrefix(strings.TrimSpace(input), "@")
	if !utf8.ValidString(s) {
		return Handle{}, invalid("encoding", "not valid UTF-8")
	}
	display := norm.NFKC.String(stripIgnorable(s))
	key := Fold(display)
	if err := check(key); err != nil {
		return Handle{}, err
	}
	return Handle{Key: key, Skeleton: HandleSkeleton(key), Display: display}, nil
}

func punctuation(r rune) bool { return r == '_' || r == '.' }

// check applies the character, shape, numbering and script rules to a key.
func check(key string) error {
	n := utf8.RuneCountInString(key)
	if n < MinLength || n > MaxLength {
		return invalid("length", "%d characters (%d to %d)", n, MinLength, MaxLength)
	}
	var prev rune
	var zero rune = -1
	for i, r := range []rune(key) {
		if !identifierAllowed(r) || !(unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsDigit(r) || punctuation(r)) {
			return invalid("character", "%q (U+%04X) is not allowed", r, r)
		}
		switch {
		case i == 0 && !unicode.IsLetter(r):
			return invalid("shape", "a handle starts with a letter")
		case i == n-1 && punctuation(r):
			return invalid("shape", "a handle cannot end with %q", r)
		case punctuation(r) && punctuation(prev):
			return invalid("shape", "consecutive punctuation")
		}
		if unicode.IsDigit(r) {
			z := digitZero(r)
			if zero >= 0 && z != zero {
				return invalid("numbers", "digits from more than one numbering system")
			}
			zero = z
		}
		prev = r
	}
	return checkScripts(key)
}

// digitZero returns the zero of a decimal digit's block of ten. Nd digits
// come in runs of ten; the only adjacent runs (mathematical digits) are
// compatibility characters that NFKC has already mapped to ASCII.
func digitZero(r rune) rune {
	for z := r; z > r-10 && z >= 0; z-- {
		if !unicode.IsDigit(z) {
			return z + 1
		}
	}
	return r - 9
}

var (
	scriptNames []string
	scriptOnce  sync.Once
)

// scriptOf returns the Script property value of r.
func scriptOf(r rune) string {
	scriptOnce.Do(func() {
		for name := range unicode.Scripts {
			scriptNames = append(scriptNames, name)
		}
		// Most handles are Latin; check frequent scripts first.
		slices.SortFunc(scriptNames, func(a, b string) int {
			rank := func(s string) int {
				switch s {
				case "Latin":
					return 0
				case "Common", "Inherited":
					return 1
				}
				return 2
			}
			if d := rank(a) - rank(b); d != 0 {
				return d
			}
			return strings.Compare(a, b)
		})
	})
	for _, name := range scriptNames {
		if unicode.Is(unicode.Scripts[name], r) {
			return name
		}
	}
	return "Unknown"
}

// highlyRestrictive lists the script combinations UTS #39 §5.2 allows
// beyond a single script.
var highlyRestrictive = []map[string]bool{
	{"Latin": true, "Han": true, "Hiragana": true, "Katakana": true},
	{"Latin": true, "Han": true, "Bopomofo": true},
	{"Latin": true, "Han": true, "Hangul": true},
}

func checkScripts(key string) error {
	seen := map[string]bool{}
	for _, r := range key {
		switch sc := scriptOf(r); sc {
		case "Common", "Inherited":
		case "Unknown":
			return invalid("script", "U+%04X has no script in this Unicode version", r)
		default:
			seen[sc] = true
		}
	}
	if len(seen) <= 1 {
		return nil
	}
	for _, allowedSet := range highlyRestrictive {
		ok := true
		for sc := range seen {
			ok = ok && allowedSet[sc]
		}
		if ok {
			return nil
		}
	}
	names := make([]string, 0, len(seen))
	for sc := range seen {
		names = append(names, sc)
	}
	slices.Sort(names)
	return invalid("script", "mixes %s", strings.Join(names, ", "))
}
