package handle

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestSkeletonCollisions(t *testing.T) {
	for _, pair := range [][2]string{
		{"alice", "аlice"},    // Cyrillic а
		{"paypal", "paypa1"},  // digit one
		{"paypal", "paypaI"},  // capital I
		{"modern", "rnodern"}, // rn / m
		{"bilyon", "bіlyon"},  // Cyrillic і
		{"google", "gооgle"},
		{"x", "×"}, // multiplication sign
	} {
		if Skeleton(pair[0]) != Skeleton(pair[1]) {
			t.Errorf("%q and %q should be confusable: %q vs %q", pair[0], pair[1], Skeleton(pair[0]), Skeleton(pair[1]))
		}
	}
	for _, pair := range [][2]string{{"alice", "alicia"}, {"bob", "rob"}, {"anna", "ana"}} {
		if Skeleton(pair[0]) == Skeleton(pair[1]) {
			t.Errorf("%q and %q are not confusable", pair[0], pair[1])
		}
	}
	// Default-ignorables vanish from skeletons.
	if Skeleton("al‍ice") != Skeleton("alice") || Skeleton("ali­ce") != Skeleton("alice") {
		t.Error("default-ignorable code points must not affect the skeleton")
	}
}

func TestHandleSkeletonFoldsPrototypes(t *testing.T) {
	// UTS #39 maps "0" to the prototype "O"; handle keys are folded, so the
	// handle skeleton folds prototypes too and "supp0rt" meets "support".
	for _, pair := range [][2]string{{"support", "supp0rt"}, {"bilyon", "BI1YON"}, {"milo", "rni1o"}, {"alice", "\u0430lice"}} {
		if HandleSkeleton(pair[0]) != HandleSkeleton(pair[1]) {
			t.Errorf("%q and %q should collide: %q vs %q", pair[0], pair[1], HandleSkeleton(pair[0]), HandleSkeleton(pair[1]))
		}
	}
	if Skeleton("support") == Skeleton("supp0rt") {
		t.Error("the raw UTS #39 skeleton is case-sensitive; this test expects it")
	}
	sk, err := LookupSkeleton("@p\u0430ypal")
	if err != nil || sk != HandleSkeleton("paypal") {
		t.Errorf("LookupSkeleton of a mixed-script lookalike: %q, %v", sk, err)
	}
	for _, bad := range []string{"", "@", "\xff", strings.Repeat("a", 61)} {
		if _, err := LookupSkeleton(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("LookupSkeleton(%q): %v", bad, err)
		}
	}
}

func TestParse(t *testing.T) {
	for _, c := range []struct{ in, key, display string }{
		{"@Alice", "alice", "Alice"},
		{"  alice ", "alice", "alice"},
		{"ａｌｉｃｅ", "alice", "alice"},     // fullwidth
		{"al‍ice", "alice", "alice"},    // zero-width joiner stripped
		{"Straße", "strasse", "Straße"}, // full case folding
		{"bob_99", "bob_99", "bob_99"},
		{"a.b.c", "a.b.c", "a.b.c"},
		{"たなか", "たなか", "たなか"},                // Hiragana
		{"tanaka田中", "tanaka田中", "tanaka田中"}, // Latin + Han (Highly Restrictive)
		{"Ελένη", "ελένη", "Ελένη"},          // Greek
		{"김민수", "김민수", "김민수"},                // Hangul
		{"김tanaka田", "김tanaka田", "김tanaka田"}, // Latin + Han + Hangul (Highly Restrictive)
		{"محمد", "محمد", "محمد"},             // Arabic
		{"alíce", "alíce", "alíce"},         // composes to NFC/NFKC form
	} {
		h, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if h.Key != c.key || h.Display != c.display || h.Skeleton != HandleSkeleton(c.key) {
			t.Errorf("Parse(%q) = %+v, want key %q display %q", c.in, h, c.key, c.display)
		}
	}
}

func TestParseRejections(t *testing.T) {
	for _, c := range []struct{ in, rule string }{
		{"ab", "length"},
		{strings.Repeat("a", 31), "length"},
		{"1alice", "shape"},
		{"_alice", "shape"},
		{"alice.", "shape"},
		{"alice_", "shape"},
		{"al..ice", "shape"},
		{"al._ice", "shape"},
		{"al-ice", "character"},
		{"al ice", "character"},
		{"alice!", "character"},
		{"ali😀ce", "character"},
		{"al'ice", "character"},
		{"\u16a0\u16a2\u16a6", "character"}, // Runic letters: Identifier_Status Restricted
		{"pаypal", "script"},                // Latin with a Cyrillic а
		{"ελλaνικα", "script"},              // Greek with a Latin a
		{"alice٣", "script"},                // an Arabic-Indic digit is Arabic script
		{"\xff\xfe", "encoding"},
	} {
		_, err := Parse(c.in)
		var ie *InvalidError
		if !errors.As(err, &ie) || !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q): err = %v, want a %s rejection", c.in, err, c.rule)
			continue
		}
		if ie.Rule != c.rule {
			t.Errorf("Parse(%q): rule %s (%s), want %s", c.in, ie.Rule, ie.Detail, c.rule)
		}
	}
	// Digits from two numbering systems within one script: Devanagari
	// letters with an ASCII digit and a Devanagari digit.
	if _, err := Parse("रमेश1१"); err == nil || !strings.Contains(err.Error(), "numbers") {
		t.Errorf("mixed numbering systems: %v", err)
	}
	if _, err := Parse("रमेश१२"); err != nil {
		t.Errorf("one numbering system: %v", err)
	}
}

func TestDefaultIgnorable(t *testing.T) {
	for _, r := range []rune{0x00AD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFE0F, 0xFEFF, 0xE0001, 0x180E} {
		if !DefaultIgnorable(r) {
			t.Errorf("U+%04X should be default-ignorable", r)
		}
	}
	for _, r := range []rune{'a', ' ', 0x0600 /* prepended concatenation mark */, 0xFFF9, 0x13430, 0x0020} {
		if DefaultIgnorable(r) {
			t.Errorf("U+%04X should not be default-ignorable", r)
		}
	}
}

func TestEmbeddedData(t *testing.T) {
	mustLoad()
	if len(prototypes) != 6355 || len(allowed) != 556 {
		t.Fatalf("%d confusables, %d allowed ranges", len(prototypes), len(allowed))
	}
	for src, proto := range prototypes {
		if proto == string(src) || !utf8.ValidString(proto) || proto == "" {
			t.Fatalf("bad prototype for U+%04X: %q", src, proto)
		}
	}
	for _, r := range "abcxyz0189_" {
		if !identifierAllowed(r) {
			t.Errorf("%q should be allowed", r)
		}
	}
	for _, r := range []rune{'@', '!', ' ', 0x200D, 0x1F600} {
		if identifierAllowed(r) {
			t.Errorf("U+%04X should not be allowed", r)
		}
	}
	// Every allowed character the handle policy admits has a script.
	for _, s := range allowed {
		for r := s.lo; r <= s.hi; r++ {
			if unicode.IsLetter(r) && unicode.In(r, unicode.Letter) && scriptOf(r) == "" {
				t.Fatalf("U+%04X has no script", r)
			}
		}
	}
}

// FuzzParse checks Parse's invariants on arbitrary input: accepted handles
// are fixed points of folding, within bounds, and parse to themselves.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"alice", "@Alice", "ａｌｉｃｅ", "al‍ice", "Straße", "たなか", "pаypal", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		h, err := Parse(in)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q): unclassified error %v", in, err)
			}
			return
		}
		if Fold(h.Key) != h.Key || Fold(h.Display) != h.Key || h.Skeleton != HandleSkeleton(h.Key) {
			t.Fatalf("Parse(%q): key %q is not a fold fixed point", in, h.Key)
		}
		n := utf8.RuneCountInString(h.Key)
		if n < MinLength || n > MaxLength {
			t.Fatalf("Parse(%q): key of %d runes", in, n)
		}
		again, err := Parse(h.Key)
		if err != nil || again.Key != h.Key || again.Skeleton != h.Skeleton {
			t.Fatalf("Parse(%q) is not stable: %+v vs %+v (%v)", in, h, again, err)
		}
	})
}
