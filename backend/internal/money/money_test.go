package money_test

import (
	"math"
	"math/big"
	"regexp"
	"strconv"
	"testing"

	"pgregory.net/rapid"

	"github.com/bil1234n/bilyon/backend/internal/money"
	"github.com/bil1234n/bilyon/backend/migrations"
)

// The Go registry and the SQL seed must never drift apart.
func TestRegistryMatchesMigrationSeed(t *testing.T) {
	raw, err := migrations.Ledger.ReadFile("ledger/0001_ledger_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`\('([A-Z0-9]+)', (\d+), (\d+), +'([^']+)'\)`)
	seed := row.FindAllStringSubmatch(string(raw), -1)
	if len(seed) != len(money.All()) {
		t.Fatalf("seed has %d currencies, registry %d", len(seed), len(money.All()))
	}
	for _, m := range seed {
		c, ok := money.Lookup(m[1])
		exp, _ := strconv.Atoi(m[2])
		code, _ := strconv.Atoi(m[3])
		if !ok || c.Exponent != exp || c.LedgerCode != uint32(code) || c.Name != m[4] {
			t.Errorf("%s: seed (%d, %d, %s) vs registry %+v", m[1], exp, code, m[4], c)
		}
	}
}

func TestFormatAndParse(t *testing.T) {
	eur, _ := money.Lookup("EUR")
	jpy, _ := money.Lookup("JPY")
	kwd, _ := money.Lookup("KWD")
	cases := []struct {
		minor int64
		c     money.Currency
		text  string
	}{
		{1250, eur, "12.50"}, {-5, eur, "-0.05"}, {0, eur, "0.00"}, {1500, jpy, "1500"},
		{1, kwd, "0.001"}, {math.MaxInt64, eur, "92233720368547758.07"}, {math.MinInt64, eur, "-92233720368547758.08"},
	}
	for _, tc := range cases {
		if got := money.Format(tc.minor, tc.c); got != tc.text {
			t.Errorf("Format(%d, %s) = %q, want %q", tc.minor, tc.c.Code, got, tc.text)
		}
		back, err := money.Parse(tc.text, tc.c)
		if err != nil || back != tc.minor {
			t.Errorf("Parse(%q) = %d, %v", tc.text, back, err)
		}
	}
	if v, err := money.Parse("12.5", eur); err != nil || v != 1250 {
		t.Errorf("short fraction: %d %v", v, err)
	}
	for _, bad := range []string{"", "-", "1.", ".5", "1.234", "1e3", " 1", "1,000", "+1", "92233720368547758.08", "1.2.3"} {
		if _, err := money.Parse(bad, eur); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestOverflowChecks(t *testing.T) {
	if _, err := money.Add(math.MaxInt64, 1); err != money.ErrOverflow {
		t.Error("Add overflow not detected")
	}
	if _, err := money.Sub(math.MinInt64, 1); err != money.ErrOverflow {
		t.Error("Sub overflow not detected")
	}
	if _, err := money.Sub(0, math.MinInt64); err != money.ErrOverflow {
		t.Error("Sub of MinInt64 not detected")
	}
	if v, err := money.Sub(-1, math.MinInt64); err != nil || v != math.MaxInt64 {
		t.Errorf("Sub(-1, MinInt64) = %d %v", v, err)
	}
	if _, err := money.Neg(math.MinInt64); err != money.ErrOverflow {
		t.Error("Neg overflow not detected")
	}
	if _, err := money.Sum(math.MaxInt64, -1, 2); err != money.ErrOverflow {
		t.Error("Sum overflow not detected")
	}
}

func TestPropertyFormatParseRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		all := money.All()
		c := all[rapid.IntRange(0, len(all)-1).Draw(t, "currency")]
		v := rapid.Int64().Draw(t, "minor")
		back, err := money.Parse(money.Format(v, c), c)
		if err != nil || back != v {
			t.Fatalf("round trip %d %s -> %q -> %d (%v)", v, c.Code, money.Format(v, c), back, err)
		}
	})
}

func TestPropertyAddSubMatchBigInt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := rapid.Int64().Draw(t, "a"), rapid.Int64().Draw(t, "b")
		check := func(op string, got int64, err error, want *big.Int) {
			if want.IsInt64() != (err == nil) {
				t.Fatalf("%s(%d, %d): err=%v, exact=%s", op, a, b, err, want)
			}
			if err == nil && got != want.Int64() {
				t.Fatalf("%s(%d, %d) = %d, want %s", op, a, b, got, want)
			}
		}
		sum, err := money.Add(a, b)
		check("Add", sum, err, new(big.Int).Add(big.NewInt(a), big.NewInt(b)))
		diff, err := money.Sub(a, b)
		check("Sub", diff, err, new(big.Int).Sub(big.NewInt(a), big.NewInt(b)))
	})
}
