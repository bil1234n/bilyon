// Package money provides the currency registry and exact, overflow-checked
// arithmetic on integer minor units (RFC 0001 §2.1.1: money is never a float).
package money

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
)

// Currency describes one asset the platform can hold.
type Currency struct {
	Code       string // ISO 4217 alpha code, or a digital asset code such as USDC
	Exponent   int    // number of minor-unit digits
	LedgerCode uint32 // ISO 4217 numeric code; >= 100000 for digital assets
	Name       string
}

// The registry mirrors the seed in migrations/ledger/0001_ledger_core.sql;
// a test keeps the two identical.
var registry = func() map[string]Currency {
	list := []Currency{
		{"USD", 2, 840, "US Dollar"}, {"EUR", 2, 978, "Euro"},
		{"GBP", 2, 826, "Pound Sterling"}, {"JPY", 0, 392, "Yen"},
		{"CHF", 2, 756, "Swiss Franc"}, {"CAD", 2, 124, "Canadian Dollar"},
		{"AUD", 2, 36, "Australian Dollar"}, {"NZD", 2, 554, "New Zealand Dollar"},
		{"SEK", 2, 752, "Swedish Krona"}, {"NOK", 2, 578, "Norwegian Krone"},
		{"DKK", 2, 208, "Danish Krone"}, {"PLN", 2, 985, "Zloty"},
		{"CZK", 2, 203, "Czech Koruna"}, {"HUF", 2, 348, "Forint"},
		{"CNY", 2, 156, "Yuan Renminbi"}, {"HKD", 2, 344, "Hong Kong Dollar"},
		{"SGD", 2, 702, "Singapore Dollar"}, {"INR", 2, 356, "Indian Rupee"},
		{"IDR", 2, 360, "Rupiah"}, {"KRW", 0, 410, "Won"},
		{"THB", 2, 764, "Baht"}, {"PHP", 2, 608, "Philippine Peso"},
		{"MYR", 2, 458, "Malaysian Ringgit"}, {"VND", 0, 704, "Dong"},
		{"BRL", 2, 986, "Brazilian Real"}, {"MXN", 2, 484, "Mexican Peso"},
		{"ARS", 2, 32, "Argentine Peso"}, {"CLP", 0, 152, "Chilean Peso"},
		{"COP", 2, 170, "Colombian Peso"}, {"PEN", 2, 604, "Sol"},
		{"NGN", 2, 566, "Naira"}, {"KES", 2, 404, "Kenyan Shilling"},
		{"GHS", 2, 936, "Ghana Cedi"}, {"ZAR", 2, 710, "Rand"},
		{"EGP", 2, 818, "Egyptian Pound"}, {"MAD", 2, 504, "Moroccan Dirham"},
		{"ETB", 2, 230, "Ethiopian Birr"}, {"UGX", 0, 800, "Uganda Shilling"},
		{"TZS", 2, 834, "Tanzanian Shilling"}, {"RWF", 0, 646, "Rwanda Franc"},
		{"XOF", 0, 952, "CFA Franc BCEAO"}, {"XAF", 0, 950, "CFA Franc BEAC"},
		{"AED", 2, 784, "UAE Dirham"}, {"SAR", 2, 682, "Saudi Riyal"},
		{"QAR", 2, 634, "Qatari Riyal"}, {"KWD", 3, 414, "Kuwaiti Dinar"},
		{"BHD", 3, 48, "Bahraini Dinar"}, {"OMR", 3, 512, "Rial Omani"},
		{"JOD", 3, 400, "Jordanian Dinar"}, {"TRY", 2, 949, "Turkish Lira"},
		{"ILS", 2, 376, "New Israeli Sheqel"}, {"PKR", 2, 586, "Pakistan Rupee"},
		{"BDT", 2, 50, "Taka"}, {"LKR", 2, 144, "Sri Lanka Rupee"},
		{"USDC", 6, 100001, "USD Coin"}, {"EURC", 6, 100002, "Euro Coin"},
	}
	m := make(map[string]Currency, len(list))
	for _, c := range list {
		m[c.Code] = c
	}
	return m
}()

// Lookup returns the currency for a code.
func Lookup(code string) (Currency, bool) {
	c, ok := registry[code]
	return c, ok
}

// All returns every registered currency ordered by code.
func All() []Currency {
	out := make([]Currency, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// ByLedgerCode returns the currency with the given numeric ledger code.
func ByLedgerCode(code uint32) (Currency, bool) {
	for _, c := range registry {
		if c.LedgerCode == code {
			return c, true
		}
	}
	return Currency{}, false
}

// ErrOverflow reports a result outside the int64 range.
var ErrOverflow = errors.New("money: amount overflows int64")

// Add returns a+b or ErrOverflow.
func Add(a, b int64) (int64, error) {
	s := a + b
	if (b > 0 && s < a) || (b < 0 && s > a) {
		return 0, ErrOverflow
	}
	return s, nil
}

// Sub returns a-b or ErrOverflow.
func Sub(a, b int64) (int64, error) {
	if b == math.MinInt64 {
		if a >= 0 {
			return 0, ErrOverflow
		}
		return a - b, nil
	}
	return Add(a, -b)
}

// Neg returns -a or ErrOverflow (for math.MinInt64).
func Neg(a int64) (int64, error) {
	if a == math.MinInt64 {
		return 0, ErrOverflow
	}
	return -a, nil
}

// Sum adds every value or reports ErrOverflow.
func Sum(values ...int64) (int64, error) {
	var total int64
	for _, v := range values {
		var err error
		if total, err = Add(total, v); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// Format renders minor units as a plain decimal string ("12.50", "-0.05", "1500").
func Format(minor int64, c Currency) string {
	if c.Exponent == 0 {
		return fmt.Sprintf("%d", minor)
	}
	v := new(big.Int).SetInt64(minor)
	neg := v.Sign() < 0
	v.Abs(v)
	s := v.String()
	if len(s) <= c.Exponent {
		s = strings.Repeat("0", c.Exponent-len(s)+1) + s
	}
	out := s[:len(s)-c.Exponent] + "." + s[len(s)-c.Exponent:]
	if neg {
		out = "-" + out
	}
	return out
}

// Parse converts a plain decimal string to minor units. It accepts an
// optional leading '-', digits, and at most Exponent fractional digits; no
// exponents, separators, whitespace or rounding.
func Parse(s string, c Currency) (int64, error) {
	if s == "" {
		return 0, errors.New("money: empty amount")
	}
	neg := strings.HasPrefix(s, "-")
	body := strings.TrimPrefix(s, "-")
	whole, frac, hasDot := strings.Cut(body, ".")
	if whole == "" || (hasDot && frac == "") {
		return 0, fmt.Errorf("money: malformed amount %q", s)
	}
	if len(frac) > c.Exponent {
		return 0, fmt.Errorf("money: %q has more than %d decimals for %s", s, c.Exponent, c.Code)
	}
	for _, r := range whole + frac {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("money: malformed amount %q", s)
		}
	}
	digits := whole + frac + strings.Repeat("0", c.Exponent-len(frac))
	v, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return 0, fmt.Errorf("money: malformed amount %q", s)
	}
	if neg {
		v.Neg(v)
	}
	if !v.IsInt64() {
		return 0, ErrOverflow
	}
	return v.Int64(), nil
}
