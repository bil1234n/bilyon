package gatewayapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limit allows N requests per window.
type Limit struct {
	N   int
	Per time.Duration
}

// RateLimits are the API's limits. A zero Limit disables that class.
type RateLimits struct {
	// Unauthenticated endpoints (registration, login, refresh), per
	// client IP.
	Auth Limit
	// Directory lookups, per account and per device (RFC 0001 §4.1.4:
	// 60 per minute and 1 000 per day).
	LookupMinute Limit
	LookupDay    Limit
	// Everything else an authenticated caller does, per account.
	Calls Limit
}

// DefaultRateLimits are the RFC's lookup limits and conservative others.
var DefaultRateLimits = RateLimits{
	Auth:         Limit{N: 30, Per: time.Minute},
	LookupMinute: Limit{N: 60, Per: time.Minute},
	LookupDay:    Limit{N: 1000, Per: 24 * time.Hour},
	Calls:        Limit{N: 600, Per: time.Minute},
}

// Limiter counts requests in fixed windows in Redis, shared by every
// gateway replica.
type Limiter struct {
	rdb    redis.UniversalClient
	prefix string
	now    func() time.Time
}

// NewLimiter returns a limiter over rdb.
func NewLimiter(rdb redis.UniversalClient, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{rdb: rdb, prefix: "bilyon:rl:", now: now}
}

// incr counts one request and sets the window's expiry on its first hit.
var incr = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n`)

// Allow counts a request for key under lim and reports whether it is
// within the limit, and when the window ends.
func (l *Limiter) Allow(ctx context.Context, key string, lim Limit) (bool, time.Duration, error) {
	if lim.N <= 0 || lim.Per <= 0 {
		return true, 0, nil
	}
	now := l.now()
	window := now.UnixMilli() / lim.Per.Milliseconds()
	end := time.UnixMilli((window + 1) * lim.Per.Milliseconds())
	k := l.prefix + key + ":" + strconv.FormatInt(lim.Per.Milliseconds(), 10) + ":" + strconv.FormatInt(window, 10)
	// Keys outlive their window a little so clock skew between replicas
	// cannot reset a count early.
	n, err := incr.Run(ctx, l.rdb, []string{k}, (lim.Per + time.Minute).Milliseconds()).Int64()
	if err != nil {
		return false, 0, fmt.Errorf("rate limiter: %w", err)
	}
	return n <= int64(lim.N), end.Sub(now), nil
}

// clientIP is the address the request came from: the connection's peer,
// or, behind trustedHops proxies that append to X-Forwarded-For, the entry
// the outermost trusted proxy added.
func clientIP(r *http.Request, trustedHops int) string {
	if trustedHops > 0 {
		var hops []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			for _, h := range strings.Split(v, ",") {
				if h = strings.TrimSpace(h); h != "" {
					hops = append(hops, h)
				}
			}
		}
		if len(hops) >= trustedHops {
			if ip := net.ParseIP(hops[len(hops)-trustedHops]); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limited answers 429 when key exceeds any of lims; it reports whether the
// request was refused (or failed).
func (a *API) limited(w http.ResponseWriter, r *http.Request, key string, lims ...Limit) bool {
	for _, lim := range lims {
		ok, retry, err := a.limiter.Allow(r.Context(), key, lim)
		if err != nil {
			a.fail(w, r, fmt.Errorf("%w: %v", errLimiter, err))
			return true
		}
		if !ok {
			secs := int64(retry/time.Second) + 1
			w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
			writeProblem(w, Problem{Status: http.StatusTooManyRequests, Code: "rate_limited",
				Detail: fmt.Sprintf("at most %d requests per %s", lim.N, lim.Per)})
			return true
		}
	}
	return false
}
