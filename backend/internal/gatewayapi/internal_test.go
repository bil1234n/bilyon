package gatewayapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.7:5555"
	r.Header.Add("X-Forwarded-For", "203.0.113.9, 198.51.100.4")
	r.Header.Add("X-Forwarded-For", "192.0.2.1")
	for hops, want := range map[int]string{0: "10.0.0.7", 1: "192.0.2.1", 2: "198.51.100.4", 3: "203.0.113.9",
		4: "10.0.0.7"} {
		if got := clientIP(r, hops); got != want {
			t.Errorf("%d hops: %s, want %s", hops, got, want)
		}
	}
	// A spoofed, unparseable entry falls back to the connection.
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := clientIP(r, 1); got != "10.0.0.7" {
		t.Fatalf("garbage header: %s", got)
	}
	r.RemoteAddr = "unix-socket"
	if got := clientIP(r, 0); got != "unix-socket" {
		t.Fatalf("no port: %s", got)
	}
}

func TestMiddlewareRecoversPanics(t *testing.T) {
	var logs bytes.Buffer
	a := &API{log: slog.New(slog.NewTextHandler(&logs, nil)), m: newMetrics(nil)}
	h := a.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "internal_error") ||
		rec.Header().Get("X-Request-Id") == "" {
		t.Fatalf("panic answered %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "boom") || strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("panic details must be logged, not returned: %s", logs.String())
	}
	// http.ErrAbortHandler aborts the response as net/http intends.
	abort := a.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("recovered %v", v)
		}
	}()
	abort.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestBytesJSON(t *testing.T) {
	var b Bytes
	for _, bad := range []string{`"a+b/"`, `"YQ=="`, `12`, `"Y Q"`} {
		if err := b.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := b.UnmarshalJSON([]byte(`"_-8"`)); err != nil || len(b) != 2 {
		t.Fatalf("url-safe alphabet: %v %x", err, b)
	}
	out, _ := Bytes{0xfb, 0xff}.MarshalJSON()
	if string(out) != `"-_8"` {
		t.Fatalf("marshal %s", out)
	}
}
