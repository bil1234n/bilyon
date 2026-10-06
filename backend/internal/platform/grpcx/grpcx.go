// Package grpcx holds the gRPC plumbing shared by Bilyon services: mutual
// TLS with certificate hot-reload (workload certificates rotate hourly),
// peer identities from verified client certificates, per-method access
// control, and recovery, logging and metrics interceptors (RFC 0001 §1.2
// TB5: "mTLS, service identity, per-command authorisation").
package grpcx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// TLSFiles locates PEM files for mutual TLS.
type TLSFiles struct {
	CertFile   string // own certificate chain
	KeyFile    string // own private key
	CAFile     string // trust anchors for the peer's certificate
	ServerName string // client only: name expected in the server certificate
}

// keyPair reloads a certificate and key when either file changes, checking
// at most once per interval, so rotated workload certificates take effect
// without a restart.
type keyPair struct {
	files    TLSFiles
	interval time.Duration

	mu      sync.Mutex
	cert    *tls.Certificate
	checked time.Time
	modTime time.Time
}

func newKeyPair(files TLSFiles) (*keyPair, error) {
	kp := &keyPair{files: files, interval: 30 * time.Second}
	if _, err := kp.get(); err != nil {
		return nil, err
	}
	return kp, nil
}

func latestModTime(paths ...string) (time.Time, error) {
	var latest time.Time
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return time.Time{}, err
		}
		if st.ModTime().After(latest) {
			latest = st.ModTime()
		}
	}
	return latest, nil
}

func (kp *keyPair) get() (*tls.Certificate, error) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	if kp.cert != nil && time.Since(kp.checked) < kp.interval {
		return kp.cert, nil
	}
	kp.checked = time.Now()
	mod, err := latestModTime(kp.files.CertFile, kp.files.KeyFile)
	if err != nil {
		if kp.cert != nil {
			return kp.cert, nil // keep serving the last good pair
		}
		return nil, fmt.Errorf("grpcx: certificate files: %w", err)
	}
	if kp.cert != nil && !mod.After(kp.modTime) {
		return kp.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(kp.files.CertFile, kp.files.KeyFile)
	if err != nil {
		if kp.cert != nil {
			return kp.cert, nil // a half-written rotation: retry next interval
		}
		return nil, fmt.Errorf("grpcx: load key pair: %w", err)
	}
	kp.cert, kp.modTime = &cert, mod
	return kp.cert, nil
}

func loadPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("grpcx: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("grpcx: CA file contains no certificates")
	}
	return pool, nil
}

// ServerTLS returns server credentials that require and verify a client
// certificate signed by the CA, with TLS 1.3 only.
func ServerTLS(files TLSFiles) (credentials.TransportCredentials, error) {
	kp, err := newKeyPair(files)
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(files.CAFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return kp.get() },
	}), nil
}

// ClientTLS returns client credentials presenting the key pair and
// verifying the server against the CA.
func ClientTLS(files TLSFiles) (credentials.TransportCredentials, error) {
	kp, err := newKeyPair(files)
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(files.CAFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              pool,
		ServerName:           files.ServerName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return kp.get() },
	}), nil
}

// PeerIdentity returns the identity of an mTLS-authenticated caller: the
// first URI SAN of its verified leaf certificate (a SPIFFE ID such as
// spiffe://bilyon/gateway), else the subject common name.
func PeerIdentity(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return "", false
	}
	leaf := info.State.VerifiedChains[0][0]
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String(), true
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName, true
	}
	return "", false
}

// ACL maps caller identities to the methods (short names such as
// "Transfer", or "*") they may invoke.
type ACL map[string][]string

// ParseACL reads "identity=Method,Method;identity=*".
func ParseACL(s string) (ACL, error) {
	acl := ACL{}
	for _, rule := range strings.Split(s, ";") {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		id, methods, ok := strings.Cut(rule, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return nil, fmt.Errorf("grpcx: ACL rule %q: want identity=methods", rule)
		}
		for _, m := range strings.Split(methods, ",") {
			if m = strings.TrimSpace(m); m != "" {
				acl[id] = append(acl[id], m)
			}
		}
		if len(acl[id]) == 0 {
			return nil, fmt.Errorf("grpcx: ACL rule %q grants nothing", rule)
		}
	}
	return acl, nil
}

// Allows reports whether identity may call fullMethod ("/pkg.Service/Method").
func (a ACL) Allows(identity, fullMethod string) bool {
	allowed, ok := a[identity]
	if !ok {
		return false
	}
	short := fullMethod[strings.LastIndexByte(fullMethod, '/')+1:]
	return slices.Contains(allowed, "*") || slices.Contains(allowed, short)
}

// AuthorizeUnary enforces the ACL on mTLS identities. Calls without a
// verified identity are rejected unless allowAnonymous (development only).
func AuthorizeUnary(acl ACL, allowAnonymous bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id, ok := PeerIdentity(ctx)
		if !ok {
			if allowAnonymous {
				return handler(ctx, req)
			}
			return nil, status.Error(codes.Unauthenticated, "client certificate required")
		}
		if !acl.Allows(id, info.FullMethod) {
			return nil, status.Errorf(codes.PermissionDenied, "%s may not call %s", id, info.FullMethod)
		}
		return handler(ctx, req)
	}
}

// RecoverUnary turns a handler panic into codes.Internal.
func RecoverUnary(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.ErrorContext(ctx, "gRPC handler panicked", slog.String("method", info.FullMethod),
					slog.Any("panic", r), slog.String("stack", string(debug.Stack())))
				resp, err = nil, status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// Metrics records request counts and latencies per method and code.
type Metrics struct {
	requests *prometheus.CounterVec
	latency  *prometheus.HistogramVec
}

// NewMetrics registers gRPC server metrics (reg may be nil).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "bilyon_grpc_requests_total",
			Help: "gRPC requests by method and status code."}, []string{"method", "code"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "bilyon_grpc_request_seconds",
			Help:    "gRPC request latency by method.",
			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5}}, []string{"method"}),
	}
	if reg != nil {
		reg.MustRegister(m.requests, m.latency)
	}
	return m
}

// ObserveUnary logs and measures each call.
func ObserveUnary(log *slog.Logger, m *Metrics) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err)
		elapsed := time.Since(start)
		m.requests.WithLabelValues(info.FullMethod, code.String()).Inc()
		m.latency.WithLabelValues(info.FullMethod).Observe(elapsed.Seconds())
		level := slog.LevelDebug
		if code == codes.Internal || code == codes.Unknown || code == codes.DataLoss {
			level = slog.LevelError
		}
		id, _ := PeerIdentity(ctx)
		log.Log(ctx, level, "gRPC request", slog.String("method", info.FullMethod), slog.String("code", code.String()),
			slog.Duration("took", elapsed), slog.String("peer", id))
		return resp, err
	}
}

// RetryServiceConfig retries UNAVAILABLE calls with backoff. Use it only
// for services whose calls are idempotent (every ledger command carries an
// idempotency key).
const RetryServiceConfig = `{
  "methodConfig": [{
    "name": [{}],
    "retryPolicy": {
      "maxAttempts": 4,
      "initialBackoff": "0.05s",
      "maxBackoff": "1s",
      "backoffMultiplier": 2,
      "retryableStatusCodes": ["UNAVAILABLE"]
    }
  }]
}`
