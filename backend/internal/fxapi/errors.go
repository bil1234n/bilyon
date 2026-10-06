// Package fxapi serves the FX engine over gRPC (bilyon.fx.v1) and provides
// the Go client the gateway and orchestrator use. Engine errors travel as
// gRPC statuses carrying a google.rpc.ErrorInfo (domain "fx.bilyon") and
// are rebuilt into the same sentinel errors on the client side.
package fxapi

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bil1234n/bilyon/backend/internal/fx"
	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of FX errors.
const ErrorDomain = "fx.bilyon"

// ErrUnavailable means the FX service could not be reached or is a
// standby; retrying (against the leader) may succeed.
var ErrUnavailable = errors.New("fx: service unavailable")

type sentinel struct {
	err    error
	code   codes.Code
	reason string
}

var sentinels = []sentinel{
	{fx.ErrUnknownQuote, codes.NotFound, "UNKNOWN_QUOTE"},
	{fx.ErrUnknownEdge, codes.NotFound, "UNKNOWN_EDGE"},
	{fx.ErrTampered, codes.PermissionDenied, "TAMPERED"},
	{fx.ErrExpired, codes.FailedPrecondition, "EXPIRED"},
	{fx.ErrRequote, codes.FailedPrecondition, "REQUOTE"},
	{fx.ErrFailed, codes.FailedPrecondition, "FAILED"},
	{fx.ErrPayoutPending, codes.Unavailable, "PAYOUT_PENDING"},
	{fx.ErrConflict, codes.AlreadyExists, "CONFLICT"},
	{fx.ErrFunding, codes.InvalidArgument, "FUNDING"},
	{fx.ErrRequest, codes.InvalidArgument, "INVALID"},
	{fx.ErrUnknownCurrency, codes.InvalidArgument, "UNKNOWN_CURRENCY"},
	{fx.ErrInvalidEdge, codes.InvalidArgument, "INVALID_EDGE"},
	{fx.ErrPairNotConfigured, codes.FailedPrecondition, "PAIR_NOT_CONFIGURED"},
	{fx.ErrNoMid, codes.Unavailable, "NO_MID"},
	{fx.ErrNoRoute, codes.FailedPrecondition, "NO_ROUTE"},
	{ErrUnavailable, codes.Unavailable, "STANDBY"},
	{ledger.ErrUnavailable, codes.Unavailable, "LEDGER_UNAVAILABLE"},
}

// ToStatus converts an engine error into a gRPC status. Unknown errors
// become Internal without their text, which may hold database details.
func ToStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	for _, s := range sentinels {
		if !errors.Is(err, s.err) {
			continue
		}
		st, derr := status.New(s.code, err.Error()).WithDetails(&errdetails.ErrorInfo{Domain: ErrorDomain, Reason: s.reason})
		if derr != nil {
			return status.Error(s.code, err.Error())
		}
		return st.Err()
	}
	return status.Error(codes.Internal, "internal error")
}

// FromStatus rebuilds the engine error a status carries. Transport
// failures and unknown unavailability map to ErrUnavailable.
func FromStatus(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok || info.Domain != ErrorDomain {
			continue
		}
		for _, s := range sentinels {
			if s.reason == info.Reason {
				if s.err == ErrUnavailable {
					return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
				}
				return &remoteError{sentinel: s.err, msg: st.Message()}
			}
		}
	}
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
	case codes.Canceled:
		return context.Canceled
	}
	return fmt.Errorf("fx: remote error (%s): %s", st.Code(), st.Message())
}

// remoteError carries the server's message while matching its sentinel.
type remoteError struct {
	sentinel error
	msg      string
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Unwrap() error { return e.sentinel }
