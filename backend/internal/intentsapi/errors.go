// Package intentsapi serves the payment orchestrator over gRPC
// (bilyon.intents.v1) for the realtime gateway, and provides the Go client.
// Orchestrator errors travel as gRPC statuses with a google.rpc.ErrorInfo
// (domain "intents.bilyon") and are rebuilt into the same sentinels.
package intentsapi

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bil1234n/bilyon/backend/internal/intents"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of intent errors.
const ErrorDomain = "intents.bilyon"

type sentinel struct {
	err    error
	code   codes.Code
	reason string
}

var sentinels = []sentinel{
	{intents.ErrTxAuth, codes.PermissionDenied, "TXAUTH"},
	{intents.ErrNonce, codes.PermissionDenied, "NONCE"},
	{intents.ErrStale, codes.PermissionDenied, "STALE"},
	{intents.ErrMismatch, codes.InvalidArgument, "MISMATCH"},
	{intents.ErrConflict, codes.AlreadyExists, "CONFLICT"},
	{intents.ErrNotFound, codes.NotFound, "NOT_FOUND"},
	{intents.ErrForbidden, codes.PermissionDenied, "FORBIDDEN"},
	{intents.ErrState, codes.FailedPrecondition, "STATE"},
	{intents.ErrRequest, codes.InvalidArgument, "INVALID"},
	{intents.ErrUnavailable, codes.Unavailable, "UNAVAILABLE"},
}

// ErrUnavailable means the service could not be reached; retrying may
// succeed (every operation is idempotent).
var ErrUnavailable = intents.ErrUnavailable

// ToStatus converts an orchestrator error into a gRPC status. Unknown
// errors become Internal without their text, which may hold database
// details.
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
		info := &errdetails.ErrorInfo{Domain: ErrorDomain, Reason: s.reason}
		var se *intents.StateError
		if errors.As(err, &se) {
			info.Metadata = map[string]string{"state": string(se.State), "op": se.Op}
		}
		st, derr := status.New(s.code, err.Error()).WithDetails(info)
		if derr != nil {
			return status.Error(s.code, err.Error())
		}
		return st.Err()
	}
	return status.Error(codes.Internal, "internal error")
}

// FromStatus rebuilds the orchestrator error a status carries.
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
		if info.Reason == "STATE" {
			return &intents.StateError{Op: info.Metadata["op"], State: intents.State(info.Metadata["state"])}
		}
		for _, s := range sentinels {
			if s.reason == info.Reason {
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
	return fmt.Errorf("intents: remote error (%s): %s", st.Code(), st.Message())
}

// remoteError carries the server's message while matching its sentinel.
type remoteError struct {
	sentinel error
	msg      string
}

func (e *remoteError) Error() string { return e.msg }
func (e *remoteError) Unwrap() error { return e.sentinel }
