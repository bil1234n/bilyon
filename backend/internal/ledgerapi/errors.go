package ledgerapi

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bil1234n/bilyon/backend/internal/ledger"
)

// ErrorDomain is the google.rpc.ErrorInfo domain of ledger errors.
const ErrorDomain = "ledger.bilyon"

// Reasons carried in ErrorInfo.
const (
	ReasonInvalid             = "INVALID"
	ReasonNotFound            = "NOT_FOUND"
	ReasonInsufficientFunds   = "INSUFFICIENT_FUNDS"
	ReasonAccountFrozen       = "ACCOUNT_FROZEN"
	ReasonCurrencyMismatch    = "CURRENCY_MISMATCH"
	ReasonUnbalanced          = "UNBALANCED"
	ReasonHoldNotPending      = "HOLD_NOT_PENDING"
	ReasonHoldExpired         = "HOLD_EXPIRED"
	ReasonIdempotencyConflict = "IDEMPOTENCY_CONFLICT"
	ReasonOverflow            = "OVERFLOW"
	ReasonAlreadyReversed     = "ALREADY_REVERSED"
	ReasonNotReversible       = "NOT_REVERSIBLE"
	ReasonReserveClosed       = "RESERVE_CLOSED"
	ReasonUnavailable         = "UNAVAILABLE"
)

// sentinel pairs a ledger error with its wire form.
type sentinel struct {
	err    error
	code   codes.Code
	reason string
}

// sentinels is ordered: typed errors are matched by their Unwrap target.
var sentinels = []sentinel{
	{ledger.ErrInvalid, codes.InvalidArgument, ReasonInvalid},
	{ledger.ErrNotFound, codes.NotFound, ReasonNotFound},
	{ledger.ErrInsufficientFunds, codes.FailedPrecondition, ReasonInsufficientFunds},
	{ledger.ErrAccountFrozen, codes.FailedPrecondition, ReasonAccountFrozen},
	{ledger.ErrCurrencyMismatch, codes.InvalidArgument, ReasonCurrencyMismatch},
	{ledger.ErrUnbalanced, codes.InvalidArgument, ReasonUnbalanced},
	{ledger.ErrHoldNotPending, codes.FailedPrecondition, ReasonHoldNotPending},
	{ledger.ErrHoldExpired, codes.FailedPrecondition, ReasonHoldExpired},
	{ledger.ErrIdempotencyConflict, codes.AlreadyExists, ReasonIdempotencyConflict},
	{ledger.ErrOverflow, codes.OutOfRange, ReasonOverflow},
	{ledger.ErrAlreadyReversed, codes.FailedPrecondition, ReasonAlreadyReversed},
	{ledger.ErrNotReversible, codes.FailedPrecondition, ReasonNotReversible},
	{ledger.ErrReserveClosed, codes.FailedPrecondition, ReasonReserveClosed},
	{ledger.ErrUnavailable, codes.Unavailable, ReasonUnavailable},
}

// ToStatus converts a ledger error into a gRPC status with an ErrorInfo
// whose metadata preserves the typed error's fields. Unknown errors become
// Internal without their text: it may hold database details.
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
		info := &errdetails.ErrorInfo{Domain: ErrorDomain, Reason: s.reason, Metadata: metadata(err)}
		st, derr := status.New(s.code, err.Error()).WithDetails(info)
		if derr != nil {
			return status.Error(s.code, err.Error())
		}
		return st.Err()
	}
	return status.Error(codes.Internal, "internal error")
}

func metadata(err error) map[string]string {
	var (
		ve *ledger.ValidationError
		nf *ledger.NotFoundError
		ie *ledger.InsufficientFundsError
		fe *ledger.FrozenError
	)
	switch {
	case errors.As(err, &ve):
		return map[string]string{"field": ve.Field, "reason": ve.Reason}
	case errors.As(err, &nf):
		return map[string]string{"object": nf.Object, "id": nf.ID.String()}
	case errors.As(err, &ie):
		return map[string]string{"account_id": ie.AccountID.String(), "available": strconv.FormatInt(ie.Available, 10),
			"required": strconv.FormatInt(ie.Required, 10), "floor": strconv.FormatInt(ie.Floor, 10)}
	case errors.As(err, &fe):
		return map[string]string{"account_id": fe.AccountID.String()}
	default:
		return nil
	}
}

// FromStatus converts a gRPC error back into the ledger error it carries,
// rebuilding typed errors from ErrorInfo metadata. Transport failures map to
// ledger.ErrUnavailable so callers can retry with the same idempotency key.
func FromStatus(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%w: %v", ledger.ErrUnavailable, err)
	}
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok || info.GetDomain() != ErrorDomain {
			continue
		}
		if typed := typedError(info.GetReason(), info.GetMetadata()); typed != nil {
			return typed
		}
		for _, s := range sentinels {
			if s.reason == info.GetReason() {
				return fmt.Errorf("%w: %s", s.err, st.Message())
			}
		}
	}
	switch st.Code() {
	case codes.Canceled:
		return fmt.Errorf("%w: %s", context.Canceled, st.Message())
	case codes.DeadlineExceeded:
		return fmt.Errorf("%w: %s", context.DeadlineExceeded, st.Message())
	case codes.Unavailable, codes.ResourceExhausted, codes.Aborted:
		return fmt.Errorf("%w: %s", ledger.ErrUnavailable, st.Message())
	default:
		return fmt.Errorf("ledgerapi: %s: %s", st.Code(), st.Message())
	}
}

func typedError(reason string, md map[string]string) error {
	switch reason {
	case ReasonInvalid:
		if md["field"] != "" {
			return &ledger.ValidationError{Field: md["field"], Reason: md["reason"]}
		}
	case ReasonNotFound:
		if id, err := uuid.Parse(md["id"]); err == nil && md["object"] != "" {
			return &ledger.NotFoundError{Object: md["object"], ID: id}
		}
	case ReasonInsufficientFunds:
		id, err := uuid.Parse(md["account_id"])
		avail, err2 := strconv.ParseInt(md["available"], 10, 64)
		req, err3 := strconv.ParseInt(md["required"], 10, 64)
		floor, err4 := strconv.ParseInt(md["floor"], 10, 64)
		if err == nil && err2 == nil && err3 == nil && err4 == nil {
			return &ledger.InsufficientFundsError{AccountID: id, Available: avail, Required: req, Floor: floor}
		}
	case ReasonAccountFrozen:
		if id, err := uuid.Parse(md["account_id"]); err == nil {
			return &ledger.FrozenError{AccountID: id}
		}
	}
	return nil
}
