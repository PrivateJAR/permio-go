package permio

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Kind classifies an [Error]. Kinds are also errors, so callers can match them
// with [errors.Is]:
//
//	if errors.Is(err, permio.ErrNotFound) { ... }
type Kind string

const (
	// KindConfig: the client is configured incorrectly, e.g. a malformed API
	// key or no project.
	KindConfig Kind = "config"
	// KindAuth: the API key was missing, unknown or revoked (gRPC Unauthenticated).
	KindAuth Kind = "auth"
	// KindPermission: the API key is valid but may not make this call (gRPC
	// PermissionDenied), e.g. a check-only key trying to write. This is about
	// the caller's rights; a principal failing a check is [KindDenied].
	KindPermission Kind = "permission_denied"
	// KindValidation: the request was rejected as malformed (gRPC
	// InvalidArgument), or failed the SDK's own input checks.
	KindValidation Kind = "invalid_argument"
	// KindNotFound: the entity does not exist (gRPC NotFound).
	KindNotFound Kind = "not_found"
	// KindAlreadyExists: the entity already exists (gRPC AlreadyExists).
	KindAlreadyExists Kind = "already_exists"
	// KindUnavailable: the API could not be reached (gRPC Unavailable).
	KindUnavailable Kind = "unavailable"
	// KindTimeout: the call did not finish in time (gRPC DeadlineExceeded).
	KindTimeout Kind = "timeout"
	// KindRateLimited: the organisation's rate limit is used up (gRPC
	// ResourceExhausted). [Error.RetryAfter] is the server's requested delay.
	KindRateLimited Kind = "rate_limited"
	// KindDenied: returned by the Assert methods when the principal does not
	// hold the permissions. A normal authorization outcome, not an API failure.
	KindDenied Kind = "denied"
	// KindOther: anything else, including cancellation by the caller.
	KindOther Kind = "error"
)

// Error makes a Kind usable as an errors.Is target.
func (k Kind) Error() string { return "permio: " + string(k) }

// Sentinels for errors.Is. Each is the matching Kind.
var (
	ErrConfig        error = KindConfig
	ErrAuth          error = KindAuth
	ErrPermission    error = KindPermission
	ErrValidation    error = KindValidation
	ErrNotFound      error = KindNotFound
	ErrAlreadyExists error = KindAlreadyExists
	ErrUnavailable   error = KindUnavailable
	ErrTimeout       error = KindTimeout
	ErrRateLimited   error = KindRateLimited
	ErrDenied        error = KindDenied
)

// MissingPermission lists permissions missing on one resource.
type MissingPermission struct {
	Resource    string   `json:"resource"`
	Permissions []string `json:"permissions"`
}

// Error is the error returned by every Client call that fails, including calls
// made through the raw clients ([Client.Permissions], [Client.Organisations]).
// Use errors.As to read its fields, or errors.Is with a Kind / Err* sentinel.
type Error struct {
	// Kind classifies the error.
	Kind Kind
	// Code is the gRPC status code. Errors raised by the SDK itself use
	// FailedPrecondition (config), PermissionDenied (denied) and
	// InvalidArgument (its own input checks). It is never codes.OK.
	Code codes.Code
	// Message is the server's (or SDK's) message.
	Message string
	// Missing is set for KindPermission (what the API key lacks, with the
	// server's fully qualified internal URIs) and KindDenied (what the
	// principal lacks).
	Missing []MissingPermission
	// Principal is the checked principal, for KindDenied.
	Principal string
	// RetryAfter is the delay the server asked for (google.rpc.RetryInfo or a
	// retry-after header), for KindRateLimited and sometimes KindUnavailable.
	// Zero when the server gave none.
	RetryAfter time.Duration
	// Metadata holds the response headers and trailers sent with the error.
	Metadata metadata.MD

	cause error
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "permio: " + string(e.Kind)
	}
	return "permio: " + e.Message
}

// Unwrap returns the underlying gRPC or context error, if any.
func (e *Error) Unwrap() error { return e.cause }

// Is matches Kind targets, so errors.Is(err, permio.ErrAuth) works.
func (e *Error) Is(target error) bool {
	k, ok := target.(Kind)
	return ok && k == e.Kind
}

// GRPCStatus lets status.FromError and status.Code read the gRPC code. The
// code is never codes.OK: an *Error is always a failure.
func (e *Error) GRPCStatus() *status.Status {
	if e.cause != nil {
		if st, ok := status.FromError(e.cause); ok && st.Code() != codes.OK {
			return st
		}
	}
	code := e.Code
	if code == codes.OK {
		code = codes.Unknown
	}
	return status.New(code, e.Message)
}

// KindOf returns the Kind of err, or "" if it is not an *Error.
func KindOf(err error) Kind {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Kind
	}
	return ""
}

// IsNotFound reports whether err is a NotFound error.
func IsNotFound(err error) bool { return KindOf(err) == KindNotFound }

// The permissions service formats PermissionDenied as Go's %+v of its missing list:
//
//	missing permissions: [{ResourceURI:/organisation/o/project/p/doc MissingPermissions:[permission.check]} ...]
var missingEntry = regexp.MustCompile(`\{ResourceURI:(\S*) MissingPermissions:\[([^\]]*)\]\}`)

// ParseMissingPermissions extracts the missing-permission list from a
// PermissionDenied message, if it has one.
func ParseMissingPermissions(msg string) []MissingPermission {
	var out []MissingPermission
	for _, m := range missingEntry.FindAllStringSubmatch(msg, -1) {
		out = append(out, MissingPermission{Resource: m[1], Permissions: strings.Fields(m[2])})
	}
	return out
}

// toError converts a gRPC (or context) error into an *Error. md is the
// response metadata (headers and trailers), if known.
func toError(err error, md metadata.MD) error {
	if err == nil {
		return nil
	}
	var pe *Error
	if errors.As(err, &pe) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: KindTimeout, Code: codes.DeadlineExceeded, Message: "request timed out", cause: err}
	}
	if errors.Is(err, context.Canceled) {
		return &Error{Kind: KindOther, Code: codes.Canceled, Message: "request cancelled", cause: err}
	}
	st, ok := status.FromError(err)
	if !ok {
		return &Error{Kind: KindOther, Code: codes.Unknown, Message: err.Error(), cause: err}
	}
	e := &Error{Code: st.Code(), Message: st.Message(), Metadata: md, cause: err}
	switch st.Code() {
	case codes.Unauthenticated:
		e.Kind = KindAuth
		if e.Message == "" {
			e.Message = "the API key was rejected"
		}
	case codes.PermissionDenied:
		e.Kind = KindPermission
		e.Missing = ParseMissingPermissions(st.Message())
	case codes.InvalidArgument:
		e.Kind = KindValidation
	case codes.NotFound:
		e.Kind = KindNotFound
	case codes.AlreadyExists:
		e.Kind = KindAlreadyExists
	case codes.Unavailable:
		e.Kind = KindUnavailable
	case codes.DeadlineExceeded:
		e.Kind = KindTimeout
	case codes.ResourceExhausted:
		e.Kind = KindRateLimited
	default:
		e.Kind = KindOther
	}
	e.RetryAfter, _ = serverRetryDelay(st, md)
	if e.Message == "" {
		e.Message = st.Code().String()
	}
	return e
}

// serverRetryDelay is the delay the server asked for: a google.rpc.RetryInfo
// detail, else a retry-after header (seconds or an HTTP date).
func serverRetryDelay(st *status.Status, md metadata.MD) (time.Duration, bool) {
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok && ri.GetRetryDelay() != nil {
			return max(0, ri.GetRetryDelay().AsDuration()), true
		}
	}
	for _, v := range md.Get("retry-after") {
		v = strings.TrimSpace(v)
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Second, true
		}
		if t, err := http.ParseTime(v); err == nil {
			return max(0, time.Until(t)), true
		}
	}
	return 0, false
}

func configError(format string, args ...any) error {
	return &Error{Kind: KindConfig, Code: codes.FailedPrecondition, Message: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) error {
	return &Error{Kind: KindValidation, Code: codes.InvalidArgument, Message: fmt.Sprintf(format, args...)}
}

func inconsistent(format string, args ...any) error {
	return &Error{Kind: KindOther, Code: codes.Internal, Message: "inconsistent response from the API: " + fmt.Sprintf(format, args...)}
}

func deniedError(principal string, missing []MissingPermission) error {
	parts := make([]string, 0, len(missing))
	for _, m := range missing {
		parts = append(parts, strings.Join(m.Permissions, ", ")+" on "+m.Resource)
	}
	summary := strings.Join(parts, "; ")
	if summary == "" {
		summary = "the requested permissions"
	}
	return &Error{Kind: KindDenied, Code: codes.PermissionDenied, Principal: principal, Missing: missing,
		Message: fmt.Sprintf("principal %q is missing %s", principal, summary)}
}
