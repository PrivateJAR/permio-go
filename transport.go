package permio

import (
	"context"
	"math/rand/v2"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Read-only RPCs that are safe to repeat. Anything not listed (every Create,
// Update, Delete, Grant, Revoke, Invite, Set, Invalidate, Remove...) is sent
// exactly once.
//
// Grant and Revoke converge on the server (a grant is additive, a revoke
// ignores names the grant lacks), but they stay off this list: after a timeout
// the first attempt may still land, and repeating it could undo another
// caller's revoke or grant made in between. The caller decides instead.
var idempotentMethods = map[string]bool{
	"/permio.permissions.v1.PermissionsService/Check":                                      true,
	"/permio.permissions.v1.PermissionsService/GetPermission":                              true,
	"/permio.permissions.v1.PermissionsService/ListPermissions":                            true,
	"/permio.permissions.v1.PermissionsService/GetRole":                                    true,
	"/permio.permissions.v1.PermissionsService/ListRoles":                                  true,
	"/permio.permissions.v1.PermissionsService/GetUserPermissionsAndRolesOnResource":       true,
	"/permio.permissions.v1.PermissionsService/ListPrincipals":                             true,
	"/permio.permissions.v1.PermissionsService/GetAllAssignmentsForPrincipal":              true,
	"/permio.permissions.v1.PermissionsService/GetTotalRolesAndPermissionsForOrganisation": true,
	"/permio.permissions.v1.PermissionsService/BatchCheck":                                 true,
	"/permio.permissions.v1.PermissionsService/ListAccess":                                 true,
	"/permio.permissions.v1.PermissionsService/ListPrincipalsWithAccess":                   true,
	"/permio.permissions.v1.PermissionsService/GetGroup":                                   true,
	"/permio.permissions.v1.PermissionsService/ListGroups":                                 true,
	"/permio.permissions.v1.PermissionsService/ListGroupMembers":                           true,
	"/permio.permissions.v1.PermissionsService/ListGroupsForPrincipal":                     true,
	"/permio.permissions.v1.PermissionsService/WhoAmI":                                     true,
	"/permio.organisation.v1.OrganisationService/GetOrganisation":                          true,
	"/permio.organisation.v1.OrganisationService/GetUsersOrganisation":                     true,
	"/permio.organisation.v1.OrganisationService/ListAPIKeys":                              true,
	"/permio.organisation.v1.OrganisationService/GetProject":                               true,
	"/permio.organisation.v1.OrganisationService/GetProjectsForOrganisation":               true,
	"/permio.organisation.v1.OrganisationService/GetPrincipalUsageStats":                   true,
	"/permio.organisation.v1.OrganisationService/GetUsageHistory":                          true,
	"/permio.organisation.v1.OrganisationService/GetOrganisationDashboard":                 true,
}

// IsIdempotent reports whether the SDK retries the RPC with this full gRPC
// method name ("/package.Service/Method").
func IsIdempotent(fullMethod string) bool { return idempotentMethods[fullMethod] }

// RetryOptions configures retries of idempotent reads.
type RetryOptions struct {
	// MaxRetries is the number of retries after the first attempt. Zero means
	// the default, 2; a negative value disables retries.
	MaxRetries int
	// BaseDelay is the backoff before the first retry; it doubles each time,
	// with jitter. Default 100ms.
	BaseDelay time.Duration
	// MaxDelay caps a single backoff. Default 2s. A rate-limited read
	// (ResourceExhausted) is retried after the server's requested delay only
	// when that delay is within MaxDelay; otherwise the error is returned.
	MaxDelay time.Duration
}

func (r RetryOptions) withDefaults() RetryOptions {
	switch {
	case r.MaxRetries == 0:
		r.MaxRetries = 2
	case r.MaxRetries < 0:
		r.MaxRetries = 0
	}
	if r.BaseDelay <= 0 {
		r.BaseDelay = 100 * time.Millisecond
	}
	if r.MaxDelay <= 0 {
		r.MaxDelay = 2 * time.Second
	}
	return r
}

// resilientConn wraps a connection with auth, per-attempt timeouts, retries for
// idempotent reads and error mapping. It wraps any grpc.ClientConnInterface,
// which is how tests run the client against an in-process server.
type resilientConn struct {
	inner         grpc.ClientConnInterface
	authorization string
	timeout       time.Duration // per attempt; 0 = none
	retry         RetryOptions
	sleep         func(context.Context, time.Duration) error
}

var _ grpc.ClientConnInterface = (*resilientConn)(nil)

func (c *resilientConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", c.authorization)
	retries := 0
	if IsIdempotent(method) {
		retries = c.retry.MaxRetries
	}
	for attempt := 0; ; attempt++ {
		var header, trailer metadata.MD
		actx, cancel := ctx, context.CancelFunc(func() {})
		if c.timeout > 0 {
			actx, cancel = context.WithTimeout(ctx, c.timeout)
		}
		err := c.inner.Invoke(actx, method, args, reply, append(opts, grpc.Header(&header), grpc.Trailer(&trailer))...)
		cancel()
		if err == nil {
			return nil
		}
		md := metadata.Join(header, trailer)
		if ctx.Err() != nil {
			// The caller's own deadline or cancellation, not this attempt's.
			return toError(ctx.Err(), md)
		}
		if actx.Err() == context.DeadlineExceeded && status.Code(err) != codes.DeadlineExceeded {
			err = status.Errorf(codes.DeadlineExceeded, "request timed out after %s", c.timeout)
		}
		st, _ := status.FromError(err)
		serverDelay, hasDelay := serverRetryDelay(st, md)
		retryable := st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded ||
			(st.Code() == codes.ResourceExhausted && hasDelay)
		if attempt >= retries || !retryable || (hasDelay && serverDelay > c.retry.MaxDelay) {
			return toError(err, md)
		}
		ceiling := min(c.retry.MaxDelay, c.retry.BaseDelay<<attempt)
		delay := ceiling/2 + jitter(ceiling/2)
		if hasDelay {
			// Wait at least as long as the server asked, plus a little jitter so
			// clients limited in the same second don't all retry at once.
			delay = max(delay, serverDelay+jitter(min(100*time.Millisecond, ceiling)))
		}
		if err := c.sleep(ctx, delay); err != nil {
			return toError(err, nil)
		}
	}
}

// NewStream passes streams through with auth, without timeouts or retries. No
// public RPC streams today.
func (c *resilientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", c.authorization)
	s, err := c.inner.NewStream(ctx, desc, method, opts...)
	if err != nil {
		return nil, toError(err, nil)
	}
	return s, nil
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d) + 1))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
