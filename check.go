package permio

import (
	"context"
	"slices"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
)

// CheckRequest is a check of several permissions on several resources.
type CheckRequest struct {
	// Principal is the principal (user, service, "group:<slug>"...) whose
	// permissions are checked.
	Principal string
	// Resources are resource URIs; every one is checked. At most 100.
	Resources []string
	// Permissions are permission names. At most 100.
	Permissions []string
}

func checkInputs(principal string, resources, permissions []string, maxResources int) ([]string, []string, error) {
	if principal == "" {
		return nil, nil, invalid("principal is required")
	}
	resources, permissions = uniq(resources), uniq(permissions)
	if len(resources) == 0 {
		return nil, nil, invalid("at least one resource is required")
	}
	if len(permissions) == 0 {
		return nil, nil, invalid("at least one permission is required")
	}
	if maxResources > 0 && len(resources) > maxResources {
		return nil, nil, invalid("at most %d resources per check", maxResources)
	}
	if len(permissions) > MaxBatch {
		return nil, nil, invalid("at most %d permissions per check", MaxBatch)
	}
	for _, p := range permissions {
		if p == "" {
			return nil, nil, invalid("permission names must not be empty")
		}
	}
	for _, r := range resources {
		if err := ValidateResourceURI(r); err != nil {
			return nil, nil, err
		}
	}
	return resources, permissions, nil
}

// CheckDetailed checks whether the principal holds every permission on every
// resource and returns what is missing. A denial is a normal result, not an
// error.
//
// It fails with [KindPermission] if the API key lacks permission.check, and
// [KindValidation] for malformed URIs or empty inputs.
func (c *Client) CheckDetailed(ctx context.Context, req CheckRequest) (*CheckResult, error) {
	resources, permissions, err := checkInputs(req.Principal, req.Resources, req.Permissions, MaxBatch)
	if err != nil {
		return nil, err
	}
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.Check(ctx, &pb.CheckPermissionRequest{
		ProjectName: project, PrincipalId: req.Principal, ResourceUris: resources, Permissions: permissions,
	})
	if err != nil {
		return nil, err
	}
	out := &CheckResult{Allowed: res.GetPassed(), Missing: []MissingPermission{}}
	for _, m := range res.GetMissingPermissions() {
		if len(m.GetMissingPermissions()) == 0 {
			continue
		}
		out.Missing = append(out.Missing, MissingPermission{Resource: m.GetResourceUri(), Permissions: m.GetMissingPermissions()})
	}
	return out, nil
}

// Check reports whether principal holds permission on resource. A denial is
// false with a nil error.
func (c *Client) Check(ctx context.Context, principal, permission, resource string) (bool, error) {
	return c.CheckAll(ctx, principal, []string{permission}, resource)
}

// CheckAll reports whether principal holds every one of permissions on resource.
func (c *Client) CheckAll(ctx context.Context, principal string, permissions []string, resource string) (bool, error) {
	res, err := c.CheckDetailed(ctx, CheckRequest{Principal: principal, Resources: []string{resource}, Permissions: permissions})
	if err != nil {
		return false, err
	}
	return res.Allowed, nil
}

// CheckAny reports whether principal holds at least one of permissions on
// resource. It makes a single Check call.
func (c *Client) CheckAny(ctx context.Context, principal string, permissions []string, resource string) (bool, error) {
	res, err := c.CheckDetailed(ctx, CheckRequest{Principal: principal, Resources: []string{resource}, Permissions: permissions})
	if err != nil {
		return false, err
	}
	if res.Allowed {
		return true, nil
	}
	if len(res.Missing) == 0 {
		// Denied without saying what is missing: fail closed.
		return false, nil
	}
	wanted := uniq(permissions)
	for _, m := range res.Missing {
		if !slices.ContainsFunc(wanted, func(p string) bool { return !slices.Contains(m.Permissions, p) }) {
			return false, nil
		}
	}
	return true, nil
}

// Assert returns nil when principal holds permission on resource, and an
// [Error] of kind [KindDenied] (with Missing filled in) when it does not.
func (c *Client) Assert(ctx context.Context, principal, permission, resource string) error {
	return c.AssertAll(ctx, CheckRequest{Principal: principal, Resources: []string{resource}, Permissions: []string{permission}})
}

// AssertAll returns nil when the principal holds every permission on every
// resource, and an [Error] of kind [KindDenied] when it does not.
func (c *Client) AssertAll(ctx context.Context, req CheckRequest) error {
	res, err := c.CheckDetailed(ctx, req)
	if err != nil {
		return err
	}
	if !res.Allowed {
		return deniedError(req.Principal, res.Missing)
	}
	return nil
}

// BatchCheck checks each resource separately and returns, per resource URI,
// whether principal holds every one of permissions on it. Use it to filter a
// list you already have in memory. More than 100 resources are split into
// several calls.
func (c *Client) BatchCheck(ctx context.Context, principal string, permissions []string, resources []string) (map[string]bool, error) {
	entries, err := c.BatchCheckDetailed(ctx, principal, permissions, resources)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		out[e.Resource] = e.Allowed
	}
	return out, nil
}

// BatchCheckDetailed is BatchCheck returning one entry per distinct resource,
// in request order, with the missing permissions.
func (c *Client) BatchCheckDetailed(ctx context.Context, principal string, permissions []string, resources []string) ([]BatchResult, error) {
	resources, permissions, err := checkInputs(principal, resources, permissions, 0)
	if err != nil {
		return nil, err
	}
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	byURI := map[string]BatchResult{}
	for chunk := range slices.Chunk(resources, MaxBatch) {
		res, err := c.permissions.BatchCheck(ctx, &pb.BatchCheckRequest{
			ProjectName: project, PrincipalId: principal, ResourceUris: chunk, Permissions: permissions,
		})
		if err != nil {
			return nil, err
		}
		for _, r := range res.GetResults() {
			missing := r.GetMissingPermissions()
			if missing == nil {
				missing = []string{}
			}
			byURI[r.GetResourceUri()] = BatchResult{Resource: r.GetResourceUri(), Allowed: r.GetAllowed() && len(missing) == 0, Missing: missing}
		}
	}
	out := make([]BatchResult, 0, len(resources))
	for _, r := range resources {
		e, ok := byURI[r]
		if !ok {
			// Fail closed: every requested resource must have its own answer.
			return nil, inconsistent("no BatchCheck result for %q", r)
		}
		out = append(out, e)
	}
	return out, nil
}
