package broker

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ErrForbidden means the SPIFFE identity exists but the requested permission
// scope is not covered by its policy. The broker does not restrict which
// repositories a policy can cover; the GitHub App installation does.
var ErrForbidden = errors.New("requested scope is not permitted")

// TokenRequest is the authorization input for a MintToken RPC.
type TokenRequest struct {
	Repository  string            `json:"repository"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

// Principal identifies an authenticated caller, either by SPIFFE ID or SELinux type.
type Principal struct {
	SPIFFEID    spiffeid.ID
	SELinuxType string
}

// String returns a canonical string representation suitable for logging and cache keys.
func (p Principal) String() string {
	if p.SELinuxType != "" {
		return "selinux:" + p.SELinuxType
	}
	return p.SPIFFEID.String()
}

func (p Principal) matches(policy Policy) bool {
	if p.SELinuxType != "" && policy.SELinuxType != "" {
		return p.SELinuxType == policy.SELinuxType
	}
	if !p.SPIFFEID.IsZero() && !policy.SPIFFEID.IsZero() {
		return p.SPIFFEID.String() == policy.SPIFFEID.String()
	}
	return false
}

// Authorize returns the policy and the exact permission set to mint. The
// requested repository must be a valid owner/repo name; the GitHub App
// installation, not the broker, restricts which repositories a policy can
// cover. An empty request permission set means "all permissions granted to
// this identity".
func (c *Config) Authorize(principal Principal, req TokenRequest) (Policy, map[string]string, error) {
	repository := strings.TrimSpace(req.Repository)
	if repository == "" {
		return Policy{}, nil, fmt.Errorf("repository is required")
	}
	if !validRepository(repository) {
		return Policy{}, nil, fmt.Errorf("repository %q must be owner/repo", repository)
	}

	for _, policy := range c.Policies {
		if !principal.matches(policy) {
			continue
		}
		permissions := policy.Permissions
		if len(req.Permissions) > 0 {
			permissions = clonePermissions(req.Permissions)
			for name, value := range permissions {
				allowed, ok := policy.Permissions[name]
				if !ok {
					return Policy{}, nil, ErrForbidden
				}
				requestedRank, ok := permissionRank(value)
				if !ok {
					return Policy{}, nil, fmt.Errorf("invalid permission %q=%q", name, value)
				}
				allowedRank, _ := permissionRank(allowed)
				if requestedRank > allowedRank {
					return Policy{}, nil, ErrForbidden
				}
			}
		}
		return policy, clonePermissions(permissions), nil
	}
	return Policy{}, nil, ErrForbidden
}

func permissionRank(value string) (int, bool) {
	switch strings.ToLower(value) {
	case "read":
		return 1, true
	case "write":
		return 2, true
	default:
		return 0, false
	}
}

func clonePermissions(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func permissionKey(permissions map[string]string) string {
	keys := make([]string, 0, len(permissions))
	for key := range permissions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(permissions[key])
		b.WriteByte(',')
	}
	return b.String()
}
