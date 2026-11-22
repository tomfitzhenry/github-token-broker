package broker

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/tomfitzhenry/github-token-broker/internal/githubapi"
)

// Config is the broker configuration. It is built from command-line flags.
type Config struct {
	ListenAddr        string
	PeerSecListenAddr string
	TrustDomain       spiffeid.TrustDomain
	CacheSkew         time.Duration
	GitHub            GitHubConfig
	Key               *rsa.PrivateKey
	Policies          []Policy
}

type GitHubConfig struct {
	AppID          int64
	InstallationID int64
	PrivateKeyFile string
	APIURL         string
}

type Policy struct {
	SPIFFEID       spiffeid.ID
	SELinuxType    string
	InstallationID int64
	Permissions    map[string]string
}

// LoadPrivateKey reads and parses the GitHub App RSA private key.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	key, err := githubapi.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

// Validate applies defaults and checks the flag-derived configuration.
func (c *Config) Validate() error {
	if c.ListenAddr == "" && c.PeerSecListenAddr == "" {
		return fmt.Errorf("at least one of -listen or -peersec-listen is required")
	}
	if c.ListenAddr != "" && c.TrustDomain.String() == "" {
		return fmt.Errorf("-trust-domain is required when -listen is set")
	}
	if c.GitHub.AppID <= 0 {
		return fmt.Errorf("-app-id is required")
	}
	if c.GitHub.InstallationID <= 0 {
		return fmt.Errorf("-installation-id is required")
	}
	if c.Key == nil {
		return fmt.Errorf("-private-key is required")
	}
	if c.GitHub.APIURL == "" {
		c.GitHub.APIURL = githubapi.DefaultAPIURL
	}
	if c.CacheSkew == 0 {
		c.CacheSkew = 5 * time.Minute
	}
	if c.CacheSkew < time.Minute || c.CacheSkew >= time.Hour {
		return fmt.Errorf("-cache-skew must be between 1m and 59m")
	}
	if len(c.Policies) == 0 {
		return fmt.Errorf("at least one -policy is required")
	}

	for i := range c.Policies {
		policy := &c.Policies[i]
		hasSPIFFE := !policy.SPIFFEID.IsZero()
		hasSELinux := policy.SELinuxType != ""
		if hasSPIFFE == hasSELinux {
			return fmt.Errorf("policies[%d] must specify exactly one of spiffe_id or selinux_type", i)
		}
		if hasSPIFFE {
			if c.TrustDomain.String() == "" {
				return fmt.Errorf("-trust-domain is required for policies[%d].spiffe_id", i)
			}
			if policy.SPIFFEID.TrustDomain().String() != c.TrustDomain.String() {
				return fmt.Errorf("policies[%d].spiffe_id is outside trust domain %s", i, c.TrustDomain)
			}
		}
		if hasSELinux {
			if err := validateSELinuxType(policy.SELinuxType); err != nil {
				return fmt.Errorf("policies[%d].selinux_type: %w", i, err)
			}
		}
		if policy.InstallationID == 0 {
			policy.InstallationID = c.GitHub.InstallationID
		}
		if policy.InstallationID <= 0 {
			return fmt.Errorf("policies[%d].installation_id is required", i)
		}
		if len(policy.Permissions) == 0 {
			return fmt.Errorf("policies[%d].permissions is required", i)
		}
		for name, value := range policy.Permissions {
			if _, ok := permissionRank(value); !ok {
				return fmt.Errorf("policies[%d].permissions[%q] must be read or write", i, name)
			}
		}
	}
	return nil
}

func validateSELinuxType(t string) error {
	if t == "" {
		return fmt.Errorf("must not be empty")
	}
	if t == "unlabeled_t" {
		return fmt.Errorf("unlabeled_t is not allowed")
	}
	if strings.ContainsAny(t, " \t\r\n:") {
		return fmt.Errorf("invalid type %q", t)
	}
	return nil
}

// ParsePolicy parses one repeatable -policy flag:
//
//	spiffe_id=spiffe://example.org/agent/opencode;permissions=contents=write,pull_requests=write
//	selinux_type=svc_reader_t;permissions=contents=read
//
// The GitHub App installation determines which repositories are available; a
// policy only grants permissions. installation_id is optional and defaults to
// the global -installation-id.
func ParsePolicy(raw string, trustDomain spiffeid.TrustDomain, defaultInstallationID int64) (Policy, error) {
	var (
		policy     Policy
		spiffeRaw  string
		selinuxRaw string
		permsRaw   string
		installRaw string
	)
	for _, field := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(field, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return Policy{}, fmt.Errorf("policy field %q must be key=value", field)
		}
		switch strings.TrimSpace(key) {
		case "spiffe_id":
			spiffeRaw = strings.TrimSpace(value)
		case "selinux_type":
			selinuxRaw = strings.TrimSpace(value)
		case "permissions":
			permsRaw = strings.TrimSpace(value)
		case "installation_id":
			installRaw = strings.TrimSpace(value)
		default:
			return Policy{}, fmt.Errorf("unknown policy field %q", key)
		}
	}

	if (spiffeRaw == "") == (selinuxRaw == "") {
		return Policy{}, fmt.Errorf("policy must specify exactly one of spiffe_id or selinux_type")
	}
	if spiffeRaw != "" {
		if trustDomain.String() == "" {
			return Policy{}, fmt.Errorf("-trust-domain is required for spiffe_id policies")
		}
		id, err := spiffeid.FromString(spiffeRaw)
		if err != nil {
			return Policy{}, fmt.Errorf("spiffe_id: %w", err)
		}
		if id.TrustDomain().String() != trustDomain.String() {
			return Policy{}, fmt.Errorf("spiffe_id is outside trust domain %s", trustDomain)
		}
		policy.SPIFFEID = id
	}
	if selinuxRaw != "" {
		if err := validateSELinuxType(selinuxRaw); err != nil {
			return Policy{}, fmt.Errorf("selinux_type: %w", err)
		}
		policy.SELinuxType = selinuxRaw
	}
	if permsRaw == "" {
		return Policy{}, fmt.Errorf("policy is missing permissions")
	}
	policy.Permissions = make(map[string]string)
	for _, pair := range strings.Split(permsRaw, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			return Policy{}, fmt.Errorf("permission %q must be name=read|write", pair)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if _, ok := permissionRank(value); !ok {
			return Policy{}, fmt.Errorf("permission %q must be read or write", value)
		}
		policy.Permissions[name] = value
	}

	policy.InstallationID = defaultInstallationID
	if installRaw != "" {
		installationID, err := strconv.ParseInt(installRaw, 10, 64)
		if err != nil || installationID <= 0 {
			return Policy{}, fmt.Errorf("installation_id %q is invalid", installRaw)
		}
		policy.InstallationID = installationID
	}
	return policy, nil
}

// ParsePolicies parses all repeatable -policy flags.
func ParsePolicies(raw []string, trustDomain spiffeid.TrustDomain, defaultInstallationID int64) ([]Policy, error) {
	policies := make([]Policy, 0, len(raw))
	for i, value := range raw {
		policy, err := ParsePolicy(value, trustDomain, defaultInstallationID)
		if err != nil {
			return nil, fmt.Errorf("policy[%d]: %w", i, err)
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func validRepository(repository string) bool {
	if repository == "" || strings.Contains(repository, "..") {
		return false
	}
	parts := strings.Split(repository, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}
