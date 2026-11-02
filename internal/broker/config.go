package broker

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/tomfitzhenry/github-token-broker/internal/githubapi"
)

// Config is the broker configuration. It is JSON so the only dependency
// beyond go-spiffe is the standard library.
type Config struct {
	ListenAddr  string
	TrustDomain spiffeid.TrustDomain
	CacheSkew   time.Duration
	GitHub      GitHubConfig
	Key         *rsa.PrivateKey
	Policies    []Policy
}

type GitHubConfig struct {
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKeyFile string `json:"private_key_file"`
	APIURL         string `json:"api_url"`
}

type Policy struct {
	SPIFFEID       spiffeid.ID
	InstallationID int64
	Repositories   []string
	Permissions    map[string]string
}

type rawConfig struct {
	ListenAddr       string       `json:"listen_addr"`
	TrustDomain      string       `json:"trust_domain"`
	CacheSkewSeconds int          `json:"cache_skew_seconds"`
	GitHub           GitHubConfig `json:"github"`
	Policies         []rawPolicy  `json:"policies"`
}

type rawPolicy struct {
	SPIFFEID       string            `json:"spiffe_id"`
	InstallationID int64             `json:"installation_id"`
	Repositories   []string          `json:"repositories"`
	Permissions    map[string]string `json:"permissions"`
}

// LoadConfig reads and validates a JSON configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var raw rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if raw.ListenAddr == "" {
		raw.ListenAddr = ":8443"
	}
	if raw.TrustDomain == "" {
		return nil, fmt.Errorf("trust_domain is required")
	}
	trustDomain, err := spiffeid.TrustDomainFromString(raw.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("trust_domain: %w", err)
	}

	cacheSkew := 5 * time.Minute
	if raw.CacheSkewSeconds != 0 {
		if raw.CacheSkewSeconds < 60 || raw.CacheSkewSeconds >= 3600 {
			return nil, fmt.Errorf("cache_skew_seconds must be between 60 and 3599")
		}
		cacheSkew = time.Duration(raw.CacheSkewSeconds) * time.Second
	}

	if raw.GitHub.AppID <= 0 {
		return nil, fmt.Errorf("github.app_id is required")
	}
	if raw.GitHub.InstallationID <= 0 {
		return nil, fmt.Errorf("github.installation_id is required")
	}
	if raw.GitHub.PrivateKeyFile == "" {
		return nil, fmt.Errorf("github.private_key_file is required")
	}
	if raw.GitHub.APIURL == "" {
		raw.GitHub.APIURL = githubapi.DefaultAPIURL
	}
	keyBytes, err := os.ReadFile(raw.GitHub.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read github.private_key_file: %w", err)
	}
	key, err := githubapi.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("github private key: %w", err)
	}

	if len(raw.Policies) == 0 {
		return nil, fmt.Errorf("at least one policy is required")
	}
	policies := make([]Policy, 0, len(raw.Policies))
	for i, rp := range raw.Policies {
		if rp.SPIFFEID == "" {
			return nil, fmt.Errorf("policies[%d].spiffe_id is required", i)
		}
		id, err := spiffeid.FromString(rp.SPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("policies[%d].spiffe_id: %w", i, err)
		}
		if id.TrustDomain().String() != trustDomain.String() {
			return nil, fmt.Errorf("policies[%d].spiffe_id is outside trust domain %s", i, trustDomain)
		}
		installationID := rp.InstallationID
		if installationID == 0 {
			installationID = raw.GitHub.InstallationID
		}
		if len(rp.Repositories) == 0 {
			return nil, fmt.Errorf("policies[%d].repositories is required", i)
		}
		if len(rp.Permissions) == 0 {
			return nil, fmt.Errorf("policies[%d].permissions is required", i)
		}
		for name, value := range rp.Permissions {
			if rank, ok := permissionRank(value); !ok || rank < 1 {
				return nil, fmt.Errorf("policies[%d].permissions[%q] must be read or write", i, name)
			}
		}
		policies = append(policies, Policy{
			SPIFFEID:       id,
			InstallationID: installationID,
			Repositories:   append([]string(nil), rp.Repositories...),
			Permissions:    clonePermissions(rp.Permissions),
		})
	}

	return &Config{
		ListenAddr:  raw.ListenAddr,
		TrustDomain: trustDomain,
		CacheSkew:   cacheSkew,
		GitHub:      raw.GitHub,
		Key:         key,
		Policies:    policies,
	}, nil
}
