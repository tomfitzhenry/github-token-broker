package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func testTrustDomain(t *testing.T) spiffeid.TrustDomain {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		t.Fatal(err)
	}
	return td
}

func testKeyFile(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

func TestParsePolicies(t *testing.T) {
	td := testTrustDomain(t)
	raw := []string{
		"spiffe_id=spiffe://example.org/agent/opencode;repositories=owner/a,owner/b;permissions=contents=write,pull_requests=write",
		"spiffe_id=spiffe://example.org/agent/reader;repositories=owner/a;permissions=contents=read;installation_id=99",
	}
	policies, err := ParsePolicies(raw, td, 42)
	if err != nil {
		t.Fatalf("ParsePolicies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("policies = %d", len(policies))
	}
	if len(policies[0].Repositories) != 2 || policies[0].InstallationID != 42 {
		t.Fatalf("policy 0 = %+v", policies[0])
	}
	if policies[1].InstallationID != 99 || policies[1].Permissions["contents"] != "read" {
		t.Fatalf("policy 1 = %+v", policies[1])
	}
}

func TestParsePolicyRejectsBadPermission(t *testing.T) {
	td := testTrustDomain(t)
	_, err := ParsePolicy(
		"spiffe_id=spiffe://example.org/agent/opencode;repositories=owner/a;permissions=contents=admin",
		td, 42,
	)
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestValidate(t *testing.T) {
	keyPath, key := testKeyFile(t)
	td := testTrustDomain(t)
	policy, err := ParsePolicy(
		"spiffe_id=spiffe://example.org/agent/opencode;repositories=owner/a;permissions=contents=write",
		td, 42,
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		ListenAddr:  ":8443",
		TrustDomain: td,
		CacheSkew:   5 * time.Minute,
		GitHub: GitHubConfig{
			AppID:          1,
			InstallationID: 42,
			PrivateKeyFile: keyPath,
		},
		Key:      key,
		Policies: []Policy{policy},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Policies[0].InstallationID != 42 {
		t.Fatalf("installation ID = %d", cfg.Policies[0].InstallationID)
	}
}

func TestLoadPrivateKey(t *testing.T) {
	path, key := testKeyFile(t)
	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("key mismatch")
	}
}
