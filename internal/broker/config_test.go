package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
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
		"spiffe_id=spiffe://example.org/agent/opencode;permissions=contents=write,pull_requests=write",
		"spiffe_id=spiffe://example.org/agent/reader;permissions=contents=read;installation_id=99",
	}
	policies, err := ParsePolicies(raw, td, 42)
	if err != nil {
		t.Fatalf("ParsePolicies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("policies = %d", len(policies))
	}
	if policies[0].InstallationID != 42 || policies[0].Permissions["contents"] != "write" {
		t.Fatalf("policy 0 = %+v", policies[0])
	}
	if policies[1].InstallationID != 99 || policies[1].Permissions["contents"] != "read" {
		t.Fatalf("policy 1 = %+v", policies[1])
	}
}

func TestParsePolicyRejectsBadPermission(t *testing.T) {
	td := testTrustDomain(t)
	_, err := ParsePolicy(
		"spiffe_id=spiffe://example.org/agent/opencode;permissions=contents=admin",
		td, 42,
	)
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestParsePolicyRejectsRepositoriesField(t *testing.T) {
	td := testTrustDomain(t)
	_, err := ParsePolicy(
		"spiffe_id=spiffe://example.org/agent/opencode;repositories=owner/a;permissions=contents=write",
		td, 42,
	)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "unknown policy field") {
		t.Fatalf("error = %v, want unknown policy field", err)
	}
}

func TestValidate(t *testing.T) {
	keyPath, key := testKeyFile(t)
	td := testTrustDomain(t)
	policy, err := ParsePolicy(
		"spiffe_id=spiffe://example.org/agent/opencode;permissions=contents=write",
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

func TestParsePolicySELinuxType(t *testing.T) {
	policy, err := ParsePolicy(
		"selinux_type=svc_reader_t;permissions=contents=read;installation_id=77",
		spiffeid.TrustDomain{}, 42,
	)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if policy.SELinuxType != "svc_reader_t" || policy.InstallationID != 77 {
		t.Fatalf("policy = %+v", policy)
	}

	for _, bad := range []string{
		"selinux_type=unlabeled_t;permissions=contents=read",
		"spiffe_id=spiffe://example.org/a;selinux_type=svc_foo_t;permissions=contents=read",
		"permissions=contents=read",
		"selinux_type=bad:type;permissions=contents=read",
	} {
		if _, err := ParsePolicy(bad, testTrustDomain(t), 42); err == nil {
			t.Fatalf("ParsePolicy(%q) succeeded, want error", bad)
		}
	}
}

func TestValidatePeerSecOnly(t *testing.T) {
	keyPath, key := testKeyFile(t)
	policy, err := ParsePolicy(
		"selinux_type=svc_reader_t;permissions=contents=read",
		spiffeid.TrustDomain{}, 42,
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		PeerSecListenAddr: ":8444",
		CacheSkew:         5 * time.Minute,
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

	cfg.PeerSecListenAddr = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when both ListenAddr and PeerSecListenAddr are empty")
	}
}
