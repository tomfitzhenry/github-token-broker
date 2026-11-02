package broker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "app.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	config := `{
	  "listen_addr": ":8443",
	  "trust_domain": "example.org",
	  "github": {
	    "app_id": 123,
	    "installation_id": 456,
	    "private_key_file": "` + keyPath + `"
	  },
	  "policies": [{
	    "spiffe_id": "spiffe://example.org/agent/opencode",
	    "repositories": ["example/repo"],
	    "permissions": {"contents": "write", "pull_requests": "write"}
	  }]
	}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].InstallationID != 456 {
		t.Fatalf("unexpected policies: %+v", cfg.Policies)
	}
	if cfg.CacheSkew.Seconds() != 300 {
		t.Fatalf("cache skew = %v", cfg.CacheSkew)
	}
}
