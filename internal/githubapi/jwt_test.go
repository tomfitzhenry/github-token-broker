package githubapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestSignAppJWT(t *testing.T) {
	key := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	token, err := SignAppJWT(12345, key, now)
	if err != nil {
		t.Fatalf("SignAppJWT: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("header: %v", err)
	}
	if header.Alg != "RS256" {
		t.Fatalf("alg = %q, want RS256", header.Alg)
	}
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims.Issuer != 12345 || claims.ExpiresAt-claims.IssuedAt != 600 {
		t.Fatalf("claims = %+v", claims)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestParsePrivateKeyPKCS8(t *testing.T) {
	key := testKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Fatal("key mismatch")
	}
}
