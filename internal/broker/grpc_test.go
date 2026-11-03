package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	tokenbrokerv1 "github.com/tomfitzhenry/github-token-broker/gen/tokenbroker/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testBrokerConfig(t *testing.T) *Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	writer := testID(t, "spiffe://example.org/agent/writer")
	reader := testID(t, "spiffe://example.org/agent/reader")
	return &Config{
		GitHub: GitHubConfig{AppID: 123, InstallationID: 456, APIURL: "https://api.github.com"},
		Key:    key,
		Policies: []Policy{
			{
				SPIFFEID:       writer,
				InstallationID: 456,
				Permissions:    map[string]string{"contents": "write", "pull_requests": "write"},
			},
			{
				SPIFFEID:       reader,
				InstallationID: 456,
				Permissions:    map[string]string{"contents": "read"},
			},
		},
		CacheSkew: 300 * time.Second,
	}
}

func TestMintTokenRPC(t *testing.T) {
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode: %v", err)
		}
		fmt.Fprint(w, `{"token":"ghs_test","expires_at":"2026-11-02T12:00:00Z"}`)
	}))
	defer server.Close()

	cfg := testBrokerConfig(t)
	b := New(cfg, nil)
	b.github.BaseURL = server.URL
	b.github.HTTP = server.Client()
	id := testID(t, "spiffe://example.org/agent/writer")
	ctx := context.WithValue(context.Background(), peerIDKey{}, id)

	resp, err := (&tokenService{broker: b}).MintToken(ctx, &tokenbrokerv1.MintTokenRequest{
		Repository: "example/repo",
	})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if resp.GetToken() != "ghs_test" {
		t.Fatalf("token = %q", resp.GetToken())
	}
	if gotBody["repositories"] == nil {
		t.Fatalf("request body = %v", gotBody)
	}
}

func TestMintTokenRPCAllowsAnyRepository(t *testing.T) {
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode: %v", err)
		}
		fmt.Fprint(w, `{"token":"ghs_test","expires_at":"2026-11-02T12:00:00Z"}`)
	}))
	defer server.Close()

	cfg := testBrokerConfig(t)
	b := New(cfg, nil)
	b.github.BaseURL = server.URL
	b.github.HTTP = server.Client()
	id := testID(t, "spiffe://example.org/agent/writer")
	ctx := context.WithValue(context.Background(), peerIDKey{}, id)

	// The old policies used to list example/repo. The broker no longer rejects
	// other repositories; the App installation enforces that boundary.
	resp, err := (&tokenService{broker: b}).MintToken(ctx, &tokenbrokerv1.MintTokenRequest{
		Repository: "example/other",
	})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if resp.GetToken() != "ghs_test" {
		t.Fatalf("token = %q", resp.GetToken())
	}
	repositories, ok := gotBody["repositories"].([]any)
	if !ok || len(repositories) != 1 || repositories[0] != "other" {
		t.Fatalf("request body repositories = %v, want [%q]", gotBody["repositories"], "other")
	}
}

func TestMintTokenRPCForbidden(t *testing.T) {
	cfg := testBrokerConfig(t)
	b := New(cfg, nil)
	id := testID(t, "spiffe://example.org/agent/reader")
	ctx := context.WithValue(context.Background(), peerIDKey{}, id)

	_, err := (&tokenService{broker: b}).MintToken(ctx, &tokenbrokerv1.MintTokenRequest{
		Repository:  "example/repo",
		Permissions: map[string]string{"contents": "write"},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}
