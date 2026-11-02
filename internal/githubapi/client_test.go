package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMint(t *testing.T) {
	key := testKey(t)
	var gotPath, gotAuth string
	var gotBody tokenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"ghs_test","expires_at":"2026-11-02T12:00:00Z"}`)
	}))
	defer server.Close()

	client := &Client{AppID: 123, Key: key, BaseURL: server.URL, HTTP: server.Client()}
	token, err := client.Mint(context.Background(), 42, "example/repo", map[string]string{
		"contents":      "write",
		"pull_requests": "write",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if token.Token != "ghs_test" {
		t.Fatalf("token = %q", token.Token)
	}
	if gotPath != "/app/installations/42/access_tokens" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth == "" || gotAuth[:7] != "Bearer " {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if len(gotBody.Repositories) != 1 || gotBody.Repositories[0] != "repo" {
		t.Fatalf("repositories = %v", gotBody.Repositories)
	}
	if gotBody.Permissions["contents"] != "write" {
		t.Fatalf("permissions = %v", gotBody.Permissions)
	}
}

func TestMintAPIError(t *testing.T) {
	key := testKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	}))
	defer server.Close()
	client := &Client{AppID: 123, Key: key, BaseURL: server.URL, HTTP: server.Client()}
	if _, err := client.Mint(context.Background(), 42, "owner/repo", map[string]string{"contents": "read"}); err == nil {
		t.Fatal("expected an error")
	}
}
