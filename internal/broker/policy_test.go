package broker

import (
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func testID(t *testing.T, raw string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(raw)
	if err != nil {
		t.Fatalf("parse ID: %v", err)
	}
	return id
}

func TestAuthorize(t *testing.T) {
	writer := testID(t, "spiffe://example.org/agent/writer")
	reader := testID(t, "spiffe://example.org/agent/reader")
	cfg := &Config{Policies: []Policy{
		{
			SPIFFEID:       writer,
			InstallationID: 7,
			Repositories:   []string{"example/repo"},
			Permissions:    map[string]string{"contents": "write", "pull_requests": "write"},
		},
		{
			SPIFFEID:       reader,
			InstallationID: 7,
			Repositories:   []string{"example/repo"},
			Permissions:    map[string]string{"contents": "read"},
		},
	}}

	policy, perms, err := cfg.Authorize(writer, TokenRequest{Repository: "example/repo"})
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if policy.InstallationID != 7 || perms["contents"] != "write" {
		t.Fatalf("writer policy = %+v perms = %v", policy, perms)
	}

	_, perms, err = cfg.Authorize(writer, TokenRequest{
		Repository:  "example/repo",
		Permissions: map[string]string{"contents": "read"},
	})
	if err != nil || perms["contents"] != "read" || len(perms) != 1 {
		t.Fatalf("writer read request: perms=%v err=%v", perms, err)
	}

	if _, _, err := cfg.Authorize(reader, TokenRequest{
		Repository:  "example/repo",
		Permissions: map[string]string{"contents": "write"},
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader write error = %v, want forbidden", err)
	}

	if _, _, err := cfg.Authorize(writer, TokenRequest{Repository: "other/repo"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong repo error = %v, want forbidden", err)
	}
}
