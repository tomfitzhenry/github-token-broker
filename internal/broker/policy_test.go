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
	writer := Principal{SPIFFEID: testID(t, "spiffe://example.org/agent/writer")}
	reader := Principal{SPIFFEID: testID(t, "spiffe://example.org/agent/reader")}
	peersecReader := Principal{SELinuxType: "svc_reader_t"}
	cfg := &Config{Policies: []Policy{
		{
			SPIFFEID:       writer.SPIFFEID,
			InstallationID: 7,
			Permissions:    map[string]string{"contents": "write", "pull_requests": "write"},
		},
		{
			SPIFFEID:       reader.SPIFFEID,
			InstallationID: 7,
			Permissions:    map[string]string{"contents": "read"},
		},
		{
			SELinuxType:    "svc_reader_t",
			InstallationID: 9,
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

	policy, perms, err = cfg.Authorize(peersecReader, TokenRequest{Repository: "example/repo"})
	if err != nil {
		t.Fatalf("peersecReader: %v", err)
	}
	if policy.InstallationID != 9 || perms["contents"] != "read" {
		t.Fatalf("peersecReader policy = %+v perms = %v", policy, perms)
	}

	if _, _, err := cfg.Authorize(Principal{SELinuxType: "svc_other_t"}, TokenRequest{
		Repository: "example/repo",
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown selinux type error = %v, want forbidden", err)
	}

	if _, _, err := cfg.Authorize(Principal{}, TokenRequest{
		Repository: "example/repo",
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("empty principal error = %v, want forbidden", err)
	}

	// The broker does not restrict which repositories a policy covers; the
	// GitHub App installation does. Any valid owner/repo is allowed.
	policy, perms, err = cfg.Authorize(writer, TokenRequest{Repository: "other/repo"})
	if err != nil {
		t.Fatalf("other repo: %v", err)
	}
	if policy.InstallationID != 7 || perms["contents"] != "write" {
		t.Fatalf("other repo policy = %+v perms = %v", policy, perms)
	}

	if _, _, err := cfg.Authorize(writer, TokenRequest{Repository: "no-slash"}); err == nil || errors.Is(err, ErrForbidden) {
		t.Fatalf("malformed repo error = %v, want a non-forbidden error", err)
	}

	if _, _, err := cfg.Authorize(writer, TokenRequest{}); err == nil || errors.Is(err, ErrForbidden) {
		t.Fatalf("empty repo error = %v, want a non-forbidden error", err)
	}
}
