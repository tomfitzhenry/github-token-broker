package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tomfitzhenry/github-token-broker/internal/agent"
)

func testOptions(t *testing.T) *options {
	t.Helper()
	return &options{
		broker:      "127.0.0.1:1",
		serverID:    "spiffe://test/github-token-broker",
		repository:  "example/repo",
		permissions: permissionFlag{values: map[string]string{"contents": "write"}},
		cacheTTL:    5 * time.Minute,
		cacheDir:    t.TempDir(),
	}
}

// fakeMinter returns tok-1, tok-2, ... for successful calls, and the configured
// error for calls listed in errs.
type fakeMinter struct {
	mu        sync.Mutex
	calls     int
	successes int
	errs      map[int]error
	delay     time.Duration
	expiry    time.Duration
}

func (f *fakeMinter) mint(context.Context) (agent.Token, error) {
	f.mu.Lock()
	call := f.calls
	f.calls++
	err := f.errs[call]
	delay := f.delay
	expiry := f.expiry
	f.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if err != nil {
		return agent.Token{}, err
	}

	f.mu.Lock()
	f.successes++
	token := fmt.Sprintf("tok-%d", f.successes)
	f.mu.Unlock()

	if expiry == 0 {
		expiry = time.Hour
	}
	return agent.Token{Token: token, ExpiresAt: timeNow().Add(expiry)}, nil
}

func (f *fakeMinter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func setClock(t *testing.T, start time.Time) *time.Time {
	t.Helper()
	original := timeNow
	current := start
	timeNow = func() time.Time { return current }
	t.Cleanup(func() { timeNow = original })
	return &current
}

func TestTokenCacheHit(t *testing.T) {
	setClock(t, time.Unix(1000, 0))
	opts := testOptions(t)
	minter := &fakeMinter{}

	first, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard)
	if err != nil {
		t.Fatalf("first token: %v", err)
	}
	second, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard)
	if err != nil {
		t.Fatalf("second token: %v", err)
	}
	if first.Token != "tok-1" || second.Token != "tok-1" {
		t.Fatalf("tokens = %q, %q; want tok-1 twice", first.Token, second.Token)
	}
	if got := minter.callCount(); got != 1 {
		t.Fatalf("mint calls = %d; want 1", got)
	}

	path := cachePath(opts.cacheDir, opts.cacheKey())
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("cache file mode = %o; want 600", got)
	}
	dirInfo, err := os.Stat(opts.cacheDir)
	if err != nil {
		t.Fatalf("stat cache dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("cache dir mode = %o; want 700", got)
	}
}

func TestTokenCacheScopeIsKeyed(t *testing.T) {
	setClock(t, time.Unix(1000, 0))
	opts := testOptions(t)
	minter := &fakeMinter{}

	if _, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard); err != nil {
		t.Fatalf("first token: %v", err)
	}

	other := *opts
	other.repository = "example/other"
	if _, err := tokenWithCache(context.Background(), &other, minter.mint, io.Discard); err != nil {
		t.Fatalf("other repository token: %v", err)
	}

	changedPermissions := *opts
	changedPermissions.permissions = permissionFlag{values: map[string]string{"contents": "read"}}
	if _, err := tokenWithCache(context.Background(), &changedPermissions, minter.mint, io.Discard); err != nil {
		t.Fatalf("other permissions token: %v", err)
	}

	if got := minter.callCount(); got != 3 {
		t.Fatalf("mint calls = %d; want 3 (one per scope)", got)
	}
}

func TestTokenCacheExpiryRefreshes(t *testing.T) {
	clock := setClock(t, time.Unix(1000, 0))
	opts := testOptions(t)
	minter := &fakeMinter{}

	if _, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard); err != nil {
		t.Fatalf("first token: %v", err)
	}
	*clock = clock.Add(opts.cacheTTL + time.Second)
	token, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if token.Token != "tok-2" {
		t.Fatalf("token after expiry = %q; want tok-2", token.Token)
	}
	if got := minter.callCount(); got != 2 {
		t.Fatalf("mint calls = %d; want 2", got)
	}
}

func TestTokenCacheFailedRefreshFailsClosed(t *testing.T) {
	clock := setClock(t, time.Unix(1000, 0))
	opts := testOptions(t)
	minter := &fakeMinter{errs: map[int]error{1: errors.New("broker unavailable")}}

	if _, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard); err != nil {
		t.Fatalf("first token: %v", err)
	}
	path := cachePath(opts.cacheDir, opts.cacheKey())
	*clock = clock.Add(opts.cacheTTL + time.Second)

	if _, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard); err == nil {
		t.Fatal("expired token refreshed while the broker was unavailable")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache file still exists after a failed refresh: %v", err)
	}

	// A later successful mint is cached again.
	token, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard)
	if err != nil {
		t.Fatalf("token after recovery: %v", err)
	}
	if token.Token != "tok-2" {
		t.Fatalf("token after recovery = %q; want tok-2", token.Token)
	}
}

func TestTokenCacheDisabled(t *testing.T) {
	setClock(t, time.Unix(1000, 0))
	opts := testOptions(t)
	opts.cacheTTL = 0
	minter := &fakeMinter{}

	for i := 0; i < 2; i++ {
		if _, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard); err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
	}
	if got := minter.callCount(); got != 2 {
		t.Fatalf("mint calls = %d; want 2 when the cache is disabled", got)
	}
	entries, err := os.ReadDir(opts.cacheDir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("cache dir has %d entries; want none", len(entries))
	}
}

func TestTokenCacheDefaultsToPerUserRuntimeDir(t *testing.T) {
	setClock(t, time.Unix(1000, 0))
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_CACHE_HOME", "")
	opts := testOptions(t)
	opts.cacheDir = ""
	minter := &fakeMinter{}

	if _, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard); err != nil {
		t.Fatalf("token: %v", err)
	}
	path := cachePath(filepath.Join(runtimeDir, cacheSubdir), opts.cacheKey())
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("token was not cached under XDG_RUNTIME_DIR: %v", err)
	}
}

func TestTokenCacheReplacesPermissiveFile(t *testing.T) {
	setClock(t, time.Unix(1000, 0))
	opts := testOptions(t)
	minter := &fakeMinter{}
	path := cachePath(opts.cacheDir, opts.cacheKey())

	// A token file other users could read must not be trusted.
	entry := `{"token":"leaked","expires_at":"2100-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(entry), 0o644); err != nil {
		t.Fatalf("write permissive cache: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod permissive cache: %v", err)
	}

	token, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if token.Token != "tok-1" {
		t.Fatalf("token = %q; want tok-1 (permissive cache must be ignored)", token.Token)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("cache file mode = %o; want 600", got)
	}
}

func TestTokenCacheCapRespectsTokenExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	setClock(t, now)
	opts := testOptions(t)
	minter := &fakeMinter{expiry: 30 * time.Second}

	if _, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard); err != nil {
		t.Fatalf("token: %v", err)
	}
	entry, ok := readCache(cachePath(opts.cacheDir, opts.cacheKey()))
	if !ok {
		t.Fatal("token was not cached")
	}
	want := now.Add(30*time.Second - cacheExpirySkew)
	if !entry.ExpiresAt.Equal(want) {
		t.Fatalf("cache expiry = %s; want %s", entry.ExpiresAt, want)
	}
}

func TestConcurrentCallersMintOnce(t *testing.T) {
	setClock(t, time.Unix(1000, 0))
	opts := testOptions(t)
	minter := &fakeMinter{delay: 100 * time.Millisecond}

	const callers = 8
	var wait sync.WaitGroup
	tokens := make([]string, callers)
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			token, err := tokenWithCache(context.Background(), opts, minter.mint, io.Discard)
			tokens[i] = token.Token
			errs[i] = err
		}(i)
	}
	wait.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if tokens[i] != "tok-1" {
			t.Errorf("caller %d token = %q; want tok-1", i, tokens[i])
		}
	}
	if got := minter.callCount(); got != 1 {
		t.Fatalf("mint calls = %d; want 1 under flock", got)
	}
}
