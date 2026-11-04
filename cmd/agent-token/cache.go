package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tomfitzhenry/github-token-broker/internal/agent"
)

const (
	// defaultCacheTTL is deliberately well below the installation token's
	// one-hour expiry, and below the broker's default five-minute cache skew.
	defaultCacheTTL = 5 * time.Minute
	cacheSubdir     = "github-token-broker"
	cacheDirMode    = 0o700
	cacheFileMode   = 0o600
	// cacheExpirySkew stops the client serving a token that GitHub would
	// reject because it is about to expire.
	cacheExpirySkew = 10 * time.Second
)

// timeNow is a test seam for cache expiry tests.
var timeNow = time.Now

type mintFunc func(context.Context) (agent.Token, error)

type tokenCacheEntry struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// cacheKey identifies the token scope: a token minted for one broker,
// repository and permission set must never be served for another. The uid is
// part of the filename, and the cache directory is per user.
func (o *options) cacheKey() string {
	permissions := make([]string, 0, len(o.permissions.values))
	for key, value := range o.permissions.values {
		permissions = append(permissions, key+"="+value)
	}
	sort.Strings(permissions)
	return strings.Join(
		[]string{o.broker, o.serverID, o.repository, strings.Join(permissions, ",")},
		"\n",
	)
}

// cacheDir picks a per-user directory. XDG_RUNTIME_DIR is a per-user tmpfs
// (mode 0700), so a token does not outlive the login. Where it is not set (for
// example a systemd service), fall back to XDG_CACHE_HOME, then ~/.cache; the
// file is still mode 0600 and the directory is tightened to mode 0700.
func cacheDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, cacheSubdir), nil
	}
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, cacheSubdir), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory for token cache: %w", err)
	}
	return filepath.Join(home, ".cache", cacheSubdir), nil
}

// ensureCacheDir creates the cache directory and refuses to use one owned by a
// different user or readable by other users.
func ensureCacheDir(dir string) error {
	if err := os.MkdirAll(dir, cacheDirMode); err != nil {
		return fmt.Errorf("create cache directory %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect cache directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cache path %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, cacheDirMode); err != nil {
			return fmt.Errorf("tighten cache directory %s: %w", dir, err)
		}
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return fmt.Errorf(
			"cache directory %s is owned by uid %d, not %d",
			dir,
			stat.Uid,
			os.Getuid(),
		)
	}
	return nil
}

// cachePath names the cache entry. The uid is included so that a shared
// directory (if an operator points --cache-dir at one) still gives each user a
// distinct file, and the scope hash prevents one repository or permission set
// from reusing another's token.
func cachePath(dir, scope string) string {
	sum := sha256.Sum256([]byte(scope))
	return filepath.Join(
		dir,
		fmt.Sprintf("token-%d-%s.json", os.Getuid(), hex.EncodeToString(sum[:12])),
	)
}

// readCache reads and validates an entry without following symlinks. A file
// with the wrong mode or owner is treated as a cache miss; the caller removes
// it before minting.
func readCache(path string) (tokenCacheEntry, bool) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return tokenCacheEntry{}, false
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return tokenCacheEntry{}, false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return tokenCacheEntry{}, false
	}
	var entry tokenCacheEntry
	if err := json.NewDecoder(file).Decode(&entry); err != nil {
		return tokenCacheEntry{}, false
	}
	if entry.Token == "" || entry.ExpiresAt.IsZero() {
		return tokenCacheEntry{}, false
	}
	return entry, true
}

func writeCache(path string, entry tokenCacheEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".token-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(cacheFileMode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type cacheLock struct {
	file *os.File
}

func lockCache(path string) (*cacheLock, error) {
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, cacheFileMode)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return &cacheLock{file: file}, nil
}

func (l *cacheLock) Close() error {
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}

// tokenWithCache returns a token from the local cache when one is fresh, and
// otherwise mints one and caches it. The mint runs under an exclusive flock so
// concurrent callers mint once, and the previous entry is removed first so a
// failed refresh fails closed instead of serving an expired token. A cache that
// cannot be created or locked is not fatal: the caller still mints a token.
func tokenWithCache(
	ctx context.Context,
	opts *options,
	mint mintFunc,
	warn io.Writer,
) (agent.Token, error) {
	if opts.cacheTTL <= 0 {
		return mint(ctx)
	}
	dir, err := cacheDir(opts.cacheDir)
	if err != nil {
		warnf(warn, "token cache disabled: %v", err)
		return mint(ctx)
	}
	if err := ensureCacheDir(dir); err != nil {
		warnf(warn, "token cache disabled: %v", err)
		return mint(ctx)
	}
	path := cachePath(dir, opts.cacheKey())

	if entry, ok := freshCacheEntry(path); ok {
		return agent.Token{Token: entry.Token, ExpiresAt: entry.ExpiresAt}, nil
	}

	lock, err := lockCache(path)
	if err != nil {
		warnf(warn, "token cache lock failed, minting without caching: %v", err)
		return mint(ctx)
	}
	defer lock.Close()

	// Another process may have refreshed the token while this one waited.
	if entry, ok := freshCacheEntry(path); ok {
		return agent.Token{Token: entry.Token, ExpiresAt: entry.ExpiresAt}, nil
	}

	// Never leave an expired token available to another caller after a failed
	// refresh: remove it before asking the broker.
	_ = os.Remove(path)

	token, err := mint(ctx)
	if err != nil {
		return agent.Token{}, err
	}

	now := timeNow()
	expires := now.Add(opts.cacheTTL)
	if !token.ExpiresAt.IsZero() {
		if capped := token.ExpiresAt.Add(-cacheExpirySkew); capped.Before(expires) {
			expires = capped
		}
	}
	if expires.After(now) {
		entry := tokenCacheEntry{Token: token.Token, ExpiresAt: expires}
		if err := writeCache(path, entry); err != nil {
			warnf(warn, "token cache write failed, token still returned: %v", err)
		}
	}
	return token, nil
}

func freshCacheEntry(path string) (tokenCacheEntry, bool) {
	entry, ok := readCache(path)
	if !ok || !entry.ExpiresAt.After(timeNow()) {
		return tokenCacheEntry{}, false
	}
	return entry, true
}

func warnf(writer io.Writer, format string, args ...any) {
	if writer == nil {
		return
	}
	fmt.Fprintf(writer, "agent-token: "+format+"\n", args...)
}
