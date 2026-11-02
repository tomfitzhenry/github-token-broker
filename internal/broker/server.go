package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tomfitzhenry/github-token-broker/internal/githubapi"
)

type cacheEntry struct {
	token     string
	expiresAt time.Time
}

// Broker serves scoped GitHub App installation tokens over SPIFFE mTLS.
type Broker struct {
	cfg    *Config
	github *githubapi.Client
	log    *slog.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// New creates a broker. Run performs the SPIFFE Workload API setup.
func New(cfg *Config, logger *slog.Logger) *Broker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Broker{
		cfg: cfg,
		github: &githubapi.Client{
			AppID:   cfg.GitHub.AppID,
			Key:     cfg.Key,
			BaseURL: cfg.GitHub.APIURL,
		},
		log:   logger,
		cache: make(map[string]cacheEntry),
	}
}

// Run serves until ctx is cancelled or the server fails.
func (b *Broker) Run(ctx context.Context) error {
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return fmt.Errorf("SPIFFE Workload API: %w", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("get broker SVID: %w", err)
	}
	b.log.Info("broker identity", "spiffe_id", svid.ID.String())

	tlsConfig := tlsconfig.MTLSServerConfig(
		source,
		source,
		tlsconfig.AuthorizeMemberOf(b.cfg.TrustDomain),
	)

	listener, err := net.Listen("tcp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	tlsListener := tls.NewListener(listener, tlsConfig)

	server := &http.Server{
		Handler:           b.routes(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		b.log.Info("listening", "addr", b.cfg.ListenAddr)
		errCh <- server.Serve(tlsListener)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

func (b *Broker) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/token", b.handleToken)
	return mux
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := peerSPIFFEID(r)
	if err != nil {
		http.Error(w, "client SVID required", http.StatusUnauthorized)
		return
	}

	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var req TokenRequest
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if decoder.More() {
		http.Error(w, "trailing JSON data", http.StatusBadRequest)
		return
	}

	policy, permissions, err := b.cfg.Authorize(id, req)
	if errors.Is(err, ErrForbidden) {
		b.log.Warn("denied token request", "spiffe_id", id.String(), "repository", req.Repository)
		http.Error(w, "requested scope is not permitted", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := b.mint(r.Context(), id, policy, req.Repository, permissions)
	if err != nil {
		b.log.Error("mint token", "spiffe_id", id.String(), "repository", req.Repository, "error", err)
		http.Error(w, "could not mint GitHub token", http.StatusBadGateway)
		return
	}

	b.log.Info(
		"issued token",
		"spiffe_id", id.String(),
		"repository", req.Repository,
		"permissions", permissionKey(permissions),
		"expires_at", token.ExpiresAt,
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}{Token: token.Token, ExpiresAt: token.ExpiresAt})
}

func (b *Broker) mint(
	ctx context.Context,
	id spiffeid.ID,
	policy Policy,
	repository string,
	permissions map[string]string,
) (githubapi.Token, error) {
	key := strings.Join([]string{
		id.String(),
		strconv.FormatInt(policy.InstallationID, 10),
		strings.ToLower(repository),
		permissionKey(permissions),
	}, "|")

	b.mu.Lock()
	defer b.mu.Unlock()

	if entry, ok := b.cache[key]; ok && time.Until(entry.expiresAt) > b.cfg.CacheSkew {
		return githubapi.Token{Token: entry.token, ExpiresAt: entry.expiresAt}, nil
	}

	token, err := b.github.Mint(ctx, policy.InstallationID, repository, permissions)
	if err != nil {
		return githubapi.Token{}, err
	}
	b.cache[key] = cacheEntry{token: token.Token, expiresAt: token.ExpiresAt}
	return token, nil
}

func peerSPIFFEID(r *http.Request) (spiffeid.ID, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return spiffeid.ID{}, errors.New("no peer certificate")
	}
	for _, cert := range r.TLS.PeerCertificates {
		for _, uri := range cert.URIs {
			id, err := spiffeid.FromURI(uri)
			if err == nil {
				return id, nil
			}
		}
	}
	return spiffeid.ID{}, errors.New("no SPIFFE ID in peer certificate")
}
