package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	tokenbrokerv1 "github.com/tomfitzhenry/github-token-broker/gen/tokenbroker/v1"
	"github.com/tomfitzhenry/github-token-broker/internal/githubapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type cacheEntry struct {
	token     string
	expiresAt time.Time
}

type peerIDKey struct{}

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

	creds := grpccredentials.MTLSServerCredentials(
		source,
		source,
		tlsconfig.AuthorizeMemberOf(b.cfg.TrustDomain),
	)
	listener, err := net.Listen("tcp", b.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	server := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(b.authInterceptor),
		grpc.MaxRecvMsgSize(64<<10),
	)
	tokenbrokerv1.RegisterTokenBrokerServer(server, &tokenService{broker: b})

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	errCh := make(chan error, 1)
	go func() {
		b.log.Info("listening", "addr", b.cfg.ListenAddr)
		errCh <- server.Serve(listener)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	case <-ctx.Done():
		healthServer.Shutdown()
		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			server.Stop()
		}
		return nil
	}
}

func (b *Broker) authInterceptor(
	ctx context.Context,
	req any,
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	id, ok := grpccredentials.PeerIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client SVID required")
	}
	return handler(context.WithValue(ctx, peerIDKey{}, id), req)
}

type tokenService struct {
	tokenbrokerv1.UnimplementedTokenBrokerServer
	broker *Broker
}

func (s *tokenService) MintToken(ctx context.Context, req *tokenbrokerv1.MintTokenRequest) (*tokenbrokerv1.MintTokenResponse, error) {
	id, ok := ctx.Value(peerIDKey{}).(spiffeid.ID)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client SVID required")
	}

	policy, permissions, err := s.broker.cfg.Authorize(id, TokenRequest{
		Repository:  req.GetRepository(),
		Permissions: req.GetPermissions(),
	})
	if errors.Is(err, ErrForbidden) {
		s.broker.log.Warn("denied token request", "spiffe_id", id.String(), "repository", req.GetRepository())
		return nil, status.Error(codes.PermissionDenied, "requested scope is not permitted")
	}
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	token, err := s.broker.mint(ctx, id, policy, req.GetRepository(), permissions)
	if err != nil {
		s.broker.log.Error("mint token", "spiffe_id", id.String(), "repository", req.GetRepository(), "error", err)
		return nil, status.Error(codes.Unavailable, "could not mint GitHub token")
	}

	s.broker.log.Info(
		"issued token",
		"spiffe_id", id.String(),
		"repository", req.GetRepository(),
		"permissions", permissionKey(permissions),
		"expires_at", token.ExpiresAt,
	)
	return &tokenbrokerv1.MintTokenResponse{
		Token:     token.Token,
		ExpiresAt: timestamppb.New(token.ExpiresAt),
	}, nil
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
