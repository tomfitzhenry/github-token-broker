package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/tomfitzhenry/github-token-broker/internal/broker"
)

const policyHelp = "policy: spiffe_id=SPIFFE_ID;permissions=name=read|write[,name=read|write...][;installation_id=N] (repeatable; the GitHub App installation restricts repositories)"

func main() {
	var (
		listenAddr     = flag.String("listen", ":8443", "listen address")
		trustDomainRaw = flag.String("trust-domain", "", "SPIFFE trust domain")
		cacheSkew      = flag.Duration("cache-skew", 5*time.Minute, "stop serving cached tokens this long before expiry")
		appID          = flag.Int64("app-id", 0, "GitHub App ID")
		installationID = flag.Int64("installation-id", 0, "default GitHub App installation ID")
		privateKey     = flag.String("private-key", "", "path to the GitHub App RSA private key")
		apiURL         = flag.String("api-url", "https://api.github.com", "GitHub REST API base URL")
		policyFlags    []string
	)
	flag.Func("policy", policyHelp, func(value string) error {
		policyFlags = append(policyFlags, value)
		return nil
	})
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *trustDomainRaw == "" {
		logger.Error("-trust-domain is required")
		os.Exit(2)
	}
	trustDomain, err := spiffeid.TrustDomainFromString(*trustDomainRaw)
	if err != nil {
		logger.Error("invalid -trust-domain", "error", err)
		os.Exit(2)
	}
	key, err := broker.LoadPrivateKey(*privateKey)
	if err != nil {
		logger.Error("load private key", "error", err)
		os.Exit(1)
	}
	policies, err := broker.ParsePolicies(policyFlags, trustDomain, *installationID)
	if err != nil {
		logger.Error("parse policies", "error", err)
		os.Exit(2)
	}
	cfg := &broker.Config{
		ListenAddr:  *listenAddr,
		TrustDomain: trustDomain,
		CacheSkew:   *cacheSkew,
		GitHub: broker.GitHubConfig{
			AppID:          *appID,
			InstallationID: *installationID,
			PrivateKeyFile: *privateKey,
			APIURL:         *apiURL,
		},
		Key:      key,
		Policies: policies,
	}
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := broker.New(cfg, logger).Run(ctx); err != nil {
		logger.Error("broker", "error", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "broker stopped")
}
