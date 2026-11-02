package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tomfitzhenry/github-token-broker/internal/broker"
)

func main() {
	var (
		configPath = flag.String("config", "/etc/github-token-broker/config.json", "path to JSON config")
		listenAddr = flag.String("listen", "", "override listen address")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := broker.LoadConfig(*configPath)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := broker.New(cfg, logger).Run(ctx); err != nil {
		logger.Error("broker", "error", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "broker stopped")
}
