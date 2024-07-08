package main

import (
	"context"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/cmd"
	"github.com/clambin/traefik-simple-auth/internal/server/configuration"
	"github.com/prometheus/client_golang/prometheus"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

var version = "change-me"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := configuration.GetConfiguration()
	if err == nil {
		var opts slog.HandlerOptions
		if cfg.Debug {
			opts.Level = slog.LevelDebug
		}
		logger := slog.New(slog.NewJSONHandler(os.Stderr, &opts))
		err = cmd.Run(ctx, cfg, prometheus.DefaultRegisterer, version, logger)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to start traefik-simple-auth: %s", err.Error())
		os.Exit(1)
	}
}
