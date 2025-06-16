package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"codeberg.org/clambin/go-common/httputils"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
)

var version = "change-me"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := server.GetConfiguration(flag.CommandLine)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid configuration: %v", err)
		os.Exit(1)
	}

	if err = run(ctx, cfg, prometheus.DefaultRegisterer, cfg.Logger(os.Stderr, nil)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to start traefik-simple-auth: %s", err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg server.Configuration, r prometheus.Registerer, logger *slog.Logger) error {
	logger.Info("traefik-simple-auth starting", "version", version)
	defer logger.Info("traefik-simple-auth stopped")

	// create the server
	metrics := server.NewMetrics("traefik_simple_auth", "", prometheus.Labels{"provider": cfg.OIDC.Provider})
	r.MustRegister(metrics)
	s := server.New(ctx, cfg, metrics, logger)

	// if configured, start the pprof server.
	if cfg.PProfAddr != "" {
		go func() { _ = http.ListenAndServe(cfg.PProfAddr, nil) }()
	}

	// run the different HTTP servers
	var g errgroup.Group
	g.Go(func() error {
		return cfg.Serve(ctx)
	})
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{Addr: cfg.Addr, Handler: s})
	})
	return g.Wait()
}
