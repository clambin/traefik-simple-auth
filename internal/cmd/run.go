package cmd

import (
	"codeberg.org/clambin/go-common/httputils"
	"context"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
)

func Main(ctx context.Context, r prometheus.Registerer, version string) error {
	cfg, err := server.GetConfiguration()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return run(ctx, cfg, r, version, cfg.Logger(os.Stderr))
}

func run(ctx context.Context, cfg server.Configuration, r prometheus.Registerer, version string, logger *slog.Logger) error {
	logger.Info("traefik-simple-auth starting", "version", version)
	defer logger.Info("traefik-simple-auth stopped")

	// create the server
	metrics := server.NewMetrics("traefik_simple_auth", "", prometheus.Labels{"provider": cfg.Provider})
	r.MustRegister(metrics)
	s := server.New(ctx, cfg, metrics, logger)

	// if configured, start the pprof server.
	if cfg.PProfAddr != "" {
		go func() { _ = http.ListenAndServe(cfg.PProfAddr, nil) }()
	}

	// run the different HTTP servers
	var g errgroup.Group
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{Addr: cfg.PromAddr, Handler: promhttp.Handler()})
	})
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{Addr: cfg.Addr, Handler: s})
	})
	return g.Wait()
}
