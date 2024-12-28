package cmd

import (
	"context"
	"fmt"
	"github.com/clambin/go-common/httputils"
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net/http"
	"os"
)

func Main(ctx context.Context, r prometheus.Registerer, version string) error {
	cfg, err := configuration.GetConfiguration()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return run(ctx, cfg, r, version, cfg.Logger(os.Stderr))
}

func run(ctx context.Context, cfg configuration.Configuration, r prometheus.Registerer, version string, logger *slog.Logger) error {
	logger.Info("traefik-simple-auth starting", "version", version)
	defer logger.Info("traefik-simple-auth stopped")

	metrics := server.NewMetrics("traefik_simple_auth", "", prometheus.Labels{"provider": cfg.Provider})
	r.MustRegister(metrics)
	authenticator := auth.Authenticator{
		Secret:     cfg.Secret,
		CookieName: cfg.SessionCookieName,
		Expiration: cfg.SessionExpiration,
	}
	stateStore := state.New(cfg.StateConfiguration)
	s := server.New(ctx, authenticator, stateStore, cfg, metrics, logger)

	var g errgroup.Group
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{Addr: cfg.PromAddr, Handler: promhttp.Handler()})
	})
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{Addr: cfg.Addr, Handler: s})
	})
	return g.Wait()
}
