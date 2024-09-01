package cmd

import (
	"context"
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/pkg/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net/http"
)

func Run(ctx context.Context, cfg configuration.Configuration, registry prometheus.Registerer, version string, logger *slog.Logger) error {
	logger.Info("traefik-simple-auth starting", "version", version)
	defer logger.Info("traefik-simple-auth stopped")

	metrics := server.NewMetrics("traefik_simple_auth", "", prometheus.Labels{"provider": cfg.Provider})
	registry.MustRegister(metrics)
	sessionStore := sessions.New(cfg.SessionCookieName, cfg.Secret, cfg.SessionExpiration)
	stateStore := state.New(cfg.StateConfiguration)
	s := server.New(ctx, sessionStore, stateStore, cfg, metrics, logger)

	var g errgroup.Group
	runHTTPServer(ctx, &g, &http.Server{Addr: cfg.PromAddr, Handler: promhttp.Handler()})
	runHTTPServer(ctx, &g, &http.Server{Addr: cfg.Addr, Handler: s})

	return g.Wait()
}

func runHTTPServer(ctx context.Context, g *errgroup.Group, s *http.Server) {
	subCtx, cancel := context.WithCancel(ctx)
	g.Go(func() error {
		defer cancel()
		if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-subCtx.Done()
		if err := s.Shutdown(context.Background()); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
}
