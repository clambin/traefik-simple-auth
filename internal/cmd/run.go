package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/pkg/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func Main(ctx context.Context, r prometheus.Registerer, version string) error {
	cfg, err := configuration.GetConfiguration()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return Run(ctx, cfg, r, version, cfg.Logger(os.Stderr))
}

func Run(ctx context.Context, cfg configuration.Configuration, r prometheus.Registerer, version string, logger *slog.Logger) error {
	logger.Info("traefik-simple-auth starting", "version", version)
	defer logger.Info("traefik-simple-auth stopped")

	metrics := server.NewMetrics("traefik_simple_auth", "", prometheus.Labels{"provider": cfg.Provider})
	r.MustRegister(metrics)
	sessionStore := sessions.New(cfg.SessionCookieName, cfg.Secret, cfg.SessionExpiration)
	stateStore := state.New(cfg.StateConfiguration)
	s := server.New(ctx, sessionStore, stateStore, cfg, metrics, logger)

	var g errgroup.Group
	g.Go(func() error { return runHTTPServer(ctx, &http.Server{Addr: cfg.PromAddr, Handler: promhttp.Handler()}) })
	g.Go(func() error { return runHTTPServer(ctx, &http.Server{Addr: cfg.Addr, Handler: s}) })
	return g.Wait()
}

func runHTTPServer(ctx context.Context, s *http.Server) error {
	subCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error)
	go func() {
		<-subCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		err := s.Shutdown(shutdownCtx)
		if err != nil {
			err = fmt.Errorf("http server failed to stop: %w", err)
		}
		errCh <- err
	}()

	err := s.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if err != nil {
		err = fmt.Errorf("http server failed to start: %w", err)
	}
	cancel()
	return errors.Join(err, <-errCh)
}
