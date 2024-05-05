package cmd

import (
	"context"
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"log/slog"
	"net/http"
	"time"
)

func Run(ctx context.Context, cfg server.Configuration, registry prometheus.Registerer, logOutput io.Writer, version string) error {
	var opts slog.HandlerOptions
	if cfg.Debug {
		opts.Level = slog.LevelDebug
	}
	l := slog.New(slog.NewJSONHandler(logOutput, &opts))
	l.Info("traefik-simple-auth starting", "version", version)

	promErr := make(chan error)
	go func() {
		m := http.NewServeMux()
		m.Handle("/metrics", promhttp.Handler())
		promErr <- runHTTPServer(ctx, cfg.PromAddr, m)
	}()

	m := server.NewMetrics("traefik_simple_auth", "", map[string]string{"provider": cfg.Provider})
	registry.MustRegister(m)
	sessionStore := sessions.New(cfg.SessionCookieName, cfg.Secret, cfg.Expiration)
	stateStore := state.New[string](time.Minute)
	s := server.New(ctx, sessionStore, stateStore, cfg, m, l)

	serverErr := make(chan error)
	go func() {
		serverErr <- runHTTPServer(ctx, cfg.Addr, s)
	}()

	err := errors.Join(<-serverErr, <-promErr)
	l.Info("traefik-simple-auth stopped")
	return err
}

func runHTTPServer(ctx context.Context, addr string, handler http.Handler) error {
	httpServer := &http.Server{Addr: addr, Handler: handler}
	errCh := make(chan error)
	go func() {
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel2()
	err := httpServer.Shutdown(ctx2)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
