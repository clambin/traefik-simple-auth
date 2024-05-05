package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"log/slog"
	"net/http"
	"time"
)

func Run(ctx context.Context, logOutput io.Writer, version string) error {
	flag.Parse()
	cfg, err := GetConfiguration()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

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

	m := NewMetrics("traefik_simple_auth", "", map[string]string{"provider": cfg.Provider})
	prometheus.MustRegister(m)
	sessionStore := sessions.New(cfg.SessionCookieName, cfg.Secret, cfg.Expiration)
	stateStore := state.New[string](time.Minute)
	s := New(ctx, sessionStore, stateStore, cfg, m, l)

	serverErr := make(chan error)
	go func() {
		serverErr <- runHTTPServer(ctx, cfg.Addr, s)
	}()

	err = errors.Join(<-serverErr, <-promErr)
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

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err := httpServer.Shutdown(ctx2)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
