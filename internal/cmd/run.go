package cmd

import (
	"context"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/internal/server/configuration"
	"github.com/clambin/traefik-simple-auth/pkg/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"io"
	"log/slog"
	"net/http"
	"time"
)

func Run(ctx context.Context, cfg configuration.Configuration, registry prometheus.Registerer, logOutput io.Writer, version string) error {
	var opts slog.HandlerOptions
	if cfg.Debug {
		opts.Level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(logOutput, &opts))
	logger.Info("traefik-simple-auth starting", "version", version)

	promErr := make(chan error)
	go func() {
		m := http.NewServeMux()
		m.Handle("/metrics", promhttp.Handler())
		promErr <- runHTTPServer(ctx, cfg.PromAddr, m)
	}()

	metrics := server.NewMetrics("traefik_simple_auth", "", prometheus.Labels{"provider": cfg.Provider})
	registry.MustRegister(metrics)
	sessionStore := sessions.New(cfg.SessionCookieName, cfg.Secret, cfg.TTL)
	stateStore := makeStateStore(cfg.CacheConfiguration)
	s := server.New(ctx, sessionStore, stateStore, cfg, metrics, logger)

	serverErr := make(chan error)
	go func() {
		serverErr <- runHTTPServer(ctx, cfg.Addr, s)
	}()

	err := errors.Join(<-serverErr, <-promErr)
	logger.Info("traefik-simple-auth stopped")
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

func makeStateStore(cfg configuration.CacheConfiguration) state.States[string] {
	var backend state.Backend[string]
	switch cfg.Backend {
	case "memory":
		backend = state.NewLocalCache[string]()
	case "memcached":
		backend = state.MemcachedCache[string]{
			Namespace: "github.com/clambin/traefik-simple-auth",
			Client:    memcache.New(cfg.MemcachedConfiguration.Addr),
		}
	case "redis":
		backend = state.RedisCache[string]{
			Namespace: "github.com/clambin/traefik-simple-auth",
			Client: redis.NewClient(&redis.Options{
				Addr:     cfg.RedisConfiguration.Addr,
				DB:       cfg.RedisConfiguration.Database,
				Username: cfg.RedisConfiguration.Username,
				Password: cfg.RedisConfiguration.Password,
			}),
		}
	default:
		panic("unknown backend: " + cfg.Backend)
	}

	return state.States[string]{
		Backend: backend,
		TTL:     cfg.TTL,
	}
}
