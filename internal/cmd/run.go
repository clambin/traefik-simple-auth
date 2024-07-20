package cmd

import (
	"context"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/pkg/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"net/http"
	"time"
)

func Run(ctx context.Context, cfg configuration.Configuration, registry prometheus.Registerer, version string, logger *slog.Logger) error {
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

func makeStateStore(cfg configuration.CacheConfiguration) state.States {
	var backend state.Cache[string]
	switch cfg.Backend {
	case "memory":
		backend = state.NewLocalCache[string]()
	case "memcached":
		backend = state.MemcachedCache[string]{
			Client: memcache.New(cfg.MemcachedConfiguration.Addr),
		}
	case "redis":
		backend = state.RedisCache[string]{
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

	return state.States{
		Cache:     backend,
		Namespace: "github.com/clambin/traefik-simple-auth",
		TTL:       10 * time.Minute,
	}
}
