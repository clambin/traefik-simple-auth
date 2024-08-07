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
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net/http"
	"time"
)

func Run(ctx context.Context, cfg configuration.Configuration, registry prometheus.Registerer, version string, logger *slog.Logger) error {
	logger.Info("traefik-simple-auth starting", "version", version)

	metrics := server.NewMetrics("traefik_simple_auth", "", prometheus.Labels{"provider": cfg.Provider})
	registry.MustRegister(metrics)
	sessionStore := sessions.New(cfg.SessionCookieName, cfg.Secret, cfg.TTL)
	stateStore := makeStateStore(cfg.CacheConfiguration)
	s := server.New(ctx, sessionStore, stateStore, cfg, metrics, logger)

	var g errgroup.Group
	runServer(ctx, &g, &http.Server{Addr: cfg.PromAddr, Handler: promhttp.Handler()})
	runServer(ctx, &g, &http.Server{Addr: cfg.Addr, Handler: s})

	logger.Info("traefik-simple-auth stopped")
	return g.Wait()
}

func runServer(ctx context.Context, g *errgroup.Group, s *http.Server) {
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
		TTL:       5 * time.Minute,
	}
}
