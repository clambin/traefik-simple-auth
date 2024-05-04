package main

import (
	"context"
	"errors"
	"flag"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net/http"
	"os"
	"time"
)

var version string = "change-me"

func main() {
	flag.Parse()

	cfg, err := configuration.GetConfiguration()
	if err != nil {
		panic(err)
	}

	var opts slog.HandlerOptions
	if cfg.Debug {
		opts.Level = slog.LevelDebug
	}
	l := slog.New(slog.NewJSONHandler(os.Stderr, &opts))
	l.Info("Starting traefik-simple-auth", "version", version)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err = http.ListenAndServe(cfg.PromAddr, nil); !errors.Is(err, http.ErrServerClosed) {
			l.Error("Error starting Prometheus metrics server", "err", err)
			os.Exit(1)
		}
	}()

	m := server.NewMetrics("traefik_simple_auth", "", map[string]string{"provider": cfg.Provider})
	prometheus.MustRegister(m)

	sessionStore := sessions.New(cfg.SessionCookieName, cfg.Secret, cfg.Expiration)
	stateStore := state.New[string](time.Minute)

	s := server.New(context.TODO(), sessionStore, stateStore, cfg, m, l)
	if err = http.ListenAndServe(cfg.Addr, s); !errors.Is(err, http.ErrServerClosed) {
		l.Error("Error starting server", "err", err)
		os.Exit(1)
	}
}
