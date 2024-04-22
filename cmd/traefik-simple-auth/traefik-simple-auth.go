package main

import (
	"errors"
	"flag"
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/metrics"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net/http"
	"os"
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

	m := metrics.New("traefik_simple_auth", "", map[string]string{"provider": cfg.Provider})
	prometheus.MustRegister(m)

	s := server.New(cfg, l)
	if err = http.ListenAndServe(cfg.Addr, middleware.WithRequestMetrics(m)(s)); !errors.Is(err, http.ErrServerClosed) {
		l.Error("Error starting server", "err", err)
		os.Exit(1)
	}
}
