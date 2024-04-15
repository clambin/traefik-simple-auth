package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/traefik-simple-auth/internal/metrics"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	debug        = flag.Bool("debug", false, "Enable debug mode")
	addr         = flag.String("addr", ":8080", "The address to listen on for HTTP requests")
	promAddr     = flag.String("prom", ":9090", "The address to listen on for Prometheus scrape requests")
	expiry       = flag.Duration("expiry", 30*24*time.Hour, "How long a session remains valid")
	secret       = flag.String("secret", "", "Secret to use for authentication")
	insecure     = flag.Bool("insecure", false, "Enable insecure cookies")
	domain       = flag.String("domain", "", "domain managed by traefik-simple-auth")
	users        = flag.String("users", "", "Comma-separated list of usernames to login")
	authHost     = flag.String("auth-host", "", "Hostname that handles authentication requests from Google")
	clientId     = flag.String("client-id", "", "Google OAuth Client ID")
	clientSecret = flag.String("client-secret", "", "Google OAuth Client Secret")
)

func main() {
	flag.Parse()

	var opts slog.HandlerOptions
	if *debug {
		opts.Level = slog.LevelDebug
	}
	l := slog.New(slog.NewJSONHandler(os.Stderr, &opts))

	go func() {
		if err := http.ListenAndServe(*promAddr, promhttp.Handler()); !errors.Is(err, http.ErrServerClosed) {
			l.Error("failed to start Prometheus metrics handler", "error", err)
			panic(err)
		}
	}()

	m := metrics.New("traefik_simple_auth", "", nil)
	prometheus.MustRegister(m)

	s := server.New(getConfiguration(l), l)
	if err := http.ListenAndServe(*addr, middleware.WithRequestMetrics(m)(s)); !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func getConfiguration(l *slog.Logger) server.Config {
	if len(*domain) > 0 && (*domain)[0] != '.' {
		*domain = "." + *domain
	}
	authHostname := *authHost
	if authHostname == "" {
		authHostname = "auth" + *domain
		l.Warn("no auth hostname set, using default auth hostname: " + authHostname)
	}
	secretBytes, err := base64.StdEncoding.DecodeString(*secret)
	if err != nil {
		l.Error("Could not decode secret", "err", err)
		os.Exit(1)
	}
	return server.Config{
		Expiry:         *expiry,
		Secret:         secretBytes,
		InsecureCookie: *insecure,
		Domain:         *domain,
		Users:          strings.Split(*users, ","),
		AuthHost:       authHostname,
		ClientID:       *clientId,
		ClientSecret:   *clientSecret,
	}
}
