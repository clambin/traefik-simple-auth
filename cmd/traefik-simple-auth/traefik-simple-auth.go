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
	debug             = flag.Bool("debug", false, "Enable debug mode")
	addr              = flag.String("addr", ":8080", "The address to listen on for HTTP requests")
	promAddr          = flag.String("prom", ":9090", "The address to listen on for Prometheus scrape requests")
	sessionCookieName = flag.String("session-cookie-name", "traefik_simple_auth", "The cookie name to use for authentication")
	expiry            = flag.Duration("expiry", 30*24*time.Hour, "How long a session remains valid")
	insecure          = flag.Bool("insecure", false, "Use insecure cookies")
	authPrefix        = flag.String("auth-prefix", "auth", "prefix to construct the authRedirect URL from the domain")
	domains           = flag.String("domains", "", "Comma-separated list of domains to allow access")
	users             = flag.String("users", "", "Comma-separated list of usernames to login")
	provider          = flag.String("provider", "google", "The OAuth2 provider to use")
	clientId          = flag.String("client-id", "", "OAuth2 Client ID")
	clientSecret      = flag.String("client-secret", "", "OAuth2 Client Secret")
	secret            = flag.String("secret", "", "Secret to use for authentication")

	version string = "change-me"
)

func main() {
	flag.Parse()

	var opts slog.HandlerOptions
	if *debug {
		opts.Level = slog.LevelDebug
	}
	l := slog.New(slog.NewJSONHandler(os.Stderr, &opts))

	l.Info("Starting traefik-simple-auth", "version", version)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(*promAddr, nil); !errors.Is(err, http.ErrServerClosed) {
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
	if len(*domains) > 0 && (*domains)[0] != '.' {
		*domains = "." + *domains
	}
	secretBytes, err := base64.StdEncoding.DecodeString(*secret)
	if err != nil {
		l.Error("Could not decode secret", "err", err)
		os.Exit(1)
	}
	return server.Config{
		SessionCookieName: *sessionCookieName,
		Expiry:            *expiry,
		Secret:            secretBytes,
		InsecureCookie:    *insecure,
		Domains:           strings.Split(*domains, ","),
		Users:             strings.Split(*users, ","),
		Provider:          *provider,
		ClientID:          *clientId,
		ClientSecret:      *clientSecret,
		AuthPrefix:        *authPrefix,
	}
}
