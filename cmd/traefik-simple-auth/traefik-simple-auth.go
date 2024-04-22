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
	sessionCookieName = flag.String("session-cookie-name", "_traefik_simple_auth", "The cookie name to use for authentication")
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
			l.Error("Error starting Prometheus metrics server", "err", err)
			os.Exit(1)
		}
	}()

	cfg, err := getConfiguration()
	if err != nil {
		l.Error("Error loading configuration", "err", err)
		os.Exit(1)
	}

	m := metrics.New("traefik_simple_auth", "", map[string]string{"provider": *provider})
	prometheus.MustRegister(m)

	s := server.New(cfg, l)
	if err = http.ListenAndServe(*addr, middleware.WithRequestMetrics(m)(s)); !errors.Is(err, http.ErrServerClosed) {
		l.Error("Error starting server", "err", err)
		os.Exit(1)
	}
}

func getConfiguration() (server.Config, error) {
	if *domains == "" {
		return server.Config{}, errors.New("must specify at least one domain")
	}
	domainList := strings.Split(*domains, ",")
	for i := range domainList {
		if domainList[i] != "" && domainList[i][0] != '.' {
			domainList[i] = "." + domainList[i]
		}
	}
	secretBytes, err := base64.StdEncoding.DecodeString(*secret)
	if err != nil {
		return server.Config{}, err
	}
	return server.Config{
		SessionCookieName: *sessionCookieName,
		Expiry:            *expiry,
		Secret:            secretBytes,
		InsecureCookie:    *insecure,
		Domains:           domainList,
		Users:             strings.Split(*users, ","),
		Provider:          *provider,
		ClientID:          *clientId,
		ClientSecret:      *clientSecret,
		AuthPrefix:        *authPrefix,
	}, nil
}
