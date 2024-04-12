package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/go-common/set"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	debug        = flag.Bool("debug", false, "Enable debug mode")
	addr         = flag.String("addr", ":8080", "The address to listen on for HTTP requests.")
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

	s := server.New(getConfiguration(l), l)
	mw := middleware.RequestLogger(l, slog.LevelDebug, middleware.DefaultRequestLogFormatter)

	if err := http.ListenAndServe(*addr, mw(s)); !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func getConfiguration(l *slog.Logger) server.Config {
	userSet := set.New(strings.Split(*users, ",")...)
	authHostname := *authHost
	if authHostname == "" {
		authHostname = "auth." + *domain
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
		Users:          userSet,
		AuthHost:       authHostname,
		ClientID:       *clientId,
		ClientSecret:   *clientSecret,
	}
}
