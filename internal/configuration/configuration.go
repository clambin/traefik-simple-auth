package configuration

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/domain"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"io"
	"log/slog"
	"strings"
	"time"
)

type Configuration struct {
	Whitelist          whitelist.Whitelist
	Addr               string
	PromAddr           string
	PProfAddr          string
	SessionCookieName  string
	Provider           string
	OIDCIssuerURL      string
	ClientID           string
	ClientSecret       string
	AuthPrefix         string
	Secret             []byte
	Domain             domain.Domain
	StateConfiguration state.Configuration
	SessionExpiration  time.Duration
	Debug              bool
}

func GetConfiguration() (Configuration, error) {
	cfg := Configuration{
		StateConfiguration: state.Configuration{
			Namespace: "github.com/clambin/traefik-simple-auth/state",
			TTL:       10 * time.Minute,
		},
	}
	users := flag.String("users", "", "Comma-separated list of usernames to allow access")
	flag.StringVar(&cfg.Addr, "addr", ":8080", "The address to listen on for HTTP requests")
	flag.StringVar(&cfg.PromAddr, "prom", ":9090", "The address to listen on for Prometheus scrape requests")
	flag.StringVar(&cfg.PProfAddr, "pprof", "", "The address to listen on for Go pprof profiler (default: no pprof profiler)")
	flag.StringVar(&cfg.SessionCookieName, "session-cookie-name", "_traefik_simple_auth", "The cookie name to use for authentication")
	flag.StringVar(&cfg.Provider, "provider", "google", "OAuth2 provider")
	flag.StringVar(&cfg.OIDCIssuerURL, "provider-oidc-issuer", "https://accounts.google.com", "The OIDC Issuer URL to use (only used when provider is oidc")
	flag.StringVar(&cfg.ClientID, "client-id", "", "OAuth2 Client ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", "", "OAuth2 Client Secret")
	flag.StringVar(&cfg.AuthPrefix, "auth-prefix", "auth", "Prefix to construct the authRedirect URL from the domain")
	secret := flag.String("secret", "", "Secret to use for authentication (base64 encoded)")
	domainString := flag.String("domain", "", "Domain to allow access")
	flag.StringVar(&cfg.StateConfiguration.CacheType, "cache", "memory", "The backend to use for caching CSFR states. memory, memcached and redis are supported")
	flag.StringVar(&cfg.StateConfiguration.MemcachedConfiguration.Addr, "cache-memcached-addr", "", "memcached address to use (only used when cache backend is memcached)")
	flag.StringVar(&cfg.StateConfiguration.RedisConfiguration.Addr, "cache-redis-addr", "", "redis address to use (only used when cache backend is redis)")
	flag.IntVar(&cfg.StateConfiguration.RedisConfiguration.Database, "cache-redis-database", 0, "redis database to use (only used when cache backend is redis)")
	flag.StringVar(&cfg.StateConfiguration.RedisConfiguration.Username, "cache-redis-username", "", "Redis username (only used when cache backend is redis)")
	flag.StringVar(&cfg.StateConfiguration.RedisConfiguration.Password, "cache-redis-password", "", "Redis password (only used when cache backend is redis)")
	flag.DurationVar(&cfg.SessionExpiration, "expiry", 30*24*time.Hour, "How long a session remains valid")
	flag.BoolVar(&cfg.Debug, "debug", false, "Log debug messages")
	flag.Parse()

	var err error
	if cfg.Whitelist, err = whitelist.New(strings.Split(*users, ",")); err != nil {
		return Configuration{}, fmt.Errorf("invalid whitelist: %w", err)
	}
	if cfg.Secret, err = base64.StdEncoding.DecodeString(*secret); err != nil {
		return Configuration{}, fmt.Errorf("failed to decode secret: %w", err)
	}
	if cfg.Domain, err = domain.New(*domainString); err != nil {
		return Configuration{}, fmt.Errorf("invalid domain: %w", err)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return Configuration{}, errors.New("must specify both client-id and client-secret")
	}
	return cfg, nil
}

func (c Configuration) Logger(w io.Writer) *slog.Logger {
	var opts slog.HandlerOptions
	if c.Debug {
		opts = slog.HandlerOptions{Level: slog.LevelDebug}
	}
	return slog.New(slog.NewJSONHandler(w, &opts))
}
