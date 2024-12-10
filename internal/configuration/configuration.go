package configuration

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"io"
	"log/slog"
	"strings"
	"time"
)

var (
	debug              = flag.Bool("debug", false, "Log debug messages")
	addr               = flag.String("addr", ":8080", "The address to listen on for HTTP requests")
	promAddr           = flag.String("prom", ":9090", "The address to listen on for Prometheus scrape requests")
	sessionCookieName  = flag.String("session-cookie-name", "_traefik_simple_auth", "The cookie name to use for authentication")
	sessionExpiration  = flag.Duration("expiry", 30*24*time.Hour, "How long a session remains valid")
	authPrefix         = flag.String("auth-prefix", "auth", "prefix to construct the authRedirect URL from the domain")
	domainsString      = flag.String("domains", "", "Comma-separated list of domains to allow access")
	users              = flag.String("users", "", "Comma-separated list of usernames to allow access")
	provider           = flag.String("provider", "google", "The OAuth2 provider")
	oidcIssuerURL      = flag.String("provider-oidc-issuer", "https://accounts.google.com", "The OIDC Issuer URL to use (only used when provider is oidc")
	clientId           = flag.String("client-id", "", "OAuth2 Client ID")
	clientSecret       = flag.String("client-secret", "", "OAuth2 Client Secret")
	secret             = flag.String("secret", "", "Secret to use for authentication (base64 encoded)")
	cacheBackend       = flag.String("cache", "memory", "The backend to use for caching CSFR states. memory, memcached and redis are supported")
	cacheMemcachedAddr = flag.String("cache-memcached-addr", "", "memcached address to use (only used when cache backend is memcached)")
	cacheRedisAddr     = flag.String("cache-redis-addr", "", "redis address to use (only used when cache backend is redis)")
	cacheRedisDatabase = flag.Int("cache-redis-database", 0, "redis database to use (only used when cache backend is redis)")
	cacheRedisUsername = flag.String("cache-redis-username", "", "Redis username (only used when cache backend is redis)")
	cacheRedisPassword = flag.String("cache-redis-password", "", "Redis password (only used when cache backend is redis)")
)

type Configuration struct {
	Whitelist          whitelist.Whitelist
	Addr               string
	PromAddr           string
	SessionCookieName  string
	Provider           string
	OIDCIssuerURL      string
	ClientID           string
	ClientSecret       string
	AuthPrefix         string
	Secret             []byte
	Domains            domains.Domains
	StateConfiguration state.Configuration
	SessionExpiration  time.Duration
	Debug              bool
}

func GetConfiguration() (Configuration, error) {
	flag.Parse()
	cfg := Configuration{
		Debug:             *debug,
		Addr:              *addr,
		PromAddr:          *promAddr,
		SessionCookieName: *sessionCookieName,
		Provider:          *provider,
		OIDCIssuerURL:     *oidcIssuerURL,
		ClientID:          *clientId,
		ClientSecret:      *clientSecret,
		AuthPrefix:        *authPrefix,
		SessionExpiration: *sessionExpiration,
		StateConfiguration: state.Configuration{
			CacheType: *cacheBackend,
			Namespace: "github.com/clambin/traefik-simple-auth/state",
			TTL:       10 * time.Minute,
			MemcachedConfiguration: state.MemcachedConfiguration{
				Addr: *cacheMemcachedAddr,
			},
			RedisConfiguration: state.RedisConfiguration{
				Addr:     *cacheRedisAddr,
				Database: *cacheRedisDatabase,
				Username: *cacheRedisUsername,
				Password: *cacheRedisPassword,
			},
		},
	}
	var err error
	cfg.Domains, err = domains.New(strings.Split(*domainsString, ","))
	if err != nil {
		return Configuration{}, fmt.Errorf("invalid domain list: %w", err)
	}
	cfg.Whitelist, err = whitelist.New(strings.Split(*users, ","))
	if err != nil {
		return Configuration{}, fmt.Errorf("invalid whitelist: %w", err)
	}
	cfg.Secret, err = base64.StdEncoding.DecodeString(*secret)
	if err != nil {
		return Configuration{}, fmt.Errorf("failed to decode secret: %w", err)
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
