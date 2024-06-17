package configuration

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"strings"
	"time"
)

var (
	debug              = flag.Bool("debug", false, "Log debug messages")
	addr               = flag.String("addr", ":8080", "The address to listen on for HTTP requests")
	promAddr           = flag.String("prom", ":9090", "The address to listen on for Prometheus scrape requests")
	sessionCookieName  = flag.String("session-cookie-name", "_traefik_simple_auth", "The cookie name to use for authentication")
	expiry             = flag.Duration("expiry", 30*24*time.Hour, "How long a session remains valid")
	authPrefix         = flag.String("auth-prefix", "auth", "prefix to construct the authRedirect URL from the domain")
	domainsString      = flag.String("domains", "", "Comma-separated list of domains to allow access")
	users              = flag.String("users", "", "Comma-separated list of usernames to allow access")
	provider           = flag.String("provider", "google", "The OAuth2 provider")
	oidcIssuerURL      = flag.String("provider-oidc-issuer", "https://accounts.google.com", "The OIDC Issuer URL to use (only used when provider is oidc")
	clientId           = flag.String("client-id", "", "OAuth2 Client ID")
	clientSecret       = flag.String("client-secret", "", "OAuth2 Client Secret")
	secret             = flag.String("secret", "", "Secret to use for authentication (base64 encoded)")
	cacheBackend       = flag.String("cache", "memory", "The backend to use for caching")
	cacheMemcachedAddr = flag.String("cache-memcached-addr", "", "memcached address to use (only used when cache backend is memcached)")
)

type Configuration struct {
	Debug             bool
	Addr              string
	PromAddr          string
	SessionCookieName string
	Secret            []byte
	Provider          string
	OIDCIssuerURL     string
	Domains           domains.Domains
	Whitelist         whitelist.Whitelist
	ClientID          string
	ClientSecret      string
	AuthPrefix        string
	CacheConfiguration
}

type CacheConfiguration struct {
	Backend string
	TTL     time.Duration
	RedisConfiguration
	MemcachedConfiguration
}

type RedisConfiguration struct {
	Addr     string
	Database int
	Username string
	Password string
}

type MemcachedConfiguration struct {
	Addr string
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
		CacheConfiguration: CacheConfiguration{
			Backend: *cacheBackend,
			TTL:     *expiry,
			MemcachedConfiguration: MemcachedConfiguration{
				Addr: *cacheMemcachedAddr,
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
