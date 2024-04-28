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
	debug             = flag.Bool("debug", false, "Enable debug mode")
	addr              = flag.String("addr", ":8080", "The address to listen on for HTTP requests")
	promAddr          = flag.String("prom", ":9090", "The address to listen on for Prometheus scrape requests")
	sessionCookieName = flag.String("session-cookie-name", "_traefik_simple_auth", "The cookie name to use for authentication")
	expiry            = flag.Duration("expiry", 30*24*time.Hour, "How long a session remains valid")
	insecure          = flag.Bool("insecure", false, "Use insecure cookies")
	authPrefix        = flag.String("auth-prefix", "auth", "prefix to construct the authRedirect URL from the domain")
	domainsString     = flag.String("domains", "", "Comma-separated list of domains to allow access")
	users             = flag.String("users", "", "Comma-separated list of usernames to login")
	provider          = flag.String("provider", "google", "The OAuth2 provider to use")
	clientId          = flag.String("client-id", "", "OAuth2 Client ID")
	clientSecret      = flag.String("client-secret", "", "OAuth2 Client Secret")
	secret            = flag.String("secret", "", "Secret to use for authentication")
)

type Configuration struct {
	Debug             bool
	Addr              string
	PromAddr          string
	SessionCookieName string
	Expiry            time.Duration
	Secret            []byte
	Provider          string
	Domains           domains.Domains
	Whitelist         whitelist.Whitelist
	ClientID          string
	ClientSecret      string
	AuthPrefix        string
}

func GetConfiguration() (Configuration, error) {
	domainList, err := domains.GetDomains(strings.Split(*domainsString, ","))
	if err != nil {
		return Configuration{}, fmt.Errorf("invalid domain list: %w", err)
	}
	if len(domainList) == 0 {
		return Configuration{}, errors.New("no valid domains")
	}
	whiteList, err := whitelist.New(strings.Split(*users, ","))
	if err != nil {
		return Configuration{}, fmt.Errorf("invalid whitelist: %w", err)
	}
	secretBytes, err := base64.StdEncoding.DecodeString(*secret)
	if err != nil {
		return Configuration{}, err
	}
	if *clientId == "" || *clientSecret == "" {
		return Configuration{}, errors.New("must specify both client-id and client-secret")
	}
	return Configuration{
		Debug:             *debug,
		Addr:              *addr,
		PromAddr:          *promAddr,
		SessionCookieName: *sessionCookieName,
		Expiry:            *expiry,
		Secret:            secretBytes,
		Domains:           domainList,
		Whitelist:         whiteList,
		Provider:          *provider,
		ClientID:          *clientId,
		ClientSecret:      *clientSecret,
		AuthPrefix:        *authPrefix,
	}, nil
}
