package server

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"codeberg.org/clambin/go-common/flagger"
	"github.com/clambin/traefik-simple-auth/internal/server/csrf"
)

type Configuration struct {
	Whitelist Whitelist `flagger.skip:"true"`
	Auth
	flagger.Log
	flagger.Prom
	Session
	Addr              string             `flagger.usage:"The address to listen on for HTTP requests"`
	PProfAddr         string             `flagger.name:"pprof.addr" flagger.usage:"The address to listen on for Go pprof profiler (default: no pprof profiler)"`
	Domain            Domain             `flagger.skip:"true"`
	CSRFConfiguration csrf.Configuration `flagger.name:"csrf"`
}

type Session struct {
	CookieName string        `flagger.name:"cookie-name" flagger.usage:"The cookie name to use for authentication"`
	Secret     []byte        `flagger.skip:"true"`
	Expiration time.Duration `flagger.usage:"How long the session should remain valid"`
}

type Auth struct {
	Provider     string `flagger.usage:"OAuth2 provider"`
	IssuerURL    string `flagger.name:"issuer-url" flagger.usage:"The Auth Issuer URL to use (only used when provider is oidc)"`
	ClientID     string `flagger.name:"client-id" flagger.usage:"OAuth2 Client ID"`
	ClientSecret string `flagger.name:"client-secret" flagger.usage:"OAuth2 Client Secret"`
	AuthPrefix   string `flagger.name:"auth-prefix" flagger.usage:"Prefix to construct the authRedirect URL from the domain"`
}

var DefaultConfiguration = Configuration{
	Addr: ":8080",
	Session: Session{
		CookieName: "_traefik_simple_auth",
		Expiration: 30 * 24 * time.Hour,
	},
	Auth: Auth{
		Provider:   "google",
		IssuerURL:  "https://accounts.google.com",
		AuthPrefix: "auth",
	},
	CSRFConfiguration: csrf.Configuration{
		TTL:   10 * time.Minute,
		Redis: csrf.RedisConfiguration{Namespace: "github.com/clambin/traefik-simple-auth/state"},
	},
	Log:  flagger.DefaultLog,
	Prom: flagger.DefaultProm,
}

func GetConfiguration(f *flag.FlagSet, args ...string) (Configuration, error) {
	cfg := DefaultConfiguration
	flagger.SetFlags(f, &cfg)
	// these flags require special processing that flagger doesn't support
	f.Func("users", "Comma-separated list of usernames to allow access", func(s string) error {
		return cfg.Whitelist.Add(s)
	})
	f.Func("session.secret", "Secret to use for authentication (base64 encoded)", func(s string) (err error) {
		if cfg.Secret, err = base64.StdEncoding.DecodeString(s); err != nil {
			return fmt.Errorf("failed to decode secret: %w", err)
		}
		return nil
	})
	f.Func("domain", "Domain to allow access", func(s string) (err error) {
		if cfg.Domain, err = NewDomain(s); err != nil {
			return fmt.Errorf("invalid domain: %w", err)
		}
		return err
	})

	if args == nil {
		args = os.Args[1:]
	}
	err := f.Parse(args)
	if err != nil {
		return Configuration{}, err
	}

	if cfg.Domain == "" {
		return Configuration{}, errors.New("missing domain")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return Configuration{}, errors.New("must specify both client-id and client-secret")
	}
	return cfg, nil
}
