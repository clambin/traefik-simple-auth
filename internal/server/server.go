package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"log/slog"
	"net/http"
	"time"
)

const OAUTHPath = "/_oauth"

// New returns a new http.Handler that handles traefik's forward-auth requests, and the associated oauth flow.
// It panics if config.Provider is invalid.
func New(ctx context.Context, sessions sessions.Sessions, states state.States, config configuration.Configuration, metrics *Metrics, logger *slog.Logger) http.Handler {
	if metrics != nil {
		go monitorSessions(ctx, metrics, sessions, 10*time.Second)
	}
	logger = logger.With("provider", config.Provider)
	oauthHandlers := buildOAuthHandlers(ctx, config, logger)

	// create the server router
	r := http.NewServeMux()
	addServerRoutes(r,
		newForwardAuthHandler(config.Domains, oauthHandlers, sessions, states, metrics, logger),
		config.Domains,
		config.Whitelist,
		oauthHandlers,
		states,
		sessions,
		metrics,
		logger,
	)
	return r
}

func monitorSessions(ctx context.Context, m *Metrics, sessions sessions.Sessions, interval time.Duration) {
	for {
		for user, count := range sessions.ActiveUsers() {
			m.activeUsers.WithLabelValues(user).Set(float64(count))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func buildOAuthHandlers(ctx context.Context, config configuration.Configuration, logger *slog.Logger) map[domains.Domain]oauth.Handler {
	oauthHandlers := make(map[domains.Domain]oauth.Handler)
	for _, domain := range config.Domains {
		var err error
		if oauthHandlers[domain], err = oauth.NewHandler(ctx, config.Provider, config.OIDCIssuerURL, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, domain, OAUTHPath), logger.With("domain", domain)); err != nil {
			panic("invalid provider: " + config.Provider + ", err: " + err.Error())
		}
	}
	return oauthHandlers
}

func makeAuthURL(authPrefix string, domain domains.Domain, OAUTHPath string) string {
	var dot string
	if domain != "" && domain[0] != '.' {
		dot = "."
	}
	return "https://" + authPrefix + dot + string(domain) + OAUTHPath
}
