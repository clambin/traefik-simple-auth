package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const OAUTHPath = "/_oauth"

func New(ctx context.Context, sessions sessions.Sessions, states state.States[string], config configuration.Configuration, metrics *Metrics, logger *slog.Logger) http.Handler {
	logger = logger.With("provider", config.Provider)

	oauthHandlers := make(map[domains.Domain]oauth.Handler)
	for _, domain := range config.Domains {
		var err error
		if oauthHandlers[domain], err = oauth.NewHandler(ctx, config.Provider, config.OIDCIssuerURL, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, domain, OAUTHPath), logger.With("domain", domain)); err != nil {
			panic("invalid provider: " + config.Provider + ", err: " + err.Error())
		}
	}

	if metrics != nil {
		go monitorSessions(ctx, metrics, sessions, 10*time.Second)
	}

	// create the server router
	r := http.NewServeMux()
	addRoutes(r,
		config.Domains,
		config.Whitelist,
		oauthHandlers,
		states,
		sessions,
		metrics,
		logger,
	)
	return traefikForwardAuthParser(logger)(r)
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

// makeAuthURL returns the auth URL for a given domain
func makeAuthURL(authPrefix string, domain domains.Domain, OAUTHPath string) string {
	var dot string
	if domain != "" && domain[0] != '.' {
		dot = "."
	}
	return "https://" + authPrefix + dot + string(domain) + OAUTHPath
}

// traefikForwardAuthParser takes a request passed by traefik's forwardAuth middleware and reconstructs the original request.
func traefikForwardAuthParser(logger *slog.Logger) func(next http.Handler) http.Handler {
	logger = logger.With("handler", "traefikForwardAuthParser")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("received request", "url", r.URL)
			if isForwardAuth(r) {
				r.URL = getOriginalTarget(r)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isForwardAuth(r *http.Request) bool {
	_, ok := r.Header["X-Forwarded-Host"]
	return ok
}

func getOriginalTarget(r *http.Request) *url.URL {
	hdr := r.Header
	path := getHeaderValue(hdr, "X-Forwarded-Uri", "/")
	var rawQuery string
	if n := strings.Index(path, "?"); n > 0 {
		rawQuery = path[n+1:]
		path = path[:n]
	}
	return &url.URL{
		Scheme:   getHeaderValue(hdr, "X-Forwarded-Proto", "https"),
		Host:     getHeaderValue(hdr, "X-Forwarded-Host", ""),
		Path:     path,
		RawQuery: rawQuery,
	}
}

func getHeaderValue(h map[string][]string, key string, defaultValue string) string {
	val, ok := h[key]
	if !ok || len(val) == 0 {
		return defaultValue
	}
	return val[0]
}
