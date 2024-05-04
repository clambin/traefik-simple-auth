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

type Server struct {
	sessions      sessions.Sessions
	states        state.States[string]
	oauthHandlers map[domains.Domain]oauth.Handler
	http.Handler
}

func New(ctx context.Context, config configuration.Configuration, metrics *Metrics, logger *slog.Logger) *Server {
	logger = logger.With("provider", config.Provider)

	s := Server{
		sessions:      sessions.New(config.SessionCookieName, config.Secret, config.Expiry),
		states:        state.New[string](5 * time.Minute),
		oauthHandlers: make(map[domains.Domain]oauth.Handler),
	}
	for _, domain := range config.Domains {
		var err error
		if s.oauthHandlers[domain], err = oauth.NewHandler(ctx, config.Provider, config.OIDCIssuerURL, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, domain, OAUTHPath), logger.With("domain", domain)); err != nil {
			panic("unknown provider: " + config.Provider)
		}
	}

	if metrics != nil {
		go s.monitorSessions(metrics, 10*time.Second)
	}

	// create the server router
	r := http.NewServeMux()
	addRoutes(r,
		config.Domains,
		config.Whitelist,
		s.oauthHandlers,
		s.states,
		s.sessions,
		metrics,
		logger,
	)
	s.Handler = traefikForwardAuthParser(r)
	return &s
}
func (s Server) monitorSessions(m *Metrics, interval time.Duration) {
	for {
		for user, count := range s.sessions.ActiveUsers() {
			m.activeUsers.WithLabelValues(user).Set(float64(count))
		}
		time.Sleep(interval)
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
func traefikForwardAuthParser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isForwardAuth(r) {
			r.URL = getOriginalTarget(r)
		}
		next.ServeHTTP(w, r)
	})
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
