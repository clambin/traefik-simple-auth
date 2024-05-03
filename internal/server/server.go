package server

import (
	"context"
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/handlers"
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
	sessions    *sessions.Sessions
	states      state.States[string]
	cbHandler   handlers.AuthCallbackHandler
	authHandler handlers.ForwardAuthHandler
	http.Handler
}

func New(ctx context.Context, config configuration.Configuration, m *Metrics, l *slog.Logger) *Server {
	l = l.With("provider", config.Provider)

	oauthHandlers := make(map[domains.Domain]oauth.Handler)
	for _, domain := range config.Domains {
		var err error
		if oauthHandlers[domain], err = oauth.NewHandler(ctx, config.Provider, config.OIDCServiceURL, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, domain, OAUTHPath), l.With("domain", domain)); err != nil {
			panic("unknown provider: " + config.Provider)
		}
	}

	sessionStore := sessions.New(config.SessionCookieName, config.Secret, config.Expiry)
	stateStore := state.New[string](5 * time.Minute)

	s := Server{
		sessions: sessionStore,
		states:   stateStore,
		cbHandler: handlers.AuthCallbackHandler{
			Logger:        l.With("handler", "authCallback"),
			States:        &stateStore,
			Domains:       config.Domains,
			OAuthHandlers: oauthHandlers,
			Whitelist:     config.Whitelist,
			Sessions:      sessionStore,
		},
		authHandler: handlers.ForwardAuthHandler{
			Logger:        l.With("handler", "forwardAuth"),
			Domains:       config.Domains,
			States:        &stateStore,
			Sessions:      sessionStore,
			OAuthHandlers: oauthHandlers,
			OAUTHPath:     OAUTHPath,
		},
	}

	withMetrics := func(next http.Handler) http.Handler {
		return next
	}
	if m != nil {
		withMetrics = func(next http.Handler) http.Handler {
			return middleware.WithRequestMetrics(m)(next)
		}
		go s.monitorSessions(m, 10*time.Second)
	}

	// create the server router
	r := http.NewServeMux()
	// oauth flow is sent directly to the server
	r.Handle(OAUTHPath, withMetrics(&s.cbHandler))
	// forwardAuth & logout flow are sent by forwardAuth
	//
	// both metrics and authHandler need the session (stored in a cookie), so we use SessionExtractor to extract it once
	// and store it in the request's context.
	r.Handle("/", traefikForwardAuthParser()( // convert the forwardAuth request to a regular http request
		handlers.SessionExtractor(s.cbHandler.Sessions, l)( // extract & validate the session cookie from the request
			withMetrics( // add metrics
				&s.authHandler, // authenticate or logout
			),
		),
	))

	s.Handler = r
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
func traefikForwardAuthParser() func(next http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.URL = getOriginalTarget(r)
			next.ServeHTTP(w, r)
		}
	}
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
