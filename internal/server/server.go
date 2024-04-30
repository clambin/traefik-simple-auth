package server

import (
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/handlers"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"log/slog"
	"net/http"
	"time"
)

const OAUTHPath = "/_oauth"

type Server struct {
	sessions    *sessions.Sessions
	states      state.Store[string]
	cbHandler   handlers.AuthCallbackHandler
	authHandler handlers.ForwardAuthHandler
	http.Handler
}

func New(config configuration.Configuration, m *Metrics, l *slog.Logger) *Server {
	oauthHandlers := make(map[string]oauth.Handler)
	for _, d := range config.Domains {
		var err error
		if oauthHandlers[d], err = oauth.NewHandler(config.Provider, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, d, OAUTHPath), l.With("oauth", config.Provider)); err != nil {
			panic("unknown provider: " + config.Provider)
		}
	}

	s := Server{
		sessions: sessions.New(config.SessionCookieName, config.Secret, config.Expiry),
		states:   state.New[string](5 * time.Minute),
	}

	s.cbHandler = handlers.AuthCallbackHandler{
		Logger:        l.With("handler", "authCallback"),
		States:        &s.states,
		Domains:       config.Domains,
		OAuthHandlers: oauthHandlers,
		Whitelist:     config.Whitelist,
		Sessions:      s.sessions,
	}

	s.authHandler = handlers.ForwardAuthHandler{
		Logger:        l.With("handler", "forwardAuth"),
		Domains:       config.Domains,
		States:        &s.states,
		Sessions:      s.sessions,
		OAuthHandlers: oauthHandlers,
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

	authMiddleware := func(next http.HandlerFunc) http.Handler {
		return traefikForwardAuthParser()(handlers.SessionExtractor(s.cbHandler.Sessions, l)(withMetrics(next)))
	}

	r := http.NewServeMux()
	r.Handle("/", authMiddleware(s.authHandler.Authenticate))
	r.Handle(OAUTHPath+"/logout", authMiddleware(s.authHandler.LogOut))
	r.Handle(OAUTHPath, withMetrics(&s.cbHandler))

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
func makeAuthURL(authPrefix, domain, OAUTHPath string) string {
	var dot string
	if domain != "" && domain[0] != '.' {
		dot = "."
	}
	return "https://" + authPrefix + dot + domain + OAUTHPath
}
