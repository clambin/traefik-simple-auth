package server

import (
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
	oauthHandlers := make(map[domains.Domain]oauth.Handler)
	for _, domain := range config.Domains {
		var err error
		if oauthHandlers[domain], err = oauth.NewHandler(config.Provider, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, domain, OAUTHPath), l.With("oauth", config.Provider)); err != nil {
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

	// create the server router
	r := http.NewServeMux()
	// oauth flow is sent directly to the server
	r.Handle(OAUTHPath, withMetrics(&s.cbHandler))

	// forwardAuth & logout flows come in via forwardAuth middleware
	forwardAuthHandler := http.NewServeMux()
	forwardAuthHandler.HandleFunc(OAUTHPath+"/logout", s.authHandler.LogOut)
	forwardAuthHandler.HandleFunc("/", s.authHandler.Authenticate)
	r.Handle("/",
		traefikForwardAuthParser()( // convert the forwardAuth request to a regular http request
			handlers.SessionExtractor(s.cbHandler.Sessions, l)( // extract & validate the session cookie from the request
				withMetrics( // add metrics
					forwardAuthHandler, // authenticate or logout
				),
			),
		),
	)

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
			r.URL, _ = url.Parse(getOriginalTarget(r))
			next.ServeHTTP(w, r)
		}
	}
}

func getOriginalTarget(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		// TODO: why is this sometimes not set?
		proto = "https"
	}
	return proto + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
}
