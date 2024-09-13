package server

import (
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"log/slog"
	"net/http"
)

// newForwardAuthHandler returns a http.Handler that servers the auth request ("/") and the logout request ("/_oauth/logout)
func newForwardAuthHandler(
	domains domains.Domains,
	oauthHandlers map[domains.Domain]oauth.Handler,
	sessions sessions.Sessions,
	states state.States,
	metrics *Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	addForwardAuthRoutes(mux, domains, oauthHandlers, sessions, states, logger)
	return traefikForwardAuthParser(
		forwardAuthMiddleware(sessions, metrics, logger)(
			mux,
		),
	)
}

func addForwardAuthRoutes(
	mux *http.ServeMux,
	domains domains.Domains,
	oauthHandlers map[domains.Domain]oauth.Handler,
	sessions sessions.Sessions,
	states state.States,
	logger *slog.Logger,
) {
	mux.Handle("/", ForwardAuthHandler(domains, oauthHandlers, states, logger.With("handler", "forwardAuth")))
	mux.Handle(OAUTHPath+"/logout", LogoutHandler(domains, sessions, logger.With("handler", "logout")))
}

// forwardAuthMiddleware returns a middleware that extracts the session cookie (if it exists) and measures the request metrics
func forwardAuthMiddleware(sessions sessions.Sessions, m *Metrics, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return sessionExtractor(sessions, logger.With("middleware", "sessionExtractor"))( // extract & validate the session cookie from the request
			withMetrics(m)( // measure request metrics
				next,
			),
		)
	}
}

// traefikForwardAuthParser takes a request passed by traefik's forwardAuth middleware and reconstructs the original request.
func traefikForwardAuthParser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL = getOriginalTarget(r)
		next.ServeHTTP(w, r)
	})
}
