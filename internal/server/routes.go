package server

import (
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"log/slog"
	"net/http"
)

func addRoutes(
	mux *http.ServeMux,
	domains domains.Domains,
	whitelist whitelist.Whitelist,
	oauthHandlers map[domains.Domain]oauth.Handler,
	states state.States,
	sessions sessions.Sessions,
	metrics *Metrics,
	logger *slog.Logger,
) {
	mux.Handle("/",
		forwardAuthMiddleware(sessions, metrics, logger)(
			ForwardAuthHandler(domains, oauthHandlers, states, logger.With("handler", "forwardAuth")),
		),
	)
	mux.Handle(OAUTHPath+"/logout",
		forwardAuthMiddleware(sessions, metrics, logger)(
			LogoutHandler(domains, sessions, logger.With("handler", "logout")),
		),
	)
	mux.Handle(OAUTHPath,
		withMetrics(metrics)(
			AuthCallbackHandler(
				domains,
				whitelist,
				oauthHandlers,
				states,
				sessions,
				logger.With("handler", "authCallback"),
			),
		),
	)
	mux.Handle("/health", HealthHandler(sessions, states, logger.With("handler", "health")))
}

func forwardAuthMiddleware(sessions sessions.Sessions, m *Metrics, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return sessionExtractor(sessions, logger.With("middleware", "sessionExtractor"))( // extract & validate the session cookie from the request
			withMetrics(m)( // measure request metrics
				next,
			),
		)
	}
}

func withMetrics(m *Metrics) func(next http.Handler) http.Handler {
	if m == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return middleware.WithRequestMetrics(m)
}
