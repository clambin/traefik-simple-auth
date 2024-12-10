package server

import (
	"github.com/clambin/go-common/httputils/middleware"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"log/slog"
	"net/http"
)

func addServerRoutes(
	mux *http.ServeMux,
	forwardAuthHandler http.Handler,
	domains domains.Domains,
	whitelist whitelist.Whitelist,
	oauthHandlers map[domains.Domain]oauth.Handler,
	states state.States,
	sessions sessions.Sessions,
	metrics *Metrics,
	logger *slog.Logger,
) {
	mux.Handle("/", forwardAuthHandler)
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

func withMetrics(m *Metrics) func(next http.Handler) http.Handler {
	if m == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return middleware.WithRequestMetrics(m)
}
