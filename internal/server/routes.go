package server

import (
	"github.com/clambin/traefik-simple-auth/internal/server/handlers"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"log/slog"
	"net/http"
)

func addRoutes(
	mux *http.ServeMux,
	domains domains.Domains,
	whitelist whitelist.Whitelist,
	oauthHandlers map[domains.Domain]oauth.Handler,
	states *state.States[string],
	sessions *sessions.Sessions,
	metricsMiddleware func(http.Handler) http.Handler,
	logger *slog.Logger,
) {
	forwardAuthMiddleware := func(next http.Handler) http.Handler {
		return handlers.SessionExtractor(sessions, logger.With("middleware", "sessionExtractor"))( // extract & validate the session cookie from the request
			metricsMiddleware(next),
		)
	}
	mux.Handle("/", forwardAuthMiddleware(handlers.ForwardAuthHandler(domains, oauthHandlers, states, logger.With("handler", "forwardAuth"))))
	mux.Handle(OAUTHPath+"/logout", forwardAuthMiddleware(handlers.LogoutHandler(domains, sessions, logger.With("handler", "logout"))))
	mux.Handle(OAUTHPath, metricsMiddleware(handlers.AuthCallbackHandler(
		domains,
		whitelist,
		oauthHandlers,
		states,
		sessions,
		logger.With("handler", "authCallback"),
	)))
}
