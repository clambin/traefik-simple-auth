package server

import (
	"github.com/clambin/go-common/httputils/middleware"
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"log/slog"
	"net/http"
)

func addServerRoutes(
	mux *http.ServeMux,
	authenticator *auth.Authenticator,
	authorizer authorizer,
	oauthHandler oauth.Handler,
	states state.States,
	metrics *Metrics,
	logger *slog.Logger,
) {
	// sub-router for forwardAuth & logout handlers
	mux2 := http.NewServeMux()
	mux2.Handle("/", ForwardAuthHandler(authorizer, oauthHandler, states, logger.With("handler", "forwardAuth")))
	mux2.Handle(OAUTHPath+"/logout", LogoutHandler(authenticator, authorizer, logger.With("handler", "logout")))

	mux.Handle("/", authExtractor(authenticator)( // validate the JWT cookie and store it in the request context
		withMetrics(metrics)( // record request metrics
			traefikForwardAuthParser( // restore the original request
				mux2, // handle forwardAuth or logout
			),
		),
	))
	mux.Handle(OAUTHPath,
		withMetrics(metrics)(
			AuthCallbackHandler(authenticator, authorizer, oauthHandler, states, logger.With("handler", "authCallback")),
		),
	)
	mux.Handle("/health", HealthHandler(states, logger.With("handler", "health")))
}

func withMetrics(m *Metrics) func(next http.Handler) http.Handler {
	if m == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return middleware.WithRequestMetrics(m)
}
