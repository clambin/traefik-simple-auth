package server

import (
	"context"
	"github.com/clambin/go-common/httputils/metrics"
	"github.com/clambin/go-common/httputils/middleware"
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"log/slog"
	"net/http"
)

const OAUTHPath = "/_oauth"

// New returns a new http.Handler that handles traefik's forward-auth requests, and the associated oauth flow.
// It panics if config.Provider is invalid.
func New(ctx context.Context, authenticator *auth.Authenticator, states state.States, config configuration.Configuration, metrics metrics.RequestMetrics, logger *slog.Logger) http.Handler {
	logger = logger.With("provider", config.Provider)
	oauthHandler, err := oauth.NewHandler(
		ctx,
		config.Provider,
		config.OIDCIssuerURL,
		config.ClientID,
		config.ClientSecret,
		"https://"+config.AuthPrefix+string(config.Domain)+OAUTHPath,
		logger.With("domain", string(config.Domain)),
	)
	if err != nil {
		panic("invalid provider: " + config.Provider + ", err: " + err.Error())
	}

	// create the server router
	r := http.NewServeMux()
	addServerRoutes(
		r,
		authenticator,
		authorizer{Whitelist: config.Whitelist, Domain: config.Domain},
		oauthHandler,
		states,
		metrics,
		logger,
	)
	return r
}

func addServerRoutes(
	mux *http.ServeMux,
	authenticator *auth.Authenticator,
	authorizer authorizer,
	oauthHandler oauth.Handler,
	states state.States,
	metrics metrics.RequestMetrics,
	logger *slog.Logger,
) {
	// sub-router for forwardAuthHandler & logoutHandler
	mux2 := http.NewServeMux()
	mux2.Handle("/", forwardAuthHandler(authorizer, oauthHandler, states, logger.With("handler", "forwardAuth")))
	mux2.Handle(OAUTHPath+"/logout", logoutHandler(authenticator, authorizer, logger.With("handler", "logout")))

	mux.Handle("/", authenticate(authenticator)( // validate the JWT cookie and store it in the request context
		withMetrics(metrics)( // record request metrics
			forwardAuthParser( // restore the original request
				mux2, // handle forwardAuth or logout
			),
		),
	))
	mux.Handle(OAUTHPath,
		// oAuth2CallbackHandler is called by the OAuth2 provider, so will not have a JWT cookie
		withMetrics(metrics)( // record request metrics
			oAuth2CallbackHandler(authenticator, authorizer, oauthHandler, states, logger.With("handler", "authCallback")),
		),
	)
	mux.Handle("/health", healthHandler(states, logger.With("handler", "health")))
}

func withMetrics(m metrics.RequestMetrics) func(next http.Handler) http.Handler {
	if m == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return middleware.WithRequestMetrics(m)
}
