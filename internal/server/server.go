package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/clambin/go-common/httputils/metrics"
	"github.com/clambin/go-common/httputils/middleware"
	"github.com/clambin/traefik-simple-auth/internal/server/authn"
	"github.com/clambin/traefik-simple-auth/internal/server/csrf"
)

const OAUTHPath = "/_oauth"

type Server struct {
	http.Handler
	authenticator  *authenticator
	csrfStateStore csrf.StateStore
}

// New returns a new Server that handles traefik's forward-auth requests, and the associated authn flow.
// It panics if config.Provider is invalid.
func New(ctx context.Context, config Configuration, metrics metrics.RequestMetrics, logger *slog.Logger) Server {
	logger = logger.With("provider", config.AuthConfiguration.Provider)
	oauthHandler, err := authn.NewHandler(
		ctx,
		config.AuthConfiguration.Provider,
		config.AuthConfiguration.IssuerURL,
		config.AuthConfiguration.ClientID,
		config.AuthConfiguration.ClientSecret,
		"https://"+config.AuthConfiguration.AuthPrefix+string(config.Domain)+OAUTHPath,
		logger.With("domain", string(config.Domain)),
	)
	if err != nil {
		panic("invalid provider: " + config.AuthConfiguration.Provider + ", err: " + err.Error())
	}

	auth := newAuthenticator(config.SessionConfiguration.CookieName, string(config.Domain), config.Secret, config.SessionConfiguration.Expiration)
	states := csrf.New(config.CSRF)

	// create the server router
	r := http.NewServeMux()
	addServerRoutes(
		r,
		auth,
		authorizer{whitelist: config.Whitelist, domain: config.Domain},
		oauthHandler,
		states,
		metrics,
		logger,
	)
	return Server{Handler: r, authenticator: auth, csrfStateStore: states}
}

func addServerRoutes(
	mux *http.ServeMux,
	authenticator *authenticator,
	authorizer authorizer,
	oauthHandler authn.Handler,
	states csrf.StateStore,
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
