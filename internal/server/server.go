package server

import (
	"context"
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
func New(ctx context.Context, authenticator *auth.Authenticator, states state.States, config configuration.Configuration, metrics *Metrics, logger *slog.Logger) http.Handler {
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
	addServerRoutes(r,
		config.Domain,
		config.Whitelist,
		oauthHandler,
		states,
		authenticator,
		metrics,
		logger,
	)
	return r
}
