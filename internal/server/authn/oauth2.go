// Package authn implements handlers for traefik-simple-auth to authenticate a user. It implements the authn handshake,
// as well as a means to get the email address of the authenticated users.
//
// Currently, Google and GitHub are supported as authn providers.
//
// Additionally, it implements a means of protecting the OAuth2 flow against CSRF attacks by associating each login request
// with a randomly generated state.
package authn

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

// A Handler performs the OAuth handshake and get the email address for the authenticated user.
type Handler interface {
	// AuthCodeURL generates the URL to use in the authn handshake.
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	// GetUserEmailAddress returns the email address of the authenticated user.
	GetUserEmailAddress(ctx context.Context, code string) (string, error)
}

// NewHandler returns a new Handler for the selected provider. Currently, Google and GitHub are supported.
func NewHandler(ctx context.Context, provider, oidcServiceURL, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	switch provider {
	case "github":
		return NewGitHubHandler(ctx, clientID, clientSecret, authURL, logger), nil
	case "google":
		return NewOIDCHandler(ctx, "https://accounts.google.com", clientID, clientSecret, authURL, logger)
	case "oidc":
		return NewOIDCHandler(ctx, oidcServiceURL, clientID, clientSecret, authURL, logger)
	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

// BaseHandler implements the generic part of a Handler.
type BaseHandler struct {
	oauth2.Config
	httpClient *http.Client
	logger     *slog.Logger
}

func (h BaseHandler) getAccessToken(ctx context.Context, code string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, h.httpClient)
	return h.Exchange(ctx, code)
}
