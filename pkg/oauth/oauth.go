// Package oauth implements handlers for traefik-simple-auth to authenticate a user.  It implements the oauth2 handshake,
// as well as a means to get the email address of the authenticated users.
//
// Currently, Google and GitHub are supported as oauth2 providers.
package oauth

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
)

// A Handler performs the OAuth handshake and get the email address for the authenticated user.
type Handler interface {
	// AuthCodeURL generates the URL to use in the oauth2 handshake.
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	// GetUserEmailAddress returns the email address of the authenticated user.
	GetUserEmailAddress(ctx context.Context, code string) (string, error)
}

// NewHandler returns a new Handler for the selected provider. Currently, Google and GitHub are supported.
func NewHandler(ctx context.Context, provider, oidcServiceURL, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	switch provider {
	// TODO: make this a OIDCHandler. ServiceURL "https://accounts.google.com"
	case "google":
		return NewGoogleHandler(ctx, clientID, clientSecret, authURL, logger), nil
	case "github":
		return NewGitHubHandler(ctx, clientID, clientSecret, authURL, logger), nil
	case "oidc":
		return NewOIDCHandler(ctx, oidcServiceURL, clientID, clientSecret, authURL, logger)
	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

// BaseHandler implements the generic part of a Handler.
type BaseHandler struct {
	oauth2.Config
	HTTPClient *http.Client
	Logger     *slog.Logger
}

func (h BaseHandler) getAccessToken(ctx context.Context, code string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, h.HTTPClient)
	return h.Config.Exchange(ctx, code)
}
