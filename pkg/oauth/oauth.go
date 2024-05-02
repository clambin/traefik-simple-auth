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
	GetUserEmailAddress(code string) (string, error)
}

// NewHandler returns a new Handler for the selected provider. Currently, Google and GitHub are supported.
func NewHandler(provider, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	switch provider {
	case "google":
		return NewGoogleHandler(clientID, clientSecret, authURL, logger), nil
	case "github":
		return NewGitHubHandler(clientID, clientSecret, authURL, logger), nil
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

func (h BaseHandler) getAccessToken(code string) (*oauth2.Token, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, h.HTTPClient)
	return h.Config.Exchange(ctx, code)
}
