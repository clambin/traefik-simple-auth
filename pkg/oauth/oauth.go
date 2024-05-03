// Package oauth implements handlers for traefik-simple-auth to authenticate a user.  It implements the oauth2 handshake,
// as well as a means to get the email address of the authenticated users.
//
// Currently, Google and GitHub are supported as oauth2 providers.
package oauth

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
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
func NewHandler(ctx context.Context, provider, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	switch provider {
	case "google":
		return NewGoogleHandler(ctx, clientID, clientSecret, authURL, logger), nil
	case "github":
		return NewGitHubHandler(ctx, clientID, clientSecret, authURL, logger), nil
	case "google2":
		return NewOIDCHandler(ctx, "google", clientID, clientSecret, authURL, logger)
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

type OIDCHandler struct {
	oauth2.Config
	Logger *slog.Logger
	*oidc.Provider
}

var oidcProviders = map[string]string{
	"google": "https://accounts.google.com",
}

func NewOIDCHandler(ctx context.Context, provider, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	oidcProviderURL, ok := oidcProviders[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
	oidcProvider, err := oidc.NewProvider(ctx, oidcProviderURL)
	if err != nil {
		return nil, fmt.Errorf("could not create OIDC provider: %w", err)
	}
	return &OIDCHandler{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     oidcProvider.Endpoint(),
			RedirectURL:  authURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		Logger:   logger,
		Provider: oidcProvider,
	}, nil
}

func (h *OIDCHandler) GetUserEmailAddress(ctx context.Context, code string) (string, error) {
	oauth2Token, err := h.Config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("could not get access token: %w", err)
	}

	h.Logger.Debug("exchanged access token", "token", oauth2Token.AccessToken)

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token field in oauth2 token")
	}

	h.Logger.Debug("extracted access token id_token", "id", rawIDToken)

	// Parse and verify ID Token payload.
	verifier := h.Provider.Verifier(&oidc.Config{ClientID: h.Config.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("could not verify ID token: %w", err)
	}

	h.Logger.Debug("verified ID token", "token", idToken)

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err = idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("could not parse ID token claims: %w", err)
	}
	if !claims.Verified {
		return "", fmt.Errorf("email address not verified: %s", claims.Email)
	}

	return claims.Email, nil
}
