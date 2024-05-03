package oauth

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"log/slog"
)

type OIDCHandler struct {
	oauth2.Config
	Logger *slog.Logger
	*oidc.Provider
}

func NewOIDCHandler(ctx context.Context, oidcServiceURL, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	oidcProvider, err := oidc.NewProvider(ctx, oidcServiceURL)
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
