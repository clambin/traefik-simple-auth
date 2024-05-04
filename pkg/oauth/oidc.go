package oauth

import (
	"context"
	"errors"
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

func NewOIDCHandler(ctx context.Context, oidcIssuerURL, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	if oidcIssuerURL == "" {
		return nil, errors.New("oidcIssuerURL cannot be empty")
	}
	oidcProvider, err := oidc.NewProvider(ctx, oidcIssuerURL)
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

	userInfo, err := h.Provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		return "", fmt.Errorf("could not get user info: %w", err)
	}
	return userInfo.Email, nil
}
