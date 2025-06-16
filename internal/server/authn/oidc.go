package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCHandler struct {
	oauth2.Config
	logger   *slog.Logger
	provider *oidc.Provider
}

func NewOIDCHandler(ctx context.Context, oidcIssuerURL, clientID, clientSecret, authURL string, logger *slog.Logger) (Handler, error) {
	if oidcIssuerURL == "" {
		return nil, errors.New("oidcIssuerURL cannot be empty")
	}
	oidcProvider, err := oidc.NewProvider(ctx, oidcIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("could not create Auth provider: %w", err)
	}
	return &OIDCHandler{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     oidcProvider.Endpoint(),
			RedirectURL:  authURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		logger:   logger,
		provider: oidcProvider,
	}, nil
}

func (h *OIDCHandler) GetUserEmailAddress(ctx context.Context, code string) (string, error) {
	oauth2Token, err := h.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("could not get access token: %w", err)
	}

	userInfo, err := h.provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		return "", fmt.Errorf("could not get user info: %w", err)
	}
	return userInfo.Email, nil
}
