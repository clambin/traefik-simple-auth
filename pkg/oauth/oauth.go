package oauth

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
)

type Handler interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	GetUserEmailAddress(code string) (string, error)
}

func NewHandler(provider, clientID, clientSecret, authURL string) (Handler, error) {
	switch provider {
	case "google":
		return NewGoogleHandler(clientID, clientSecret, authURL), nil
	case "github":
		return NewGitHubHandler(clientID, clientSecret, authURL), nil
	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

type BaseHandler struct {
	oauth2.Config
	HTTPClient *http.Client
}

func (h BaseHandler) getAccessToken(code string) (string, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, h.HTTPClient)
	var accessToken string
	token, err := h.Config.Exchange(ctx, code)
	if err == nil {
		accessToken = token.AccessToken
	}
	return accessToken, err
}
