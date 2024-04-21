package oauth

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
)

type Handler interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	GetUserEmailAddress(code string) (string, error)
}

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

type BaseHandler struct {
	oauth2.Config
	HTTPClient *http.Client
	Logger     *slog.Logger
}

func (h BaseHandler) getAccessToken(code string) (*oauth2.Token, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, h.HTTPClient)
	return h.Config.Exchange(ctx, code)
}
