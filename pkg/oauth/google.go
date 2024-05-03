package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log/slog"
	"net/http"
)

var _ Handler = &GoogleHandler{}

// GoogleHandler performs the OAuth handshake using Google as authenticator and gets the email address for the authenticated user.
type GoogleHandler struct {
	BaseHandler
}

// NewGoogleHandler returns a new Handler for Google.
func NewGoogleHandler(_ context.Context, clientID, clientSecret, authURL string, logger *slog.Logger) *GoogleHandler {
	return &GoogleHandler{
		BaseHandler: BaseHandler{
			HTTPClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     google.Endpoint,
				RedirectURL:  authURL,
				Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			},
			Logger: logger,
		},
	}
}

const googleUserURL = "https://openidconnect.googleapis.com/v1/userinfo"

// GetUserEmailAddress returns the email address of the authenticated user.
func (h GoogleHandler) GetUserEmailAddress(ctx context.Context, code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := h.getAccessToken(ctx, code)
	if err != nil {
		return "", err
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, googleUserURL, nil)
	token.SetAuthHeader(req)

	response, err := h.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	var user struct {
		Email string `json:"email"`
	}
	err = json.NewDecoder(response.Body).Decode(&user)
	return user.Email, err
}
