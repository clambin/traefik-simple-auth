package oauth

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log/slog"
	"net/http"
)

type GoogleHandler struct {
	BaseHandler
}

func NewGoogleHandler(clientID, clientSecret, authURL string, logger *slog.Logger) *GoogleHandler {
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

func (h GoogleHandler) GetUserEmailAddress(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := h.getAccessToken(code)
	if err != nil {
		return "", err
	}

	req, _ := http.NewRequest(http.MethodGet, googleUserURL, nil)
	token.SetAuthHeader(req)

	response, err := h.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer func() { _ = response.Body.Close() }()

	var user struct {
		Email string `json:"email"`
	}
	err = json.NewDecoder(response.Body).Decode(&user)
	return user.Email, err
}
