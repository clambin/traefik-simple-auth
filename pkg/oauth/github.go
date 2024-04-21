package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io"
	"net/http"
)

type GitHubHandler struct {
	BaseHandler
}

func NewGitHubHandler(clientID, clientSecret, authURL string) *GitHubHandler {
	return &GitHubHandler{
		BaseHandler: BaseHandler{
			HTTPClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     github.Endpoint,
				RedirectURL:  authURL,
				Scopes:       []string{"user.email", "emails:read"},
			},
		},
	}
}

func (h GitHubHandler) GetUserEmailAddress(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := h.getAccessToken(code)
	if err != nil {
		return "", err
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed getting user info: %s", resp.Status)
	}

	var user struct {
		Email string `json:"email"`
	}
	var body bytes.Buffer
	err = json.NewDecoder(io.TeeReader(resp.Body, &body)).Decode(&user)
	if err == nil && user.Email == "" {
		return "", fmt.Errorf("failed to parse body: %s", body.String())
	}
	return user.Email, err
}
