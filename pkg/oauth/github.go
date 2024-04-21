package oauth

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"log/slog"
	"net/http"
)

type GitHubHandler struct {
	BaseHandler
}

func NewGitHubHandler(clientID, clientSecret, authURL string, logger *slog.Logger) *GitHubHandler {
	return &GitHubHandler{
		BaseHandler: BaseHandler{
			HTTPClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     github.Endpoint,
				RedirectURL:  authURL,
				Scopes:       []string{"user:email", "read:user"},
			},
			Logger: logger,
		},
	}
}

func (h GitHubHandler) GetUserEmailAddress(code string) (string, error) {
	// Use code to get token and get user info from GitHub
	token, err := h.getAccessToken(code)
	if err != nil {
		return "", err
	}

	email, err := h.getAddress(token)
	if email != "" && err == nil {
		return email, nil
	}
	h.Logger.Debug("No email address found. Using user public profile instead", "err", err)
	return h.getAddressFromProfile(token)
}

func (h GitHubHandler) getAddress(token *oauth2.Token) (string, error) {
	resp, err := h.do("https://api.github.com/user/emails", token)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var users []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return "", err
	}

	if len(users) == 0 {
		return "", fmt.Errorf("no email addresses found")
	}

	for _, user := range users {
		if user.Primary {
			return user.Email, nil
		}
	}
	// fallback in case no primary email: return the first one
	h.Logger.Warn("No primary email address found. Defaulting to first email address instead.", "email", users[0].Email)
	return users[0].Email, nil
}

func (h GitHubHandler) getAddressFromProfile(token *oauth2.Token) (string, error) {
	resp, err := h.do("https://api.github.com/user", token)
	defer func() { _ = resp.Body.Close() }()

	var user struct {
		Email string `json:"email"`
	}

	err = json.NewDecoder(resp.Body).Decode(&user)
	return user.Email, err
}

func (h GitHubHandler) do(url string, token *oauth2.Token) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	token.SetAuthHeader(req)
	req.Header.Set("Accept", "application/vnd.github+json")

	return h.HTTPClient.Do(req)
}
