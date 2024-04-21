package oauth

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
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
	// Use code to get token and get user info from GitHub
	token, err := h.getAccessToken(code)
	if err != nil {
		return "", err
	}

	// FIXME: should use the /user/email API but currently giving 404???

	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	token.SetAuthHeader(req)

	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	var user struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed to get user info: decode: %w", err)
	}
	return user.Email, nil

	/*
		if len(users) == 0 {
			return "", fmt.Errorf("failed to get user info: no user email address")
		}
		for _, user := range users {
			if user.Primary {
				return user.Email, nil
			}
		}
		// fallback in case no primary email: return the first one
		return users[0].Email, nil
	*/
}
