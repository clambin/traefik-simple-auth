package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var _ Handler = &GitHubHandler{}

// GitHubHandler performs the OAuth handshake using GitHub as authenticator and gets the email address for the authenticated user.
type GitHubHandler struct {
	BaseHandler
}

// NewGitHubHandler returns a new Handler for GitHub.
func NewGitHubHandler(_ context.Context, clientID, clientSecret, authURL string, logger *slog.Logger) *GitHubHandler {
	return &GitHubHandler{
		BaseHandler: BaseHandler{
			httpClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     github.Endpoint,
				RedirectURL:  authURL,
				Scopes:       []string{"user:email", "read:user"},
			},
			logger: logger,
		},
	}
}

// GetUserEmailAddress returns the email address of the authenticated user.
//
// For GitHub, we first check the user's profile.  If the user's email address is marked as public, that email address is returned.
// Otherwise, we check the different email addresses for that user. If one is marked as primary, that email address is returned.
// Otherwise, we return the first email address in the list.
func (h GitHubHandler) GetUserEmailAddress(ctx context.Context, code string) (string, error) {
	// Use code to get token and get user info from GitHub
	token, err := h.getAccessToken(ctx, code)
	if err != nil {
		return "", err
	}

	email, err := h.getAddress(ctx, token)
	if email != "" && err == nil {
		return email, nil
	}
	h.logger.Debug("No email address found. Using user public profile instead", "err", err)
	// this should normally not be needed (and only works if the user made their address public).
	return h.getAddressFromProfile(ctx, token)
}

func (h GitHubHandler) getAddress(ctx context.Context, token *oauth2.Token) (string, error) {
	resp, err := h.do(ctx, "https://api.github.com/user/emails", token)
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
	h.logger.Warn("No primary email address found. Defaulting to first email address instead.", "email", users[0].Email)
	return users[0].Email, nil
}

func (h GitHubHandler) getAddressFromProfile(ctx context.Context, token *oauth2.Token) (string, error) {
	resp, err := h.do(ctx, "https://api.github.com/user", token)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var user struct {
		Email string `json:"email"`
	}

	err = json.NewDecoder(resp.Body).Decode(&user)
	return user.Email, err
}

func (h GitHubHandler) do(ctx context.Context, url string, token *oauth2.Token) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	token.SetAuthHeader(req)
	req.Header.Set("Accept", "application/vnd.github+json")

	return h.httpClient.Do(req)
}
