package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
)

type BaseHandler struct {
	oauth2.Config
	HTTPClient *http.Client
	userURL    string
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

var userURLS = map[string]string{
	"google": "https://openidconnect.googleapis.com/v1/userinfo",
	"github": "https://api.github.com/user", // TODO
}

type GoogleHandler struct {
	BaseHandler
}

func NewGoogleHandler(clientID, clientSecret, authPrefix, domain, oauthPath string) *GoogleHandler {
	return &GoogleHandler{
		BaseHandler: BaseHandler{
			HTTPClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     google.Endpoint,
				RedirectURL:  makeAuthURL(authPrefix, domain, oauthPath),
				Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			},
			userURL: userURLS["google"],
		},
	}
}

func (h GoogleHandler) GetUserEmailAddress(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := h.getAccessToken(code)
	if err != nil {
		return "", err
	}

	response, err := h.HTTPClient.Get(h.userURL + "?access_token=" + token)
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

type GitHubHandler struct {
	BaseHandler
}

func NewGitHubHandler(clientID, clientSecret, authPrefix, domain, oauthPath string) *GitHubHandler {
	return &GitHubHandler{
		BaseHandler: BaseHandler{
			HTTPClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     github.Endpoint,
				RedirectURL:  makeAuthURL(authPrefix, domain, oauthPath),
				Scopes:       []string{"user.email"},
			},
			userURL: userURLS["github"],
		},
	}
}

func (h GitHubHandler) GetUserEmailAddress(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := h.getAccessToken(code)
	if err != nil {
		return "", err
	}

	req, _ := http.NewRequest(http.MethodGet, h.userURL, nil)
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

// makeAuthURL returns the auth URL for a given domain
func makeAuthURL(authPrefix, domain, OAUTHPath string) string {
	var dot string
	if domain != "" && domain[0] != '.' {
		dot = "."
	}
	return "https://" + authPrefix + dot + domain + OAUTHPath
}
