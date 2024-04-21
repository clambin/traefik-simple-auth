package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"io"
	"log/slog"
	"net/http"
)

type Handler struct {
	oauth2.Config
	HTTPClient *http.Client
	userURL    string

	Logger *slog.Logger
}

var userURLS = map[string]string{
	"google": "https://openidconnect.googleapis.com/v1/userinfo",
	"github": "https://api.github.com/user", // TODO
}

func NewHandler(provider, clientID, clientSecret, authPrefix, domain, oauthPath string) (*Handler, error) {
	switch provider {
	case "google":
		return newGoogleHandler(clientID, clientSecret, authPrefix, domain, oauthPath), nil
	case "github":
		return newGithubHandler(clientID, clientSecret, authPrefix, domain, oauthPath), nil
	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

func newGoogleHandler(clientID, clientSecret, authPrefix, domain, oauthPath string) *Handler {
	return &Handler{
		HTTPClient: http.DefaultClient,
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  makeAuthURL(authPrefix, domain, oauthPath),
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		},
		userURL: userURLS["google"],
	}
}

func newGithubHandler(clientID, clientSecret, authPrefix, domain, oauthPath string) *Handler {
	return &Handler{
		HTTPClient: http.DefaultClient,
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     github.Endpoint,
			RedirectURL:  makeAuthURL(authPrefix, domain, oauthPath),
			Scopes:       []string{"user.email"},
		},
		userURL: userURLS["github"],
	}
}

func (o Handler) GetUserEmailAddress(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := o.getAccessToken(code)
	if err == nil {
		return o.getUserEmailAddress(token)
	}
	return "", err
}

func (o Handler) getAccessToken(code string) (string, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, o.HTTPClient)
	var accessToken string
	token, err := o.Config.Exchange(ctx, code)
	if err == nil {
		accessToken = token.AccessToken
	}
	return accessToken, err
}

func (o Handler) getUserEmailAddress(token string) (string, error) {
	response, err := o.HTTPClient.Get(o.userURL + "?access_token=" + token)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(response.Body)
	o.Logger.Debug("getUserEmailAddress", "code", response.StatusCode, "body", string(body))

	var user struct {
		Email string `json:"email"`
	}
	err = json.Unmarshal(body, &user)
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
