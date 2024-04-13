package oauth

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
)

type Handler struct {
	oauth2.Config
	HTTPClient *http.Client
}

func (o Handler) Login(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := o.getAccessToken(o.Config.RedirectURL, code)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}

	email, err := o.getUserEmailAddress(token)
	if err != nil {
		return "", fmt.Errorf("email address: %w", err)
	}
	return email, nil
}

func (o Handler) AuthCodeURL(state string) string {
	return o.Config.AuthCodeURL(state)

}

func (o Handler) getAccessToken(redirectURI string, code string) (string, error) {
	form := url.Values{
		"client_id":     {o.Config.ClientID},
		"client_secret": {o.Config.ClientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
		"code":          {code},
	}

	resp, err := o.HTTPClient.PostForm(o.Config.Endpoint.TokenURL, form)
	if err != nil {
		return "", fmt.Errorf("error getting token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var token struct {
		Token string `json:"access_token"`
	}

	err = json.NewDecoder(resp.Body).Decode(&token)
	return token.Token, err
}

func (o Handler) getUserEmailAddress(token string) (string, error) {
	response, err := o.HTTPClient.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token)
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
