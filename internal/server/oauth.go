package server

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
)

type oauthHandler struct {
	oauth2.Config
	httpClient *http.Client
}

func (o oauthHandler) login(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := o.getToken(o.Config.RedirectURL, code)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}

	email, err := o.getEmailFromToken(token)
	if err != nil {
		return "", fmt.Errorf("email address: %w", err)
	}
	return email, nil
}

func (o oauthHandler) getEmailFromToken(token string) (string, error) {
	// TODO:
	response, err := o.httpClient.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token)
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
func (o oauthHandler) getToken(redirectURI string, code string) (string, error) {
	form := url.Values{
		"client_id":     {o.Config.ClientID},
		"client_secret": {o.Config.ClientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
		"code":          {code},
	}

	resp, err := o.httpClient.PostForm(o.Config.Endpoint.TokenURL, form)
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
