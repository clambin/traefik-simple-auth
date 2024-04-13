package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
)

type Handler struct {
	oauth2.Config
	HTTPClient *http.Client
}

func (o Handler) Login(code string) (string, error) {
	// Use code to get token and get user info from Google.
	token, err := o.getAccessToken(code)
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

func (o Handler) getAccessToken(code string) (string, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, o.HTTPClient)
	token, err := o.Config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	return token.AccessToken, err
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
