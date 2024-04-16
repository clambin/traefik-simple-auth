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

func (o Handler) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return o.Config.AuthCodeURL(state, opts...)
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

const userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

func (o Handler) getUserEmailAddress(token string) (string, error) {
	response, err := o.HTTPClient.Get(userInfoURL + "?access_token=" + token)
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
