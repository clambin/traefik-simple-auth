package oauth

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestGoogleHandler_GetUserEmailAddress(t *testing.T) {
	s := oauthServer{
		roundTrip: func(r *http.Request) (*http.Response, error) {
			var resp http.Response
			switch r.URL.Path {
			case "/token":
				resp.StatusCode = http.StatusOK
				resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"123456789"}`))
			case "/v1/userinfo":
				resp.StatusCode = http.StatusOK
				resp.Body = io.NopCloser(strings.NewReader(`{"email":"foo@example.com"}`))
			default:
				resp.StatusCode = http.StatusNotFound
				resp.Body = io.NopCloser(strings.NewReader(`{"path":"` + r.URL.Path + `"}`))
			}
			return &resp, nil
		},
	}

	ctx := context.TODO()
	h, _ := NewHandler(ctx, "google", "", "1234", "1234567", "https://auth.example.com/_oauth", slog.Default())
	h.(*GoogleHandler).HTTPClient = &http.Client{Transport: s}

	user, err := h.GetUserEmailAddress(ctx, "abcd1234")
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", user)
}

func TestGoogleHandler_userInfoEndpoint(t *testing.T) {
	resp, err := http.Get("https://accounts.google.com/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var response struct {
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	assert.Equal(t, googleUserURL, response.UserInfoEndpoint, "google userinfo endpoint has changed")
}
