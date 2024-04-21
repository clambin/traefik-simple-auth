package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHandler_AuthCodeURL(t *testing.T) {
	h, err := NewHandler("google", "CLIENT_ID", "CLIENT_SECRET", "auth", "localhost", "/_oauth")
	require.NoError(t, err)

	u, err := url.Parse(h.AuthCodeURL("state", oauth2.SetAuthURLParam("prompt", "select_profile")))
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "state", q.Get("state"))
	assert.Equal(t, "select_profile", q.Get("prompt"))
}

func TestHandler_GetUserEmailAddress(t *testing.T) {
	h, err := NewHandler("google", "1234", "1234567", "auth", "", "/_oauth")
	require.NoError(t, err)
	h.HTTPClient = &http.Client{Transport: oauthServer{}}
	h.Logger = slog.Default()

	user, err := h.GetUserEmailAddress("abcd1234")
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", user)
}

func TestHandler_userInfoEndpoint(t *testing.T) {
	resp, err := http.Get("https://accounts.google.com/.well-known/openid-configuration")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var response struct {
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	assert.Equal(t, userURLS["google"], response.UserInfoEndpoint, "google userinfo endpoint has changed")
}

var _ http.RoundTripper = &oauthServer{}

type oauthServer struct{}

func (o oauthServer) RoundTrip(r *http.Request) (*http.Response, error) {
	var resp http.Response
	switch r.URL.Path {
	case "/token":
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"123456789"}`))
	case "/v1/userinfo":
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader(`{"email":"foo@example.com"}`))
	default:
		fmt.Printf("Unsupported path: %v\n", r.URL.Path)
		resp.StatusCode = http.StatusNotFound
		resp.Body = io.NopCloser(strings.NewReader(`{"path":"` + r.URL.Path + `"}`))
	}
	return &resp, nil
}
