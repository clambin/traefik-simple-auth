package oauth

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestGitHubHandler_GetUserEmailAddress(t *testing.T) {
	s := oauthServer{
		roundTrip: func(r *http.Request) (*http.Response, error) {
			var resp http.Response
			switch r.URL.Path {
			case "/login/oauth/access_token":
				resp.StatusCode = http.StatusOK
				resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"123456789"}`))
			case "/user":
				resp.StatusCode = http.StatusOK
				resp.Body = io.NopCloser(strings.NewReader(`{"email":"foo@example.com"}`))
			default:
				resp.StatusCode = http.StatusNotFound
				resp.Body = io.NopCloser(strings.NewReader(`{"path":"` + r.URL.Path + `"}`))
			}
			return &resp, nil
		},
	}

	h, _ := NewHandler("github", "1234", "1234567", "https://auth.example.com/_oauth")
	h.(*GitHubHandler).HTTPClient = &http.Client{Transport: s}

	user, err := h.GetUserEmailAddress("abcd1234")
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", user)
}

/*
func TestGitHubHandler_GetUserEmailAddress_NoPrimary(t *testing.T) {
	s := oauthServer{
		roundTrip: func(r *http.Request) (*http.Response, error) {
			var resp http.Response
			switch r.URL.Path {
			case "/login/oauth/access_token":
				resp.StatusCode = http.StatusOK
				resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"123456789"}`))
			case "/user/emails":
				resp.StatusCode = http.StatusOK
				resp.Body = io.NopCloser(strings.NewReader(`[ {"email":"foo@example.com", "primary":false} ]`))
			default:
				resp.StatusCode = http.StatusNotFound
				resp.Body = io.NopCloser(strings.NewReader(`{"path":"` + r.URL.Path + `"}`))
			}
			return &resp, nil
		},
	}

	h, _ := NewHandler("github", "1234", "1234567", "https://auth.example.com/_oauth")
	h.(*GitHubHandler).HTTPClient = &http.Client{Transport: s}

	user, err := h.GetUserEmailAddress("abcd1234")
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", user)
}


*/
