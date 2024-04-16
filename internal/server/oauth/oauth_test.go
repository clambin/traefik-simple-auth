package oauth

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHandler_AuthCodeURL(t *testing.T) {
	o := Handler{
		Config: oauth2.Config{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			Endpoint:     google.Endpoint,
			RedirectURL:  "http://localhost",
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		},
	}

	u, err := url.Parse(o.AuthCodeURL("state", oauth2.SetAuthURLParam("prompt", "select_profile")))
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "state", q.Get("state"))
	assert.Equal(t, "select_profile", q.Get("prompt"))
}

func TestHandler_GetUserEmailAddress(t *testing.T) {
	s := oauthServer{}
	o := Handler{
		HTTPClient: &http.Client{Transport: s},
		Config: oauth2.Config{
			ClientID:     "1234",
			ClientSecret: "1234567",
			Endpoint:     google.Endpoint,
			RedirectURL:  "/",
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		},
	}

	user, err := o.GetUserEmailAddress("abcd1234")
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", user)
}

var _ http.RoundTripper = &oauthServer{}

type oauthServer struct{}

func (o oauthServer) RoundTrip(r *http.Request) (*http.Response, error) {
	var resp http.Response
	switch r.URL.Path {
	case "/token":
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"123456789"}`))
	case "/oauth2/v2/userinfo":
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader(`{"email":"foo@example.com"}`))
	default:
		fmt.Printf("Unsupported path: %v\n", r.URL.Path)
		resp.StatusCode = http.StatusNotFound
		resp.Body = io.NopCloser(strings.NewReader(`{"path":"` + r.URL.Path + `"}`))
	}
	return &resp, nil
}
