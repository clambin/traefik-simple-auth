package oauth

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
)

func TestHandler_AuthCodeURL(t *testing.T) {
	h, _ := NewHandler("google", "CLIENT_ID", "CLIENT_SECRET", "https://auth/example.com/_oauth", slog.Default())

	u, err := url.Parse(h.AuthCodeURL("state", oauth2.SetAuthURLParam("prompt", "select_profile")))
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "state", q.Get("state"))
	assert.Equal(t, "select_profile", q.Get("prompt"))
}

var _ http.RoundTripper = &oauthServer{}

type oauthServer struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (o oauthServer) RoundTrip(r *http.Request) (*http.Response, error) {
	return o.roundTrip(r)
}
