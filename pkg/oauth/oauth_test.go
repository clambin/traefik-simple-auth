package oauth

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
)

func TestNewHandler(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "google",
			provider: "google",
			wantErr:  assert.NoError,
		},
		{
			name:     "github",
			provider: "github",
			wantErr:  assert.NoError,
		},
		{
			name:     "invalid",
			provider: "invalid",
			wantErr:  assert.Error,
		},
	}

	ctx := context.TODO()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewHandler(ctx, tt.provider, "CLIENT_ID", "CLIENT_SECRET", "https://auth.example.com/_oauth", slog.Default())
			tt.wantErr(t, err)
		})
	}
}

func TestHandler_AuthCodeURL(t *testing.T) {
	h, _ := NewHandler(context.TODO(), "google", "CLIENT_ID", "CLIENT_SECRET", "https://auth.example.com/_oauth", slog.Default())

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
