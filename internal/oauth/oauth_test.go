package oauth

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestNewHandler(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		serviceURL string
		wantErr    assert.ErrorAssertionFunc
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
			name:       "oidc",
			provider:   "oidc",
			serviceURL: "https://accounts.google.com",
			wantErr:    assert.NoError,
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
			_, err := NewHandler(ctx, tt.provider, tt.serviceURL, "CLIENT_ID", "CLIENT_SECRET", "https://auth.example.com/_oauth", testutils.DiscardLogger)
			tt.wantErr(t, err)
		})
	}
}

var _ http.RoundTripper = &oauthServer{}

type oauthServer struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (o oauthServer) RoundTrip(r *http.Request) (*http.Response, error) {
	return o.roundTrip(r)
}
