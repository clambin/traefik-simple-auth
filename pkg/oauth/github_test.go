package oauth

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestGitHubHandler_GetUserEmailAddress(t *testing.T) {
	tests := []struct {
		name          string
		emailResponse string
		userResponse  string
	}{
		{
			name:          "primary email",
			emailResponse: `[ {"email":"bar@example.com","primary":false}, {"email":"foo@example.com","primary":true} ]`,
		},
		{
			name:          "no primary email",
			emailResponse: `[ {"email":"foo@example.com","primary":false}, {"email":"bar@example.com","primary":false} ]`,
		},
		{
			name:          "no emails",
			emailResponse: `[  ]`,
			userResponse:  `{"email":"foo@example.com"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := oauthServer{
				roundTrip: func(r *http.Request) (*http.Response, error) {
					var resp http.Response
					switch r.URL.Path {
					case "/login/oauth/access_token":
						resp.StatusCode = http.StatusOK
						resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"123456789"}`))
					case "/user/emails":
						resp.StatusCode = http.StatusOK
						resp.Body = io.NopCloser(strings.NewReader(tt.emailResponse))
					case "/user":
						resp.StatusCode = http.StatusOK
						resp.Body = io.NopCloser(strings.NewReader(tt.userResponse))
					default:
						resp.StatusCode = http.StatusNotFound
						resp.Body = io.NopCloser(strings.NewReader(`{"path":"` + r.URL.Path + `"}`))
					}
					return &resp, nil
				},
			}

			ctx := context.Background()
			h, _ := NewHandler(ctx, "github", "1234", "1234567", "https://auth.example.com/_oauth", slog.Default())
			h.(*GitHubHandler).HTTPClient = &http.Client{Transport: s}

			user, err := h.GetUserEmailAddress(ctx, "abcd1234")
			require.NoError(t, err)
			assert.Equal(t, "foo@example.com", user)

		})
	}
}
