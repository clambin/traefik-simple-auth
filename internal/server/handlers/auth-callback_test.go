package handlers

import (
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/internal/server/testutils"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthCallbackHandler(t *testing.T) {
	tests := []struct {
		name      string
		state     string
		makeState bool
		oauthUser string
		oauthErr  error
		wantCode  int
	}{
		{
			name:     "missing state parameter",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid state parameter",
			state:    "1234",
			wantCode: http.StatusBadRequest,
		},
		{
			name:      "valid state parameter",
			makeState: true,
			oauthUser: "foo@example.com",
			wantCode:  http.StatusTemporaryRedirect,
		},
		{
			name:      "login failed",
			makeState: true,
			oauthErr:  errors.New("something went wrong"),
			wantCode:  http.StatusBadGateway,
		},
		{
			name:      "invalid user",
			makeState: true,
			oauthUser: "bar@example.com",
			wantCode:  http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := state.New[string](time.Minute)
			h := AuthCallbackHandler{
				Logger:        slog.Default(),
				States:        &store,
				Domains:       domains.Domains{".example.com"},
				OAuthHandlers: map[domains.Domain]oauth.Handler{".example.com": &testutils.FakeOauthHandler{Email: tt.oauthUser, Err: tt.oauthErr}},
				Whitelist:     map[string]struct{}{"foo@example.com": {}},
				Sessions:      sessions.New("_auth", []byte("secret"), time.Hour),
			}

			state := tt.state
			if tt.makeState {
				state = h.States.Add("https://example.com/foo")
			}
			path := "/"
			if state != "" {
				path += "?state=" + state
			}

			r, _ := http.NewRequest(http.MethodGet, "https://example.com"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(t, tt.wantCode, w.Code)

			if w.Code == http.StatusTemporaryRedirect {
				assert.Equal(t, "https://example.com/foo", w.Header().Get("Location"))
			}
		})
	}
}
