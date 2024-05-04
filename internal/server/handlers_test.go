package server

import (
	"context"
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/internal/server/testutils"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestForwardAuthHandler(t *testing.T) {
	stateStore := state.New[string](time.Minute)
	logger := slog.Default()
	oauthHandler, _ := oauth.NewHandler(context.TODO(), "google", "", "123", "1234", "https://auth.example.com/_oauth", logger)

	h := ForwardAuthHandler(domains.Domains{".example.com"}, map[domains.Domain]oauth.Handler{".example.com": oauthHandler}, stateStore, logger)

	sessionStore := sessions.New("_auth", []byte("secret"), time.Hour)
	validSession := sessionStore.Session("foo@example.com")

	type args struct {
		target  string
		session *sessions.Session
	}
	tests := []struct {
		name string
		args args
		want int
		user string
	}{
		{
			name: "missing session",
			args: args{
				target: "https://example.com",
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid session",
			args: args{
				target:  "https://example.com",
				session: &validSession,
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "invalid domain",
			args: args{
				target:  "https://example.org",
				session: &validSession,
			},
			want: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, tt.args.target, nil)
			w := httptest.NewRecorder()
			if tt.args.session != nil {
				r = r.WithContext(context.WithValue(r.Context(), sessionKey, *tt.args.session))
			}

			h.ServeHTTP(w, r)
			require.Equal(t, tt.want, w.Code)

			switch w.Code {
			case http.StatusOK:
				assert.Equal(t, tt.user, w.Header().Get("X-Forwarded-User"))
			case http.StatusTemporaryRedirect:
				assert.NotEmpty(t, w.Header().Get("Location"))
			}
		})
	}
}

func TestLogoutHandler(t *testing.T) {
	sessionStore := sessions.New("_auth", []byte("secret"), time.Hour)
	h := LogoutHandler(
		domains.Domains{".example.com"},
		sessionStore,
		slog.Default(),
	)

	t.Run("logging out clears the session cookie", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "https://example.com/_oauth/logout", nil)
		session := sessionStore.Session("foo@example.com")
		r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "You have been logged out\n", w.Body.String())
		assert.Equal(t, "_auth=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

	})

	t.Run("must be logged in to log out", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "https://example.com/_oauth/logout", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Invalid session\n", w.Body.String())
	})
}

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
			h := AuthCallbackHandler(
				domains.Domains{".example.com"},
				map[string]struct{}{"foo@example.com": {}},
				map[domains.Domain]oauth.Handler{".example.com": &testutils.FakeOauthHandler{Email: tt.oauthUser, Err: tt.oauthErr}},
				store,
				sessions.New("_auth", []byte("secret"), time.Hour),
				slog.Default(),
			)

			oauthState := tt.state
			if tt.makeState {
				oauthState = store.Add("https://example.com/foo")
			}
			path := "/"
			if oauthState != "" {
				path += "?state=" + oauthState
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
