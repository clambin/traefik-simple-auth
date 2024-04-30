package handlers

import (
	"context"
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

func TestServer_Authenticate(t *testing.T) {
	store := state.New[string](time.Minute)
	l := slog.Default()
	h := ForwardAuthHandler{
		Logger:        l,
		Domains:       domains.Domains{"example.com"},
		States:        &store,
		Sessions:      sessions.New("_auth", []byte("secret"), time.Hour),
		OAuthHandlers: map[string]oauth.Handler{"example.com": oauth.NewGoogleHandler("123", "1234", "https://auth.example.com/_oauth", l)},
	}

	validSession := h.Sessions.Session("foo@example.com")

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

			h.Authenticate(w, r)
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

func TestServer_LogoutHandler(t *testing.T) {
	store := state.New[string](time.Minute)
	h := ForwardAuthHandler{
		Logger:        slog.Default(),
		Domains:       domains.Domains{"example.com"},
		States:        &store,
		Sessions:      sessions.New("_auth", []byte("secret"), time.Hour),
		OAuthHandlers: map[string]oauth.Handler{".example.com": &testutils.FakeOauthHandler{}},
	}

	t.Run("logging out clears the session cookie", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
		session := h.Sessions.Session("foo@example.com")
		r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))
		w := httptest.NewRecorder()
		h.LogOut(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "You have been logged out\n", w.Body.String())
		assert.Equal(t, "_auth=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

	})

	t.Run("must be logged in to log out", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		h.LogOut(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Invalid session\n", w.Body.String())
	})
}
