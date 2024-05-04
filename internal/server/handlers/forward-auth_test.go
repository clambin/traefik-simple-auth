package handlers

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
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
	stateStore := state.New[string](time.Minute)
	logger := slog.Default()
	oauthHandler, _ := oauth.NewHandler(context.TODO(), "google", "", "123", "1234", "https://auth.example.com/_oauth", logger)

	h := ForwardAuthHandler(domains.Domains{".example.com"}, map[domains.Domain]oauth.Handler{".example.com": oauthHandler}, &stateStore, logger)

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
