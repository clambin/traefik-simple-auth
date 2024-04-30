package handlers

import (
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionExtractor(t *testing.T) {
	s := sessions.New("_auth", []byte("secret"), time.Hour)
	l := slog.Default()
	h := SessionExtractor(s, l)
	validSession := s.Session("foo@example.com")
	expiredSession := s.SessionWithExpiration("foo@example.com", -time.Hour)

	tests := []struct {
		name      string
		cookie    *http.Cookie
		wantOK    require.BoolAssertionFunc
		wantEmail string
	}{
		{
			name:   "no cookie",
			cookie: nil,
			wantOK: require.False,
		},
		{
			name:   "bad cookie",
			cookie: &http.Cookie{Name: s.SessionCookieName, Value: "bad-value"},
			wantOK: require.False,
		},
		{
			name:   "expired session",
			cookie: s.Cookie(expiredSession, "example.com"),
			wantOK: require.False,
		},
		{
			name:      "valid cookie",
			cookie:    s.Cookie(validSession, "example.com"),
			wantOK:    require.True,
			wantEmail: validSession.Email,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			w := httptest.NewRecorder()

			h := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				userSession, ok := GetSession(r)
				tt.wantOK(t, ok)
				if !ok {
					return
				}
				assert.Equal(t, tt.wantEmail, userSession.Email)
			}))
			h.ServeHTTP(w, r)
		})
	}
}
