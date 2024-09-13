package server

import (
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionExtractor(t *testing.T) {
	s := sessions.New("_auth", []byte("secret"), time.Hour)
	extractor := sessionExtractor(s)
	validSession := s.NewSession("foo@example.com")
	expiredSession := s.NewSessionWithExpiration("foo@example.com", -time.Hour)

	tests := []struct {
		name      string
		cookie    *http.Cookie
		wantErr   require.ErrorAssertionFunc
		wantEmail string
	}{
		{
			name:    "no cookie",
			cookie:  nil,
			wantErr: require.Error,
		},
		{
			name:    "bad cookie",
			cookie:  &http.Cookie{Name: s.SessionCookieName, Value: "bad-value"},
			wantErr: require.Error,
		},
		{
			name:    "expired session",
			cookie:  s.Cookie(expiredSession, "example.com"),
			wantErr: require.Error,
		},
		{
			name:      "valid cookie",
			cookie:    s.Cookie(validSession, "example.com"),
			wantErr:   require.NoError,
			wantEmail: validSession.Key,
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

			h := extractor(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				userSession, err := getSession(r)
				tt.wantErr(t, err)
				if err != nil {
					return
				}
				assert.Equal(t, tt.wantEmail, userSession.Key)
			}))
			h.ServeHTTP(w, r)
		})
	}
}
