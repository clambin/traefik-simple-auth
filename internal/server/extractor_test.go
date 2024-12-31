package server

import (
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionExtractor(t *testing.T) {
	a := auth.Authenticator{
		Secret:     []byte("secret"),
		CookieName: "_auth",
		Expiration: time.Hour,
	}
	extractor := authExtractor(a)
	validCookie, _ := a.CookieWithSignedToken("foo@example.com", "example.com")

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
			cookie:  a.Cookie("invalid-token", time.Hour, "example.com"),
			wantErr: require.Error,
		},
		{
			name:      "valid cookie",
			cookie:    validCookie,
			wantErr:   require.NoError,
			wantEmail: "foo@example.com",
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
				info := getUserInfo(r)
				tt.wantErr(t, info.err)
				if info.err != nil {
					return
				}
				assert.Equal(t, tt.wantEmail, info.email)
			}))
			h.ServeHTTP(w, r)
		})
	}
}
