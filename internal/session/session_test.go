package session

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	s := Sessions{
		Secret:     []byte("secret"),
		CookieName: "_auth",
		Expiration: time.Hour,
	}
	const userID = "userid@example.com"
	validCookie, err := s.JWTCookie(userID, "example.com")
	require.NoError(t, err)

	tests := []struct {
		name       string
		cookie     *http.Cookie
		err        assert.ErrorAssertionFunc
		wantUserID string
	}{
		{"no cookie", nil, assert.Error, ""},
		{"invalid cookie", s.Cookie("invalid", time.Time{}, "example.com"), assert.Error, ""},
		{"valid cookie", validCookie, assert.NoError, userID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			got, err := s.Validate(r)
			tt.err(t, err)
			require.Equal(t, tt.wantUserID, got)
		})
	}
}
