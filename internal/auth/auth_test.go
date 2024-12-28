package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	s := Authenticator{
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

func TestAuthenticator_Validate(t *testing.T) {
	tests := []struct {
		name   string
		cookie func(Authenticator) *http.Cookie
		err    assert.ErrorAssertionFunc
		want   string
	}{
		{
			name: "valid cookie",
			cookie: func(a Authenticator) *http.Cookie {
				c, _ := a.JWTCookie("foo@example.com", "example.com")
				return c
			},
			err:  assert.NoError,
			want: "foo@example.com",
		},
		{
			name: "missing cookie",
			err:  assert.Error,
		},
		{
			name: "expired cookie",
			cookie: func(a Authenticator) *http.Cookie {
				a.Expiration = -time.Hour
				c, _ := a.JWTCookie("foo@example.com", "example.com")
				return c
			},
			err: assert.Error,
		},
		{
			name: "invalid HMAC",
			cookie: func(a Authenticator) *http.Cookie {
				a.Secret = []byte("wrong-secret")
				c, _ := a.JWTCookie("foo@example.com", "example.com")
				return c
			},
			err: assert.Error,
		},
		{
			name: "invalid JWT",
			cookie: func(a Authenticator) *http.Cookie {
				claims := jwt.MapClaims{
					"exp": time.Now().Add(a.Expiration).Unix(),
					"iat": time.Now().Unix(),
				}

				// Create a new token
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

				// Sign the token with the secret key
				signedToken, _ := token.SignedString(a.Secret)

				c, _ := a.JWTCookie(signedToken, "example.com")
				c.Value = signedToken
				return c
			},
			err: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Authenticator{
				Secret:     []byte("secret"),
				CookieName: "_auth",
				Expiration: time.Hour,
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie(a))
			}
			email, err := a.Validate(r)
			tt.err(t, err)
			require.Equal(t, tt.want, email)
		})
	}
}
