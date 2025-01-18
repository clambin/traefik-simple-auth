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

func TestAuthenticator_Validate(t *testing.T) {
	tests := []struct {
		name   string
		cookie func(*Authenticator) *http.Cookie
		err    assert.ErrorAssertionFunc
		want   string
	}{
		{
			name: "valid cookie",
			cookie: func(a *Authenticator) *http.Cookie {
				c, _ := a.CookieWithSignedToken("foo@example.com", "example.com")
				return c
			},
			err:  assert.NoError,
			want: "foo@example.com",
		},
		{
			name: "empty cookie",
			cookie: func(a *Authenticator) *http.Cookie {
				c, _ := a.CookieWithSignedToken("", "example.com")
				c.Value = ""
				return c
			},
			err: assert.Error,
		},
		{
			name: "missing cookie",
			err:  assert.Error,
		},
		{
			name: "expired cookie",
			cookie: func(a *Authenticator) *http.Cookie {
				a.Expiration = -time.Hour
				c, _ := a.CookieWithSignedToken("foo@example.com", "example.com")
				return c
			},
			err: assert.Error,
		},
		{
			name: "invalid HMAC",
			cookie: func(a *Authenticator) *http.Cookie {
				b := New(a.CookieName, []byte("wrong-secret"), a.Expiration)
				c, _ := b.CookieWithSignedToken("foo@example.com", "example.com")
				return c
			},
			err: assert.Error,
		},
		{
			name: "no signature",
			cookie: func(a *Authenticator) *http.Cookie {
				// Create a new token without a signature
				claims := jwt.MapClaims{
					"exp": time.Now().Add(a.Expiration).Unix(),
					"iat": time.Now().Unix(),
					"sub": "foo@example.com",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
				unsignedToken, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				return a.Cookie(unsignedToken, a.Expiration, "example.com")
			},
			err: assert.Error,
		},
		{
			name: "invalid JWT",
			cookie: func(a *Authenticator) *http.Cookie {
				// create a JWT without a subject
				claims := jwt.MapClaims{
					"exp": time.Now().Add(a.Expiration).Unix(),
					"iat": time.Now().Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signedToken, _ := token.SignedString(a.Secret)
				return a.Cookie(signedToken, a.Expiration, "example.com")
			},
			err: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New("_auth", []byte("secret"), time.Hour)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie(a))
			}
			email, err := a.Validate(r)
			tt.err(t, err)
			if err == nil {
				require.Equal(t, tt.want, email)
			}
		})
	}
}
