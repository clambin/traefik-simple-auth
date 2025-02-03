package server

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthenticator_Authenticate(t *testing.T) {
	tests := []struct {
		name   string
		cookie func(*Authenticator) *http.Cookie
		err    assert.ErrorAssertionFunc
		want   string
	}{
		{
			name: "valid cookie",
			cookie: func(a *Authenticator) *http.Cookie {
				c, _ := a.CookieWithSignedToken("foo@example.com")
				return c
			},
			err:  assert.NoError,
			want: "foo@example.com",
		},
		{
			name: "empty cookie",
			cookie: func(a *Authenticator) *http.Cookie {
				c, _ := a.CookieWithSignedToken("")
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
				c, _ := a.CookieWithSignedToken("foo@example.com")
				return c
			},
			err: assert.Error,
		},
		{
			name: "invalid HMAC",
			cookie: func(a *Authenticator) *http.Cookie {
				b := newAuthenticator(a.CookieName, "example.com", []byte("wrong-secret"), a.Expiration)
				c, _ := b.CookieWithSignedToken("foo@example.com")
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
				return a.Cookie(unsignedToken, a.Expiration)
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
				return a.Cookie(signedToken, a.Expiration)
			},
			err: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAuthenticator("_auth", "example.com", []byte("secret"), time.Hour)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie(a))
			}
			email, err := a.Authenticate(r)
			tt.err(t, err)
			if err == nil {
				require.Equal(t, tt.want, email)
			}
		})
	}
}

func Test_authorizer(t *testing.T) {
	tests := []struct {
		name   string
		target string
		info   userInfo
		err    assert.ErrorAssertionFunc
		want   string
	}{
		{
			name:   "success",
			target: "https://www.example.com",
			info:   userInfo{email: "foo@example.com"},
			err:    assert.NoError,
		},
		{
			name:   "invalid token",
			target: "https://www.example.com",
			info:   userInfo{email: "foo@example.com", err: errors.New("invalid token")},
			err:    assert.Error,
			want:   "invalid token",
		},
		{
			name:   "missing token",
			target: "https://www.example.com",
			info:   userInfo{email: ""},
			err:    assert.Error,
			want:   "http: named cookie not present",
		},
		{
			name:   "invalid user",
			target: "https://www.example.com",
			info:   userInfo{email: "bar@example.com"},
			err:    assert.Error,
			want:   "invalid user",
		},
		{
			name:   "invalid domain",
			target: "https://www.example.org",
			info:   userInfo{email: "foo@example.com"},
			err:    assert.Error,
			want:   "invalid domain",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := authorizer{
				Whitelist: map[string]struct{}{"foo@example.com": {}},
				Domain:    ".example.com",
			}

			r, _ := http.NewRequest(http.MethodGet, tt.target, nil)
			if tt.info.email != "" {
				r = withUserInfo(r, tt.info)
			}

			email, err := a.AuthorizeRequest(r)
			tt.err(t, err)
			if err == nil {
				assert.Equal(t, tt.info.email, email)
			}
			if err != nil {
				assert.Equal(t, tt.want, err.Error())
			}
		})
	}
}
