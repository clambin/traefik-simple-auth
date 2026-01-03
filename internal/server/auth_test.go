package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticator_Authenticate(t *testing.T) {
	tests := []struct {
		name   string
		cookie func(*authenticator) *http.Cookie
		err    assert.ErrorAssertionFunc
		want   string
	}{
		{
			name: "valid cookie",
			cookie: func(a *authenticator) *http.Cookie {
				c, _ := a.CookieWithSignedToken("foo@example.com")
				return c
			},
			err:  assert.NoError,
			want: "foo@example.com",
		},
		{
			name: "empty cookie",
			cookie: func(a *authenticator) *http.Cookie {
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
			cookie: func(a *authenticator) *http.Cookie {
				a.Expiration = -time.Hour
				c, _ := a.CookieWithSignedToken("foo@example.com")
				return c
			},
			err: assert.Error,
		},
		{
			name: "invalid HMAC",
			cookie: func(a *authenticator) *http.Cookie {
				b := newAuthenticator(a.CookieName, "example.com", []byte("wrong-secret"), a.Expiration)
				c, _ := b.CookieWithSignedToken("foo@example.com")
				return c
			},
			err: assert.Error,
		},
		{
			name: "no signature",
			cookie: func(a *authenticator) *http.Cookie {
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
			cookie: func(a *authenticator) *http.Cookie {
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
				whitelist: map[string]struct{}{"foo@example.com": {}},
				domain:    ".example.com",
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

func TestWhitelist(t *testing.T) {
	tests := []struct {
		name    string
		emails  string
		email   string
		wantErr assert.ErrorAssertionFunc
		want    assert.BoolAssertionFunc
	}{
		{
			name:    "match",
			emails:  "foo@example.com,bar@example.com",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "leading whitespace is ignored",
			emails:  "foo@example.com, bar@example.com",
			email:   "bar@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "trailing whitespace is ignored",
			emails:  "foo@example.com ,bar@example.com",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "email list is case-insensitive",
			emails:  "Foo@example.com",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "email is case-insensitive",
			emails:  "foo@example.com",
			email:   "Foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "no match",
			emails:  "foo@example.com",
			email:   "bar@example.com",
			wantErr: assert.NoError,
			want:    assert.False,
		},
		{
			name:    "empty",
			emails:  "",
			email:   "foo@example.com",
			wantErr: assert.NoError,
			want:    assert.True,
		},
		{
			name:    "invalid email address",
			emails:  "0",
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			list, err := NewWhitelist(strings.Split(tt.emails, ","))
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			tt.want(t, list.Match(tt.email))
		})
	}
}

func FuzzWhitelist(f *testing.F) {
	testcases := []string{"foo@example.com", "foo@example.com,foo@example.org"}
	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if list, err := NewWhitelist(strings.Split(s, ",")); err == nil {
			for _, address := range list.list() {
				if _, err = mail.ParseAddress(address); err != nil {
					t.Errorf("invalid email address: %v", err)
				}
			}
		}
	})
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr assert.ErrorAssertionFunc
		want    Domain
	}{
		{
			name:    "no dot",
			input:   "example.com",
			wantErr: assert.NoError,
			want:    ".example.com",
		},
		{
			name:    "dot",
			input:   ".example.com",
			wantErr: assert.NoError,
			want:    ".example.com",
		},
		{
			name:    "whitespace is ignored",
			input:   " .example.com ",
			wantErr: assert.NoError,
			want:    ".example.com",
		},
		{
			name:    "port is not allowed",
			input:   ".example.com:443",
			wantErr: assert.Error,
		},
		{
			name:    "invalid entry",
			input:   ". example.com",
			wantErr: assert.Error,
		},
		{
			name:    "empty entry",
			input:   "",
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NewDomain(tt.input)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestDomain_Match(t *testing.T) {
	tests := []struct {
		name    string
		domains Domain
		target  string
		wantOK  assert.BoolAssertionFunc
		want    Domain
	}{
		{
			name:    "match",
			domains: ".example.com",
			target:  "https://example.com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "match should be case-insensitive",
			domains: ".example.com",
			target:  "https://Example.Com/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "ignore ports",
			domains: ".example.com",
			target:  "https://example.com:443/foo",
			wantOK:  assert.True,
			want:    ".example.com",
		},
		{
			name:    "no match",
			domains: ".example.com",
			target:  "https://www.example.net",
			wantOK:  assert.False,
		},
		{
			name:    "overlap",
			domains: ".example.com",
			target:  "https://www.badexample.com/foo",
			wantOK:  assert.False,
		},
		{
			name:    "empty",
			domains: ".example.com",
			target:  "",
			wantOK:  assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.target)
			tt.wantOK(t, tt.domains.Matches(u))
		})
	}
}

// Current:
// BenchmarkDomains_Domain-10    	82262750	        14.60 ns/op	       0 B/op	       0 allocs/op
func BenchmarkDomains_Domain(b *testing.B) {
	domain, _ := NewDomain(".example.com")
	u := url.URL{Host: "www.example.com"}
	b.ReportAllocs()
	for b.Loop() {
		if ok := domain.Matches(&u); !ok {
			b.Fatal("should match")
		}
	}
}
