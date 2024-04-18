package server

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestServer_AuthHandler(t *testing.T) {
	type args struct {
		host   string
		cookie sessionCookie
	}
	tests := []struct {
		name string
		args args
		want int
		user string
	}{
		{
			name: "missing cookie",
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid cookie",
			args: args{
				host:   "example.com",
				cookie: sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "expired cookie",
			args: args{
				host:   "example.com",
				cookie: sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(-time.Hour)},
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid subdomain",
			args: args{
				host:   "www.example.com",
				cookie: sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		/*		{
					name: "valid domain with user info",
					args: args{
						host:   "user:password@www.example.com",
						cookie: s.makeSessionCookie("foo@example.com", Config.Secret),
					},
					want: http.StatusOK,
					user: "foo@example.com",
				},
		*/
		{
			name: "invalid domain",
			args: args{
				host:   "example2.com",
				cookie: sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusUnauthorized,
		},
	}

	config := Config{
		Domain:   "example.com",
		Secret:   []byte("secret"),
		Expiry:   time.Hour,
		Users:    []string{"foo@example.com"},
		AuthHost: "https://auth.example.com",
	}
	s := New(config, slog.Default())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := makeHTTPRequest(http.MethodGet, tt.args.host, "/foo")
			w := httptest.NewRecorder()
			if tt.args.cookie.Email != "" {
				r.AddCookie(s.makeCookie(tt.args.cookie.encode(config.Secret)))
			}

			s.ServeHTTP(w, r)
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

// w/out caching:
// Benchmark_AuthHandler-16          389076              2993 ns/op            1997 B/op         23 allocs/op
// with caching:
// Benchmark_AuthHandler-16          587284              1914 ns/op            1389 B/op         15 allocs/op

func Benchmark_AuthHandler(b *testing.B) {
	config := Config{
		Domain:   "example.com",
		Secret:   []byte("secret"),
		Expiry:   time.Hour,
		Users:    []string{"foo@example.com"},
		AuthHost: "https://auth.example.com",
	}
	s := New(config, slog.Default())
	w := httptest.NewRecorder()
	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	sc := sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)}
	r.AddCookie(s.makeCookie(sc.encode(config.Secret)))

	b.ResetTimer()
	for range b.N {
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			b.Fatal("unexpected status code", w.Code)
		}
	}
}

func TestServer_redirectToAuth(t *testing.T) {
	config := Config{
		AuthHost:     "auth.example.com",
		ClientID:     "1234",
		ClientSecret: "secret",
	}
	s := New(config, slog.Default())

	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	got := w.Header().Get("Location")
	require.NotEmpty(t, got)
	u, err := url.Parse(got)
	require.NoError(t, err)

	for key, wantValue := range map[string]string{
		"client_id":     config.ClientID,
		"redirect_uri":  "https://" + config.AuthHost + OAUTHPath,
		"response_type": "code",
		"scope":         "https://www.googleapis.com/auth/userinfo.email",
	} {
		assert.Equal(t, wantValue, u.Query().Get(key))
	}

	state := u.Query().Get("state")
	require.NotEmpty(t, state)
	cachedURL, ok := s.stateHandler.cache.Get(state)
	require.True(t, ok)
	assert.Equal(t, "https://example.com/foo", cachedURL)
}

func TestServer_LogoutHandler(t *testing.T) {
	config := Config{
		Secret: []byte("secret"),
		Domain: "example.com",
		Expiry: time.Hour,
	}
	s := New(config, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	sc := sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)}
	r.AddCookie(s.makeCookie(sc.encode(config.Secret)))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	r = makeHTTPRequest(http.MethodGet, "example.com", "/_oauth/logout")
	r.AddCookie(s.makeCookie(sc.encode(config.Secret)))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "You have been logged out\n", w.Body.String())

	assert.Zero(t, s.sessionCookieHandler.sessions.Len())
}

func TestServer_AuthCallbackHandler(t *testing.T) {
	tests := []struct {
		name      string
		state     string
		makeState bool
		oauthUser string
		oauthErr  error
		wantCode  int
	}{
		{
			name:     "missing state parameter",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid state parameter",
			state:    "1234",
			wantCode: http.StatusBadRequest,
		},
		{
			name:      "valid state parameter",
			makeState: true,
			oauthUser: "foo@example.com",
			wantCode:  http.StatusTemporaryRedirect,
		},
		{
			name:      "login failed",
			makeState: true,
			oauthErr:  errors.New("something went wrong"),
			wantCode:  http.StatusBadGateway,
		},
		{
			name:      "invalid user",
			makeState: true,
			oauthUser: "bar@example.com",
			wantCode:  http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
			s := New(Config{Users: []string{"foo@example.com"}}, l)
			s.OAuthHandler = &fakeOauthHandler{email: tt.oauthUser, err: tt.oauthErr}

			state := tt.state
			if tt.makeState {
				state, _ = s.stateHandler.add("https://example.com/foo")
			}
			path := OAUTHPath
			if state != "" {
				path += "?state=" + state
			}

			r := makeHTTPRequest(http.MethodGet, "example.com", path)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			assert.Equal(t, tt.wantCode, w.Code)

			if w.Code == http.StatusTemporaryRedirect {
				assert.Equal(t, "https://example.com/foo", w.Header().Get("Location"))
			}
		})
	}
}

func Test_isSubdomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		input  string
		want   assert.BoolAssertionFunc
	}{
		{
			name:   "equal",
			domain: ".example.com",
			input:  "example.com",
			want:   assert.True,
		},
		{
			name:   "valid subdomain",
			domain: ".example.com",
			input:  "www.example.com",
			want:   assert.True,
		},
		{
			name:   "don't match on overlap",
			domain: ".example.com",
			input:  "bad-example.com",
			want:   assert.False,
		},
		{
			name:   "mismatch",
			domain: ".example.com",
			input:  "www.example2.com",
			want:   assert.False,
		},
		{
			name:  "empty subdomain",
			input: "example.com",
			want:  assert.False,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, isValidSubdomain(tt.domain, tt.input))
		})
	}
}

func makeHTTPRequest(method, host, uri string) *http.Request {
	req, _ := http.NewRequest(http.MethodPut, "https://traefik/", nil)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("User-Agent", "unit-test")
	return req
}

var _ OAuthHandler = fakeOauthHandler{}

type fakeOauthHandler struct {
	email string
	err   error
}

func (f fakeOauthHandler) AuthCodeURL(_ string, _ ...oauth2.AuthCodeOption) string {
	// not needed to test authCallbackHandler()
	panic("implement me")
}

func (f fakeOauthHandler) GetUserEmailAddress(_ string) (string, error) {
	return f.email, f.err
}
