package server

import (
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/session"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
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

func TestServer_Panics(t *testing.T) {
	var panics bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				panics = true
			}
		}()
		cfg := configuration.Configuration{
			Provider: "foobar",
			Domains:  []string{"example.com"},
		}
		l := slog.Default()
		_ = New(cfg, nil, l)
	}()
	assert.True(t, panics)
}

func TestServer_authHandler(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_traefik_simple_auth",
		Domains:           domains.Domains{"example.com"},
		Secret:            []byte("secret"),
		Expiry:            time.Hour,
		Users:             []string{"foo@example.com"},
		Provider:          "google",
	}
	s := New(config, nil, slog.Default())
	validSession := s.sessions.MakeSession("foo@example.com")
	expiredSession := session.NewSession("bar@example.com", -config.Expiry, config.Secret)

	type args struct {
		host   string
		cookie *http.Cookie
	}
	tests := []struct {
		name string
		args args
		want int
		user string
	}{
		{
			name: "missing cookie",
			args: args{
				host: "example.com",
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid cookie",
			args: args{
				host:   "example.com",
				cookie: s.sessions.Cookie(validSession, "example.com"),
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "expired cookie",
			args: args{
				host:   "example.com",
				cookie: s.sessions.Cookie(expiredSession, "example.com"),
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid subdomain",
			args: args{
				host:   "www.example.com",
				cookie: s.sessions.Cookie(validSession, "example.com"),
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "valid domain with user info",
			args: args{
				host:   "user:password@www.example.com",
				cookie: s.sessions.Cookie(validSession, "example.com"),
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "invalid domain",
			args: args{
				host:   "example2.com",
				cookie: s.sessions.Cookie(validSession, "example.com"),
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "blank cookie",
			args: args{
				host:   "example.com",
				cookie: &http.Cookie{Name: config.SessionCookieName, Value: ""},
			},
			want: http.StatusTemporaryRedirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := makeHTTPRequest(http.MethodGet, tt.args.host, "/foo")
			w := httptest.NewRecorder()
			if tt.args.cookie != nil {
				r.AddCookie(tt.args.cookie)
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

// Benchmark_authHandler-16          857482              1298 ns/op             501 B/op         10 allocs/op
func Benchmark_authHandler(b *testing.B) {
	config := configuration.Configuration{
		SessionCookieName: "_traefik_simple_auth",
		Domains:           domains.Domains{"example.com"},
		Secret:            []byte("secret"),
		Expiry:            time.Hour,
		Users:             []string{"foo@example.com"},
		Provider:          "google",
	}
	s := New(config, nil, slog.Default())
	sess := session.NewSession("foo@example.com", time.Hour, config.Secret)
	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	r.AddCookie(s.sessions.Cookie(sess, config.Domains[0]))
	w := httptest.NewRecorder()

	b.ResetTimer()
	for range b.N {
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			b.Fatal("unexpected status code", w.Code)
		}
	}
}

func TestServer_authHandler_expiry(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_traefik_simple_auth",
		Expiry:            500 * time.Millisecond,
		Secret:            []byte("secret"),
		Domains:           []string{"example.com"},
		Users:             []string{"foo@example.com"},
		Provider:          "google",
	}
	s := New(config, nil, slog.Default())

	assert.Eventually(t, func() bool {
		r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
		sess := session.NewSession("foo@example.com", config.Expiry, config.Secret)
		r.AddCookie(s.sessions.Cookie(sess, config.Domains[0]))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code == http.StatusTemporaryRedirect
	}, time.Second, 10*time.Millisecond)
}

func TestServer_redirectToAuth(t *testing.T) {
	tests := []struct {
		name            string
		target          string
		wantCode        int
		wantRedirectURI string
	}{
		{
			name:            "redirect for example.com",
			target:          "example.com",
			wantCode:        http.StatusTemporaryRedirect,
			wantRedirectURI: "https://auth.example.com" + OAUTHPath,
		},
		{
			name:            "redirect for example.org",
			target:          "example.org",
			wantCode:        http.StatusTemporaryRedirect,
			wantRedirectURI: "https://auth.example.org" + OAUTHPath,
		},
		{
			name:     "redirect for bad domain",
			target:   "example.net",
			wantCode: http.StatusUnauthorized,
		},
	}

	config := configuration.Configuration{
		ClientID:     "1234",
		ClientSecret: "secret",
		Domains:      domains.Domains{"example.com", ".example.org"},
		AuthPrefix:   "auth",
		Provider:     "google",
	}
	s := New(config, nil, slog.Default())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := makeHTTPRequest(http.MethodGet, tt.target, "/foo")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			assert.Equal(t, tt.wantCode, w.Code)
			if w.Code != http.StatusTemporaryRedirect {
				return
			}

			l := w.Header().Get("Location")
			u, err := url.Parse(l)
			require.NoError(t, err)
			assert.Equal(t, tt.wantRedirectURI, u.Query().Get("redirect_uri"))

			state := u.Query().Get("state")
			require.NotEmpty(t, state)
			cachedURL, ok := s.states.Get(state)
			require.True(t, ok)
			assert.Equal(t, "https://"+tt.target+"/foo", cachedURL)
		})
	}
}

func TestServer_LogoutHandler(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_traefik_simple_auth",
		Secret:            []byte("secret"),
		Domains:           domains.Domains{"example.com"},
		Expiry:            time.Hour,
		Provider:          "google",
	}
	s := New(config, nil, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	sess := session.NewSession("foo@example.com", config.Expiry, config.Secret)
	r.AddCookie(s.sessions.Cookie(sess, config.Domains[0]))

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	r = makeHTTPRequest(http.MethodGet, "example.com", "/_oauth/logout")
	r.AddCookie(s.sessions.Cookie(sess, config.Domains[0]))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "You have been logged out\n", w.Body.String())
	assert.Equal(t, "_traefik_simple_auth=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

	r = makeHTTPRequest(http.MethodGet, "example.com", "/_oauth/logout")
	r.AddCookie(s.sessions.Cookie(session.Session{}, config.Domains[0]))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "Invalid session\n", w.Body.String())
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
			s := New(configuration.Configuration{Users: []string{"foo@example.com"}, Domains: domains.Domains{"example.com"}, Provider: "google"}, nil, l)
			s.oauthHandlers["example.com"] = &fakeOauthHandler{email: tt.oauthUser, err: tt.oauthErr}

			state := tt.state
			if tt.makeState {
				state = s.states.Add("https://example.com/foo")
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

func makeHTTPRequest(method, host, uri string) *http.Request {
	req, _ := http.NewRequest(http.MethodPut, "https://traefik/", nil)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("User-Agent", "unit-test")
	return req
}

var _ oauth.Handler = fakeOauthHandler{}

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
