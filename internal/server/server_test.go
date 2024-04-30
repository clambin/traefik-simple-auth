package server

import (
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/testutils"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
		Whitelist:         map[string]struct{}{"foo@example.com": {}},
		Provider:          "google",
	}
	s := New(config, nil, slog.Default())
	validSession := s.cbHandler.Sessions.Session("foo@example.com")
	expiredSession := s.cbHandler.Sessions.SessionWithExpiration("bar@example.com", -config.Expiry)

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
				cookie: s.cbHandler.Sessions.Cookie(validSession, "example.com"),
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "expired session",
			args: args{
				host:   "example.com",
				cookie: s.cbHandler.Sessions.Cookie(expiredSession, "example.com"),
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid subdomain",
			args: args{
				host:   "www.example.com",
				cookie: s.cbHandler.Sessions.Cookie(validSession, "example.com"),
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "valid domain with user info",
			args: args{
				host:   "user:password@www.example.com",
				cookie: s.cbHandler.Sessions.Cookie(validSession, "example.com"),
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "invalid domain",
			args: args{
				host:   "example2.com",
				cookie: s.cbHandler.Sessions.Cookie(validSession, "example.com"),
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
			//t.Parallel()

			r := makeForwardAuthRequest(http.MethodGet, tt.args.host, "/foo")
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
		Whitelist:         map[string]struct{}{"foo@example.com": {}},
		Provider:          "google",
	}
	s := New(config, nil, slog.Default())
	sess := s.sessions.SessionWithExpiration("foo@example.com", time.Hour)
	r := makeForwardAuthRequest(http.MethodGet, "example.com", "/foo")
	r.AddCookie(s.cbHandler.Sessions.Cookie(sess, config.Domains[0]))
	w := httptest.NewRecorder()

	b.ResetTimer()
	for range b.N {
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			b.Fatal("unexpected status code", w.Code)
		}
	}
}

/*

func TestServer_LogoutHandler(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_traefik_simple_auth",
		Secret:            []byte("secret"),
		Domains:           domains.Domains{"example.com"},
		Expiry:            time.Hour,
		Provider:          "google",
	}
	s := New(config, nil, slog.Default())
	sess := s.sessions.Session("foo@example.com")

	t.Run("logging out clears the session cookie", func(t *testing.T) {
		r := testutils.makeForwardAuthRequest(http.MethodGet, "example.com", "/_oauth/logout")
		r.AddCookie(s.sessions.Cookie(sess, config.Domains[0]))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "You have been logged out\n", w.Body.String())
		assert.Equal(t, "_traefik_simple_auth=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

	})

	t.Run("must be logged in to log out", func(t *testing.T) {
		r := testutils.makeForwardAuthRequest(http.MethodGet, "example.com", "/_oauth/logout")
		r.AddCookie(s.sessions.Cookie(sessions.Session{}, config.Domains[0]))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Invalid session\n", w.Body.String())
	})
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

			cfg := configuration.Configuration{
				Whitelist: map[string]struct{}{"foo@example.com": {}},
				Domains:   domains.Domains{"example.com"},
				Provider:  "google",
			}
			l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
			s := New(cfg, nil, l)
			s.oauthHandlers["example.com"] = &testutils.FakeOauthHandler{Email: tt.oauthUser, Err: tt.oauthErr}

			state := tt.state
			if tt.makeState {
				state = s.states.Add("https://example.com/foo")
			}
			path := OAUTHPath
			if state != "" {
				path += "?state=" + state
			}

			r, _ := http.NewRequest(http.MethodGet, "https://example.com"+path, nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			assert.Equal(t, tt.wantCode, w.Code)

			if w.Code == http.StatusTemporaryRedirect {
				assert.Equal(t, "https://example.com/foo", w.Header().Get("Location"))
			}
		})
	}
}


*/

func TestServer(t *testing.T) {
	config := configuration.Configuration{
		Debug:             false,
		SessionCookieName: "_traefik_simple_auth",
		Expiry:            time.Hour,
		Secret:            []byte("secret"),
		Provider:          "google",
		Domains:           domains.Domains{"example.com"},
		Whitelist:         whitelist.Whitelist{},
		ClientID:          "123",
		ClientSecret:      "1234",
		AuthPrefix:        "auth",
	}
	s := New(config, nil, slog.Default())

	t.Run("forwardAuth requests without cookie get redirected", func(t *testing.T) {
		r := makeForwardAuthRequest(http.MethodGet, "example.com", "/foo")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	})

	t.Run("forwardAuth requests with valid cookie are accepted", func(t *testing.T) {
		validSession := s.sessions.Session("foo@example.com")
		r := makeForwardAuthRequest(http.MethodGet, "example.com", "/foo")
		r.AddCookie(s.sessions.Cookie(validSession, "example.com"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code)
		count, _ := s.sessions.ActiveUsers()["foo@example.com"]
		assert.Equal(t, 1, count)
	})

	t.Run("forwardAuth requests with valid cookie for logout handler are accepted", func(t *testing.T) {
		validSession := s.sessions.Session("foo@example.com")
		r := makeForwardAuthRequest(http.MethodGet, "example.com", OAUTHPath+"/logout")
		r.AddCookie(s.sessions.Cookie(validSession, "example.com"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		count, _ := s.sessions.ActiveUsers()["foo@example.com"]
		assert.Zero(t, count)
	})

	t.Run("oauth callback", func(t *testing.T) {
		s.cbHandler.OAuthHandlers["example.com"] = testutils.FakeOauthHandler{Email: "foo@example.com"}
		state := s.states.Add("https://example.com")
		r, _ := http.NewRequest(http.MethodGet, "https://traefik"+OAUTHPath+"?state="+state, nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
		assert.Equal(t, "https://example.com", w.Header().Get("Location"))
	})
}

func makeForwardAuthRequest(method, host, uri string) *http.Request {
	req, _ := http.NewRequest(http.MethodPut, "https://traefik/", nil)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("User-Agent", "unit-test")
	return req
}
