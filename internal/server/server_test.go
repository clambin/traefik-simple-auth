package server

import (
	"context"
	"github.com/clambin/go-common/set"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name: "invalid cookie",
			args: args{
				host:   "example.com",
				cookie: sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(-time.Hour)},
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "invalid user",
			args: args{
				host:   "example.com",
				cookie: sessionCookie{Email: "bar@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusUnauthorized,
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
						cookie: s.makeSessionCookie("foo@example.com", config.Secret),
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
		Users:    set.New("foo@example.com"),
		AuthHost: "https://auth.example.com",
	}
	s := New(config, slog.Default())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := makeHTTPRequest(http.MethodGet, tt.args.host, "/foo")
			w := httptest.NewRecorder()
			if tt.args.cookie.Email != "" {
				// Generate a new cookie.
				// SaveCookie works in ResponseWriters, so save it there and then copy it to the request
				p := sessionCookieHandler{Secret: config.Secret}
				p.SaveCookie(w, tt.args.cookie)
				for _, c := range w.Header()["Set-Cookie"] {
					r.Header.Add("Cookie", c)
				}
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

func Benchmark_AuthHandler(b *testing.B) {
	config := Config{
		Domain:   "example.com",
		Secret:   []byte("secret"),
		Expiry:   time.Hour,
		Users:    set.New("foo@example.com"),
		AuthHost: "https://auth.example.com",
	}
	s := New(config, slog.Default())
	w := httptest.NewRecorder()
	s.sessionCookieHandler.SaveCookie(w, sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)})
	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")

	b.ResetTimer()
	for range b.N {
		r2 := r.Clone(context.Background())
		r2.Header.Set("Cookie", w.Header()["Set-Cookie"][0])
		s.ServeHTTP(w, r2)
		if w.Code != http.StatusOK {
			b.Fatal("unexpected status code", w.Code)
		}
	}
}

func Test_isSubdomain(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		subdomain string
		want      assert.BoolAssertionFunc
	}{
		{
			name:      "equal",
			domain:    "example.com",
			subdomain: "example.com",
			want:      assert.True,
		},
		{
			name:      "valid subdomain",
			domain:    "example.com",
			subdomain: "www.example.com",
			want:      assert.True,
		},
		{
			name:      "mismatch",
			domain:    "example.com",
			subdomain: "example2.com",
			want:      assert.False,
		},
		{
			name:      "mismatch",
			domain:    "example.com",
			subdomain: "www.example2.com",
			want:      assert.False,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, isValidSubdomain(tt.domain, tt.subdomain))
		})
	}
}

func TestServer_authRedirect(t *testing.T) {
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
		"redirect_uri":  "https://" + config.AuthHost + oauthPath,
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
	var config Config
	s := New(config, slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	r := makeHTTPRequest(http.MethodGet, "example.com", "/_oauth/logout")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "You have been logged out\n", w.Body.String())
}

func TestServer_AuthCallbackHandler(t *testing.T) {
	/*validOauth := oauthState{
		Nonce:       []byte("12345678901234567890123456789012"),
		RedirectURL: "https://example.com/foo",
	}*/

	tests := []struct {
		name     string
		path     string
		wantCode int
	}{
		{
			name:     "missing state parameter",
			path:     oauthPath,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid state parameter",
			path:     oauthPath + "?" + "state=1234",
			wantCode: http.StatusBadRequest,
		},
		/*
			{
				name:     "valid state parameter",
				path:     oauthPath + "?" + oauthStateCookieName + "=" + validOauth.encode(),
				wantCode: http.StatusBadRequest,
			},
		*/
	}

	s := New(Config{}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := makeHTTPRequest(http.MethodGet, "example.com", tt.path)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			assert.Equal(t, tt.wantCode, w.Code)
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
