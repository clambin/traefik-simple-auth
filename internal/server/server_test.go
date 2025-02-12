package server

import (
	"context"
	"github.com/clambin/go-common/httputils/metrics"
	"github.com/clambin/traefik-simple-auth/internal/server/oauth2"
	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestServer_Panics(t *testing.T) {
	cfg := Configuration{
		Provider: "foobar",
		Domain:   Domain("example.com"),
	}
	assert.Panics(t, func() {
		_ = New(context.Background(), cfg, nil, testutils.DiscardLogger)
	})
}

func TestForwardAuthHandler(t *testing.T) {
	authenticator, _, _, handler := setupServer(t.Context(), t, nil)
	validSession, _ := authenticator.CookieWithSignedToken("foo@example.com")

	type args struct {
		target string
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
				target: "https://example.com",
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "invalid domain",
			args: args{
				target: "https://example.org",
				cookie: validSession,
			},
			want: http.StatusForbidden,
		},
		{
			name: "valid cookie",
			args: args{
				target: "https://example.com",
				cookie: validSession,
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "port specified",
			args: args{
				target: "https://example.com:443",
				cookie: validSession,
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testutils.ForwardAuthRequest(http.MethodGet, tt.args.target)
			if tt.args.cookie != nil {
				r.AddCookie(tt.args.cookie)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
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

func TestLogoutHandler(t *testing.T) {
	authenticator, _, _, handler := setupServer(t.Context(), t, nil)

	t.Run("logging out clears the browser's cookie", func(t *testing.T) {
		r := testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/_oauth/logout")
		c, _ := authenticator.CookieWithSignedToken("foo@example.com")
		r.AddCookie(c)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "You have been logged out\n", w.Body.String())
		assert.Equal(t, "_auth=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))
	})

	t.Run("must be logged in to log out", func(t *testing.T) {
		r := testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/_oauth/logout")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Unauthorized\n", w.Body.String())
	})
}

func TestAuthCallbackHandler(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		code     string
		state    string
		wantCode int
	}{
		{
			name:     "valid",
			email:    "foo@example.com",
			wantCode: http.StatusTemporaryRedirect,
		},
		{
			name:     "invalid email address",
			email:    "foo@example.org",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "invalid code",
			email:    "foo@example.com",
			code:     "1234",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "invalid state",
			email:    "foo@example.com",
			state:    "1234",
			wantCode: http.StatusUnauthorized,
		},
	}

	ctx := t.Context()
	_, states, oidcServer, handler := setupServer(ctx, t, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// mockoidc is not thread-safe
			//t.Parallel()
			oauthState := tt.state
			if oauthState == "" {
				oauthState, _ = states.Add(ctx, "https://example.com/foo")
			}

			code := tt.code
			if code == "" {
				u := mockoidc.MockUser{Email: tt.email, EmailVerified: true}
				oidcSession, err := oidcServer.SessionStore.NewSession("oidc profile email", "", &u, "", "")
				require.NoError(t, err)
				code = oidcSession.SessionID
			}

			v := url.Values{}
			v.Set("state", oauthState)
			v.Set("code", code)

			r, _ := http.NewRequest(http.MethodGet, OAUTHPath+"?"+v.Encode(), nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			assert.Equal(t, tt.wantCode, w.Code)

			if w.Code == http.StatusTemporaryRedirect {
				assert.Equal(t, "https://example.com/foo", w.Header().Get("Location"))
			}
		})
	}
}

func TestHealthHandler(t *testing.T) {
	//l := slog.NewAuthenticator(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l := slog.New(slog.NewTextHandler(io.Discard, nil))

	// up
	states := oauth2.NewCSFRStateStore(oauth2.Configuration{CacheType: "memory"})
	s := healthHandler(states, l)
	r, _ := http.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	// down
	states = oauth2.NewCSFRStateStore(oauth2.Configuration{CacheType: "redis"})
	s = healthHandler(states, l)
	r, _ = http.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func setupServer(ctx context.Context, t *testing.T, metrics metrics.RequestMetrics) (*authenticator, oauth2.CSRFStateStore, *mockoidc.MockOIDC, http.Handler) {
	t.Helper()
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)

	go func() {
		<-ctx.Done()
		require.NoError(t, oidcServer.Shutdown())
	}()

	list, _ := NewWhitelist([]string{"foo@example.com"})
	cfg := Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
		SessionExpiration: time.Hour,
		Provider:          "oidc",
		AuthPrefix:        "auth",
		ClientID:          oidcServer.ClientID,
		ClientSecret:      oidcServer.ClientSecret,
		OIDCIssuerURL:     oidcServer.Issuer(),
		Domain:            Domain("example.com"),
		Whitelist:         list,
		StateConfiguration: oauth2.Configuration{
			CacheType: "memory",
			TTL:       time.Minute,
		},
	}
	s := New(ctx, cfg, metrics, testutils.DiscardLogger)
	return s.authenticator, s.CSRFStateStore, oidcServer, s
}

// Before:
// Benchmark_header_get/header.Get-16              86203075                13.77 ns/op            0 B/op          0 allocs/op
// Benchmark_header_get/direct-16                  315107350                3.767 ns/op           0 B/op          0 allocs/op
// Go 1.24:
// Benchmark_header_get/header.Get-16         	62699799	        18.95 ns/op	       0 B/op	       0 allocs/op
// Benchmark_header_get/direct-16             	147151948	         8.114 ns/op	       0 B/op	       0 allocs/op
// PASS
func Benchmark_header_get(b *testing.B) {
	const headerName = "X-Foo"
	const headerValue = "bar"

	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(headerName, headerValue)

	b.Run("header.Get", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if r.Header.Get(headerName) != headerValue {
				b.Fatal("header not found")
			}
		}
	})

	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			vals := r.Header[headerName]
			if len(vals) != 1 || vals[0] != headerValue {
				b.Fatal("header not found:" + strings.Join(vals, ","))
			}
		}
	})
}

// Before:
// BenchmarkForwardAuthHandler-16    	  182762	      6250 ns/op	    3184 B/op	      63 allocs/op
// Go 1.24:
// BenchmarkForwardAuthHandler-16    	  194578	      5888 ns/op	    3184 B/op	      63 allocs/op
func BenchmarkForwardAuthHandler(b *testing.B) {
	whiteList, _ := NewWhitelist([]string{"foo@example.com"})
	config := Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
		SessionExpiration: time.Hour,
		Domain:            Domain("example.com"),
		Whitelist:         whiteList,
		Provider:          "google",
		StateConfiguration: oauth2.Configuration{
			CacheType: "memory",
			TTL:       time.Minute,
		},
	}
	s := New(context.Background(), config, nil, testutils.DiscardLogger)

	c, _ := s.authenticator.CookieWithSignedToken("foo@example.com")
	req := testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/foo")
	req.AddCookie(c)

	resp := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			b.Fatal("unexpected status code", resp.Code)
		}
	}
}
