package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
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
	cfg := configuration.Configuration{
		Provider: "foobar",
		Domains:  domains.Domains{"example.com"},
	}
	authenticator := auth.New("_traefik-simple-auth", []byte("secret"), time.Hour)
	stateStore := state.New(state.Configuration{CacheType: "memory", TTL: time.Minute})
	assert.Panics(t, func() {
		_ = New(context.Background(), authenticator, stateStore, cfg, nil, testutils.DiscardLogger)
	})
}

func TestForwardAuthHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	authenticator, _, _, handler := setupServer(ctx, t, nil)
	validSession, _ := authenticator.CookieWithSignedToken("foo@example.com", "example.com")

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
			t.Parallel()

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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	authenticator, _, _, handler := setupServer(ctx, t, nil)

	t.Run("logging out clears the browser's cookie", func(t *testing.T) {
		r := testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/_oauth/logout")
		c, _ := authenticator.CookieWithSignedToken("foo@example.com", "example.com")
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
		assert.Equal(t, "Invalid cookie\n", w.Body.String())
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

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
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
	//l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l := slog.New(slog.NewTextHandler(io.Discard, nil))

	// up
	states := state.New(state.Configuration{CacheType: "memory"})
	s := HealthHandler(states, l)
	r, _ := http.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	// down
	states = state.New(state.Configuration{CacheType: "redis"})
	s = HealthHandler(states, l)
	r, _ = http.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func setupServer(ctx context.Context, t *testing.T, metrics *Metrics) (*auth.Authenticator, state.States, *mockoidc.MockOIDC, http.Handler) {
	t.Helper()
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)

	go func() {
		<-ctx.Done()
		require.NoError(t, oidcServer.Shutdown())
	}()

	list, _ := whitelist.New([]string{"foo@example.com"})
	cfg := configuration.Configuration{
		Provider:      "oidc",
		AuthPrefix:    "auth",
		ClientID:      oidcServer.ClientID,
		ClientSecret:  oidcServer.ClientSecret,
		OIDCIssuerURL: oidcServer.Issuer(),
		Domains:       domains.Domains{"example.com"},
		Whitelist:     list,
	}
	authenticator := auth.New("_auth", []byte("secret"), time.Hour)
	stateStore := state.New(state.Configuration{CacheType: "memory", TTL: time.Minute})
	return authenticator, stateStore, oidcServer, New(ctx, authenticator, stateStore, cfg, metrics, testutils.DiscardLogger)
}

// Benchmark_header_get/header.Get-16              86203075                13.77 ns/op            0 B/op          0 allocs/op
// Benchmark_header_get/direct-16                  315107350                3.767 ns/op           0 B/op          0 allocs/op
func Benchmark_header_get(b *testing.B) {
	const headerName = "X-Foo"
	const headerValue = "bar"

	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(headerName, headerValue)

	b.Run("header.Get", func(b *testing.B) {
		for range b.N {
			if r.Header.Get(headerName) != headerValue {
				b.Fatal("header not found")
			}
		}
	})

	b.Run("direct", func(b *testing.B) {
		for range b.N {
			vals := r.Header[headerName]
			if len(vals) != 1 || vals[0] != headerValue {
				b.Fatal("header not found:" + strings.Join(vals, ","))
			}
		}
	})
}

// Current:
// BenchmarkForwardAuthHandler-16    	  182762	      6250 ns/op	    3184 B/op	      63 allocs/op
func BenchmarkForwardAuthHandler(b *testing.B) {
	whiteList, _ := whitelist.New([]string{"foo@example.com"})
	config := configuration.Configuration{
		Domains:   domains.Domains{"example.com"},
		Whitelist: whiteList,
		Provider:  "google",
	}
	authenticator := auth.New("_traefik-simple-auth", []byte("secret"), time.Hour)
	states := state.New(state.Configuration{CacheType: "memory", TTL: time.Minute})
	s := New(context.Background(), authenticator, states, config, nil, testutils.DiscardLogger)

	c, _ := authenticator.CookieWithSignedToken("foo@example.com", "example.com")
	req := testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/foo")
	req.AddCookie(c)

	resp := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			b.Fatal("unexpected status code", resp.Code)
		}
	}
}
