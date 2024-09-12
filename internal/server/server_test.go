package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
			Domains:  domains.Domains{"example.com"},
		}
		sessionStore := sessions.New("traefik_simple_auth", []byte("secret"), time.Hour)
		stateStore := state.New(state.Configuration{CacheType: "memory", TTL: time.Minute})
		_ = New(context.Background(), sessionStore, stateStore, cfg, nil, slog.Default())
	}()
	assert.True(t, panics)
}

func TestForwardAuthHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sessionStore, _, _, h := setupServer(ctx, t, nil)
	validSession := sessionStore.NewSession("foo@example.com")

	type args struct {
		target  string
		session *sessions.Session
	}
	tests := []struct {
		name string
		args args
		want int
		user string
	}{
		{
			name: "missing session",
			args: args{
				target: "example.com",
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid session",
			args: args{
				target:  "example.com",
				session: &validSession,
			},
			want: http.StatusOK,
			user: validSession.Key,
		},
		{
			name: "invalid domain",
			args: args{
				target:  "example.org",
				session: &validSession,
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "port specified",
			args: args{
				target:  "example.com:443",
				session: &validSession,
			},
			want: http.StatusOK,
			user: validSession.Key,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := testutils.ForwardAuthRequest(http.MethodGet, tt.args.target, "/")
			w := httptest.NewRecorder()
			if tt.args.session != nil {
				r = withSession(r, *tt.args.session)
			}

			h.ServeHTTP(w, r)
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
	sessionStore, _, _, s := setupServer(ctx, t, nil)

	t.Run("logging out clears the session cookie", func(t *testing.T) {
		r := testutils.ForwardAuthRequest(http.MethodGet, "example.com", "/_oauth/logout")
		session := sessionStore.NewSession("foo@example.com")
		r = withSession(r, session)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "You have been logged out\n", w.Body.String())
		assert.Equal(t, "_auth=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))
	})

	t.Run("must be logged in to log out", func(t *testing.T) {
		r := testutils.ForwardAuthRequest(http.MethodGet, "example.com", "/_oauth/logout")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Invalid session\n", w.Body.String())
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
	sessionStore, stateStore, oidcServer, server := setupServer(ctx, t, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// mockoidc is not thread-safe
			//t.Parallel()
			oauthState := tt.state
			if oauthState == "" {
				oauthState, _ = stateStore.Add(ctx, "https://example.com/foo")
			}

			code := tt.code
			if code == "" {
				u := mockoidc.MockUser{Email: tt.email, EmailVerified: true}
				session, err := oidcServer.SessionStore.NewSession("oidc profile email", "", &u, "", "")
				require.NoError(t, err)
				code = session.SessionID
			}

			v := url.Values{}
			v.Set("state", oauthState)
			v.Set("code", code)

			r, _ := http.NewRequest(http.MethodGet, OAUTHPath+"?"+v.Encode(), nil)
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			assert.Equal(t, tt.wantCode, w.Code)

			if w.Code == http.StatusTemporaryRedirect {
				assert.Equal(t, "https://example.com/foo", w.Header().Get("Location"))
				assert.True(t, sessionStore.Contains(tt.email))
			}
		})
	}
}

func TestHealthHandler(t *testing.T) {
	ctx := context.Background()
	sessionStore, stateStore, _, server := setupServer(ctx, t, nil)

	r, _ := http.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, `{"sessions":0,"states":0}
`, w.Body.String())

	sessionStore.NewSession("foo@example.com")
	_, _ = stateStore.Add(ctx, "https://example.com")

	r, _ = http.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, `{"sessions":1,"states":1}
`, w.Body.String())

}

func setupServer(ctx context.Context, t *testing.T, metrics *Metrics) (sessions.Sessions, state.States, *mockoidc.MockOIDC, http.Handler) {
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
	sessionStore := sessions.New("_auth", []byte("secret"), time.Hour)
	stateStore := state.New(state.Configuration{CacheType: "memory", TTL: time.Minute})
	return sessionStore, stateStore, oidcServer, New(ctx, sessionStore, stateStore, cfg, metrics, slog.Default())
}

func Test_getOriginalTarget(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
	}{
		{
			name: "with scheme",
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
				"X-Forwarded-Host":  []string{"example.com"},
				"X-Forwarded-Uri":   []string{"/foo"},
			},
			want: "http://example.com/foo",
		},
		{
			name: "with parameters",
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
				"X-Forwarded-Host":  []string{"example.com"},
				"X-Forwarded-Uri":   []string{"/foo?arg1=foo&arg2=bar"},
			},
			want: "http://example.com/foo?arg1=foo&arg2=bar",
		},
		{
			name: "default scheme is https",
			headers: http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Uri":  []string{"/foo"},
			},
			want: "https://example.com/foo",
		},
		{
			name: "ports are ignored",
			headers: http.Header{
				"X-Forwarded-Proto": []string{"https"},
				"X-Forwarded-Host":  []string{"example.com"},
				"X-Forwarded-Port":  []string{"443"},
			},
			want: "https://example.com/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header = tt.headers
			assert.Equal(t, tt.want, getOriginalTarget(r).String())
		})
	}
}

// before:
// Benchmark_authHandler-16                  927531              1194 ns/op             941 B/op         14 allocs/op
func Benchmark_authHandler(b *testing.B) {
	config := configuration.Configuration{
		Domains:   domains.Domains{"example.com"},
		Whitelist: map[string]struct{}{"foo@example.com": {}},
		Provider:  "google",
	}
	sessionStore := sessions.New("traefik_simple_auth", []byte("secret"), time.Hour)
	stateStore := state.New(state.Configuration{CacheType: "memory", TTL: time.Minute})
	s := New(context.Background(), sessionStore, stateStore, config, nil, slog.Default())
	sess := sessionStore.NewSessionWithExpiration("foo@example.com", time.Hour)
	r := testutils.ForwardAuthRequest(http.MethodGet, "example.com", "/foo")
	r.AddCookie(sessionStore.Cookie(sess, string(config.Domains[0])))
	w := httptest.NewRecorder()

	b.ResetTimer()
	for range b.N {
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			b.Fatal("unexpected status code", w.Code)
		}
	}
}

// before:
// Benchmark_getOriginalTarget/new-16              20134730                58.27 ns/op          144 B/op          1 allocs/op
func Benchmark_getOriginalTarget(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header = http.Header{
		"X-Forwarded-Proto": []string{"https"},
		"X-Forwarded-Host":  []string{"example.com"},
		"X-Forwarded-Uri":   []string{"/foo?arg1=bar"},
	}

	b.ResetTimer()
	for range b.N {
		_ = getOriginalTarget(r)
	}
}

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

func BenchmarkForwardAuthHandler(b *testing.B) {
	whiteList, _ := whitelist.New([]string{"foo@example.com"})
	config := configuration.Configuration{
		Domains:   domains.Domains{"example.com"},
		Whitelist: whiteList,
		Provider:  "google",
	}
	sessionStore := sessions.New("traefik_simple_auth", []byte("secret"), time.Hour)
	stateStore := state.New(state.Configuration{CacheType: "memory", TTL: time.Minute})
	s := New(context.Background(), sessionStore, stateStore, config, nil, slog.Default())
	session := sessionStore.NewSession("foo@example.com")

	req := testutils.ForwardAuthRequest(http.MethodGet, "example.com", "/foo")
	req.AddCookie(sessionStore.Cookie(session, string(config.Domains[0])))
	b.ResetTimer()
	for range b.N {
		resp := httptest.NewRecorder()
		s.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			b.Fatal("unexpected status code", resp.Code)
		}
	}
}
