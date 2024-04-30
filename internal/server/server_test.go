package server

import (
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/testutils"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
		assert.Equal(t, 1, s.sessions.ActiveUsers()["foo@example.com"])
	})

	t.Run("forwardAuth requests with valid cookie for logout handler are accepted", func(t *testing.T) {
		validSession := s.sessions.Session("foo@example.com")
		r := makeForwardAuthRequest(http.MethodGet, "example.com", OAUTHPath+"/logout")
		r.AddCookie(s.sessions.Cookie(validSession, "example.com"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Zero(t, s.sessions.ActiveUsers()["foo@example.com"])
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
		l := slog.Default()
		_ = New(cfg, nil, l)
	}()
	assert.True(t, panics)
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

func makeForwardAuthRequest(method, host, uri string) *http.Request {
	req, _ := http.NewRequest(http.MethodPut, "https://traefik/", nil)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("User-Agent", "unit-test")
	return req
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
			name: "default scheme is https",
			headers: http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Uri":  []string{"/foo"},
			},
			want: "https://example.com/foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header = tt.headers
			assert.Equal(t, tt.want, getOriginalTarget(r))
		})
	}
}
