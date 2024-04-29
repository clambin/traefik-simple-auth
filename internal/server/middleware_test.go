package server

import (
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServer_sessionExtractor(t *testing.T) {
	cfg := configuration.Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
	}
	l := slog.Default()
	s := New(cfg, nil, l)
	sess := s.sessions.Session("foo@example.com")

	tests := []struct {
		name      string
		cookie    *http.Cookie
		wantOK    require.BoolAssertionFunc
		wantEmail string
	}{
		{
			name:   "no cookie",
			cookie: nil,
			wantOK: require.False,
		},
		{
			name:   "bad cookie",
			cookie: &http.Cookie{Name: s.sessions.SessionCookieName, Value: "bad-value"},
			wantOK: require.False,
		},
		{
			name:      "valid cookie",
			cookie:    s.sessions.Cookie(sess, "example.com"),
			wantOK:    require.True,
			wantEmail: sess.Email,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			w := httptest.NewRecorder()

			h := s.sessionExtractor(slog.Default())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				ctx, ok := r.Context().Value(sessionKey).(sessions.Session)
				tt.wantOK(t, ok)
				if !ok {
					return
				}
				assert.Equal(t, tt.wantEmail, ctx.Email)
			}))

			h.ServeHTTP(w, r)
		})
	}
}

func TestServer_withMetrics(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
		Whitelist:         map[string]struct{}{"foo@example.com": {}},
		Domains:           []string{"example.com"},
		Provider:          "google",
	}
	m := NewMetrics("", "", map[string]string{"provider": "foo"})
	s := New(config, m, slog.Default())

	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	r = makeHTTPRequest(http.MethodGet, "example.com", "/_oauth")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	sess := s.sessions.Session("foo@example.com")
	r = makeHTTPRequest(http.MethodGet, "example.org", "/foo")
	r.AddCookie(s.sessions.Cookie(sess, "example.com"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	r = makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	r.AddCookie(s.sessions.Cookie(sess, "example.com"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	assert.NoError(t, testutil.CollectAndCompare(m, strings.NewReader(`
# HELP http_requests_total total number of http requests
# TYPE http_requests_total counter
http_requests_total{code="200",host="example.com",path="/",provider="foo",user="foo@example.com"} 1
http_requests_total{code="307",host="example.com",path="/",provider="foo",user=""} 1
http_requests_total{code="400",host="example.com",path="/_oauth",provider="foo",user=""} 1
http_requests_total{code="401",host="example.org",path="/",provider="foo",user="foo@example.com"} 1

`), "http_requests_total"))

	assert.Equal(t, 4, testutil.CollectAndCount(m, "http_request_duration_seconds"))
}

func TestMetrics_Collect_ActiveUsers(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
		Whitelist:         map[string]struct{}{"foo@example.com": {}},
		Domains:           []string{"example.com"},
		Provider:          "google",
		Expiry:            time.Hour,
	}
	m := NewMetrics("", "", map[string]string{"provider": "foo"})
	s := New(config, m, slog.Default())

	s.sessions.Session("foo@example.com")
	s.sessions.SessionWithExpiration("foo@example.com", 30*time.Minute)
	s.sessions.Session("bar@example.com")

	go s.monitorSessions(m, 100*time.Millisecond)

	assert.Eventually(t, func() bool {
		return testutil.CollectAndCount(m) > 0
	}, time.Second, time.Millisecond)

	assert.NoError(t, testutil.CollectAndCompare(m, strings.NewReader(`
# HELP active_users number of active users
# TYPE active_users gauge
active_users{provider="foo",user="bar@example.com"} 1
active_users{provider="foo",user="foo@example.com"} 2
`), "active_users"))
}
