package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServer_withMetrics(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
		Whitelist:         map[string]struct{}{"foo@example.com": {}},
		Domains:           domains.Domains{".example.com"},
		Provider:          "google",
	}
	m := NewMetrics("", "", map[string]string{"provider": "foo"})
	s := New(context.TODO(), config, m, slog.Default())

	r := makeForwardAuthRequest(http.MethodGet, "example.com", "/foo")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	r, _ = http.NewRequest(http.MethodGet, "https://example.com/_oauth", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	sess := s.sessions.Session("foo@example.com")
	r = makeForwardAuthRequest(http.MethodGet, "example.org", "/foo")
	r.AddCookie(s.sessions.Cookie(sess, "example.com"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	r = makeForwardAuthRequest(http.MethodGet, "example.com", "/foo")
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
		Domains:           domains.Domains{"example.com"},
		Provider:          "google",
		Expiry:            time.Hour,
	}
	m := NewMetrics("", "", map[string]string{"provider": "foo"})
	s := New(context.TODO(), config, m, slog.Default())

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
