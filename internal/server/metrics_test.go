package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/internal/server/testutils"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServer_withMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	metrics := NewMetrics("", "", map[string]string{"provider": "foo"})
	sessionStore, _, _, s := setupServer(ctx, t, metrics)

	r := testutils.ForwardAuthRequest(http.MethodGet, "example.com", "/foo")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	r, _ = http.NewRequest(http.MethodGet, "https://example.com/_oauth", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	sess := sessionStore.Session("foo@example.com")
	r = testutils.ForwardAuthRequest(http.MethodGet, "example.org", "/foo")
	r.AddCookie(sessionStore.Cookie(sess, "example.com"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	r = testutils.ForwardAuthRequest(http.MethodGet, "example.com", "/foo")
	r.AddCookie(sessionStore.Cookie(sess, "example.com"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	assert.NoError(t, testutil.CollectAndCompare(metrics, strings.NewReader(`
# HELP http_requests_total total number of http requests
# TYPE http_requests_total counter
http_requests_total{code="200",host="example.com",path="/",provider="foo",user="foo@example.com"} 1
http_requests_total{code="307",host="example.com",path="/",provider="foo",user=""} 1
http_requests_total{code="401",host="example.com",path="/_oauth",provider="foo",user=""} 1
http_requests_total{code="401",host="example.org",path="/",provider="foo",user="foo@example.com"} 1

`), "http_requests_total"))

	assert.Equal(t, 4, testutil.CollectAndCount(metrics, "http_request_duration_seconds"))
}

func TestMetrics_Collect_ActiveUsers(t *testing.T) {
	metrics := NewMetrics("", "", map[string]string{"provider": "foo"})
	sessionStore := sessions.New("traefik_simple_auth", []byte("secret"), time.Hour)

	sessionStore.Session("foo@example.com")
	sessionStore.SessionWithExpiration("foo@example.com", 30*time.Minute)
	sessionStore.Session("bar@example.com")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go monitorSessions(ctx, metrics, sessionStore, 100*time.Millisecond)

	assert.Eventually(t, func() bool {
		return testutil.CollectAndCount(metrics) > 0
	}, time.Second, time.Millisecond)

	assert.NoError(t, testutil.CollectAndCompare(metrics, strings.NewReader(`
# HELP active_users number of active users
# TYPE active_users gauge
active_users{provider="foo",user="bar@example.com"} 1
active_users{provider="foo",user="foo@example.com"} 2
`), "active_users"))
}
