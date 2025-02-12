package server

import (
	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServer_withMetrics(t *testing.T) {
	metrics := NewMetrics("", "", map[string]string{"provider": "foo"})
	authenticator, _, _, s := setupServer(t.Context(), t, metrics)

	// no cookie: redirect
	r := testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/foo")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	// no cookie: redirect (_oauth)
	r, _ = http.NewRequest(http.MethodGet, "https://example.com/_oauth", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// invalid domain: forbidden
	r = testutils.ForwardAuthRequest(http.MethodGet, "https://example.org/foo")
	c, _ := authenticator.CookieWithSignedToken("foo@example.com")
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// invalid user: forbidden
	r = testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/foo")
	c, _ = authenticator.CookieWithSignedToken("bar@example.com")
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// valid user & domain, valid token: ok
	r = testutils.ForwardAuthRequest(http.MethodGet, "https://example.com/foo")
	c, _ = authenticator.CookieWithSignedToken("foo@example.com")
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	assert.NoError(t, testutil.CollectAndCompare(metrics, strings.NewReader(`
# HELP http_requests_total total number of http requests
# TYPE http_requests_total counter
http_requests_total{code="200",host="example.com",path="/",provider="foo",user="foo@example.com"} 1
http_requests_total{code="307",host="example.com",path="/",provider="foo",user=""} 1
http_requests_total{code="401",host="example.com",path="/_oauth",provider="foo",user=""} 1
http_requests_total{code="403",host="example.com",path="/",provider="foo",user="bar@example.com"} 1
http_requests_total{code="403",host="example.org",path="/",provider="foo",user="foo@example.com"} 1
`), "http_requests_total"))

	assert.Equal(t, 5, testutil.CollectAndCount(metrics, "http_request_duration_seconds"))
}
