package server

import (
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_Measure(t *testing.T) {
	config := configuration.Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
		Users:             []string{"foo@example.com"},
		Domains:           []string{"example.com"},
		Provider:          "google",
	}
	m := NewMetrics("", "", nil, 1, 2)
	s := New(config, m, slog.Default())

	r := makeHTTPRequest(http.MethodGet, "example.com", "/")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	sess := s.sessions.MakeSession("foo@example.com")
	r = makeHTTPRequest(http.MethodGet, "example.org", "/")
	r.AddCookie(s.sessions.Cookie(sess, "example.com"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	r = makeHTTPRequest(http.MethodGet, "example.com", "/")
	r.AddCookie(s.sessions.Cookie(sess, "example.com"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	assert.NoError(t, testutil.CollectAndCompare(m, strings.NewReader(`
# HELP http_requests_total total number of http requests
# TYPE http_requests_total counter
http_requests_total{code="200",domain="example.com",host="example.com",path="/",user="foo@example.com"} 1
http_requests_total{code="307",domain="example.com",host="example.com",path="/", user=""} 1
http_requests_total{code="401",domain="",host="example.org",path="/",user="foo@example.com"} 1

`), "http_requests_total"))
}
