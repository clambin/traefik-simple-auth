package server

import (
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/session"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServer_sessionExtractor(t *testing.T) {
	cfg := configuration.Configuration{
		SessionCookieName: "_auth",
		Secret:            []byte("secret"),
	}
	l := slog.Default()
	s := New(cfg, nil, l)
	sess := s.sessions.MakeSession("foo@example.com")

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

			h := s.sessionExtractor(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, ok := r.Context().Value(SessionKey).(session.Session)
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
		Users:             []string{"foo@example.com"},
		Domains:           []string{"example.com"},
		Provider:          "google",
	}
	m := NewMetrics("", "", map[string]string{"provider": "foo"}, 1, 2)
	s := New(config, m, slog.Default())

	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	r = makeHTTPRequest(http.MethodGet, "example.com", "/_oauth")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	sess := s.sessions.MakeSession("foo@example.com")
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
}
