package metrics

import (
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMetrics_Collect(t *testing.T) {
	m := New("", "", nil)
	m.Measure(&http.Request{URL: &url.URL{Path: "/foo"}}, http.StatusOK, time.Millisecond)
	m.Measure(&http.Request{URL: &url.URL{Path: "/bar"}}, http.StatusTemporaryRedirect, 2*time.Millisecond)
	m.Measure(&http.Request{URL: &url.URL{Path: server.OAUTHPath}}, http.StatusTemporaryRedirect, 10*time.Millisecond)
	m.Measure(&http.Request{URL: &url.URL{Path: server.OAUTHPath + "/logout"}}, http.StatusUnauthorized, 5*time.Millisecond)

	assert.NoError(t, testutil.CollectAndCompare(m, strings.NewReader(`
# HELP http_request_duration_seconds duration of http requests
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{code="200",method="",path="/",le="0.005"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="0.01"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="0.025"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="0.05"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="0.1"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="0.25"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="0.5"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="1"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="2.5"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="5"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="10"} 1
http_request_duration_seconds_bucket{code="200",method="",path="/",le="+Inf"} 1
http_request_duration_seconds_sum{code="200",method="",path="/"} 0.001
http_request_duration_seconds_count{code="200",method="",path="/"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="0.005"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="0.01"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="0.025"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="0.05"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="0.1"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="0.25"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="0.5"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="1"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="2.5"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="5"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="10"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/",le="+Inf"} 1
http_request_duration_seconds_sum{code="307",method="",path="/"} 0.002
http_request_duration_seconds_count{code="307",method="",path="/"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="0.005"} 0
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="0.01"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="0.025"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="0.05"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="0.1"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="0.25"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="0.5"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="1"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="2.5"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="5"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="10"} 1
http_request_duration_seconds_bucket{code="307",method="",path="/_oauth",le="+Inf"} 1
http_request_duration_seconds_sum{code="307",method="",path="/_oauth"} 0.01
http_request_duration_seconds_count{code="307",method="",path="/_oauth"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="0.005"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="0.01"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="0.025"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="0.05"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="0.1"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="0.25"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="0.5"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="1"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="2.5"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="5"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="10"} 1
http_request_duration_seconds_bucket{code="401",method="",path="/_oauth/logout",le="+Inf"} 1
http_request_duration_seconds_sum{code="401",method="",path="/_oauth/logout"} 0.005
http_request_duration_seconds_count{code="401",method="",path="/_oauth/logout"} 1
# HELP http_requests_total total number of http requests
# TYPE http_requests_total counter
http_requests_total{code="200",method="",path="/"} 1
http_requests_total{code="307",method="",path="/"} 1
http_requests_total{code="307",method="",path="/_oauth"} 1
http_requests_total{code="401",method="",path="/_oauth/logout"} 1
`)))
}
