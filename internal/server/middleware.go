package server

import (
	"context"
	"github.com/clambin/go-common/http/metrics"
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/traefik-simple-auth/internal/server/session"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	"strconv"
	"time"
)

type sessionKeyCtx string

var SessionKey sessionKeyCtx = "sessionKey"

func (s *Server) sessionExtractor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userSession, err := s.sessions.Validate(r); err == nil {
			ctx := context.WithValue(r.Context(), SessionKey, userSession)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////////

func (s *Server) withMetrics(m *Metrics) func(next http.Handler) http.Handler {
	return middleware.WithRequestMetrics(m)
}

var _ metrics.RequestMetrics = &Metrics{}

type Metrics struct {
	requestDuration *prometheus.HistogramVec
	requestCounter  *prometheus.CounterVec
}

func NewMetrics(namespace, subsystem string, constLabels map[string]string, buckets ...float64) *Metrics {
	if len(buckets) == 0 {
		buckets = []float64{0.0001, 0.0005, 0.001, .005, .01, .05, .1, .5, 1}
	}
	return &Metrics{
		requestCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        metrics.RequestTotal,
			Help:        "total number of http requests",
			ConstLabels: constLabels,
		},
			[]string{"user", "host", "path", "code"},
		),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        metrics.RequestsDuration,
			Help:        "duration of http requests",
			ConstLabels: constLabels,
			Buckets:     buckets,
		},
			[]string{"user", "host", "path", "code"},
		),
	}
}

func (m Metrics) Measure(req *http.Request, statusCode int, duration time.Duration) {
	sess, _ := req.Context().Value(SessionKey).(session.Session)
	code := strconv.Itoa(statusCode)
	path := req.URL.Path
	if path != OAUTHPath && path != OAUTHPath+"/logout" {
		path = "/"
	}
	m.requestCounter.WithLabelValues(sess.Email, req.URL.Host, path, code).Inc()
	m.requestDuration.WithLabelValues(sess.Email, req.URL.Host, path, code).Observe(duration.Seconds())
}

func (m Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.requestCounter.Describe(ch)
	m.requestDuration.Describe(ch)
}

func (m Metrics) Collect(ch chan<- prometheus.Metric) {
	m.requestCounter.Collect(ch)
	m.requestDuration.Collect(ch)
}