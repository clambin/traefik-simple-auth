package server

import (
	"github.com/clambin/go-common/http/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	"strconv"
	"time"
)

var _ metrics.RequestMetrics = &Metrics{}

type Metrics struct {
	server          *Server
	requestDuration *prometheus.HistogramVec
	requestCounter  *prometheus.CounterVec
}

func NewMetrics(namespace, subsystem string, constLabels map[string]string, buckets ...float64) *Metrics {
	if len(buckets) == 0 {
		buckets = []float64{0.0001, 0.0005, 0.001, .005, .01, .05, .1, .5, 1}
	}
	return &Metrics{
		//server: nil,
		requestCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        metrics.RequestTotal,
			Help:        "total number of http requests",
			ConstLabels: constLabels,
		},
			[]string{"user", "domain", "host", "path", "code"},
		),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        metrics.RequestsDuration,
			Help:        "duration of http requests",
			ConstLabels: constLabels,
			Buckets:     buckets,
		},
			[]string{"user", "domain", "host", "path", "code"},
		),
	}
}

func (m Metrics) Measure(req *http.Request, statusCode int, duration time.Duration) {
	sess, _ := m.server.sessions.Validate(req)
	domain, _ := m.server.domains.Domain(req.URL)
	code := strconv.Itoa(statusCode)
	path := req.URL.Path
	if path != OAUTHPath && path != OAUTHPath+"/logout" {
		path = "/"
	}
	m.requestCounter.WithLabelValues(sess.Email, domain, req.URL.Host, path, code).Inc()
	m.requestDuration.WithLabelValues(sess.Email, domain, req.URL.Host, path, code).Observe(duration.Seconds())
}

func (m Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.requestCounter.Describe(ch)
	m.requestDuration.Describe(ch)
}

func (m Metrics) Collect(ch chan<- prometheus.Metric) {
	m.requestCounter.Collect(ch)
	m.requestDuration.Collect(ch)
}
