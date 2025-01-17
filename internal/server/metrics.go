package server

import (
	"github.com/clambin/go-common/httputils/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	"strconv"
	"time"
)

var _ metrics.RequestMetrics = &Metrics{}

type Metrics struct {
	requestDuration *prometheus.HistogramVec
	requestCounter  *prometheus.CounterVec
}

func NewMetrics(namespace, subsystem string, constLabels prometheus.Labels, buckets ...float64) *Metrics {
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

func (m Metrics) Measure(r *http.Request, statusCode int, duration time.Duration) {
	email, _ := getAuthenticatedUserEmail(r)
	code := strconv.Itoa(statusCode)
	path := r.URL.Path
	if path != OAUTHPath && path != OAUTHPath+"/logout" {
		path = "/"
	}
	m.requestCounter.WithLabelValues(email, r.URL.Host, path, code).Inc()
	m.requestDuration.WithLabelValues(email, r.URL.Host, path, code).Observe(duration.Seconds())
}

func (m Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.requestCounter.Describe(ch)
	m.requestDuration.Describe(ch)
}

func (m Metrics) Collect(ch chan<- prometheus.Metric) {
	m.requestCounter.Collect(ch)
	m.requestDuration.Collect(ch)
}
