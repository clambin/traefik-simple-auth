package metrics

import (
	"github.com/clambin/go-common/http/metrics"
	"github.com/clambin/traefik-simple-auth/internal/server"
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

func New(namespace, subsystem string, constLabels map[string]string, buckets ...float64) *Metrics {
	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}
	return &Metrics{
		requestCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        metrics.RequestTotal,
			Help:        "total number of http requests",
			ConstLabels: constLabels,
		},
			[]string{"method", "path", "code"},
		),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        metrics.RequestsDuration,
			Help:        "duration of http requests",
			ConstLabels: constLabels,
			Buckets:     buckets,
		},
			[]string{"method", "path", "code"},
		),
	}
}

func (m Metrics) Measure(req *http.Request, statusCode int, duration time.Duration) {
	code := strconv.Itoa(statusCode)
	path := "/"
	if req.URL != nil && (req.URL.Path == server.OAUTHPath || req.URL.Path == server.OAUTHPath+"/logout") {
		path = req.URL.Path
	}
	m.requestCounter.WithLabelValues(req.Method, path, code).Inc()
	m.requestDuration.WithLabelValues(req.Method, path, code).Observe(duration.Seconds())

}

func (m Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.requestCounter.Describe(ch)
	m.requestDuration.Describe(ch)
}

func (m Metrics) Collect(ch chan<- prometheus.Metric) {
	m.requestCounter.Collect(ch)
	m.requestDuration.Collect(ch)
}
