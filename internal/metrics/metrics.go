package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ScanMetrics holds Prometheus metrics for TLS scan operations.
type ScanMetrics struct {
	TLSScansTotal       *prometheus.CounterVec
	TLSScanDuration     *prometheus.HistogramVec
	TLSScanSuccessTotal *prometheus.CounterVec
	TLSScanErrorTotal   *prometheus.CounterVec
}

var defaultMetrics *ScanMetrics

// Init initializes the default metrics instance.
func Init() *ScanMetrics {
	if defaultMetrics != nil {
		return defaultMetrics
	}

	defaultMetrics = &ScanMetrics{
		TLSScansTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cafe_scanner_tls_scans_total",
				Help: "Total number of TLS scans performed",
			},
			[]string{"scan_type"},
		),
		TLSScanDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "cafe_scanner_tls_scan_duration_seconds",
				Help:    "Duration of TLS scans in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"scan_type"},
		),
		TLSScanSuccessTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cafe_scanner_tls_scan_success_total",
				Help: "Total number of successful TLS scans",
			},
			[]string{"scan_type", "result"},
		),
		TLSScanErrorTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cafe_scanner_tls_scan_error_total",
				Help: "Total number of failed TLS scans",
			},
			[]string{"scan_type", "result"},
		),
	}

	return defaultMetrics
}

// Get returns the default metrics instance, initializing it if necessary.
func Get() *ScanMetrics {
	if defaultMetrics == nil {
		return Init()
	}
	return defaultMetrics
}

// RecordTLSScan records metrics for a TLS scan operation.
func (m *ScanMetrics) RecordTLSScan(duration time.Duration, success bool) {
	scanType := "tls"
	m.TLSScansTotal.WithLabelValues(scanType).Inc()
	m.TLSScanDuration.WithLabelValues(scanType).Observe(duration.Seconds())
	if success {
		m.TLSScanSuccessTotal.WithLabelValues(scanType, "success").Inc()
	} else {
		m.TLSScanErrorTotal.WithLabelValues(scanType, "failure").Inc()
	}
}
