package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// TestRegisterMetrics wires the dashboard instruments to an isolated meter and
// Prometheus registry (so the global OTel state other tests touch can't leak
// in), registers them against an in-memory dashboard, and scrapes the registry.
// It asserts the local-worker liveness gauge and a per-worker series render, and
// pins the exact exported metric names — OTel mangles dots and appends unit
// suffixes — so the alert rules in scripts/prometheus-hopper-alerts.yml stay in
// step with the instrument definitions.
func TestRegisterMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		t.Fatalf("prometheus exporter: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Logf("meter provider shutdown: %v", err)
		}
	})

	wd := &webDashboard{}

	// Local scan worker reported down.
	litmus := &litmusServer{}
	litmus.setHealth(false, "test: crashed", "")
	wd.litmus = litmus

	// One remote worker last seen a while ago, plus some ingest progress.
	tracker := newWorkerTracker()
	tracker.workers["edge:10.0.0.5"] = &workerStats{
		LastSeen: time.Now().Add(-90 * time.Second),
		Slots:    4, ActiveClaims: 2, Analyzed: 1234, Errors: 5, RSSMB: 512,
	}
	wd.tracker = tracker

	var progress loadProgress
	progress.analyzed.Store(99)
	progress.walked.Store(4242)
	progress.insertFails[causeLockTimeout].Store(7)
	wd.progress = &progress

	if err := wd.registerMetrics(provider.Meter(meterName)); err != nil {
		t.Fatalf("registerMetrics: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d", rec.Code)
	}
	body := rec.Body.String()

	// Exact exported names the alert rules depend on (OTel maps dots to
	// underscores and appends unit suffixes; the dimensionless gauges must NOT
	// gain a _ratio suffix).
	want := []string{
		"hopper_local_worker_up{",
		"hopper_worker_last_seen_age_seconds{",
		`worker="edge:10.0.0.5"`,
		"hopper_analyzed_total",
		"hopper_walk_files_total",
		`hopper_insert_failures_total{cause="lock_timeout"`,
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("scrape missing %q\n---\n%s", w, metricLines(body, "hopper_"))
		}
	}
	if strings.Contains(body, "hopper_local_worker_up_ratio") {
		t.Error("local_worker_up gained a _ratio suffix; drop its unit")
	}
	// The local worker was reported down, so the gauge must read 0.
	for ln := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(ln, "hopper_local_worker_up{") && !strings.HasSuffix(ln, " 0") {
			t.Errorf("local_worker_up not 0 while down: %s", ln)
		}
	}
}

// TestClassifyInsertFailure pins the SQLSTATE-to-cause mapping the insert
// failure metric depends on. Lock contention (55P03 / SQLite "database is
// locked") is the case the 2026-06-14 silent ingestion outage hinged on, so it
// gets explicit coverage alongside the other transient and permanent classes.
func TestClassifyInsertFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want insertFailCause
	}{
		{"nil", nil, causeOther},
		{"lock_timeout", &pgconn.PgError{Code: "55P03"}, causeLockTimeout},
		{"statement_timeout", &pgconn.PgError{Code: "57014"}, causeStatementTimeout},
		{"serialization", &pgconn.PgError{Code: "40001"}, causeSerialization},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, causeDeadlock},
		{"constraint", &pgconn.PgError{Code: "23505"}, causeConstraint},
		{"data", &pgconn.PgError{Code: "22021"}, causeData},
		{"connection", &pgconn.PgError{Code: "08006"}, causeConnection},
		{"context_deadline", fmt.Errorf("insert: %w", context.DeadlineExceeded), causeContext},
		{"context_canceled", context.Canceled, causeContext},
		{"sqlite_locked", errors.New("database is locked"), causeLockTimeout},
		{"unknown", errors.New("disk full"), causeOther},
		{"wrapped_pg", fmt.Errorf("batch insert: %w", &pgconn.PgError{Code: "55P03"}), causeLockTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInsertFailure(tt.err); got != tt.want {
				t.Errorf("classifyInsertFailure(%v) = %s, want %s", tt.err, got, tt.want)
			}
		})
	}
}

// metricLines returns the body lines mentioning prefix, for failure context.
func metricLines(body, prefix string) string {
	var b strings.Builder
	for ln := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(ln, prefix) {
			b.WriteString(ln)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
