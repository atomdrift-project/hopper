package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func TestLookupCachePrometheusMetrics(t *testing.T) {
	db, err := hopper.Open(t.Context(), filepath.Join(t.TempDir(), "cache.db"), "hopper-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Wait for the asynchronous estimate without making an HTTP scrape do
	// cache traversal. Empty caches still own structural storage.
	deadline := time.Now().Add(time.Second)
	for {
		s := db.CacheStatistics()
		if !s[0].MemorySampledAt.IsZero() && !s[1].MemorySampledAt.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("memory estimate never completed")
		}
		time.Sleep(time.Millisecond)
	}
	reg := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		t.Fatal(err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	wd := &webDashboard{db: db}
	if err := wd.registerMetrics(provider.Meter(meterName)); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape failed: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, cache := range []string{"sample", "record"} {
		for _, metric := range []string{"hopper_cache_entries", "hopper_cache_capacity", "hopper_cache_requests_total", "hopper_cache_memory_estimated_bytes", "hopper_cache_memory_sampled_at_seconds"} {
			if !strings.Contains(body, metric+`{cache="`+cache+`"`) {
				t.Errorf("missing %s for %s", metric, cache)
			}
		}
	}
	for _, source := range []string{"cache", "database"} {
		if !strings.Contains(body, `source="`+source+`"`) {
			t.Errorf("missing source %s", source)
		}
	}
}
