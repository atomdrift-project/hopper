package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// With the verdict store open the dashboard renders the store's corpus: its
// queue, its newest arrival, and the page does not read the legacy tables.
func TestDashboardFromStore(t *testing.T) {
	api, st, _ := verdictAPI(t)
	ctx := t.Context()
	waiting := hexSum([]byte("waiting for a scan"))
	if _, err := ingest(ctx, st, []*hopper.Sample{
		{SHA256: waiting, SizeBytes: 900, Path: "incoming/feeds/waiting.bin", Source: "walk", Feed: "testfeed", Label: "unknown"},
	}, store.QueueNew); err != nil {
		t.Fatal(err)
	}
	wd := &webDashboard{}
	progress := &loadProgress{}
	wd.configure(progress, nil, newWorkerTracker(), api, api.db, time.Now(), 0, 1, "", time.Hour, nil)

	pending, depths, err := queueDepths(ctx, api.db, st, time.Hour)
	if err != nil || pending != 1 || depths.Total() != 0 {
		t.Errorf("queue depths %d %+v, %v; want the one file waiting", pending, depths, err)
	}
	if n, err := arrivalWatermark(ctx, api.db, st); err != nil || n < 1 {
		t.Errorf("watermark %d, %v", n, err)
	}

	rec := httptest.NewRecorder()
	wd.handler(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard: %d", rec.Code)
	}
	if page := rec.Body.String(); !strings.Contains(page, "testfeed") {
		t.Errorf("dashboard does not list the queued file's feed:\n%.2000s", page)
	}
}
