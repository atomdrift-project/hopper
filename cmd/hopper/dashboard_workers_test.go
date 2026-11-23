package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWorkersJSONListsTheTrackedFleetSorted(t *testing.T) {
	tracker := newWorkerTracker()
	tracker.update("nazgul:10.9.8.5", 8, "0.9.5", "deed8", 0, 0, "")
	tracker.update("gandalf:10.9.8.3", 8, "0.9.5", "deed8", 0, 0, "")
	tracker.update("uruk-hai-idle", 4, "0.9.0", "deed8", 0, 0, "")
	wd := &webDashboard{tracker: tracker}

	rec := httptest.NewRecorder()
	wd.workersJSON(rec, httptest.NewRequest(http.MethodGet, "/workers.json", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var rows []workerRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("body is not the documented JSON: %v\n%s", err, rec.Body)
	}
	want := []struct{ name, version string }{
		{"gandalf:10.9.8.3", "0.9.5"},
		{"nazgul:10.9.8.5", "0.9.5"},
		{"uruk-hai-idle", "0.9.0"},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d workers, want %d: %+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		if rows[i].Name != w.name || rows[i].Version != w.version {
			t.Errorf("row %d = %s %s, want %s %s", i, rows[i].Name, rows[i].Version, w.name, w.version)
		}
		if age := time.Since(rows[i].LastSeen); age < 0 || age > time.Minute {
			t.Errorf("row %d last_seen age = %s, want just now", i, age)
		}
	}
}

func TestWorkersJSONEmptyFleetIsAnArrayNotNull(t *testing.T) {
	wd := &webDashboard{tracker: newWorkerTracker()}
	rec := httptest.NewRecorder()
	wd.workersJSON(rec, httptest.NewRequest(http.MethodGet, "/workers.json", http.NoBody))
	if got := rec.Body.String(); got != "[]\n" {
		t.Errorf("body = %q, want %q: a consumer iterating it must not meet null", got, "[]\n")
	}
}

func TestWorkersJSONWhileStartingIsRetryableNotEmpty(t *testing.T) {
	wd := &webDashboard{}
	rec := httptest.NewRecorder()
	wd.workersJSON(rec, httptest.NewRequest(http.MethodGet, "/workers.json", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503: an empty list before the tracker exists reads as a vanished fleet", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After")
	}
}
