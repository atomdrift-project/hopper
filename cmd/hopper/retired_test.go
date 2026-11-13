package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An old path answers 410 with the route that replaced it, whatever the
// method, and does not shadow the new tree.
func TestRetiredPaths(t *testing.T) {
	mux := http.NewServeMux()
	(&apiServer{}).registerAPI(mux)
	for _, c := range []struct {
		method, path, use string
	}{
		{http.MethodGet, "/api/next?worker=w", "/v1/work/next"},
		{http.MethodPost, "/api/next", "/v1/work/next"},
		{http.MethodPost, "/api/triage", "/v1/triage/rulings"},
		{http.MethodGet, "/api/triage/scoreboard", "/v1/triage/{queue}"},
		{http.MethodGet, "/api/provenance/" + strings.Repeat("a", 64), "/v1/files/{sha256}/provenance"},
		{http.MethodPost, "/api/known", "/v1/intake/held"},
		{http.MethodGet, "/healthz", "/_/health"},
		{http.MethodGet, "/data/bad/x.bin", "/v1/files/{sha256}"},
		{http.MethodPost, "/api/release", ""},
		{http.MethodGet, "/api/never-was", ""},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, http.NoBody))
		var body struct {
			Error struct {
				Code string `json:"code"`
				Use  string `json:"use"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: %v: %s", c.method, c.path, err, rec.Body.Bytes())
		}
		if rec.Code != http.StatusGone || body.Error.Code != "retired" || body.Error.Use != c.use {
			t.Errorf("%s %s = %d %+v, want 410 retired, use %q", c.method, c.path, rec.Code, body.Error, c.use)
		}
	}
	// The new tree is not shadowed: a new path reaches its handler, which
	// with no database answers anything but 410.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/lookup?sha256="+strings.Repeat("a", 64), http.NoBody))
	if rec.Code == http.StatusGone {
		t.Error("/v1/lookup answered as retired")
	}
}

func TestThrottle(t *testing.T) {
	th := &throttle{every: time.Minute, last: map[string]time.Time{}}
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	if !th.due("k", now) || th.due("k", now.Add(30*time.Second)) || !th.due("k", now.Add(61*time.Second)) {
		t.Error("want the first call logged, one 30 s later held, one past the minute logged")
	}
	if !th.due("other", now) {
		t.Error("a second key waits on the first")
	}
}
