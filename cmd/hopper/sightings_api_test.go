package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postSightings drives handleSightings with the given body + content type and
// returns the recorder.
func postSightings(t *testing.T, api *apiServer, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/sightings", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	api.handleSightings(rec, req)
	return rec
}

func TestHandleSightingsJSONArrayAndNDJSON(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t, ctx, t.TempDir()+"/hopper.db")
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db}

	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// JSON array form.
	rec := postSightings(t, api, "application/json",
		`[{"source":"socket","subject":"`+sha+`","note":"malware"},`+
			`{"source":"aikido","subject":"pkg:npm/evil","note":"malware"}]`)
	if rec.Code != http.StatusOK {
		t.Fatalf("array status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp sightingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Changed != 2 {
		t.Fatalf("array changed = %d, want 2", resp.Changed)
	}

	// NDJSON form — one new record, one duplicate of the array push (no change).
	rec = postSightings(t, api, "application/x-ndjson",
		`{"source":"osv","subject":"pkg:npm/evil","note":"MAL-1"}`+"\n"+
			`{"source":"socket","subject":"`+sha+`","note":"malware"}`+"\n")
	if rec.Code != http.StatusOK {
		t.Fatalf("ndjson status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Changed != 1 {
		t.Fatalf("ndjson changed = %d, want 1 (one new, one duplicate)", resp.Changed)
	}

	// Verify the store: purl has two sources now (aikido, osv).
	m, err := db.SightingsFor(ctx, []string{"pkg:npm/evil"})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(m["pkg:npm/evil"]) != 2 {
		t.Fatalf("purl sightings = %d, want 2", len(m["pkg:npm/evil"]))
	}
}

func TestHandleSightingsUppercaseSHANormalized(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t, ctx, t.TempDir()+"/hopper.db")
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db}

	const upper = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const lower = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rec := postSightings(t, api, "application/json",
		`[{"source":"vt","subject":"`+upper+`"}]`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	m, err := db.SightingsFor(ctx, []string{lower})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(m[lower]) != 1 {
		t.Fatalf("lowercased sha lookup = %d rows, want 1 (subject should be normalized)", len(m[lower]))
	}
}

func TestHandleSightingsBadJSON(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t, ctx, t.TempDir()+"/hopper.db")
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db}

	rec := postSightings(t, api, "application/json", `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleSightingsStarting(t *testing.T) {
	api := &apiServer{} // db nil
	rec := postSightings(t, api, "application/json", `[]`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
