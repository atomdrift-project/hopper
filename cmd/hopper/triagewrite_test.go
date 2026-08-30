package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

func postJSON(t *testing.T, h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

// TestHandleReportDrainsAQueue proves the endpoint writes the row a selector
// anti-joins on: after filing an "unconvicted-suspicious-stale" report the sample leaves that
// queue, which is the whole purpose of the write.
func TestHandleReportDrainsAQueue(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedUnconvictedQueue(t, ctx, api.db, 1)
	const sha = "0000000000000000000000000000000000000000000000000000000000000001"

	before, err := hopper.TriageQueues["unconvicted-suspicious-stale"].Select(ctx, api.db, 5)
	if err != nil {
		t.Fatalf("select before: %v", err)
	}
	if len(before) != 1 {
		t.Fatalf("unconvicted-suspicious-stale returned %d rows before the drain, want 1", len(before))
	}

	rec := postJSON(t, api.handleReport, "/api/report",
		`{"sha256":"`+sha+`","type":"unconvicted-suspicious-stale","provider":"test","content":"judgement=confirmed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.Bytes())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "recorded" {
		t.Errorf("status = %q, want recorded", got["status"])
	}

	after, err := hopper.TriageQueues["unconvicted-suspicious-stale"].Select(ctx, api.db, 5)
	if err != nil {
		t.Fatalf("select after: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("unconvicted-suspicious-stale returned %d rows after the drain, want 0 — the report did not drain the queue", len(after))
	}
}

func TestHandleReportRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedUnconvictedQueue(t, ctx, api.db, 1)
	const sha = "0000000000000000000000000000000000000000000000000000000000000001"

	for name, body := range map[string]string{
		"invalid sha":  `{"sha256":"nope","type":"unconvicted-suspicious-stale"}`,
		"missing sha":  `{"type":"unconvicted-suspicious-stale"}`,
		"empty type":   `{"sha256":"` + sha + `","type":""}`,
		"missing type": `{"sha256":"` + sha + `"}`,
		"bad json":     `{`,
	} {
		if rec := postJSON(t, api.handleReport, "/api/report", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}

	// An unrecognized type is warned about, not refused: "re", "gap" and "fpr"
	// are other producers' and the set is open.
	rec := postJSON(t, api.handleReport, "/api/report", `{"sha256":"`+sha+`","type":"gap"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("unknown-but-legitimate type: status = %d, want 200", rec.Code)
	}
}

// TestHandleCleaveResultStores proves the write-back lands on the column the
// caller recomputed, with the traits version derived server-side.
func TestHandleCleaveResultStores(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	const sha = "0000000000000000000000000000000000000000000000000000000000000001"
	if err := api.db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Label: "good", Path: "incoming/forager/a.tgz",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	result := `{"tv":"traits-42","fs":[{"sha":"` + sha + `","type":"elf","dp":0,"ts":[{"l":4}]}]}`
	rec := postJSON(t, api.handleCleaveResult, "/api/cleave-result",
		`{"sha256":"`+sha+`","result":`+result+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.Bytes())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "stored" {
		t.Fatalf("status = %q, want stored", got["status"])
	}

	stored, err := api.db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if len(stored.CleaveResult) == 0 {
		t.Fatal("cleave_result was not written")
	}
	if stored.FileType != "elf" {
		t.Errorf("file_type = %q, want elf — the server-side parse did not derive it", stored.FileType)
	}
}

// TestHandleCleaveResultRefusesEmptyResult is the guard that matters most here.
// UpdateCleaveResult DELETES a sample whose envelope parses to no file type, so
// a caller that forgot to attach its scan must be refused rather than silently
// removing the row.
func TestHandleCleaveResultRefusesEmptyResult(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	const sha = "0000000000000000000000000000000000000000000000000000000000000001"
	if err := api.db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Label: "good", Path: "incoming/forager/a.tgz",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	for name, body := range map[string]string{
		"absent result": `{"sha256":"` + sha + `"}`,
		"invalid sha":   `{"sha256":"nope","result":{"fs":[]}}`,
		"bad json":      `{`,
	} {
		if rec := postJSON(t, api.handleCleaveResult, "/api/cleave-result", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}

	// The sample must still be there: a refused write cannot have deleted it.
	if _, err := api.db.SampleBySHA256(ctx, sha); err != nil {
		t.Fatalf("sample was removed by a refused write-back: %v", err)
	}
}

// TestTriageWritesRefusedOnReplica proves both new endpoints are behind the
// read-only front door. A logical subscriber is a writable Postgres primary, so
// a write reaching one diverges it from the publisher until replication wedges.
func TestTriageWritesRefusedOnReplica(t *testing.T) {
	mux := http.NewServeMux()
	(&apiServer{readOnly: true}).registerAPI(mux)

	for _, path := range []string{"/api/report", "/api/cleave-result"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s on a replica: status = %d, want 403", path, rec.Code)
		}
	}

	// And they ARE served on a primary, or the refusal above proves nothing.
	primary := http.NewServeMux()
	(&apiServer{}).registerAPI(primary)
	for _, path := range []string{"/api/report", "/api/cleave-result"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		if _, pattern := primary.Handler(r); pattern == "" {
			t.Errorf("POST %s is not routed on a primary", path)
		}
	}
}
