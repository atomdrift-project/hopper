package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// seedUnconvictedQueue inserts n unknown-labeled samples carrying a hostile trait, which
// is TriageNew's population. The recipe mirrors hopper's own triage tests:
// insert, then store a cleave result whose single file entry carries a trait
// level, because queue membership is computed from the stored analysis rather
// than from the row alone.
func seedUnconvictedQueue(t *testing.T, ctx context.Context, db *hopper.DB, n int) {
	t.Helper()
	for i := range n {
		sha := fmt.Sprintf("%064x", i+1)
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha,
			Label:  "unknown",
			Path:   fmt.Sprintf("incoming/forager/%d.tgz", i),
		}); err != nil {
			t.Fatalf("InsertSample(%s): %v", sha, err)
		}
		// Two crit-4 traits, not one: unconvicted-suspicious now requires
		// suspicious_count > 1 unconditionally (the OR label='unknown' arm was
		// removed to bound the population), so a single suspicious finding no
		// longer selects and this fixture would seed an empty queue.
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":0,"dp":0,"ts":[{"l":4},{"l":4}]}]}`, sha)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult(%s): %v", sha, err)
		}
	}
}

func newTriageAPI(t *testing.T, ctx context.Context) *apiServer {
	t.Helper()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "hopper.db"))
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return &apiServer{db: db, tracker: newWorkerTracker()}
}

// selectFrom issues one GET /api/triage/{queue} and decodes the envelope.
func selectFrom(t *testing.T, api *apiServer, queue, query string) (shas []string, code int) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/triage/"+queue+query, http.NoBody)
	r.SetPathValue("queue", queue)
	rec := httptest.NewRecorder()
	api.handleTriageSelect(rec, r)
	if rec.Code != http.StatusOK {
		return nil, rec.Code
	}
	var body struct {
		Samples []*hopper.Sample `json:"samples"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode select body: %v (%s)", err, rec.Body.Bytes())
	}
	for _, s := range body.Samples {
		shas = append(shas, s.SHA256)
	}
	return shas, rec.Code
}

// TestTriageSelectIsARead pins the contract: a select claims nothing, so
// repeated selects return the same head and limit alone bounds the result.
// Who works which sample is the consumer's to decide; the lease this replaced
// held every returned row for two hours and stranded whole queues.
func TestTriageSelectIsARead(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedUnconvictedQueue(t, ctx, api.db, 6)

	first, code := selectFrom(t, api, "unconvicted-suspicious", "?limit=3")
	if code != http.StatusOK || len(first) != 3 {
		t.Fatalf("first select = %v, status %d; want 3 samples", first, code)
	}
	second, _ := selectFrom(t, api, "unconvicted-suspicious", "?limit=3")
	if !slices.Equal(first, second) {
		t.Errorf("second select = %v, want the same head %v", second, first)
	}
	all, _ := selectFrom(t, api, "unconvicted-suspicious", "?limit=64")
	if len(all) != 6 {
		t.Errorf("wide select returned %d samples, want all 6", len(all))
	}
}

// TestTriageQueuesListsRegistry proves the endpoint a client validates its own
// per-queue policy tables against reports the real registry, including which
// queues can answer /depth.
func TestTriageQueuesListsRegistry(t *testing.T) {
	api := &apiServer{}
	rec := httptest.NewRecorder()
	api.handleTriageQueues(rec, httptest.NewRequest(http.MethodGet, "/api/triage/queues", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Queues []struct {
			Name  string `json:"name"`
			Depth bool   `json:"depth"`
		} `json:"queues"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.Bytes())
	}
	if len(body.Queues) != len(hopper.TriageQueues) {
		t.Fatalf("listed %d queues, registry has %d", len(body.Queues), len(hopper.TriageQueues))
	}
	for i, q := range body.Queues {
		reg, ok := hopper.TriageQueues[q.Name]
		if !ok {
			t.Errorf("listed unknown queue %q", q.Name)
			continue
		}
		if reg.Select == nil {
			t.Errorf("queue %q: registry entry has no Select", q.Name)
		}
		// Every registered queue can answer a depth: it is the selection counted.
		if !q.Depth {
			t.Errorf("queue %q: depth = false, want true", q.Name)
		}
		// Sorted, because a client's worker start order derives from this list
		// and Go randomizes map iteration.
		if i > 0 && body.Queues[i-1].Name >= q.Name {
			t.Errorf("queues are not sorted: %q before %q", body.Queues[i-1].Name, q.Name)
		}
	}
}

func TestTriageSelectUnknownQueue(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)

	_, code := selectFrom(t, api, "nosuchqueue", "")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}

	// The 404 names the valid set, so an operator typo is self-correcting.
	r := httptest.NewRequest(http.MethodGet, "/api/triage/nosuchqueue", http.NoBody)
	r.SetPathValue("queue", "nosuchqueue")
	rec := httptest.NewRecorder()
	api.handleTriageSelect(rec, r)
	var body struct {
		Queues []string `json:"queues"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.Bytes())
	}
	if len(body.Queues) != len(hopper.TriageQueues) {
		t.Errorf("404 body listed %d queues, registry has %d", len(body.Queues), len(hopper.TriageQueues))
	}
}

// TestTriageSelectLimit covers the parsing boundary: a bad limit is reported
// rather than silently defaulted, because the caller asked for something
// specific and would otherwise never find out it did not get it.
func TestTriageSelectLimit(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedUnconvictedQueue(t, ctx, api.db, 3)

	for _, bad := range []string{"?limit=0", "?limit=-1", "?limit=abc"} {
		if _, code := selectFrom(t, api, "unconvicted-suspicious", bad); code != http.StatusBadRequest {
			t.Errorf("limit %q: status = %d, want 400", bad, code)
		}
	}
	// Absent limit uses the default rather than erroring.
	if _, code := selectFrom(t, api, "unconvicted-suspicious", ""); code != http.StatusOK {
		t.Errorf("no limit: status = %d, want 200", code)
	}
	// An oversized limit is clamped, not refused: the caller still gets work.
	got, code := selectFrom(t, api, "unconvicted-suspicious", "?limit=100000")
	if code != http.StatusOK {
		t.Fatalf("huge limit: status = %d, want 200", code)
	}
	if len(got) != 3 {
		t.Errorf("huge limit returned %d samples, want the 3 that exist", len(got))
	}
}

func TestTriageDepth(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedUnconvictedQueue(t, ctx, api.db, 4)

	depth := func(queue string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/triage/"+queue+"/depth", http.NoBody)
		r.SetPathValue("queue", queue)
		rec := httptest.NewRecorder()
		api.handleTriageDepth(rec, r)
		return rec
	}

	rec := depth("unconvicted-suspicious")
	if rec.Code != http.StatusOK {
		t.Fatalf("new depth: status = %d body = %s", rec.Code, rec.Body.Bytes())
	}
	var body struct {
		Queue  string `json:"queue"`
		Depth  int64  `json:"depth"`
		Capped bool   `json:"capped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Queue != "unconvicted-suspicious" {
		t.Errorf("queue = %q, want new", body.Queue)
	}
	if body.Depth != 4 {
		t.Errorf("depth = %d, want 4", body.Depth)
	}
	if body.Capped {
		t.Errorf("capped = true for a depth of %d", body.Depth)
	}

	// The queues that used to have no countable population now answer like any
	// other: their depth is their own selection counted, so there is no
	// "uncountable" case left to 404 on.
	if rec := depth("acquit"); rec.Code != http.StatusOK {
		t.Errorf("acquit depth: status = %d, want 200 — every queue answers a depth now", rec.Code)
	}
	if rec := depth("nosuchqueue"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown queue depth: status = %d, want 404", rec.Code)
	}
}

// TestTriageRoutesAreReadOnlySafe proves the triage routes are registered on a
// read-only replica — that is the deployment they exist for — and that adding
// them did not accidentally open one of the mutating routes.
func TestTriageRoutesAreReadOnlySafe(t *testing.T) {
	api := &apiServer{readOnly: true}
	mux := http.NewServeMux()
	api.registerAPI(mux)

	for _, path := range []string{"/api/triage/queues", "/api/triage/new", "/api/triage/new/depth"} {
		r := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		if _, pattern := mux.Handler(r); pattern == "" {
			t.Errorf("%s is not routed on a read-only replica", path)
		}
	}

	// The ruling endpoint shares the /api/triage prefix and must still refuse.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/triage", http.NoBody))
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /api/triage on a replica: status = %d, want 403", rec.Code)
	}
}
