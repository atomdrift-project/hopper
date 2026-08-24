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
	"time"

	"github.com/atomdrift-project/hopper"
)

// seedNewQueue inserts n unknown-labeled samples carrying a hostile trait, which
// is TriageNew's population. The recipe mirrors hopper's own triage tests:
// insert, then store a cleave result whose single file entry carries a trait
// level, because queue membership is computed from the stored analysis rather
// than from the row alone.
func seedNewQueue(t *testing.T, ctx context.Context, db *hopper.DB, n int) {
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
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":0,"dp":0,"ts":[{"l":4}]}]}`, sha)
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
	return &apiServer{db: db, tracker: newWorkerTracker(), triageClaims: newTriageClaims(triageClaimTTL)}
}

// selectFrom issues one GET /api/triage/{queue} and decodes the envelope.
func selectFrom(t *testing.T, api *apiServer, queue, query string) (shas []string, withheld int, code int) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/triage/"+queue+query, http.NoBody)
	r.SetPathValue("queue", queue)
	rec := httptest.NewRecorder()
	api.handleTriageSelect(rec, r)
	if rec.Code != http.StatusOK {
		return nil, 0, rec.Code
	}
	var body struct {
		Samples  []*hopper.Sample `json:"samples"`
		Withheld int              `json:"withheld"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode select body: %v (%s)", err, rec.Body.Bytes())
	}
	for _, s := range body.Samples {
		shas = append(shas, s.SHA256)
	}
	return shas, body.Withheld, rec.Code
}

// TestTriageSelectClaimsAcrossRequests is the whole reason the claim set exists:
// two clients reading the same queue window must not be handed the same sample.
// Before selection moved behind this API each scan host had its own in-process
// claim, which coordinated that host's workers and nothing else.
func TestTriageSelectClaimsAcrossRequests(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedNewQueue(t, ctx, api.db, 6)

	first, withheld, code := selectFrom(t, api, "new", "?limit=3")
	if code != http.StatusOK {
		t.Fatalf("first select: status = %d", code)
	}
	if len(first) != 3 {
		t.Fatalf("first select returned %d samples, want 3", len(first))
	}
	if withheld != 0 {
		t.Errorf("first select withheld = %d, want 0 (nothing claimed yet)", withheld)
	}

	second, withheld, code := selectFrom(t, api, "new", "?limit=3")
	if code != http.StatusOK {
		t.Fatalf("second select: status = %d", code)
	}
	if len(second) != 3 {
		t.Fatalf("second select returned %d samples, want 3", len(second))
	}
	if withheld != 3 {
		t.Errorf("second select withheld = %d, want 3 (the first select's claims)", withheld)
	}

	held := map[string]bool{}
	for _, sha := range first {
		held[sha] = true
	}
	for _, sha := range second {
		if held[sha] {
			t.Errorf("sample %s was handed to two callers — the claim did not hold", sha)
		}
	}

	// The population is exhausted, so a third caller gets nothing rather than a
	// repeat. withheld is what distinguishes that from a drained queue.
	third, withheld, _ := selectFrom(t, api, "new", "?limit=3")
	if len(third) != 0 {
		t.Errorf("third select returned %d samples, want 0 (all six claimed)", len(third))
	}
	if withheld != 6 {
		t.Errorf("third select withheld = %d, want 6", withheld)
	}
}

// Preview is observational: repeated previews return the same head and do not
// withhold it from the next real worker claim.
func TestTriageSelectPreviewDoesNotClaim(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedNewQueue(t, ctx, api.db, 3)

	first, withheld, code := selectFrom(t, api, "new", "?limit=2&preview=1")
	if code != http.StatusOK || len(first) != 2 || withheld != 0 {
		t.Fatalf("first preview = %v withheld=%d status=%d", first, withheld, code)
	}
	second, withheld, _ := selectFrom(t, api, "new", "?limit=2&preview=1")
	if !slices.Equal(first, second) || withheld != 0 {
		t.Fatalf("second preview = %v withheld=%d, want same %v and zero", second, withheld, first)
	}
	claimed, withheld, _ := selectFrom(t, api, "new", "?limit=2")
	if !slices.Equal(first, claimed) || withheld != 0 {
		t.Fatalf("claim after previews = %v withheld=%d, want %v and zero", claimed, withheld, first)
	}
}

// TestTriageClaimsExpire proves a claim is a lease, not a tombstone: a worker
// that dies mid-batch must not strand its samples forever.
func TestTriageClaimsExpire(t *testing.T) {
	ctx := context.Background()
	api := newTriageAPI(t, ctx)
	seedNewQueue(t, ctx, api.db, 2)
	api.triageClaims = newTriageClaims(time.Nanosecond)

	first, _, _ := selectFrom(t, api, "new", "?limit=2")
	if len(first) != 2 {
		t.Fatalf("first select returned %d, want 2", len(first))
	}
	// The TTL is a nanosecond, so both claims have already lapsed.
	second, withheld, _ := selectFrom(t, api, "new", "?limit=2")
	if len(second) != 2 {
		t.Errorf("second select returned %d, want 2 (claims should have lapsed)", len(second))
	}
	if withheld != 0 {
		t.Errorf("withheld = %d, want 0", withheld)
	}
}

// TestTriageClaimsSweepBoundsMap guards the memory bound. A sample that gets
// fixed leaves its queue and is never selected again, so pruning only on lookup
// would leave one permanent entry per sample the process ever served.
func TestTriageClaimsSweepBoundsMap(t *testing.T) {
	c := newTriageClaims(time.Nanosecond)
	for i := range 100 {
		s := &hopper.Sample{SHA256: fmt.Sprintf("%064x", i)}
		if taken, _ := c.claim([]*hopper.Sample{s}, 1); len(taken) != 1 {
			t.Fatalf("claim %d: got %d samples, want 1", i, len(taken))
		}
	}
	// Every claim lapsed as it was made, so the sweep on the final call should
	// have left only that call's own entry behind.
	if got := c.held(); got > 1 {
		t.Errorf("held = %d after 100 expired claims, want <= 1 — the sweep is not bounding the map", got)
	}
}

// TestTriageClaimsWithholdsOnlyLiveClaims covers the claim/withheld accounting
// directly, without a database in the way.
func TestTriageClaimsWithholdsOnlyLiveClaims(t *testing.T) {
	c := newTriageClaims(time.Hour)
	candidates := make([]*hopper.Sample, 0, 4)
	for i := range 4 {
		candidates = append(candidates, &hopper.Sample{SHA256: fmt.Sprintf("%064x", i)})
	}

	taken, withheld := c.claim(candidates, 2)
	if len(taken) != 2 || withheld != 0 {
		t.Fatalf("first claim: taken = %d withheld = %d, want 2 and 0", len(taken), withheld)
	}
	// Asking again walks past the two live claims and takes the rest.
	taken, withheld = c.claim(candidates, 2)
	if len(taken) != 2 {
		t.Errorf("second claim: taken = %d, want 2", len(taken))
	}
	if withheld != 2 {
		t.Errorf("second claim: withheld = %d, want 2", withheld)
	}
	// n bounds what is taken even when more is unclaimed.
	c2 := newTriageClaims(time.Hour)
	if taken, _ := c2.claim(candidates, 1); len(taken) != 1 {
		t.Errorf("bounded claim: taken = %d, want 1", len(taken))
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
		if want := reg.Depth != nil; q.Depth != want {
			t.Errorf("queue %q: depth = %v, want %v", q.Name, q.Depth, want)
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

	_, _, code := selectFrom(t, api, "nosuchqueue", "")
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
	seedNewQueue(t, ctx, api.db, 3)

	for _, bad := range []string{"?limit=0", "?limit=-1", "?limit=abc"} {
		if _, _, code := selectFrom(t, api, "new", bad); code != http.StatusBadRequest {
			t.Errorf("limit %q: status = %d, want 400", bad, code)
		}
	}
	// Absent limit uses the default rather than erroring.
	if _, _, code := selectFrom(t, api, "new", ""); code != http.StatusOK {
		t.Errorf("no limit: status = %d, want 200", code)
	}
	// An oversized limit is clamped, not refused: the caller still gets work.
	api.triageClaims = newTriageClaims(triageClaimTTL)
	got, _, code := selectFrom(t, api, "new", "?limit=100000")
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
	seedNewQueue(t, ctx, api.db, 4)

	depth := func(queue string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/triage/"+queue+"/depth", http.NoBody)
		r.SetPathValue("queue", queue)
		rec := httptest.NewRecorder()
		api.handleTriageDepth(rec, r)
		return rec
	}

	rec := depth("new")
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
	if body.Queue != "new" {
		t.Errorf("queue = %q, want new", body.Queue)
	}
	if body.Depth != 4 {
		t.Errorf("depth = %d, want 4", body.Depth)
	}
	if body.Capped {
		t.Errorf("capped = true for a depth of %d", body.Depth)
	}

	// A queue with no countable population must say so rather than report zero,
	// which a dashboard would render as "drained".
	if rec := depth("acquit"); rec.Code != http.StatusNotFound {
		t.Errorf("acquit depth: status = %d, want 404 (no depth count)", rec.Code)
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

	// registerAPI must supply a claim set even when the caller did not, or the
	// first select panics.
	if api.triageClaims == nil {
		t.Error("registerAPI left triageClaims nil")
	}
}
