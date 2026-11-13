package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// verdictAPI returns an apiServer storing results in a fresh verdict schema
// of the disposable database HOPPER_TEST_PG_DSN.
func verdictAPI(t *testing.T) (*apiServer, *store.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("HOPPER_TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("HOPPER_TEST_PG_DSN not set (a disposable Postgres database)")
	}
	if strings.Contains(dsn, "hopper-db") {
		t.Fatal("HOPPER_TEST_PG_DSN names the production host; these tests write data")
	}
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("results_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		pool.Close()
	})
	for _, ddl := range []string{"CREATE SCHEMA " + schema, store.Schema} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	// db is never touched on this path; it only has to be non-nil.
	api := &apiServer{db: mustOpenDB(t, ctx, t.TempDir()+"/hopper.db"), results: st, tracker: newWorkerTracker(), progress: &loadProgress{}}
	return api, st, pool
}

func hexSum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// v8Body is a version 8 body for a package holding one script, zstd-compressed.
func v8Body(t *testing.T, ruleset, scriptReport string) (body []byte, pkg, script string) {
	t.Helper()
	pkg, script = hexSum([]byte("package")), hexSum([]byte("script"))
	reports := []string{`{"traits":[]}`, scriptReport}
	lines := []any{
		map[string]any{"v": 8, "files": 2, "scan": map[string]any{
			"engine": "3.0.0", "ruleset": ruleset, "level": 25, "worker": "w1", "at": "2026-11-12T15:00:00Z", "ms": 40,
		}},
		map[string]any{
			"sha256": pkg, "size": 900, "type": "npm", "report": hexSum([]byte(reports[0])),
			"verdict":  map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "floor", "in": script},
			"floor":    map[string]any{"class": "hostile", "fires_at": 12},
			"contents": map[string]any{"children": []int{1}, "paths": []string{"package/install.js"}},
		},
		map[string]any{
			"sha256": script, "size": 60, "type": "javascript", "report": hexSum([]byte(reports[1])),
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "floor"},
			"floor":   map[string]any{"class": "hostile", "fires_at": 12},
		},
	}
	var b bytes.Buffer
	for _, l := range lines {
		j, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(append(j, '\n'))
	}
	for _, r := range reports {
		b.WriteString(r + "\n")
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	return enc.EncodeAll(b.Bytes(), nil), pkg, script
}

// post sends body to handleResult and decodes the answer.
func post(t *testing.T, api *apiServer, body []byte, ndjson bool) (code int, stored bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/work/result", bytes.NewReader(body))
	if ndjson {
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("Content-Encoding", "zstd")
	}
	rec := httptest.NewRecorder()
	api.handleResult(rec, req)
	var answer struct {
		Stored bool `json:"stored"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
			t.Fatalf("answer %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, answer.Stored
}

func TestResultVersion8(t *testing.T) {
	api, st, _ := verdictAPI(t)
	ctx := t.Context()
	body, pkg, script := v8Body(t, "r1", `{"traits":[{"id":"b::fetch","crit":5}]}`)

	if code, stored := post(t, api, body, true); code != http.StatusOK || !stored {
		t.Fatalf("first post: %d, stored %v", code, stored)
	}
	rawPkg, _ := hex.DecodeString(pkg)       //nolint:errcheck // test constant
	rawScript, _ := hex.DecodeString(script) //nolint:errcheck // test constant
	rec, err := st.BySHA256(ctx, rawPkg)
	if err != nil || rec.Class != "hostile" || rec.Ruleset != "r1" {
		t.Errorf("package record %+v, %v", rec, err)
	}
	if report, err := st.Report(ctx, rawScript); err != nil || !strings.Contains(string(report), "b::fetch") {
		t.Errorf("script report %q, %v", report, err)
	}

	if code, stored := post(t, api, body, true); code != http.StatusOK || stored {
		t.Errorf("repeat post: %d, stored %v; want 200 and nothing stored", code, stored)
	}

	// A new report that does not hash to what its file line says is refused
	// whole. (A report hopper already holds is not read, so not checked.)
	bad, _, _ := v8Body(t, "r2", `{"traits":[{"id":"b::fetch","crit":5},{"id":"c::new","crit":3}]}`)
	plain, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := plain.DecodeAll(bad, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines = bytes.Replace(lines, []byte(`"crit":3}]}`+"\n"), []byte(`"crit":2}]}`+"\n"), 1)
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, api, enc.EncodeAll(lines, nil), true); code != http.StatusUnprocessableEntity {
		t.Errorf("tampered report: %d, want 422", code)
	}
	if rec, err := st.BySHA256(ctx, rawPkg); err != nil || rec.Ruleset != "r1" {
		t.Errorf("record %+v, %v: a refused body changed it", rec, err)
	}

	if code, _ := post(t, api, enc.EncodeAll([]byte(`{"v":7}`+"\n"), nil), true); code != http.StatusBadRequest {
		t.Errorf("wrong version: %d, want 400", code)
	}
}

func TestResultVersion7(t *testing.T) {
	api, st, _ := verdictAPI(t)
	ctx := t.Context()
	pkg, script := hexSum([]byte("v7 package")), hexSum([]byte("v7 script"))
	raw := fmt.Sprintf(`{"v":"8","rev":"r7","files":[
		{"id":0,"depth":0,"sha":%q,"path":"pkg.tgz","type":"npm","size":900},
		{"id":1,"pid":0,"depth":1,"sha":%q,"path":"pkg.tgz!!package/install.js","type":"javascript","size":60,
		 "traits":[{"id":"b::fetch","crit":5}]}]}`, pkg, script)
	body, err := json.Marshal(resultRequest{
		SHA256: pkg, Worker: "w1", Raw: json.RawMessage(raw),
		ML: json.RawMessage(`{"lvl":12,"files":[{"id":0,"lvl":12},{"id":1,"lvl":12}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, stored := post(t, api, body, false); code != http.StatusOK || !stored {
		t.Fatalf("post: %d, stored %v", code, stored)
	}
	rawPkg, _ := hex.DecodeString(pkg) //nolint:errcheck // test constant
	rec, err := st.BySHA256(ctx, rawPkg)
	if err != nil || rec.Class != "hostile" || rec.Ruleset != "r7" {
		t.Errorf("record %+v, %v", rec, err)
	}

	// A worker error that is about the file becomes a verdict that keeps
	// what is known; one about where the file is records nothing.
	for _, tc := range []struct{ sha, msg string }{
		{pkg, "analysis timed out after 60s"},
		{hexSum([]byte("never seen")), "Path does not exist: /x"},
	} {
		body, err := json.Marshal(resultRequest{SHA256: tc.sha, Worker: "w1", Error: tc.msg})
		if err != nil {
			t.Fatal(err)
		}
		if code, stored := post(t, api, body, false); code != http.StatusOK || stored {
			t.Errorf("%q: %d, stored %v; want 200 and nothing stored", tc.msg, code, stored)
		}
	}
	if rec, err := st.BySHA256(ctx, rawPkg); err != nil || rec.Class != "hostile" {
		t.Errorf("record %+v, %v: a timeout replaced the verdict", rec, err)
	}

	wrong, err := json.Marshal(resultRequest{SHA256: script, Worker: "w1", Raw: json.RawMessage(raw)})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, api, wrong, false); code != http.StatusUnprocessableEntity {
		t.Errorf("report for another file: %d, want 422", code)
	}
}

func TestQueueHandout(t *testing.T) {
	api, st, pool := verdictAPI(t)
	ctx := t.Context()
	body, pkg, _ := v8Body(t, "r1", `{"traits":[{"id":"b::fetch","crit":5}]}`)
	rawPkg, _ := hex.DecodeString(pkg) //nolint:errcheck // test constant
	if _, err := pool.Exec(ctx, `INSERT INTO samples (sha256, size_bytes, file_type) VALUES ($1, 900, 'npm')`, rawPkg); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO locations (path, sample_id) SELECT 'pool/pkg.tgz', id FROM samples`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO queue (sample_id, priority) SELECT id, $1 FROM samples`, int16(store.QueueNew)); err != nil {
		t.Fatal(err)
	}

	jobs, err := api.claimJobs(ctx, "w1", 4, nil, 0, 8)
	if err != nil || len(jobs) != 1 || jobs[0].SHA256 != pkg || jobs[0].Path != "pool/pkg.tgz" || jobs[0].Tier != tierUnanalyzed {
		t.Fatalf("claim %+v, %v", jobs, err)
	}
	// Another hopper, with its own tracker, sees the lease.
	other := &apiServer{db: api.db, results: st, tracker: newWorkerTracker(), progress: &loadProgress{}}
	if jobs, err := other.claimJobs(ctx, "w2", 4, nil, 0, 8); err != nil || len(jobs) != 0 {
		t.Errorf("a leased file was handed out again: %+v, %v", jobs, err)
	}

	if code, stored := post(t, api, body, true); code != http.StatusOK || !stored {
		t.Fatalf("result: %d, stored %v", code, stored)
	}
	depths, stuck, err := st.Depths(ctx)
	if err != nil || len(depths) != 0 || stuck != 0 {
		t.Errorf("queue after the result: %v, stuck %d, %v; want empty", depths, stuck, err)
	}

	// A worker that cannot find the bytes where it was sent: that location
	// is forgotten and the lease given back, so the file can be tried
	// wherever else it is. (A file left with no path leaves the queue;
	// store's TestUnlocateUnqueues.)
	if _, err := pool.Exec(ctx, `INSERT INTO locations (path, sample_id) SELECT 'mirror/pkg.tgz', id FROM samples WHERE sha256 = $1`, rawPkg); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.Rescan(ctx, rawPkg, time.Now()); err != nil || !ok {
		t.Fatalf("rescan: %v, %v", ok, err)
	}
	if jobs, err := api.claimJobs(ctx, "w1", 4, nil, 0, 8); err != nil || len(jobs) != 1 {
		t.Fatalf("claim %+v, %v", jobs, err)
	}
	missing, err := json.Marshal(resultRequest{SHA256: pkg, Worker: "w1", Error: "Path does not exist: pool/pkg.tgz"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post(t, api, missing, false); code != http.StatusOK {
		t.Fatalf("missing: %d", code)
	}
	var places, attempts int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM locations), (SELECT attempts FROM queue)`).Scan(&places, &attempts); err != nil ||
		places != 1 || attempts != 0 {
		t.Errorf("%d locations, %d attempts, %v; want one location forgotten and the lease given back", places, attempts, err)
	}
}

// A sample the walker built lands in the verdict schema, is handed out as a
// first scan, and moves up the ladder when an operator asks for it.
func TestIngestAndRescan(t *testing.T) {
	api, st, pool := verdictAPI(t)
	ctx := t.Context()
	sha := hexSum([]byte("walked"))
	mtime := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	walked := []*hopper.Sample{{
		SHA256: sha, SizeBytes: 900, Path: "good/npm/left-pad/left-pad-1.3.0.tgz", Source: "walk", Feed: "npm-top",
		Label: "purgatory", LabelSource: "review", Package: "left-pad", PURLBase: "pkg:npm/left-pad", Version: "1.3.0",
		Ecosystem: "npm", Filename: "left-pad-1.3.0.tgz", Mtime: &mtime,
	}}
	got, err := ingest(ctx, st, walked, store.QueueNew)
	if want := (store.Ingested{New: 1, Located: 1, Queued: 1}); err != nil || got != want {
		t.Fatalf("ingest %+v, %v; want %+v", got, err, want)
	}
	if got, err := ingest(ctx, st, walked, store.QueueNew); err != nil || got != (store.Ingested{}) {
		t.Errorf("walked again: %+v, %v; want nothing written", got, err)
	}
	var label, name, version, source string
	if err := pool.QueryRow(ctx, `SELECT s.label::text, n.name, s.version, l.source FROM samples s
		JOIN names n ON n.id = s.name_id JOIN locations l ON l.sample_id = s.id`).Scan(&label, &name, &version, &source); err != nil ||
		label != "inconclusive" || name != "pkg:npm/left-pad" || version != "1.3.0" || source != "walk" {
		t.Errorf("stored %s %s@%s from %s, %v; want the legacy alias spelled inconclusive", label, name, version, source, err)
	}

	rescan := func(sha string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/v1/work/rescan/"+sha, http.NoBody)
		r.SetPathValue("sha256", sha)
		rec := httptest.NewRecorder()
		api.handleRescan(rec, r)
		return rec.Code
	}
	if code := rescan(hexSum([]byte("never seen"))); code != http.StatusConflict {
		t.Errorf("rescan of an unknown file: %d, want 409", code)
	}
	if code := rescan(sha); code != http.StatusOK {
		t.Errorf("rescan: %d, want 200", code)
	}
	jobs, err := api.claimJobs(ctx, "w1", 4, nil, 0, 8)
	if err != nil || len(jobs) != 1 || jobs[0].SHA256 != sha || jobs[0].Path != walked[0].Path || jobs[0].Tier != tierForcedRescan {
		t.Errorf("claim %+v, %v; want the file handed out as a requested rescan", jobs, err)
	}
}

// The rescan-by-age tier: a file last scanned before the cutoff is found by
// the sweep and handed out last in the ladder, and the sweep stops looking
// while enough of them are already queued.
func TestRefillStale(t *testing.T) {
	api, st, pool := verdictAPI(t)
	ctx := t.Context()
	body, pkg, _ := v8Body(t, "r1", `{"traits":[{"id":"b::fetch","crit":5}]}`) // scanned 2026-11-12 15:00
	if code, stored := post(t, api, body, true); code != http.StatusOK || !stored {
		t.Fatalf("result: %d, stored %v", code, stored)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO locations (path, sample_id)
		SELECT 'pool/pkg.tgz', id FROM samples WHERE sha256 = decode($1, 'hex')`, pkg); err != nil {
		t.Fatal(err)
	}
	scanned := time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC)

	if next, queued, err := refillStale(ctx, st, store.Cursor{}, scanned.Add(-time.Hour)); err != nil || queued != 0 || next != (store.Cursor{}) {
		t.Errorf("cutoff before the scan: next %+v, queued %d, %v; want nothing old and the pass complete", next, queued, err)
	}

	// Enough rescans already owed: the sweep does not look for more.
	if _, err := pool.Exec(ctx, `WITH filler AS (
			INSERT INTO samples (sha256, size_bytes)
			SELECT sha256(i::text::bytea), 10 FROM generate_series(1, $1::int) AS i RETURNING id)
		INSERT INTO queue (sample_id, priority) SELECT id, $2 FROM filler`,
		staleTarget/2, int16(store.QueueStale)); err != nil {
		t.Fatal(err)
	}
	where := store.Cursor{At: scanned.Add(-time.Minute), ID: 7}
	if next, queued, err := refillStale(ctx, st, where, scanned.Add(time.Hour)); err != nil || queued != 0 || next != where {
		t.Errorf("queue half full: next %+v, queued %d, %v; want the sweep left where it was", next, queued, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM queue`); err != nil {
		t.Fatal(err)
	}

	if next, queued, err := refillStale(ctx, st, store.Cursor{}, scanned.Add(time.Hour)); err != nil || queued != 1 || next != (store.Cursor{}) {
		t.Errorf("cutoff after the scan: next %+v, queued %d, %v; want the file queued", next, queued, err)
	}
	jobs, err := api.claimJobs(ctx, "w1", 4, nil, 0, 8)
	if err != nil || len(jobs) != 1 || jobs[0].SHA256 != pkg || jobs[0].Tier != tierRescanAge {
		t.Errorf("claim %+v, %v; want the file handed out as a rescan by age", jobs, err)
	}
}

// The triage endpoints read the verdict schema when a results store is set:
// a file the floor misses under a bad label is handed out by "bad" in the
// shape cyclotron decodes, a report on it parks it, and the depth agrees.
func TestTriageFromStore(t *testing.T) {
	api, _, pool := verdictAPI(t)
	ctx := t.Context()
	body, pkg, _ := v8Body(t, "r1", `{"traits":[]}`)
	if code, stored := post(t, api, body, true); code != http.StatusOK || !stored {
		t.Fatalf("result: %d, stored %v", code, stored)
	}
	for _, q := range []string{
		`UPDATE samples SET label = 'bad', label_source = 'pool' WHERE sha256 = decode($1, 'hex')`,
		`DELETE FROM verdicts WHERE scanner_id = 2 AND sample_id = (SELECT id FROM samples WHERE sha256 = decode($1, 'hex'))`,
		`UPDATE scans SET flagged = true, scanned_at = now() WHERE sample_id = (SELECT id FROM samples WHERE sha256 = decode($1, 'hex'))`,
		`INSERT INTO locations (path, sample_id) SELECT 'bad/pkg.tgz', id FROM samples WHERE sha256 = decode($1, 'hex')`,
	} {
		if _, err := pool.Exec(ctx, q, pkg); err != nil {
			t.Fatal(err)
		}
	}
	selected := func() []hopper.Sample {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/triage/bad?limit=5", http.NoBody)
		r.SetPathValue("queue", "bad")
		rec := httptest.NewRecorder()
		api.handleTriageSelect(rec, r)
		var got struct{ Samples []hopper.Sample }
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("select: %d %s", rec.Code, rec.Body)
		}
		return got.Samples
	}
	got := selected()
	if len(got) != 1 || got[0].SHA256 != pkg || got[0].Path != "bad/pkg.tgz" || got[0].Label != "bad" || got[0].AnalyzedAt == nil {
		t.Fatalf("samples %+v", got)
	}

	r := httptest.NewRequest(http.MethodGet, "/v1/triage/bad/depth", http.NoBody)
	r.SetPathValue("queue", "bad")
	rec := httptest.NewRecorder()
	api.handleTriageDepth(rec, r)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"depth":1`) {
		t.Errorf("depth: %d %s", rec.Code, rec.Body)
	}

	report := `{"sha256":"` + pkg + `","type":"bad","provider":"p","content":"judgement=wrote traits"}`
	rec = httptest.NewRecorder()
	api.handleReport(rec, httptest.NewRequest(http.MethodPost, "/v1/triage/reports", strings.NewReader(report)))
	if rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body)
	}
	if got := selected(); len(got) != 0 {
		t.Errorf("samples %+v after a report; want the file parked", got)
	}
	rec = httptest.NewRecorder()
	unknown := `{"sha256":"` + strings.Repeat("ab", 32) + `","type":"bad"}`
	api.handleReport(rec, httptest.NewRequest(http.MethodPost, "/v1/triage/reports", strings.NewReader(unknown)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("report on an unknown file: %d, want 404", rec.Code)
	}

	for _, dropped := range []string{"stranded", "bad-shared"} {
		r = httptest.NewRequest(http.MethodGet, "/v1/triage/"+dropped, http.NoBody)
		r.SetPathValue("queue", dropped)
		rec = httptest.NewRecorder()
		api.handleTriageSelect(rec, r)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404: the queue is dropped", dropped, rec.Code)
		}
	}
}

// A ruling moves the file on disk and records the move and the label in the
// verdict schema when a results store is set.
func TestRulingFromStore(t *testing.T) {
	api, st, pool := verdictAPI(t)
	ctx := t.Context()
	api.dataRoot = t.TempDir()
	api.ready.Store(true)
	content := []byte("a package someone ruled on")
	sha := hexSum(content)
	rel := filepath.Join("pending", "npm", "pkg.tgz")
	if err := os.MkdirAll(filepath.Join(api.dataRoot, filepath.Dir(rel)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(api.dataRoot, rel), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, []store.Arrival{{SHA256: digestOf(sha), Size: int64(len(content)), Path: rel}}, store.QueueNew); err != nil {
		t.Fatal(err)
	}

	body := `{"verdicts":[{"sha256":"` + sha + `","ruling":"bad","source":"cyclotron:bad"}]}`
	rec := httptest.NewRecorder()
	api.handleTriage(rec, httptest.NewRequest(http.MethodPost, "/v1/triage/rulings", strings.NewReader(body)))
	var resp triageResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || len(resp.Results) != 1 {
		t.Fatalf("triage: %d %s", rec.Code, rec.Body)
	}
	res := resp.Results[0]
	if res.Status != "moved" || !strings.HasPrefix(res.NewPath, "bad/") || res.OldPath != rel {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(filepath.Join(api.dataRoot, res.NewPath)); err != nil {
		t.Errorf("destination: %v", err)
	}
	if _, err := os.Stat(filepath.Join(api.dataRoot, rel)); !os.IsNotExist(err) {
		t.Errorf("source still there: %v", err)
	}
	l, err := st.LabelOf(ctx, digestOf(sha))
	if err != nil || l.Label != "bad" || l.LabelSource != "cyclotron:bad" || len(l.Paths) != 1 || l.Paths[0] != res.NewPath {
		t.Errorf("catalog %+v, %v; want bad, by cyclotron, at %s alone", l, err, res.NewPath)
	}
	var events int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM label_events WHERE sha256 = $1 AND to_label = 'bad'`, sha).Scan(&events); err != nil || events != 1 {
		t.Errorf("%d label events, %v", events, err)
	}

	rec = httptest.NewRecorder()
	api.handleTriage(rec, httptest.NewRequest(http.MethodPost, "/v1/triage/rulings", strings.NewReader(body)))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Results[0].Status != "noop" {
		t.Errorf("the same ruling again: %s, want noop", rec.Body)
	}
}

// A reconcile walk with a results store records what it finds there: a file
// moved from good/ to bad/ on disk follows its pool, and a deleted file loses
// its path.
func TestWalkReconcilesStore(t *testing.T) {
	api, st, _ := verdictAPI(t)
	ctx := t.Context()
	root := t.TempDir()
	write := func(rel string, content []byte) {
		t.Helper()
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, b := bytes.Repeat([]byte("a"), 4096), bytes.Repeat([]byte("b"), 4096)
	write("good/a.bin", a)
	write("bad/b.bin", b)
	pass := &walkPass{
		db: api.db, results: st, progress: &loadProgress{}, source: "walk", nworkers: 2, markMissing: true,
		dirs: []struct{ dir, label string }{{filepath.Join(root, "good"), "good"}, {filepath.Join(root, "bad"), "bad"}},
	}
	pass.run(ctx, nil, time.Time{}, true)
	for sha, want := range map[string]string{hexSum(a): "good good/a.bin", hexSum(b): "bad bad/b.bin"} {
		l, err := st.LabelOf(ctx, digestOf(sha))
		if err != nil || len(l.Paths) != 1 || l.Label+" "+l.Paths[0] != want {
			t.Fatalf("first walk: %+v, %v; want %s", l, err, want)
		}
	}

	if err := os.Rename(filepath.Join(root, "good", "a.bin"), filepath.Join(root, "bad", "a.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "bad", "b.bin")); err != nil {
		t.Fatal(err)
	}
	pass.run(ctx, nil, time.Time{}, true)
	if l, err := st.LabelOf(ctx, digestOf(hexSum(a))); err != nil || l.Label != "bad" || l.LabelSource != "" ||
		!slices.Equal(l.Paths, []string{"bad/a.bin"}) {
		t.Errorf("moved file: %+v, %v; want bad, no longer a conflict, at bad/a.bin alone", l, err)
	}
	if l, err := st.LabelOf(ctx, digestOf(hexSum(b))); err != nil || len(l.Paths) != 0 {
		t.Errorf("deleted file: %+v, %v; want no path", l, err)
	}
}

// A claimed file gone from the path it was handed out with is opened at
// another the store records, and the dead path is forgotten.
func TestClaimOpensAnotherCopy(t *testing.T) {
	api, _, pool := verdictAPI(t)
	ctx := t.Context()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	api.dataRoot, api.allowedDirs = root, []string{root}
	content := []byte("bytes that moved to the mirror")
	if err := os.MkdirAll(filepath.Join(root, "mirror"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "mirror", "x.bin"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sha := hexSum(content)
	for _, sql := range []string{
		`INSERT INTO samples (sha256, size_bytes) VALUES (decode($1, 'hex'), ` + strconv.Itoa(len(content)) + `)`,
		`INSERT INTO locations (path, sample_id, seen_at) SELECT 'mirror/x.bin', id, now() - interval '1 day' FROM samples WHERE sha256 = decode($1, 'hex')`,
		`INSERT INTO locations (path, sample_id, seen_at) SELECT 'pool/x.bin', id, now() FROM samples WHERE sha256 = decode($1, 'hex')`,
		`INSERT INTO queue (sample_id, priority) SELECT id, ` + strconv.Itoa(int(store.QueueNew)) + ` FROM samples WHERE sha256 = decode($1, 'hex')`,
	} {
		if _, err := pool.Exec(ctx, sql, sha); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	jobs, err := api.claimJobs(ctx, "w1", 4, nil, 0, 8)
	if err != nil || len(jobs) != 1 || jobs[0].Path != "mirror/x.bin" {
		t.Fatalf("claim %+v, %v: want the job at the mirror's copy", jobs, err)
	}
	var paths []string
	if err := pool.QueryRow(ctx, `SELECT array_agg(path) FROM locations`).Scan(&paths); err != nil || len(paths) != 1 || paths[0] != "mirror/x.bin" {
		t.Errorf("locations %v, %v: want the dead path forgotten", paths, err)
	}
}
