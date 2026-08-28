package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
)

func TestHandleTriageMovesAndFlips(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// A file that lived in the bad/ pool but triage decided is actually benign.
	sha := testSHA256([]byte("hello"))
	oldRel := filepath.Join("bad", "foo.bin")
	oldAbs := filepath.Join(root, oldRel)
	if err := os.MkdirAll(filepath.Dir(oldAbs), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(oldAbs, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	// A stale litmus marker that should not survive the move.
	marker := filepath.Join(root, "bad", markerPrefix+"foo.bin"+markerBad)
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Source: "test", Path: oldRel, Label: "bad", LabelSource: "test",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}

	resp := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Verdict: "good"}}})
	if resp.Moved != 1 || resp.Failed != 0 {
		t.Fatalf("moved=%d failed=%d, results=%+v", resp.Moved, resp.Failed, resp.Results)
	}
	wantRel := filepath.Join("good", "mislabeled-bad", "foo.bin")
	if got := resp.Results[0].NewPath; got != wantRel {
		t.Fatalf("new path = %q, want %q", got, wantRel)
	}

	// Bytes moved to the corrected bucket; old path and marker are gone.
	if _, err := os.Stat(filepath.Join(root, wantRel)); err != nil {
		t.Fatalf("expected moved file: %v", err)
	}
	if _, err := os.Stat(oldAbs); !os.IsNotExist(err) {
		t.Fatalf("old path should be gone, stat err = %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("stale marker should be gone, stat err = %v", err)
	}

	// DB row reflects the new label and path.
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "good" || samp.LabelSource != "triage" || samp.Path != wantRel {
		t.Fatalf("row not updated: label=%q source=%q path=%q", samp.Label, samp.LabelSource, samp.Path)
	}

	// Re-running the same batch is a no-op, not a second move.
	resp2 := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Verdict: "good"}}})
	if resp2.Noop != 1 || resp2.Moved != 0 {
		t.Fatalf("re-run: noop=%d moved=%d", resp2.Noop, resp2.Moved)
	}
}

func TestHandleTriageDryRunDoesNotMove(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	sha := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	oldRel := filepath.Join("good", "bar.js")
	oldAbs := filepath.Join(root, oldRel)
	if err := os.MkdirAll(filepath.Dir(oldAbs), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(oldAbs, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Source: "test", Path: oldRel, Label: "good", LabelSource: "test",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}
	resp := callTriage(t, api, triageRequest{DryRun: true, Verdicts: []triageVerdict{{SHA256: sha, Verdict: "bad"}}})
	if resp.Moved != 1 || resp.Results[0].Status != "plan" {
		t.Fatalf("dry-run status=%q moved=%d", resp.Results[0].Status, resp.Moved)
	}
	if _, err := os.Stat(oldAbs); err != nil {
		t.Fatalf("dry-run must not move the file: %v", err)
	}
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "good" {
		t.Fatalf("dry-run must not flip label, got %q", samp.Label)
	}
}

// TestHandleTriageAbsentBytes: on a partial mirror the DB row exists but the
// bytes don't. The verdict must be deferred — no move, no DB-only relabel
// (which the next full-corpus load walk would flip back by pool precedence).
func TestHandleTriageAbsentBytes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}

	sha := repeat("7")
	rel := filepath.Join("bad", "foraged", "npm", "gone", "gone-1.0.tgz")
	// DB row only — no file on disk.
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Source: "test", Path: rel, Label: "bad", LabelSource: "harvest",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	resp := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Ruling: "sighted", Source: "sighted-backfill"}}})
	if resp.Absent != 1 || resp.Failed != 0 || resp.Moved != 0 {
		t.Fatalf("absent=%d failed=%d moved=%d, want 1/0/0: %+v", resp.Absent, resp.Failed, resp.Moved, resp.Results)
	}
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "bad" || samp.Path != rel {
		t.Fatalf("deferred row must be untouched: label=%q path=%q", samp.Label, samp.Path)
	}
}

func TestHandleTriageUnknownSHA(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}
	sha := "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"[:64]
	resp := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Verdict: "bad"}}})
	if resp.Results[0].Status != "not_found" {
		t.Fatalf("status = %q, want not_found", resp.Results[0].Status)
	}
}

// TestHandleTriageRulings covers promoter's remote flow: each ruling preserves
// the source subpath into its pool tree and relabels, and re-running is
// idempotent.
func TestHandleTriageRulings(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}

	// seed writes an unknown candidate under unknown/foraged/<sub> and returns it.
	seed := func(sha, sub string) string {
		t.Helper()
		rel := filepath.Join("unknown", "foraged", sub)
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(abs, []byte(sub), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha, Source: "test", Path: rel, Label: "unknown", LabelSource: "forager",
		}); err != nil {
			t.Fatalf("InsertSample: %v", err)
		}
		return rel
	}

	cases := []struct {
		ruling   string
		sha      string
		source   string
		wantPath string
		wantLbl  string
		wantSrc  string
	}{
		// No source → default "promoter".
		{"good", testSHA256([]byte(filepath.Join("npm", "a.tgz"))), "", filepath.Join("good", "foraged-promote", "npm", "a.tgz"), "good", "promoter"},
		// Client source overrides the recorded label_source.
		{"bad", testSHA256([]byte(filepath.Join("npm", "b.tgz"))), "cyclotron:bad", filepath.Join("bad", "foraged-quarantine", "npm", "b.tgz"), "bad", "cyclotron:bad"},
	}
	for _, tc := range cases {
		sub := filepath.Join("npm", map[string]string{"good": "a.tgz", "bad": "b.tgz"}[tc.ruling])
		oldRel := seed(tc.sha, sub)
		resp := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: tc.sha, Ruling: tc.ruling, Source: tc.source}}})
		if resp.Moved != 1 || resp.Failed != 0 {
			t.Fatalf("%s: moved=%d failed=%d results=%+v", tc.ruling, resp.Moved, resp.Failed, resp.Results)
		}
		if got := resp.Results[0].NewPath; got != tc.wantPath {
			t.Fatalf("%s: new path = %q, want %q", tc.ruling, got, tc.wantPath)
		}
		if _, err := os.Stat(filepath.Join(root, tc.wantPath)); err != nil {
			t.Fatalf("%s: moved file missing: %v", tc.ruling, err)
		}
		if _, err := os.Stat(filepath.Join(root, oldRel)); !os.IsNotExist(err) {
			t.Fatalf("%s: source should be gone, err=%v", tc.ruling, err)
		}
		samp, err := db.SampleBySHA256(ctx, tc.sha)
		if err != nil {
			t.Fatalf("%s: SampleBySHA256: %v", tc.ruling, err)
		}
		if samp.Label != tc.wantLbl || samp.LabelSource != tc.wantSrc || samp.Path != tc.wantPath {
			t.Fatalf("%s: row label=%q source=%q path=%q", tc.ruling, samp.Label, samp.LabelSource, samp.Path)
		}
		// Idempotent re-run.
		again := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: tc.sha, Ruling: tc.ruling, Source: tc.source}}})
		if again.Noop != 1 || again.Moved != 0 {
			t.Fatalf("%s: re-run noop=%d moved=%d", tc.ruling, again.Noop, again.Moved)
		}
	}

	// A request with neither verdict nor ruling is an error.
	bad := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: repeat("4")}}})
	if bad.Failed != 1 {
		t.Fatalf("empty item: failed=%d results=%+v", bad.Failed, bad.Results)
	}
}

func TestHandleTriageWorkflowMovePreservesCatalogState(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	sha := testSHA256([]byte("sample"))
	oldRel := filepath.Join("incoming", "unknown", "foraged", "javascript", "npmjs.org", "npm", "pkg", "pkg-1.0.0.tgz")
	newRel := filepath.Join("review", "unknown", "foraged", "javascript", "npmjs.org", "npm", "pkg", "pkg-1.0.0.tgz")
	oldAbs := filepath.Join(root, oldRel)
	if err := os.MkdirAll(filepath.Dir(oldAbs), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldAbs, []byte("sample"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Source: "forager", Path: oldRel, Label: "unknown",
		LabelSource: "forager", Skip: "deferred",
	}); err != nil {
		t.Fatal(err)
	}

	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}
	resp := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Ruling: "review"}}})
	if resp.Moved != 1 || resp.Failed != 0 || resp.Results[0].NewPath != newRel {
		t.Fatalf("workflow response = %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(root, newRel)); err != nil {
		t.Fatalf("review file missing: %v", err)
	}
	if _, err := os.Stat(oldAbs); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incoming file still present: %v", err)
	}

	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Path != newRel || sample.Label != "unknown" || sample.LabelSource != "forager" ||
		sample.Source != "forager" || sample.Skip != "deferred" {
		t.Fatalf("workflow move changed catalog state: %+v", sample)
	}

	again := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Ruling: "review"}}})
	if again.Noop != 1 || again.Moved != 0 {
		t.Fatalf("workflow retry = %+v", again)
	}
}

func TestHandleIncomingLocationsOldestFirst(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour).UTC()
	newer := old.Add(time.Hour)
	for _, sample := range []*hopper.Sample{
		{SHA256: repeat("1"), Path: "incoming/forager/old.bin", Label: "unknown", Mtime: &old},
		{SHA256: repeat("2"), Path: "incoming/forager/new.bin", Label: "unknown", Mtime: &newer},
		{SHA256: repeat("3"), Path: "pending/forager/cold.bin", Label: "unknown", Mtime: &old},
	} {
		if err := db.InsertSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}
	req := httptest.NewRequest(http.MethodGet, "/api/locations/incoming?before="+time.Now().UTC().Format(time.RFC3339Nano)+"&limit=1", http.NoBody)
	rec := httptest.NewRecorder()
	api.handleIncomingLocations(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var response incomingLocationsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Locations) != 1 || response.Locations[0].Path != "incoming/forager/old.bin" {
		t.Fatalf("locations = %+v", response.Locations)
	}
}

// TestHandleTriageRulingCollision covers a ruling whose destination is already
// occupied — pool files are stored read-only, so without explicit handling the
// copy fails EACCES on every retry and the sample churns through triage
// forever. Identical bytes at the destination are adopted in place (source
// dropped); different bytes (forager re-fetched a same-named build) get a
// sha-suffixed slot beside the incumbent.
func TestHandleTriageRulingCollision(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}

	// write places content at rel, read-only like real pool files.
	write := func(rel string, content []byte) {
		t.Helper()
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(abs, content, 0o444); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	seed := func(sha, rel string, content []byte) {
		t.Helper()
		write(rel, content)
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha, Source: "test", Path: rel, Label: "bad", LabelSource: "harvest",
		}); err != nil {
			t.Fatalf("InsertSample: %v", err)
		}
	}
	shaOf := func(content []byte) string {
		sum := sha256.Sum256(content)
		return hex.EncodeToString(sum[:])
	}

	// Same bytes already at the destination: adopt in place.
	sameContent := []byte("identical bytes")
	sameSHA := shaOf(sameContent)
	oldRelA := filepath.Join("bad", "foraged", "npm", "same.tgz")
	destRelA := filepath.Join("good", "foraged-promote", "npm", "same.tgz")
	seed(sameSHA, oldRelA, sameContent)
	write(destRelA, sameContent)
	resp := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sameSHA, Ruling: "good"}}})
	if resp.Moved != 1 || resp.Failed != 0 {
		t.Fatalf("adopt: moved=%d failed=%d results=%+v", resp.Moved, resp.Failed, resp.Results)
	}
	if got := resp.Results[0].NewPath; got != destRelA {
		t.Fatalf("adopt: new path = %q, want %q", got, destRelA)
	}
	if _, err := os.Stat(filepath.Join(root, oldRelA)); !os.IsNotExist(err) {
		t.Fatalf("adopt: source should be gone, err=%v", err)
	}
	samp, err := db.SampleBySHA256(ctx, sameSHA)
	if err != nil {
		t.Fatalf("adopt: SampleBySHA256: %v", err)
	}
	if samp.Label != "good" || samp.Path != destRelA {
		t.Fatalf("adopt: row label=%q path=%q", samp.Label, samp.Path)
	}

	// Different bytes at the destination: sha-suffix this sample's basename.
	newContent := []byte("newer build")
	newSHA := shaOf(newContent)
	oldRelB := filepath.Join("bad", "foraged", "npm", "pkg.tgz")
	destRelB := filepath.Join("good", "foraged-promote", "npm", "pkg.tgz")
	seed(newSHA, oldRelB, newContent)
	write(destRelB, []byte("older build, different bytes"))
	resp = callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: newSHA, Ruling: "good"}}})
	if resp.Moved != 1 || resp.Failed != 0 {
		t.Fatalf("suffix: moved=%d failed=%d results=%+v", resp.Moved, resp.Failed, resp.Results)
	}
	wantRel := filepath.Join("good", "foraged-promote", "npm", "pkg."+newSHA[:12]+".tgz")
	if got := resp.Results[0].NewPath; got != wantRel {
		t.Fatalf("suffix: new path = %q, want %q", got, wantRel)
	}
	got, err := os.ReadFile(filepath.Join(root, wantRel))
	if err != nil || !bytes.Equal(got, newContent) {
		t.Fatalf("suffix: moved bytes wrong: err=%v content=%q", err, got)
	}
	if incumbent, err := os.ReadFile(filepath.Join(root, destRelB)); err != nil || bytes.Equal(incumbent, newContent) {
		t.Fatalf("suffix: incumbent clobbered: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, oldRelB)); !os.IsNotExist(err) {
		t.Fatalf("suffix: source should be gone, err=%v", err)
	}
}

// TestHandleTriageSightedRulings covers the sighted pool's two flows: the
// demote-sighted backfill (bad/foraged -> sighted/foraged, subpath mirrored)
// and promoter's re-promotion (sighted/foraged ->
// bad/foraged-quarantine).
func TestHandleTriageSightedRulings(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}

	seed := func(rel, label, source string) string {
		t.Helper()
		abs := filepath.Join(root, rel)
		content := []byte(rel)
		sha := testSHA256(content)
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(abs, content, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha, Source: "test", Path: rel, Label: label, LabelSource: source,
		}); err != nil {
			t.Fatalf("InsertSample: %v", err)
		}
		return sha
	}
	rule := func(sha, ruling, source string) triageResult {
		t.Helper()
		resp := callTriage(t, api, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Ruling: ruling, Source: source}}})
		if resp.Failed != 0 {
			t.Fatalf("%s: failed=%d results=%+v", ruling, resp.Failed, resp.Results)
		}
		return resp.Results[0]
	}

	// Backfill demotion: bad/foraged -> sighted/foraged with the
	// subpath mirrored, relabeled sighted with the client-supplied source.
	shaA := seed(filepath.Join("bad", "foraged", "npm", "registry", "socket", "evil", "evil-1.0.tgz"), "bad", "harvest")
	res := rule(shaA, "sighted", "sighted-backfill")
	wantA := filepath.Join("sighted", "foraged", "npm", "registry", "socket", "evil", "evil-1.0.tgz")
	if res.NewPath != wantA {
		t.Fatalf("demote path = %q, want %q", res.NewPath, wantA)
	}
	if _, err := os.Stat(filepath.Join(root, wantA)); err != nil {
		t.Fatalf("moved file missing: %v", err)
	}
	samp, err := db.SampleBySHA256(ctx, shaA)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "sighted" || samp.LabelSource != "sighted-backfill" || samp.Path != wantA {
		t.Fatalf("row after demote: label=%q source=%q path=%q", samp.Label, samp.LabelSource, samp.Path)
	}
	// Idempotent re-run.
	if again := rule(shaA, "sighted", "sighted-backfill"); again.Status != "noop" {
		t.Fatalf("re-run status = %q, want noop", again.Status)
	}

	// Relocation: forager's version-matched purl re-flag relabels DB-only, so
	// a sighted-labeled row can still sit under unknown/foraged. The sighted
	// ruling is tree-aware: it must move the file rather than noop on label.
	shaB := seed(filepath.Join("unknown", "foraged", "pypi", "registry", "osv", "pkg", "pkg-2.0.tgz"), "sighted", "forager")
	res = rule(shaB, "sighted", "")
	wantRelo := filepath.Join("sighted", "foraged", "pypi", "registry", "osv", "pkg", "pkg-2.0.tgz")
	if res.Status != "moved" || res.NewPath != wantRelo {
		t.Fatalf("relocation status=%q path=%q, want moved %q", res.Status, res.NewPath, wantRelo)
	}
	if again := rule(shaB, "sighted", ""); again.Status != "noop" {
		t.Fatalf("relocation re-run status = %q, want noop", again.Status)
	}

	// Promoter re-promotion: sighted/foraged ->
	// bad/foraged-quarantine, subpath mirrored, default promoter source.
	res = rule(shaA, "bad", "")
	wantB := filepath.Join("bad", "foraged-quarantine", "npm", "registry", "socket", "evil", "evil-1.0.tgz")
	if res.NewPath != wantB {
		t.Fatalf("re-promote path = %q, want %q", res.NewPath, wantB)
	}
	samp, err = db.SampleBySHA256(ctx, shaA)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "bad" || samp.LabelSource != "promoter" {
		t.Fatalf("row after re-promote: label=%q source=%q", samp.Label, samp.LabelSource)
	}

	// Acquittal out of a destination tree: bad/foraged-quarantine →
	// good/foraged-promote. The quarantine tree is a source root, so the subpath
	// survives the round trip instead of collapsing to a flat basename.
	res = rule(shaA, "good", "cyclotron:acquit")
	wantC := filepath.Join("good", "foraged-promote", "npm", "registry", "socket", "evil", "evil-1.0.tgz")
	if res.NewPath != wantC {
		t.Fatalf("acquit path = %q, want %q", res.NewPath, wantC)
	}
	if _, err := os.Stat(filepath.Join(root, wantC)); err != nil {
		t.Fatalf("acquitted file missing: %v", err)
	}
	samp, err = db.SampleBySHA256(ctx, shaA)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "good" || samp.LabelSource != "cyclotron:acquit" || samp.Path != wantC {
		t.Fatalf("row after acquit: label=%q source=%q path=%q", samp.Label, samp.LabelSource, samp.Path)
	}
}

// TestRulingPlanPreservesSubpath pins the placement arithmetic on its own. Every
// tree a ruled sample can sit in — discovery, upload shard, and the three ruling
// destinations — must preserve the subpath, because a ruling is not final and a
// sample can re-enter from wherever the last one put it. A tree no root
// enumerates keeps its whole path below the pool root; only a single-component
// path falls back to the basename.
func TestRulingPlanPreservesSubpath(t *testing.T) {
	const sub = "npm/registry/socket/evil/evil-1.0.tgz"
	cases := []struct {
		name   string
		oldRel string
		ruling string
		want   string
	}{
		{"hot foraged promote", "incoming/bad/foraged/" + sub, "good", "good/foraged-promote/bad/foraged/" + sub},
		{"hot upload demote", "incoming/scan/sha/example.com/ab/cd/hash/" + sub, "bad", "bad/foraged-quarantine/scan/sha/example.com/ab/cd/hash/" + sub},
		{"discovery promote", "pending/foraged/" + sub, "good", "good/foraged-promote/" + sub},
		{"discovery demote", "pending/foraged/" + sub, "bad", "bad/foraged-quarantine/" + sub},
		{"review promote", "review/foraged/" + sub, "good", "good/foraged-promote/foraged/" + sub},
		{"legacy discovery promote", "unknown/foraged/" + sub, "good", "good/foraged-promote/" + sub},
		{"legacy upload shard", "unknown/uploads/ab/cd/evil-1.0.tgz", "good", "good/foraged-promote/ab/cd/evil-1.0.tgz"},
		{"sighted promote", "sighted/foraged/" + sub, "bad", "bad/foraged-quarantine/" + sub},
		{"legacy sighted promote", "sighted/foraged/" + sub, "bad", "bad/foraged-quarantine/" + sub},
		// Round trips out of a destination tree: these flattened to the basename
		// before the destinations were themselves source roots.
		{"quarantine acquit", "bad/foraged-quarantine/" + sub, "good", "good/foraged-promote/" + sub},
		{"promoted demote", "good/foraged-promote/" + sub, "bad", "bad/foraged-quarantine/" + sub},
		{"promoted to sighted", "good/foraged-promote/" + sub, "sighted", "sighted/foraged/" + sub},
		// bad/foraged/ must not shadow bad/foraged-quarantine/.
		{"bad discovery demote", "bad/foraged/" + sub, "sighted", "sighted/foraged/" + sub},
		// The mislabeled-<label>/ buckets triagePlan writes are trees no root
		// enumerates. They must keep everything below their pool root: with a
		// basename they piled flat into the destination root, and purgatoryTree
		// being the bare pool root put them in /data/samples/purgatory itself.
		{"mislabeled to purgatory", "bad/mislabeled-good/" + sub, "purgatory", "purgatory/mislabeled-good/" + sub},
		{"mislabeled to sighted", "good/mislabeled-bad/" + sub, "sighted", "sighted/foraged/mislabeled-bad/" + sub},
		{"mislabeled acquit", "bad/mislabeled-good/" + sub, "good", "good/foraged-promote/mislabeled-good/" + sub},
		// Any other unenumerated pool tree keeps its subpath the same way.
		{"unenumerated bad tree", "bad/cyclotron/" + sub, "purgatory", "purgatory/cyclotron/" + sub},
		{"unenumerated sighted tree", "sighted/aur/" + sub, "purgatory", "purgatory/aur/" + sub},
		{"unrooted", "misc/foraged-undetermined/" + sub, "good", "good/foraged-promote/foraged-undetermined/" + sub},
		// Only a single-component path has nothing below a root to preserve.
		{"single component", "evil-1.0.tgz", "purgatory", "purgatory/evil-1.0.tgz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := rulingPlan(nil, tc.oldRel, tc.ruling)
			if !ok {
				t.Fatalf("rulingPlan(%q, %q) not ok", tc.oldRel, tc.ruling)
			}
			if got.newRel != tc.want {
				t.Errorf("newRel = %q, want %q", got.newRel, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		oldRel string
		ruling string
		want   string
	}{
		{"pending to review", "pending/foraged/" + sub, "review", "review/foraged/" + sub},
		{"review to pending", "review/foraged/" + sub, "pending", "pending/foraged/" + sub},
		{"incoming to review", "incoming/scan/sha/example.com/ab/cd/hash/pkg.tgz", "review", "review/scan/sha/example.com/ab/cd/hash/pkg.tgz"},
		{"legacy review not special", "unknown/foraged-review/" + sub, "review", "review/foraged-review/" + sub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := rulingPlan(nil, tc.oldRel, tc.ruling)
			if !ok {
				t.Fatalf("rulingPlan(%q, %q) not ok", tc.oldRel, tc.ruling)
			}
			if got.newRel != tc.want {
				t.Errorf("newRel = %q, want %q", got.newRel, tc.want)
			}
			if got.label != "" {
				t.Errorf("label = %q, want path-only move", got.label)
			}
		})
	}
}

func repeat(b string) string {
	out := ""
	for len(out) < 64 {
		out += b
	}
	return out[:64]
}

func testSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func callTriage(t *testing.T, api *apiServer, req triageRequest) triageResponse {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/triage", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	api.handleTriage(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp triageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}
