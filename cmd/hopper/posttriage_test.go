package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/atomdrift/hopper"
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
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
// the source subpath into its pool tree, good/bad relabel while review does not,
// and re-running is idempotent.
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
		if err := os.WriteFile(abs, []byte("data"), 0o600); err != nil {
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
		{"good", repeat("1"), "", filepath.Join("good", "foraged-promote", "npm", "a.tgz"), "good", "promoter"},
		// Client source overrides the recorded label_source.
		{"bad", repeat("2"), "cyclotron:bad", filepath.Join("bad", "foraged-quarantine", "npm", "b.tgz"), "bad", "cyclotron:bad"},
		// review relabels nothing, so it keeps the existing source and ignores the override.
		{"review", repeat("3"), "cyclotron:review", filepath.Join("unknown", "foraged-review", "npm", "c.tgz"), "unknown", "forager"},
	}
	for _, tc := range cases {
		sub := filepath.Join("npm", map[string]string{"good": "a.tgz", "bad": "b.tgz", "review": "c.tgz"}[tc.ruling])
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

func repeat(b string) string {
	out := ""
	for len(out) < 64 {
		out += b
	}
	return out[:64]
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
