package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/atomdrift-project/hopper"
)

type triageCollisionCase struct {
	name, ruling, verdict, destination, label, labelSource string
}

// A human-readable package path can name different builds in every pool,
// including unknown-class workflow pools. Preserve both artifacts, and keep
// workflow metadata and retry behavior independent of collision handling.
func TestHandleTriageCollisionsAcrossPools(t *testing.T) {
	for _, tc := range []triageCollisionCase{
		{"good", "good", "", "good/foraged-promote/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "good", "promoter"},
		{"bad", "bad", "", "bad/foraged-quarantine/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "bad", "promoter"},
		{"sighted", "sighted", "", "sighted/foraged/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "sighted", "promoter"},
		{"inconclusive", "inconclusive", "", "inconclusive/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "inconclusive", "triage"},
		{"purgatory-alias", "purgatory", "", "inconclusive/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "inconclusive", "triage"},
		{"dual-use", "dual-use", "", "dual-use/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "dual-use", "triage"},
		{"pending", "pending", "", "pending/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "unknown", "forager"},
		{"review", "review", "", "review/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0", "unknown", "forager"},
		{"verdict-good", "", "good", "good/mislabeled-unknown/skillsaw@v0", "good", "triage"},
		{"verdict-bad", "", "bad", "bad/mislabeled-unknown/skillsaw@v0", "bad", "triage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, identical := range []bool{false, true} {
				for _, exact := range []bool{false, true} {
					// Exact-location retries are the lifecycle ruling contract;
					// operator verdicts use the SHA-only post-triage flow.
					if exact && tc.verdict != "" {
						continue
					}
					name := "different"
					if identical {
						name = "identical"
					}
					if exact {
						name += "/exact-location"
					} else {
						name += "/sha-only"
					}
					t.Run(name, func(t *testing.T) {
						runTriageCollision(t, tc, identical, exact)
					})
				}
			}
		})
	}
}

func runTriageCollision(t *testing.T, tc triageCollisionCase, identical, exact bool) {
	t.Helper()
	ctx := t.Context()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}
	content := []byte("new build")
	incumbent := []byte("older build")
	if identical {
		incumbent = content
	}
	sha := testSHA256(content)
	oldRel := "incoming/scan/pkg/github/stbenjam/skillsaw/v0/skillsaw@v0"
	write := func(rel string, data []byte) {
		t.Helper()
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, data, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	assertBytes := func(rel string, want []byte) {
		t.Helper()
		got, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: bytes=%q error=%v, want %q", rel, got, err, want)
		}
	}
	write(oldRel, content)
	write(tc.destination, incumbent)
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Path: oldRel, Label: "unknown", Source: "forager",
		LabelSource: "forager", Skip: "deferred",
	}); err != nil {
		t.Fatal(err)
	}
	wantRel := tc.destination
	if !identical {
		wantRel += "." + sha[:12] // This GitHub artifact has no extension.
	}
	v := triageVerdict{SHA256: sha, Ruling: tc.ruling, Verdict: tc.verdict}
	if exact {
		v.OldPath = oldRel
	}
	request := triageRequest{Verdicts: []triageVerdict{v}, DryRun: true}
	preview := callTriage(t, api, request)
	if preview.Failed != 0 || preview.Results[0].Status != "plan" || preview.Results[0].NewPath != wantRel {
		t.Fatalf("preview: %+v, want plan at %s", preview, wantRel)
	}
	assertBytes(oldRel, content)
	assertBytes(tc.destination, incumbent)
	before, err := db.SampleBySHA256(ctx, sha)
	if err != nil || before.Path != oldRel || before.Label != "unknown" || before.Skip != "deferred" {
		t.Fatalf("dry-run changed catalog: %+v, %v", before, err)
	}
	request.DryRun = false
	resp := callTriage(t, api, request)
	if resp.Moved != 1 || resp.Failed != 0 || resp.Results[0].NewPath != wantRel {
		t.Fatalf("move: %+v, want %s", resp, wantRel)
	}
	assertBytes(wantRel, content)
	assertBytes(tc.destination, incumbent)
	if _, err := os.Stat(filepath.Join(root, oldRel)); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Path != wantRel || sample.Label != tc.label || sample.LabelSource != tc.labelSource || sample.Source != "forager" {
		t.Fatalf("wrong catalog state: %+v", sample)
	}
	if tc.label == "unknown" && sample.Skip != "deferred" {
		t.Fatalf("workflow move changed skip: %q", sample.Skip)
	}
	again := callTriage(t, api, request)
	if again.Failed != 0 || again.Noop+again.Moved != 1 {
		t.Fatalf("retry: %+v", again)
	}
	assertBytes(wantRel, content)
	assertBytes(tc.destination, incumbent)
}
