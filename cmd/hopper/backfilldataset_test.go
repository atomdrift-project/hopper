package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// bkcTree lays out one artifact directory under root in the dataset grammar
// and returns the artifact's data-root-relative path.
func bkcTree(t *testing.T, root string) string {
	t.Helper()
	rel := filepath.Join("bad", "datasets", "various", "Backstabber's Knife Collection", "samples", "npm", "@servicetitan", "forge", "0.5.6")
	dir := filepath.Join(root, rel)
	mustMkdirAll(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "forge-0.5.6.tgz"), []byte("tarball"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeZstd(t, filepath.Join(dir, "meta.json.zst"), []byte(forgeManifest))
	if err := os.WriteFile(filepath.Join(dir, maintainersName), []byte(`["st-team"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(filepath.Join(rel, "forge-0.5.6.tgz"))
}

func TestCmdBackfillDatasetMetadata(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	dbPath := filepath.Join(root, "hopper.db")
	db := mustOpenDB(t, ctx, dbPath)
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	artifactRel := bkcTree(t, root)
	metaRel := strings.TrimSuffix(artifactRel, "forge-0.5.6.tgz") + "meta.json.zst"
	artifactSHA, metaSHA, memberSHA, otherSHA := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	// What the old walk wrote: the artifact with a filename-guessed package, the
	// document as a sample, a member exploded out of it, and an unrelated row.
	rows := []*hopper.Sample{
		{SHA256: artifactSHA, Source: "harvest", Label: "bad", LabelSource: "harvest", Path: artifactRel, Filename: "forge-0.5.6.tgz", SizeBytes: 4096, Package: "forge", Version: "0.5.6"},
		{SHA256: metaSHA, Source: "harvest", Label: "bad", LabelSource: "harvest", Path: metaRel, Filename: "meta.json.zst", SizeBytes: 4096},
		{SHA256: memberSHA, Source: "harvest", Label: "bad", LabelSource: "harvest", Path: metaRel + "!!meta.json", Filename: "meta.json", Parent: metaSHA, SizeBytes: 4096},
		{SHA256: otherSHA, Source: "harvest", Label: "bad", LabelSource: "harvest", Path: "bad/harvest/x/metadata.json", Filename: "metadata.json", SizeBytes: 4096},
	}
	for _, s := range rows {
		if err := db.InsertSample(ctx, s); err != nil {
			t.Fatal(err)
		}
	}

	// Dry run: reports, changes nothing.
	out := captureStdout(t, func() {
		withArgs([]string{"hopper", "backfill-dataset-metadata", "-db", dbPath, "-data", root, "-purge"}, func() {
			if err := cmdBackfillDatasetMetadata(ctx); err != nil {
				t.Fatalf("dry run: %v", err)
			}
		})
	})
	dsRoot := "bad/datasets/various/Backstabber's Knife Collection"
	for _, want := range []string{
		"would attach provenance to 1 artifact(s)",
		"would delete 2 row(s)",
		"1         0            0            " + dsRoot, // per-dataset outcome row
		"       2  " + dsRoot,                           // per-dataset purge row
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	if s, err := db.SampleBySHA256(ctx, artifactSHA); err != nil || s.Package != "forge" {
		t.Fatalf("dry run must not write: %+v %v", s, err)
	}

	out = captureStdout(t, func() {
		withArgs([]string{"hopper", "backfill-dataset-metadata", "-db", dbPath, "-data", root, "-purge", "-apply"}, func() {
			if err := cmdBackfillDatasetMetadata(ctx); err != nil {
				t.Fatalf("apply: %v", err)
			}
		})
	})
	if !strings.Contains(out, "attached provenance to 1 artifact(s)") || !strings.Contains(out, "deleted 2 row(s)") {
		t.Fatalf("apply output:\n%s", out)
	}

	// The command wrote through its own handle; this test's handle cached the
	// row during the dry-run check, so verify through a fresh one.
	db.Close()
	db = mustOpenDB(t, ctx, dbPath)
	s, err := db.SampleBySHA256(ctx, artifactSHA)
	if err != nil {
		t.Fatal(err)
	}
	if s.Package != "@servicetitan/forge" || s.Version != "0.5.6" || s.PURLBase != "pkg:npm/%40servicetitan/forge" ||
		s.Feed != "backstabbers-knife-collection" || s.Ecosystem != "javascript" ||
		s.URL != "https://registry.npmjs.org/@servicetitan/forge/-/forge-0.5.6.tgz" {
		t.Errorf("identity not adopted: %+v", s)
	}
	prov, err := db.ProvenanceBySHA256(ctx, artifactSHA)
	if err != nil || len(prov) == 0 {
		t.Fatalf("provenance = %q, %v", prov, err)
	}
	var sc hopper.Sidecar
	if err := json.Unmarshal(prov, &sc); err != nil || sc.Feed == nil || sc.Feed.SourceID != "backstabbers-knife-collection" {
		t.Errorf("stored sidecar = %s (%v)", prov, err)
	}

	for _, sha := range []string{metaSHA, memberSHA} {
		if _, err := db.SampleBySHA256(ctx, sha); err == nil {
			t.Errorf("%s: document row should be purged", sha)
		}
	}
	if _, err := db.SampleBySHA256(ctx, otherSHA); err != nil {
		t.Errorf("metadata.json outside a dataset tree must survive: %v", err)
	}

	// Idempotent: nothing left to do.
	out = captureStdout(t, func() {
		withArgs([]string{"hopper", "backfill-dataset-metadata", "-db", dbPath, "-data", root, "-purge", "-apply"}, func() {
			if err := cmdBackfillDatasetMetadata(ctx); err != nil {
				t.Fatalf("re-run: %v", err)
			}
		})
	})
	if !strings.Contains(out, "attached provenance to 0 artifact(s)") {
		t.Fatalf("re-run output:\n%s", out)
	}
}
