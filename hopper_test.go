package hopper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustInsert(t *testing.T, ctx context.Context, db *DB, s *Sample) {
	t.Helper()
	// The insert layer rejects samples with empty paths. Many existing
	// tests build minimal Sample literals without a Path; give them a
	// synthetic one derived from the sha so they still exercise the DB
	// without needing every test updated.
	if s.Path == "" {
		s.Path = "test/" + s.SHA256
	}
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
}

func mustAnalyze(t *testing.T, ctx context.Context, db *DB, sha string, score int) {
	t.Helper()
	mustAnalyzeWithTraits(t, ctx, db, sha, score, "")
}

// mustAnalyzeWithTraits is mustAnalyze plus an optional comma-separated list
// of trait literals (e.g. `{"l":5,"c":1.0}`) inserted into the depth-0 entry.
func mustAnalyzeWithTraits(t *testing.T, ctx context.Context, db *DB, sha string, score int, traits string) {
	t.Helper()
	// Include a non-empty type so UpdateCleaveResult actually persists the row;
	// an empty type triggers the belt-and-suspenders delete path.
	result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":%d,"dp":0,"ts":[%s]}]}`, sha, score, traits)
	if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
}

func TestMigrateDoesNotRunBackfill(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cleave := `{"fs":[{"sha":"` + sha + `","type":"elf","f":"H₂O","x":7,"dp":0,"ts":[{"l":5},{"l":3}]}]}`
	if _, err := db.lite.ExecContext(ctx, `
		INSERT INTO samples (sha256, source, label, label_source, path, cleave_result)
		VALUES (?, 'test', 'bad', 'test', ?, ?)`,
		sha, "test/"+sha, cleave); err != nil {
		t.Fatal(err)
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	var elements string
	var maxCrit, suspiciousCount int
	if err := db.lite.QueryRowContext(ctx, `
		SELECT elements, max_crit, suspicious_count FROM samples WHERE sha256 = ?`, sha,
	).Scan(&elements, &maxCrit, &suspiciousCount); err != nil {
		t.Fatal(err)
	}
	if elements != "" || maxCrit != 0 || suspiciousCount != 0 {
		t.Fatalf("Migrate backfilled legacy row: elements=%q max_crit=%d suspicious_count=%d", elements, maxCrit, suspiciousCount)
	}

	pending, err := db.BackfillPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.CleaveColumns != 1 {
		t.Fatalf("pending cleave columns = %d, want 1", pending.CleaveColumns)
	}
}

func TestInsertAndLookup(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	s := &Sample{
		SHA256:      "abc123def456",
		Source:      "test",
		Filename:    "malware.exe",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/malware.exe",
		Status:      "bad-review",
	}
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	got, err := db.SampleBySHA256(ctx, "abc123def456")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.SHA256 != s.SHA256 {
		t.Errorf("SHA256 = %q, want %q", got.SHA256, s.SHA256)
	}
	if got.Label != "bad" {
		t.Errorf("Label = %q, want %q", got.Label, "bad")
	}
	if got.Status != "bad-review" {
		t.Errorf("Status = %q, want %q", got.Status, "bad-review")
	}
	if got.Path != s.Path {
		t.Errorf("Path = %q, want %q", got.Path, s.Path)
	}
}

// TestInsertPreservesCanonicalAndParent guards against placeholder/arg-list
// drift in the single-insert path. Both canonical_sha256 (defaults to the
// row's own sha via a $1-reuse in the SQL) and parent (from s.Parent) must
// land in the correct columns — a swap here previously went unnoticed
// because mock shas have no A-F chars that'd trigger the hex CHECK.
func TestInsertPreservesCanonicalAndParent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const (
		sha    = "child1"
		parent = "parent1"
	)
	// Parent must exist first — no FK check, but exercises a non-empty
	// sha2 argument to the insert.
	mustInsert(t, ctx, db, &Sample{SHA256: parent, Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      sha,
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "bad/archive!!child",
		Parent:      parent,
	})

	got, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	// canonical_sha256 defaults to sha256 for top-level rows; for a row
	// with Parent set, the insert still copies sha into the column (the
	// sample's own content is its canonical identity — the archive
	// relationship is separate, in parent).
	if got.CanonicalSHA256 != sha {
		t.Errorf("CanonicalSHA256 = %q, want %q (must not be swapped with Parent)", got.CanonicalSHA256, sha)
	}
	if got.Parent != parent {
		t.Errorf("Parent = %q, want %q (must not be swapped with canonical)", got.Parent, parent)
	}
}

func TestInsertDuplicate(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	s := &Sample{SHA256: "dup1", Source: "test", Label: "bad", LabelSource: "test"}
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatal(err)
	}
	// Duplicate insert should succeed silently.
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatalf("duplicate insert should not error: %v", err)
	}
}

func TestNotFound(t *testing.T) {
	db := openTestDB(t)
	_, err := db.SampleBySHA256(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSetStatus(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "s1", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	if err := db.SetStatus(ctx, "s1", "bad-reversed"); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "s1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.Status != "bad-reversed" {
		t.Errorf("Status = %q, want %q", got.Status, "bad-reversed")
	}
}

func TestUpdateCleaveResult(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "c1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, "c1", []byte(`{"fs":[{"sha":"c1","type":"elf","dp":0,"ts":[{"i":"test","l":4}]}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "c1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.CleaveResult == nil {
		t.Error("CleaveResult should not be nil")
	}
	if got.AnalyzedAt == nil {
		t.Error("AnalyzedAt should be set")
	}
}

func TestUpdateSample(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "u1", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	if err := db.UpdateSample(ctx, "u1", "bad-reversed", []byte(`{"fs":[{"sha":"u1","type":"elf","dp":0,"ts":[{"i":"test","l":5}]}]}`), ""); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "u1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.Status != "bad-reversed" {
		t.Errorf("Status = %q, want %q", got.Status, "bad-reversed")
	}
}

func TestReclassify(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.Reclassify(ctx, "r1", "good", "manual"); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "r1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.Label != "good" {
		t.Errorf("Label = %q, want %q", got.Label, "good")
	}
	if got.LabelSource != "manual" {
		t.Errorf("LabelSource = %q, want %q", got.LabelSource, "manual")
	}
}

func TestSamplesInPipelineStage(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "bad", LabelSource: "test", Status: "bad"})

	got, err := db.SamplesInPipelineStage(ctx, "bad-review", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d samples, want 2", len(got))
	}
}

func TestCountByLabel(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "good", LabelSource: "test"})

	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 2 {
		t.Errorf("bad = %d, want 2", counts["bad"])
	}
	if counts["good"] != 1 {
		t.Errorf("good = %d, want 1", counts["good"])
	}
}

func TestCountByStatus(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "good", LabelSource: "test", Status: "good"})

	counts, err := db.CountByStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 1 {
		t.Errorf("bad = %d, want 1", counts["bad"])
	}
	if counts["bad-review"] != 1 {
		t.Errorf("bad-review = %d, want 1", counts["bad-review"])
	}
}

func TestSamplesByStatusInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review", Path: "/data/bad/elf/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review", Path: "/data/bad/pe/s2"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "good", LabelSource: "test", Status: "good", Path: "/data/good/s3"})

	got, err := db.SamplesByStatusInPaths(ctx, "bad-review", []string{"/data/bad/elf"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "a" {
		t.Errorf("got %d samples, want 1 with sha256=a", len(got))
	}

	got, err = db.SamplesByStatusInPaths(ctx, "bad-review", []string{"/data/bad/elf", "/data/bad/pe"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d samples, want 2", len(got))
	}

	// Empty prefixes returns nil.
	got, err = db.SamplesByStatusInPaths(ctx, "bad-review", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("empty prefixes should return nil, got %d", len(got))
	}
}

func TestFalsePositivesInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp1",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app1",
		Score:       90,
	})
	// Include a hostile-level trait so fp1 passes the detection filter
	// (max_crit >= 5 OR suspicious_count >= 2).
	mustAnalyzeWithTraits(t, ctx, db, "fp1", 90, `{"l":5,"c":1.0}`)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp2",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app2",
		Score:       90,
		Skip:        "misclassified",
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp3",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app3",
		Score:       70,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp4",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/good/app4",
		Score:       90,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp5",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/other/good/app5",
		Score:       90,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp6",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app6",
		Status:      "good-review",
		Score:       90,
	})

	got, err := db.FalsePositivesInPaths(ctx, []string{"/data/good"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fp1" {
		t.Fatalf("got %+v, want only fp1", got)
	}
}

func TestFalsePositivesExcludeArchiveChildren(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp-parent",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/pkg.vsix",
		Score:       90,
	})
	mustAnalyzeWithTraits(t, ctx, db, "fp-parent", 90, `{"l":5,"c":1.0}`)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp-child",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/pkg.vsix!!extension/dist/server.js",
		Parent:      "fp-parent",
		Score:       95,
	})
	mustAnalyzeWithTraits(t, ctx, db, "fp-child", 95, `{"l":5,"c":1.0}`)

	got, err := db.FalsePositives(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fp-parent" {
		t.Fatalf("FalsePositives got %+v, want only fp-parent", got)
	}

	light, err := db.FalsePositivesLight(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(light) != 1 || light[0].SHA256 != "fp-parent" {
		t.Fatalf("FalsePositivesLight got %+v, want only fp-parent", light)
	}
}

func TestFalseNegativesInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn1",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app1",
		Score:       40,
	})
	mustAnalyze(t, ctx, db, "fn1", 40)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn2",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app2",
		Score:       40,
		Skip:        "misclassified",
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn3",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app3",
		Score:       90,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn4",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/bad/app4",
		Score:       40,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn5",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/other/bad/app5",
		Score:       40,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn6",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app6",
		Status:      "bad-review",
		Score:       40,
	})

	got, err := db.FalseNegativesInPaths(ctx, []string{"/data/bad"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fn1" {
		t.Fatalf("got %+v, want only fn1", got)
	}
}

func TestFalseNegativesExcludeArchiveChildren(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn-parent",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/pkg.vsix",
		Score:       0,
	})
	mustAnalyze(t, ctx, db, "fn-parent", 0)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn-child",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/pkg.vsix!!extension/dist/server.js",
		Parent:      "fn-parent",
		Score:       0,
	})
	mustAnalyze(t, ctx, db, "fn-child", 0)

	got, err := db.FalseNegatives(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fn-parent" {
		t.Fatalf("FalseNegatives got %+v, want only fn-parent", got)
	}

	light, err := db.FalseNegativesLight(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(light) != 1 || light[0].SHA256 != "fn-parent" {
		t.Fatalf("FalseNegativesLight got %+v, want only fn-parent", light)
	}
}

func TestTruePositives(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp1",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Score:       95,
	})
	mustAnalyze(t, ctx, db, "tp1", 95)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp2",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Score:       95,
		Skip:        "misclassified",
	})
	mustAnalyze(t, ctx, db, "tp2", 95)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp3",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Score:       70,
	})
	mustAnalyze(t, ctx, db, "tp3", 70)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp4",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Score:       95,
	})
	mustAnalyze(t, ctx, db, "tp4", 95)

	got, err := db.TruePositives(ctx, 85, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "tp1" {
		t.Fatalf("got %+v, want only tp1", got)
	}
}

func TestBenignReview(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// br1: hostile trait (max_crit=5) -> qualifies for benign-review.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br1",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br1", 92, `{"l":5,"c":1.0}`)
	// br2: only one suspicious trait, no hostile -> not in queue.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br2",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br2", 60, `{"l":4,"c":1.0}`)
	// br3: not marker-sourced -> excluded regardless of traits.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br3",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br3", 92, `{"l":5,"c":1.0}`)
	// br4: claimed -> excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br4",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
		Status:      "claimed",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br4", 92, `{"l":5,"c":1.0}`)

	got, err := db.BenignReview(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "br1" {
		t.Fatalf("got %+v, want only br1", got)
	}
}

func TestBadReview(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// mr1: no traits -> looks benign, qualifies for bad-review.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr1",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyze(t, ctx, db, "mr1", 20)
	// mr2: two suspicious traits -> doesn't look benign, excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr2",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "mr2", 90, `{"l":4,"c":1.0},{"l":4,"c":1.0}`)
	// mr3: not marker-sourced -> excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr3",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Skip:        "misclassified",
	})
	mustAnalyze(t, ctx, db, "mr3", 20)
	// mr4: claimed -> excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr4",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
		Status:      "claimed",
	})
	mustAnalyze(t, ctx, db, "mr4", 20)

	got, err := db.BadReview(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "mr1" {
		t.Fatalf("got %+v, want only mr1", got)
	}
}

func TestCountByStatusInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad", Path: "/data/bad/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad", Path: "/data/bad/s2"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review", Path: "/other/s3"})

	counts, err := db.CountByStatusInPaths(ctx, []string{"/data/bad"})
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 2 {
		t.Errorf("bad = %d, want 2", counts["bad"])
	}
	if counts["bad-review"] != 0 {
		t.Errorf("bad-review = %d, want 0 (filtered out)", counts["bad-review"])
	}
}

func TestAgesByPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Path: "/other/s2"})

	ages, err := db.AgesByPaths(ctx, []string{"/data"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ages) != 1 {
		t.Errorf("got %d ages, want 1", len(ages))
	}
	if _, ok := ages["/data/s1"]; !ok {
		t.Error("expected /data/s1 in ages")
	}
}

func TestUnanalyzed(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, "b", []byte(`{"fs":[{"sha":"b","type":"elf","dp":0}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}

	got, err := db.Unanalyzed(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "a" {
		t.Errorf("got %d unanalyzed, want 1 with sha256=a", len(got))
	}
}

func TestReports(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "test"})

	if err := db.InsertReport(ctx, &Report{SHA256: "r1", Type: "re", Content: "# Report 1", Provider: "claude"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // ensure distinct created_at in SQLite
	if err := db.InsertReport(ctx, &Report{SHA256: "r1", Type: "re", Content: "# Report 2", Provider: "gemini"}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertReport(ctx, &Report{SHA256: "r1", Type: "gap", Content: "# Gap", Provider: "claude"}); err != nil {
		t.Fatal(err)
	}

	all, err := db.ReportsBySHA256(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("got %d reports, want 3", len(all))
	}

	latest, err := db.LatestReport(ctx, "r1", "re")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Content != "# Report 2" {
		t.Errorf("latest RE content = %q, want %q", latest.Content, "# Report 2")
	}

	_, err = db.LatestReport(ctx, "r1", "fpr")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing report type, got %v", err)
	}
}

func TestSamplesByLabel(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "good", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "bad", LabelSource: "test"})

	got, err := db.SamplesByLabel(ctx, "bad", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2", len(got))
	}
}

func TestDeleteAll(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "d1", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "d2", Source: "test", Label: "good", LabelSource: "test"})
	if err := db.InsertReport(ctx, &Report{SHA256: "d1", Type: "re", Content: "report"}); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteAll(ctx); err != nil {
		t.Fatal(err)
	}

	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != 0 {
		t.Errorf("expected 0 samples after DeleteAll, got %d", total)
	}
}

func TestSetSkip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "sk1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.SetSkip(ctx, "sk1", skipBenignArchiveItem); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "sk1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Skip != skipBenignArchiveItem {
		t.Errorf("Skip = %q, want %q", got.Skip, skipBenignArchiveItem)
	}

	// Clear skip.
	if err := db.SetSkip(ctx, "sk1", ""); err != nil {
		t.Fatal(err)
	}
	got, err = db.SampleBySHA256(ctx, "sk1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Skip != "" {
		t.Errorf("Skip = %q, want empty", got.Skip)
	}
}

func TestSetNote(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "n1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.SetNote(ctx, "n1", "analysis timed out"); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "analysis timed out" {
		t.Errorf("Note = %q, want %q", got.Note, "analysis timed out")
	}
	if got.LastErrorAt == nil {
		t.Fatal("LastErrorAt not set")
	}

	if err := db.SetNote(ctx, "n1", ""); err != nil {
		t.Fatal(err)
	}
	got, err = db.SampleBySHA256(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "" {
		t.Errorf("Note = %q, want empty", got.Note)
	}
	if got.LastErrorAt != nil {
		t.Errorf("LastErrorAt = %v, want nil", got.LastErrorAt)
	}
}

func TestInsertSampleBatch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	samples := []*Sample{
		{SHA256: "b1", Source: "test", Label: "bad", LabelSource: "test", Path: "test/b1", SizeBytes: 100},
		{SHA256: "b2", Source: "test", Label: "good", LabelSource: "test", Path: "test/b2", SizeBytes: 200},
		{SHA256: "b3", Source: "test", Label: "bad", LabelSource: "test", Path: "test/b3", SizeBytes: 300},
	}
	_, needs, err := db.InsertSampleBatch(ctx, samples)
	if err != nil {
		t.Fatal(err)
	}
	// Note: n might be 0 currently because we don't distinguish INSERT vs UPDATE easily in PG/SQLite drivers
	// but needs should be 3.
	if len(needs) != 3 {
		t.Errorf("needs analysis = %d, want 3", len(needs))
	}

	// Duplicate batch: should still return needs analysis if they haven't been analyzed.
	_, needs, err = db.InsertSampleBatch(ctx, samples)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 3 {
		t.Errorf("duplicate batch needs analysis = %d, want 3", len(needs))
	}

	// Mock an analysis result.
	if err := db.UpdateLitmusResult(ctx, "b1", []byte("{}")); err != nil {
		t.Fatal(err)
	}

	// Third batch: b1 should now be missing from needs.
	_, needs, err = db.InsertSampleBatch(ctx, samples)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 2 {
		t.Errorf("needs analysis = %d, want 2 (b1 has result)", len(needs))
	}

	// Empty batch.
	n, needs, err := db.InsertSampleBatch(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(needs) != 0 {
		t.Errorf("empty batch n=%d needs=%d, want 0,0", n, len(needs))
	}
}

func TestInsertSampleBatchMarksReplaced(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert an unanalyzed sample at a known path.
	mustInsert(t, ctx, db, &Sample{SHA256: "old1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg.whl", SizeBytes: 100})

	// Re-insert the same path with a different SHA256 (file was replaced on disk).
	batch := []*Sample{
		{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg.whl", SizeBytes: 200},
	}
	_, _, err := db.InsertSampleBatch(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}

	// The old row should be marked as replaced.
	old, err := db.SampleBySHA256(ctx, "old1")
	if err != nil {
		t.Fatal(err)
	}
	if old.Skip != "replaced" {
		t.Errorf("old sample skip = %q, want 'replaced'", old.Skip)
	}

	// The new row should remain claimable (skip empty).
	nw, err := db.SampleBySHA256(ctx, "new1")
	if err != nil {
		t.Fatal(err)
	}
	if nw.Skip != "" {
		t.Errorf("new sample skip = %q, want empty", nw.Skip)
	}
}

func TestInsertSampleBatchDoesNotReplaceAnalyzed(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert a sample and give it analysis results.
	mustInsert(t, ctx, db, &Sample{SHA256: "analyzed1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg2.whl", SizeBytes: 100})
	cleave := []byte(`{"fs":[{"sha":"analyzed1","f":"H2O","x":5,"type":"zip","dp":0,"ts":[]}]}`)
	if err := db.UpdateCleaveResult(ctx, "analyzed1", cleave, nil, ""); err != nil {
		t.Fatal(err)
	}

	// Re-insert the same path with a different SHA256.
	batch := []*Sample{
		{SHA256: "new2", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg2.whl", SizeBytes: 200},
	}
	if _, _, err := db.InsertSampleBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}

	// The analyzed row should NOT be marked as replaced.
	old, err := db.SampleBySHA256(ctx, "analyzed1")
	if err != nil {
		t.Fatal(err)
	}
	if old.Skip != "" {
		t.Errorf("analyzed sample skip = %q, want empty", old.Skip)
	}
}

func TestStaleSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "st1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "st2", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/s2"})
	mustInsert(t, ctx, db, &Sample{SHA256: "st3", Source: "test", Label: "bad", LabelSource: "test", Path: "/other/s3"})

	// All samples were just inserted, so using a future threshold should return all under /data.
	future := time.Now().Add(time.Hour)
	got, err := db.StaleSamples(ctx, []string{"/data"}, future, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d stale samples, want 2", len(got))
	}

	// Threshold in the past: no samples are stale.
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err = db.StaleSamples(ctx, []string{"/data"}, past, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d stale samples with past threshold, want 0", len(got))
	}
}

func TestClaimJobsForceRescan(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	mustInsert(t, ctx, db, &Sample{SHA256: "fr1", Source: "test", Label: "bad", Path: "bad/pkg/a.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "fr2", Source: "test", Label: "bad", Path: "bad/other/b.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "fr3", Source: "test", Label: "bad", Path: "bad/pkg/skipped.bin", Skip: "unsupported"})

	// Seed prior analysis results so the rows look already-analyzed.
	for _, sha := range []string{"fr1", "fr2", "fr3"} {
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":50,"dp":0,"ts":[{"l":5,"c":1.0}]}]}`, sha)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, "oldtv"); err != nil {
			t.Fatalf("UpdateCleaveResult(%s): %v", sha, err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"prob":0.9}`)); err != nil {
			t.Fatalf("UpdateLitmusResult(%s): %v", sha, err)
		}
	}

	// Claim with force-rescan on bad/pkg and hopperStart in the future so all
	// three rows' analyzed_at is "before" start. Only fr1 should be claimed:
	// fr2 is outside the prefix, fr3 is marked skip.
	hopperStart := time.Now().Add(time.Hour)
	jobs, err := db.ClaimJobs(ctx, "w1", 10, 30*time.Minute, "", 7*24*time.Hour, hopperStart, []string{"bad/pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != "fr1" {
		t.Fatalf("force-rescan claim: got %+v, want [fr1]", jobs)
	}

	// Prior analysis must still be visible on the claimed row — nothing is
	// nulled at claim time; UpdateSample overwrites when new data arrives.
	rescanned, err := db.SampleBySHA256(ctx, "fr1")
	if err != nil {
		t.Fatal(err)
	}
	if rescanned.CleaveResult == nil || rescanned.LitmusResult == nil || rescanned.TraitsVersion != "oldtv" {
		t.Fatalf("fr1 data was reset at claim time: %+v", rescanned)
	}

	// Outside-prefix and skipped rows are untouched.
	for _, sha := range []string{"fr2", "fr3"} {
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if s.CleaveResult == nil || s.LitmusResult == nil || s.TraitsVersion != "oldtv" {
			t.Fatalf("%s unexpectedly affected: %+v", sha, s)
		}
	}

	// A second claim while fr1 is still held returns nothing.
	jobs, err = db.ClaimJobs(ctx, "w2", 10, 30*time.Minute, "", 7*24*time.Hour, hopperStart, []string{"bad/pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("second claim should see fr1 in flight: got %+v", jobs)
	}

	// With no force-rescan prefixes and no traits version, no claims happen
	// after tier-1 is empty — the force-rescan tier is opt-in per call.
	jobs, err = db.ClaimJobs(ctx, "w3", 10, 0, "", 7*24*time.Hour, hopperStart, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("without force-rescan prefixes, no tier-2 claim: got %+v", jobs)
	}
}

func TestClaimJobsStaleTraitsOrdering(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	type sample struct {
		sha    string
		label  string
		score  int
		traits string
		litmus string
	}
	samples := []sample{
		// Disagrees with label and closest to the litmus boundary: first.
		{sha: "1111111111111111111111111111111111111111111111111111111111111111", label: "bad", score: 0, traits: "", litmus: `{"prob":0.49}`},
		// Disagrees with label but farther from the boundary: second.
		{sha: "2222222222222222222222222222222222222222222222222222222222222222", label: "good", score: 50, traits: `{"l":5,"c":1.0}`, litmus: `{"prob":0.10}`},
		// Does not disagree, but is near the boundary: third.
		{sha: "3333333333333333333333333333333333333333333333333333333333333333", label: "good", score: 0, traits: "", litmus: `{"prob":0.51}`},
		// Does not disagree and is farther from the boundary: last.
		{sha: "4444444444444444444444444444444444444444444444444444444444444444", label: "bad", score: 50, traits: `{"l":5,"c":1.0}`, litmus: `{"prob":0.90}`},
	}
	for _, s := range samples {
		mustInsert(t, ctx, db, &Sample{SHA256: s.sha, Source: "test", Label: s.label, LabelSource: "test"})
		mustAnalyzeWithTraits(t, ctx, db, s.sha, s.score, s.traits)
		if err := db.UpdateLitmusResult(ctx, s.sha, []byte(s.litmus)); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, traits_version = 'old-traits'`,
		old); err != nil {
		t.Fatal(err)
	}

	jobs, err := db.ClaimJobs(ctx, "w1", 4, 30*time.Minute, "new-traits", 72*time.Hour, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{samples[0].sha, samples[1].sha, samples[2].sha, samples[3].sha}
	if len(jobs) != len(want) {
		t.Fatalf("claimed %d jobs, want %d: %+v", len(jobs), len(want), jobs)
	}
	for i := range want {
		if jobs[i].SHA256 != want[i] {
			t.Fatalf("job %d sha = %s, want %s; jobs=%+v", i, jobs[i].SHA256, want[i], jobs)
		}
	}
}

func TestRelativizePaths(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)
	root := filepath.ToSlash(filepath.Join(t.TempDir(), "data"))
	mustInsert(t, ctx, db, &Sample{SHA256: "rp1", Source: "test", Label: "bad", Path: root + "/bad/pkg/a.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "rp2", Source: "test", Label: "bad", Path: root + "-other/bad/pkg/a.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "rp3", Source: "test", Label: "bad", Path: "bad/pkg/already.bin"})
	// A legacy-style absolute path that happens to live outside the current
	// dataRoot — should be left alone (no implicit "/data/" marker fallback).
	mustInsert(t, ctx, db, &Sample{SHA256: "rp4", Source: "test", Label: "bad", Path: "/moved/archive/data/good/pkg/b.bin"})

	n, err := db.RelativizePaths(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("RelativizePaths affected %d rows, want 1", n)
	}

	rel, err := db.SampleBySHA256(ctx, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	if rel.Path != "bad/pkg/a.bin" {
		t.Fatalf("rp1 path = %q, want relative path", rel.Path)
	}

	outside, err := db.SampleBySHA256(ctx, "rp2")
	if err != nil {
		t.Fatal(err)
	}
	if outside.Path != root+"-other/bad/pkg/a.bin" {
		t.Fatalf("rp2 path = %q, want unchanged outside path", outside.Path)
	}

	// rp4 has /data/ in the path but is NOT under dataRoot — stays
	// untouched.
	marker, err := db.SampleBySHA256(ctx, "rp4")
	if err != nil {
		t.Fatal(err)
	}
	if marker.Path != "/moved/archive/data/good/pkg/b.bin" {
		t.Fatalf("rp4 path = %q, want unchanged (no /data/ marker fallback)", marker.Path)
	}
}

// TestRelativizePathsLocationConflicts covers the case that trips up a
// naïve UPDATE … WHERE NOT EXISTS: a sample has both the absolute and
// relative form of the same location, left over from a prior deployment
// or a backfill race. RelativizePaths must collapse them without tripping
// the UNIQUE (sha256, path) constraint.
func TestRelativizePathsLocationConflicts(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)
	root := filepath.ToSlash(filepath.Join(t.TempDir(), "data"))

	// Fresh walker inserted an absolute path; prior backfill (or a
	// previous relativize pass) already has the relative equivalent.
	mustInsert(t, ctx, db, &Sample{SHA256: "conflict1", Source: "test", Label: "bad", Path: root + "/bad/foo.exe"})
	if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: "conflict1", Path: "bad/foo.exe"}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.RelativizePaths(ctx, root); err != nil {
		t.Fatalf("RelativizePaths: %v", err)
	}

	locs, err := db.LocationsForSHA(ctx, "conflict1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 || locs[0].Path != "bad/foo.exe" {
		t.Fatalf("conflict1 locations = %+v, want single path=bad/foo.exe", locs)
	}
}

func TestExplodeArchiveMembers(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	cleaveJSON := []byte(`{"fs":[
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"elf","path":"pkg/bin","dp":0,"sz":1000,"ts":[{"l":5,"c":0.9}]},
		{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","type":"py","path":"pkg/setup.py","dp":1,"sz":500,"ts":[{"l":5,"c":0.95}]},
		{"sha":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","type":"txt","path":"pkg/readme.txt","dp":1,"sz":50,"ts":[{"l":1,"c":1.0}]}
	]}`)

	parentLitmus := []byte(`{"v":"4","prob":0.97,"class":1,"version":"vtest","thresholds":[0.5,0.9],"fs":[{"id":0,"prob":0.97,"class":1},{"id":1,"prob":0.91,"class":1},{"id":2,"prob":0.12,"class":0}]}`)
	analyzedAt := time.Date(2026, 4, 27, 7, 30, 0, 0, time.UTC)
	parent := &Sample{
		SHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:          "test",
		Label:           "bad",
		LabelSource:     "test",
		Path:            "bad/archive.zip",
		CleaveResult:    cleaveJSON,
		LitmusResult:    parentLitmus,
		CanonicalSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AnalyzedAt:      &analyzedAt,
	}
	mustInsert(t, ctx, db, parent)

	n, err := db.ExplodeArchiveMembers(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 { // dp=0 is skipped, dp=1 entries inserted
		t.Errorf("exploded = %d, want 2", n)
	}

	// Idempotent explosion: should return 0 NEWly inserted, but same number of members.
	n, err = db.ExplodeArchiveMembers(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("duplicate explosion inserted = %d, want 0", n)
	}

	// The txt file with only level 1 findings should have skip="skip-benign-archive-item"
	// and a virtual path combining parent.Path with its in-archive path.
	txt, err := db.SampleBySHA256(ctx, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatal(err)
	}
	if txt.Skip != skipBenignArchiveItem {
		t.Errorf("txt Skip = %q, want %q", txt.Skip, skipBenignArchiveItem)
	}
	if txt.Parent != parent.SHA256 {
		t.Errorf("txt Parent = %q, want %q", txt.Parent, parent.SHA256)
	}
	if want := "bad/archive.zip!!pkg/readme.txt"; txt.Path != want {
		t.Errorf("txt Path = %q, want %q", txt.Path, want)
	}

	// The py file with hostile level findings should NOT be skipped.
	py, err := db.SampleBySHA256(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if py.Skip != "" {
		t.Errorf("py Skip = %q, want empty", py.Skip)
	}
	if want := "bad/archive.zip!!pkg/setup.py"; py.Path != want {
		t.Errorf("py Path = %q, want %q", py.Path, want)
	}

	// Regression guard for the "archive orphan" class: Explode must persist
	// cleave_result (single-file wrapper derived from the parent's fs[]
	// entry) AND member-specific litmus_result on every member.
	// Before the insert column-list fix, these fields were silently
	// dropped because neither insertSampleBatch* listed them, leaving
	// members with NULL cleave_result — invisible to ClaimJobs and hence
	// undead in the queue forever.
	wantLitmusScores := map[string]float64{
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": 0.91,
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc": 0.12,
	}
	for sha, wantScore := range wantLitmusScores {
		m, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.CleaveResult) == 0 {
			t.Errorf("%s: cleave_result missing — explode inserted nothing into the column", sha[:12])
		} else if !bytes.Contains(m.CleaveResult, []byte(sha)) {
			t.Errorf("%s: cleave_result doesn't reference own sha: %s", sha[:12], m.CleaveResult)
		}
		if bytes.Equal(m.LitmusResult, parentLitmus) {
			t.Errorf("%s: litmus_result inherited parent envelope: %q", sha[:12], m.LitmusResult)
		}
		var litmus struct {
			Prob float64 `json:"prob"`
		}
		if err := json.Unmarshal(m.LitmusResult, &litmus); err != nil {
			t.Errorf("%s: parse member litmus_result: %v", sha[:12], err)
		} else if litmus.Prob != wantScore {
			t.Errorf("%s: member litmus prob = %v, want %v", sha[:12], litmus.Prob, wantScore)
		}
		if m.LitmusScore != wantScore {
			t.Errorf("%s: litmus_score = %v, want %v", sha[:12], m.LitmusScore, wantScore)
		}
		if m.AnalyzedAt == nil || !m.AnalyzedAt.Equal(analyzedAt) {
			t.Errorf("%s: analyzed_at = %v, want inherited %v", sha[:12], m.AnalyzedAt, analyzedAt)
		}
	}
}

func TestBackfillArchiveMemberAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	childSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	parentCleave := []byte(`{"fs":[{"sha":"` + parentSHA + `","type":"zip","dp":0}]}`)
	parentLitmus := []byte(`{"prob":0.97}`)

	mustInsert(t, ctx, db, &Sample{SHA256: parentSHA, Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, parentSHA, parentCleave, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, parentSHA, parentLitmus); err != nil {
		t.Fatal(err)
	}
	parent, err := db.SampleBySHA256(ctx, parentSHA)
	if err != nil {
		t.Fatal(err)
	}
	if parent.AnalyzedAt == nil {
		t.Fatal("parent analyzed_at missing")
	}

	childCleave := []byte(`{"fs":[{"sha":"` + childSHA + `","type":"py","dp":1}]}`)
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{
		SHA256:       childSHA,
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.zip!!pkg/x.py",
		Parent:       parentSHA,
		CleaveResult: childCleave,
		LitmusResult: parentLitmus,
	}}); err != nil {
		t.Fatal(err)
	}
	child, err := db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if child.AnalyzedAt != nil {
		t.Fatalf("precondition: child analyzed_at = %v, want nil", child.AnalyzedAt)
	}

	if _, err := db.Backfill(ctx); err != nil {
		t.Fatal(err)
	}
	child, err = db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if child.AnalyzedAt == nil || !child.AnalyzedAt.Equal(*parent.AnalyzedAt) {
		t.Fatalf("child analyzed_at = %v, want parent analyzed_at %v", child.AnalyzedAt, parent.AnalyzedAt)
	}
}

func TestBackfillArchiveMemberLitmusResult(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	childSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	parentCleave := []byte(`{"fs":[
		{"sha":"` + parentSHA + `","type":"zip","path":"archive.zip","dp":0},
		{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1}
	]}`)
	parentLitmus := []byte(`{"v":"4","prob":0.97,"class":1,"version":"vtest","fs":[{"id":0,"prob":0.97,"class":1},{"id":1,"prob":0.41,"class":0}]}`)
	childCleave := []byte(`{"fs":[{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1}]}`)

	mustInsert(t, ctx, db, &Sample{SHA256: parentSHA, Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, parentSHA, parentCleave, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, parentSHA, parentLitmus); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{
		SHA256:       childSHA,
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.zip!!pkg/x.py",
		Parent:       parentSHA,
		CleaveResult: childCleave,
		LitmusResult: parentLitmus,
	}}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Backfill(ctx); err != nil {
		t.Fatal(err)
	}
	child, err := db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(child.LitmusResult, parentLitmus) {
		t.Fatalf("child litmus_result still inherited parent envelope: %s", child.LitmusResult)
	}
	var litmus struct {
		Prob float64 `json:"prob"`
	}
	if err := json.Unmarshal(child.LitmusResult, &litmus); err != nil {
		t.Fatal(err)
	}
	if litmus.Prob != 0.41 || child.LitmusScore != 0.41 {
		t.Fatalf("child litmus prob/score = %v/%v, want 0.41/0.41", litmus.Prob, child.LitmusScore)
	}
}

func TestExplodeArchiveMembersViaSampleParentInfoAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	childSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cleaveJSON := []byte(`{"fs":[
		{"sha":"` + parentSHA + `","type":"zip","path":"archive.zip","dp":0,"ts":[{"l":5,"c":0.9}]},
		{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1,"ts":[{"l":5,"c":0.9}]}
	]}`)
	litmusJSON := []byte(`{"v":"4","prob":0.97,"class":1,"fs":[{"id":0,"prob":0.97,"class":1},{"id":1,"prob":0.83,"class":1}]}`)

	mustInsert(t, ctx, db, &Sample{
		SHA256:      parentSHA,
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "bad/archive.zip",
	})
	if err := db.UpdateCleaveResult(ctx, parentSHA, cleaveJSON, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, parentSHA, litmusJSON); err != nil {
		t.Fatal(err)
	}

	parent, err := db.SampleParentInfo(ctx, parentSHA)
	if err != nil {
		t.Fatal(err)
	}
	if parent.AnalyzedAt == nil {
		t.Fatal("SampleParentInfo did not fetch analyzed_at")
	}
	parent.CleaveResult = cleaveJSON

	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}
	child, err := db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if child.AnalyzedAt == nil || !child.AnalyzedAt.Equal(*parent.AnalyzedAt) {
		t.Fatalf("child analyzed_at = %v, want parent analyzed_at %v", child.AnalyzedAt, parent.AnalyzedAt)
	}
}

// TestExplodeArchiveMembersCleaveFormat verifies that we strip cleave's
// "<archive-path>!!<member>" prefix before joining the member to our own
// parent.Path. Historical bug: we were blindly prepending parent.Path +
// "!" on top of cleave's already-qualified path, producing triple-nested
// stored paths like "bad/foo.tgz!/abs/data/bad/foo.tgz!!member.py".
func TestExplodeArchiveMembersCleaveFormat(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mSha := "2222222222222222222222222222222222222222222222222222222222222222"
	nSha := "3333333333333333333333333333333333333333333333333333333333333333"
	// Absolute-path format (what cleave emits for depth-1 members) and
	// nested-archive format (depth-2; the last "!!" is still the boundary).
	cleaveJSON := []byte(`{"fs":[
		{"sha":"1111111111111111111111111111111111111111111111111111111111111111","type":"tar.gz","path":"/abs/data/bad/archive.tgz","dp":0},
		{"sha":"` + mSha + `","type":"py","path":"/abs/data/bad/archive.tgz!!package/setup.py","dp":1,"sz":100,"ts":[{"l":5,"c":0.95}]},
		{"sha":"` + nSha + `","type":"txt","path":"inner.tgz!!inner.tgz!deep/note.txt","dp":2,"sz":50,"ts":[{"l":5,"c":0.9}]}
	]}`)
	parent := &Sample{
		SHA256:       "1111111111111111111111111111111111111111111111111111111111111111",
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.tgz",
		CleaveResult: cleaveJSON,
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}

	// dp=1 member: last "!!" separates archive from member → "package/setup.py".
	m, err := db.SampleBySHA256(ctx, mSha)
	if err != nil {
		t.Fatal(err)
	}
	if want := "bad/archive.tgz!!package/setup.py"; m.Path != want {
		t.Errorf("dp=1 member path = %q, want %q", m.Path, want)
	}
	if m.Filename != "package/setup.py" {
		t.Errorf("dp=1 member filename = %q, want %q", m.Filename, "package/setup.py")
	}

	// dp=2 nested member: after last "!!", the in-archive portion is
	// "inner.tgz!deep/note.txt". Joined with parent: "bad/archive.tgz!!inner.tgz!deep/note.txt".
	n, err := db.SampleBySHA256(ctx, nSha)
	if err != nil {
		t.Fatal(err)
	}
	if want := "bad/archive.tgz!!inner.tgz!deep/note.txt"; n.Path != want {
		t.Errorf("dp=2 member path = %q, want %q", n.Path, want)
	}
}

// TestExplodeDoesNotClobberWalkerPath is the regression guard for the
// content-collision orphan class: when a sha has been inserted by the
// walker (top-level, parent=”) and the same sha then appears inside an
// archive via ExplodeArchiveMembers, the archive-member upsert must NOT
// overwrite samples.path with the virtual "<archive>!<member>" form —
// that would leave the samples row pointing at a non-existent disk path,
// marked tier-1 claimable, and workers would all report "missing on disk".
// Observed in prod on shared code (vendored deps, copies of the same
// library across versions). The sample_locations table still records the
// archive observation separately; only the denormalized samples row is
// protected from Explode clobber.
func TestExplodeDoesNotClobberWalkerPath(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sharedSHA = "7777777777777777777777777777777777777777777777777777777777777777"

	// Step 1: walker sees the file as a top-level sample.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      sharedSHA,
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "good/vendor/shared/lib.js",
	})

	// Step 2: an archive with the same content inside is analyzed and
	// ExplodeArchiveMembers inserts a member with parent=<archive-sha>.
	cleaveJSON := []byte(`{"fs":[
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"zip","path":"bad/pkg.zip","dp":0},
		{"sha":"` + sharedSHA + `","type":"js","path":"pkg/lib.js","dp":1,"sz":500,"ts":[{"l":5,"c":0.9}]}
	]}`)
	parent := &Sample{
		SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/pkg.zip",
		CleaveResult: cleaveJSON,
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}

	// The samples row for sharedSHA must still point at the walker's
	// top-level path, with parent=''. If Explode's upsert had
	// clobbered it, samples.path would be "bad/pkg.zip!!pkg/lib.js" and
	// samples.parent would still be '' — the orphan state.
	got, err := db.SampleBySHA256(ctx, sharedSHA)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "good/vendor/shared/lib.js" {
		t.Errorf("Path = %q, want walker path %q (Explode clobbered?)",
			got.Path, "good/vendor/shared/lib.js")
	}
	if got.Parent != "" {
		t.Errorf("Parent = %q, want '' (top-level observation wins)", got.Parent)
	}

	// sample_locations should hold BOTH observations — walker's and
	// Explode's — since they're different (sha, path) pairs.
	locs, err := db.LocationsForSHA(ctx, sharedSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Fatalf("locations = %d, want 2 (walker + archive)", len(locs))
	}
	var sawWalker, sawArchive bool
	for _, l := range locs {
		switch l.Path {
		case "good/vendor/shared/lib.js":
			sawWalker = true
			if l.ParentSHA256 != "" {
				t.Errorf("walker location has parent_sha256 = %q, want empty", l.ParentSHA256)
			}
		case "bad/pkg.zip!!pkg/lib.js":
			sawArchive = true
			if l.ParentSHA256 != parent.SHA256 {
				t.Errorf("archive location parent_sha256 = %q, want %q", l.ParentSHA256, parent.SHA256)
			}
		default:
			t.Errorf("unexpected location: %s", l.Path)
		}
	}
	if !sawWalker || !sawArchive {
		t.Errorf("want both walker and archive locations; walker=%v archive=%v", sawWalker, sawArchive)
	}
}

// TestExplodeResultsSurviveReingest guards the "walker arrives after Explode"
// case: if the walker re-hashes an archive member that's already on disk
// as a standalone file, its InsertSample call must NOT null out the
// cleave_result / litmus_result that Explode wrote earlier. The fix in
// the ON CONFLICT clause leaves the analysis columns untouched on update.
func TestExplodeResultsSurviveReingest(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	memberSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cleaveJSON := []byte(`{"fs":[
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"elf","path":"pkg/bin","dp":0,"sz":1000,"ts":[{"l":5,"c":0.9}]},
		{"sha":"` + memberSHA + `","type":"py","path":"pkg/setup.py","dp":1,"sz":500,"ts":[{"l":5,"c":0.95}]}
	]}`)
	parent := &Sample{
		SHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:          "test",
		Label:           "bad",
		LabelSource:     "test",
		Path:            "bad/archive.zip",
		CleaveResult:    cleaveJSON,
		LitmusResult:    []byte(`{"v":"4","prob":0.9,"class":1,"fs":[{"id":0,"prob":0.9,"class":1},{"id":1,"prob":0.82,"class":1}]}`),
		CanonicalSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}

	// Member now has cleave_result + litmus_result from explosion.
	before, err := db.SampleBySHA256(ctx, memberSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.CleaveResult) == 0 || len(before.LitmusResult) == 0 {
		t.Fatalf("precondition: Explode should have set both results, got cleave=%d bytes litmus=%d bytes", len(before.CleaveResult), len(before.LitmusResult))
	}

	// Simulate the walker re-ingesting this same content as a standalone
	// file on disk — it has no analysis to contribute. The ON CONFLICT
	// path must leave the existing results alone.
	walkerInsert := &Sample{
		SHA256:      memberSHA,
		Source:      "test",
		Label:       "unknown",
		LabelSource: "test",
		Path:        "bad/extracted/setup.py",
	}
	if _, err := db.InsertSampleNew(ctx, walkerInsert); err != nil {
		t.Fatal(err)
	}

	after, err := db.SampleBySHA256(ctx, memberSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.CleaveResult, before.CleaveResult) {
		t.Errorf("cleave_result clobbered by re-ingest:\n  before = %s\n  after  = %s", before.CleaveResult, after.CleaveResult)
	}
	if !bytes.Equal(after.LitmusResult, before.LitmusResult) {
		t.Errorf("litmus_result clobbered by re-ingest:\n  before = %s\n  after  = %s", before.LitmusResult, after.LitmusResult)
	}
}

// TestInsertSampleBatchPersistsResults covers the batch-insert path with
// cleave/litmus preset on the Sample struct. Before the column-list fix
// the batch path silently dropped these fields.
func TestInsertSampleBatchPersistsResults(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	cleave := []byte(`{"fs":[{"sha":"bloc1","type":"py"}]}`)
	litmus := []byte(`{"score":0.5}`)
	batch := []*Sample{
		{SHA256: "bloc1", Source: "test", Path: "x/1", CleaveResult: cleave, LitmusResult: litmus},
		{SHA256: "bloc2", Source: "test", Path: "x/2", CleaveResult: cleave}, // no litmus
		{SHA256: "bloc3", Source: "test", Path: "x/3"},                       // neither
	}
	if _, _, err := db.InsertSampleBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}

	got1, err := db.SampleBySHA256(ctx, "bloc1")
	if err != nil {
		t.Fatalf("SampleBySHA256(bloc1): %v", err)
	}
	if !bytes.Equal(got1.CleaveResult, cleave) {
		t.Errorf("bloc1 cleave_result = %q, want %q", got1.CleaveResult, cleave)
	}
	if !bytes.Equal(got1.LitmusResult, litmus) {
		t.Errorf("bloc1 litmus_result = %q, want %q", got1.LitmusResult, litmus)
	}
	got2, err := db.SampleBySHA256(ctx, "bloc2")
	if err != nil {
		t.Fatalf("SampleBySHA256(bloc2): %v", err)
	}
	if !bytes.Equal(got2.CleaveResult, cleave) {
		t.Errorf("bloc2 cleave_result = %q, want %q", got2.CleaveResult, cleave)
	}
	if len(got2.LitmusResult) != 0 {
		t.Errorf("bloc2 litmus_result = %q, want empty (nothing was supplied)", got2.LitmusResult)
	}
	got3, err := db.SampleBySHA256(ctx, "bloc3")
	if err != nil {
		t.Fatalf("SampleBySHA256(bloc3): %v", err)
	}
	if len(got3.CleaveResult) != 0 {
		t.Errorf("bloc3 cleave_result = %q, want empty", got3.CleaveResult)
	}
}

func TestExplodeArchiveMembersEmpty(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// No cleave result → 0 members.
	n, err := db.ExplodeArchiveMembers(ctx, &Sample{SHA256: "e1"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("exploded empty = %d, want 0", n)
	}
}

// TestLocationsDualWrite verifies that both the single-insert and batch-insert
// paths populate sample_locations alongside samples, that re-observing the
// same (sha, path) pair updates last_seen_at without adding a row, and that
// a second observation of the same sha at a new path adds a second location.
func TestLocationsDualWrite(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Single insert path.
	mustInsert(t, ctx, db, &Sample{SHA256: "loc1", Path: "bad/a.exe", Source: "harvest", Feed: "feed-a"})
	locs, err := db.LocationsForSHA(ctx, "loc1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 || locs[0].Path != "bad/a.exe" || locs[0].Source != "harvest" || locs[0].Feed != "feed-a" {
		t.Fatalf("single-insert location = %+v, want path=bad/a.exe source=harvest feed=feed-a", locs)
	}
	firstSeen := locs[0].FirstSeenAt
	firstLastSeen := locs[0].LastSeenAt

	// Re-inserting the same (sha, path) should upsert: no new row, last_seen_at bumped.
	time.Sleep(5 * time.Millisecond)
	mustInsert(t, ctx, db, &Sample{SHA256: "loc1", Path: "bad/a.exe", Source: "harvest", Feed: "feed-a"})
	locs, err = db.LocationsForSHA(ctx, "loc1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 {
		t.Fatalf("after re-observe, locations = %d, want 1", len(locs))
	}
	if !locs[0].FirstSeenAt.Equal(firstSeen) {
		t.Errorf("first_seen_at moved: got %v, want %v", locs[0].FirstSeenAt, firstSeen)
	}
	if !locs[0].LastSeenAt.After(firstLastSeen) {
		t.Errorf("last_seen_at should advance on re-observe: was %v, now %v", firstLastSeen, locs[0].LastSeenAt)
	}

	// Observing the same sha at a new path adds a second row (this is the
	// behavior the old schema's ON CONFLICT path-clobber destroyed).
	mustInsert(t, ctx, db, &Sample{SHA256: "loc1", Path: "good/a.exe", Source: "harvest", Feed: "feed-b"})
	locs, err = db.LocationsForSHA(ctx, "loc1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Fatalf("two-path observe = %d locations, want 2", len(locs))
	}

	// Batch insert path: three samples, each should produce one location row.
	batch := []*Sample{
		{SHA256: "bloc1", Path: "x/1", Source: "harvest"},
		{SHA256: "bloc2", Path: "x/2", Source: "harvest"},
		{SHA256: "bloc3", Path: "x/3", Source: "harvest"},
	}
	if _, _, err := db.InsertSampleBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	for _, s := range batch {
		locs, err := db.LocationsForSHA(ctx, s.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if len(locs) != 1 || locs[0].Path != s.Path {
			t.Errorf("batch %s location = %+v, want path=%s", s.SHA256, locs, s.Path)
		}
	}

	// Backfill path: ExplodeArchiveMembers writes through InsertSampleBatch,
	// so members should land in sample_locations with virtual paths.
	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	memberSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	parent := &Sample{
		SHA256: parentSHA, Path: "bad/archive.zip", Source: "harvest", Label: "bad", LabelSource: "test",
		CleaveResult: []byte(`{"fs":[{"sha":"` + memberSHA + `","type":"py","path":"pkg/x.py","dp":1,"ts":[{"l":5,"c":0.9}]}]}`),
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}
	memberLocs, err := db.LocationsForSHA(ctx, memberSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(memberLocs) != 1 || memberLocs[0].Path != "bad/archive.zip!!pkg/x.py" || memberLocs[0].ParentSHA256 != parentSHA {
		t.Errorf("member location = %+v, want virtual path + parent_sha256", memberLocs)
	}
}

func TestCanonicalSHA(t *testing.T) {
	tests := []struct {
		name   string
		sha    string
		result string
		want   string
	}{
		{"empty result", "ffff", "", "ffff"},
		{"invalid json", "ffff", "{bad", "ffff"},
		{"no files", "ffff", `{"fs":[]}`, "ffff"},
		{"self is min", "aaaa", `{"fs":[{"sha":"bbbb"}]}`, "aaaa"},
		{
			"embedded is min",
			"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			`{"fs":[{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			"short sha ignored",
			"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			`{"fs":[{"sha":"short"}]}`,
			"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalSHA(tt.sha, []byte(tt.result))
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInsertSampleNew(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	isNew, err := db.InsertSampleNew(ctx, &Sample{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test", Path: "test/new1"})
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("first insert should be new")
	}

	isNew, err = db.InsertSampleNew(ctx, &Sample{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test", Path: "test/new1"})
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("duplicate insert should not be new")
	}
}

func TestSamplesByEmbeddedSHA256(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Fixture carries two parallel layouts:
	//   - fs[]/sha/type is what parseCleaveFile reads (UpdateCleaveResult needs
	//     a non-empty type or it deletes the row).
	//   - files[]/sha256 is what SamplesByEmbeddedSHA256's JSON query reads.
	cleave := []byte(`{"fs":[{"sha":"parent1","type":"archive","dp":0}],` +
		`"files":[{"sha256":"embedded1","formula":"H2O","score":10},` +
		`{"sha256":"embedded2","formula":"O2","score":5}]}`)
	s := &Sample{SHA256: "parent1", Source: "test", Path: "test/parent1", CleaveResult: cleave}
	if _, err := db.InsertSampleNew(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, s.SHA256, cleave, nil, ""); err != nil {
		t.Fatal(err)
	}

	samples, err := db.SamplesByEmbeddedSHA256(ctx, "embedded1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Errorf("expected 1 sample, got %d", len(samples))
	} else if samples[0].SHA256 != "parent1" {
		t.Errorf("expected parent1, got %s", samples[0].SHA256)
	}
}

func TestRecomputeCanonicalSHA256(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parent2 := "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	embedded2 := "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// embedded2 is smaller than parent2
	cleave := []byte(`{"files": [{"sha256": "` + embedded2 + `", "formula": "H2O", "score": 10}]}`)
	s := &Sample{SHA256: parent2, Source: "test", Path: "test/" + parent2, CleaveResult: cleave, CanonicalSHA256: parent2}
	if _, err := db.InsertSampleNew(ctx, s); err != nil {
		t.Fatal(err)
	}

	// Manually set cleave_result and "wrong" canonical_sha256 since InsertSampleNew doesn't set cleave_result
	// and UpdateCleaveResult would set the correct canonical.
	if _, err := db.lite.ExecContext(ctx, "UPDATE samples SET cleave_result = ?, canonical_sha256 = ? WHERE sha256 = ?", string(cleave), parent2, parent2); err != nil {
		t.Fatal(err)
	}

	n, err := db.RecomputeCanonicalSHA256(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 row updated, got %d", n)
	}

	s2, err := db.SampleBySHA256(ctx, parent2)
	if err != nil {
		t.Fatal(err)
	}
	if s2.CanonicalSHA256 != embedded2 {
		t.Errorf("expected canonical %s, got %s", embedded2, s2.CanonicalSHA256)
	}
}

func TestFeedSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	s1 := &Sample{SHA256: "s1", Source: "test", Feed: "feed1", Ecosystem: "eco1", Label: "bad"}
	s2 := &Sample{SHA256: "s2", Source: "test", Feed: "feed2", Ecosystem: "eco2", Label: "bad"}
	mustInsert(t, ctx, db, s1)
	mustInsert(t, ctx, db, s2)

	// Update with cleave result and analyzed_at. Each row needs its own
	// payload with the matching sha so parseCleaveFile pulls a non-empty
	// file_type — otherwise UpdateCleaveResult treats the row as
	// unclassified and deletes it.
	resultFor := func(sha string) []byte {
		return []byte(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	}
	if err := db.UpdateCleaveResult(ctx, "s1", resultFor("s1"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, "s2", resultFor("s2"), nil, ""); err != nil {
		t.Fatal(err)
	}

	q := FeedQuery{Source: "test", Limit: 10}
	samples, err := db.FeedSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(samples))
	}

	q.Feeds = []string{"feed1"}
	samples, err = db.FeedSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].SHA256 != "s1" {
		t.Errorf("expected only s1, got %v", samples)
	}

	sources, err := db.FeedSources(ctx, "test", "bad")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Errorf("expected 2 sources, got %v", sources)
	}

	ecos, err := db.FeedEcosystems(ctx, "test", "bad")
	if err != nil {
		t.Fatal(err)
	}
	if len(ecos) != 2 {
		t.Errorf("expected 2 ecosystems, got %v", ecos)
	}

	count, err := db.FeedSamplesCount(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	// Test default sort order (should be mtime)
	t1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	s3 := &Sample{SHA256: "s3", Source: "test", Mtime: &t1}
	s4 := &Sample{SHA256: "s4", Source: "test", Mtime: &t2}
	mustInsert(t, ctx, db, s3)
	mustInsert(t, ctx, db, s4)
	if err := db.UpdateCleaveResult(ctx, "s3", resultFor("s3"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, "s4", resultFor("s4"), nil, ""); err != nil {
		t.Fatal(err)
	}

	q = FeedQuery{Source: "test", Limit: 10}
	samples, err = db.FeedSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	// Filter out s1, s2 which might have nil mtime or default sorting
	var sorted []string
	for _, s := range samples {
		if s.SHA256 == "s3" || s.SHA256 == "s4" {
			sorted = append(sorted, s.SHA256)
		}
	}
	if len(sorted) != 2 || sorted[0] != "s4" || sorted[1] != "s3" {
		t.Errorf("expected [s4 s3] sorted by mtime (default), got %v", sorted)
	}

	// Explicit analyzed_at sort
	q.OrderBy = "analyzed_at"
	_, err = db.FeedSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}

	// Explicit created_at sort
	q.OrderBy = "created_at"
	_, err = db.FeedSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPool(t *testing.T) {
	db := openTestDB(t)
	if db.Pool() != nil {
		t.Error("Pool() should be nil for SQLite")
	}
}

func TestStripSubscripts(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"O₃(C₂Er₂As)H₃(F₃OsPo₃)Md₃(PtBi)", "O(CErAs)H(FOsPo)Md(PtBi)"},
		{"", ""},
		{"NoPo", "NoPo"},
		{"H₁₀", "H"},
	}
	for _, tt := range tests {
		got := stripSubscripts(tt.in)
		if got != tt.want {
			t.Errorf("stripSubscripts(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseCleaveFile(t *testing.T) {
	result := []byte(`{"fs":[{"sha":"aaa","f":"O₃H₂","x":16,"dp":0}]}`)
	fi := parseCleaveFile("aaa", result)
	if fi.Formula != "O₃H₂" {
		t.Errorf("Formula = %q", fi.Formula)
	}
	if fi.Elements != "OH" {
		t.Errorf("Elements = %q", fi.Elements)
	}
	if fi.Score != 16 {
		t.Errorf("Score = %d", fi.Score)
	}

	// Empty result.
	fi = parseCleaveFile("aaa", nil)
	if fi.Formula != "" || fi.Score != 0 {
		t.Errorf("expected empty for nil result, got %+v", fi)
	}

	// Invalid JSON.
	fi = parseCleaveFile("aaa", []byte("{bad"))
	if fi.Formula != "" {
		t.Errorf("expected empty for bad JSON, got %+v", fi)
	}
}

func TestUpdateCleaveResultSetsFormulaAndScore(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "fs1", Source: "test", Label: "bad", LabelSource: "test"})
	result := []byte(`{"fs":[{"sha":"fs1","type":"elf","f":"O₃(C₂Er₂As)","x":42,"dp":0}]}`)
	if err := db.UpdateCleaveResult(ctx, "fs1", result, nil, ""); err != nil {
		t.Fatal(err)
	}

	got, err := db.SampleBySHA256(ctx, "fs1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Formula != "O₃(C₂Er₂As)" {
		t.Errorf("Formula = %q", got.Formula)
	}
	if got.Elements != "O(CErAs)" {
		t.Errorf("Elements = %q", got.Elements)
	}
	if got.Score != 42 {
		t.Errorf("Score = %d", got.Score)
	}
}

func TestDeleteSample(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "del1", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "del2", Source: "test", Label: "good", LabelSource: "test"})
	if err := db.InsertReport(ctx, &Report{SHA256: "del1", Type: "re", Content: "r"}); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteSample(ctx, "del1"); err != nil {
		t.Fatalf("DeleteSample: %v", err)
	}

	if _, err := db.SampleBySHA256(ctx, "del1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("del1 should be gone, got err=%v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "del2"); err != nil {
		t.Errorf("del2 should still exist, got err=%v", err)
	}
	reports, err := db.ReportsBySHA256(ctx, "del1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Errorf("reports for del1 should be gone, got %d", len(reports))
	}

	// Idempotent: deleting a non-existent sample is not an error.
	if err := db.DeleteSample(ctx, "doesnotexist"); err != nil {
		t.Errorf("DeleteSample(missing): %v", err)
	}
}

func TestUpdateCleaveResultDeletesOnEmptyFileType(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "nc1", Source: "test", Label: "bad", LabelSource: "test"})
	// Report with no fs[] entry → parseCleaveFile returns empty file_type →
	// the row should be deleted, not updated.
	if err := db.UpdateCleaveResult(ctx, "nc1", []byte(`{"fs":[]}`), nil, ""); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "nc1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("nc1 should be deleted, got err=%v", err)
	}
}

func TestUpdateSampleDeletesOnEmptyFileType(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "us1", Source: "test", Label: "bad", LabelSource: "test", Status: "pending"})
	if err := db.UpdateSample(ctx, "us1", "done", []byte(`{"fs":[]}`), ""); err != nil {
		t.Fatalf("UpdateSample: %v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "us1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("us1 should be deleted, got err=%v", err)
	}
}

func TestPurgeUnsupported(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Analyzed + recognized → stays.
	mustInsert(t, ctx, db, &Sample{SHA256: "keep1", Source: "test", Label: "bad", LabelSource: "test"})
	mustAnalyze(t, ctx, db, "keep1", 90)

	// Unanalyzed → stays (P3 will catch it when analysis runs).
	mustInsert(t, ctx, db, &Sample{SHA256: "keep2", Source: "test", Label: "bad", LabelSource: "test"})

	// Analyzed but unrecognized: simulate a historical row by writing a
	// cleave_result with an empty fs[] (no fs[0], so GENERATED file_type
	// evaluates to '').
	mustInsert(t, ctx, db, &Sample{SHA256: "junk1", Source: "test", Label: "bad", LabelSource: "test"})
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET cleave_result = ? WHERE sha256 = ?`,
		`{"fs":[]}`, "junk1"); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertReport(ctx, &Report{SHA256: "junk1", Type: "re", Content: "stale"}); err != nil {
		t.Fatal(err)
	}

	// Dry run: should count but not delete.
	n, err := db.PurgeUnsupported(ctx, true)
	if err != nil {
		t.Fatalf("PurgeUnsupported dry-run: %v", err)
	}
	if n != 1 {
		t.Errorf("dry-run count = %d, want 1", n)
	}
	if _, err := db.SampleBySHA256(ctx, "junk1"); err != nil {
		t.Errorf("junk1 should still exist after dry-run, got err=%v", err)
	}

	// Apply: deletes junk1 and its report, leaves keep1/keep2 alone.
	n, err = db.PurgeUnsupported(ctx, false)
	if err != nil {
		t.Fatalf("PurgeUnsupported apply: %v", err)
	}
	if n != 1 {
		t.Errorf("apply count = %d, want 1", n)
	}
	if _, err := db.SampleBySHA256(ctx, "junk1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("junk1 should be gone, got err=%v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "keep1"); err != nil {
		t.Errorf("keep1 should still exist, got err=%v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "keep2"); err != nil {
		t.Errorf("keep2 should still exist, got err=%v", err)
	}
	reports, err := db.ReportsBySHA256(ctx, "junk1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Errorf("junk1 reports should be gone, got %d", len(reports))
	}
}

func TestSanitizeJSONB(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no escapes", `{"a":"b"}`, `{"a":"b"}`},
		// Single-backslash \u0000 should be stripped.
		{"null escape", `{"v":"\u0000"}`, `{"v":""}`},
		// Double-backslash \\u0000 is a literal backslash + "u0000" — must be preserved.
		{"escaped backslash u0000", `{"v":"\\u0000"}`, `{"v":"\\u0000"}`},
		// \x86 (single backslash) → \u0086
		{"hex escape", `{"v":"\x86"}`, `{"v":"\u0086"}`},
		// \\x86 is a literal backslash + "x86" — must be preserved.
		{"escaped backslash x86", `{"v":"\\x86"}`, `{"v":"\\x86"}`},
		// Mixed: real null inside a range pattern.
		{"null in range", `{"v":"/[^\u0000-\u001f]/"}`, `{"v":"/[^-\u001f]/"}`},
		// \\u0000 inside a JS regex pattern should be left alone.
		{"escaped null in range", `{"v":"/[^\\u0000-\\u001f]/"}`, `{"v":"/[^\\u0000-\\u001f]/"}`},
		// \x00 → \u0000 → stripped
		{"hex null", `{"v":"\x00"}`, `{"v":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(sanitizeJSONB([]byte(tt.in)))
			if got != tt.want {
				t.Errorf("sanitizeJSONB(%q)\n  got  %q\n  want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMarkMissingSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Create a real file and a path that doesn't exist.
	realFile := filepath.Join(t.TempDir(), "real.exe")
	if err := os.WriteFile(realFile, []byte("MZ..."), 0o644); err != nil {
		t.Fatal(err)
	}
	gonePath := filepath.Join(t.TempDir(), "gone.exe")

	// Insert samples: one with a real file, one with a missing file,
	// one with a real file but not in the walked set (unsupported).
	mustInsert(t, ctx, db, &Sample{SHA256: "aaa1", Path: realFile, Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "bbb2", Path: gonePath, Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "ccc3", Path: realFile, Label: "bad"})

	// Only aaa1 was seen by iter-files.
	walkedPaths := map[string]struct{}{realFile: {}}
	wasWalked := func(path string) bool {
		_, ok := walkedPaths[path]
		return ok
	}

	// But ccc3 has the same path as aaa1 — both exist on disk.
	// Only aaa1 is in walkedPaths, so ccc3 should be marked as unsupported.
	// Wait — ccc3 has the same path, so it IS in walkedPaths. Let me use a different path.
	unsupportedFile := filepath.Join(t.TempDir(), "readme.txt")
	if err := os.WriteFile(unsupportedFile, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: "ddd4", Path: unsupportedFile, Label: "bad"})

	marked, err := db.MarkMissingSamples(ctx, wasWalked)
	if err != nil {
		t.Fatal(err)
	}

	// bbb2 (missing) + ddd4 (unsupported) = 2 marked.
	// aaa1 is in walkedPaths so untouched.
	// ccc3 has same path as aaa1 which is in walkedPaths, so untouched.
	if marked != 2 {
		t.Errorf("marked = %d, want 2", marked)
	}

	// Verify skip values.
	s, err := db.SampleBySHA256(ctx, "aaa1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Skip != "" {
		t.Errorf("aaa1 skip = %q, want empty", s.Skip)
	}
	s, err = db.SampleBySHA256(ctx, "bbb2")
	if err != nil {
		t.Fatal(err)
	}
	if s.Skip != "missing" {
		t.Errorf("bbb2 skip = %q, want 'missing'", s.Skip)
	}
	s, err = db.SampleBySHA256(ctx, "ddd4")
	if err != nil {
		t.Fatal(err)
	}
	if s.Skip != "unsupported" {
		t.Errorf("ddd4 skip = %q, want 'unsupported'", s.Skip)
	}
}

func TestClaimJobsSkipsMarkedSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert 3 unanalyzed samples: one normal, one skipped, one missing.
	mustInsert(t, ctx, db, &Sample{SHA256: "claim1", Path: "/data/a.exe", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "claim2", Path: "/data/b.exe", Label: "bad", Skip: "unsupported"})
	mustInsert(t, ctx, db, &Sample{SHA256: "claim3", Path: "/data/c.exe", Label: "bad", Skip: "missing"})

	jobs, err := db.ClaimJobs(ctx, "testworker", 10, 30*time.Minute, "", 7*24*time.Hour, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Only claim1 should be returned — the other two have non-empty skip.
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if jobs[0].SHA256 != "claim1" {
		t.Errorf("got sha256 = %q, want 'claim1'", jobs[0].SHA256)
	}
}

func TestClaimJobsRetriesOldErrorsAfterRestart(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "err1", Path: "/data/a.exe", Label: "bad"})
	if err := db.SetNote(ctx, "err1", "worker failed"); err != nil {
		t.Fatal(err)
	}

	currentRunStart := time.Now().Add(-time.Hour)
	jobs, err := db.ClaimJobs(ctx, "worker1", 10, 30*time.Minute, "", 7*24*time.Hour, currentRunStart, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("current-run error claimed: got %+v, want none", jobs)
	}

	restartAfterError := time.Now().Add(time.Hour)
	jobs, err = db.ClaimJobs(ctx, "worker2", 10, 30*time.Minute, "", 7*24*time.Hour, restartAfterError, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != "err1" {
		t.Fatalf("old error after restart: got %+v, want err1", jobs)
	}
}

func TestClaimJobsExpiry(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "exp1", Path: "/data/a.exe", Label: "bad"})

	// Claim it.
	jobs, err := db.ClaimJobs(ctx, "worker1", 1, 30*time.Minute, "", 7*24*time.Hour, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("first claim: got %d jobs, want 1", len(jobs))
	}

	// Try to claim again — should get nothing (still claimed).
	jobs, err = db.ClaimJobs(ctx, "worker2", 1, 30*time.Minute, "", 7*24*time.Hour, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("second claim: got %d jobs, want 0", len(jobs))
	}

	// Claim with zero expiry — should reclaim the expired job.
	jobs, err = db.ClaimJobs(ctx, "worker2", 1, 0, "", 7*24*time.Hour, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expired claim: got %d jobs, want 1", len(jobs))
	}
	if jobs[0].SHA256 != "exp1" {
		t.Errorf("got sha256 = %q, want 'exp1'", jobs[0].SHA256)
	}
}
