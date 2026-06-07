package hopper

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	if got.FirstAnalyzedAt == nil {
		t.Error("FirstAnalyzedAt should be set")
	}
}

func TestUpdateCleaveResultPreservesFirstAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "fa1", Source: "test", Label: "bad", LabelSource: "test"})
	result := []byte(`{"fs":[{"sha":"fa1","type":"elf","dp":0,"x":1}]}`)
	if err := db.UpdateCleaveResult(ctx, "fa1", result, nil, "old"); err != nil {
		t.Fatal(err)
	}
	first, err := db.SampleBySHA256(ctx, "fa1")
	if err != nil {
		t.Fatal(err)
	}
	if first.FirstAnalyzedAt == nil || first.AnalyzedAt == nil {
		t.Fatalf("first analysis timestamps missing: %+v", first)
	}

	time.Sleep(2 * time.Millisecond)
	result = []byte(`{"fs":[{"sha":"fa1","type":"elf","dp":0,"x":2}]}`)
	if err := db.UpdateCleaveResult(ctx, "fa1", result, nil, "new"); err != nil {
		t.Fatal(err)
	}
	second, err := db.SampleBySHA256(ctx, "fa1")
	if err != nil {
		t.Fatal(err)
	}
	if second.FirstAnalyzedAt == nil || !second.FirstAnalyzedAt.Equal(*first.FirstAnalyzedAt) {
		t.Fatalf("first_analyzed_at = %v, want preserved %v", second.FirstAnalyzedAt, first.FirstAnalyzedAt)
	}
	if second.AnalyzedAt == nil || !second.AnalyzedAt.After(*first.AnalyzedAt) {
		t.Fatalf("analyzed_at = %v, want after %v", second.AnalyzedAt, first.AnalyzedAt)
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

func TestClassifyLabelTransition(t *testing.T) {
	tests := []struct {
		name                           string
		stored, storedSrc, storedSkip  string
		in, inSrc                      string
		wantCategory, wantFrom, wantTo string
	}{
		{"promote unknown to good", "unknown", "forager", "", "good", "forager", "promoted", "unknown", "good"},
		{"promote unknown to bad", "unknown", "forager", "", "bad", "forager", "promoted", "unknown", "bad"},
		{"conflict good then bad", "good", "forager", "", "bad", "forager", "conflict", "good", "bad"},
		{"conflict bad then good", "bad", "forager", "", "good", "forager", "conflict", "bad", "bad"},
		{"unknown does not demote good", "good", "forager", "", "unknown", "forager", "", "", ""},
		{"equal labels no change", "bad", "forager", "", "bad", "forager", "", "", ""},
		{"incoming marker is logged in go", "unknown", "forager", "", "good", "marker", "", "", ""},
		{"rehabilitate cleared marker", "bad", "marker", "misclassified", "bad", "forager", "rehabilitated", "bad", "bad"},
		{"rehabilitate flipped marker", "good", "marker", "misclassified", "bad", "forager", "rehabilitated", "good", "bad"},
		{"stale marker already clean no change", "bad", "marker", "", "bad", "forager", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, from, to := classifyLabelTransition(tt.stored, tt.storedSrc, tt.storedSkip, tt.in, tt.inSrc)
			if cat != tt.wantCategory || from != tt.wantFrom || to != tt.wantTo {
				t.Errorf("classifyLabelTransition = (%q,%q,%q), want (%q,%q,%q)",
					cat, from, to, tt.wantCategory, tt.wantFrom, tt.wantTo)
			}
		})
	}
}

// TestLabelPrecedenceOnReobservation exercises the ON CONFLICT pool-precedence
// resolution end-to-end through InsertSampleBatch (the same path the load
// pipeline uses), one rule per subtest.
func TestLabelPrecedenceOnReobservation(t *testing.T) {
	reobserve := func(t *testing.T, ctx context.Context, db *DB, s *Sample) {
		t.Helper()
		if _, _, err := db.InsertSampleBatch(ctx, []*Sample{s}); err != nil {
			t.Fatalf("InsertSampleBatch: %v", err)
		}
	}
	want := func(t *testing.T, ctx context.Context, db *DB, sha, label, source, skip string) {
		t.Helper()
		got, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha, err)
		}
		if got.Label != label || got.LabelSource != source || got.Skip != skip {
			t.Errorf("%s: got (label=%q source=%q skip=%q), want (label=%q source=%q skip=%q)",
				sha, got.Label, got.LabelSource, got.Skip, label, source, skip)
		}
	}

	t.Run("promote unknown to good", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "p1", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/p1", SizeBytes: 1})
		reobserve(t, ctx, db, &Sample{SHA256: "p1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/p1", SizeBytes: 1})
		want(t, ctx, db, "p1", "good", "forager", "")
	})

	t.Run("promote unknown to bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "p2", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/p2", SizeBytes: 1})
		reobserve(t, ctx, db, &Sample{SHA256: "p2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/p2", SizeBytes: 1})
		want(t, ctx, db, "p2", "bad", "forager", "")
	})

	t.Run("conflict good then bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "c1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/c1", SizeBytes: 1})
		reobserve(t, ctx, db, &Sample{SHA256: "c1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/c1", SizeBytes: 1})
		want(t, ctx, db, "c1", "bad", "conflict", "conflict")
	})

	t.Run("conflict bad then good resolves to bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "c2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/c2", SizeBytes: 1})
		reobserve(t, ctx, db, &Sample{SHA256: "c2", Source: "test", Label: "good", LabelSource: "forager", Path: "good/c2", SizeBytes: 1})
		want(t, ctx, db, "c2", "bad", "conflict", "conflict")
	})

	t.Run("unknown does not demote", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "d1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/d1", SizeBytes: 1})
		reobserve(t, ctx, db, &Sample{SHA256: "d1", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/d1", SizeBytes: 1})
		want(t, ctx, db, "d1", "good", "forager", "")
	})

	t.Run("incoming marker is authoritative", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "m1", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/m1", SizeBytes: 1})
		// A good/ file carrying a .BAD marker: Go flips it before insert.
		reobserve(t, ctx, db, &Sample{SHA256: "m1", Source: "test", Label: "bad", LabelSource: "marker", Skip: "misclassified", Path: "good/m1", SizeBytes: 1})
		want(t, ctx, db, "m1", "bad", "marker", "misclassified")
	})

	t.Run("rehabilitate after marker removed", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		// Stored quarantine from a good/ file with a .BAD marker.
		reobserve(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "marker", Skip: "misclassified", Path: "good/r1", SizeBytes: 1})
		// Moved into bad/ with the marker dropped: plain pool observation.
		reobserve(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/r1", SizeBytes: 1})
		want(t, ctx, db, "r1", "bad", "forager", "")
	})

	t.Run("missing auto-heals on re-observation", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "g1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/g1", SizeBytes: 1})
		if err := db.SetSkip(ctx, "g1", "missing"); err != nil {
			t.Fatal(err)
		}
		reobserve(t, ctx, db, &Sample{SHA256: "g1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/g1", SizeBytes: 1})
		want(t, ctx, db, "g1", "bad", "forager", "")
	})

	t.Run("missing returning as conflict is quarantined", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "g2", Source: "test", Label: "good", LabelSource: "forager", Path: "good/g2", SizeBytes: 1})
		if err := db.SetSkip(ctx, "g2", "missing"); err != nil {
			t.Fatal(err)
		}
		reobserve(t, ctx, db, &Sample{SHA256: "g2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/g2", SizeBytes: 1})
		want(t, ctx, db, "g2", "bad", "conflict", "conflict")
	})

	t.Run("hard skip preserved on promotion", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "h1", Source: "test", Label: "unknown", LabelSource: "forager", Skip: "corrupt", Path: "unknown/h1", SizeBytes: 1})
		reobserve(t, ctx, db, &Sample{SHA256: "h1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/h1", SizeBytes: 1})
		want(t, ctx, db, "h1", "good", "forager", "corrupt")
	})

	t.Run("archive member never changes top-level label", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "a1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/a1", SizeBytes: 1})
		// Same content hash seen inside a bad archive (parent set).
		reobserve(t, ctx, db, &Sample{SHA256: "a1", Source: "test", Label: "bad", LabelSource: "forager", Parent: "archivesha", Path: "bad/arc.zip!!a1", SizeBytes: 1})
		want(t, ctx, db, "a1", "good", "forager", "")
	})
}

func TestConflictReview(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Create a good+bad conflict and an ordinary bad sample.
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{SHA256: "k1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/k1", SizeBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{SHA256: "k1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/k1", SizeBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{SHA256: "k2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/k2", SizeBytes: 1}}); err != nil {
		t.Fatal(err)
	}

	got, err := db.ConflictReview(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "k1" {
		t.Fatalf("ConflictReview returned %d rows (%v), want just k1", len(got), got)
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

	// hopperStart in the future so all three rows' analyzed_at is "before"
	// start. Only fr1 should be returned: fr2 is outside the prefix, fr3 is
	// marked skip.
	hopperStart := time.Now().Add(time.Hour)
	jobs, err := db.ForceRescanCandidates(ctx, hopperStart, []string{"bad/pkg"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != "fr1" {
		t.Fatalf("force-rescan candidates: got %+v, want [fr1]", jobs)
	}

	// Candidate fetches must not mutate samples. Prior analysis stays put.
	rescanned, err := db.SampleBySHA256(ctx, "fr1")
	if err != nil {
		t.Fatal(err)
	}
	if rescanned.CleaveResult == nil || rescanned.LitmusResult == nil || rescanned.TraitsVersion != "oldtv" {
		t.Fatalf("fr1 data was reset at fetch time: %+v", rescanned)
	}
	for _, sha := range []string{"fr2", "fr3"} {
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if s.CleaveResult == nil || s.LitmusResult == nil || s.TraitsVersion != "oldtv" {
			t.Fatalf("%s unexpectedly affected: %+v", sha, s)
		}
	}

	// Empty prefixes: caller is opting out of Tier 2.
	jobs, err = db.ForceRescanCandidates(ctx, hopperStart, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("empty prefixes should return no candidates: got %+v", jobs)
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

	jobs, err := db.StaleTraitsCandidates(ctx, "new-traits", 72*time.Hour, time.Now(), 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{samples[0].sha, samples[1].sha, samples[2].sha, samples[3].sha}
	if len(jobs) != len(want) {
		t.Fatalf("got %d jobs, want %d: %+v", len(jobs), len(want), jobs)
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

// TestLitmusResultForMemberAcceptsV4AndV5 exercises the per-member envelope
// extraction directly. The function must inherit envelope-level metadata
// (version/threshold/level for v=5, version/thresholds for v=4) onto the
// per-member result so downstream consumers can interpret it standalone.
func TestLitmusResultForMemberAcceptsV4AndV5(t *testing.T) {
	cases := []struct {
		name        string
		parent      []byte
		wantPresent []string // envelope-level keys that must appear on the member
		wantAbsent  []string // envelope-level keys that must NOT appear on the member
	}{
		{
			name:        "v4 envelope",
			parent:      []byte(`{"v":"4","prob":0.97,"class":1,"version":"vtest","thresholds":[0.5,0.9],"fs":[{"id":0,"prob":0.91,"class":1}]}`),
			wantPresent: []string{"v", "version", "thresholds"},
			wantAbsent:  []string{"threshold", "level"},
		},
		{
			name:        "v5 envelope",
			parent:      []byte(`{"v":"5","prob":0.97,"class":1,"version":"vtest","threshold":0.9,"level":3,"fs":[{"id":0,"prob":0.91,"class":1,"threshold":0.9}]}`),
			wantPresent: []string{"v", "version", "threshold", "level"},
			wantAbsent:  []string{"thresholds"},
		},
		{
			name:        "v5 envelope with null level (manual thresholds)",
			parent:      []byte(`{"v":"5","prob":0.97,"class":1,"version":"vtest","threshold":0.9,"level":null,"fs":[{"id":0,"prob":0.91,"class":1,"threshold":0.9}]}`),
			wantPresent: []string{"v", "version", "threshold", "level"},
			wantAbsent:  []string{"thresholds"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := litmusResultForMember(tc.parent, 0)
			if got == nil {
				t.Fatal("got nil; want member envelope")
			}
			var out map[string]json.RawMessage
			if err := json.Unmarshal(got, &out); err != nil {
				t.Fatalf("unmarshal member: %v", err)
			}
			// Member's own prob must survive.
			if _, ok := out["prob"]; !ok {
				t.Error("member missing prob")
			}
			for _, k := range tc.wantPresent {
				if _, ok := out[k]; !ok {
					t.Errorf("missing envelope-level key %q on member; got: %s", k, got)
				}
			}
			for _, k := range tc.wantAbsent {
				if _, ok := out[k]; ok {
					t.Errorf("unexpected envelope-level key %q on member; got: %s", k, got)
				}
			}
		})
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

	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{
		SHA256:       parentSHA,
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.zip",
		CleaveResult: parentCleave,
		LitmusResult: parentLitmus,
	}}); err != nil {
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
	if parent.FirstAnalyzedAt == nil {
		t.Fatal("SampleParentInfo did not fetch first_analyzed_at")
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
	if child.FirstAnalyzedAt == nil || !child.FirstAnalyzedAt.Equal(*parent.FirstAnalyzedAt) {
		t.Fatalf("child first_analyzed_at = %v, want parent first_analyzed_at %v", child.FirstAnalyzedAt, parent.FirstAnalyzedAt)
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

	ecos, err := db.FeedEcosystems(ctx, "test", "bad", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ecos) != 2 {
		t.Errorf("expected 2 ecosystems, got %v", ecos)
	}

	// A since within the window keeps both freshly-inserted ecosystems; a
	// since in the future excludes them, exercising both filter branches.
	recent, err := db.FeedEcosystems(ctx, "test", "bad", time.Now().Add(-72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 {
		t.Errorf("expected 2 recent ecosystems, got %v", recent)
	}
	future, err := db.FeedEcosystems(ctx, "test", "bad", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(future) != 0 {
		t.Errorf("expected 0 ecosystems past the cutoff, got %v", future)
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

// TestFeedSamplesSearch exercises the free-text Search predicate: a
// case-insensitive filename substring or an exact sha256, applied in SQL so it
// spans the whole index rather than an in-memory page. LIKE metacharacters in
// the term must match literally, not as wildcards.
func TestFeedSamplesSearch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	resultFor := func(sha string) []byte {
		return []byte(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	}
	insert := func(sha, filename string) {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Filename: filename})
		if err := db.UpdateCleaveResult(ctx, sha, resultFor(sha), nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	insert("abc123def", "requests.tar.gz")
	insert("beef0001", "left-pad.js")
	insert("cafe0002", "100%_real.bin")

	shas := func(q FeedQuery) []string {
		q.Source = "test"
		q.Limit = 10
		samples, err := db.FeedSamples(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		count, err := db.FeedSamplesCount(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if count != len(samples) {
			t.Errorf("count %d disagrees with %d rows for %q", count, len(samples), q.Search)
		}
		out := make([]string, len(samples))
		for i, s := range samples {
			out[i] = s.SHA256
		}
		slices.Sort(out)
		return out
	}

	tests := []struct {
		name   string
		search string
		want   []string
	}{
		{"empty matches all", "", []string{"abc123def", "beef0001", "cafe0002"}},
		{"filename substring", "requests", []string{"abc123def"}},
		{"filename case-insensitive", "REQUESTS", []string{"abc123def"}},
		{"sha exact match", "beef0001", []string{"beef0001"}},
		{"sha partial no longer matches", "beef000", nil},
		{"no match", "nonexistent", nil},
		{"percent is literal not wildcard", "100%", []string{"cafe0002"}},
		// A bare "%" is a literal percent sign, so it matches only the
		// filename that contains one — not every row, as it would if the
		// term leaked through as a LIKE wildcard.
		{"bare percent is literal", "%", []string{"cafe0002"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shas(FeedQuery{Search: tt.search})
			if !slices.Equal(got, tt.want) {
				t.Errorf("Search(%q) = %v, want %v", tt.search, got, tt.want)
			}
		})
	}
}

// TestFeedSamplesLitmusClassesV6 locks in the v6 `l` → 0/1/2 class derivation
// used by the LitmusClasses filter, mirroring prism's envelopeClass: -1 benign,
// null manual-mode hostile, 0..=CriticalLevel hostile, above suspicious. It
// guards the regression where the hostile filter dropped v6 rows.
func TestFeedSamplesLitmusClassesV6(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// class is the expected 0/1/2 bucket under the default CriticalLevel (4).
	rows := []struct {
		sha    string
		litmus string
		class  int
	}{
		{"v6null", `{"v":"6","l":null}`, 2}, // manual-mode hostile, fail-safe
		{"v6lo", `{"v":"6","l":0}`, 2},      // fires at the strictest level
		{"v6crit", `{"v":"6","l":4}`, 2},    // boundary: at the critical line
		{"v6susp", `{"v":"6","l":10}`, 1},   // fires only above the line
		{"v6benign", `{"v":"6","l":-1}`, 0}, // never fires
		{"legacy2", `{"v":"4","class":2}`, 2},
		{"legacy1", `{"v":"4","class":1}`, 1},
	}
	for _, r := range rows {
		mustInsert(t, ctx, db, &Sample{SHA256: r.sha, Source: "v6test", Label: "bad"})
		if err := db.UpdateCleaveResult(ctx, r.sha, []byte(`{"fs":[{"sha":"`+r.sha+`","type":"elf","dp":0}]}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateLitmusResult(ctx, r.sha, []byte(r.litmus)); err != nil {
			t.Fatal(err)
		}
	}

	for class := range 3 {
		q := FeedQuery{Source: "v6test", Limit: 100, CriticalLevel: 4, LitmusClasses: []int{class}}
		samples, err := db.FeedSamples(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]bool, len(samples))
		for _, s := range samples {
			got[s.SHA256] = true
		}
		count, err := db.FeedSamplesCount(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if count != len(samples) {
			t.Errorf("class=%d: count %d != len(samples) %d", class, count, len(samples))
		}
		for _, r := range rows {
			if want := r.class == class; got[r.sha] != want {
				t.Errorf("class=%d filter: %s (l-class %d) present=%v, want %v", class, r.sha, r.class, got[r.sha], want)
			}
		}
	}

	// A caller-pinned cutoff moves the line: with CriticalLevel=3, l=4 (hostile
	// at the default cutoff) becomes suspicious. This is the consistency knob.
	q := FeedQuery{Source: "v6test", Limit: 100, CriticalLevel: 3, LitmusClasses: []int{1}}
	samples, err := db.FeedSamples(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range samples {
		if s.SHA256 == "v6crit" {
			found = true
		}
	}
	if !found {
		t.Errorf("CriticalLevel=3: expected v6crit (l=4) to be classed suspicious")
	}
}

func TestPool(t *testing.T) {
	db := openTestDB(t)
	if db.Pool() != nil {
		t.Error("Pool() should be nil for SQLite")
	}
}

func TestWorkflowLatestReadyUsesFirstAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	oldFirst := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	newFirst := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	oldCreated := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	newCreated := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

	for _, sha := range []string{"ready-old", "ready-new"} {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "bad", LabelSource: "test"})
		if err := db.UpdateCleaveResult(ctx, sha, []byte(`{"fs":[{"sha":"`+sha+`","type":"elf","dp":0}]}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"prob":0.9,"class":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET created_at = ?, first_analyzed_at = ?, analyzed_at = ? WHERE sha256 = ?`,
		oldCreated.Format(time.RFC3339Nano), oldFirst.Format(time.RFC3339Nano), oldFirst.Format(time.RFC3339Nano), "ready-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET created_at = ?, first_analyzed_at = ?, analyzed_at = ? WHERE sha256 = ?`,
		newCreated.Format(time.RFC3339Nano), newFirst.Format(time.RFC3339Nano), newFirst.Format(time.RFC3339Nano), "ready-new"); err != nil {
		t.Fatal(err)
	}

	rows, err := db.WorkflowLatestReady(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].SHA256 != "ready-new" || rows[1].SHA256 != "ready-old" {
		t.Fatalf("latest ready order = %+v, want ready-new then ready-old", rows)
	}
	if rows[0].FirstAnalyzedAt == nil || !rows[0].FirstAnalyzedAt.Equal(newFirst) {
		t.Fatalf("first analyzed = %v, want %v", rows[0].FirstAnalyzedAt, newFirst)
	}
	h, err := db.WorkflowHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !h.LatestReady.Equal(newFirst) {
		t.Fatalf("health latest ready = %v, want %v", h.LatestReady, newFirst)
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

func TestParseCleaveResultV5KeepsMetadataAndIgnoresFacts(t *testing.T) {
	result := []byte(`{"v":"5","tv":"abcde","fs":[{"sha":"aaa","type":"pe","f":"O₃","x":16,"dp":0,"ts":[{"l":4},{"l":5}],"ff":{"id":"pe","m":{"binary":{"overall_entropy":7.2}},"v":{"pe.machine":"x86_64"}}}]}`)
	parsed := ParseCleaveResult("aaa", result)
	if parsed.TraitsVersion != "abcde" {
		t.Fatalf("TraitsVersion = %q", parsed.TraitsVersion)
	}
	if parsed.FileInfo.FileType != "pe" || parsed.FileInfo.Formula != "O₃" || parsed.FileInfo.Score != 16 {
		t.Fatalf("FileInfo = %+v", parsed.FileInfo)
	}
	if parsed.FileInfo.MaxCrit != 5 || parsed.FileInfo.SuspiciousCount != 2 {
		t.Fatalf("crit summary = max %d suspicious %d", parsed.FileInfo.MaxCrit, parsed.FileInfo.SuspiciousCount)
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

func TestUpdateCleaveResultCompactsArchiveStorage(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	childSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result := []byte(`{"tv":"abcde","fs":[` +
		`{"sha":"` + parentSHA + `","type":"zip","path":"archive.zip","dp":0,"x":7},` +
		`{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1,"x":3}` +
		`]}`)
	mustInsert(t, ctx, db, &Sample{SHA256: parentSHA, Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, parentSHA, result, nil, "abcde"); err != nil {
		t.Fatal(err)
	}

	got, err := db.SampleBySHA256(ctx, parentSHA)
	if err != nil {
		t.Fatal(err)
	}
	if got.CanonicalSHA256 != childSHA {
		t.Fatalf("canonical = %s, want embedded child %s", got.CanonicalSHA256, childSHA)
	}
	var stored struct {
		TraitsVersion string `json:"tv"`
		Files         []struct {
			SHA256 string `json:"sha"`
			Depth  int    `json:"dp"`
		} `json:"fs"`
		Truncated    bool `json:"truncated"`
		OmittedFiles int  `json:"omitted_files"`
	}
	if err := json.Unmarshal(got.CleaveResult, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Files) != 1 || stored.Files[0].SHA256 != parentSHA || stored.Files[0].Depth != 0 {
		t.Fatalf("stored fs = %+v, want only parent", stored.Files)
	}
	if !stored.Truncated || stored.OmittedFiles != 1 || stored.TraitsVersion != "abcde" {
		t.Fatalf("stored compact metadata = %+v", stored)
	}
	if bytes.Contains(got.CleaveResult, []byte(childSHA)) {
		t.Fatalf("stored cleave_result still contains child sha: %s", got.CleaveResult)
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

func TestScrubNULs(t *testing.T) {
	s := &Sample{
		SHA256:   "abc",
		Path:     "pkg/bin\x00.exe",
		Filename: "evil\x00.sh",
		Package:  "left\x00pad",
		Version:  "1.0\x000",
		Elements: "C\x00H4",
		Label:    "bad", // no NUL, must be untouched
	}
	s.scrubNULs()

	for field, got := range map[string]string{
		"Path": s.Path, "Filename": s.Filename, "Package": s.Package,
		"Version": s.Version, "Elements": s.Elements,
	} {
		if strings.IndexByte(got, 0) >= 0 {
			t.Errorf("scrubNULs left a NUL in %s: %q", field, got)
		}
	}
	if s.Path != "pkg/bin.exe" {
		t.Errorf("Path = %q, want %q", s.Path, "pkg/bin.exe")
	}
	if s.Label != "bad" {
		t.Errorf("Label = %q, want unchanged %q", s.Label, "bad")
	}
}

// ageLocation backdates a sample's standalone location so reconciliation treats
// it as not-seen-this-walk, simulating a file that has moved away.
func loc(sha, path string) SampleLocationKey { return SampleLocationKey{SHA256: sha, Path: path} }

// stageWalk resets the staging table and records the given files as present in
// the current walk, exactly as runDirPipeline streams them in during a real
// walk. Files not listed are, by definition, not present this walk.
func stageWalk(t *testing.T, ctx context.Context, db *DB, present ...SampleLocationKey) {
	t.Helper()
	if err := db.StartWalkStaging(ctx); err != nil {
		t.Fatalf("StartWalkStaging: %v", err)
	}
	if err := db.StageLocations(ctx, present); err != nil {
		t.Fatalf("StageLocations: %v", err)
	}
}

func skipOf(t *testing.T, ctx context.Context, db *DB, sha string) string {
	t.Helper()
	s, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256(%s): %v", sha, err)
	}
	return s.Skip
}

func labelOf(t *testing.T, ctx context.Context, db *DB, sha string) string {
	t.Helper()
	s, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256(%s): %v", sha, err)
	}
	return s.Label
}

// TestReconcilePoolsRelabel covers the pool-placement label transitions:
// demotion (bad→good), promotion (good→bad), the both-pools conflict, and the
// marker exemption.
func TestReconcilePoolsRelabel(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// dem: stored bad, but its only copy is now in good/ → demote to good.
	mustInsert(t, ctx, db, &Sample{SHA256: "dem", Path: "good/dem.bin", Label: "bad", LabelSource: "local"})
	// pro: stored good, but now in bad/ → promote to bad.
	mustInsert(t, ctx, db, &Sample{SHA256: "pro", Path: "bad/pro.bin", Label: "good", LabelSource: "local"})
	// conf: present in both good/ and bad/ at once → bad + skip='conflict'.
	mustInsert(t, ctx, db, &Sample{SHA256: "conf", Path: "good/conf.bin", Label: "good", LabelSource: "local"})
	mustInsert(t, ctx, db, &Sample{SHA256: "conf", Path: "bad/conf.bin", Label: "good", LabelSource: "local"})
	// mark: a marker label must never be overridden by pool placement.
	mustInsert(t, ctx, db, &Sample{SHA256: "mark", Path: "bad/mark.bin", Label: "good", LabelSource: "marker", Skip: "misclassified"})

	stageWalk(t, ctx, db,
		loc("dem", "good/dem.bin"),
		loc("pro", "bad/pro.bin"),
		loc("conf", "good/conf.bin"), loc("conf", "bad/conf.bin"),
		loc("mark", "bad/mark.bin"),
	)
	if _, err := db.ReconcilePools(ctx, func(p string) string { return p }); err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}

	if got := labelOf(t, ctx, db, "dem"); got != "good" {
		t.Errorf("dem label = %q, want good (demoted)", got)
	}
	if got := labelOf(t, ctx, db, "pro"); got != "bad" {
		t.Errorf("pro label = %q, want bad (promoted)", got)
	}
	if got := labelOf(t, ctx, db, "conf"); got != "bad" {
		t.Errorf("conf label = %q, want bad (conflict)", got)
	}
	if got := skipOf(t, ctx, db, "conf"); got != "conflict" {
		t.Errorf("conf skip = %q, want conflict", got)
	}
	if got := labelOf(t, ctx, db, "mark"); got != "good" {
		t.Errorf("marker sample relabeled to %q, want good (untouched)", got)
	}

	// dem, pro, conf each produced one audit row; mark did not change.
	var events int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT count(*) FROM label_events WHERE sha256 IN ('dem','pro','conf','mark')`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 3 {
		t.Errorf("label_events = %d, want 3", events)
	}
}

// TestReconcilePoolsMissing covers marking standalone files missing (including
// already-analyzed ones) vs unsupported.
func TestReconcilePoolsMissing(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	realFile := filepath.Join(t.TempDir(), "present.bin")
	if err := os.WriteFile(realFile, []byte("MZ...."), 0o644); err != nil {
		t.Fatal(err)
	}
	disk := func(p string) string {
		if p == "bad/present.bin" {
			return realFile
		}
		return filepath.Join(t.TempDir(), "nope", p) // never exists
	}

	// seen: present this walk. gone: analyzed then moved away. unsup: on disk
	// but not enumerated this walk.
	mustInsert(t, ctx, db, &Sample{SHA256: "seen", Path: "bad/seen.bin", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "gone", Path: "bad/gone.bin", Label: "bad"})
	mustAnalyze(t, ctx, db, "gone", 5)
	mustInsert(t, ctx, db, &Sample{SHA256: "unsup", Path: "bad/present.bin", Label: "bad"})

	stageWalk(t, ctx, db, loc("seen", "bad/seen.bin"))
	st, err := db.ReconcilePools(ctx, disk)
	if err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if st.MarkedMissing != 1 || st.MarkedUnsupported != 1 {
		t.Errorf("stats missing=%d unsupported=%d, want 1/1", st.MarkedMissing, st.MarkedUnsupported)
	}
	if got := skipOf(t, ctx, db, "seen"); got != "" {
		t.Errorf("seen skip = %q, want empty", got)
	}
	if got := skipOf(t, ctx, db, "gone"); got != "missing" {
		t.Errorf("gone skip = %q, want missing (analyzed file moved away)", got)
	}
	if got := skipOf(t, ctx, db, "unsup"); got != "unsupported" {
		t.Errorf("unsup skip = %q, want unsupported", got)
	}
}

// TestReconcilePoolsCascade covers missing cascading to archive members, the
// shared-archive veto, and revival when an archive reappears.
func TestReconcilePoolsCascade(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	gone := func(p string) string { return filepath.Join(t.TempDir(), "nope", p) }

	// Good archive G and bad archive P.
	mustInsert(t, ctx, db, &Sample{SHA256: "G", Path: "good/pkg.tgz", Label: "good"})
	mustInsert(t, ctx, db, &Sample{SHA256: "P", Path: "bad/arch.tgz", Label: "bad"})

	// C1 lives only inside P. C2 lives inside P AND inside live G (shared file).
	mustInsert(t, ctx, db, &Sample{SHA256: "C1", Parent: "P", Path: "bad/arch.tgz!!evil.js", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "C2", Parent: "P", Path: "bad/arch.tgz!!shared.js", Label: "bad"})
	// Second containment edge for C2: also a member of live archive G.
	mustInsert(t, ctx, db, &Sample{SHA256: "C2", Parent: "G", Path: "good/pkg.tgz!!shared.js", Label: "good"})

	// P moved away; only G is present this walk.
	stageWalk(t, ctx, db, loc("G", "good/pkg.tgz"))
	st, err := db.ReconcilePools(ctx, gone)
	if err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if got := skipOf(t, ctx, db, "P"); got != "missing" {
		t.Errorf("P skip = %q, want missing", got)
	}
	if got := skipOf(t, ctx, db, "C1"); got != "missing" {
		t.Errorf("C1 skip = %q, want missing (orphaned member)", got)
	}
	if got := skipOf(t, ctx, db, "C2"); got != "" {
		t.Errorf("C2 skip = %q, want empty (shared with live archive — veto)", got)
	}
	if st.CascadedMissing != 1 {
		t.Errorf("CascadedMissing = %d, want 1", st.CascadedMissing)
	}

	// P reappears: both archives present this walk → C1 revives.
	stageWalk(t, ctx, db, loc("G", "good/pkg.tgz"), loc("P", "bad/arch.tgz"))
	st2, err := db.ReconcilePools(ctx, func(p string) string { return p })
	if err != nil {
		t.Fatalf("ReconcilePools revive: %v", err)
	}
	if got := skipOf(t, ctx, db, "C1"); got != "" {
		t.Errorf("C1 skip = %q after revival, want empty", got)
	}
	if st2.Revived != 1 {
		t.Errorf("Revived = %d, want 1", st2.Revived)
	}
}

// TestReconcilePoolsMovedToNewPath covers a file moved within a pool (or
// between pools) to a path with no prior location row: staging the new path
// relabels the sample rather than marking it missing.
func TestReconcilePoolsMovedToNewPath(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "mv", Path: "good/x.bin", Label: "good", LabelSource: "local"})

	// Seen this walk only at a new bad/ path.
	stageWalk(t, ctx, db, loc("mv", "bad/x.bin"))
	if _, err := db.ReconcilePools(ctx, func(p string) string { return p }); err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if got := labelOf(t, ctx, db, "mv"); got != "bad" {
		t.Errorf("mv label = %q, want bad (relabeled after good→bad move)", got)
	}
	if got := skipOf(t, ctx, db, "mv"); got != "" {
		t.Errorf("mv skip = %q, want empty (must not be marked missing)", got)
	}
}

// TestReconcilePoolsBadUnknownGood walks a sample through bad/ → unknown/ →
// good/. unknown/ asserts no pool, so the label is retained there; the final
// good/ placement demotes it.
func TestReconcilePoolsBadUnknownGood(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	keep := func(p string) string { return p }

	mustInsert(t, ctx, db, &Sample{SHA256: "t", Path: "bad/t.bin", Label: "bad", LabelSource: "local"})

	// → unknown/: label retained (unknown/ does not downgrade), still present.
	stageWalk(t, ctx, db, loc("t", "unknown/t.bin"))
	if _, err := db.ReconcilePools(ctx, keep); err != nil {
		t.Fatal(err)
	}
	if got := labelOf(t, ctx, db, "t"); got != "bad" {
		t.Errorf("in unknown/ label = %q, want bad (unknown does not downgrade)", got)
	}
	if got := skipOf(t, ctx, db, "t"); got != "" {
		t.Errorf("in unknown/ skip = %q, want empty (present)", got)
	}

	// → good/: now demoted to good.
	stageWalk(t, ctx, db, loc("t", "good/t.bin"))
	if _, err := db.ReconcilePools(ctx, keep); err != nil {
		t.Fatal(err)
	}
	if got := labelOf(t, ctx, db, "t"); got != "good" {
		t.Errorf("after move to good/ label = %q, want good", got)
	}
}

// TestReconcilePoolsRemovedThenReadded covers removal from bad/ (→ missing,
// label retained) followed by re-adding the same content to bad/ at a different
// path (→ revived, skip cleared).
func TestReconcilePoolsRemovedThenReadded(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "rb", Path: "bad/a.bin", Label: "bad", LabelSource: "local"})
	mustAnalyze(t, ctx, db, "rb", 5)

	// Removed from bad/ entirely (nothing present this walk) → missing.
	gone := func(p string) string { return filepath.Join(t.TempDir(), "nope", p) }
	stageWalk(t, ctx, db)
	if _, err := db.ReconcilePools(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if got := skipOf(t, ctx, db, "rb"); got != "missing" {
		t.Fatalf("after removal skip = %q, want missing", got)
	}
	if got := labelOf(t, ctx, db, "rb"); got != "bad" {
		t.Errorf("after removal label = %q, want bad (retained)", got)
	}

	// Re-added to bad/ at a different path → revived (skip cleared).
	stageWalk(t, ctx, db, loc("rb", "bad/b.bin"))
	if _, err := db.ReconcilePools(ctx, func(p string) string { return p }); err != nil {
		t.Fatal(err)
	}
	if got := skipOf(t, ctx, db, "rb"); got != "" {
		t.Errorf("after re-add skip = %q, want empty (revived)", got)
	}
	if got := labelOf(t, ctx, db, "rb"); got != "bad" {
		t.Errorf("after re-add label = %q, want bad", got)
	}
}

func TestUnanalyzedCandidatesSkipsMarkedSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert 3 unanalyzed samples: one normal, two with skip set.
	mustInsert(t, ctx, db, &Sample{SHA256: "claim1", Path: "/data/a.exe", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "claim2", Path: "/data/b.exe", Label: "bad", Skip: "unsupported"})
	mustInsert(t, ctx, db, &Sample{SHA256: "claim3", Path: "/data/c.exe", Label: "bad", Skip: "missing"})

	jobs, err := db.UnanalyzedCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if jobs[0].SHA256 != "claim1" {
		t.Errorf("got sha256 = %q, want 'claim1'", jobs[0].SHA256)
	}
}

// TestUnanalyzedCandidatesRetriesOldErrorsAfterRestart verifies that the
// hopperStart cutoff lets a freshly restarted process pick up samples whose
// last_error_at predates this run.
func TestUnanalyzedCandidatesRetriesOldErrorsAfterRestart(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "err1", Path: "/data/a.exe", Label: "bad"})
	if err := db.SetNote(ctx, "err1", "worker failed"); err != nil {
		t.Fatal(err)
	}

	currentRunStart := time.Now().Add(-time.Hour)
	jobs, err := db.UnanalyzedCandidates(ctx, currentRunStart, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("current-run error returned as candidate: got %+v, want none", jobs)
	}

	restartAfterError := time.Now().Add(time.Hour)
	jobs, err = db.UnanalyzedCandidates(ctx, restartAfterError, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != "err1" {
		t.Fatalf("old error after restart: got %+v, want err1", jobs)
	}
}

func TestUnanalyzedCandidatesUsesRandomPivot(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	lowest := strings.Repeat("0", 64)
	mustInsert(t, ctx, db, &Sample{SHA256: lowest, Path: "/data/lowest.exe", Label: "bad"})
	for i := 1; i < 256; i++ {
		sha := fmt.Sprintf("%02x%s", i, strings.Repeat("0", 62))
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: "/data/" + sha, Label: "bad"})
	}

	sawNonLowestFirst := false
	for range 20 {
		jobs, err := db.UnanalyzedCandidates(ctx, time.Now(), 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) != 5 {
			t.Fatalf("got %d jobs, want 5", len(jobs))
		}
		if jobs[0].SHA256 != lowest {
			sawNonLowestFirst = true
			break
		}
	}
	if !sawNonLowestFirst {
		t.Fatal("random candidate pivot kept returning the lowest SHA first")
	}
}

// TestRequestRescanQueuesTier0 covers the happy path: an analyzed sample
// becomes eligible for rescan after the cooldown elapses, RequestRescan
// clears its analysis fields + stamps forced_rescan_at, and the next
// ForcedRescanCandidates call returns it.
func TestRequestRescanQueuesTier0(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "aaaaaa00000000000000000000000000000000000000000000000000000000aa"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)

	// Backdate analyzed_at so the cooldown predicate accepts the request.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	jobs, err := db.ForcedRescanCandidates(ctx, 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != sha {
		t.Fatalf("ForcedRescanCandidates = %+v, want one job for %s", jobs, sha)
	}
}

// TestRequestRescanHonorsCooldown covers the defense-in-depth path: a
// sample analyzed within the cooldown window is rejected with
// ErrRescanNotEligible even if the caller asks.
func TestRequestRescanHonorsCooldown(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "bbbbbb00000000000000000000000000000000000000000000000000000000bb"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); !errors.Is(err, ErrRescanNotEligible) {
		t.Fatalf("RequestRescan within cooldown: err = %v, want ErrRescanNotEligible", err)
	}
}

// TestRequestRescanRejectsArchiveChild covers the parent-non-empty gate:
// an archive member is never eligible for rescan (the parent archive
// owns its analysis).
func TestRequestRescanRejectsArchiveChild(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const parent = "cccccc00000000000000000000000000000000000000000000000000000000cc"
	const child = "dddddd00000000000000000000000000000000000000000000000000000000dd"
	mustInsert(t, ctx, db, &Sample{SHA256: parent, Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: child, Source: "test", Label: "bad", LabelSource: "test", Parent: parent})

	if err := db.RequestRescan(ctx, child, 15*time.Minute); !errors.Is(err, ErrRescanNotEligible) {
		t.Fatalf("RequestRescan on archive child: err = %v, want ErrRescanNotEligible", err)
	}
}

// TestUpdateCleaveResultClearsForcedRescan covers the queue-drain path:
// when a worker submits fresh analysis for a forced-rescan sample, the
// forced_rescan_at marker clears so the row drops out of Tier 0.
func TestUpdateCleaveResultClearsForcedRescan(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "eeeeee00000000000000000000000000000000000000000000000000000000ee"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	mustAnalyze(t, ctx, db, sha, 2) // simulates a worker finishing the rescan

	jobs, err := db.ForcedRescanCandidates(ctx, 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("ForcedRescanCandidates after re-analysis = %+v, want empty", jobs)
	}
}

// TestForcedRescanCandidatesOrder verifies FIFO ordering by forced_rescan_at.
func TestForcedRescanCandidatesOrder(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	shas := []string{
		"aabbcc0000000000000000000000000000000000000000000000000000000010",
		"aabbcc0000000000000000000000000000000000000000000000000000000020",
		"aabbcc0000000000000000000000000000000000000000000000000000000030",
	}
	for i, sha := range shas {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
		mustAnalyze(t, ctx, db, sha, 1)
		// Stamp forced_rescan_at explicitly so the test isn't dependent on
		// RequestRescan's now()-based ordering (which is rate-limited by the
		// SQLite clock resolution).
		ts := time.Now().Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE samples SET cleave_result = NULL, forced_rescan_at = ? WHERE sha256 = ?`,
			ts, sha); err != nil {
			t.Fatalf("stamp: %v", err)
		}
	}

	jobs, err := db.ForcedRescanCandidates(ctx, 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != len(shas) {
		t.Fatalf("got %d jobs, want %d", len(jobs), len(shas))
	}
	for i, j := range jobs {
		if j.SHA256 != shas[i] {
			t.Fatalf("jobs[%d] = %s, want %s (FIFO order)", i, j.SHA256, shas[i])
		}
	}
}

// TestRequestRescanPreservesEnvelope verifies the no-null-window guarantee:
// while a forced rescan is pending, readers still see the prior cleave/litmus
// envelope, the analyzed_at timestamp, and the traits version. The row only
// transitions to its new state when a worker stores fresh analysis.
func TestRequestRescanPreservesEnvelope(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "ffffff00000000000000000000000000000000000000000000000000000000ff"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyzeWithTraits(t, ctx, db, sha, 1, `{"l":2}`)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, traits_version = 'abc12' WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// Snapshot before the rescan request.
	var beforeCleave, beforeTraits string
	var beforeAnalyzedAt sql.NullString
	if err := db.lite.QueryRowContext(ctx,
		`SELECT cleave_result, traits_version, analyzed_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&beforeCleave, &beforeTraits, &beforeAnalyzedAt); err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if beforeCleave == "" || beforeTraits != "abc12" || !beforeAnalyzedAt.Valid {
		t.Fatalf("setup invariants violated: cleave=%q traits=%q analyzed_at_valid=%v",
			beforeCleave, beforeTraits, beforeAnalyzedAt.Valid)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	// After the rescan request the row must remain in Tier 0 *and* still
	// expose its cached envelope to readers.
	jobs, err := db.ForcedRescanCandidates(ctx, 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != sha {
		t.Fatalf("ForcedRescanCandidates = %+v, want one job for %s", jobs, sha)
	}

	var afterCleave, afterTraits string
	var afterAnalyzedAt sql.NullString
	var forcedAt sql.NullString
	if err := db.lite.QueryRowContext(ctx,
		`SELECT cleave_result, traits_version, analyzed_at, forced_rescan_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&afterCleave, &afterTraits, &afterAnalyzedAt, &forcedAt); err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if afterCleave != beforeCleave {
		t.Fatalf("cleave_result changed: before=%q after=%q", beforeCleave, afterCleave)
	}
	if afterTraits != beforeTraits {
		t.Fatalf("traits_version changed: before=%q after=%q", beforeTraits, afterTraits)
	}
	if afterAnalyzedAt.String != beforeAnalyzedAt.String {
		t.Fatalf("analyzed_at changed: before=%q after=%q", beforeAnalyzedAt.String, afterAnalyzedAt.String)
	}
	if !forcedAt.Valid {
		t.Fatalf("forced_rescan_at not set after RequestRescan")
	}
}

// TestRequestRescanIdempotent verifies that asking to rescan a row that
// is already queued is a no-op success: the original forced_rescan_at
// timestamp is preserved (so FIFO position holds) and no error is
// returned even if the cooldown would otherwise reject the call.
func TestRequestRescanIdempotent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "abcdef00000000000000000000000000000000000000000000000000000000ab"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan first call: %v", err)
	}
	var firstForcedAt string
	if err := db.lite.QueryRowContext(ctx,
		`SELECT forced_rescan_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&firstForcedAt); err != nil {
		t.Fatalf("read first forced_rescan_at: %v", err)
	}

	// Bring analyzed_at back into the cooldown window to prove the second
	// call short-circuits via the forced_rescan_at branch rather than the
	// cooldown branch.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("re-stamp analyzed_at: %v", err)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan second call (already queued): %v", err)
	}
	var secondForcedAt string
	if err := db.lite.QueryRowContext(ctx,
		`SELECT forced_rescan_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&secondForcedAt); err != nil {
		t.Fatalf("read second forced_rescan_at: %v", err)
	}
	if secondForcedAt != firstForcedAt {
		t.Fatalf("forced_rescan_at moved: first=%q second=%q (FIFO position should not change on idempotent re-request)",
			firstForcedAt, secondForcedAt)
	}
}

func TestKVGetNotFound(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.KVGet(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("KVGet missing key: err = %v, want ErrNotFound", err)
	}
}

func TestKVSetIfAbsentAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if err := db.KVSetIfAbsent(ctx, "k1", "first"); err != nil {
		t.Fatalf("KVSetIfAbsent first: %v", err)
	}
	if got, err := db.KVGet(ctx, "k1"); err != nil || got != "first" {
		t.Fatalf("KVGet after first set: got=%q err=%v", got, err)
	}

	// Second SetIfAbsent on the same key must NOT overwrite.
	if err := db.KVSetIfAbsent(ctx, "k1", "second"); err != nil {
		t.Fatalf("KVSetIfAbsent second: %v", err)
	}
	if got, err := db.KVGet(ctx, "k1"); err != nil || got != "first" {
		t.Errorf("KVSetIfAbsent overwrote: got=%q err=%v, want first", got, err)
	}

	// Independent keys coexist.
	if err := db.KVSetIfAbsent(ctx, "k2", "other"); err != nil {
		t.Fatalf("KVSetIfAbsent k2: %v", err)
	}
	if got, err := db.KVGet(ctx, "k2"); err != nil || got != "other" {
		t.Errorf("KVGet k2: got=%q err=%v, want other", got, err)
	}
}

func TestUpdateEcosystem(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "e1", Source: "test", Ecosystem: "objectivesee", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "e2", Source: "test", Ecosystem: "objectivesee", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "e3", Source: "test", Ecosystem: "macos", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "e4", Source: "test", Ecosystem: "c_linux", Label: "bad"})

	assertEcosystems := func(want string) {
		t.Helper()
		got, err := db.DistinctEcosystems(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != want {
			t.Fatalf("DistinctEcosystems = %v, want %q", got, want)
		}
	}

	assertEcosystems("c_linux,macos,objectivesee")

	// One call remaps several values at once: a junk value collapses onto an
	// existing canonical one (objectivesee→macos) while another is cleared
	// (c_linux→""). Each sample also has a sample_locations row. Rows changed:
	// e1,e2 (objectivesee) + e4 (c_linux) = 3 samples + 3 locations = 6.
	n, err := db.UpdateEcosystems(ctx, map[string]string{"objectivesee": "macos", "c_linux": ""})
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Errorf("UpdateEcosystems rows = %d, want 6 (3 samples + 3 locations)", n)
	}
	assertEcosystems("macos")

	// Clearing to empty drops the value from the distinct set entirely.
	if _, err := db.UpdateEcosystems(ctx, map[string]string{"macos": ""}); err != nil {
		t.Fatal(err)
	}
	assertEcosystems("")

	// An empty mapping is a no-op rather than a malformed statement.
	if n, err := db.UpdateEcosystems(ctx, nil); err != nil || n != 0 {
		t.Fatalf("UpdateEcosystems(nil) = %d, %v; want 0, nil", n, err)
	}
}
