package hopper

import (
	"context"
	"errors"
	"fmt"
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
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
}

func mustAnalyze(t *testing.T, ctx context.Context, db *DB, sha string, score int) {
	t.Helper()
	// Include a non-empty type so UpdateCleaveResult actually persists the row;
	// an empty type triggers the belt-and-suspenders delete path.
	result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":%d,"dp":0}]}`, sha, score)
	if err := db.UpdateCleaveResult(ctx, sha, result, ""); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
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
	if err := db.UpdateCleaveResult(ctx, "c1", []byte(`{"fs":[{"sha":"c1","type":"elf","dp":0,"ts":[{"i":"test","l":4}]}]}`), ""); err != nil {
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

func TestSamplesByStatus(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "bad", LabelSource: "test", Status: "bad"})

	got, err := db.SamplesByStatus(ctx, "bad-review", 10)
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

	got, err := db.FalsePositivesInPaths(ctx, []string{"/data/good"}, 85, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fp1" {
		t.Fatalf("got %+v, want only fp1", got)
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

	got, err := db.FalseNegativesInPaths(ctx, []string{"/data/bad"}, 75, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fn1" {
		t.Fatalf("got %+v, want only fn1", got)
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

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br1",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
		Score:       92,
	})
	mustAnalyze(t, ctx, db, "br1", 92)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br2",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
		Score:       60,
	})
	mustAnalyze(t, ctx, db, "br2", 60)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br3",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Skip:        "misclassified",
		Score:       92,
	})
	mustAnalyze(t, ctx, db, "br3", 92)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br4",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
		Status:      "claimed",
		Score:       92,
	})
	mustAnalyze(t, ctx, db, "br4", 92)

	got, err := db.BenignReview(ctx, 85, 10)
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

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr1",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
		Score:       20,
	})
	mustAnalyze(t, ctx, db, "mr1", 20)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr2",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
		Score:       90,
	})
	mustAnalyze(t, ctx, db, "mr2", 90)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr3",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Skip:        "misclassified",
		Score:       20,
	})
	mustAnalyze(t, ctx, db, "mr3", 20)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr4",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
		Status:      "claimed",
		Score:       20,
	})
	mustAnalyze(t, ctx, db, "mr4", 20)

	got, err := db.BadReview(ctx, 25, 10)
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
	if err := db.UpdateCleaveResult(ctx, "b", []byte(`{"fs":[{"sha":"b","type":"elf","dp":0}]}`), ""); err != nil {
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
	if err := db.SetSkip(ctx, "sk1", "weak-findings"); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "sk1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Skip != "weak-findings" {
		t.Errorf("Skip = %q, want %q", got.Skip, "weak-findings")
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
}

func TestInsertSampleBatch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	samples := []*Sample{
		{SHA256: "b1", Source: "test", Label: "bad", LabelSource: "test", SizeBytes: 100},
		{SHA256: "b2", Source: "test", Label: "good", LabelSource: "test", SizeBytes: 200},
		{SHA256: "b3", Source: "test", Label: "bad", LabelSource: "test", SizeBytes: 300},
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

func TestExplodeArchiveMembers(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	cleaveJSON := []byte(`{"fs":[
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"elf","path":"pkg/bin","dp":0,"sz":1000,"ts":[{"l":5,"c":0.9}]},
		{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","type":"py","path":"pkg/setup.py","dp":1,"sz":500,"ts":[{"l":5,"c":0.95}]},
		{"sha":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","type":"txt","path":"pkg/readme.txt","dp":1,"sz":50,"ts":[{"l":1,"c":1.0}]}
	]}`)

	parent := &Sample{
		SHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:          "test",
		Label:           "bad",
		LabelSource:     "test",
		CleaveResult:    cleaveJSON,
		CanonicalSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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

	// The txt file with only level 1 findings should have skip="weak-findings".
	txt, err := db.SampleBySHA256(ctx, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatal(err)
	}
	if txt.Skip != "weak-findings" {
		t.Errorf("txt Skip = %q, want %q", txt.Skip, "weak-findings")
	}
	if txt.Parent != parent.SHA256 {
		t.Errorf("txt Parent = %q, want %q", txt.Parent, parent.SHA256)
	}

	// The py file with hostile level findings should NOT be skipped.
	py, err := db.SampleBySHA256(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if py.Skip != "" {
		t.Errorf("py Skip = %q, want empty", py.Skip)
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

	isNew, err := db.InsertSampleNew(ctx, &Sample{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("first insert should be new")
	}

	isNew, err = db.InsertSampleNew(ctx, &Sample{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test"})
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
	s := &Sample{SHA256: "parent1", Source: "test", CleaveResult: cleave}
	if _, err := db.InsertSampleNew(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, s.SHA256, cleave, s.SHA256); err != nil {
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
	s := &Sample{SHA256: parent2, Source: "test", CleaveResult: cleave, CanonicalSHA256: parent2}
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
	if err := db.UpdateCleaveResult(ctx, "s1", resultFor("s1"), "s1"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, "s2", resultFor("s2"), "s2"); err != nil {
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
	if err := db.UpdateCleaveResult(ctx, "s3", resultFor("s3"), "s3"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, "s4", resultFor("s4"), "s4"); err != nil {
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
	if err := db.UpdateCleaveResult(ctx, "fs1", result, ""); err != nil {
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
	if err := db.UpdateCleaveResult(ctx, "nc1", []byte(`{"fs":[]}`), ""); err != nil {
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

	// Analyzed but unrecognized: simulate a historical row by writing the
	// bad blob via raw SQL so we bypass P3's live short-circuit.
	mustInsert(t, ctx, db, &Sample{SHA256: "junk1", Source: "test", Label: "bad", LabelSource: "test"})
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET cleave_result = ?, file_type = '' WHERE sha256 = ?`,
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
