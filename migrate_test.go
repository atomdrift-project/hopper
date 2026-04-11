package hopper

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func createLegacyDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cyclotron.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	_, err = db.Exec(`
		CREATE TABLE samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sha256 TEXT UNIQUE NOT NULL,
			path TEXT NOT NULL,
			status TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			cleave_json TEXT,
			risk TEXT,
			last_error TEXT,
			finding_count INTEGER DEFAULT 0,
			attempts INTEGER DEFAULT 0,
			scan_failures INTEGER DEFAULT 0,
			re_failures INTEGER DEFAULT 0,
			gap_failures INTEGER DEFAULT 0,
			rem_failures INTEGER DEFAULT 0,
			fpa_failures INTEGER DEFAULT 0,
			fpr_failures INTEGER DEFAULT 0,
			total_duration_ms INTEGER DEFAULT 0
		)`)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	samples := []struct {
		sha256, path, status, cleaveJSON, risk string
		updatedAt                              int64
		findings                               int
	}{
		{"aaa111", "/data/bad/malware.exe", "bad-reversed", `{"findings":[{"id":"net"}]}`, "hostile", now - 3600, 3},
		{"bbb222", "/data/bad/dropper.dll", "bad-exhausted", `{"findings":[]}`, "suspicious", now - 7200, 1},
		{"ccc333", "/data/good/ls", "good", "", "", now, 0},
		{"ddd444", "/data/good/curl", "good-review", `{"findings":[{"id":"net"}]}`, "notable", now - 1800, 2},
		{"eee555", "/data/bad/benign.txt", "bad-benign", "", "", now, 0},
	}
	for _, s := range samples {
		_, err := db.Exec(`INSERT INTO samples (sha256, path, status, updated_at, cleave_json, risk, finding_count)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			s.sha256, s.path, s.status, s.updatedAt, s.cleaveJSON, s.risk, s.findings)
		if err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestMigrateLegacy(t *testing.T) {
	legacyPath := createLegacyDB(t)
	dst := openTestDB(t)
	ctx := context.Background()

	n, err := MigrateLegacy(ctx, dst, legacyPath, 0)
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if n != 5 {
		t.Errorf("migrated %d samples, want 5", n)
	}

	// Check label mapping.
	s, err := dst.SampleBySHA256(ctx, "aaa111")
	if err != nil {
		t.Fatal(err)
	}
	if s.Label != "bad" {
		t.Errorf("aaa111 label = %q, want %q", s.Label, "bad")
	}
	if s.Status != "bad-reversed" {
		t.Errorf("aaa111 status = %q, want %q", s.Status, "bad-reversed")
	}
	if s.CleaveResult == nil {
		t.Error("aaa111 should have cleave result")
	}
	if s.Path != "/data/bad/malware.exe" {
		t.Errorf("aaa111 path = %q, want %q", s.Path, "/data/bad/malware.exe")
	}
	if s.Source != "legacy" {
		t.Errorf("aaa111 source = %q, want %q", s.Source, "legacy")
	}

	// bad-benign → label "good"
	s, err = dst.SampleBySHA256(ctx, "eee555")
	if err != nil {
		t.Fatal(err)
	}
	if s.Label != "good" {
		t.Errorf("eee555 label = %q, want %q (bad-benign → good)", s.Label, "good")
	}

	// good-review → label "good"
	s, err = dst.SampleBySHA256(ctx, "ddd444")
	if err != nil {
		t.Fatal(err)
	}
	if s.Label != "good" {
		t.Errorf("ddd444 label = %q, want %q", s.Label, "good")
	}

	// Sample without cleave_json should have nil CleaveResult.
	s, err = dst.SampleBySHA256(ctx, "ccc333")
	if err != nil {
		t.Fatal(err)
	}
	if s.CleaveResult != nil {
		t.Error("ccc333 should have nil cleave result")
	}

	// Counts should match.
	counts, err := dst.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 2 {
		t.Errorf("bad count = %d, want 2", counts["bad"])
	}
	if counts["good"] != 3 {
		t.Errorf("good count = %d, want 3", counts["good"])
	}
}

func TestMigrateLegacy_Idempotent(t *testing.T) {
	legacyPath := createLegacyDB(t)
	dst := openTestDB(t)
	ctx := context.Background()

	n1, err := MigrateLegacy(ctx, dst, legacyPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := MigrateLegacy(ctx, dst, legacyPath, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Second run should insert 0 (all duplicates silently ignored).
	if n2 != 0 {
		t.Errorf("second migration inserted %d, want 0 (idempotent)", n2)
	}
	_ = n1
}

func TestTransferSamples(t *testing.T) {
	src := openTestDB(t)
	dst := openTestDB(t)
	ctx := context.Background()

	// Seed source with samples and reports.
	mustInsert(t, ctx, src, &Sample{SHA256: "t1", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review", Path: "/data/t1"})
	mustInsert(t, ctx, src, &Sample{SHA256: "t2", Source: "test", Label: "good", LabelSource: "test", Status: "good", Path: "/data/t2"})
	if err := src.UpdateCleaveResult(ctx, "t1", []byte(`{"fs":[{"sha":"t1","type":"elf","dp":0,"ts":[{"i":"test","l":5}]}]}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := src.InsertReport(ctx, &Report{SHA256: "t1", Type: "re", Content: "# Analysis", Provider: "claude"}); err != nil {
		t.Fatal(err)
	}
	if err := src.InsertReport(ctx, &Report{SHA256: "t1", Type: "gap", Content: "# Gap", Provider: "gemini"}); err != nil {
		t.Fatal(err)
	}

	samples, reports, err := TransferSamples(ctx, dst, src, 0, 0)
	if err != nil {
		t.Fatalf("TransferSamples: %v", err)
	}
	if samples != 2 {
		t.Errorf("transferred %d samples, want 2", samples)
	}
	if reports != 2 {
		t.Errorf("transferred %d reports, want 2", reports)
	}

	// Verify destination.
	got, err := dst.SampleBySHA256(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "bad-review" {
		t.Errorf("t1 status = %q, want %q", got.Status, "bad-review")
	}
	reps, err := dst.ReportsBySHA256(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 2 {
		t.Errorf("got %d reports, want 2", len(reps))
	}
}

func TestLabelFromLegacyStatus(t *testing.T) {
	tests := []struct {
		status, want string
	}{
		{"good", "good"},
		{"good-review", "good"},
		{"good-analyzed", "good"},
		{"good-exhausted", "good"},
		{"bad-benign", "good"},
		{"bad", "bad"},
		{"bad-review", "bad"},
		{"bad-reversed", "bad"},
		{"bad-gapped", "bad"},
		{"bad-exhausted", "bad"},
		{"good-malicious", "bad"},
		{"nonsense", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		got := labelFromLegacyStatus(tt.status)
		if got != tt.want {
			t.Errorf("labelFromLegacyStatus(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestMigrateLegacy_Resume(t *testing.T) {
	legacyPath := createLegacyDB(t)
	dst := openTestDB(t)
	ctx := context.Background()

	// Import only after rowid 2 (skips first 2 rows).
	n, err := MigrateLegacy(ctx, dst, legacyPath, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("migrated %d samples after resume, want 3", n)
	}
}

func TestTransferSamples_WithReports(t *testing.T) {
	src := openTestDB(t)
	dst := openTestDB(t)
	ctx := context.Background()

	// Create enough samples to trigger batch flushing (batch size = 500).
	for i := range 10 {
		sha := fmt.Sprintf("batch%04d", i)
		mustInsert(t, ctx, src, &Sample{
			SHA256: sha, Source: "test", Label: "bad", LabelSource: "test",
			Path: fmt.Sprintf("/data/%s", sha), Status: "bad-review",
		})
		if err := src.InsertReport(ctx, &Report{SHA256: sha, Type: "re", Content: "analysis", Provider: "claude"}); err != nil {
			t.Fatal(err)
		}
	}

	samples, reports, err := TransferSamples(ctx, dst, src, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if samples != 10 {
		t.Errorf("transferred %d samples, want 10", samples)
	}
	if reports != 10 {
		t.Errorf("transferred %d reports, want 10", reports)
	}

	// Verify resume: transfer again from after the last IDs.
	s2, r2, err := TransferSamples(ctx, dst, src, int64(samples), int64(reports))
	if err != nil {
		t.Fatal(err)
	}
	if s2 != 0 || r2 != 0 {
		t.Errorf("resume transfer: samples=%d reports=%d, want 0/0", s2, r2)
	}
}

func TestTransferSamples_Idempotent(t *testing.T) {
	src := openTestDB(t)
	dst := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, src, &Sample{SHA256: "x1", Source: "test", Label: "bad", LabelSource: "test"})

	s1, _, err := TransferSamples(ctx, dst, src, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := TransferSamples(ctx, dst, src, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s1 != 1 {
		t.Errorf("first transfer = %d, want 1", s1)
	}
	if s2 != 0 {
		t.Errorf("second transfer = %d, want 0 (idempotent)", s2)
	}
}
