package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
)

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// useTestPathLister swaps the package-level pathLister for a pure-Go walker
// so tests do not depend on a real cleave binary. Each regular file under
// the given root is streamed to the emit callback with a fake file type.
// Cleanup restores the original lister.
func useTestPathLister(t *testing.T) {
	t.Helper()
	original := pathLister
	pathLister = func(_ context.Context, dir string, newerThan time.Time, emit func(labeledPath) bool) error {
		return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			// Mirror cleave's incremental filter: skip files older than the
			// cutoff before emitting them.
			if !newerThan.IsZero() {
				if info, statErr := entry.Info(); statErr == nil && info.ModTime().Before(newerThan) {
					return nil
				}
			}
			if !emit(labeledPath{path: path, fileType: "test"}) {
				return filepath.SkipAll
			}
			return nil
		})
	}
	t.Cleanup(func() { pathLister = original })
}

func TestAttachSidecarProvenance(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "pkg-1.0.0.tgz")
	if err := os.WriteFile(artifact, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sidecar := `{"schema_version":"1.0","fetch":{"at":"2026-06-12T16:33:17Z"},"registry":{"source_id":"npm"}}`
	if err := os.WriteFile(artifact+sidecarSuffix, []byte(sidecar), 0o644); err != nil {
		t.Fatal(err)
	}

	var s hopper.Sample
	attachSidecarProvenance(&s, artifact)
	if len(s.Provenance) == 0 {
		t.Fatal("provenance not loaded from sidecar")
	}
	if s.FetchedAt == nil || s.FetchedAt.UTC().Format(time.RFC3339) != "2026-06-12T16:33:17Z" {
		t.Errorf("fetched_at = %v, want 2026-06-12T16:33:17Z", s.FetchedAt)
	}

	// No sidecar: both stay unset.
	var s2 hopper.Sample
	attachSidecarProvenance(&s2, filepath.Join(dir, "nope.tgz"))
	if s2.Provenance != nil || s2.FetchedAt != nil {
		t.Error("missing sidecar should leave provenance/fetched_at unset")
	}
}

func TestStartEnumerationSkipsSidecars(t *testing.T) {
	useTestPathLister(t)
	dir := t.TempDir()
	sample := filepath.Join(dir, "pkg-1.0.0.tar.gz")
	sidecar := sample + sidecarSuffix
	for _, p := range []string{sample, sidecar} {
		if err := os.WriteFile(p, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var got []string
	for lp := range startEnumeration(context.Background(), dir, time.Time{}) {
		got = append(got, filepath.Base(lp.path))
	}

	if len(got) != 1 || got[0] != "pkg-1.0.0.tar.gz" {
		t.Fatalf("enumeration = %v, want only the sample (sidecar must be skipped)", got)
	}
}

func TestStartEnumerationSkipsStaging(t *testing.T) {
	useTestPathLister(t)
	dir := t.TempDir()
	sample := filepath.Join(dir, "pkg-1.0.0.tgz")
	staged := filepath.Join(dir, stagingDirName, "pkg-unpkg.tgz")     // in a .tmp staging dir
	legacy := filepath.Join(dir, "evil-pkg"+legacyUnpkgScratchSuffix) // pre-staging scratch name
	mustMkdirAll(t, filepath.Dir(staged))
	for _, p := range []string{sample, staged, legacy} {
		if err := os.WriteFile(p, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var got []string
	for lp := range startEnumeration(context.Background(), dir, time.Time{}) {
		got = append(got, filepath.Base(lp.path))
	}

	if len(got) != 1 || got[0] != "pkg-1.0.0.tgz" {
		t.Fatalf("enumeration = %v, want only the sample (staging artifacts must be skipped)", got)
	}
}

func TestIsStagingPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"bad/foraged/javascript/pkg/.tmp/pkg-unpkg.tgz", true},
		{"good/.tmp/x.tgz", true},
		{".tmp/x.tgz", true},
		{"bad/foraged/javascript/npmjs.org/kmsec.uk/chalk-pro/chalk-pro-unpkg-tmp.tgz", true},
		{"bad/foraged/pkg-1.0.0.tgz", false},
		{"good/foo.tmp.tgz", false}, // ".tmp" as a substring, not a path component
		{"unknown/uploads/sample.bin", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isStagingPath(filepath.FromSlash(tt.path)); got != tt.want {
			t.Errorf("isStagingPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustRename(t *testing.T, oldPath, newPath string) {
	t.Helper()
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func mustOpenDB(t *testing.T, ctx context.Context, path string) *hopper.DB {
	t.Helper()
	db, err := hopper.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestIsMarkerFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"._malware.whl.BENIGN", true},
		{"._malware.whl.BAD", true},
		{"._an177-0.1.0-py3-none-any.whl.BENIGN", true},
		{"malware.whl", false},
		{"malware.whl.BENIGN", false}, // missing ._ prefix
		{"._malware.whl", false},      // missing suffix
		{".BENIGN", false},            // no ._ prefix
		{"._foo.BAD.extra", false},    // suffix not terminal
	}
	for _, tt := range tests {
		if got := isMarkerFile(tt.name); got != tt.want {
			t.Errorf("isMarkerFile(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCheckMarker(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "malware.whl")
	mustWriteFile(t, sample, []byte("sample content"))

	// No marker → empty string.
	if got := checkMarker(sample); got != "" {
		t.Fatalf("checkMarker with no marker = %q, want empty", got)
	}

	// Create BENIGN marker → "benign".
	benign := filepath.Join(dir, "._malware.whl.BENIGN")
	mustWriteFile(t, benign, nil)
	if got := checkMarker(sample); got != "benign" {
		t.Fatalf("checkMarker with BENIGN marker = %q, want %q", got, "benign")
	}

	// Remove BENIGN, create BAD marker → "bad".
	mustRemove(t, benign)
	bad := filepath.Join(dir, "._malware.whl.BAD")
	mustWriteFile(t, bad, nil)
	if got := checkMarker(sample); got != "bad" {
		t.Fatalf("checkMarker with BAD marker = %q, want %q", got, "bad")
	}

	// Both markers present → BENIGN wins (checked first).
	mustWriteFile(t, benign, nil)
	if got := checkMarker(sample); got != "benign" {
		t.Fatalf("checkMarker with both markers = %q, want %q", got, "benign")
	}
}

func TestCheckMarkerSubdirectory(t *testing.T) {
	// Marker must be in the same directory as the sample.
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	mustMkdirAll(t, sub)

	sample := filepath.Join(sub, "pkg.tar.gz")
	mustWriteFile(t, sample, []byte("data"))

	// Marker in parent dir should NOT match.
	mustWriteFile(t, filepath.Join(dir, "._pkg.tar.gz.BENIGN"), nil)
	if got := checkMarker(sample); got != "" {
		t.Fatalf("checkMarker with marker in parent dir = %q, want empty", got)
	}

	// Marker in same dir should match.
	mustWriteFile(t, filepath.Join(sub, "._pkg.tar.gz.BENIGN"), nil)
	if got := checkMarker(sample); got != "benign" {
		t.Fatalf("checkMarker with marker in same dir = %q, want %q", got, "benign")
	}
}

func TestWalkFilesSkipsMarkers(t *testing.T) {
	useTestPathLister(t)
	dir := t.TempDir()
	// Create a real sample and a marker file.
	mustWriteFile(t, filepath.Join(dir, "malware.whl"), []byte("sample content!"))
	mustWriteFile(t, filepath.Join(dir, "._malware.whl.BENIGN"), nil)
	mustWriteFile(t, filepath.Join(dir, "._other.exe.BAD"), nil)
	mustWriteFile(t, filepath.Join(dir, "legit.bin"), []byte("another sample!"))

	// runDirPipeline drops marker files via isMarkerFile; exercise the
	// same filter here by walking the lister directly.
	var got []string
	err := pathLister(t.Context(), dir, time.Time{}, func(lp labeledPath) bool {
		name := filepath.Base(lp.path)
		if isMarkerFile(name) {
			return true
		}
		got = append(got, name)
		return true
	})
	if err != nil {
		t.Fatalf("pathLister: %v", err)
	}

	// Only real samples should appear, not marker files.
	if len(got) != 2 {
		t.Fatalf("pathLister returned %d files %v, want 2 (malware.whl, legit.bin)", len(got), got)
	}
	for _, name := range got {
		if isMarkerFile(name) {
			t.Errorf("walker emitted marker file %q", name)
		}
	}
}

func TestHashFileAppliesMarker(t *testing.T) {
	dir := t.TempDir()

	// Sample in a "bad" directory with a BENIGN marker → should flip to good + misclassified.
	samplePath := filepath.Join(dir, "malware.whl")
	mustWriteFile(t, samplePath, []byte("sample content!"))
	mustWriteFile(t, filepath.Join(dir, "._malware.whl.BENIGN"), nil)

	hr, err := hashFile(t.Context(), samplePath, "bad", "", "harvest", nil, nil)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	sample := hr.sample

	// hashFile doesn't apply markers — that's done in the hash worker.
	// Verify the raw sample has the original label.
	if sample.Label != "bad" {
		t.Fatalf("hashFile label = %q, want %q", sample.Label, "bad")
	}

	// Simulate the marker logic from the hash worker.
	label := "bad"
	if marker := checkMarker(samplePath); marker != "" {
		if (label == "bad" && marker == "benign") || (label == "good" && marker == "bad") {
			sample.Label = marker
			if marker == "benign" {
				sample.Label = "good"
			}
			sample.LabelSource = "marker"
			sample.Skip = "misclassified"
		}
	}

	if sample.Label != "good" {
		t.Errorf("after marker: label = %q, want %q", sample.Label, "good")
	}
	if sample.LabelSource != "marker" {
		t.Errorf("after marker: label_source = %q, want %q", sample.LabelSource, "marker")
	}
	if sample.Skip != "misclassified" {
		t.Errorf("after marker: skip = %q, want %q", sample.Skip, "misclassified")
	}
}

func TestHashFileMarkerNoContradiction(t *testing.T) {
	dir := t.TempDir()

	// BAD marker on a bad-labeled file is not a contradiction → no change.
	samplePath := filepath.Join(dir, "malware.whl")
	mustWriteFile(t, samplePath, []byte("sample content!"))
	mustWriteFile(t, filepath.Join(dir, "._malware.whl.BAD"), nil)

	hr, err := hashFile(t.Context(), samplePath, "bad", "", "harvest", nil, nil)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	sample := hr.sample

	label := "bad"
	marker := checkMarker(samplePath)
	contradicts := (label == "bad" && marker == "benign") || (label == "good" && marker == "bad")
	if contradicts {
		t.Fatal("BAD marker on bad-labeled file should not be a contradiction")
	}

	if sample.Label != "bad" {
		t.Errorf("label = %q, want %q (unchanged)", sample.Label, "bad")
	}
	if sample.Skip != "" {
		t.Errorf("skip = %q, want empty (no misclassification)", sample.Skip)
	}
}

func TestHashCacheHitMiss(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := openHashCache(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("openHashCache: %v", err)
	}
	defer c.close(t.Context())

	// Write a sample file to get real stat values.
	samplePath := filepath.Join(t.TempDir(), "sample.bin")
	mustWriteFile(t, samplePath, []byte("hello world 123"))
	info := mustStat(t, samplePath)
	dev, ino := fileStat(info)

	// Miss on empty cache.
	if _, _, ok := c.lookup(t.Context(), dev, ino, info.Size(), info.ModTime()); ok {
		t.Fatal("expected cache miss on empty cache")
	}

	// Store and hit.
	c.store(t.Context(), dev, ino, info.Size(), info.ModTime(), "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	sha, _, ok := c.lookup(t.Context(), dev, ino, info.Size(), info.ModTime())
	if !ok {
		t.Fatal("expected cache hit after store")
	}
	if sha != "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234" {
		t.Fatalf("cached sha = %q", sha)
	}

	// Miss on different size.
	if _, _, ok := c.lookup(t.Context(), dev, ino, info.Size()+1, info.ModTime()); ok {
		t.Fatal("expected cache miss for different size")
	}

	// Miss on different mtime.
	if _, _, ok := c.lookup(t.Context(), dev, ino, info.Size(), info.ModTime().Add(1)); ok {
		t.Fatal("expected cache miss for different mtime")
	}
}

func TestHashCachePersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")

	// Write an entry and close.
	c, err := openHashCache(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("openHashCache: %v", err)
	}
	c.store(t.Context(), 42, 999, 1024, fixedTime(), "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	c.close(t.Context())

	// Reopen and verify the entry survived.
	c2, err := openHashCache(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.close(t.Context())

	sha, _, ok := c2.lookup(t.Context(), 42, 999, 1024, fixedTime())
	if !ok {
		t.Fatal("expected cache hit after reopen")
	}
	if sha != "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234" {
		t.Fatalf("persisted sha = %q", sha)
	}
}

func fixedTime() time.Time {
	return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
}

func TestHashCacheConcurrent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := openHashCache(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("openHashCache: %v", err)
	}
	defer c.close(t.Context())

	const n = 5000
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			ino := uint64(i)
			sha := fmt.Sprintf("%064x", i)
			c.store(t.Context(), 1, ino, 100, fixedTime(), sha)
			got, _, ok := c.lookup(t.Context(), 1, ino, 100, fixedTime())
			if !ok {
				t.Errorf("miss for inode %d after store", ino)
				return
			}
			if got != sha {
				t.Errorf("inode %d: got %q, want %q", ino, got, sha)
			}
		})
	}
	wg.Wait()
}

func TestHashFileWithCache(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := openHashCache(t.Context(), dbPath)
	if err != nil {
		t.Fatalf("openHashCache: %v", err)
	}
	defer c.close(t.Context())

	samplePath := filepath.Join(t.TempDir(), "sample.bin")
	mustWriteFile(t, samplePath, []byte("sample content!"))

	// First call: cache miss, computes hash and stores it.
	hr1, err := hashFile(t.Context(), samplePath, "bad", "", "harvest", c, nil)
	if err != nil {
		t.Fatalf("hashFile (miss): %v", err)
	}

	// Second call: cache hit, should return same hash without re-reading.
	hr2, err := hashFile(t.Context(), samplePath, "bad", "", "harvest", c, nil)
	if err != nil {
		t.Fatalf("hashFile (hit): %v", err)
	}
	if hr1.sample.SHA256 != hr2.sample.SHA256 {
		t.Fatalf("cache returned different hash: %q vs %q", hr1.sample.SHA256, hr2.sample.SHA256)
	}
}

func withArgs(args []string, fn func()) {
	old := os.Args
	os.Args = args
	defer func() { os.Args = old }()
	fn()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestCmdInit(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "init-test.db")
	withArgs([]string{"hopper", "init", "-db", dbPath}, func() {
		if err := cmdInit(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	// Verify DB was created and is usable.
	db, err := hopper.Open(t.Context(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.CountByLabel(t.Context())
	if err != nil {
		t.Fatalf("DB not usable after init: %v", err)
	}
}

func TestCmdReset(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "reset-test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{SHA256: "aaa", Source: "test", Label: "bad", LabelSource: "test"}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	withArgs([]string{"hopper", "reset", "-db", dbPath}, func() {
		if err := cmdReset(ctx); err != nil {
			t.Fatal(err)
		}
	})

	db = mustOpenDB(t, ctx, dbPath)
	defer db.Close()
	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != 0 {
		t.Errorf("expected 0 samples after reset, got %d", total)
	}
}

func TestCmdStats(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "stats-test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{SHA256: "s1", Source: "test", Label: "bad", LabelSource: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{SHA256: "s2", Source: "test", Label: "good", LabelSource: "test"}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	withArgs([]string{"hopper", "stats", "-db", dbPath}, func() {
		if err := cmdStats(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCmdLoadIntegration(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "load-test.db")
	dir := t.TempDir()
	sample1 := []byte("malicious content!")
	sample1Sum := sha256.Sum256(sample1)
	sample1SHA := hex.EncodeToString(sample1Sum[:])
	mustWriteFile(t, filepath.Join(dir, "sample1.bin"), sample1)
	mustWriteFile(t, filepath.Join(dir, "sample2.bin"), []byte("another evil file!"))
	reportsDir := filepath.Join(t.TempDir(), "reports")
	mustMkdir(t, reportsDir)
	mustWriteFile(t, filepath.Join(reportsDir, sample1SHA+".md"), []byte("# Loaded report\n"))

	data := t.TempDir()
	mustMkdir(t, filepath.Join(data, "bad"))
	mustRename(t, dir, filepath.Join(data, "bad", "test"))
	withArgs([]string{"hopper", "load", "-db", dbPath, "-data", data, "-workers", "2", "-litmus", "", "-dashboard-addr", "", "-reports-dir", reportsDir}, func() {
		if err := cmdLoad(ctx); err != nil {
			t.Fatal(err)
		}
	})

	db := mustOpenDB(t, ctx, dbPath)
	defer db.Close()
	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 2 {
		t.Errorf("bad count = %d, want 2", counts["bad"])
	}
	samples, err := db.SamplesByLabel(ctx, "bad", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range samples {
		if filepath.IsAbs(s.Path) {
			t.Fatalf("stored path %q is absolute, want relative", s.Path)
		}
		if !strings.HasPrefix(filepath.ToSlash(s.Path), "bad/test/") {
			t.Fatalf("stored path %q, want under bad/test/", s.Path)
		}
	}
	report, err := db.LatestReport(ctx, sample1SHA, "re")
	if err != nil {
		t.Fatalf("latest report: %v", err)
	}
	if report.Content != "# Loaded report\n" {
		t.Fatalf("report content = %q", report.Content)
	}
}

func TestCmdImport(t *testing.T) {
	ctx := t.Context()
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Set up source DB with a sample.
	srcPath := filepath.Join(t.TempDir(), "src.db")
	src := mustOpenDB(t, ctx, srcPath)
	if err := src.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := src.InsertSample(ctx, &hopper.Sample{SHA256: sha, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/imported"}); err != nil {
		t.Fatal(err)
	}
	if err := src.InsertReport(ctx, &hopper.Report{SHA256: sha, Type: "re", Content: "report"}); err != nil {
		t.Fatal(err)
	}
	src.Close()

	dstPath := filepath.Join(t.TempDir(), "dst.db")
	withArgs([]string{"hopper", "import", "-db", dstPath, "-from", srcPath}, func() {
		if err := cmdImport(ctx); err != nil {
			t.Fatal(err)
		}
	})

	dst := mustOpenDB(t, ctx, dstPath)
	defer dst.Close()
	got, err := dst.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "bad" {
		t.Errorf("label = %q, want bad", got.Label)
	}
}

func TestIngestReportsDir(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "reports.db")
	db := mustOpenDB(t, ctx, dbPath)
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	shaWithReport := "008a1e2cfd6bf252151738bcff2b1796d0866bf8dda2e0d51d5d581e19b45cce"
	shaExisting := "1111111111111111111111111111111111111111111111111111111111111111"
	shaMissingSample := "2222222222222222222222222222222222222222222222222222222222222222"

	if err := db.InsertSample(ctx, &hopper.Sample{SHA256: shaWithReport, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/sample"}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{SHA256: shaExisting, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/existing"}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertReport(ctx, &hopper.Report{SHA256: shaExisting, Type: "re", Content: "# Existing"}); err != nil {
		t.Fatal(err)
	}

	reportsDir := filepath.Join(t.TempDir(), "reports")
	mustMkdir(t, reportsDir)
	mustWriteFile(t, filepath.Join(reportsDir, shaWithReport+".md"), []byte("# RE report\n"))
	mustWriteFile(t, filepath.Join(reportsDir, shaExisting+".md"), []byte("# Should not duplicate\n"))
	mustWriteFile(t, filepath.Join(reportsDir, shaMissingSample+".md"), []byte("# No sample\n"))
	mustWriteFile(t, filepath.Join(reportsDir, "not-a-sha.md"), []byte("# Invalid\n"))
	mustWriteFile(t, filepath.Join(reportsDir, shaWithReport+".txt"), []byte("# Wrong extension\n"))

	stats, err := db.IngestReportsDir(ctx, reportsDir, "re", "cyclotron")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Inserted != 2 || stats.SkippedExisting != 0 || stats.SkippedMissingSample != 1 || stats.SkippedInvalid != 2 {
		t.Fatalf("stats = %+v, want inserted=2 existing=0 missing=1 invalid=2", stats)
	}

	report, err := db.LatestReport(ctx, shaWithReport, "re")
	if err != nil {
		t.Fatal(err)
	}
	if report.Content != "# RE report\n" || report.Provider != "cyclotron" {
		t.Fatalf("report = %#v", report)
	}
	existing, err := db.LatestReport(ctx, shaExisting, "re")
	if err != nil {
		t.Fatal(err)
	}
	if existing.Content != "# Should not duplicate\n" {
		t.Fatalf("existing latest report = %#v", existing)
	}

	stats, err = db.IngestReportsDir(ctx, reportsDir, "re", "cyclotron")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Inserted != 0 || stats.SkippedExisting != 2 {
		t.Fatalf("second stats = %+v, want inserted=0 existing=2", stats)
	}
}

func TestCmdLoadGood(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "load-good.db")
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "benign.bin"), []byte("harmless content!"))

	data := t.TempDir()
	mustMkdir(t, filepath.Join(data, "good"))
	mustRename(t, dir, filepath.Join(data, "good", "test"))
	withArgs([]string{"hopper", "load", "-db", dbPath, "-data", data, "-workers", "1", "-litmus", "", "-dashboard-addr", "", "-no-cache"}, func() {
		if err := cmdLoad(ctx); err != nil {
			t.Fatal(err)
		}
	})

	db := mustOpenDB(t, ctx, dbPath)
	defer db.Close()
	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["good"] != 1 {
		t.Errorf("good count = %d, want 1", counts["good"])
	}
}

func TestCmdLoadBothDirs(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "load-both.db")
	badDir := t.TempDir()
	goodDir := t.TempDir()
	mustWriteFile(t, filepath.Join(badDir, "evil.bin"), []byte("malicious payload!"))
	mustWriteFile(t, filepath.Join(goodDir, "safe.bin"), []byte("harmless content!"))

	data := t.TempDir()
	mustMkdir(t, filepath.Join(data, "bad"))
	mustMkdir(t, filepath.Join(data, "good"))
	mustRename(t, filepath.Join(badDir, "evil.bin"), filepath.Join(data, "bad", "evil.bin"))
	mustRename(t, filepath.Join(goodDir, "safe.bin"), filepath.Join(data, "good", "safe.bin"))

	withArgs([]string{"hopper", "load", "-db", dbPath, "-data", data, "-workers", "1", "-litmus", "", "-dashboard-addr", ""}, func() {
		if err := cmdLoad(ctx); err != nil {
			t.Fatal(err)
		}
	})

	db := mustOpenDB(t, ctx, dbPath)
	defer db.Close()
	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 1 {
		t.Errorf("bad = %d, want 1", counts["bad"])
	}
	if counts["good"] != 1 {
		t.Errorf("good = %d, want 1", counts["good"])
	}
}

func TestRun(t *testing.T) {
	// Unknown command returns error.
	withArgs([]string{"hopper", "bogus"}, func() {
		err := run(t.Context())
		if err == nil || err.Error() != "unknown command: bogus" {
			t.Errorf("expected unknown command error, got %v", err)
		}
	})

	// Valid commands through run().
	dbPath := filepath.Join(t.TempDir(), "run-test.db")

	withArgs([]string{"hopper", "init", "-db", dbPath}, func() {
		if err := run(t.Context()); err != nil {
			t.Errorf("run init: %v", err)
		}
	})
	withArgs([]string{"hopper", "stats", "-db", dbPath}, func() {
		if err := run(t.Context()); err != nil {
			t.Errorf("run stats: %v", err)
		}
	})
	withArgs([]string{"hopper", "false-positives", "-db", dbPath}, func() {
		if err := run(t.Context()); err != nil {
			t.Errorf("run false-positives: %v", err)
		}
	})
	withArgs([]string{"hopper", "false-negatives", "-db", dbPath}, func() {
		if err := run(t.Context()); err != nil {
			t.Errorf("run false-negatives: %v", err)
		}
	})
	withArgs([]string{"hopper", "benign-review", "-db", dbPath}, func() {
		if err := run(t.Context()); err != nil {
			t.Errorf("run benign-review: %v", err)
		}
	})
	withArgs([]string{"hopper", "bad-review", "-db", dbPath}, func() {
		if err := run(t.Context()); err != nil {
			t.Errorf("run bad-review: %v", err)
		}
	})
	withArgs([]string{"hopper", "reset", "-db", dbPath}, func() {
		if err := run(t.Context()); err != nil {
			t.Errorf("run reset: %v", err)
		}
	})
}

func TestOpenDB(t *testing.T) {
	ctx := t.Context()
	// SQLite path.
	dbPath := filepath.Join(t.TempDir(), "opendb-test.db")
	t.Setenv("DATABASE_URL", dbPath)
	db, err := openDB(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func TestRedactDSN(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"postgres://user:secret@host:5432/db", "postgres://user:xxxxx@host:5432/db"},
		{"postgres://host/db", "postgres://host/db"},
		{"/path/to/file.db", "/path/to/file.db"},
		{"not a url", "not%20a%20url"},
	}
	for _, tt := range tests {
		got := redactDSN(tt.in)
		if got != tt.want {
			t.Errorf("redactDSN(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtractCanonicalSHA(t *testing.T) {
	// Embedded file has smaller SHA than the sample itself.
	raw := []byte(`{"fs":[
		{"sha":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	]}`)
	got := extractCanonicalSHA("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", raw)
	if got != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("canonical = %q", got)
	}

	// No files: canonical is the sample SHA.
	got = extractCanonicalSHA("abcd", []byte(`{"fs":[]}`))
	if got != "abcd" {
		t.Errorf("canonical = %q, want abcd", got)
	}

	// Invalid JSON returns input SHA.
	got = extractCanonicalSHA("x", []byte(`{bad`))
	if got != "x" {
		t.Errorf("canonical = %q, want x", got)
	}
}

func TestFreePort(t *testing.T) {
	port, l, err := freePort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := l.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}()
	if port == "" || port == "0" {
		t.Errorf("freePort returned %q", port)
	}
}

func TestHashFileTooSmall(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "tiny.bin")
	mustWriteFile(t, small, []byte("short"))

	_, err := hashFile(t.Context(), small, "bad", "", "test", nil, nil)
	if !errors.Is(err, errTooSmall) {
		t.Errorf("expected errTooSmall, got %v", err)
	}
}

func TestHashFileTooLarge(t *testing.T) {
	// Verify the default cap matches defaultMaxFileSize.
	if maxFileSize != defaultMaxFileSize {
		t.Errorf("maxFileSize = %d, want %d", maxFileSize, defaultMaxFileSize)
	}
}

func TestWalkFilesSkipsGitDir(t *testing.T) {
	useTestPathLister(t)
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, ".git", "objects"))
	mustWriteFile(t, filepath.Join(dir, ".git", "objects", "pack.idx"), []byte("git internal!"))
	mustWriteFile(t, filepath.Join(dir, "sample.bin"), []byte("real sample!!!"))

	var got []string
	err := pathLister(t.Context(), dir, time.Time{}, func(lp labeledPath) bool {
		got = append(got, filepath.Base(lp.path))
		return true
	})
	if err != nil {
		t.Fatalf("pathLister: %v", err)
	}

	if len(got) != 1 || got[0] != "sample.bin" {
		t.Errorf("pathLister returned %v, want just [sample.bin]", got)
	}
}

func TestNewLitmusServer(t *testing.T) {
	s := newLitmusServer(litmusConfig{Bin: "/usr/bin/litmus", MaxWorkers: 4})
	if s.Workers() != 4 {
		t.Errorf("Workers = %d, want 4", s.Workers())
	}
	if s.bin != "/usr/bin/litmus" {
		t.Errorf("bin = %q", s.bin)
	}

	// Defaults: bin falls back to "atomscan" (the installed Atomdrift Scan binary),
	// workers to max(2, NumCPU/2).
	s2 := newLitmusServer(litmusConfig{})
	if s2.bin != "atomscan" {
		t.Errorf("default bin = %q, want atomscan", s2.bin)
	}
	wantWorkers := max(2, runtime.NumCPU()/2)
	if s2.Workers() != wantWorkers {
		t.Errorf("default Workers = %d, want %d", s2.Workers(), wantWorkers)
	}
}

func TestFlagWasSet(t *testing.T) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	litmus := f.String("litmus", "litmus", "")
	cleave := f.String("cleave", "cleave", "")
	parseFlags(f, []string{"--litmus", "/opt/litmus"})

	if !flagWasSet(f, "litmus") {
		t.Fatal("flagWasSet(litmus) = false, want true")
	}
	if flagWasSet(f, "cleave") {
		t.Fatal("flagWasSet(cleave) = true, want false")
	}
	if *litmus != "/opt/litmus" {
		t.Fatalf("litmus = %q, want /opt/litmus", *litmus)
	}
	if *cleave != "cleave" {
		t.Fatalf("cleave = %q, want cleave", *cleave)
	}
}

func TestLoadDir(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()

	// Set up a temp SQLite DB.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// Create sample files.
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "malware1.bin"), []byte("malicious payload one"))
	mustWriteFile(t, filepath.Join(dir, "malware2.bin"), []byte("malicious payload two"))
	mustWriteFile(t, filepath.Join(dir, "tiny"), []byte("x"))
	mustMkdirAll(t, filepath.Join(dir, ".git"))
	mustWriteFile(t, filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"))

	shared := &loadProgress{}
	shared.analyzeDurationMin.Store(math.MaxInt64)
	n := loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{dir, "bad"}}, nil, "test", 2, false, 0, "", nil, "", 0)
	// 2 valid files inserted (tiny skipped, .git skipped)
	if n != 2 {
		t.Errorf("loadAll returned %d, want 2", n)
	}

	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 2 {
		t.Errorf("bad count = %d, want 2", counts["bad"])
	}
}

// TestLoadDirSkipsForagerSidecars verifies the load walk ingests the vendor
// binary but never the forager metadata sidecars beside it — both the current
// hidden ".<sha>.sidecar.json" form and the legacy bare "<sha>.json" form.
func TestLoadDirSkipsForagerSidecars(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	binSHA := strings.Repeat("a", 64)
	otherSHA := strings.Repeat("b", 64)
	dir := t.TempDir()
	host := filepath.Join(dir, "owasp-amass.github.io")
	mustMkdirAll(t, host)
	mustWriteFile(t, filepath.Join(host, binSHA+"-amass_Linux_amd64.zip"), []byte("real amass release binary bytes"))
	mustWriteFile(t, filepath.Join(host, "."+binSHA+".sidecar.json"), []byte(`{"fetch_url":"https://example/x"}`))
	mustWriteFile(t, filepath.Join(host, otherSHA+".json"), []byte(`{"fetch_url":"https://example/y"}`))

	n := loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{dir, "good"}}, nil, "forager", 1, false, 0, "", nil, "", 0)
	if n != 1 {
		t.Errorf("loadAll returned %d, want 1 (only the binary, sidecars skipped)", n)
	}

	samples, err := db.SamplesByLabel(ctx, "good", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("expected 1 good sample, got %d", len(samples))
	}
	if strings.HasSuffix(samples[0].Filename, ".json") {
		t.Errorf("a sidecar .json was ingested as a sample: %q", samples[0].Filename)
	}
}

// TestLoadDirReadsVendorSidecar verifies the walk reads a vendor binary's
// sibling sidecar to fill url/feed on the row (the path supplies only
// domain/ecosystem), so vendor provenance is recovered even without forager
// direct-insert.
func TestLoadDirReadsVendorSidecar(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	host := filepath.Join(dir, "good", "foraged", "vendor", "owasp-amass.github.io")
	mustMkdirAll(t, host)
	content := []byte("real amass release binary content bytes")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	mustWriteFile(t, filepath.Join(host, sha+"-amass_Linux_amd64.zip"), content)
	url := "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip"
	mustWriteFile(t, filepath.Join(host, "."+sha+".sidecar.json"),
		fmt.Appendf(nil, `{"fetch_url":%q,"source":"amass","hostname":"owasp-amass.github.io"}`, url))

	loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{dir, "good"}}, nil, "forager", 1, false, 0, "", nil, "", 0)

	got, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got == nil {
		t.Fatal("vendor binary not inserted")
	}
	if got.URL != url {
		t.Errorf("URL = %q, want %q (from sidecar)", got.URL, url)
	}
	if got.Feed != "amass" {
		t.Errorf("Feed = %q, want amass (from sidecar)", got.Feed)
	}
	if got.Domain != "owasp-amass.github.io" {
		t.Errorf("Domain = %q, want owasp-amass.github.io", got.Domain)
	}
	if got.Source != "forager" {
		t.Errorf("Source = %q, want forager", got.Source)
	}
}

func TestLoadDirWithCache(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	cachePath := filepath.Join(t.TempDir(), "cache.db")
	cache, err := openHashCache(ctx, cachePath)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.close(ctx)

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "sample.bin"), []byte("sample content!!"))

	// First load: cache miss, hashes file.
	s1 := &loadProgress{}
	s1.analyzeDurationMin.Store(math.MaxInt64)
	n1 := loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, cache, []struct{ dir, label string }{{dir, "bad"}}, nil, "test", 1, false, 0, "", nil, "", 0)
	if n1 != 1 {
		t.Errorf("first load = %d, want 1", n1)
	}

	// Second load: cache hit, same hash → duplicate skipped.
	s2 := &loadProgress{}
	s2.analyzeDurationMin.Store(math.MaxInt64)
	n2 := loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, cache, []struct{ dir, label string }{{dir, "bad"}}, nil, "test", 1, false, 0, "", nil, "", 0)
	if n2 != 1 { // 1 total (0 inserted + 1 skipped)
		t.Errorf("second load = %d, want 1", n2)
	}
}

func TestLoadDirMarkers(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "malware.bin"), []byte("malicious payload!"))
	mustWriteFile(t, filepath.Join(dir, "._malware.bin.BENIGN"), nil)

	sm := &loadProgress{}
	sm.analyzeDurationMin.Store(math.MaxInt64)
	loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{dir, "bad"}}, nil, "test", 1, false, 0, "", nil, "", 0)

	// The sample should be flipped to "good" with skip="misclassified".
	samples, err := db.SamplesByLabel(ctx, "good", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("expected 1 good sample, got %d", len(samples))
	}
	if samples[0].Skip != "misclassified" {
		t.Errorf("skip = %q, want misclassified", samples[0].Skip)
	}
	if samples[0].MarkerMtime == nil {
		t.Fatalf("marker_mtime = nil, want set")
	}
}

func TestLoadDirMarkersRefreshMarkerMtimeOnDuplicate(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	samplePath := filepath.Join(dir, "malware.bin")
	markerPath := filepath.Join(dir, "._malware.bin.BENIGN")
	mustWriteFile(t, samplePath, []byte("malicious payload!"))
	mustWriteFile(t, markerPath, nil)

	first := time.Now().Add(-48 * time.Hour).UTC()
	second := time.Now().Add(-24 * time.Hour).UTC()
	if err := os.Chtimes(markerPath, first, first); err != nil {
		t.Fatal(err)
	}

	sm := &loadProgress{}
	sm.analyzeDurationMin.Store(math.MaxInt64)
	loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{dir, "bad"}}, nil, "test", 1, false, 0, "", nil, "", 0)

	samples, err := db.SamplesByLabel(ctx, "good", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].MarkerMtime == nil {
		t.Fatalf("expected first marker_mtime to be set, got %+v", samples)
	}

	if err := os.Chtimes(markerPath, second, second); err != nil {
		t.Fatal(err)
	}
	sm = &loadProgress{}
	sm.analyzeDurationMin.Store(math.MaxInt64)
	loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{dir, "bad"}}, nil, "test", 1, false, 0, "", nil, "", 0)

	samples, err = db.SamplesByLabel(ctx, "good", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].MarkerMtime == nil {
		t.Fatalf("expected refreshed marker_mtime to be set, got %+v", samples)
	}
	if !samples[0].MarkerMtime.Equal(second) {
		t.Fatalf("marker_mtime = %v, want %v", samples[0].MarkerMtime.UTC(), second)
	}
}

// TestLoadRehabilitatesAfterMarkerRemoved exercises the full load path twice:
// a good/ file with a .BAD marker is flipped to bad and quarantined
// (skip=misclassified), then the same content is re-observed in bad/ with no
// marker, which must rehabilitate it into a clean bad training sample.
func TestLoadRehabilitatesAfterMarkerRemoved(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "rehab.db")
	db, err := hopper.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	content := []byte("identical payload observed across two pools!")

	// Phase 1: good/ file carrying a .BAD marker → flips to bad, quarantined.
	goodDir := t.TempDir()
	mustWriteFile(t, filepath.Join(goodDir, "x.bin"), content)
	mustWriteFile(t, filepath.Join(goodDir, "._x.bin.BAD"), nil)
	loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{goodDir, "good"}}, nil, "test", 1, false, 0, "", nil, "", 0)

	flipped, err := db.SamplesByLabel(ctx, "bad", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(flipped) != 1 {
		t.Fatalf("after marker flip: got %d bad samples, want 1", len(flipped))
	}
	if flipped[0].Skip != "misclassified" || flipped[0].LabelSource != "marker" {
		t.Fatalf("after marker flip: skip=%q source=%q, want misclassified/marker", flipped[0].Skip, flipped[0].LabelSource)
	}
	sha := flipped[0].SHA256

	// Phase 2: same content now in bad/ with no marker → rehabilitate.
	badDir := t.TempDir()
	mustWriteFile(t, filepath.Join(badDir, "x.bin"), content)
	loadAll(ctx, func() {}, db, nil, newWorkerTracker(), nil, nil, []struct{ dir, label string }{{badDir, "bad"}}, nil, "test", 1, false, 0, "", nil, "", 0)

	got, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "bad" || got.Skip != "" || got.LabelSource != "test" {
		t.Errorf("after rehabilitation: label=%q skip=%q source=%q, want bad/\"\"/test",
			got.Label, got.Skip, got.LabelSource)
	}
}

func TestHashFileMarkerBadOnGood(t *testing.T) {
	dir := t.TempDir()

	// BAD marker on a good-labeled file → flip to bad + misclassified.
	samplePath := filepath.Join(dir, "legit.bin")
	mustWriteFile(t, samplePath, []byte("sample content!"))
	mustWriteFile(t, filepath.Join(dir, "._legit.bin.BAD"), nil)

	hr, err := hashFile(t.Context(), samplePath, "good", "", "harvest", nil, nil)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	sample := hr.sample

	label := "good"
	if marker := checkMarker(samplePath); marker != "" {
		if (label == "bad" && marker == "benign") || (label == "good" && marker == "bad") {
			sample.Label = marker
			if marker == "benign" {
				sample.Label = "good"
			}
			sample.LabelSource = "marker"
			sample.Skip = "misclassified"
		}
	}

	if sample.Label != "bad" {
		t.Errorf("after marker: label = %q, want %q", sample.Label, "bad")
	}
	if sample.LabelSource != "marker" {
		t.Errorf("after marker: label_source = %q, want %q", sample.LabelSource, "marker")
	}
	if sample.Skip != "misclassified" {
		t.Errorf("after marker: skip = %q, want %q", sample.Skip, "misclassified")
	}
}

func TestReviewCommands(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "review-test.db")
	db := mustOpenDB(t, ctx, dbPath)
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	type fixture struct {
		s      *hopper.Sample
		traits string
	}
	for _, fx := range []fixture{
		{
			s: &hopper.Sample{
				SHA256:      "fp",
				Source:      "test",
				Label:       "good",
				LabelSource: "test",
				Score:       90,
				Path:        "/samples/good/fp",
			},
			traits: `{"l":5,"c":1.0}`, // hostile -> triggers detection for FP
		},
		{
			s: &hopper.Sample{
				SHA256:      "fn",
				Source:      "test",
				Label:       "bad",
				LabelSource: "test",
				Score:       20,
				Path:        "/samples/bad/fn",
			},
		},
		{
			s: &hopper.Sample{
				SHA256:      "br",
				Source:      "test",
				Label:       "good",
				LabelSource: "marker",
				Skip:        "misclassified",
				Score:       90,
				Path:        "/samples/bad/br",
			},
			traits: `{"l":5,"c":1.0}`, // hostile -> qualifies for benign-review
		},
		{
			s: &hopper.Sample{
				SHA256:      "mr",
				Source:      "test",
				Label:       "bad",
				LabelSource: "marker",
				Skip:        "misclassified",
				Score:       20,
				Path:        "/samples/good/mr",
			},
			// no traits -> max_crit=0, suspicious_count=0, qualifies for bad-review
		},
	} {
		sample := fx.s
		if err := db.InsertSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":%d,"dp":0,"ts":[%s]}]}`,
			sample.SHA256, sample.Score, fx.traits)
		if err := db.UpdateCleaveResult(ctx, sample.SHA256, result, nil, ""); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		want string
		args []string
	}{
		{want: "fp", args: []string{"hopper", "false-positives", "-db", dbPath, "-threshold", "85"}},
		{want: "fn", args: []string{"hopper", "false-negatives", "-db", dbPath, "-threshold", "25"}},
		{want: "br", args: []string{"hopper", "benign-review", "-db", dbPath, "-threshold", "85"}},
		{want: "mr", args: []string{"hopper", "bad-review", "-db", dbPath, "-threshold", "25"}},
	}

	for _, tt := range tests {
		out := captureStdout(t, func() {
			withArgs(tt.args, func() {
				if err := run(ctx); err != nil {
					t.Fatalf("run(%v): %v", tt.args[1], err)
				}
			})
		})
		if !strings.Contains(out, tt.want) {
			t.Fatalf("output for %v = %q, want substring %q", tt.args[1], out, tt.want)
		}
	}
}

func TestReviewFlushCommands(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "review-flush.db")
	db := mustOpenDB(t, ctx, dbPath)
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	benignPath := filepath.Join(dir, "marker-benign.bin")
	badPath := filepath.Join(dir, "marker-bad.bin")
	mustWriteFile(t, benignPath, []byte("malicious payload!"))
	mustWriteFile(t, badPath, []byte("harmless content!"))
	mustWriteFile(t, reviewMarkerPath("benign-review", benignPath), nil)
	mustWriteFile(t, reviewMarkerPath("bad-review", badPath), nil)

	type flushFixture struct {
		s      *hopper.Sample
		traits string
	}
	for _, fx := range []flushFixture{
		{
			s: &hopper.Sample{
				SHA256:      "br-flush",
				Source:      "test",
				Label:       "good",
				LabelSource: "marker",
				Skip:        "misclassified",
				Score:       90,
				Path:        benignPath,
			},
			traits: `{"l":5,"c":1.0}`, // hostile -> benign-review
		},
		{
			s: &hopper.Sample{
				SHA256:      "mr-flush",
				Source:      "test",
				Label:       "bad",
				LabelSource: "marker",
				Skip:        "misclassified",
				Score:       20,
				Path:        badPath,
			},
			// no traits -> bad-review
		},
	} {
		sample := fx.s
		if err := db.InsertSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":%d,"dp":0,"ts":[%s]}]}`,
			sample.SHA256, sample.Score, fx.traits)
		if err := db.UpdateCleaveResult(ctx, sample.SHA256, result, nil, ""); err != nil {
			t.Fatal(err)
		}
	}

	out := captureStdout(t, func() {
		withArgs([]string{"hopper", "benign-review", "-db", dbPath, "-threshold", "85", "-flush"}, func() {
			if err := run(ctx); err != nil {
				t.Fatalf("run benign-review --flush: %v", err)
			}
		})
	})
	if !strings.Contains(out, "br-flush") {
		t.Fatalf("benign-review flush output = %q, want br-flush", out)
	}

	out = captureStdout(t, func() {
		withArgs([]string{"hopper", "bad-review", "-db", dbPath, "-threshold", "25", "-flush"}, func() {
			if err := run(ctx); err != nil {
				t.Fatalf("run bad-review --flush: %v", err)
			}
		})
	})
	if !strings.Contains(out, "mr-flush") {
		t.Fatalf("bad-review flush output = %q, want mr-flush", out)
	}

	if _, err := os.Stat(reviewMarkerPath("benign-review", benignPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("benign marker still exists: %v", err)
	}
	if _, err := os.Stat(reviewMarkerPath("bad-review", badPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bad marker still exists: %v", err)
	}

	br, err := db.SampleBySHA256(ctx, "br-flush")
	if err != nil {
		t.Fatal(err)
	}
	if br.Label != "bad" || br.LabelSource != "flush" || br.Skip != "" {
		t.Fatalf("benign-review flush sample = %+v, want label=bad label_source=flush skip=''", br)
	}

	mr, err := db.SampleBySHA256(ctx, "mr-flush")
	if err != nil {
		t.Fatal(err)
	}
	if mr.Label != "good" || mr.LabelSource != "flush" || mr.Skip != "" {
		t.Fatalf("bad-review flush sample = %+v, want label=good label_source=flush skip=''", mr)
	}
}

func TestCmdLoadHarvestMetadata(t *testing.T) {
	useTestPathLister(t)
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "metadata.db")
	data := t.TempDir()

	badBytes := []byte("malicious package content")
	badSum := sha256.Sum256(badBytes)
	badSHA := hex.EncodeToString(badSum[:])
	badPath := filepath.Join(data, "bad", "harvest", "opensourcemalware", "pypi", "evil.whl")
	mustMkdirAll(t, filepath.Dir(badPath))
	mustWriteFile(t, badPath, badBytes)
	db := mustOpenDB(t, ctx, dbPath)
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256:      badSHA,
		Source:      "harvest",
		Filename:    "evil.whl",
		Label:       "bad",
		LabelSource: "harvest",
		Path:        "bad/old/evil.whl",
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	goodBytes := []byte("benign package content")
	goodSum := sha256.Sum256(goodBytes)
	goodSHA := hex.EncodeToString(goodSum[:])
	goodPath := filepath.Join(data, "good", "harvest", "npm", "safe.tgz")
	mustMkdirAll(t, filepath.Dir(goodPath))
	mustWriteFile(t, goodPath, goodBytes)

	withArgs([]string{"hopper", "load", "-db", dbPath, "-data", data, "-workers", "2", "-litmus", "", "-dashboard-addr", ""}, func() {
		if err := cmdLoad(ctx); err != nil {
			t.Fatal(err)
		}
	})

	db = mustOpenDB(t, ctx, dbPath)
	defer db.Close()
	bad, err := db.SampleBySHA256(ctx, badSHA)
	if err != nil {
		t.Fatal(err)
	}
	if bad.Feed != "opensourcemalware" || bad.Ecosystem != "python" {
		t.Fatalf("bad metadata feed/ecosystem = %q/%q, want opensourcemalware/python", bad.Feed, bad.Ecosystem)
	}
	good, err := db.SampleBySHA256(ctx, goodSHA)
	if err != nil {
		t.Fatal(err)
	}
	if good.Feed != "" || good.Ecosystem != "javascript" {
		t.Fatalf("good metadata feed/ecosystem = %q/%q, want ''/javascript", good.Feed, good.Ecosystem)
	}
}

func TestExtractPathProvenance(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		label string
		want  pathProvenance
	}{
		// Legacy harvest layout — preserved for the relayout transition.
		{
			name:  "legacy bad harvest with feed+ecosystem",
			path:  "/srv/data/bad/harvest/opensourcemalware/pypi/pkg.whl",
			label: "bad",
			want:  pathProvenance{feed: "opensourcemalware", ecosystem: "pypi"},
		},
		{
			name:  "legacy good harvest with ecosystem only",
			path:  "/srv/data/good/harvest/npm/pkg.tgz",
			label: "good",
			want:  pathProvenance{ecosystem: "npm"},
		},
		{
			name:  "legacy unknown harvest with ecosystem only",
			path:  "/srv/data/unknown/harvest/crates/pkg.crate",
			label: "unknown",
			want:  pathProvenance{ecosystem: "crates"},
		},
		{
			name:  "legacy bare harvest marker",
			path:  "/srv/harvest/osv/maven/pkg.jar",
			label: "bad",
			want:  pathProvenance{feed: "osv", ecosystem: "maven"},
		},
		// New foraged layout: runtime/domain/feed/name/file (no version dir).
		{
			name:  "foraged bad: full provenance",
			path:  "/srv/data/bad/foraged/javascript/npmjs.org/aikido.dev/lodash/lodash-4.17.21.tgz",
			label: "bad",
			want: pathProvenance{
				ecosystem: "javascript",
				domain:    "npmjs.org",
				feed:      "aikido.dev",
				pkg:       "lodash",
			},
		},
		{
			name:  "foraged good: registry-as-feed",
			path:  "/srv/data/good/foraged/python/pythonhosted.org/pypi.org/requests/requests-2.31.0.tar.gz",
			label: "good",
			want: pathProvenance{
				ecosystem: "python",
				domain:    "pythonhosted.org",
				feed:      "pypi.org",
				pkg:       "requests",
			},
		},
		{
			name:  "foraged with _unknown placeholders normalizes to empty",
			path:  "/srv/data/bad/foraged/windows/_unknown/abuse.ch/_unknown/evil.exe",
			label: "bad",
			want: pathProvenance{
				ecosystem: "windows",
				feed:      "abuse.ch",
			},
		},
		{
			name:  "foraged with _ feed collapse expands to domain",
			path:  "/srv/data/good/foraged/javascript/npmjs.org/_/lodash/lodash-1.0.0.tgz",
			label: "good",
			want: pathProvenance{
				ecosystem: "javascript",
				domain:    "npmjs.org",
				feed:      "npmjs.org",
				pkg:       "lodash",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPathProvenance(tt.path, tt.label)
			if got != tt.want {
				t.Fatalf("extractPathProvenance() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestStripDataRoot(t *testing.T) {
	t.Run("direct prefix match", func(t *testing.T) {
		got := stripDataRoot("/srv/data/unknown/harvest/new/crates/foo.crate", "/srv/data/")
		want := "unknown/harvest/new/crates/foo.crate"
		if got != want {
			t.Errorf("stripDataRoot = %q, want %q", got, want)
		}
	})

	t.Run("symlinked prefix resolved via EvalSymlinks", func(t *testing.T) {
		// Create: tmp/real/bad/sample.bin and tmp/link → tmp/real
		// dataRoot prefix is "tmp/real/", DB path uses "tmp/link/bad/sample.bin".
		tmp := t.TempDir()
		realDir := filepath.Join(tmp, "real")
		mustMkdirAll(t, filepath.Join(realDir, "bad"))
		mustWriteFile(t, filepath.Join(realDir, "bad", "sample.bin"), []byte("x"))

		linkDir := filepath.Join(tmp, "link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}

		prefix := realDir + string(filepath.Separator)
		dbPath := filepath.Join(linkDir, "bad", "sample.bin")
		got := stripDataRoot(dbPath, prefix)
		want := filepath.Join("bad", "sample.bin")
		if got != want {
			t.Errorf("stripDataRoot(%q, %q) = %q, want %q", dbPath, prefix, got, want)
		}
	})

	t.Run("intermediate symlink resolved via EvalSymlinks", func(t *testing.T) {
		// Create: tmp/target/sub/file.txt and tmp/alias → tmp/target
		// dataRoot is "tmp/target/sub/", DB path is "tmp/alias/sub/file.txt".
		tmp := t.TempDir()
		targetDir := filepath.Join(tmp, "target")
		mustMkdirAll(t, filepath.Join(targetDir, "sub"))
		mustWriteFile(t, filepath.Join(targetDir, "sub", "file.txt"), []byte("y"))

		aliasDir := filepath.Join(tmp, "alias")
		if err := os.Symlink(targetDir, aliasDir); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}

		prefix := filepath.Join(targetDir, "sub") + string(filepath.Separator)
		dbPath := filepath.Join(aliasDir, "sub", "file.txt")
		got := stripDataRoot(dbPath, prefix)
		if got != "file.txt" {
			t.Errorf("stripDataRoot(%q, %q) = %q, want %q", dbPath, prefix, got, "file.txt")
		}
	})

	t.Run("no match returns path as-is", func(t *testing.T) {
		got := stripDataRoot("/completely/different/path.bin", "/srv/data/")
		if got != "/completely/different/path.bin" {
			t.Errorf("stripDataRoot = %q, want original path", got)
		}
	})
}

func TestLocalListenAddr(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"0.0.0.0:8081", "127.0.0.1:8081"},
		{":8081", "127.0.0.1:8081"},
		{"127.0.0.1:9090", "127.0.0.1:9090"},
		{"192.0.2.10:8081", "127.0.0.1:8081"},
	}
	for _, tt := range tests {
		if got := localListenAddr(tt.in); got != tt.want {
			t.Errorf("localListenAddr(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeForceRescanDirs(t *testing.T) {
	root := t.TempDir()
	abs := filepath.Join(root, "bad", "pkg")
	var dirs stringListFlag
	if err := dirs.Set(abs); err != nil {
		t.Fatal(err)
	}
	if err := dirs.Set("good/pkg,unknown/feed"); err != nil {
		t.Fatal(err)
	}
	got, err := normalizeForceRescanDirs(root, dirs)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bad/pkg", "good/pkg", "unknown/feed"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("normalizeForceRescanDirs = %v, want %v", got, want)
	}
	if _, err := normalizeForceRescanDirs(root, []string{filepath.Dir(root)}); err == nil {
		t.Fatal("normalizeForceRescanDirs outside root succeeded, want error")
	}
	// Absolute paths outside root no longer get silently "fixed" via a
	// /data/ marker — they're a hard error.
	if _, err := normalizeForceRescanDirs(root, []string{"/moved/archive/data/bad/moved"}); err == nil {
		t.Fatal("normalizeForceRescanDirs with out-of-root absolute path succeeded, want error")
	}
}

// TestFillSampleProvenance covers the name-anchored version split: when the
// forager path supplies the package name, the version must be derived by
// anchoring on that name, not by ParseFilename's joint name/version guess —
// which absorbs digit-bearing name segments into the version
// ("@kl-starfish-test-01-1.0.0.tgz" → "01-1.0.0", shipped to socket.dev as a
// purl that matches nothing).
func TestFillSampleProvenance(t *testing.T) {
	tests := []struct {
		name        string
		prov        pathProvenance
		filename    string
		wantPkg     string
		wantVersion string
	}{
		{
			name:        "digit-bearing scoped name anchors the version",
			prov:        pathProvenance{ecosystem: "javascript", pkg: "@kl-starfish/test-01"},
			filename:    "@kl-starfish-test-01-1.0.0.tgz",
			wantPkg:     "@kl-starfish/test-01",
			wantVersion: "1.0.0",
		},
		{
			name:        "plain name: anchored and joint splits agree",
			prov:        pathProvenance{ecosystem: "javascript", pkg: "lodash"},
			filename:    "lodash-4.17.21.tgz",
			wantPkg:     "lodash",
			wantVersion: "4.17.21",
		},
		{
			name:        "no path name: joint parse supplies both",
			prov:        pathProvenance{ecosystem: "javascript"},
			filename:    "lodash-4.17.21.tgz",
			wantPkg:     "lodash",
			wantVersion: "4.17.21",
		},
		{
			name:        "path name that fails anchoring falls back to joint parse",
			prov:        pathProvenance{ecosystem: "javascript", pkg: "renamed-on-disk"},
			filename:    "lodash-4.17.21.tgz",
			wantPkg:     "renamed-on-disk",
			wantVersion: "4.17.21",
		},
		{
			name:        "path version wins over any filename parse",
			prov:        pathProvenance{ecosystem: "javascript", pkg: "lodash", version: "9.9.9"},
			filename:    "lodash-4.17.21.tgz",
			wantPkg:     "lodash",
			wantVersion: "9.9.9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &hopper.Sample{}
			fillSampleProvenance(s, tt.prov, tt.filename)
			if s.Package != tt.wantPkg || s.Version != tt.wantVersion {
				t.Errorf("fillSampleProvenance(%q) = (%q, %q), want (%q, %q)",
					tt.filename, s.Package, s.Version, tt.wantPkg, tt.wantVersion)
			}
		})
	}
}
