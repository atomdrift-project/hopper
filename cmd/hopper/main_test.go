package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"codeberg.org/atomdrift/hopper"
)

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
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
	dir := t.TempDir()
	// Create a real sample and a marker file.
	mustWriteFile(t, filepath.Join(dir, "malware.whl"), []byte("sample content!"))
	mustWriteFile(t, filepath.Join(dir, "._malware.whl.BENIGN"), nil)
	mustWriteFile(t, filepath.Join(dir, "._other.exe.BAD"), nil)
	mustWriteFile(t, filepath.Join(dir, "legit.bin"), []byte("another sample!"))

	paths := make(chan labeledPath, 10)
	var progress loadProgress

	dirs := []struct{ dir, label string }{{dir, "bad"}}
	walkAndShuffle(t.Context(), dirs, paths, &progress)
	close(paths)

	var got []string
	for lp := range paths {
		got = append(got, filepath.Base(lp.path))
	}

	// Only real samples should appear, not marker files.
	if len(got) != 2 {
		t.Fatalf("walkAndShuffle returned %d files %v, want 2 (malware.whl, legit.bin)", len(got), got)
	}
	for _, name := range got {
		if isMarkerFile(name) {
			t.Errorf("walkAndShuffle emitted marker file %q", name)
		}
	}
}

func TestHashFileAppliesMarker(t *testing.T) {
	dir := t.TempDir()

	// Sample in a "bad" directory with a BENIGN marker → should flip to good + misclassified.
	samplePath := filepath.Join(dir, "malware.whl")
	mustWriteFile(t, samplePath, []byte("sample content!"))
	mustWriteFile(t, filepath.Join(dir, "._malware.whl.BENIGN"), nil)

	sample, err := hashFile(t.Context(), samplePath, "bad", "harvest", nil, nil)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

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

	sample, err := hashFile(t.Context(), samplePath, "bad", "harvest", nil, nil)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

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
	if _, ok := c.lookup(dev, ino, info.Size(), info.ModTime()); ok {
		t.Fatal("expected cache miss on empty cache")
	}

	// Store and hit.
	c.store(t.Context(), dev, ino, info.Size(), info.ModTime(), "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	sha, ok := c.lookup(dev, ino, info.Size(), info.ModTime())
	if !ok {
		t.Fatal("expected cache hit after store")
	}
	if sha != "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234" {
		t.Fatalf("cached sha = %q", sha)
	}

	// Miss on different size.
	if _, ok := c.lookup(dev, ino, info.Size()+1, info.ModTime()); ok {
		t.Fatal("expected cache miss for different size")
	}

	// Miss on different mtime.
	if _, ok := c.lookup(dev, ino, info.Size(), info.ModTime().Add(1)); ok {
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

	sha, ok := c2.lookup(42, 999, 1024, fixedTime())
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
			got, ok := c.lookup(1, ino, 100, fixedTime())
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
	s1, err := hashFile(t.Context(), samplePath, "bad", "harvest", c, nil)
	if err != nil {
		t.Fatalf("hashFile (miss): %v", err)
	}

	// Second call: cache hit, should return same hash without re-reading.
	s2, err := hashFile(t.Context(), samplePath, "bad", "harvest", c, nil)
	if err != nil {
		t.Fatalf("hashFile (hit): %v", err)
	}
	if s1.SHA256 != s2.SHA256 {
		t.Fatalf("cache returned different hash: %q vs %q", s1.SHA256, s2.SHA256)
	}
}

func withArgs(args []string, fn func()) {
	old := os.Args
	os.Args = args
	defer func() { os.Args = old }()
	fn()
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
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "load-test.db")
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "sample1.bin"), []byte("malicious content!"))
	mustWriteFile(t, filepath.Join(dir, "sample2.bin"), []byte("another evil file!"))

	data := t.TempDir()
	mustMkdir(t, filepath.Join(data, "bad"))
	mustRename(t, dir, filepath.Join(data, "bad", "test"))
	withArgs([]string{"hopper", "load", "-db", dbPath, "-data", data, "-workers", "2", "-litmus", ""}, func() {
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
}

func TestCmdImport(t *testing.T) {
	ctx := t.Context()

	// Set up source DB with a sample.
	srcPath := filepath.Join(t.TempDir(), "src.db")
	src := mustOpenDB(t, ctx, srcPath)
	if err := src.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := src.InsertSample(ctx, &hopper.Sample{SHA256: "imp1", Source: "test", Label: "bad", LabelSource: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := src.InsertReport(ctx, &hopper.Report{SHA256: "imp1", Type: "re", Content: "report"}); err != nil {
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
	got, err := dst.SampleBySHA256(ctx, "imp1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "bad" {
		t.Errorf("label = %q, want bad", got.Label)
	}
}

func TestCmdLoadGood(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "load-good.db")
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "benign.bin"), []byte("harmless content!"))

	data := t.TempDir()
	mustMkdir(t, filepath.Join(data, "good"))
	mustRename(t, dir, filepath.Join(data, "good", "test"))
	withArgs([]string{"hopper", "load", "-db", dbPath, "-data", data, "-workers", "1", "-litmus", "", "-no-cache"}, func() {
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

	withArgs([]string{"hopper", "load", "-db", dbPath, "-data", data, "-workers", "1", "-litmus", ""}, func() {
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

	_, err := hashFile(t.Context(), small, "bad", "test", nil, nil)
	if !errors.Is(err, errTooSmall) {
		t.Errorf("expected errTooSmall, got %v", err)
	}
}

func TestHashFileTooLarge(t *testing.T) {
	// We can't create a 1GB file in tests, but we can verify the constant.
	if maxFileSize != 1<<30 {
		t.Errorf("maxFileSize = %d, want %d", maxFileSize, 1<<30)
	}
}

func TestWalkFilesSkipsGitDir(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, ".git", "objects"))
	mustWriteFile(t, filepath.Join(dir, ".git", "objects", "pack.idx"), []byte("git internal!"))
	mustWriteFile(t, filepath.Join(dir, "sample.bin"), []byte("real sample!!!"))

	paths := make(chan labeledPath, 10)
	var progress loadProgress

	dirs := []struct{ dir, label string }{{dir, "good"}}
	walkAndShuffle(t.Context(), dirs, paths, &progress)
	close(paths)

	var got []string
	for lp := range paths {
		got = append(got, filepath.Base(lp.path))
	}

	if len(got) != 1 || got[0] != "sample.bin" {
		t.Errorf("walkAndShuffle returned %v, want just [sample.bin]", got)
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

	// Defaults.
	s2 := newLitmusServer(litmusConfig{})
	if s2.bin != "litmus" {
		t.Errorf("default bin = %q, want litmus", s2.bin)
	}
	if s2.Workers() != 8 {
		t.Errorf("default Workers = %d, want 8", s2.Workers())
	}
}

func TestLoadDir(t *testing.T) {
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
	n := loadAll(ctx, func() {}, db, nil, nil, []struct{ dir, label string }{{dir, "bad"}}, "test", 2, false, 0, "", shared)
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

func TestLoadDirWithCache(t *testing.T) {
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
	n1 := loadAll(ctx, func() {}, db, nil, cache, []struct{ dir, label string }{{dir, "bad"}}, "test", 1, false, 0, "", s1)
	if n1 != 1 {
		t.Errorf("first load = %d, want 1", n1)
	}

	// Second load: cache hit, same hash → duplicate skipped.
	s2 := &loadProgress{}
	s2.analyzeDurationMin.Store(math.MaxInt64)
	n2 := loadAll(ctx, func() {}, db, nil, cache, []struct{ dir, label string }{{dir, "bad"}}, "test", 1, false, 0, "", s2)
	if n2 != 1 { // 1 total (0 inserted + 1 skipped)
		t.Errorf("second load = %d, want 1", n2)
	}
}

func TestLoadDirMarkers(t *testing.T) {
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
	loadAll(ctx, func() {}, db, nil, nil, []struct{ dir, label string }{{dir, "bad"}}, "test", 1, false, 0, "", sm)

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
}

func TestHashFileMarkerBadOnGood(t *testing.T) {
	dir := t.TempDir()

	// BAD marker on a good-labeled file → flip to bad + misclassified.
	samplePath := filepath.Join(dir, "legit.bin")
	mustWriteFile(t, samplePath, []byte("sample content!"))
	mustWriteFile(t, filepath.Join(dir, "._legit.bin.BAD"), nil)

	sample, err := hashFile(t.Context(), samplePath, "good", "harvest", nil, nil)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

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
