package hopper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRebasePoolPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		pool string
		want string
	}{
		{"incoming/forager/pkg/a.tgz", PoolPending, "pending/forager/pkg/a.tgz"},
		{"pending/forager/pkg/a.tgz", PoolReview, "review/forager/pkg/a.tgz"},
		{"review/forager/pkg/a.tgz", PoolIncoming, "incoming/forager/pkg/a.tgz"},
		{"unknown/foraged/pkg/a.tgz", PoolPending, "pending/foraged/pkg/a.tgz"},
	} {
		got, err := RebasePoolPath(tc.in, tc.pool)
		if err != nil {
			t.Fatalf("RebasePoolPath(%q, %q): %v", tc.in, tc.pool, err)
		}
		if got != tc.want {
			t.Fatalf("RebasePoolPath(%q, %q) = %q, want %q", tc.in, tc.pool, got, tc.want)
		}
	}
	for _, in := range []string{"incoming", "incoming/../escape", "/incoming/a", "bad/a"} {
		if _, err := RebasePoolPath(in, PoolPending); err == nil {
			t.Errorf("RebasePoolPath(%q) accepted invalid path", in)
		}
	}
}

func TestMoveLocationMovesBundleAndCatalog(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root := t.TempDir()
	oldRel := "incoming/forager/pkg/example.tgz"
	newRel := "pending/forager/pkg/example.tgz"
	content := []byte("sample bytes")
	sha := moveTestSHA(content)
	oldAbs := filepath.Join(root, filepath.FromSlash(oldRel))
	newAbs := filepath.Join(root, filepath.FromSlash(newRel))
	if err := os.MkdirAll(filepath.Dir(oldAbs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldAbs, content, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldAbs+ProvenanceSidecarSuffix, []byte(`{"source":"test"}`), 0o440); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: oldRel, Label: "unknown", LabelSource: "forager"})

	result, err := db.MoveLocation(ctx, MoveLocationOptions{
		DataRoot: root,
		SHA256:   sha,
		OldPath:  oldRel,
		NewPath:  newRel,
	})
	if err != nil {
		t.Fatalf("MoveLocation: %v", err)
	}
	if !result.Relocated || !result.SourceRemoved || result.BytesFreed != int64(len(content)) {
		t.Fatalf("result = %+v", result)
	}
	if got, err := os.ReadFile(newAbs); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("destination = %q, %v", got, err)
	}
	if got, err := os.ReadFile(newAbs + ProvenanceSidecarSuffix); err != nil || string(got) != `{"source":"test"}` {
		t.Fatalf("destination sidecar = %q, %v", got, err)
	}
	for _, name := range []string{oldAbs, oldAbs + ProvenanceSidecarSuffix} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source remains at %s: %v", name, err)
		}
	}
	locations, err := db.LocationsForSHA(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if len(locations) != 1 || locations[0].Path != newRel {
		t.Fatalf("locations = %+v", locations)
	}
	retired, err := db.RetiredLocationsForSHA(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0].Path != oldRel || retired[0].Reason != "move" || retired[0].SuccessorPath != newRel {
		t.Fatalf("retired locations = %+v", retired)
	}
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Path != newRel || sample.Label != "unknown" || sample.LabelSource != "forager" {
		t.Fatalf("sample = %+v", sample)
	}

	// A lost success response is harmless: source is gone, but the verified
	// destination and catalog row are enough to finish the same request again.
	result, err = db.MoveLocation(ctx, MoveLocationOptions{
		DataRoot: root,
		SHA256:   sha,
		OldPath:  oldRel,
		NewPath:  newRel,
	})
	if err != nil || !result.Relocated {
		t.Fatalf("idempotent MoveLocation = %+v, %v", result, err)
	}
	retired, err = db.RetiredLocationsForSHA(ctx, sha)
	if err != nil || len(retired) != 1 {
		t.Fatalf("idempotent retired locations = %+v, %v", retired, err)
	}
}

func TestMoveLocationRecoversPreparedMove(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root := t.TempDir()
	oldRel := "incoming/scan/a.bin"
	newRel := "review/scan/a.bin"
	content := []byte("prepared move")
	sha := moveTestSHA(content)
	oldAbs := filepath.Join(root, filepath.FromSlash(oldRel))
	newAbs := filepath.Join(root, filepath.FromSlash(newRel))
	if err := os.MkdirAll(filepath.Dir(oldAbs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(newAbs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldAbs, content, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(oldAbs, newAbs); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: oldRel, Label: "unknown"})
	prepared, err := db.prepareLocationMove(ctx, sha, oldRel, newRel, nil)
	if err != nil || !prepared {
		t.Fatalf("prepareLocationMove = %v, %v", prepared, err)
	}
	locations, err := db.LocationsForSHA(ctx, sha)
	if err != nil || len(locations) != 2 {
		t.Fatalf("prepared locations = %+v, %v", locations, err)
	}

	result, err := db.MoveLocation(ctx, MoveLocationOptions{
		DataRoot: root,
		SHA256:   sha,
		OldPath:  oldRel,
		NewPath:  newRel,
	})
	if err != nil || !result.Relocated || !result.SourceRemoved {
		t.Fatalf("recovery = %+v, %v", result, err)
	}
	locations, err = db.LocationsForSHA(ctx, sha)
	if err != nil || len(locations) != 1 || locations[0].Path != newRel {
		t.Fatalf("recovered locations = %+v, %v", locations, err)
	}
	retired, err := db.RetiredLocationsForSHA(ctx, sha)
	if err != nil || len(retired) != 1 || retired[0].Path != oldRel || retired[0].SuccessorPath != newRel {
		t.Fatalf("recovered retired locations = %+v, %v", retired, err)
	}
}

func TestMoveLocationRelabelClearsSkipTimestamp(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root := t.TempDir()
	oldRel := "review/scan/a.bin"
	newRel := "pending/scan/a.bin"
	content := []byte("reviewed sample")
	sha := moveTestSHA(content)
	oldAbs := filepath.Join(root, filepath.FromSlash(oldRel))
	if err := os.MkdirAll(filepath.Dir(oldAbs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldAbs, content, 0o440); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: oldRel, Label: "unknown"})
	if _, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = 'stuck', skipped_at = ? WHERE sha256 = ?`, now(), sha); err != nil {
		t.Fatal(err)
	}

	if _, err := db.MoveLocation(ctx, MoveLocationOptions{
		DataRoot: root,
		SHA256:   sha,
		OldPath:  oldRel,
		NewPath:  newRel,
		Relabel:  &LocationRelabel{Label: "good", Source: "review"},
	}); err != nil {
		t.Fatalf("MoveLocation: %v", err)
	}
	var skip string
	var skippedAt any
	if err := db.lite.QueryRowContext(ctx,
		`SELECT skip, skipped_at FROM samples WHERE sha256 = ?`, sha,
	).Scan(&skip, &skippedAt); err != nil {
		t.Fatal(err)
	}
	if skip != "" || skippedAt != nil {
		t.Fatalf("skip state = %q, %v; want empty and NULL", skip, skippedAt)
	}
}

func TestMoveLocationDoesNotClobberConflict(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root := t.TempDir()
	oldRel := "incoming/forager/a.bin"
	newRel := "pending/forager/a.bin"
	content := []byte("source")
	sha := moveTestSHA(content)
	oldAbs := filepath.Join(root, filepath.FromSlash(oldRel))
	newAbs := filepath.Join(root, filepath.FromSlash(newRel))
	for _, name := range []string{oldAbs, newAbs} {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(oldAbs, content, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newAbs, []byte("incumbent"), 0o440); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: oldRel, Label: "unknown"})
	if _, err := db.MoveLocation(ctx, MoveLocationOptions{
		DataRoot: root, SHA256: sha, OldPath: oldRel, NewPath: newRel,
	}); err == nil {
		t.Fatal("MoveLocation accepted conflicting destination")
	}
	if got, err := os.ReadFile(newAbs); err != nil || string(got) != "incumbent" {
		t.Fatalf("destination was clobbered: %q, %v", got, err)
	}
	if got, err := os.ReadFile(oldAbs); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("source changed: %q, %v", got, err)
	}
}

func TestLockMoveSourceHonorsContext(t *testing.T) {
	t.Parallel()
	name := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(name, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck // releasing the test lock; nothing depends on the close
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	locked, err := lockMoveSource(ctx, name)
	if locked != nil {
		locked.Close() //nolint:errcheck // test is already failing
		t.Fatal("lockMoveSource acquired a held lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lockMoveSource error = %v, want context deadline", err)
	}
}

func moveTestSHA(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:])
}

// crossDeviceDir returns a temporary directory on a different filesystem from
// want, skipping the test when the machine offers only one.
//
// The donor path exists precisely because /data/samples/incoming (zroot/hot)
// and /data/samples/good (tank) are separate pools. A same-filesystem test
// cannot reach it: os.Link(src, dst) simply succeeds and publishMoveFile never
// looks for a donor.
func crossDeviceDir(t *testing.T, want string) string {
	t.Helper()
	var target syscall.Stat_t
	if err := syscall.Stat(want, &target); err != nil {
		t.Fatal(err)
	}
	// t.TempDir() lives on os.TempDir(), which may be the very filesystem
	// this helper is trying to escape, so the bases are probed by hand.
	for _, base := range []string{"/dev/shm", os.TempDir(), os.Getenv("HOME")} { //nolint:usetesting // see above
		if base == "" {
			continue
		}
		var candidate syscall.Stat_t
		if err := syscall.Stat(base, &candidate); err != nil || candidate.Dev == target.Dev {
			continue
		}
		dir, err := os.MkdirTemp(base, "hopper-xdev-") //nolint:usetesting // must land on base, not os.TempDir()
		if err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(dir) }) //nolint:errcheck // best-effort test cleanup
		return dir
	}
	t.Skip("no second filesystem available to exercise the cross-device donor path")
	return ""
}

func moveTestInode(t *testing.T, name string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(name, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// TestPublishMoveFilePrefersDonorOverCopy is the point of the whole donor path:
// when the source is on another filesystem but the destination's own pool
// already holds the bytes, publish by hard link and copy nothing. On the real
// corpus this is the difference between moving ~900 GB off the hot pool and
// also writing ~900 GB into tank.
func TestPublishMoveFilePrefersDonorOverCopy(t *testing.T) {
	ctx := context.Background()
	dstRoot := t.TempDir()
	srcRoot := crossDeviceDir(t, dstRoot)

	content := []byte("shipped inside a package we already collected")
	sha := moveTestSHA(content)
	src := filepath.Join(srcRoot, "incoming.tgz")
	donor := filepath.Join(dstRoot, "already-good.tgz")
	dst := filepath.Join(dstRoot, "promoted", "example.tgz")
	for _, name := range []string{src, donor} {
		if err := os.WriteFile(name, content, 0o440); err != nil {
			t.Fatal(err)
		}
	}

	created, err := publishMoveFile(ctx, src, dst, sha, []string{donor})
	if err != nil {
		t.Fatalf("publishMoveFile: %v", err)
	}
	if !created {
		t.Fatal("destination was not created")
	}
	if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("destination = %q, %v", got, err)
	}
	// Sharing an inode with the donor is the assertion that no bytes were
	// copied; equal content alone would also pass on the copy path.
	if moveTestInode(t, dst) != moveTestInode(t, donor) {
		t.Error("destination does not share the donor's inode: it was copied, not linked")
	}
}

// TestPublishMoveFileRejectsWrongDonor: a donor is trusted only after the bytes
// that actually appear at the destination are hashed. A catalog row claiming a
// sha it does not have must never publish those bytes.
func TestPublishMoveFileRejectsWrongDonor(t *testing.T) {
	ctx := context.Background()
	dstRoot := t.TempDir()
	srcRoot := crossDeviceDir(t, dstRoot)

	content := []byte("the real sample bytes")
	sha := moveTestSHA(content)
	src := filepath.Join(srcRoot, "incoming.tgz")
	if err := os.WriteFile(src, content, 0o440); err != nil {
		t.Fatal(err)
	}
	liar := filepath.Join(dstRoot, "mislabelled.tgz")
	if err := os.WriteFile(liar, []byte("entirely different bytes"), 0o440); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dstRoot, "promoted", "example.tgz")

	created, err := publishMoveFile(ctx, src, dst, sha, []string{liar})
	if err != nil {
		t.Fatalf("publishMoveFile: %v", err)
	}
	if !created {
		t.Fatal("destination was not created")
	}
	// The bad donor is rejected and the copy fallback runs, so the destination
	// holds the right bytes and is nobody's link.
	if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("destination = %q, %v", got, err)
	}
	if moveTestInode(t, dst) == moveTestInode(t, liar) {
		t.Error("destination is linked to the mismatched donor")
	}
	if got, err := os.ReadFile(liar); err != nil || string(got) != "entirely different bytes" {
		t.Errorf("donor was modified: %q, %v", got, err)
	}
}

func TestSelectMoveDonors(t *testing.T) {
	root := "/data/samples"
	locs := func(paths ...string) []*SampleLocation {
		out := make([]*SampleLocation, 0, len(paths))
		for _, p := range paths {
			out = append(out, &SampleLocation{Path: p})
		}
		return out
	}
	tests := []struct {
		name   string
		oldRel string
		newRel string
		locs   []*SampleLocation
		want   []string
	}{
		{
			name:   "same pool donor is offered",
			oldRel: "incoming/forager/a.tgz",
			newRel: "good/foraged-promote/a.tgz",
			locs:   locs("incoming/forager/a.tgz", "good/foraged/mint/a.tgz"),
			want:   []string{"/data/samples/good/foraged/mint/a.tgz"},
		},
		{
			// incoming/ is a different pool on a different vdev; linking there
			// is EXDEV, so it is not worth a syscall.
			name:   "other pools are skipped",
			oldRel: "incoming/forager/a.tgz",
			newRel: "good/foraged-promote/a.tgz",
			locs:   locs("incoming/forager/b.tgz", "pending/foraged/a.tgz", "bad/foraged/a.tgz"),
			want:   []string{},
		},
		{
			name:   "source and destination are never donors",
			oldRel: "good/foraged/a.tgz",
			newRel: "good/foraged-promote/a.tgz",
			locs:   locs("good/foraged/a.tgz", "good/foraged-promote/a.tgz"),
			want:   []string{},
		},
		{
			name:   "capped so a damaged sha cannot cost unbounded hashes",
			oldRel: "incoming/forager/a.tgz",
			newRel: "good/foraged-promote/a.tgz",
			locs:   locs("good/1.tgz", "good/2.tgz", "good/3.tgz", "good/4.tgz", "good/5.tgz", "good/6.tgz"),
			want: []string{
				"/data/samples/good/1.tgz", "/data/samples/good/2.tgz",
				"/data/samples/good/3.tgz", "/data/samples/good/4.tgz",
			},
		},
		{
			name:   "traversal in a catalog path is not resolved",
			oldRel: "incoming/forager/a.tgz",
			newRel: "good/foraged-promote/a.tgz",
			locs:   locs("good/../../etc/passwd"),
			want:   []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, _, _ := strings.Cut(tt.newRel, "/")
			got := selectMoveDonors(tt.locs, root, pool, tt.oldRel, tt.newRel)
			if len(got) != len(tt.want) {
				t.Fatalf("donors = %v, want %v", got, tt.want)
			}
			for i := range got {
				if filepath.ToSlash(got[i]) != tt.want[i] {
					t.Errorf("donor[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// writeDedupeFile writes content at rel under root and returns the absolute path.
func writeDedupeFile(t *testing.T, root, rel string, content []byte) string {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, content, 0o440); err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestLinkDuplicateLocations(t *testing.T) {
	ctx := context.Background()
	content := []byte("bytes stored twice because two images shipped them")
	sha := moveTestSHA(content)
	other := []byte("something else entirely, recorded by nobody")

	t.Run("collapses duplicate copies", func(t *testing.T) {
		root := t.TempDir()
		a := writeDedupeFile(t, root, "good/a.tgz", content)
		b := writeDedupeFile(t, root, "good/b.tgz", content)

		result, err := LinkDuplicateLocations(ctx, root, sha, []string{"good/a.tgz", "good/b.tgz"}, false)
		if err != nil {
			t.Fatal(err)
		}
		if result.Linked != 1 || result.Skipped != 0 || result.BytesSaved != int64(len(content)) {
			t.Fatalf("result = %+v", result)
		}
		if moveTestInode(t, a) != moveTestInode(t, b) {
			t.Error("copies were not collapsed onto one inode")
		}
		// Both observations must still resolve: the catalog was never updated,
		// so a path that stopped working would now be a lie.
		for _, name := range []string{a, b} {
			if got, err := os.ReadFile(name); err != nil || !bytes.Equal(got, content) {
				t.Errorf("%s = %q, %v", name, got, err)
			}
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		root := t.TempDir()
		writeDedupeFile(t, root, "good/a.tgz", content)
		if err := os.Link(filepath.Join(root, "good", "a.tgz"), filepath.Join(root, "good", "b.tgz")); err != nil {
			t.Fatal(err)
		}
		result, err := LinkDuplicateLocations(ctx, root, sha, []string{"good/a.tgz", "good/b.tgz"}, false)
		if err != nil {
			t.Fatal(err)
		}
		if result.Linked != 0 || result.Skipped != 0 {
			t.Fatalf("result = %+v, want a no-op on already-shared inodes", result)
		}
	})

	t.Run("never overwrites a victim holding other bytes", func(t *testing.T) {
		root := t.TempDir()
		writeDedupeFile(t, root, "good/a.tgz", content)
		z := writeDedupeFile(t, root, "good/z.tgz", other)

		result, err := LinkDuplicateLocations(ctx, root, sha, []string{"good/a.tgz", "good/z.tgz"}, false)
		if err != nil {
			t.Fatal(err)
		}
		if result.Linked != 0 || result.Skipped != 1 {
			t.Fatalf("result = %+v", result)
		}
		// Those bytes are unaccounted for, which is exactly why they must
		// survive for someone to look at.
		if got, err := os.ReadFile(z); err != nil || !bytes.Equal(got, other) {
			t.Fatalf("mismatched copy was destroyed: %q, %v", got, err)
		}
	})

	t.Run("skips the whole group when the survivor is wrong", func(t *testing.T) {
		root := t.TempDir()
		a := writeDedupeFile(t, root, "good/a.tgz", other) // sorts first, becomes survivor
		z := writeDedupeFile(t, root, "good/z.tgz", content)

		result, err := LinkDuplicateLocations(ctx, root, sha, []string{"good/a.tgz", "good/z.tgz"}, false)
		if err != nil {
			t.Fatal(err)
		}
		if result.Linked != 0 || result.Skipped != 2 {
			t.Fatalf("result = %+v", result)
		}
		if got, err := os.ReadFile(a); err != nil || !bytes.Equal(got, other) {
			t.Errorf("survivor was modified: %q, %v", got, err)
		}
		if got, err := os.ReadFile(z); err != nil || !bytes.Equal(got, content) {
			t.Errorf("good copy was overwritten from a bad survivor: %q, %v", got, err)
		}
	})

	t.Run("dry run changes nothing", func(t *testing.T) {
		root := t.TempDir()
		a := writeDedupeFile(t, root, "good/a.tgz", content)
		b := writeDedupeFile(t, root, "good/b.tgz", content)

		result, err := LinkDuplicateLocations(ctx, root, sha, []string{"good/a.tgz", "good/b.tgz"}, true)
		if err != nil {
			t.Fatal(err)
		}
		if result.Linked != 1 || result.BytesSaved != int64(len(content)) {
			t.Fatalf("result = %+v", result)
		}
		if moveTestInode(t, a) == moveTestInode(t, b) {
			t.Error("dry run collapsed the copies")
		}
	})

	t.Run("absent copies are skipped", func(t *testing.T) {
		root := t.TempDir()
		writeDedupeFile(t, root, "good/a.tgz", content)

		result, err := LinkDuplicateLocations(ctx, root, sha, []string{"good/a.tgz", "good/gone.tgz"}, false)
		if err != nil {
			t.Fatal(err)
		}
		if result.Linked != 0 || result.Skipped != 1 {
			t.Fatalf("result = %+v", result)
		}
	})
}
