package hopper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if got, err := os.ReadFile(newAbs); err != nil || string(got) != string(content) {
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
	if got, err := os.ReadFile(oldAbs); err != nil || string(got) != string(content) {
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
	defer held.Close() //nolint:errcheck
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	locked, err := lockMoveSource(ctx, name)
	if locked != nil {
		locked.Close() //nolint:errcheck
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
