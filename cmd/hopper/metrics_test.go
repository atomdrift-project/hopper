package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestMetricsStore(t *testing.T) {
	ctx := context.Background()
	ms, err := openMetricsStore(ctx, filepath.Join(t.TempDir(), "queue-metrics.db"))
	if err != nil {
		t.Fatalf("openMetricsStore: %v", err)
	}
	t.Cleanup(func() {
		if err := ms.close(); err != nil {
			t.Errorf("close metrics store: %v", err)
		}
	})

	base := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	for i := range 3 {
		p := queuePoint{
			T:         base.Add(time.Duration(i) * time.Minute),
			Pending:   int64(100 - i),
			Rescan:    int64(1000 + i),
			Completed: int64(i * 10),
		}
		if err := ms.record(ctx, p); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	// A cutoff before every point returns all three, oldest first.
	pts, err := ms.series(ctx, base.Add(-time.Minute))
	if err != nil {
		t.Fatalf("series: %v", err)
	}
	if len(pts) != 3 {
		t.Fatalf("series len = %d, want 3", len(pts))
	}
	if pts[0].Pending != 100 || pts[2].Completed != 20 {
		t.Errorf("unexpected endpoints: first=%+v last=%+v", pts[0], pts[2])
	}
	if !pts[0].T.Before(pts[1].T) || !pts[1].T.Before(pts[2].T) {
		t.Errorf("points not ordered ascending by time")
	}

	// A later cutoff drops the earliest point.
	pts, err = ms.series(ctx, base.Add(30*time.Second))
	if err != nil {
		t.Fatalf("series: %v", err)
	}
	if len(pts) != 2 {
		t.Fatalf("series after cutoff len = %d, want 2", len(pts))
	}

	// prune drops everything strictly older than the cutoff.
	if err := ms.prune(ctx, base.Add(90*time.Second)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	pts, err = ms.series(ctx, base.Add(-time.Hour))
	if err != nil {
		t.Fatalf("series: %v", err)
	}
	if len(pts) != 1 {
		t.Fatalf("after prune len = %d, want 1", len(pts))
	}
}

// TestMetricsStoreMigratesExistingCache proves the added column reaches a cache
// file that predates it. CREATE TABLE IF NOT EXISTS silently does nothing to an
// existing table, so without the ALTER every write would fail against a cache
// carried over from the previous build -- and the graphs would stay empty for
// exactly the reason the user could not see.
func TestMetricsStoreMigratesExistingCache(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "queue-metrics.db")

	// An old-schema cache with one row of history worth keeping.
	old, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.ExecContext(ctx, `CREATE TABLE queue_metrics (
		ts INTEGER PRIMARY KEY, pending INTEGER NOT NULL,
		rescan INTEGER NOT NULL, completed INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.ExecContext(ctx,
		`INSERT INTO queue_metrics (ts,pending,rescan,completed) VALUES (?,?,?,?)`,
		time.Now().Add(-time.Hour).Unix(), 5, 6, 7); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	ms, err := openMetricsStore(ctx, path)
	if err != nil {
		t.Fatalf("openMetricsStore on a pre-existing cache: %v", err)
	}
	defer ms.close() //nolint:errcheck // test cleanup
	if err := ms.record(ctx, queuePoint{T: time.Now(), Pending: 1, Rescan: 2, Completed: 3, Added: 4}); err != nil {
		t.Fatalf("record after migration: %v", err)
	}
	pts, err := ms.series(ctx, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 2 {
		t.Fatalf("got %d points, want 2; the pre-existing row must survive the migration", len(pts))
	}
	if pts[0].Added != 0 {
		t.Errorf("legacy row Added = %d, want 0", pts[0].Added)
	}
	if pts[1].Added != 4 {
		t.Errorf("new row Added = %d, want 4", pts[1].Added)
	}

	// Reopening must be a no-op, not a duplicate-column failure.
	again, err := openMetricsStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen after migration: %v", err)
	}
	if err := again.close(); err != nil {
		t.Fatal(err)
	}
}
