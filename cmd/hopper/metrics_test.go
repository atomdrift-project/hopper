package main

import (
	"context"
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
