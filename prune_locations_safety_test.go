package hopper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckObsoleteSafety(t *testing.T) {
	opts := LocationPruneOptions{MaxObsoleteFraction: 0.4}
	for _, tc := range []struct {
		name              string
		obsolete, scanned int64
		victims, batch    int
		trip              bool
		fraction          float64
	}{
		{name: "quiet batch", victims: 10, batch: 1000},
		{name: "small cluster under the floor", victims: 50, batch: 50},
		{name: "wrong root", victims: 1000, batch: 1000, trip: true},
		{name: "batch at the cap", victims: 400, batch: 1000},
		{name: "batch over the cap", victims: 401, batch: 1000, trip: true},
		// Each batch passes alone; the pass as a whole drifted past the cap.
		{name: "cumulative drift", obsolete: 3900, scanned: 9000, victims: 390, batch: 1000, trip: true},
		{name: "cumulative fine", obsolete: 100, scanned: 9000, victims: 390, batch: 1000},
		{name: "disabled", victims: 1000, batch: 1000, fraction: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			if tc.fraction != 0 {
				o.MaxObsoleteFraction = tc.fraction
			}
			stats := &LocationPruneStats{Obsolete: tc.obsolete, Scanned: tc.scanned}
			err := checkObsoleteSafety(o, stats, tc.victims, tc.batch)
			if got := errors.As(err, new(*PruneSafetyExceeded)); got != tc.trip {
				t.Fatalf("trip=%v, want %v (%v)", got, tc.trip, err)
			}
		})
	}
}

func TestPruneLocationsSafetyCap(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			for i := range 20 {
				path := fmt.Sprintf("good/present-%d.bin", i)
				writeDedupeFile(t, root, path, []byte(path))
				mustInsert(t, ctx, db, &Sample{SHA256: hexSHA(1400 + i), Path: path, Label: "good"})
			}
			for i := range 100 {
				mustInsert(t, ctx, db, &Sample{SHA256: hexSHA(1500 + i), Path: fmt.Sprintf("good/gone-%d.bin", i), Label: "good"})
			}
			before := pruneTestCount(t, db, "sample_locations")
			opts := LocationPruneOptions{DataRoot: root, Phase: "obsolete", Batch: 1000, DryRun: true}

			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || !preview.Complete || preview.Obsolete != 100 || preview.SafetyTrips != 1 {
				t.Fatalf("preview should report the trip without stopping: %+v %v", preview, err)
			}

			opts.DryRun = false
			stats, err := db.PruneLocations(ctx, opts)
			var exceeded *PruneSafetyExceeded
			if !errors.As(err, &exceeded) || exceeded.Victims != 100 || exceeded.Total != 120 {
				t.Fatalf("apply should refuse the batch: %+v %v", stats, err)
			}
			if stats.Deleted != 0 || pruneTestCount(t, db, "sample_locations") != before {
				t.Fatal("refused batch modified the catalog")
			}

			opts.MaxObsoleteFraction = 1
			stats, err = db.PruneLocations(ctx, opts)
			if err != nil || stats.Deleted != 100 {
				t.Fatalf("forced apply: %+v %v", stats, err)
			}
		})
	}
}

func TestPruneLocationsPoolGuard(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			// "empty" is an unmounted mountpoint; "absent" has no directory at all.
			if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
				t.Fatal(err)
			}
			pruneTestPools(t, root, "mounted")
			for i, path := range []string{"empty/a.bin", "empty/sub/b.tgz!!m.js", "absent/c.bin", "mounted/d.bin", "e.bin"} {
				mustInsert(t, ctx, db, &Sample{SHA256: hexSHA(1600 + i), Path: path, Label: "good"})
			}
			opts := LocationPruneOptions{DataRoot: root, Phase: "obsolete", Batch: 100, MaxObsoleteFraction: 1}
			stats, err := db.PruneLocations(ctx, opts)
			if err != nil || stats.Deleted != 2 || stats.Uncheckable != 3 || stats.PoolGuarded != 3 {
				t.Fatalf("guard: %+v %v", stats, err)
			}
			for i := range 3 {
				if locs, err := db.LocationsForSHA(ctx, hexSHA(1600+i)); err != nil || len(locs) != 1 {
					t.Fatalf("guarded row %d removed: %+v %v", i, locs, err)
				}
			}
		})
	}
}
