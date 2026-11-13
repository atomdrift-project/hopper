package hopper

import (
	"fmt"
	"path/filepath"
	"testing"
)

// pruneTestOptions disables the obsolete fraction cap: these fixtures remove
// most of a tiny catalog on purpose. TestPruneLocationsSafetyCap covers it.
func pruneTestOptions(root string) LocationPruneOptions {
	return LocationPruneOptions{DataRoot: root, Batch: 7, MaxObsoleteFraction: 1}
}

// pruneTestPools gives each pool a sentinel so it reads as mounted; an empty
// or missing pool directory protects its rows from the obsolete pass.
func pruneTestPools(t *testing.T, root string, pools ...string) {
	t.Helper()
	for _, pool := range pools {
		writeDedupeFile(t, root, pool+"/.mounted", nil)
	}
}

func pruneTestCount(t *testing.T, db *DB, table string) int {
	t.Helper()
	var count int
	if err := db.queryLocations(t.Context(), `SELECT count(*) FROM `+table, nil, func(rows sqlRows) error {
		if rows.Next() {
			return rows.Scan(&count)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestPruneLocationsObsolete(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			parent, child, gone, goneChild, moved, reference, outside, manual := hexSHA(1001), hexSHA(1002), hexSHA(1003), hexSHA(1004), hexSHA(1005), hexSHA(1006), hexSHA(1007), hexSHA(1008)
			pruneTestPools(t, root, "bad")
			// Invalid archive bytes prove that pruning only checks the outer file.
			writeDedupeFile(t, root, "good/present.tgz", []byte("not a readable archive"))
			writeDedupeFile(t, root, "good/new.bin", []byte("present bytes"))
			fixtures := []*Sample{
				{SHA256: parent, Path: "good/present.tgz", Label: "good"},
				{SHA256: child, Path: "good/present.tgz!!does/not/exist.js", Parent: parent, Label: "good"},
				{SHA256: gone, Path: "bad/gone.tgz", Label: "bad"},
				{SHA256: goneChild, Path: "bad/gone.tgz!!nested.zip!!member.js", Parent: gone, Label: "good"},
				{SHA256: moved, Path: "good/old.bin", Label: "good"},
				{SHA256: reference, Path: "https://example.test/dependency", Parent: parent, LocationRel: "fetched", Label: "good"},
				{SHA256: outside, Path: filepath.Join(t.TempDir(), "elsewhere.bin"), Label: "good"},
				{SHA256: manual, Path: "bad/manual.bin", Label: "bad", Skip: "unsupported"},
			}
			for _, s := range fixtures {
				mustInsert(t, ctx, db, s)
			}
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: moved, Path: "good/new.bin"}); err != nil {
				t.Fatal(err)
			}
			beforeLocations, beforeHistory, beforeKV := pruneTestCount(t, db, "sample_locations"), pruneTestCount(t, db, "sample_location_history"), pruneTestCount(t, db, "hopper_kv")
			opts := pruneTestOptions(root)
			opts.DryRun = true
			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || !preview.Complete || preview.Obsolete != 1 || preview.Deleted != 0 || preview.Protected != 3 || preview.Uncheckable != 2 {
				t.Fatalf("preview: %+v %v", preview, err)
			}
			if preview.CacheHits < 2 {
				t.Fatalf("outer paths were not shared: %+v", preview)
			}
			if pruneTestCount(t, db, "sample_locations") != beforeLocations || pruneTestCount(t, db, "sample_location_history") != beforeHistory || pruneTestCount(t, db, "hopper_kv") != beforeKV {
				t.Fatal("preview modified database")
			}
			s, err := db.SampleBySHA256(ctx, moved)
			if err != nil || s.Path != "good/old.bin" {
				t.Fatalf("preview changed primary: %+v %v", s, err)
			}
			opts.DryRun = false
			stats, err := db.PruneLocations(ctx, opts)
			if err != nil || !stats.Complete || stats.Deleted != 1 || stats.Protected != 3 {
				t.Fatalf("apply: %+v %v", stats, err)
			}
			s, err = db.SampleBySHA256(ctx, moved)
			if err != nil || s.Path != "good/new.bin" || s.Label != "good" || s.Skip != "" {
				t.Fatalf("promoted primary: %+v %v", s, err)
			}
			for _, sha := range []string{gone, goneChild, manual} {
				if got := len(pruneTestLocationPaths(t, db, sha)); got != 1 {
					t.Fatalf("final observation removed for %s: %d", sha, got)
				}
			}
			locs, err := db.LocationsForSHA(ctx, child)
			if err != nil || len(locs) != 1 {
				t.Fatalf("member in present archive removed: %+v %v", locs, err)
			}
			// The archive's final path is protected, and redundant leaf paths
			// do not need a second copy in history.
			if got := pruneTestCount(t, db, "sample_location_history"); got != beforeHistory {
				t.Fatalf("history rows: %d, want %d", got, beforeHistory)
			}
			again, err := db.PruneLocations(ctx, opts)
			if err != nil || again.Deleted != 0 {
				t.Fatalf("repeat: %+v %v", again, err)
			}
		})
	}
}

func seedPruneOccurrences(t *testing.T, db *DB, child, parent, outer string, count int) []*SampleLocation {
	t.Helper()
	locs := make([]*SampleLocation, 0, count)
	for i := range count {
		locs = append(locs, &SampleLocation{SHA256: child, ParentSHA256: parent, Path: fmt.Sprintf("%s!!member-%03d.js", outer, i)})
	}
	if err := db.UpsertLocationBatch(t.Context(), locs); err != nil {
		t.Fatal(err)
	}
	return locs
}

func TestPruneLocationsResumeAndGeneration(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			pruneTestPools(t, root, "bad")
			for i := range 5 {
				mustInsert(t, ctx, db, &Sample{SHA256: hexSHA(1200 + i), Path: fmt.Sprintf("bad/missing-%d", i), Label: "bad"})
			}
			writeDedupeFile(t, root, "good/live", []byte("live"))
			for i := range 5 {
				if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: hexSHA(1200 + i), Path: "good/live"}); err != nil {
					t.Fatal(err)
				}
			}
			opts := pruneTestOptions(root)
			opts.Batch = 2
			opts.Limit = 2
			first, err := db.PruneLocations(ctx, opts)
			if err != nil || first.Complete || first.Deleted != 2 {
				t.Fatalf("first: %+v %v", first, err)
			}
			// Arrivals beyond the initial high-water mark must not enter the resumed pass.
			later := hexSHA(1300)
			mustInsert(t, ctx, db, &Sample{SHA256: later, Path: "bad/new-missing", Label: "bad"})
			opts.AfterID = first.AfterID
			opts.ThroughID = first.ThroughID
			opts.Limit = 0
			second, err := db.PruneLocations(ctx, opts)
			if err != nil || !second.Complete || second.Deleted != 3 {
				t.Fatalf("resume: %+v %v", second, err)
			}
			locs, err := db.LocationsForSHA(ctx, later)
			if err != nil || len(locs) != 1 {
				t.Fatal("resumed sweep touched new arrival")
			}
			// A stale generation marker cannot block a newly created sample row.
			execBoth(t, ctx, db, `INSERT INTO hopper_kv(key,value) VALUES($1,'-1')`, "location-member-cap/"+later)
			parent := hexSHA(1400)
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: "good/parent", Label: "good"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: later, Path: "good/parent!!new.js", ParentSHA256: parent}); err != nil {
				t.Fatal(err)
			}
			locs, err = db.LocationsForSHA(ctx, later)
			if err != nil || len(locs) != 2 {
				t.Fatal("stale generation blocked new observations")
			}
		})
	}
}

func TestPruneCheckerErrorsAndSharedOuter(t *testing.T) {
	stats := LocationPruneStats{}
	root := t.TempDir()
	c := pruneChecker{root: root, cache: map[string]prunePresence{}, stats: &stats}
	writeDedupeFile(t, root, "archive", []byte("invalid archive contents"))
	for _, p := range []string{"archive!!a", "archive!!nested!!b"} {
		if c.check(p, false) != prunePresent {
			t.Fatal("missing member treated as missing archive")
		}
	}
	if stats.StatCalls != 1 || stats.CacheHits != 1 {
		t.Fatalf("cache: %+v", stats)
	}
	if c.check("https://example.test/file", false) != pruneUnknown || c.check("../outside", false) != pruneUnknown {
		t.Fatal("uncheckable path treated as obsolete")
	}
	// ENOTDIR is an error, not proof that a stored observation is obsolete.
	if c.check("archive/child", false) != pruneUnknown {
		t.Fatal("non-ENOENT stat error deleted")
	}
}
