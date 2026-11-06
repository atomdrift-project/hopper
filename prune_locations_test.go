package hopper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pruneTestOptions(root, phase string) LocationPruneOptions {
	return LocationPruneOptions{DataRoot: root, Phase: phase, Batch: 7, MaxPaths: 512}
}

func pruneTestCount(t *testing.T, db *DB, table string) int {
	t.Helper()
	var count int
	if err := db.queryLocations(t.Context(), `SELECT count(*) FROM `+table, nil, func(rows locationRows) error {
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
			opts := pruneTestOptions(root, "obsolete")
			opts.DryRun = true
			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || !preview.Complete || preview.Obsolete != 4 || preview.Deleted != 0 || preview.Uncheckable != 2 {
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
			if err != nil || !stats.Complete || stats.Deleted != 4 {
				t.Fatalf("apply: %+v %v", stats, err)
			}
			s, err = db.SampleBySHA256(ctx, moved)
			if err != nil || s.Path != "good/new.bin" || s.Label != "good" || s.Skip != "" {
				t.Fatalf("promoted primary: %+v %v", s, err)
			}
			checkPrunedPrimaries(t, db, []string{gone, goneChild, manual}, manual)
			locs, err := db.LocationsForSHA(ctx, child)
			if err != nil || len(locs) != 1 {
				t.Fatalf("member in present archive removed: %+v %v", locs, err)
			}
			if pruneTestCount(t, db, "sample_location_history") != beforeHistory {
				t.Fatal("obsolete rows copied to history")
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

func pruneOuterCount(t *testing.T, db *DB, child, outer string) int {
	t.Helper()
	locs, err := db.LocationsForSHA(t.Context(), child)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, l := range locs {
		if strings.HasPrefix(l.Path, outer+"!!") {
			count++
		}
	}
	return count
}

func TestPruneLocationsCapAndAdmission(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			parent, child := hexSHA(1101), hexSHA(1102)
			parent2, parent3 := hexSHA(1103), hexSHA(1104)
			first, second, third := "good/archive.tgz", "good/second.tgz", "good/third.tgz"
			for outer, archiveSHA := range map[string]string{first: parent, second: parent2, third: parent3} {
				writeDedupeFile(t, root, outer, []byte("invalid archive bytes"))
				mustInsert(t, ctx, db, &Sample{SHA256: archiveSHA, Path: outer, Label: "good"})
			}
			execBoth(t, ctx, db, `UPDATE samples SET path=$1 WHERE sha256=$2`, first, parent)
			pinned := first + "!!pinned.js"
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: pinned, Parent: parent, Label: "good"})
			observations := seedPruneOccurrences(t, db, child, parent, first, 600)
			seedPruneOccurrences(t, db, child, parent2, second, 130)
			seedPruneOccurrences(t, db, child, parent3, third, 3)
			seedPrunePhysicalAndReferences(t, db, root, child, parent)
			execBoth(t, ctx, db, `UPDATE sample_locations SET first_seen_at=$1 WHERE sha256=$2 AND path=$3`, "2000-01-01T00:00:00Z", child, first+"!!member-259.js")
			countBefore, kvBefore := pruneTestCount(t, db, "sample_locations"), pruneTestCount(t, db, "hopper_kv")
			opts := pruneTestOptions(root, "cap")
			opts.DryRun = true
			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || !preview.Complete || preview.Excess != 222 || preview.CappedSHAs != 1 || preview.ArchiveEdgesRemoved != 0 {
				t.Fatalf("preview: %+v %v", preview, err)
			}
			if pruneTestCount(t, db, "sample_locations") != countBefore || pruneTestCount(t, db, "hopper_kv") != kvBefore {
				t.Fatal("preview wrote data")
			}
			opts.DryRun = false
			stats, err := db.PruneLocations(ctx, opts)
			if err != nil || stats.Deleted != 222 || stats.StatCalls != 0 {
				t.Fatalf("cap: %+v %v", stats, err)
			}
			checkPruneRetained(t, db, child, pinned)
			for outer, want := range map[string]int{first: 510, second: 1, third: 1} {
				if got := pruneOuterCount(t, db, child, outer); got != want {
					t.Fatalf("%s: %d, want %d", outer, got, want)
				}
			}
			checkPruneAdmission(t, db, root, parent, child, observations)
		})
	}
}

func seedPrunePhysicalAndReferences(t *testing.T, db *DB, root, child, parent string) {
	t.Helper()
	var locs []*SampleLocation
	for i := range 600 {
		path := fmt.Sprintf("good/physical-%d.js", i)
		writeDedupeFile(t, root, path, []byte("physical sample"))
		locs = append(locs, &SampleLocation{SHA256: child, Path: path})
	}
	for i := range 200 {
		locs = append(locs, &SampleLocation{SHA256: child, ParentSHA256: parent, Rel: string(RelFetched), Path: fmt.Sprintf("https://example.test/ref-%d", i)})
	}
	if err := db.UpsertLocationBatch(t.Context(), locs); err != nil {
		t.Fatal(err)
	}
}

func checkPruneRetained(t *testing.T, db *DB, child, pinned string) {
	t.Helper()
	locs, err := db.LocationsForSHA(t.Context(), child)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	physical, references := 0, 0
	for _, l := range locs {
		kept[l.Path] = true
		if l.ParentSHA256 == "" {
			physical++
		}
		if l.Rel == string(RelFetched) {
			references++
		}
	}
	if !kept[pinned] || !kept["good/archive.tgz!!member-259.js"] || kept["good/archive.tgz!!member-599.js"] {
		t.Fatal("wrong primary/age selection")
	}
	if physical != 600 || references != 200 {
		t.Fatalf("cap changed physical/reference locations: %d/%d", physical, references)
	}
}

func TestPruneLocationsResumeAndGeneration(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			for i := range 5 {
				mustInsert(t, ctx, db, &Sample{SHA256: hexSHA(1200 + i), Path: fmt.Sprintf("bad/missing-%d", i), Label: "bad"})
			}
			opts := pruneTestOptions(root, "obsolete")
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
			execBoth(t, ctx, db, `INSERT INTO hopper_kv(key,value) VALUES($1,'-1')`, locationCapKey(later, "good/parent!!new.js"))
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

func checkPrunedPrimaries(t *testing.T, db *DB, shas []string, manual string) {
	t.Helper()
	ctx := t.Context()
	for _, sha := range shas {
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		wantSkip := "missing"
		if sha == manual {
			wantSkip = "unsupported"
		}
		if s.Path != "" || s.Skip != wantSkip {
			t.Fatalf("unrecoverable primary: %+v", s)
		}
	}
}

func checkPruneAdmission(t *testing.T, db *DB, root, parent, child string, observations []*SampleLocation) {
	t.Helper()
	ctx := t.Context()
	if err := db.UpsertLocation(ctx, observations[550]); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertLocationBatch(ctx, observations[551:553]); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: child, Path: observations[553].Path, Parent: parent, Label: "good"})
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{SHA256: child, Path: observations[554].Path, Parent: parent, Label: "good"}}); err != nil {
		t.Fatal(err)
	}
	envelope := fmt.Appendf(nil, `{"v":8,"files":[{"sha":%q,"type":"tar.gz","path":"good/archive.tgz"},{"sha":%q,"type":"javascript","depth":1,"size":100,"path":"good/archive.tgz!!member-555.js"}]}`, parent, child)
	if _, err := db.StoreResult(ctx, parent, envelope, nil, nil, nil, "cap-test", ResultAttribution{}); err != nil {
		t.Fatal(err)
	}
	if got := pruneOuterCount(t, db, child, "good/archive.tgz"); got != 510 {
		t.Fatalf("ingest recreated capped rows: %d", got)
	}
	if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: child, Path: observations[0].Path, ParentSHA256: parent, Rel: string(RelUnpacked)}); err != nil {
		t.Fatal(err)
	}
	locs, err := db.LocationsForSHA(ctx, child)
	if err != nil {
		t.Fatal(err)
	}
	refreshed := false
	for _, l := range locs {
		refreshed = refreshed || l.Path == observations[0].Path && l.Rel == string(RelUnpacked)
	}
	if !refreshed {
		t.Fatal("cap blocked retained metadata update")
	}
	seedPruneOccurrences(t, db, child, parent, "good/fourth.tgz", 4)
	if got := pruneOuterCount(t, db, child, "good/fourth.tgz"); got != 0 {
		t.Fatal("global cap admitted another archive")
	}
	checkPruneFreedFile(t, db, root, child, observations[550])
}

func checkPruneFreedFile(t *testing.T, db *DB, root, child string, discarded *SampleLocation) {
	t.Helper()
	ctx := t.Context()
	if err := os.Remove(filepath.Join(root, "good", "archive.tgz")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PruneLocations(ctx, pruneTestOptions(root, "obsolete")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.KVGet(ctx, locationCapKey(child, "good/archive.tgz!!member")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("marker survived freed file: %v", err)
	}
	if err := db.UpsertLocation(ctx, discarded); err != nil {
		t.Fatal(err)
	}
	if got := pruneOuterCount(t, db, child, "good/archive.tgz"); got != 1 {
		t.Fatal("freed file not refillable")
	}
	if _, err := os.Stat(filepath.Join(root, "good", "physical-1.js")); err != nil {
		t.Fatal("cap removed files:", err)
	}
}

func TestPruneArchiveCapDuringMove(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			parent, child := hexSHA(1501), hexSHA(1502)
			oldPath, newPath := "good/old.tgz", "good/new.tgz"
			writeDedupeFile(t, root, newPath, []byte("not a readable archive"))
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: oldPath, Label: "good"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: parent, Path: newPath}); err != nil {
				t.Fatal(err)
			}
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: oldPath + "!!pinned", Parent: parent, Label: "good"})
			seedPruneOccurrences(t, db, child, parent, oldPath, 600)
			// This models the window after source unlink, before member rebasing. The
			// pruner must skip the archive even though its old outer file is absent.
			held, err := lockMoveContent(ctx, root, parent)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close() //nolint:errcheck // explicit close below releases it before recovery
			opts := pruneTestOptions(root, "cap")
			stats, err := db.PruneLocations(ctx, opts)
			if err != nil || stats.Deleted != 0 || stats.BusyArchives != 1 {
				t.Fatalf("busy: %+v %v", stats, err)
			}
			if got := pruneOuterCount(t, db, child, oldPath); got != 601 {
				t.Fatalf("busy archive lost paths: %d", got)
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			moved, err := db.moveLocation(ctx, MoveLocationOptions{DataRoot: root, SHA256: parent, OldPath: oldPath, NewPath: newPath, ExpectedLabel: "good"}, false)
			if err != nil || !moved.Relocated {
				t.Fatalf("recover move: %+v %v", moved, err)
			}
			stats, err = db.PruneLocations(ctx, opts)
			if err != nil || stats.Deleted != 89 || stats.BusyArchives != 0 || stats.StatCalls != 0 {
				t.Fatalf("cap after move: %+v %v", stats, err)
			}
			if got := pruneOuterCount(t, db, child, newPath); got != 512 {
				t.Fatalf("new archive allowance: %d", got)
			}
			sample, err := db.SampleBySHA256(ctx, child)
			if err != nil || sample.Path != newPath+"!!pinned" {
				t.Fatalf("primary lost: %+v %v", sample, err)
			}
		})
	}
}

func TestPruneGlobalCapAcrossArchives(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			child := hexSHA(2001)
			firstParent := hexSHA(2100)
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: "good/0.tgz!!item", Parent: firstParent, Label: "good"})
			var locs []*SampleLocation
			for i := range 600 {
				parent := hexSHA(2100 + i)
				mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: fmt.Sprintf("good/%d.tgz", i), Label: "good"})
				locs = append(locs, &SampleLocation{SHA256: child, ParentSHA256: parent, Path: fmt.Sprintf("good/%d.tgz!!item", i)})
			}
			if err := db.UpsertLocationBatch(ctx, locs); err != nil {
				t.Fatal(err)
			}
			opts := pruneTestOptions(root, "cap")
			opts.DryRun = true
			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || preview.Excess != 88 || preview.ArchivesSeen != 600 || preview.ArchiveEdgesRemoved != 88 || preview.StatCalls != 0 {
				t.Fatalf("preview: %+v %v", preview, err)
			}
			opts.DryRun = false
			applied, err := db.PruneLocations(ctx, opts)
			if err != nil || applied.Deleted != 88 {
				t.Fatalf("apply: %+v %v", applied, err)
			}
			kept, err := db.LocationsForSHA(ctx, child)
			if err != nil || len(kept) != 512 {
				t.Fatalf("retained=%d %v", len(kept), err)
			}
			sample, err := db.SampleBySHA256(ctx, child)
			if err != nil || sample.Path != "good/0.tgz!!item" || sample.Skip != "" {
				t.Fatalf("primary changed: %+v %v", sample, err)
			}
		})
	}
}
