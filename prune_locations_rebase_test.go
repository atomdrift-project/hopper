package hopper

import (
	"fmt"
	"testing"
)

func pruneTestLocationPaths(t *testing.T, db *DB, sha string) map[string]bool {
	t.Helper()
	locs, err := db.LocationsForSHA(t.Context(), sha)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, l := range locs {
		paths[l.Path] = true
	}
	return paths
}

// An archive moved out of band leaves members under its old path. The obsolete
// pass must move them onto the live copy, not discard them as missing.
func TestPruneLocationsRebaseMovedArchive(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			pruneTestPools(t, root, "unknown")
			const oldArch, newArch = "unknown/harvest/arch.whl", "good/new/arch.whl"
			writeDedupeFile(t, root, newArch, []byte("live archive bytes"))
			archive, goneArchive := hexSHA(1701), hexSHA(1702)
			member, nested, orphan, unmapped, dup, staged := hexSHA(1703), hexSHA(1704), hexSHA(1705), hexSHA(1706), hexSHA(1707), hexSHA(1708)
			// The stale archive row has the lowest ID, so it is removed before its
			// members are reached; the retired path must keep them mappable.
			mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: oldArch, Label: "good"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: archive, Path: newArch}); err != nil {
				t.Fatal(err)
			}
			mustInsert(t, ctx, db, &Sample{SHA256: goneArchive, Path: "unknown/harvest/gone.whl", Label: "good"})
			for _, s := range []*Sample{
				{SHA256: member, Path: oldArch + "!!pkg/m.py", Parent: archive, Label: "good"},
				{SHA256: nested, Path: oldArch + "!!inner.zip!!x.js", Parent: archive, Label: "good"},
				{SHA256: orphan, Path: "unknown/harvest/gone.whl!!o.py", Parent: goneArchive, Label: "good"},
				{SHA256: unmapped, Path: "unknown/elsewhere/other.whl!!u.js", Parent: archive, Label: "good"},
				{SHA256: dup, Path: oldArch + "!!d.js", Parent: archive, Label: "good"},
				// Recorded under a staging path the archive itself never had.
				{SHA256: staged, Path: "unknown/harvest/new/pypi/arch.whl!!s.py", Parent: archive, Label: "good"},
			} {
				mustInsert(t, ctx, db, s)
			}
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: dup, ParentSHA256: archive, Path: newArch + "!!d.js"}); err != nil {
				t.Fatal(err)
			}
			before := pruneTestCount(t, db, "sample_locations")
			opts := pruneTestOptions(root)
			opts.Batch = 2 // archive rows and members land in different batches
			opts.DryRun = true
			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || preview.Rebased != 4 || preview.RebaseDuplicates != 1 || preview.RebaseConflicts != 0 ||
				preview.Obsolete != 1 || preview.Protected != 2 || preview.Unmapped != 1 {
				t.Fatalf("preview: %+v %v", preview, err)
			}
			if pruneTestCount(t, db, "sample_locations") != before {
				t.Fatal("preview wrote rows")
			}

			opts.DryRun = false
			// A fresh run proves the mapping does not depend on the in-memory cache.
			stats, err := db.PruneLocations(ctx, opts)
			if err != nil || stats.Rebased != 4 || stats.Deleted != 1 || stats.Protected != 2 || stats.Unmapped != 1 {
				t.Fatalf("apply: %+v %v", stats, err)
			}
			for sha, want := range map[string]string{
				member: newArch + "!!pkg/m.py", nested: newArch + "!!inner.zip!!x.js", archive: newArch, staged: newArch + "!!s.py",
			} {
				s, err := db.SampleBySHA256(ctx, sha)
				if err != nil || s.Path != want || s.Skip != "" {
					t.Fatalf("%s primary: %+v %v, want %s", sha[:8], s, err, want)
				}
				if paths := pruneTestLocationPaths(t, db, sha); len(paths) != 1 || !paths[want] {
					t.Fatalf("%s locations: %v", sha[:8], paths)
				}
			}
			if paths := pruneTestLocationPaths(t, db, dup); len(paths) != 1 || !paths[newArch+"!!d.js"] {
				t.Fatalf("duplicate rebase: %v", paths)
			}
			if paths := pruneTestLocationPaths(t, db, unmapped); len(paths) != 1 {
				t.Fatalf("unmapped member removed: %v", paths)
			}
			s, err := db.SampleBySHA256(ctx, orphan)
			if err != nil || s.Path != "unknown/harvest/gone.whl!!o.py" || s.Skip != "" {
				t.Fatalf("member of a vanished archive: %+v %v", s, err)
			}
		})
	}
}

// A member whose archive's stale row was removed by an earlier, separate run
// is still rebased from the retired path.
func TestPruneRebaseTarget(t *testing.T) {
	p := &pruneParent{known: map[string]bool{}, names: map[string]bool{}, live: "good/live/inner.zip"}
	for _, path := range []string{"old/outer.tgz!!inner.zip", "good/live/inner.zip"} {
		p.remember(path)
	}
	for _, tc := range []struct{ path, want string }{
		{"old/outer.tgz!!inner.zip!!m.js", "good/live/inner.zip!!m.js"},     // exact nested prefix
		{"staging/outer.tgz!!inner.zip!!m.js", "good/live/inner.zip!!m.js"}, // name fallback, innermost boundary
		{"staging/inner.zip!!deep/x.zip!!m.js", "good/live/inner.zip!!deep/x.zip!!m.js"},
		{"staging/other.zip!!m.js", ""},
		{"staging/inner.zip!!deep/inner.zip!!m.js", ""}, // ambiguous filename fallback
	} {
		got, ok := p.rebaseTarget(tc.path)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: %q %v, want %q", tc.path, got, ok, tc.want)
		}
	}
}

func TestPruneTruncatedParentLookupIsNotAbsence(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			parent := hexSHA(6500)
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: "good/old.tgz", Label: "good"})
			locs := make([]*SampleLocation, 0, pruneParentLimit)
			for i := range pruneParentLimit {
				locs = append(locs, &SampleLocation{SHA256: parent, Path: fmt.Sprintf("good/missing-%d.tgz", i)})
			}
			if err := db.UpsertLocationBatch(ctx, locs); err != nil {
				t.Fatal(err)
			}
			writeDedupeFile(t, root, "good/live.tgz", []byte("live archive"))
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: parent, Path: "good/live.tgz"}); err != nil {
				t.Fatal(err)
			}
			stats := LocationPruneStats{}
			checker := &pruneChecker{root: root, stats: &stats, cache: map[string]prunePresence{}}
			plan, err := db.planObsoleteRebases(ctx, []pruneLocation{{SHA: hexSHA(6501), Parent: parent, Path: "good/old.tgz!!m.js"}}, checker, false)
			if err != nil || len(plan.deletes) != 0 || plan.unmapped != 1 {
				t.Fatalf("truncated lookup treated as absence: %+v %v", plan, err)
			}
		})
	}
}

func TestPruneLocationsRebaseAcrossRuns(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			pruneTestPools(t, root, "unknown")
			const oldArch, newArch = "unknown/harvest/a.tgz", "good/a.tgz"
			writeDedupeFile(t, root, newArch, []byte("live"))
			archive, member := hexSHA(1801), hexSHA(1802)
			mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: oldArch, Label: "good"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: archive, Path: newArch}); err != nil {
				t.Fatal(err)
			}
			mustInsert(t, ctx, db, &Sample{SHA256: member, Path: oldArch + "!!m.js", Parent: archive, Label: "good"})
			opts := pruneTestOptions(root)
			opts.Limit = 1 // first run: only the archive row
			first, err := db.PruneLocations(ctx, opts)
			if err != nil || first.Deleted != 1 || first.Rebased != 0 {
				t.Fatalf("first: %+v %v", first, err)
			}
			opts.Limit = 0
			opts.AfterID, opts.ThroughID = first.AfterID, first.ThroughID
			second, err := db.PruneLocations(ctx, opts)
			if err != nil || second.Rebased != 1 || second.Unmapped != 0 {
				t.Fatalf("second: %+v %v", second, err)
			}
			if paths := pruneTestLocationPaths(t, db, member); !paths[newArch+"!!m.js"] {
				t.Fatalf("member not rebased: %v", paths)
			}
		})
	}
}
