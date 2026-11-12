package hopper

import (
	"fmt"
	"testing"
)

func TestPruneObsoletePreservesFinalRelationship(t *testing.T) {
	for _, backend := range testBackends {
		for _, batch := range []int{1, 100} {
			t.Run(fmt.Sprintf("%s/batch-%d", backend.name, batch), func(t *testing.T) {
				db := backend.open(t)
				ctx := t.Context()
				root := t.TempDir()
				pruneTestPools(t, root, "good")
				child := hexSHA(6100)
				for i := range 3 {
					parent := hexSHA(6101 + i)
					path := fmt.Sprintf("good/gone-%d.tgz", i)
					mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: path, Label: "good"})
					if i == 0 {
						mustInsert(t, ctx, db, &Sample{SHA256: child, Path: path + "!!m.js", Parent: parent, Label: "good"})
					} else if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: child, Path: path + "!!m.js", ParentSHA256: parent}); err != nil {
						t.Fatal(err)
					}
				}
				opts := pruneTestOptions(root)
				opts.Batch = batch
				stats, err := db.PruneLocations(ctx, opts)
				if err != nil || stats.Deleted != 2 {
					t.Fatalf("obsolete: %+v %v", stats, err)
				}
				locs, err := db.LocationsForSHA(ctx, child)
				if err != nil || len(locs) != 1 || locs[0].ParentSHA256 == "" {
					t.Fatalf("final relationship lost: %+v %v", locs, err)
				}
				sample, err := db.SampleBySHA256(ctx, child)
				if err != nil || sample.Parent != locs[0].ParentSHA256 || sample.Path != locs[0].Path {
					t.Fatalf("primary no longer traverses the retained edge: %+v %v", sample, err)
				}
				again, err := db.PruneLocations(ctx, opts)
				if err != nil || again.Deleted != 0 {
					t.Fatalf("second pass removed the final edge: %+v %v", again, err)
				}
			})
		}
	}
}

func TestPrunePhysicalCopyPreservesFinalParent(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			parent, child := hexSHA(6200), hexSHA(6201)
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: "good/p.tgz", Label: "good"})
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: "good/physical", Label: "good"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: child, Path: "good/p.tgz!!m.js", ParentSHA256: parent}); err != nil {
				t.Fatal(err)
			}
			locs, err := db.LocationsForSHA(ctx, child)
			if err != nil {
				t.Fatal(err)
			}
			var victim pruneLocation
			for _, l := range locs {
				if l.ParentSHA256 != "" {
					victim = pruneLocation{ID: l.ID, SHA: l.SHA256, Path: l.Path, Parent: l.ParentSHA256, Rel: l.Rel}
				}
			}
			stats := LocationPruneStats{}
			checker := &pruneChecker{root: t.TempDir(), stats: &stats, cache: map[string]prunePresence{}}
			deleted, protected, err := db.deletePruneLocations(ctx, []pruneLocation{victim}, checker)
			if err != nil || deleted != 0 || protected != 1 {
				t.Fatalf("physical copy must not erase the final parent edge: deleted=%d protected=%d %v", deleted, protected, err)
			}
		})
	}
}

func TestPruneRebasePreservesConflictingParent(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			parent, other, child := hexSHA(6300), hexSHA(6301), hexSHA(6302)
			for i, sha := range []string{parent, other} {
				mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: fmt.Sprintf("good/%d.tgz", i), Label: "good"})
			}
			const oldPath, newPath = "good/old.tgz!!m.js", "good/new.tgz!!m.js"
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: oldPath, Parent: parent, Label: "good"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: child, Path: newPath, ParentSHA256: other}); err != nil {
				t.Fatal(err)
			}
			locs, err := db.LocationsForSHA(ctx, child)
			if err != nil {
				t.Fatal(err)
			}
			var old *SampleLocation
			for _, l := range locs {
				if l.Path == oldPath {
					old = l
				}
			}
			if old == nil {
				t.Fatal("missing source fixture")
			}
			rebases := []pruneRebase{{loc: pruneLocation{ID: old.ID, SHA: child, Path: oldPath, Parent: parent}, newPath: newPath}}
			duplicates, conflicts, err := db.previewPruneRebaseTargets(ctx, rebases)
			if err != nil || duplicates != 0 || conflicts != 1 {
				t.Fatalf("conflicting preview target: duplicates=%d conflicts=%d %v", duplicates, conflicts, err)
			}
			moved, err := db.rebasePruneLocations(ctx, rebases)
			if err != nil || moved != 0 || len(pruneTestLocationPaths(t, db, child)) != 2 {
				t.Fatalf("conflicting edge was discarded: moved=%d %v", moved, err)
			}
			sample, err := db.SampleBySHA256(ctx, child)
			if err != nil || sample.Path != oldPath || sample.Parent != parent {
				t.Fatalf("primary changed on conflicting rebase: %+v %v", sample, err)
			}
		})
	}
}
