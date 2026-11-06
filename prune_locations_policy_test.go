package hopper

import (
	"fmt"
	"strings"
	"testing"
)

func TestPruneLocationLabelPolicy(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			parent := hexSHA(5100)
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: "good/archive", Label: "good"})
			shas := map[string]string{}
			for i, label := range []string{"good", "unknown", "bad", "sighted"} {
				sha := hexSHA(5101 + i)
				shas[label] = sha
				mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: "good/archive!!" + label, Parent: parent, Label: label})
				count := 600
				if label == "good" {
					count = 300
				}
				seedPruneOccurrences(t, db, sha, parent, "good/archive", count)
			}
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: shas["good"], Path: "good/physical"}); err != nil {
				t.Fatal(err)
			}
			opts := LocationPruneOptions{DataRoot: root, Phase: "cap", Batch: 100, PreviewRows: 10000, DryRun: true}
			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || preview.Scanned != 2106 || preview.Excess != 134 || preview.Labels.Good.Excess != 45 || preview.Labels.Unknown.Excess != 89 || preview.Labels.Bad.Excess != 0 || preview.Labels.Bad.Rows != 601 {
				t.Fatalf("preview: %+v labels=%+v %v", preview, preview.Labels, err)
			}
			opts.PreviewRows = 0
			opts.DryRun = false
			applied, err := db.PruneLocations(ctx, opts)
			if err != nil || applied.Deleted != 134 {
				t.Fatalf("apply: %+v %v", applied, err)
			}
			for label, want := range map[string]int{"good": 257, "unknown": 512, "bad": 601, "sighted": 601} {
				locs, err := db.LocationsForSHA(ctx, shas[label])
				if err != nil || len(locs) != want {
					t.Fatalf("%s retained=%d want=%d %v", label, len(locs), want, err)
				}
			}
			checkPruneLabelChanges(t, db, root, shas["good"], parent)
		})
	}
}

func checkPruneLabelChanges(t *testing.T, db *DB, root, sha, parent string) {
	t.Helper()
	ctx := t.Context()
	locs, err := db.LocationsForSHA(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	var victim pruneLocation
	for _, l := range locs {
		if strings.Contains(l.Path, "!!") && l.Path != "good/archive!!good" {
			victim = pruneLocation{ID: l.ID, SHA: sha, Path: l.Path, Parent: l.ParentSHA256, Rel: l.Rel}
			break
		}
	}
	if victim.ID == 0 {
		t.Fatal("no victim fixture")
	}
	opts := normalizeLocationCaps(LocationPruneOptions{})
	opts.MaxPaths = 256
	stats := LocationPruneStats{}
	checker := &pruneChecker{root: root, stats: &stats, cache: map[string]prunePresence{}}
	for _, label := range []string{"bad", "unknown", "sighted"} {
		execBoth(t, ctx, db, `UPDATE samples SET label=$1 WHERE sha256=$2`, label, sha)
		deleted, protected, err := db.deletePruneLocations(ctx, []pruneLocation{victim}, true, nil, checker, opts)
		if err != nil || deleted != 0 || protected != 1 {
			t.Fatalf("label changed to %s: deleted=%d protected=%d %v", label, deleted, protected, err)
		}
		// The old good/256 marker cannot suppress observations after a label change.
		path := "good/archive!!after-" + label
		if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, ParentSHA256: parent, Path: path}); err != nil {
			t.Fatal(err)
		}
		found := false
		rows, err := db.LocationsForSHA(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range rows {
			found = found || l.Path == path
		}
		if !found {
			t.Fatalf("old marker blocked new %s observation", label)
		}
	}
}

func TestPruneLocationPreviewWindow(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			parent := hexSHA(5200)
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: "good/archive", Label: "good"})
			for i, label := range []string{"good", "unknown"} {
				sha := hexSHA(5201 + i)
				mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: "good/archive!!" + label + "-0", Parent: parent, Label: label})
				for j := 1; j < 6; j++ {
					if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, ParentSHA256: parent, Path: fmt.Sprintf("good/archive!!%s-%d", label, j)}); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, kv := pruneTestCount(t, db, "sample_locations"), pruneTestCount(t, db, "hopper_kv")
			opts := LocationPruneOptions{DataRoot: root, Phase: "cap", Batch: 7, GoodMaxPaths: 2, UnknownMaxPaths: 3, PreviewRows: 10, DryRun: true}
			preview, err := db.PruneLocations(ctx, opts)
			if err != nil || !preview.Complete || preview.Scanned != 10 || preview.Excess != 4 || preview.Labels.Good.MemberLocations != 6 || preview.Labels.Unknown.MemberLocations != 3 || preview.Deleted != 0 || preview.StatCalls != 0 {
				t.Fatalf("window: %+v labels=%+v %v", preview, preview.Labels, err)
			}
			if pruneTestCount(t, db, "sample_locations") != before || pruneTestCount(t, db, "hopper_kv") != kv {
				t.Fatal("window modified the database")
			}
			opts.DryRun = false
			if _, err := db.PruneLocations(ctx, opts); err == nil {
				t.Fatal("bounded window allowed apply")
			}
			opts.DryRun = true
			opts.PreviewRows = 0
			full, err := db.PruneLocations(ctx, opts)
			if err != nil || full.Excess != 7 {
				t.Fatalf("unbounded preview: %+v %v", full, err)
			}
		})
	}
}
