package hopper

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPrunePreservesChangedObservation(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			parent, child := hexSHA(6600), hexSHA(6601)
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: "good/p.tgz", Label: "good"})
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: "good/p.tgz!!kept", Parent: parent, Label: "good"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: child, ParentSHA256: parent, Path: "good/p.tgz!!changed"}); err != nil {
				t.Fatal(err)
			}
			locs, err := db.LocationsForSHA(ctx, child)
			if err != nil {
				t.Fatal(err)
			}
			var observed pruneLocation
			var unchanged pruneLocation
			for _, l := range locs {
				if l.Path == "good/p.tgz!!changed" {
					observed = pruneLocation{ID: l.ID, SHA: l.SHA256, Path: l.Path, Parent: l.ParentSHA256, Rel: l.Rel}
				} else {
					unchanged = pruneLocation{ID: l.ID, SHA: l.SHA256, Path: l.Path, Parent: l.ParentSHA256, Rel: l.Rel}
				}
			}
			if observed.ID == 0 {
				t.Fatal("missing observation fixture")
			}
			execBoth(t, ctx, db, `UPDATE sample_locations SET rel=$1 WHERE id=$2`, string(RelUnpacked), observed.ID)
			checker := &pruneChecker{root: t.TempDir(), stats: &LocationPruneStats{}, cache: map[string]prunePresence{}}
			deleted, protected, err := db.deletePruneLocations(ctx, []pruneLocation{observed}, checker)
			if err != nil || deleted != 0 || protected != 1 {
				t.Fatalf("changed edge deleted: deleted=%d protected=%d %v", deleted, protected, err)
			}
			moved, err := db.rebasePruneLocations(ctx, []pruneRebase{{loc: observed, newPath: "good/new.tgz!!changed"}})
			if err != nil || moved != 0 {
				t.Fatalf("changed edge rebased: %d %v", moved, err)
			}
			if paths := pruneTestLocationPaths(t, db, child); len(paths) != 2 || !paths[observed.Path] {
				t.Fatalf("changed relationship lost: %+v", paths)
			}
			moved, err = db.rebasePruneLocations(ctx, []pruneRebase{
				{loc: observed, newPath: "good/new.tgz!!changed"},
				{loc: unchanged, newPath: "good/new.tgz!!kept"},
			})
			if err != nil || moved != 1 {
				t.Fatalf("mixed changed/unchanged rebase: %d %v", moved, err)
			}
			if paths := pruneTestLocationPaths(t, db, child); len(paths) != 2 || !paths[observed.Path] || !paths["good/new.tgz!!kept"] {
				t.Fatalf("mixed rebase lost an edge: %+v", paths)
			}
		})
	}
}

func TestPruneSurvivorCannotChangeBeforeCommit(t *testing.T) {
	db := openDisposablePG(t)
	ctx := t.Context()
	parent, child := hexSHA(6700), hexSHA(6701)
	mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: "good/p.tgz", Label: "good"})
	mustInsert(t, ctx, db, &Sample{SHA256: child, Path: "good/p.tgz!!kept", Parent: parent, Label: "good"})
	if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: child, Path: "good/p.tgz!!victim", ParentSHA256: parent}); err != nil {
		t.Fatal(err)
	}
	locs, err := db.LocationsForSHA(ctx, child)
	if err != nil {
		t.Fatal(err)
	}
	var victim pruneLocation
	var keeperID int64
	for _, l := range locs {
		if l.Path == "good/p.tgz!!victim" {
			victim = pruneLocation{ID: l.ID, SHA: l.SHA256, Path: l.Path, Parent: l.ParentSHA256, Rel: l.Rel}
		} else {
			keeperID = l.ID
		}
	}
	other, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	if _, err := other.Exec(ctx, `SET lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	err = db.locationTransaction(ctx, func(tx locationSQLTx) error {
		eligible, protected, err := protectPruneRelationships(tx, []pruneLocation{victim}, true)
		if err != nil {
			return err
		}
		if len(eligible) != 1 || protected != 0 {
			t.Fatalf("survivor not found: %+v %d", eligible, protected)
		}
		_, err = other.Exec(ctx, `UPDATE sample_locations SET rel='unpacked' WHERE id=$1`, keeperID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Fatalf("surviving relation changed during prune: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
