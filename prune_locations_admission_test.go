package hopper

import (
	"fmt"
	"testing"
)

// Old cap markers must have no effect on any ingestion entry point. A new
// occurrence under an existing parent matters even when the SHA has many paths.
func TestPruneLocationsRetainsAllLiveOccurrences(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			parent, child := hexSHA(6800), hexSHA(6801)
			const archive = "good/archive.tgz"
			writeDedupeFile(t, root, archive, []byte("live archive"))
			mustInsert(t, ctx, db, &Sample{SHA256: parent, Path: archive, Label: "good"})
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: archive + "!!member-000.js", Parent: parent, Label: "good"})
			seedPruneOccurrences(t, db, child, parent, archive, 600)

			writers := []struct {
				name  string
				write func(*Sample) error
			}{
				{"single", func(s *Sample) error { return db.InsertSample(ctx, s) }},
				{"batch", func(s *Sample) error {
					_, _, err := db.InsertSampleBatch(ctx, []*Sample{s})
					return err
				}},
				{"location", func(s *Sample) error {
					return db.UpsertLocation(ctx, &SampleLocation{SHA256: s.SHA256, Path: s.Path, ParentSHA256: s.Parent})
				}},
				{"locations", func(s *Sample) error {
					return db.UpsertLocationBatch(ctx, []*SampleLocation{{SHA256: s.SHA256, Path: s.Path, ParentSHA256: s.Parent}})
				}},
				{"result", func(s *Sample) error {
					envelope := fmt.Appendf(nil, `{"v":8,"files":[
						{"id":0,"sha":%q,"type":"tar","depth":0,"path":"archive.tgz"},
						{"id":1,"pid":0,"sha":%q,"type":"javascript","depth":1,"path":"archive.tgz!!result.js"}
					]}`, parent, s.SHA256)
					_, err := db.StoreResult(ctx, parent, envelope, nil, nil, nil, "uncapped", ResultAttribution{})
					return err
				}},
			}
			for _, writer := range writers {
				// Match the old active marker format, rather than using a stale
				// generation that the old policy would already have ignored.
				execBoth(t, ctx, db, `INSERT INTO hopper_kv(key,value)
 SELECT $1,CAST(id AS TEXT)||'/'||label FROM samples WHERE sha256=$2
 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "location-member-cap/"+child, child)
				path := archive + "!!" + writer.name + ".js"
				if err := writer.write(&Sample{SHA256: child, Path: path, Parent: parent, Label: "good"}); err != nil {
					t.Fatalf("%s: %v", writer.name, err)
				}
				if !pruneTestLocationPaths(t, db, child)[path] {
					t.Fatalf("%s suppressed a valid occurrence", writer.name)
				}
			}
			other := hexSHA(6802)
			const otherPath = "good/other.tgz"
			writeDedupeFile(t, root, otherPath, []byte("another live archive"))
			mustInsert(t, ctx, db, &Sample{SHA256: other, Path: otherPath, Label: "good"})
			if err := db.UpsertLocationBatch(ctx, []*SampleLocation{
				{SHA256: child, ParentSHA256: other, Path: otherPath + "!!child.js"},
				{SHA256: child, ParentSHA256: parent, Path: archive + "!!unpacked.js", Rel: string(RelUnpacked)},
			}); err != nil {
				t.Fatal(err)
			}
			checkPruneLiveOccurrences(t, db, root, child, 602+len(writers))
		})
	}
}

func checkPruneLiveOccurrences(t *testing.T, db *DB, root, child string, count int) {
	t.Helper()
	ctx := t.Context()
	// Exercise the default phase and both formerly capped labels. Repeated
	// passes must retain every occurrence, including distinct parent/type edges.
	for _, label := range []string{"good", "unknown"} {
		execBoth(t, ctx, db, `UPDATE samples SET label=$1 WHERE sha256=$2`, label, child)
		for _, dry := range []bool{true, false} {
			opts := LocationPruneOptions{DataRoot: root, Batch: 100, DryRun: dry}
			stats, err := db.PruneLocations(ctx, opts)
			if err != nil || !stats.Complete || stats.Obsolete != 0 || stats.Deleted != 0 || stats.Rebased != 0 {
				t.Fatalf("label=%s dry=%v: %+v %v", label, dry, stats, err)
			}
			if got := len(pruneTestLocationPaths(t, db, child)); got != count {
				t.Fatalf("label=%s dry=%v retained %d occurrences, want %d", label, dry, got, count)
			}
		}
	}
}
