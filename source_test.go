package hopper

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSourceSurvivesResultRefreshAndReingest(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			checkSourceSurvivesResultRefreshAndReingest(t, db)
		})
	}
}

func checkSourceSurvivesResultRefreshAndReingest(t *testing.T, db *DB) {
	t.Helper()
	ctx := t.Context()
	archive := strings.Repeat("a", 64)
	member := strings.Repeat("b", 64)
	archivePath := "incoming/forager/archive.tgz"
	memberPath := archivePath + "!!pkg/index.js"
	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: archivePath, Source: "forager"})
	mustInsert(t, ctx, db, &Sample{
		SHA256: member, Path: memberPath, Parent: archive, Source: "forager",
	})
	check := func(stage string) {
		t.Helper()
		for _, sha := range []string{archive, member} {
			sample, err := db.sampleBySHA256Uncached(ctx, sha)
			if err != nil {
				t.Fatal(err)
			}
			if sample.Source != "forager" {
				t.Errorf("%s: sample %s source = %q, want forager", stage, sha, sample.Source)
			}
			locs, err := db.LocationsForSHA(ctx, sha)
			if err != nil {
				t.Fatal(err)
			}
			if len(locs) != 1 {
				t.Fatalf("%s: locations = %d, want 1", stage, len(locs))
			}
			if locs[0].Source != "forager" {
				t.Errorf("%s: location %s source = %q, want forager", stage, sha, locs[0].Source)
			}
		}
	}
	for _, version := range []string{"rev1", "rev2"} {
		envelope := fmt.Appendf(nil, `{"v":8,"rev":%q,"files":[
			{"id":0,"sha":%q,"type":"tar","depth":0,"path":"archive.tgz"},
			{"id":1,"pid":0,"sha":%q,"type":"javascript","depth":1,"path":"archive.tgz!!pkg/index.js"}
		]}`, version, archive, member)
		if _, err := db.StoreResult(ctx, archive, envelope, nil, nil, nil, version, ResultAttribution{}); err != nil {
			t.Fatal(err)
		}
		check(version)
		got, err := db.sampleBySHA256Uncached(ctx, member)
		if err != nil {
			t.Fatal(err)
		}
		if got.TraitsVersion != version {
			t.Fatalf("member traits version = %q, want %q", got.TraitsVersion, version)
		}
	}
	if err := db.UpdateCleaveResult(ctx, member, fmt.Appendf(nil,
		`{"v":8,"files":[{"sha":%q,"type":"javascript","depth":0}]}`, member), nil, "rev3"); err != nil {
		t.Fatal(err)
	}
	check("cleave write-back")

	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: archivePath, Source: SourceFilesystem})
	check("single reingest")
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{
		{SHA256: archive, Path: archivePath, Source: SourceFilesystem},
		{SHA256: member, Path: memberPath, Parent: archive, Source: SourceExploded},
	}); err != nil {
		t.Fatal(err)
	}
	check("batch reingest")
	if err := db.UpsertLocationBatch(ctx, []*SampleLocation{
		{SHA256: member, Path: memberPath, ParentSHA256: archive, Source: SourceExploded, Feed: "updated-feed"},
	}); err != nil {
		t.Fatal(err)
	}
	check("batch location update")
	// Updating another field must also leave the original source intact.
	mtime := time.Now().UTC()
	mustInsert(t, ctx, db, &Sample{
		SHA256: archive, Path: archivePath, Source: SourceFilesystem, Mtime: &mtime,
	})
	check("metadata update")

	// Sources belong to observations: a new path records its own producer.
	newPath := "good/archive.tgz"
	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: newPath, Source: SourceFilesystem})
	locs, err := db.LocationsForSHA(ctx, archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Fatalf("new path: locations = %d, want 2", len(locs))
	}
	for _, loc := range locs {
		want := "forager"
		if loc.Path == newPath {
			want = SourceFilesystem
		}
		if loc.Source != want {
			t.Errorf("%s: source = %q, want %q", loc.Path, loc.Source, want)
		}
	}
}

func TestLocationSourceFillsWhenUnknown(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			sha := strings.Repeat("c", 64)
			path := "incoming/sample.bin"
			mustInsert(t, t.Context(), db, &Sample{SHA256: sha, Path: path})
			for _, source := range []string{"forager", SourceFilesystem, ""} {
				mustInsert(t, t.Context(), db, &Sample{SHA256: sha, Path: path, Source: source})
				locs, err := db.LocationsForSHA(t.Context(), sha)
				if err != nil {
					t.Fatal(err)
				}
				if len(locs) != 1 || locs[0].Source != "forager" {
					t.Fatalf("source %q: locations = %+v, want original source forager", source, locs)
				}
			}
		})
	}
}
