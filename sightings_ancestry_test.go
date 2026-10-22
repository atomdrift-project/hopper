package hopper

import (
	"errors"
	"strings"
	"testing"
)

func TestSightingsInAncestryChecksAlternateParentsAndGrandparents(t *testing.T) {
	db := openTestDB(t)
	root, clean, parent, grand := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	for _, sha := range []string{root, clean, parent, grand} {
		mustInsert(t, t.Context(), db, &Sample{SHA256: sha, Label: "good"})
	}
	for _, edge := range [][2]string{{root, clean}, {root, parent}, {parent, grand}, {grand, root}} {
		if _, err := db.lite.ExecContext(t.Context(), `INSERT INTO sample_locations (sha256,path,parent_sha256) VALUES (?,?,?)`, edge[0], "test/"+edge[1]+"!!"+edge[0], edge[1]); err != nil {
			t.Fatal(err)
		}
	}
	checked, err := db.SightingsInAncestry(t.Context(), root)
	if err != nil || !checked.Checked || len(checked.Sightings) != 0 {
		t.Fatalf("clear cyclic ancestry = %+v, %v", checked, err)
	}
	addSightings(t, db, Sighting{Source: "triage", Subject: grand, Claim: ClaimMalicious})
	blocked, err := db.SightingsInAncestry(t.Context(), root)
	if err != nil || !blocked.Checked || len(blocked.Sightings) != 1 || blocked.Sightings[0].SHA256 != grand {
		t.Fatalf("grandparent sighting = %+v, %v", blocked, err)
	}
}

func TestSightingsInAncestryHonorsPackageVersionsAndPrimaryParent(t *testing.T) {
	db := openTestDB(t)
	root, parent := strings.Repeat("a", 64), strings.Repeat("b", 64)
	mustInsert(t, t.Context(), db, &Sample{SHA256: root, Label: "good"})
	mustInsert(t, t.Context(), db, &Sample{SHA256: parent, Label: "good"})
	if _, err := db.lite.ExecContext(t.Context(), `UPDATE samples SET parent=? WHERE sha256=?`, parent, root); err != nil {
		t.Fatal(err)
	}
	if _, err := db.lite.ExecContext(t.Context(), `UPDATE samples SET purl_base='pkg:npm/example',version='2.0' WHERE sha256=?`, parent); err != nil {
		t.Fatal(err)
	}
	addSightings(t, db, Sighting{Source: "osv", Subject: "pkg:npm/example", Affected: "1.0", Claim: ClaimMalicious})
	checked, err := db.SightingsInAncestry(t.Context(), root)
	if err != nil || len(checked.Sightings) != 0 {
		t.Fatalf("unaffected parent release = %+v, %v", checked, err)
	}
	addSightings(t, db, Sighting{Source: "osv", Subject: "pkg:npm/example", Affected: "*", Claim: ClaimMalicious})
	blocked, err := db.SightingsInAncestry(t.Context(), root)
	if err != nil || len(blocked.Sightings) != 1 || blocked.Sightings[0].SHA256 != parent {
		t.Fatalf("affected primary parent = %+v, %v", blocked, err)
	}
}

func TestSightingsInAncestryUnknownNodesNeverClear(t *testing.T) {
	db := openTestDB(t)
	root, parent := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := db.SightingsInAncestry(t.Context(), root); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown root = %v", err)
	}
	mustInsert(t, t.Context(), db, &Sample{SHA256: root, Label: "good"})
	if _, err := db.lite.ExecContext(t.Context(), `UPDATE samples SET parent=? WHERE sha256=?`, parent, root); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SightingsInAncestry(t.Context(), root); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown parent = %v", err)
	}
}
