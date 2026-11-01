package hopper

import (
	"fmt"
	"testing"
)

func TestBadSharedLocations(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			seed := func(id, count int, label, parent, skip string) string {
				sha := fmt.Sprintf("%064x", id)
				path := fmt.Sprintf("bad/%d/0", id)
				mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: path, Label: label, Parent: parent, Skip: skip})
				for i := range count {
					loc := &SampleLocation{SHA256: sha, Path: fmt.Sprintf("bad/%d/%d", id, i), ParentSHA256: parent}
					if err := db.UpsertLocation(ctx, loc); err != nil {
						t.Fatal(err)
					}
					// Repeat observations must not turn five paths into six locations.
					if err := db.UpsertLocation(ctx, loc); err != nil {
						t.Fatal(err)
					}
				}
				return sha
			}
			seed(1, 5, "bad", "", "")
			six := seed(2, 6, "bad", "", "")
			member := seed(3, 7, "bad", six, "")
			seed(4, 6, "good", "", "")
			seed(5, 6, "unknown", "", "")
			seed(6, 6, "bad", "", "conflict")
			q := TriageQueues["bad-shared"]
			got, err := q.Select(ctx, db, 10)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, s := range got {
				seen[s.SHA256] = true
			}
			if len(got) != 2 || !seen[six] || !seen[member] {
				t.Fatalf("selection: %v", seen)
			}
			if n, capped, err := q.Count(ctx, db); err != nil || n != 2 || capped {
				t.Fatalf("depth: %d %v %v", n, capped, err)
			}
			got, err = q.Select(ctx, db, 1, []string{six})
			if err != nil || len(got) != 1 || got[0].SHA256 != member {
				t.Fatalf("exclusion before limit: %v %v", got, err)
			}
			if err := db.InsertReport(ctx, &Report{SHA256: member, Type: "bad-shared", Content: "{}"}); err != nil {
				t.Fatal(err)
			}
			got, err = q.Select(ctx, db, 10)
			if err != nil || len(got) != 1 || got[0].SHA256 != six {
				t.Fatalf("review did not drain: %v %v", got, err)
			}
			if n, _, err := q.Count(ctx, db); err != nil || n != 1 {
				t.Fatalf("drained depth: %d %v", n, err)
			}
		})
	}
}
