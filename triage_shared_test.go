package hopper

import (
	"fmt"
	"strings"
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

// A shared sample behind many non-shared bad rows must still be reached. The
// location predicate and exclusions belong before LIMIT; the expensive sample
// metadata belongs after it. Check the real PostgreSQL planner as well as the
// result, since a correct selector can still time out on the global index.
func TestBadSharedCoveringPG(t *testing.T) {
	db := openDisposablePG(t)
	ctx := t.Context()
	_, err := db.pool.Exec(ctx, `INSERT INTO samples (sha256,path,label,created_at)
 SELECT lpad(to_hex(g),64,'0'), 'sample/' || g, CASE WHEN g % 32 = 0 THEN 'bad' ELSE 'unknown' END, now()-g*interval '1 second'
 FROM generate_series(1,160000) g`)
	if err != nil {
		t.Fatal(err)
	}
	sha := fmt.Sprintf("%064x", 160000)
	_, err = db.pool.Exec(ctx, `INSERT INTO sample_locations (sha256,path)
 SELECT $1, 'location/' || g FROM generate_series(1,6) g`, sha)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, "VACUUM ANALYZE samples"); err != nil {
		t.Fatal(err)
	}
	q := TriageQueues["bad-shared"]
	got, err := q.Select(ctx, db, 1)
	if err != nil || len(got) != 1 || got[0].SHA256 != sha {
		t.Fatalf("late shared candidate lost: got=%v err=%v", got, err)
	}
	got, err = q.Select(ctx, db, 1, []string{sha})
	if err != nil || len(got) != 0 {
		t.Fatalf("exclusion: got=%v err=%v", got, err)
	}
	extra, args := triageFilterClausePG(queueFilter("bad-shared", TriageFilter{}), 1, "samples")
	args = append(args, 64)
	rows, err := db.pool.Query(ctx, "EXPLAIN "+triageBadSharedSQL(extra, "$2"), args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "Index Only Scan using idx_samples_bad_shared_newest") {
		t.Fatalf("candidate walk is not covered:\n%s", plan.String())
	}
	t.Log(plan.String())
}
