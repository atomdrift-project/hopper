package hopper

import (
	"context"
	"testing"
)

// TestTriageQueueRegistryIsWellFormed guards the registry's own invariants. The
// map key is the wire name — it is what a client asks for, what the drain
// reports are typed with, and what the triage SQL matches literally — so a
// Name that disagrees with its key would route one queue's work through another
// queue's drain.
func TestTriageQueueRegistryIsWellFormed(t *testing.T) {
	if len(TriageQueues) == 0 {
		t.Fatal("registry is empty")
	}
	for key, q := range TriageQueues {
		if q.Name != key {
			t.Errorf("queue %q has Name %q — the key is the wire name and they must agree", key, q.Name)
		}
		if q.Select == nil {
			t.Errorf("queue %q has no Select", key)
		}
		if key == "queues" {
			t.Errorf(`a queue named "queues" is unreachable: GET /api/triage/queues is the registry route`)
		}
	}

	names := TriageQueueNames()
	if len(names) != len(TriageQueues) {
		t.Fatalf("TriageQueueNames returned %d names, registry has %d", len(names), len(TriageQueues))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("TriageQueueNames is not sorted: %q before %q", names[i-1], names[i])
		}
	}
}

// TestTriageQueuesRunAgainstASchema executes every registered selector and depth
// against an empty database. It proves each one is wired to SQL that parses and
// binds — a typo in a predicate or a wrong argument count would otherwise only
// surface when that queue was next selected in production, which for the rarer
// queues can be a long time.
func TestTriageQueuesRunAgainstASchema(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	for _, name := range TriageQueueNames() {
		q := TriageQueues[name]
		t.Run(name, func(t *testing.T) {
			got, err := q.Select(ctx, db, 5)
			if err != nil {
				t.Fatalf("Select: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("Select returned %d rows from an empty database", len(got))
			}
			if q.Depth == nil {
				return
			}
			depth, err := q.Depth(ctx, db)
			if err != nil {
				t.Fatalf("Depth: %v", err)
			}
			if depth != 0 {
				t.Errorf("Depth = %d on an empty database", depth)
			}
		})
	}
}

// TestStaleTriageFilterDrainsPerQueue pins the property the -stale and popular
// queues depend on: each excludes a report type named for itself, so a completed
// judgement parks that sample for that queue only. Sharing one drain type across
// them would let one queue's work silently drain another's.
func TestStaleTriageFilterDrainsPerQueue(t *testing.T) {
	for _, queue := range []string{"popular", "new-stale", "good-stale"} {
		f := staleTriageFilter(queue)
		if f.ExcludeReportType != queue {
			t.Errorf("staleTriageFilter(%q).ExcludeReportType = %q, want %q", queue, f.ExcludeReportType, queue)
		}
		if f.Order != TriageStale {
			t.Errorf("staleTriageFilter(%q).Order = %v, want TriageStale", queue, f.Order)
		}
	}
}

// TestTriagePopularNeedsPopularPackages documents the failure mode that made
// popular_packages a published table: the queue gates on the marker set, so an
// empty one reads as a permanently drained queue rather than as an error. On a
// logical replica an unpublished table is exactly that — present, and empty.
func TestTriagePopularNeedsPopularPackages(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const sha = "1111111111111111111111111111111111111111111111111111111111111111"
	mustInsert(t, ctx, db, &Sample{
		SHA256: sha, Label: "unknown", Path: "incoming/forager/a.tgz",
		PURLBase: "pkg:npm/left-pad",
	})
	// popular selects on max_crit >= 5 since 2026-09-01 -- a merely
	// suspicious finding on a popular package is not what the fleet stands
	// down for -- so the fixture seeds a hostile trait.
	mustAnalyzeWithTraits(t, ctx, db, sha, 0, `{"l":5}`)

	got, err := TriageQueues["popular"].Select(ctx, db, 5)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("popular returned %d rows with no popular_packages marker", len(got))
	}

	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/left-pad", Ecosystem: "npm", Source: "test", Rank: 1},
	}); err != nil {
		t.Fatalf("SetPopularPackages: %v", err)
	}
	got, err = TriageQueues["popular"].Select(ctx, db, 5)
	if err != nil {
		t.Fatalf("Select after marking: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("popular returned %d rows after marking the package, want 1", len(got))
	}
	if got[0].SHA256 != sha {
		t.Errorf("popular returned %s, want %s", got[0].SHA256, sha)
	}
}
