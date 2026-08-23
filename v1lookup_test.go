package hopper

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The corpus holds three eras of litmus_result and the shape scan serializes
// today is the rarest of them. Measured over 3000 analyzed rows: 83% flat, 13%
// pre-level, 5% nested. A parser written against scan's current output alone
// reads 5% of the corpus and reports the rest as having no level — which, for a
// caller gating installs, silently turns most of what we know into "unknown".
func TestLitmusSectionsReadsEveryStoredShape(t *testing.T) {
	lvl := func(v int) *int { return &v }

	for _, tc := range []struct {
		name    string
		stored  string
		firesAt *int
		eng     string
		why     string
	}{
		{
			name:    "flat is the bulk of the corpus",
			stored:  `{"v":"7","prob":0.9,"lvl":3,"conf":97,"analyzed_at":"2026-07-05T06:11:55Z","id":1,"type":"js"}`,
			firesAt: lvl(3),
			eng:     "",
		},
		{
			name:    "nested is what scan writes today",
			stored:  `{"ml":{"v":"7","lvl":25,"eng":"2.8.0","analyzed_at":"2026-08-01T00:00:00Z"},"llm":{"interpretation":"Reverse shell in postinstall"}}`,
			firesAt: lvl(25),
			eng:     "2.8.0",
			why:     "Reverse shell in postinstall",
		},
		{
			name:    "clean sentinel survives the trip",
			stored:  `{"v":"7","prob":0.01,"lvl":-1}`,
			firesAt: lvl(-1),
		},
		{
			// No level was ever recorded for these, so no caller's budget can be
			// evaluated against them. Reporting null is what makes scan answer
			// "unknown" rather than clearing an artifact nobody graded.
			name:    "pre-level records have no level to report",
			stored:  `{"v":"3","class":2,"prob":0.99,"thresholds":{"hostile":0.8},"analyzed_at":"2024-01-01T00:00:00Z"}`,
			firesAt: nil,
		},
		{
			name:    "unparseable is not a level either",
			stored:  `not json`,
			firesAt: nil,
		},
		{
			name:    "absent",
			stored:  ``,
			firesAt: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ml, llm := litmusSections([]byte(tc.stored))
			switch {
			case tc.firesAt == nil && ml.Lvl != nil:
				t.Fatalf("fires_at = %d, want null", *ml.Lvl)
			case tc.firesAt != nil && ml.Lvl == nil:
				t.Fatalf("fires_at = null, want %d", *tc.firesAt)
			case tc.firesAt != nil && *ml.Lvl != *tc.firesAt:
				t.Fatalf("fires_at = %d, want %d", *ml.Lvl, *tc.firesAt)
			}
			if ml.Eng != tc.eng {
				t.Errorf("engine_version = %q, want %q", ml.Eng, tc.eng)
			}
			if llm.Interpretation != tc.why {
				t.Errorf("reason = %q, want %q", llm.Interpretation, tc.why)
			}
		})
	}
}

// findings must never marshal as null: a caller would have to tell "no
// findings" from "this key was missing", and only one of those is true.
func TestFindingsAlwaysAList(t *testing.T) {
	for _, stored := range []string{"", "   ", "not json", "{}"} {
		got := findingsOf(stored)
		if got == nil {
			t.Fatalf("findingsOf(%q) is nil; must be an empty list", stored)
		}
		if len(got) != 0 {
			t.Fatalf("findingsOf(%q) = %v, want empty", stored, got)
		}
	}

	// Worst first, as the trigger writes them.
	got := findingsOf(`[{"id":"objectives/c2/backdoor","crit":5},{"id":"micro/eval","crit":4}]`)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].ID != "objectives/c2/backdoor" || got[0].Crit != 5 {
		t.Errorf("first finding = %+v", got[0])
	}
	if got[1].Crit != 4 {
		t.Errorf("second finding = %+v", got[1])
	}
}

// The reason the record pool exists. Beamline broadcasts a lookup to every scan
// worker, and each worker that misses its own index asks here — so one artifact
// arrives as N requests. They must cost one query, not N.
func TestLookupRecordCollapsesABroadcast(t *testing.T) {
	ctx := context.Background()
	db := mustTestDB(t, ctx)

	sha := strings.Repeat("a", 64)
	mustInsertAnalyzed(t, ctx, db, sha, "evil", "1.0.0")

	before := db.RecordCacheStats()
	const fleet = 8
	var wg sync.WaitGroup
	for range fleet {
		wg.Go(func() {
			if _, err := db.LookupRecord(ctx, sha, "", ""); err != nil {
				t.Errorf("LookupRecord: %v", err)
			}
		})
	}
	wg.Wait()

	loaded := db.RecordCacheStats().Loaded - before.Loaded
	if loaded != 1 {
		t.Errorf("a broadcast of %d cost %d loads, want 1", fleet, loaded)
	}
}

// Absence is the common answer for a caller gating installs on packages we have
// never seen, and it used to reach the database on every ask: single-flighting
// collapses simultaneous misses, but a miss repeated a second later is a fresh
// query. Caching it briefly is what absorbs a retrying client.
func TestLookupRecordCachesAbsenceBriefly(t *testing.T) {
	ctx := context.Background()
	db := mustTestDB(t, ctx)

	missing := strings.Repeat("b", 64)
	for range 3 {
		if _, err := db.LookupRecord(ctx, missing, "", ""); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	}
	if loaded := db.RecordCacheStats().Loaded; loaded != 1 {
		t.Errorf("three asks about one unknown artifact cost %d loads, want 1", loaded)
	}
}

// A cached absence must not outlive the analysis that answers it. The two pools
// answer the same question from the same row, so a write that forgets one has
// to forget the other or the record survives as a verdict that is no longer
// true — for as long as its TTL, which is measured in days.
func TestLookupRecordIsForgottenWhenTheSampleChanges(t *testing.T) {
	ctx := context.Background()
	db := mustTestDB(t, ctx)

	sha := strings.Repeat("c", 64)
	if err := db.InsertSample(ctx, &Sample{
		SHA256: sha, Path: "incoming/pending.tgz", Source: "forager",
		Ecosystem: "npm", Package: "pending", Version: "1.0.0", PURLBase: "pkg:npm/pending",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
	first, err := db.LookupRecord(ctx, sha, "", "")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if first.Analyzed {
		t.Fatal("a sample nothing has looked at reported itself analyzed")
	}

	if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","lvl":3,"eng":"2.8.0"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}

	after, err := db.LookupRecord(ctx, sha, "", "")
	if err != nil {
		t.Fatalf("LookupRecord after analysis: %v", err)
	}
	if !after.Analyzed {
		t.Fatal("the record still says unanalyzed after a verdict landed")
	}
	if after.FiresAt == nil || *after.FiresAt != 3 {
		t.Fatalf("fires_at = %v, want 3", after.FiresAt)
	}
}

func mustTestDB(t *testing.T, ctx context.Context) *DB {
	t.Helper()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "hopper.db"), "test")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func mustInsertAnalyzed(t *testing.T, ctx context.Context, db *DB, sha, name, version string) {
	t.Helper()
	if err := db.InsertSample(ctx, &Sample{
		SHA256: sha, Path: "incoming/" + name + ".tgz", Source: "forager",
		Ecosystem: "npm", Package: name, Version: version,
		PURLBase: "pkg:npm/" + name,
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
	if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","lvl":3,"eng":"2.8.0"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}
}

// A process reading the logical replica never executes a write path, so nothing
// in it ever calls forgetSHA: the TTL is not a backstop there, it is the only
// bound there is. It must therefore be short enough to answer "how long may a
// re-analysed package keep serving its previous verdict" — and a scan fleet
// reads the replica first, so that answer is what they see.
func TestReplicaRecordsAgeOutFarSoonerThanThePrimarysDo(t *testing.T) {
	if replicaRecordTTL >= recordTTL {
		t.Fatalf("replica TTL %v is not shorter than the primary's %v", replicaRecordTTL, recordTTL)
	}
	if replicaRecordTTL > time.Hour {
		t.Errorf("replica TTL is %v; a stale verdict on the read path should be minutes, not hours", replicaRecordTTL)
	}
}

// Switching to replica mode must not lose the pool's identity as a pool: a
// process that ends up with no records cache answers every lookup from the
// database, which is the load this exists to prevent.
func TestServesReplicaKeepsTheRecordPool(t *testing.T) {
	ctx := context.Background()
	db := mustTestDB(t, ctx)
	db.ServesReplica()

	sha := strings.Repeat("d", 64)
	mustInsertAnalyzed(t, ctx, db, sha, "still-cached", "1.0.0")

	for range 3 {
		if _, err := db.LookupRecord(ctx, sha, "", ""); err != nil {
			t.Fatalf("LookupRecord: %v", err)
		}
	}
	if loaded := db.RecordCacheStats().Loaded; loaded != 1 {
		t.Errorf("three lookups cost %d loads on a replica, want 1", loaded)
	}
}
