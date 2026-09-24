package hopper

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestRecordProjectionMatchesFullRow pins the light record projection to the
// full-row path it replaced: whatever columns recordOf reads, the projection
// must carry, or a lookup silently starts answering null for them. Runs on
// SQLite always and on Postgres when HOPPER_TEST_PG_DSN is set.
func TestRecordProjectionMatchesFullRow(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { checkRecordProjection(t, openTestDB(t)) })
	t.Run("postgres", func(t *testing.T) { checkRecordProjection(t, openDisposablePG(t)) })
}

func checkRecordProjection(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()
	analyzed := strings.Repeat("d", 64)
	held := strings.Repeat("e", 64)
	mustInsert(t, ctx, db, &Sample{
		SHA256: analyzed, Source: "forager", Ecosystem: "npm", Package: "proj", Version: "1.2.3",
		PURLBase: "pkg:npm/proj",
	})
	mustInsert(t, ctx, db, &Sample{SHA256: held, Source: "forager"})
	if err := db.UpdateCleaveResult(ctx, analyzed,
		[]byte(`{"fs":[{"sha":"`+analyzed+`","type":"js","dp":0,"finds":[{"id":"objectives/c2/backdoor","crit":5}]}]}`),
		nil, "abcde"); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
	if err := db.UpdateLitmusResult(ctx, analyzed,
		[]byte(`{"v":"7","prob":0.9,"lvl":3,"eng":"2.8.0","analyzed_at":"2026-08-01T00:00:00Z"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}
	if err := db.UpdateLLMResult(ctx, analyzed, []byte(`{"interpretation":"beacons home"}`)); err != nil {
		t.Fatalf("UpdateLLMResult: %v", err)
	}

	for _, sha := range []string{analyzed, held} {
		full, err := db.sampleBySHA256Uncached(ctx, sha)
		if err != nil {
			t.Fatalf("full row %s: %v", sha[:1], err)
		}
		light, err := db.recordSampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("projection %s: %v", sha[:1], err)
		}
		if want, got := recordOf(full), recordOf(light); !reflect.DeepEqual(want, got) {
			t.Errorf("sha %s: projection renders %+v, full row renders %+v", sha[:1], got, want)
		}
		if light.Corroborated != full.Corroborated {
			t.Errorf("sha %s: corroborated = %v, full row %v", sha[:1], light.Corroborated, full.Corroborated)
		}
	}

	full, err := db.sampleByPURLUncached(ctx, "pkg:npm/proj", "1.2.3")
	if err != nil {
		t.Fatalf("full row by purl: %v", err)
	}
	light, err := db.recordSampleByPURL(ctx, "pkg:npm/proj", "1.2.3")
	if err != nil {
		t.Fatalf("projection by purl: %v", err)
	}
	if want, got := recordOf(full), recordOf(light); !reflect.DeepEqual(want, got) {
		t.Errorf("purl: projection renders %+v, full row renders %+v", got, want)
	}
	if _, err := db.recordSampleByPURL(ctx, "pkg:npm/proj", "9.9.9"); err != ErrNotFound {
		t.Errorf("unknown version: err = %v, want ErrNotFound", err)
	}
}

// A record cached under a PURL key is reachable from a write only through the
// digest it names. The pool used to be swept for it on every write (59% of
// hopper's CPU); the index must still find it, or a re-analysed package keeps
// its previous verdict for recordTTL — a week.
func TestLookupRecordUnderPURLIsForgottenOnWrite(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	sha := strings.Repeat("f", 64)
	mustInsert(t, ctx, db, &Sample{
		SHA256: sha, Source: "forager", Ecosystem: "npm", Package: "idx", Version: "1.0.0",
		PURLBase: "pkg:npm/idx",
	})
	if err := db.UpdateCleaveResult(ctx, sha, []byte(`{"fs":[{"sha":"`+sha+`","type":"js","dp":0}]}`), nil, "abcde"); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
	if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","lvl":3,"eng":"2.8.0"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}

	first, err := db.LookupRecord(ctx, "", "pkg:npm/idx", "1.0.0")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if first.FiresAt == nil || *first.FiresAt != 3 {
		t.Fatalf("fires_at = %v, want 3", first.FiresAt)
	}
	// The sample pool holds nothing for this digest (the record path never
	// fills it), which is exactly when only the index can reach the PURL key.
	if _, ok := db.lookup.Get(lookupSHAKey(sha)); ok {
		t.Fatal("precondition: the sample pool should not hold the row")
	}

	if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","lvl":-1,"eng":"2.9.0"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}
	after, err := db.LookupRecord(ctx, "", "pkg:npm/idx", "1.0.0")
	if err != nil {
		t.Fatalf("LookupRecord after write: %v", err)
	}
	if after.FiresAt == nil {
		t.Fatal("PURL record lost its fires_at after the write")
	}
	if *after.FiresAt != -1 {
		t.Fatalf("PURL record still serves fires_at=%d after the verdict changed to -1", *after.FiresAt)
	}
}

func TestRecordIndexPruneKeepsLiveAndFreshEntries(t *testing.T) {
	pool := newRecordCache()
	ix := newRecordIndex()
	live, gone, fresh := "p:live", "p:gone", "p:fresh"
	sha := strings.Repeat("a", 64)
	pool.Set(live, &cachedRecord{record: &LookupRecord{SHA256: &sha}})

	old := time.Now().Add(-2 * recordIndexMinAge)
	ix.bySHA[sha] = map[string]time.Time{live: old, gone: old, fresh: time.Now()}
	ix.n = 3
	ix.mu.Lock()
	ix.pruneLocked(pool)
	ix.mu.Unlock()

	got := ix.take(map[string]struct{}{sha: {}})
	slices.Sort(got)
	if want := []string{fresh, live}; !slices.Equal(got, want) {
		t.Errorf("after prune the index holds %v, want %v (evicted dropped; live and just-indexed kept)", got, want)
	}
	if ix.n != 0 {
		t.Errorf("entry count = %d after taking everything, want 0", ix.n)
	}
}
