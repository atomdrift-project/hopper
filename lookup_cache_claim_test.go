package hopper

import (
	"context"
	"testing"
)

// A claim must not touch the lookup cache.
//
// attempts and claimed_first_at are claim bookkeeping: no lookup response
// carries either — Sample has no such field — so a bump cannot make a cached
// entry wrong. MarkClaimHandout already treats claimed_first_at this way;
// IncrementAttempts was the outlier, and an expensive one. It ran forgetSHAs
// on every batch /api/next hands out, which for each sha takes the pool's
// writer lock to drop its key and then, for any sha that was not itself
// cached, scans the whole pool looking for purl keys to match — all on the
// hottest path in the server, against a reader-biased lock whose writers must
// drain every reader slot. On 2026-09-22 that convoy stalled /v1/lookup
// fleet-wide while the database sat idle.
//
// The rescan tiers claim samples that are already analyzed and therefore
// already cached, which is the case this pins: the claim must leave both of
// that sample's keys serving.
func TestIncrementAttemptsDoesNotEvictLookupCache(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	mustInsert(t, ctx, db, &Sample{
		SHA256: "r1", Source: "test", PURLBase: "pkg:npm/rescanned", Version: "1.0.0",
	})
	if err := db.UpdateCleaveResult(ctx, "r1",
		[]byte(`{"fs":[{"sha":"r1","type":"elf","dp":0}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, "r1", []byte(`{"v":"7","lvl":-1}`)); err != nil {
		t.Fatal(err)
	}

	// Warm both keyspaces; each costs exactly one load.
	if _, err := db.SampleBySHA256(ctx, "r1"); err != nil {
		t.Fatalf("warm sha: %v", err)
	}
	if _, err := db.SampleByPURL(ctx, "pkg:npm/rescanned", "1.0.0"); err != nil {
		t.Fatalf("warm purl: %v", err)
	}
	warm := db.LookupStats()

	if err := db.IncrementAttempts(ctx, []string{"r1"}); err != nil {
		t.Fatalf("IncrementAttempts: %v", err)
	}

	if _, err := db.SampleBySHA256(ctx, "r1"); err != nil {
		t.Fatalf("sha after claim: %v", err)
	}
	if _, err := db.SampleByPURL(ctx, "pkg:npm/rescanned", "1.0.0"); err != nil {
		t.Fatalf("purl after claim: %v", err)
	}
	got := db.LookupStats()

	if got.SHALoaded != warm.SHALoaded {
		t.Errorf("claim dropped the sha entry: SHALoaded %d -> %d, want unchanged",
			warm.SHALoaded, got.SHALoaded)
	}
	if got.PURLLoaded != warm.PURLLoaded {
		t.Errorf("claim dropped the purl entry: PURLLoaded %d -> %d, want unchanged",
			warm.PURLLoaded, got.PURLLoaded)
	}

	// The bump itself must still happen: ReapStuck reads this column to retire
	// poison samples, so a cache-shaped fix that quietly stopped counting
	// attempts would trade one outage for another.
	var attempts int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT attempts FROM samples WHERE sha256 = ?`, "r1").Scan(&attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}
