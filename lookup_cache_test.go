package hopper

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLookupCacheWriteIsVisible(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "c1", Source: "test", PURLBase: "pkg:npm/left-pad", Version: "1.3.0"})
	if err := db.UpdateCleaveResult(ctx, "c1", []byte(`{"fs":[{"sha":"c1","type":"elf","dp":0}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, "c1", []byte(`{"v":"7","lvl":-1}`)); err != nil {
		t.Fatal(err)
	}

	first, err := db.SampleBySHA256(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if string(first.LitmusResult) != `{"v":"7","lvl":-1}` {
		t.Fatalf("first litmus = %s", first.LitmusResult)
	}
	first.LitmusResult = []byte(`mutated`)

	again, err := db.SampleBySHA256(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if string(again.LitmusResult) != `{"v":"7","lvl":-1}` {
		t.Fatalf("cached sample aliased caller mutation: %s", again.LitmusResult)
	}

	if err := db.UpdateLitmusResult(ctx, "c1", []byte(`{"v":"7","lvl":3}`)); err != nil {
		t.Fatal(err)
	}
	fresh, err := db.SampleBySHA256(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if string(fresh.LitmusResult) != `{"v":"7","lvl":3}` {
		t.Fatalf("write not visible through cache: %s", fresh.LitmusResult)
	}

	got, err := db.SampleByPURL(ctx, "pkg:npm/left-pad", "1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != "c1" {
		t.Fatalf("purl = %s, want c1", got.SHA256)
	}
}

func TestLookupCachePURLNewestInvalidates(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	analyze := func(sha, litmus string) {
		t.Helper()
		if err := db.UpdateCleaveResult(ctx, sha, []byte(`{"fs":[{"sha":"`+sha+`","type":"elf","dp":0}]}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(litmus)); err != nil {
			t.Fatal(err)
		}
	}

	mustInsert(t, ctx, db, &Sample{SHA256: "old", Source: "test", PURLBase: "pkg:npm/lodash", Version: "4.17.20"})
	analyze("old", `{"v":"7","lvl":-1}`)
	got, err := db.SampleByPURL(ctx, "pkg:npm/lodash", "")
	if err != nil || got.SHA256 != "old" {
		t.Fatalf("before: %v sha=%v", err, got)
	}

	time.Sleep(20 * time.Millisecond)
	mustInsert(t, ctx, db, &Sample{SHA256: "new", Source: "test", PURLBase: "pkg:npm/lodash", Version: "4.17.21"})
	analyze("new", `{"v":"7","lvl":-1}`)

	got, err = db.SampleByPURL(ctx, "pkg:npm/lodash", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != "new" {
		t.Fatalf("versionless after insert = %s, want new", got.SHA256)
	}
}

func TestLookupCacheSingleflight(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	mustInsert(t, ctx, db, &Sample{SHA256: "sf1", Source: "test"})
	if err := db.UpdateCleaveResult(ctx, "sf1", []byte(`{"fs":[{"sha":"sf1","type":"elf","dp":0}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}

	const n = 32
	var wg sync.WaitGroup
	errc := make(chan error, n)
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			s, err := db.SampleBySHA256(ctx, "sf1")
			if err != nil {
				errc <- err
				return
			}
			if s.SHA256 != "sf1" {
				errc <- fmt.Errorf("sha = %q", s.SHA256)
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestLookupCacheSkipsOversizedSamples locks the memory bound: the pool caps
// entry count, not bytes, so a sample whose analysis blobs exceed
// lookupEntryBytes is served but never retained. Without this a handful of
// large-archive lookups pins hundreds of megabytes for the pool's lifetime.
func TestLookupCacheSkipsOversizedSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	big := `{"fs":[{"sha":"big","type":"elf","dp":0,"pad":"` + strings.Repeat("x", lookupEntryBytes) + `"}]}`
	mustInsert(t, ctx, db, &Sample{SHA256: "big", Source: "test"})
	if err := db.UpdateCleaveResult(ctx, "big", []byte(big), nil, ""); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: "small", Source: "test"})
	if err := db.UpdateCleaveResult(ctx, "small", []byte(`{"fs":[{"sha":"small","type":"elf","dp":0}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}

	for _, sha := range []string{"big", "small"} {
		got, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("%s: %v", sha, err)
		}
		if got.SHA256 != sha {
			t.Fatalf("%s: sha = %q", sha, got.SHA256)
		}
	}
	if _, ok := db.lookup.Get(lookupSHAKey("big")); ok {
		t.Error("oversized sample retained in lookup cache")
	}
	if _, ok := db.lookup.Get(lookupSHAKey("small")); !ok {
		t.Error("small sample not cached")
	}
}

// TestLookupCacheForgetsUncachedSHA covers forgetSHA's sweep: when the sample's
// own key has aged out, the identity key still resolving to it must go too, or
// a write is invisible to the PURL lookup until the TTL expires.
func TestLookupCacheForgetsUncachedSHA(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "u1", Source: "test", PURLBase: "pkg:npm/uncached", Version: "1.0.0"})
	if err := db.UpdateCleaveResult(ctx, "u1", []byte(`{"fs":[{"sha":"u1","type":"elf","dp":0}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, "u1", []byte(`{"v":"7","lvl":-1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SampleByPURL(ctx, "pkg:npm/uncached", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	// Age out only the sha key, as the pool's eviction would.
	db.lookup.Delete(lookupSHAKey("u1"))

	if err := db.UpdateLitmusResult(ctx, "u1", []byte(`{"v":"7","lvl":3}`)); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleByPURL(ctx, "pkg:npm/uncached", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.LitmusResult) != `{"v":"7","lvl":3}` {
		t.Fatalf("stale purl entry survived the write: %s", got.LitmusResult)
	}
}
