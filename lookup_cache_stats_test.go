package hopper

import (
	"errors"
	"sync"
	"testing"
)

// A hit must be free: the loader is the only thing that touches the database,
// so "did not run" is the definition of "did not cost a query".
func TestLookupStatsSeparatesPoolFromDatabase(t *testing.T) {
	db := newDB()
	const sha = "a1b2c3"
	loads := 0
	load := func() (*Sample, error) {
		loads++
		return &Sample{SHA256: sha}, nil
	}

	for range 5 {
		if _, err := db.fetchSample(lookupSHAKey(sha),
			&db.lookupCounts.shaServed, &db.lookupCounts.shaLoaded, load); err != nil {
			t.Fatalf("fetchSample: %v", err)
		}
	}

	st := db.LookupStats()
	if loads != 1 {
		t.Errorf("loader ran %d times, want 1", loads)
	}
	if st.SHALoaded != 1 {
		t.Errorf("SHALoaded = %d, want 1", st.SHALoaded)
	}
	if st.SHAServed != 4 {
		t.Errorf("SHAServed = %d, want 4", st.SHAServed)
	}
	if st.PURLServed != 0 || st.PURLLoaded != 0 {
		t.Errorf("sha traffic leaked into the purl counters: %+v", st)
	}
	if st.Capacity != lookupCacheSize {
		t.Errorf("Capacity = %d, want %d", st.Capacity, lookupCacheSize)
	}
}

// A failed load must not be booked as served. It cost a query and returned
// nothing, so counting it as absorbed would flatter the pool in exactly the
// situation where the database is struggling.
func TestLookupStatsCountsFailedLoadsAgainstTheDatabase(t *testing.T) {
	db := newDB()
	boom := errors.New("connection refused")
	_, err := db.fetchSample(lookupSHAKey("dead"),
		&db.lookupCounts.shaServed, &db.lookupCounts.shaLoaded,
		func() (*Sample, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if st := db.LookupStats(); st.SHALoaded != 1 || st.SHAServed != 0 {
		t.Errorf("got %+v, want one load and no serve", st)
	}
}

// Concurrent misses coalesce onto one load. The waiters never reached the
// database, so they belong on the pool side of the split.
func TestLookupStatsCountsCoalescedWaitersAsServed(t *testing.T) {
	db := newDB()
	release := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := db.fetchSample(lookupPURLKey("pkg:npm/x", "1.0"),
				&db.lookupCounts.purlServed, &db.lookupCounts.purlLoaded,
				func() (*Sample, error) {
					<-release
					return &Sample{SHA256: "z"}, nil
				})
			errs <- err
		})
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("fetchSample: %v", err)
		}
	}

	st := db.LookupStats()
	if st.PURLLoaded != 1 {
		t.Errorf("PURLLoaded = %d, want 1 — the herd should share one query", st.PURLLoaded)
	}
	if got := st.PURLServed + st.PURLLoaded; got != 8 {
		t.Errorf("accounted for %d of 8 requests", got)
	}
}
