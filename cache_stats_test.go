package hopper

import (
	"testing"
	"time"
)

func TestCacheMemoryStatistics(t *testing.T) {
	db := newDB()
	db.lookup.Set("s:test", &Sample{SHA256: "test", CleaveResult: make([]byte, 10, 100)})
	sha := "test"
	db.records.Set("s:test", &cachedRecord{record: &LookupRecord{SHA256: &sha, Findings: []LookupFinding{{ID: "id", Desc: "description"}}}})
	db.lookupCounts.shaServed.Store(7)
	db.lookupCounts.shaLoaded.Store(3)
	db.recordCounts.served.Store(9)
	db.recordCounts.loaded.Store(1)
	now := time.Now()
	db.cacheMemoryAttempt.Store(now.Unix())
	db.refreshCacheMemory(now)
	s := db.CacheStatistics()
	if len(s) != 2 || s[0].Entries != 1 || s[1].Entries != 1 || s[0].Served != 7 || s[1].Loaded != 1 {
		t.Fatalf("bad cache statistics: %+v", s)
	}
	for _, c := range s {
		if c.MemoryBytes == 0 || !c.MemorySampledAt.Equal(now) {
			t.Fatalf("missing memory sample: %+v", c)
		}
	}
	old := s[0].MemoryBytes
	db.lookup.Delete("s:test")
	db.refreshCacheMemory(now.Add(time.Second))
	if next := db.CacheStatistics()[0]; next.MemoryBytes >= old || next.Entries != 0 {
		t.Fatalf("delete did not reduce memory: before=%d after=%+v", old, next)
	}
}
