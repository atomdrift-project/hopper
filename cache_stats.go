package hopper

import (
	"time"
	"unsafe"
)

// CacheStats describes one lookup cache. Served includes coalesced misses;
// Loaded counts database loads. Memory is an estimate, not process RSS.
type CacheStats struct {
	Name              string
	Entries, Capacity int
	Served, Loaded    uint64
	MemoryBytes       uint64
	MemorySampledAt   time.Time
}

type cacheMemorySnapshot struct {
	sampleBytes, recordBytes uint64
	sampleAt, recordAt       time.Time
}

// CacheStatistics never waits for a cache lock. Memory traversal runs at most
// once a minute in one background goroutine; scrapes read the last good sample.
// The sample timestamp makes a busy or stuck cache's stale estimate visible.
func (db *DB) CacheStatistics() []CacheStats {
	now := time.Now()
	if now.Unix()-db.cacheMemoryAttempt.Load() >= 60 && db.cacheMemoryRefreshing.CompareAndSwap(false, true) {
		// Another scrape may have completed its refresh between our first
		// timestamp read and acquiring the refresh guard.
		if now.Unix()-db.cacheMemoryAttempt.Load() >= 60 {
			db.cacheMemoryAttempt.Store(now.Unix())
			go func() {
				defer db.cacheMemoryRefreshing.Store(false)
				db.refreshCacheMemory(now)
			}()
		} else {
			db.cacheMemoryRefreshing.Store(false)
		}
	}
	ls, rs := db.LookupStats(), db.RecordCacheStats()
	out := []CacheStats{
		{Name: "sample", Entries: ls.Entries, Capacity: ls.Capacity, Served: ls.SHAServed + ls.PURLServed, Loaded: ls.SHALoaded + ls.PURLLoaded},
		{Name: "record", Entries: rs.Entries, Capacity: rs.Capacity, Served: rs.Served, Loaded: rs.Loaded},
	}
	if m := db.cacheMemory.Load(); m != nil {
		out[0].MemoryBytes, out[0].MemorySampledAt = m.sampleBytes, m.sampleAt
		out[1].MemoryBytes, out[1].MemorySampledAt = m.recordBytes, m.recordAt
	}
	return out
}

func (db *DB) refreshCacheMemory(now time.Time) {
	var m cacheMemorySnapshot
	if prev := db.cacheMemory.Load(); prev != nil {
		m = *prev
	}
	if db.lookup != nil {
		if st, ok := db.lookup.MemoryStats(sampleCacheBytes); ok {
			m.sampleBytes, m.sampleAt = st.Bytes(), now
		}
	}
	if db.records != nil {
		if st, ok := db.records.MemoryStats(recordCacheBytes); ok {
			m.recordBytes, m.recordAt = st.Bytes(), now
		}
	}
	db.cacheMemory.Store(&m)
}

// These estimates count pointed-to structs, strings and slice backing storage.
// Shared strings may be counted more than once. Fido adds entry/FIFO/bloom
// storage; allocator rounding, xsync internals and in-flight loads are excluded.
func sampleCacheBytes(key string, s *Sample) uint64 {
	n := uint64(len(key))
	if s == nil {
		return n
	}
	n += uint64(unsafe.Sizeof(*s))
	for _, v := range []string{s.PURLBase, s.Elements, s.Package, s.RegistryTitle, s.RegistryDescription, s.TopTraits, s.SHA256, s.Filename, s.FileType, s.Label, s.LabelSource, s.Path, s.Status, s.Note, s.CanonicalSHA256, s.Parent, s.LocationRel, s.Skip, s.Formula, s.Version, s.TraitsVersion, s.Domain, s.URL, s.Ecosystem, s.Feed, s.Source, s.TraitGraph} {
		n += uint64(len(v))
	}
	for _, v := range [][]byte{s.CleaveResult, s.LitmusResult, s.LLMResult, s.Provenance} {
		n += uint64(cap(v))
	}
	for _, v := range []*time.Time{s.FetchedAt, s.MarkerMtime, s.Mtime, s.LastErrorAt, s.FirstAnalyzedAt, s.AnalyzedAt} {
		if v != nil {
			n += uint64(unsafe.Sizeof(*v))
		}
	}
	return n
}

func recordCacheBytes(key string, c *cachedRecord) uint64 {
	n := uint64(len(key))
	if c == nil {
		return n
	}
	n += uint64(unsafe.Sizeof(*c))
	r := c.record
	if r == nil {
		return n
	}
	n += uint64(unsafe.Sizeof(*r))
	for _, v := range []*string{r.SHA256, r.PURL, r.EngineVersion, r.TraitsVersion, r.AnalyzedAt, r.Reason} {
		if v != nil {
			n += uint64(unsafe.Sizeof(*v)) + uint64(len(*v))
		}
	}
	if r.FiresAt != nil {
		n += uint64(unsafe.Sizeof(*r.FiresAt))
	}
	n += uint64(cap(r.Findings)) * uint64(unsafe.Sizeof(LookupFinding{}))
	for _, f := range r.Findings {
		n += uint64(len(f.ID) + len(f.Desc))
	}
	return n
}
