package hopper

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/codeGROOVE-dev/fido"
)

// The in-process SampleBySHA256 / SampleByPURL pool. Fetch single-flights
// concurrent misses so a thundering herd shares one query.
//
// lookupTTL is a backstop, not the correctness mechanism: every write path
// invalidates what it touched, which is what keeps the pool honest. It exists
// only so an entry no in-process hook could reach — a row changed by a repair
// script against the same DSN, or a miss overtaken by a write before it stored
// what it loaded — eventually ages out instead of being wrong for the life of
// the process. Long enough to cost nothing in hit rate.
//
// lookupEntryBytes keeps one pathological row from pinning the heap: a sample's
// analysis blobs can reach hundreds of megabytes for a large archive, and the
// cache bounds entry count, not bytes. Oversized samples are served and dropped,
// capping the pool near lookupCacheSize * lookupEntryBytes.
const (
	lookupCacheSize  = 32768
	lookupTTL        = 48 * time.Hour
	lookupEntryBytes = 128 << 10
)

const (
	lookupSHAPrefix  = "s:"
	lookupPURLPrefix = "p:"
)

func newDB() *DB {
	return &DB{
		lookup:  fido.New[string, *Sample](fido.Size(lookupCacheSize), fido.TTL(lookupTTL)),
		records: newRecordCache(),
	}
}

// lookupCounters tallies what the pool absorbed, split by which key was asked
// about. Plain atomics: the library stays free of any telemetry dependency, and
// cmd/hopper publishes these through the same observable-instrument path the
// worker and progress trackers already use.
type lookupCounters struct {
	shaServed, shaLoaded   atomic.Uint64
	purlServed, purlLoaded atomic.Uint64
}

// LookupStats is a snapshot of sample-lookup traffic since process start.
//
// The split that matters is Served versus Loaded, and it is deliberately not
// the textbook hit/miss pair. Loaded counts the times a request actually ran a
// query; Served counts every request that did not — a live cache entry, or a
// concurrent miss that coalesced onto somebody else's in-flight load. Both
// spare the database equally, which is the question these numbers exist to
// answer, so both are Served.
type LookupStats struct {
	// SHAServed and SHALoaded cover GET /api/sample/{sha256}.
	SHAServed, SHALoaded uint64
	// PURLServed and PURLLoaded cover GET /api/sample?purl=.
	PURLServed, PURLLoaded uint64
	// Entries currently held, against the fixed capacity below it. A pool
	// pinned at capacity with a poor served rate is one worth resizing; a pool
	// well under capacity is not, whatever its hit rate.
	Entries, Capacity int
}

// LookupStats reports the in-process sample pool's effect on database load.
// Safe to call concurrently; the counters are read independently, so a snapshot
// taken under load may be skewed by a request or two.
func (db *DB) LookupStats() LookupStats {
	st := LookupStats{
		SHAServed:  db.lookupCounts.shaServed.Load(),
		SHALoaded:  db.lookupCounts.shaLoaded.Load(),
		PURLServed: db.lookupCounts.purlServed.Load(),
		PURLLoaded: db.lookupCounts.purlLoaded.Load(),
		Capacity:   lookupCacheSize,
	}
	if db.lookup != nil {
		st.Entries = db.lookup.Len()
	}
	return st
}

func lookupSHAKey(sha string) string { return lookupSHAPrefix + sha }

func lookupPURLKey(base, version string) string {
	return lookupPURLPrefix + base + "\x00" + version
}

func (db *DB) sampleBySHA256Uncached(ctx context.Context, sha256 string) (*Sample, error) {
	if db.pool != nil {
		return db.sampleBySHA256PG(ctx, sha256)
	}
	return db.sampleBySHA256SQLite(ctx, sha256)
}

func (db *DB) sampleByPURLUncached(ctx context.Context, base, version string) (*Sample, error) {
	if db.pool != nil {
		return db.sampleByPURLPG(ctx, base, version)
	}
	return db.sampleByPURLSQLite(ctx, base, version)
}

func (db *DB) lookupSampleBySHA256(ctx context.Context, sha256 string) (*Sample, error) {
	if db.lookup == nil {
		return db.sampleBySHA256Uncached(ctx, sha256)
	}
	return db.fetchSample(lookupSHAKey(sha256), &db.lookupCounts.shaServed, &db.lookupCounts.shaLoaded,
		func() (*Sample, error) {
			return db.sampleBySHA256Uncached(ctx, sha256)
		})
}

func (db *DB) lookupSampleByPURL(ctx context.Context, base, version string) (*Sample, error) {
	if db.lookup == nil {
		return db.sampleByPURLUncached(ctx, base, version)
	}
	return db.fetchSample(lookupPURLKey(base, version), &db.lookupCounts.purlServed, &db.lookupCounts.purlLoaded,
		func() (*Sample, error) {
			return db.sampleByPURLUncached(ctx, base, version)
		})
}

// fetchSample serves key from the pool, loading it once across concurrent
// misses. Callers get a clone, so a caller mutating what it was handed (or
// holding it past the entry's life) cannot corrupt the shared copy. Errors are
// never cached — a failed load leaves the key open for the next request, which
// is what keeps a database blip from being memoized as a lasting 404.
func (db *DB) fetchSample(key string, served, loaded *atomic.Uint64, load func() (*Sample, error)) (*Sample, error) {
	// Whether this request reached the database is not observable from the
	// outside, so ask the only component that knows: the loader itself. fido
	// runs it exactly once per genuine miss and never for a caller that hit a
	// live entry or joined an in-flight load, which is precisely the line we
	// want to count on.
	ran := false
	s, err := db.lookup.Fetch(key, func() (*Sample, error) {
		ran = true
		return load()
	})
	if ran {
		loaded.Add(1)
	} else {
		served.Add(1)
	}
	if err != nil {
		return nil, err
	}
	if sampleBlobBytes(s) > lookupEntryBytes {
		db.lookup.Delete(key)
	}
	return cloneSample(s), nil
}

// sampleBlobBytes is a sample's variable-length payload — everything else on it
// is scalar and bounded.
func sampleBlobBytes(s *Sample) int {
	if s == nil {
		return 0
	}
	return len(s.CleaveResult) + len(s.LitmusResult) + len(s.LLMResult) + len(s.Provenance)
}

// forgetSHA drops every entry that could answer with this sample: its own key
// and any package-identity key currently resolving to it. The cached row names
// its own identity, so the common case is two direct deletes; only when the
// sample itself is not cached — and the identity keys it would name are
// therefore unknown — is the sweep over the pool needed. Every write path pays
// this, so keeping it off the hot path matters.
func (db *DB) forgetSHA(sha string) {
	if sha == "" {
		return
	}
	// Both pools answer the same question from the same row, so every key
	// dropped here is dropped from each: one surviving a write the other saw
	// would serve a verdict that is no longer true for as long as its TTL.
	db.forget(lookupSHAKey(sha))
	if db.lookup == nil {
		db.forgetRecordsBySHA(map[string]struct{}{sha: {}})
		return
	}
	cached, ok := db.lookup.Get(lookupSHAKey(sha))
	if ok {
		if cached != nil && cached.PURLBase != "" {
			db.forget(lookupPURLKey(cached.PURLBase, cached.Version))
			db.forget(lookupPURLKey(cached.PURLBase, ""))
		}
		return
	}
	for k, v := range db.lookup.Range() {
		if strings.HasPrefix(k, lookupPURLPrefix) && v != nil && v.SHA256 == sha {
			db.lookup.Delete(k)
		}
	}
	// The record pool outlives the sample pool by four to one, so a record can
	// still be held under a PURL whose sample has already been evicted — and
	// the sweep above would not have found it.
	db.forgetRecordsBySHA(map[string]struct{}{sha: {}})
}

// forget drops one key from both pools.
func (db *DB) forget(key string) {
	if db.lookup != nil {
		db.lookup.Delete(key)
	}
	db.forgetRecord(key)
}

// forgetSHAs is forgetSHA over a batch, paying the pool sweep at most once for
// the whole set rather than once per sha that is not itself cached.
func (db *DB) forgetSHAs(shas []string) {
	all := make(map[string]struct{}, len(shas))
	for _, sha := range shas {
		if sha != "" {
			all[sha] = struct{}{}
			db.forgetRecord(lookupSHAKey(sha))
		}
	}
	if db.lookup == nil {
		db.forgetRecordsBySHA(all)
		return
	}
	defer db.forgetRecordsBySHA(all)
	sweep := make(map[string]struct{}, len(shas))
	for _, sha := range shas {
		if sha == "" {
			continue
		}
		cached, ok := db.lookup.Get(lookupSHAKey(sha))
		if ok && cached != nil && cached.PURLBase != "" {
			db.forget(lookupPURLKey(cached.PURLBase, cached.Version))
			db.forget(lookupPURLKey(cached.PURLBase, ""))
		}
		db.lookup.Delete(lookupSHAKey(sha))
		if !ok {
			sweep[sha] = struct{}{}
		}
	}
	if len(sweep) == 0 {
		return
	}
	for k, v := range db.lookup.Range() {
		if strings.HasPrefix(k, lookupPURLPrefix) && v != nil {
			if _, drop := sweep[v.SHA256]; drop {
				db.lookup.Delete(k)
			}
		}
	}
}

func (db *DB) forgetSample(s *Sample) {
	if s == nil {
		return
	}
	db.forgetSHA(s.SHA256)
	if db.lookup == nil || s.PURLBase == "" {
		return
	}
	db.lookup.Delete(lookupPURLKey(s.PURLBase, s.Version))
	db.lookup.Delete(lookupPURLKey(s.PURLBase, ""))
}

func (db *DB) forgetSamples(samples []*Sample) {
	if db.lookup == nil {
		return
	}
	drop := make(map[string]struct{}, len(samples))
	for _, s := range samples {
		if s == nil || s.SHA256 == "" {
			continue
		}
		drop[s.SHA256] = struct{}{}
		db.lookup.Delete(lookupSHAKey(s.SHA256))
		if s.PURLBase != "" {
			db.lookup.Delete(lookupPURLKey(s.PURLBase, s.Version))
			db.lookup.Delete(lookupPURLKey(s.PURLBase, ""))
		}
	}
	if len(drop) == 0 {
		return
	}
	for k, v := range db.lookup.Range() {
		if strings.HasPrefix(k, lookupPURLPrefix) && v != nil {
			if _, ok := drop[v.SHA256]; ok {
				db.lookup.Delete(k)
			}
		}
	}
}

// flushLookups drops the whole pool. Bulk maintenance (cascade, backfill, prune,
// cleanup) rewrites rows it does not enumerate, so there is nothing finer to
// invalidate; these run rarely enough that refilling costs nothing.
func (db *DB) flushLookups() {
	if db.lookup == nil {
		return
	}
	if n := db.lookup.Flush(); n > 0 {
		slog.Debug("lookup cache flushed", "entries", n)
	}
}

func (db *DB) writeSHA(sha string, err error) error {
	if err == nil {
		db.forgetSHA(sha)
	}
	return err
}

func cloneSample(s *Sample) *Sample {
	if s == nil {
		return nil
	}
	out := *s
	out.CleaveResult = bytes.Clone(s.CleaveResult)
	out.LitmusResult = bytes.Clone(s.LitmusResult)
	out.LLMResult = bytes.Clone(s.LLMResult)
	out.Provenance = bytes.Clone(s.Provenance)
	out.FetchedAt = cloneTime(s.FetchedAt)
	out.MarkerMtime = cloneTime(s.MarkerMtime)
	out.Mtime = cloneTime(s.Mtime)
	out.LastErrorAt = cloneTime(s.LastErrorAt)
	out.FirstAnalyzedAt = cloneTime(s.FirstAnalyzedAt)
	out.AnalyzedAt = cloneTime(s.AnalyzedAt)
	return &out
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := *t
	return &u
}
