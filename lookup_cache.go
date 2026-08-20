package hopper

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
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
	lookupCacheSize  = 8192
	lookupTTL        = 48 * time.Hour
	lookupEntryBytes = 128 << 10
)

const (
	lookupSHAPrefix  = "s:"
	lookupPURLPrefix = "p:"
)

func newDB() *DB {
	return &DB{lookup: fido.New[string, *Sample](fido.Size(lookupCacheSize), fido.TTL(lookupTTL))}
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
	return db.fetchSample(lookupSHAKey(sha256), func() (*Sample, error) {
		return db.sampleBySHA256Uncached(ctx, sha256)
	})
}

func (db *DB) lookupSampleByPURL(ctx context.Context, base, version string) (*Sample, error) {
	if db.lookup == nil {
		return db.sampleByPURLUncached(ctx, base, version)
	}
	return db.fetchSample(lookupPURLKey(base, version), func() (*Sample, error) {
		return db.sampleByPURLUncached(ctx, base, version)
	})
}

// fetchSample serves key from the pool, loading it once across concurrent
// misses. Callers get a clone, so a caller mutating what it was handed (or
// holding it past the entry's life) cannot corrupt the shared copy. Errors are
// never cached — a failed load leaves the key open for the next request, which
// is what keeps a database blip from being memoized as a lasting 404.
func (db *DB) fetchSample(key string, load func() (*Sample, error)) (*Sample, error) {
	s, err := db.lookup.Fetch(key, load)
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
	if db.lookup == nil || sha == "" {
		return
	}
	cached, ok := db.lookup.Get(lookupSHAKey(sha))
	if ok {
		if cached != nil && cached.PURLBase != "" {
			db.lookup.Delete(lookupPURLKey(cached.PURLBase, cached.Version))
			db.lookup.Delete(lookupPURLKey(cached.PURLBase, ""))
		}
		db.lookup.Delete(lookupSHAKey(sha))
		return
	}
	for k, v := range db.lookup.Range() {
		if strings.HasPrefix(k, lookupPURLPrefix) && v != nil && v.SHA256 == sha {
			db.lookup.Delete(k)
		}
	}
}

// forgetSHAs is forgetSHA over a batch, paying the pool sweep at most once for
// the whole set rather than once per sha that is not itself cached.
func (db *DB) forgetSHAs(shas []string) {
	if db.lookup == nil {
		return
	}
	sweep := make(map[string]struct{}, len(shas))
	for _, sha := range shas {
		if sha == "" {
			continue
		}
		cached, ok := db.lookup.Get(lookupSHAKey(sha))
		if ok && cached != nil && cached.PURLBase != "" {
			db.lookup.Delete(lookupPURLKey(cached.PURLBase, cached.Version))
			db.lookup.Delete(lookupPURLKey(cached.PURLBase, ""))
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
