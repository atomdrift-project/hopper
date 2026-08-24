package hopper

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/atomdrift-project/hopper/pkgparse"
	"github.com/codeGROOVE-dev/fido"
)

// The rendered-record pool behind LookupRecord.
//
// Separate from the sample pool, and much larger, because it holds a different
// thing. A cached *Sample carries its analysis blobs — bounded at
// lookupEntryBytes each — so 32768 of them is already a large heap. A record is
// a few hundred bytes: a level, a sentence, and at most three trait ids. Four
// times the reach for a fraction of the memory, which matters because every
// scan worker that misses its own index asks here, and a broadcast to the fleet
// asks N times for one artifact.
//
// recordTTL is a backstop, not the correctness mechanism: forgetSHA drops
// records alongside samples, so what keeps the pool honest is invalidation and
// this only ages out what no in-process hook could reach. A week rather than
// lookupTTL's two days because a record is derived from an analysis, and an
// analysis that has not been redone has not changed — the entries this pool
// holds go stale on a write or not at all.
//
// That reasoning holds only for a process that sees the writes. A hopper in
// front of the logical replica never executes a write path, so nothing there
// ever calls forgetSHA and this stops being a backstop and becomes the entire
// staleness bound — a re-analysed package would keep serving its previous
// verdict for a week, to a scan fleet that reads the replica first. NOTIFY does
// not cross replication, so a replica cannot be told; it can only age out.
// A process serving the replica therefore uses [replicaRecordTTL] instead, set
// by [DB.ServesReplica] at startup.
//
// recordMissTTL is why absence is cached at all. "Nothing stored" is the common
// answer for a caller gating installs on packages we have never seen, and it is
// the one answer that used to reach the database on every single ask: fido
// collapses simultaneous misses, but a miss repeated a second later is a fresh
// query. A minute is short enough that a package analyzed just after being
// asked about is not hidden for long, and long enough to absorb a fleet
// broadcast and a retrying client.
const (
	recordCacheSize = 128000
	recordTTL       = 7 * 24 * time.Hour
	// replicaRecordTTL is the whole staleness bound on a process that cannot
	// invalidate, so it is chosen as an answer to "how long may a re-analysed
	// package keep serving its old verdict", not as a cache-tuning number.
	replicaRecordTTL = 15 * time.Minute
	recordMissTTL    = time.Minute
)

// LookupRecord is what the corpus knows about one artifact, projected to the
// shape /v1/lookup answers with.
//
// There is deliberately no decision here and no threshold to produce one.
// Turning a level into allow/block is the one rule in this system where a
// second implementation is a security bug rather than a duplication, and it
// belongs to whoever holds the policy. Hopper reports what it stored.
//
// Every field is always present — null where unknown, [] where empty — so a
// caller writes one code path against a shape that does not move.
type LookupRecord struct {
	// SHA256 is the bytes this record describes, and is nil when it describes
	// none: a record standing on threat-feed citations for a package nothing
	// has analyzed names a package, not an artifact. Null rather than "",
	// because this field is the identity a caller compares when two spellings
	// must be proven to be one thing — and every empty string compares equal
	// to every other.
	SHA256 *string `json:"sha256"`
	PURL   *string `json:"purl"`
	// FiresAt is the tightest false-positive budget per 100 million benign
	// files at which this artifact grades hostile: lower is worse, -1 fires at
	// no level at all, and null means no level applies to this record. It is
	// measured, never chosen — a caller's own budget is what it gets compared
	// against, and that comparison does not happen here.
	FiresAt       *int    `json:"fires_at"`
	EngineVersion *string `json:"engine_version"`
	// TraitsVersion is the analyzer-judgment hash this verdict was produced
	// under — hopper's invalidation key. Distinct from EngineVersion (the scan
	// build): a build can change without the judgment changing, and this field
	// changes exactly when re-analysis could learn something. It exists so a
	// scan worker can skip re-analyzing a dependency the corpus already holds
	// at the worker's own traits version (the 2026-08-23 renewal storm:
	// thousands of dependency re-scans per hour whose stores all logged
	// "re-analysis learned nothing").
	TraitsVersion *string         `json:"traits_version"`
	AnalyzedAt    *string         `json:"analyzed_at"`
	Reason        *string         `json:"reason"`
	Findings      []LookupFinding `json:"findings"`
	// Analyzed is false when the corpus holds the bytes but nothing has looked
	// at them. Not serialized: it selects the 202 the handler answers with.
	Analyzed bool `json:"-"`
}

// LookupFinding is one of the artifact's strongest traits. crit is 4
// suspicious, 5 hostile; id is stable and descriptive enough to show someone.
//
// Sourced from the top_traits column, which a trigger maintains on every result
// write as the worst three traits at crit >= 4. That means no file, offset or
// line: those live in cleave_result, the largest column hopper holds and the
// one this path exists to avoid reading. Reason carries the sentence a person
// actually reads.
type LookupFinding struct {
	ID string `json:"id"`
	// Desc is a sentence a person reads, and is empty for a trait the analyzer
	// fired: those are described by the trait id, and the record's Reason
	// already carries the sentence for the verdict as a whole.
	//
	// It exists for findings that are not the analyzer's, where Reason is
	// either taken by a measured verdict or would be the only place the
	// evidence could go. See [feedFinding].
	Desc string `json:"desc,omitempty"`
	Crit int    `json:"crit"`
}

// cachedRecord is a record and, for an absent one, when to stop believing it.
type cachedRecord struct {
	record *LookupRecord
	// expires bounds a negative entry only; a found record is governed by
	// invalidation and recordTTL.
	expires time.Time
}

// LookupRecord returns the corpus's record for an artifact. sha256 wins when
// both keys are given: it names exact bytes, where a PURL names whatever
// release the corpus holds for that version — usually the same artifact, not
// necessarily the one being asked about.
//
// Returns ErrNotFound when nothing is stored. base/version are the versionless
// canonical PURL and its version, as [pkgparse.VersionlessPURL] and
// [pkgparse.PURLVersion] produce.
//
// Each key is cached under its own entry rather than the pair under a composite
// one. A composite key cannot be reconstructed from the row a write touches, so
// invalidating it would mean sweeping the whole pool on every write; these keys
// are the same ones the sample pool uses, so a write deletes them directly.
func (db *DB) LookupRecord(ctx context.Context, sha256, base, version string) (*LookupRecord, error) {
	if sha256 != "" {
		record, err := db.recordFor(lookupSHAKey(sha256), func() (*LookupRecord, time.Duration, error) {
			sample, err := db.SampleBySHA256(ctx, sha256)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					// Nothing holds these bytes. Outside sources may still know
					// them, and answering "nobody has analyzed this" about a
					// digest several of them call malware is a worse answer
					// than saying who says so.
					return db.fromLedger(ctx, sha256, "")
				}
				return nil, 0, err
			}
			rec, ttl := db.corroborate(ctx, recordOf(sample), sample.Corroborated, sample.SHA256, sample.PURLBase)
			return rec, ttl, nil
		})
		if err == nil {
			return record, nil
		}
		if !errors.Is(err, ErrNotFound) || base == "" {
			return nil, err
		}
	}
	if base == "" {
		return nil, ErrNotFound
	}
	return db.recordFor(lookupPURLKey(base, version), func() (*LookupRecord, time.Duration, error) {
		sample, err := db.SampleByPURL(ctx, base, version)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return db.fromLedger(ctx, "", base)
			}
			return nil, 0, err
		}
		rec, ttl := db.corroborate(ctx, recordOf(sample), sample.Corroborated, sample.SHA256, sample.PURLBase)
		return rec, ttl, nil
	})
}

// recordFor serves one key from the pool, rendering it once across concurrent
// misses.
//
// load reports how long what it produced may be believed. Zero means "as long
// as the analysis it came from", which is the ordinary case: an analysis that
// has not been redone has not changed, so invalidation and recordTTL govern it.
// A record standing on the sightings ledger names a real duration, because no
// write this process sees invalidates one — the ledger moves underneath it, and
// ageing out is the whole mechanism keeping it honest.
func (db *DB) recordFor(key string, load func() (*LookupRecord, time.Duration, error)) (*LookupRecord, error) {
	if db.records == nil {
		record, _, err := load()
		return record, err
	}
	if entry, ok := db.records.Get(key); ok && entry != nil {
		if entry.live() {
			db.recordCounts.served.Add(1)
			if entry.record == nil {
				return nil, ErrNotFound
			}
			return entry.record, nil
		}
		// Evict before Fetch, or the expiry above is decorative.
		//
		// fido.Fetch returns whatever is in memory before it calls the loader,
		// so falling through with the stale entry still present hands it back
		// unchanged — recordMissTTL expired nothing, and the real bound was
		// fido's own recordTTL: a week, or replicaRecordTTL on a replica. A
		// package analyzed a minute after being asked about stayed "unknown"
		// for days. It also has to be right before a derived record can be
		// cached here at all, since that one is only ever correct for as long
		// as the ledger behind it has not moved.
		db.records.Delete(key)
	}
	ran := false
	entry, err := db.records.Fetch(key, func() (*cachedRecord, error) {
		ran = true
		record, ttl, err := load()
		if errors.Is(err, ErrNotFound) {
			// Absence is an answer and is cached as one, briefly. Any other
			// error is not: a database blip must not be memoized as a lasting
			// "we have never seen this", which is the shape of a wrong answer a
			// caller acts on.
			return &cachedRecord{expires: time.Now().Add(recordMissTTL)}, nil
		}
		if err != nil {
			return nil, err
		}
		entry := &cachedRecord{record: record}
		if ttl > 0 {
			entry.expires = time.Now().Add(ttl)
		}
		return entry, nil
	})
	if ran {
		db.recordCounts.loaded.Add(1)
	} else {
		db.recordCounts.served.Add(1)
	}
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.record == nil {
		return nil, ErrNotFound
	}
	return entry.record, nil
}

// live reports whether a time-bound entry may still be believed.
//
// A zero expires means the entry is governed by invalidation and recordTTL
// instead — which is every record derived from a stored analysis, because an
// analysis that has not been redone has not changed. Absences and records
// derived from the sightings ledger both set one: neither is invalidated by any
// write this process sees, so ageing out is the only thing keeping them honest.
func (c *cachedRecord) live() bool {
	return c.expires.IsZero() || time.Now().Before(c.expires)
}

// forgetRecord drops one rendered record. Named for a key the sample pool uses
// too, so a write invalidates the same identity in both and the two cannot
// disagree about what the corpus holds.
func (db *DB) forgetRecord(key string) {
	if db.records != nil {
		db.records.Delete(key)
	}
}

// forgetRecordsBySHA drops rendered records this sample backs but whose keys a
// write cannot name — a record cached under a PURL whose sample the other pool
// has already evicted. Called only from the branch that sweeps the sample pool
// anyway, so it adds cost where a sweep is already being paid for rather than a
// sweep of its own.
//
// Cached absences are deliberately left alone. Dropping them here would mean a
// write to any row clearing every negative entry in the pool, and under steady
// ingestion that is every negative entry every few seconds — a cache that never
// gets to answer. They age out on recordMissTTL instead, which is a minute.
func (db *DB) forgetRecordsBySHA(shas map[string]struct{}) {
	if db.records == nil || len(shas) == 0 {
		return
	}
	for k, v := range db.records.Range() {
		if v == nil || v.record == nil {
			continue
		}
		if v.record.SHA256 == nil {
			continue // a ledger-backed record names no bytes to invalidate by
		}
		if _, ok := shas[*v.record.SHA256]; ok {
			db.records.Delete(k)
		}
	}
}

// recordOf projects a stored sample onto the wire.
//
// Deliberately never reads CleaveResult. It is the largest column hopper holds
// — megabytes for an archive — and nothing here comes from it, so touching it
// would pay a heap-TOAST detoast to render a few hundred bytes.
func recordOf(s *Sample) *LookupRecord {
	sha := s.SHA256
	r := &LookupRecord{
		SHA256:   &sha,
		Findings: findingsOf(s.TopTraits),
		Analyzed: len(s.LitmusResult) > 0 || len(s.LLMResult) > 0 || len(s.CleaveResult) > 0,
	}
	// Composed from the sample's own coordinates, never PURLBase + "@" +
	// Version: PURLBase keeps a repository_url qualifier, so appending a
	// version to it produces a string that is not a PURL.
	if purl, ok := pkgparse.SourcePURL(s.Ecosystem, s.Domain, s.Package, s.Version, ""); ok {
		r.PURL = &purl
	}

	ml, llm := litmusSections(s.LitmusResult)
	r.FiresAt = ml.Lvl
	if ml.Eng != "" {
		eng := ml.Eng
		r.EngineVersion = &eng
	}
	if s.TraitsVersion != "" {
		tv := s.TraitsVersion
		r.TraitsVersion = &tv
	}
	switch {
	case ml.AnalyzedAt != "":
		at := ml.AnalyzedAt
		r.AnalyzedAt = &at
	case s.AnalyzedAt != nil:
		at := s.AnalyzedAt.UTC().Format(time.RFC3339)
		r.AnalyzedAt = &at
	default:
		// Neither the record nor the row carries a time. Left null rather than
		// stamped with now: this field says when the artifact was analyzed, and
		// the moment it was asked about is not that.
	}

	// The rationale is its own column on newer rows and inside the litmus
	// envelope on the ones written when it was one blob.
	why := llm.Interpretation
	if why == "" {
		var col litmusLLM
		if err := json.Unmarshal(s.LLMResult, &col); err == nil {
			why = col.Interpretation
		}
	}
	if why != "" {
		r.Reason = &why
	}
	return r
}

// litmusML is the handful of fields a record needs from a stored litmus result.
type litmusML struct {
	Lvl        *int   `json:"lvl"`
	Eng        string `json:"eng"`
	AnalyzedAt string `json:"analyzed_at"`
}

// litmusLLM is the interpreter's one-sentence rationale.
type litmusLLM struct {
	Interpretation string `json:"interpretation"`
}

// litmusSections pulls the ml and llm records out of a stored litmus_result,
// whichever era wrote it.
//
// Three shapes are live in the corpus and the one scan serializes today is the
// rarest. Measured over 3000 analyzed rows: 83% are the flat ml record, 13%
// predate levels entirely, and 5% are the nested {ml, llm} envelope. A parser
// written against scan's current output alone would read a twentieth of what we
// hold and report the rest as having no level — which, to a caller gating
// installs, silently turns most of the corpus into "unknown".
func litmusSections(litmus []byte) (litmusML, litmusLLM) {
	if len(litmus) == 0 {
		return litmusML{}, litmusLLM{}
	}
	var nested struct {
		ML  *litmusML  `json:"ml"`
		LLM *litmusLLM `json:"llm"`
	}
	if err := json.Unmarshal(litmus, &nested); err == nil && nested.ML != nil {
		llm := litmusLLM{}
		if nested.LLM != nil {
			llm = *nested.LLM
		}
		return *nested.ML, llm
	}
	// Flat, or a pre-level record: either way an absent level leaves Lvl nil,
	// which is exactly what such a record should report.
	var flat litmusML
	if err := json.Unmarshal(litmus, &flat); err != nil {
		return litmusML{}, litmusLLM{}
	}
	return flat, litmusLLM{}
}

// findingsOf decodes the top_traits column. Always returns a non-nil slice so
// the field marshals as [] rather than null: a caller must not have to tell
// "no findings" from "that key was missing".
func findingsOf(topTraits string) []LookupFinding {
	out := []LookupFinding{}
	if strings.TrimSpace(topTraits) == "" {
		return out
	}
	var traits []LookupFinding
	if err := json.Unmarshal([]byte(topTraits), &traits); err != nil {
		// A row whose column will not parse is not a reason to fail the lookup:
		// the verdict itself is what the caller came for.
		return out
	}
	return append(out, traits...)
}

// recordCounters tracks how much of the record pool's traffic never reached the
// database, mirroring lookupCounters.
type recordCounters struct {
	served atomic.Uint64
	loaded atomic.Uint64
}

// RecordStats reports the rendered-record pool's hit accounting.
type RecordStats struct {
	Served   uint64
	Loaded   uint64
	Entries  int
	Capacity int
}

// RecordCacheStats snapshots the record pool.
func (db *DB) RecordCacheStats() RecordStats {
	s := RecordStats{
		Served:   db.recordCounts.served.Load(),
		Loaded:   db.recordCounts.loaded.Load(),
		Capacity: recordCacheSize,
	}
	if db.records != nil {
		s.Entries = db.records.Len()
	}
	return s
}

// newRecordCache builds the rendered-record pool.
func newRecordCache() *fido.Cache[string, *cachedRecord] {
	return fido.New[string, *cachedRecord](fido.Size(recordCacheSize), fido.TTL(recordTTL))
}

// ServesReplica narrows how long rendered records may be held, for a process
// reading the logical replica.
//
// Such a process never executes a write path, so nothing in it ever calls
// forgetSHA and [recordTTL]'s reasoning — that invalidation is the correctness
// mechanism and the TTL only a backstop — does not apply. Here the TTL is the
// only bound there is. NOTIFY does not cross replication and a logical replica
// is not in recovery, so a replica cannot be told and cannot detect itself
// either: it has to be configured, which is what this is.
//
// Call before serving. The pool is empty at that point, so replacing it costs
// nothing.
func (db *DB) ServesReplica() {
	db.records = fido.New[string, *cachedRecord](fido.Size(recordCacheSize), fido.TTL(replicaRecordTTL))
	slog.Info("serving a replica: rendered records age out rather than being invalidated",
		"record_ttl", replicaRecordTTL)
}
