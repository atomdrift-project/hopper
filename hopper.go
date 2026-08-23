// Package hopper is a sample registry backed by PostgreSQL or SQLite.
//
// It stores binary samples, analysis results, and reverse engineering
// reports for the atomdrift malware detection pipeline.
//
// Use a postgres:// DSN for PostgreSQL, or a file path for SQLite.
//
//nolint:revive // max-public-structs: these are the package's core domain types (DB, Sample, Report, ClaimJob, WorkflowSample, etc.); they form a single cohesive public API and splitting them apart would harm discoverability, not clarity.
package hopper

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	cryptosha256 "crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/codeGROOVE-dev/fido"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver

	"github.com/atomdrift-project/hopper/pkgparse"
)

const skipBenignArchiveItem = "skip-benign-archive-item"

// maxArchiveMembers bounds how many members a single archive explosion will
// insert (see ExplodeArchiveMembers). Real archives — even large containers or
// monorepo tarballs — stay well under this; the cap exists so one oversized or
// crafted cleave result can't fan a single /api/result into millions of rows.
const maxArchiveMembers = 100_000

// CriticalLevel is hopper's consumer-side cutoff between hostile and suspicious
// when deriving criticality from a v6 litmus envelope's `ml.l`. `l <= CriticalLevel`
// is hostile (fires at or below our critical line); `l > CriticalLevel` is
// suspicious (fired only at noisier operating points); `-1` is benign; `null`
// (manual-mode hostile) is hostile.
//
// L25 is our standard operating level — the level the model is currently
// deployed and calibrated at (scan's DEFAULT_SEVERITY_LEVEL); tightened from L50
// (2026-07) to the knee of the hostile curve, just below the sharp L30->L40 FP
// cliff. It lives in this single constant. The level is consumer-owned: this is
// only hopper's *default*, and any caller can override it per-query via
// [FeedQuery.CriticalLevel] (as scan's users do with `-l`), which the derivation honors.
const CriticalLevel = 25

// SuspiciousCeiling is the loosest fired-level (FP per 100M benigns) that still
// reads as suspicious. A firing at or below CriticalLevel is hostile; above
// CriticalLevel and up to (and including) SuspiciousCeiling is suspicious;
// anything looser is treated as benign informational noise rather than a
// suspicious verdict.
//
// Set to L3000 — an EXPERIMENTAL widening (2026-07) to surface as much of the
// weak-signal tail as the calibration curve supports (recall peaks at L4000 then
// collapses ~8pp at L5000, so L3000 is the loosest robustly-stable point). This
// overrides the prior L100 precision elbow from hopper's own fired-level analysis
// (L100 ~91% precision vs good, L250 ~31%; L250+ adds more false positives than
// true positives), so it knowingly re-admits a low-precision tail — re-measure
// the elbow and tighten back if the suspicious bucket floods. Mirrors scan's
// SUSPICIOUS_LEVEL_CEILING and promoter/prism's SuspiciousCeiling; keep the
// cross-repo group in sync.
const SuspiciousCeiling = 3000

// LitmusClass derives a sample's criticality class (0=benign, 1=suspicious,
// 2=hostile) from its litmus envelope at the default [CriticalLevel] cutoff.
// It is the Go mirror of the SQL derivation (feedClassExpr, the
// samples_derive_litmus_cols trigger, litmusClassSQLite — keep them in sync):
// legacy envelopes carry 'class' directly; v6/v7 use 'lvl'/'l', the strictest
// grid level at which the file fires. A missing level on a present envelope is
// manual-mode hostile (fail-safe); a negative level never fires (benign);
// <= CriticalLevel is hostile; <= SuspiciousCeiling is suspicious; looser is
// benign. A nil, empty, or unparseable result is benign.
func LitmusClass(result []byte) int {
	if len(result) == 0 {
		return 0
	}
	var env struct {
		Class *int `json:"class"`
		Lvl   *int `json:"lvl"`
		L     *int `json:"l"`
	}
	if json.Unmarshal(result, &env) != nil {
		return 0
	}
	if env.Class != nil {
		return *env.Class
	}
	lvl := env.Lvl
	if lvl == nil {
		lvl = env.L
	}
	switch {
	case lvl == nil:
		return 2
	case *lvl < 0:
		return 0
	case *lvl <= CriticalLevel:
		return 2
	case *lvl <= SuspiciousCeiling:
		return 1
	default:
		return 0
	}
}

// Pool labels, ordered by precedence: bad > good > sighted > unknown.
//
// "sighted" is a feed claim pending verification: an external threat feed
// named the package or hash (see the sightings ledger) but no independent
// evidence has confirmed it. Sighted samples are invisible to the training
// triage queues (which select bad/good/unknown exactly) and are promoted to
// bad only by promoter's corroboration rules. "unknown" remains the
// no-claims background pool.
const (
	labelUnknown = "unknown"
	labelSighted = "sighted"
	labelGood    = "good"
	labelBad     = "bad"
)

// Unknown-class storage roots. The root records workflow and storage tier; it
// is deliberately independent of the sample's classification label.
const (
	PoolIncoming      = "incoming"
	PoolPending       = "pending"
	PoolReview        = "review"
	PoolLegacyUnknown = "unknown"
)

// ProvenanceSidecarSuffix is the suffix used by Forager's on-disk metadata
// sidecar. A physical location move treats the artifact and this sidecar as one
// unit even though only the artifact has a catalog location row.
const ProvenanceSidecarSuffix = ".forage.json"

// ReportTypeMissing marks a sample whose bytes a triage worker could not fetch
// — the row outlived its file, which happens by design on a mirror running with
// --dataset-incomplete, where markServeMissing deliberately does not set
// skip='missing'. It is keyed on the root sample (a member's parent), since the
// bytes that vanished are the archive's and every member shares their fate.
//
// The score-ranked queues need this because absence is otherwise undrainable:
// a processed sample leaves via its queue's report row, but an unfetchable one
// has no verdict to record, so it would hold its place at the top of a
// score-ordered window forever while real work queued behind it. Selectors
// treat the marker as expiring (see MissingRetry) rather than permanent, so a
// re-synced pool brings its samples back on its own.
//
// Because it is parent-keyed and reports.sha256 has a foreign key to
// samples.sha256, the selectors exclude members whose parent row is itself
// absent (an orphaned "!!" path) — otherwise the insert would violate the FK.
// Those members are unservable anyway (the API answers "parent not found"), so
// dropping them from selection is correct independent of the marker.
const ReportTypeMissing = "missing"

// MissingRetry is how long a ReportTypeMissing marker suppresses a sample.
// Long enough that a queue is not re-probing the same dead rows every cycle,
// short enough that bytes restored to an incomplete mirror are picked up
// without an operator having to clear anything.
const MissingRetry = 4 * 24 * time.Hour

// triagePerRouteK bounds each file_type's candidate window in TriageHighest /
// TriageLowest. K=10 covers the threshold-pinning band: a route's operating
// point is an interpolated quantile over its top benign scores, so the top
// ~10 are the files whose labels decide reported recall — and fixing #1
// simply promotes #2 into the window on the next pass. Small enough that 80+
// routes still fit one selection batch's ordering (every route's #1 sorts
// before any route's #2).
const triagePerRouteK = 10

// notableCrit is the cleave criticality floor for the stranded queue's
// member gate — 3 = "notable" in the shared severity ladder (mirrors
// collimator's traits.py CRIT_LEVELS; info=1..hostile=5). Members below it
// are inert content whose inherited-good label threatens nothing.
const notableCrit = 3

// suspiciousCrit is the cleave criticality floor for the popular queue — 4 =
// "suspicious" in the same ladder. One above notableCrit, and the gap is the
// whole point: "notable" means a finding worth recording, not a finding worth
// a human's attention, and on a popular package it is overwhelmingly ordinary
// behaviour that the detector is right to note and wrong to escalate.
//
// Measured before it was raised here: of 68,288 samples of ranked packages at
// max_crit >= 3, 62,636 (92%) were notable-only, against 4,695 suspicious and
// 957 hostile. The split was also lopsided by ecosystem — javascript and crates
// supplied 69% of the rows and 8.6% of the suspicious ones — so the bar was
// mostly buying a very large queue of very popular, very boring packages.
//
// That queue is expensive in a way the others are not: cyclotron runs it on the
// deep provider chain AND stands every other sample queue down while it has
// work, so its length is the whole fleet's latency. At >= 3 the backlog was
// ~80 days of that; at >= 4 it is about a week.
const suspiciousCrit = 4

// strandedInnerScan bounds TriageStranded's member walk before the collapse
// to parent archives — same role highestInnerScan used to play; the stranded
// population is small (~tens of thousands) and score-concentrated, so this
// comfortably fills any batch of distinct archives.
const strandedInnerScan = 1000

// CascadeDemoteScore is the minimum cleave risk score (samples.score) an
// unlabeled archive member must carry to be demoted alongside a bad parent.
// A bad archive's malice lives in a few members, not every file; shared benign
// content (READMEs, licenses, popular vendored deps) scores below this and is
// left untouched so one bad archive cannot poison content it shares with
// thousands of clean ones. Promotion has no such floor: a clean archive vouches
// for all of its members.
const CascadeDemoteScore = 30

// cascadeBackfillLogEvery is how often (in archives processed) CascadeBackfill
// emits a progress log line during each pass.
const cascadeBackfillLogEvery = 1000

// cascadeSource is the label_source stamped on members demoted by [DB.CascadeLabel]
// because their archive parent was marked bad. It encodes the parent so a later
// promotion of that same parent can find and revert exactly the members it
// demoted. A member demoted via two bad parents records only the most recent;
// reverting the older parent then leaves it good even though the other parent
// still considers it bad. That cross-parent imprecision is accepted.
func cascadeSource(parentSHA256 string) string { return "cascade:" + parentSHA256 }

// Label-related skip reasons and label sources managed by the pool-precedence
// resolution. Other skip reasons (corrupt/encrypted/missing/unsupported/
// replaced/empty_path/skip-benign-archive-item) are "hard" and never cleared
// by relabeling.
const (
	skipMisclassified   = "misclassified" // marker contradicts the pool directory
	skipConflict        = "conflict"      // same SHA256 asserted in both good/ and bad/
	labelSourceMarker   = "marker"        // label flipped by a .BENIGN/.BAD marker
	labelSourceConflict = "conflict"      // label forced to bad by a good+bad conflict
)

// logLabelTransition emits a structured log line for a top-level label change
// that the upsert is about to apply, categorized by classifyLabelTransition.
// No-op when the label is unchanged.
func logLabelTransition(sha, path, stored, storedSrc, storedSkip, in, inSrc string) {
	category, from, to := classifyLabelTransition(stored, storedSrc, storedSkip, in, inSrc)
	switch category {
	case "conflict":
		slog.Warn("label conflict good+bad", "sha256", sha, "path", path,
			"stored", from, "incoming", in, "resolved", to)
	case "rehabilitated":
		slog.Info("marker cleared, label rehabilitated", "sha256", sha, "path", path,
			"from", from, "to", to)
	case "promoted":
		slog.Info("label promoted", "sha256", sha, "path", path, "from", from, "to", to)
	default:
		// Empty category → nothing log-worthy changed.
	}
}

// labelRank orders pool labels for precedence resolution: bad outranks good
// outranks sighted outranks unknown. Used to decide whether a re-observation
// promotes a sample. A feed claim (sighted) never overrides a verified good
// or bad label. Keep in sync with labelRankSQL.
func labelRank(label string) int {
	switch label {
	case labelBad:
		return 3
	case labelGood:
		return 2
	case labelSighted:
		return 1
	default:
		return 0
	}
}

// labelRankSQL renders labelRank as a SQL CASE expression over the given
// column reference. It is interpolated (never parameterized — col is always a
// compile-time constant) into the upsert/relabel statements in pg.go and
// sqlite.go so the precedence order cannot drift between Go and SQL.
func labelRankSQL(col string) string {
	return "(CASE " + col + " WHEN 'bad' THEN 3 WHEN 'good' THEN 2 WHEN 'sighted' THEN 1 ELSE 0 END)"
}

// classifyLabelTransition mirrors the ON CONFLICT label-resolution rules (see
// insertSampleBatchSQLite / insertBatchStagingInsert) for a top-level
// (parent=”) re-observation. It is logging-only: the authoritative write
// happens in the upsert SQL, which compares against the live row and is
// therefore race-safe under concurrent per-directory pipelines. It returns the
// transition category ("" when nothing log-worthy changes) and the from/to
// labels. stored* is the existing row; in*/inSrc is the incoming (already
// marker-processed) pool observation.
func classifyLabelTransition(stored, storedSrc, storedSkip, in, inSrc string) (category, from, to string) {
	switch {
	case inSrc == labelSourceMarker:
		// Rule 1: a contradicting marker is present; Go already logged it.
		return "", "", ""
	case storedSrc == labelSourceMarker:
		// Rule 2: stored row is a marker quarantine but no marker is present
		// now (removed or the file moved pools) → the directory governs again.
		if stored == in && storedSkip != skipMisclassified {
			return "", "", ""
		}
		return "rehabilitated", stored, in
	case (stored == labelGood && in == labelBad) || (stored == labelBad && in == labelGood):
		// Rule 3: the same SHA256 is asserted good in one pool and bad in
		// another → resolve to bad and quarantine for review.
		return "conflict", stored, labelBad
	case labelRank(in) > labelRank(stored):
		// Rule 4: a higher-rank pool placement promotes the label.
		return "promoted", stored, in
	default:
		// Rule 5: no change (incoming does not outrank the stored label).
		return "", "", ""
	}
}

// nulSentinel stands in for a JSON NUL (\u0000) in stored data. PostgreSQL's
// JSONB cannot represent the null character, so rather than drop it (lossy) we
// substitute this Private-Use code point on write and restore it on read (see
// restoreNULs), so a NUL survives the storage round-trip. U+E000 never appears
// in well-formed analysis output; a literal U+E000 in the input is the one
// reserved character and is read back as NUL. Encoding is idempotent: the
// sentinel contains no \u0000 / \xNN, so re-running sanitizeJSONB over
// already-encoded data is a no-op, keeping the read-modify-write backfill paths
// safe.
const nulSentinel = "\uE000"

// sanitizeJSONB makes JSON storable in PostgreSQL's strict JSONB:
//   - \u0000 / \x00 (NUL): encoded to nulSentinel; PG JSONB can't hold a null
//     character. restoreNULs reverses this on read.
//   - \xNN (other hex escapes): rewritten to \u00NN; \xNN is not valid JSON.
//     One-way: it fixes malformed cleave output, there is nothing to restore.
//
// Both are common in malware analysis output where cleave reports binary strings
// as-is. Only single-backslash sequences are touched; \\u0000 and \\xNN (escaped
// backslash + literal text) are left intact.
func sanitizeJSONB(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	needsHex := bytes.Contains(b, []byte(`\x`))
	needsNull := bytes.Contains(b, []byte(`\u0000`))
	if !needsHex && !needsNull {
		return b
	}

	// Single pass: scan for backslash sequences, rewriting as needed.
	// We track whether the current backslash is escaped (preceded by \).
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}

		next := b[i+1]
		switch {
		case next == '\\':
			// Escaped backslash — emit both and skip ahead so the
			// second \ is not treated as starting a new escape.
			out = append(out, '\\', '\\')
			i++

		case next == 'x' && needsHex && i+3 < len(b) && isHex(b[i+2]) && isHex(b[i+3]):
			// \xNN → \u00NN; \x00 is a NUL, encoded to the sentinel.
			if b[i+2] == '0' && b[i+3] == '0' {
				out = append(out, nulSentinel...)
				i += 3
			} else {
				out = append(out, `\u00`...)
				out = append(out, b[i+2], b[i+3])
				i += 3
			}

		case next == 'u' && needsNull && i+5 < len(b) && b[i+2] == '0' && b[i+3] == '0' && b[i+4] == '0' && b[i+5] == '0':
			// \u0000 (NUL): PG JSONB can't store it; encode to the sentinel.
			out = append(out, nulSentinel...)
			i += 5

		default:
			out = append(out, b[i])
		}
	}
	return out
}

// restoreNULs reverses the nulSentinel substitution sanitizeJSONB applies on
// write: each sentinel code point becomes a JSON NUL escape again. It is the
// read half of the column-boundary codec and a no-op on data carrying no
// sentinel (including everything written before the codec existed).
func restoreNULs(b []byte) []byte {
	if !bytes.Contains(b, []byte(nulSentinel)) {
		return b
	}
	return bytes.ReplaceAll(b, []byte(nulSentinel), []byte(`\u0000`))
}

func randomSHA256Pivot() string {
	var b [32]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		sum := cryptosha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(b[:])
}

// compactCleaveResultForStorage shrinks an archive's stored cleave result for
// the parent row. It runs the result's `raw` section through [Split], which keeps
// the container in full and replaces every embedded member with a lightweight
// reference; the members' full analysis is stored separately by
// [DB.ExplodeArchiveMembers] and rejoined on read by [Reassemble]. A non-archive
// result is returned verbatim.
//
// On top of Split's structural decomposition this applies the storage policy:
// normalize the member list under the v8 "files" key, bound it by
// maxArchiveMembers (the excess reported as "omitted_files" rather than stored,
// so a pathological member count can't bloat the row), and mark the row
// "truncated" so the read path knows to rehydrate.
func compactCleaveResultForStorage(result []byte) []byte {
	if len(result) == 0 {
		return result
	}
	parent, members, err := splitParentOnly(mustMarshal(map[string]json.RawMessage{"raw": json.RawMessage(result)}))
	if err != nil || members == 0 {
		return result // unparseable or not an archive: store verbatim
	}
	top, err := decodeObject(parent)
	if err != nil {
		return result
	}
	rawObj, err := decodeObject(top["raw"])
	if err != nil {
		return result
	}

	// Normalize the member list under the v8 "files" key (Split preserves
	// whichever alias the input used).
	files := rawObj["files"]
	if len(files) == 0 {
		files = rawObj["fs"]
	}
	delete(rawObj, "fs")

	var entries []json.RawMessage
	if json.Unmarshal(files, &entries) != nil {
		return result
	}
	kept := entries[:0]
	members, omitted := 0, 0
	for _, e := range entries {
		obj, derr := decodeObject(e)
		isMember := derr == nil && entryDepth(obj) > 0
		if isMember && members >= maxArchiveMembers {
			omitted++
			continue
		}
		if isMember {
			members++
		}
		kept = append(kept, e)
	}

	rawObj["files"] = mustMarshal(kept)
	rawObj["truncated"] = json.RawMessage(`true`)
	if omitted > 0 {
		rawObj["omitted_files"] = mustMarshal(omitted)
	} else {
		delete(rawObj, "omitted_files")
	}
	return mustMarshal(rawObj)
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

//go:embed schema.sql
var schemaPG string

//go:embed schema_sqlite.sql
var schemaSQLite string

// ErrNotFound is returned when a query matches no rows.
var ErrNotFound = errors.New("hopper: not found")

// DB is a connection to the sample registry.
// Backed by either PostgreSQL (pool) or SQLite (lite).
type DB struct {
	pool             *pgxpool.Pool
	lite             *sql.DB
	lookup           *fido.Cache[string, *Sample]
	records          *fido.Cache[string, *cachedRecord]
	backfillProgress atomic.Pointer[BackfillProgressFn]
	lookupCounts     lookupCounters
	recordCounts     recordCounters
	// replicaIndexPolicy makes migrations decline secondary indexes a logical
	// replica does not need. See SetReplicaIndexPolicy.
	replicaIndexPolicy bool
}

// BackfillProgressFn reports per-batch progress during Backfill. current is
// rows updated so far; total is the upfront candidate count (0 if unknown).
type BackfillProgressFn func(current, total int64)

// SetBackfillProgress installs an optional callback invoked after each
// backfill batch completes. Pass nil to clear. Safe to call concurrently
// with Backfill, but typically set once before Migrate / Backfill runs.
func (db *DB) SetBackfillProgress(fn BackfillProgressFn) {
	if fn == nil {
		db.backfillProgress.Store(nil)
		return
	}
	db.backfillProgress.Store(&fn)
}

func (db *DB) reportBackfill(current, total int64) {
	if p := db.backfillProgress.Load(); p != nil {
		(*p)(current, total)
	}
}

// Sample is a binary in the registry.
type Sample struct {
	CreatedAt       time.Time
	UpdatedAt       time.Time
	FetchedAt       *time.Time
	MarkerMtime     *time.Time
	Mtime           *time.Time
	LastErrorAt     *time.Time
	FirstAnalyzedAt *time.Time
	AnalyzedAt      *time.Time
	PURLBase        string
	Elements        string
	Package         string
	// RegistryTitle/RegistryDescription (with RegistryDownloads below) are
	// the marketplace display title, capped short description, and install
	// count from the provenance sidecar's registry record, extracted at
	// query time. Populated only by FeedSamples and SampleBySHA256.
	RegistryTitle       string
	RegistryDescription string
	// TopTraits is the JSON []TopTrait column: the sample's few strongest
	// suspicious+ trait ids, derived on every result write (PG trigger /
	// ParseCleaveResult). "" when nothing reaches the bar or for rows
	// written before the column existed (healed by backfill).
	TopTraits       string
	SHA256          string
	Filename        string
	FileType        string
	Label           string
	LabelSource     string
	Path            string
	Status          string
	Note            string
	CanonicalSHA256 string
	Parent          string
	// LocationRel is the edge type of this sample's Path observation to
	// Parent, mirroring cleave's `rel` ("", "fetched", "unpacked",
	// "registry" — see SampleLocation.Rel). It rides into sample_locations
	// only; the samples table does not store it.
	LocationRel       string
	Skip              string
	Formula           string
	Version           string
	TraitsVersion     string
	Domain            string
	URL               string
	Ecosystem         string
	Feed              string
	Source            string
	CleaveResult      []byte
	LitmusResult      []byte
	LLMResult         []byte
	Provenance        []byte
	RegistryDownloads int64
	LitmusScore       float64
	ID                int64
	SizeBytes         int64
	Score             int
	MaxCrit           int
	SuspiciousCount   int
	// Corroborated mirrors the samples.corroborated column: an external threat
	// feed has cited this sample's sha256 or purl_base. Populated by the feed
	// and detail read paths (FeedSamples / SampleBySHA256, which select the
	// registry extras); per-source detail comes from SightingsFor.
	Corroborated bool
}

// restoreJSONB reverses the write-time nulSentinel substitution on a sample's
// JSON columns, so a Sample read from the DB carries the same NUL bytes the
// analyzer emitted — the read half of the column-boundary codec whose write half
// is [sanitizeJSONB]. The TEXT columns [Sample.scrubNULs] strips are not
// restored: those NULs are irrecoverably dropped (PG TEXT cannot hold them) and
// are metadata noise, not analysis content.
func (s *Sample) restoreJSONB() {
	s.CleaveResult = restoreNULs(s.CleaveResult)
	s.LitmusResult = restoreNULs(s.LitmusResult)
	s.LLMResult = restoreNULs(s.LLMResult)
	s.Provenance = restoreNULs(s.Provenance)
}

// scrubNULs removes embedded NUL bytes (0x00) from a sample's TEXT fields.
// PostgreSQL stores text as C strings and rejects an embedded 0x00 with
// SQLSTATE 22021 ("invalid byte sequence for encoding UTF8"); a malformed
// archive member whose path or filename carries one would otherwise fail every
// INSERT/COPY for that sample — and, because the failure is deterministic, the
// worker would retry it forever. A NUL is never legitimate filesystem
// metadata, so dropping it is safe. The JSONB result columns are handled
// separately by [sanitizeJSONB]; SHA256 is validated as hex upstream.
func (s *Sample) scrubNULs() {
	fields := []struct {
		p    *string
		name string
	}{
		{&s.Source, "source"},
		{&s.Feed, "feed"},
		{&s.Ecosystem, "ecosystem"},
		{&s.Filename, "filename"},
		{&s.Label, "label"},
		{&s.LabelSource, "label_source"},
		{&s.Path, "path"},
		{&s.Status, "status"},
		{&s.Parent, "parent"},
		{&s.Skip, "skip"},
		{&s.Elements, "elements"},
		{&s.URL, "url"},
		{&s.Domain, "domain"},
		{&s.Package, "package"},
		{&s.Version, "version"},
	}
	for _, f := range fields {
		if strings.IndexByte(*f.p, 0) < 0 {
			continue
		}
		*f.p = strings.ReplaceAll(*f.p, "\x00", "")
		slog.Warn("scrubbed NUL byte from sample text field",
			"sha256", s.SHA256, "field", f.name)
	}
}

// SampleLocation is one observation of a sample at a particular path. A
// single sha256 can have many locations — the same jQuery.min.js shows up
// in thousands of npm packages, the same stub in many droppers — so path /
// source / feed / parent are per-observation, not per-content. The row is
// upsert-keyed on (sha256, path): re-observing the same pair refreshes mtime
// and any field that actually changed, and writes nothing when nothing did.
//
// LastSeenAt is no longer maintained — it is set once on insert and never
// bumped. Re-stamping it on every walk rewrote nearly the whole table each
// pass and swamped the logical replicas; see locationChangedPG. It survives
// only as a stable sort key, so treat it as "first seen", not "last seen".
type SampleLocation struct {
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
	Mtime        *time.Time
	SHA256       string
	Path         string
	ParentSHA256 string // sha of the archive this observation was extracted from; "" if top-level
	// Rel is the edge type to ParentSHA256, mirroring cleave's `rel`:
	// "" for an ordinary contained member, "fetched" for content retrieved
	// over the network from a reference the parent declares (never actually
	// inside it), "unpacked" for a transform product (UPX, base64),
	// "registry" for a provenance sidecar. "" on rows predating the column.
	Rel      string
	Filename string
	// Source records what INSERTED this row (not its collector feed, which is
	// Feed). Collector direct-inserts are "forager"/"upload"; rows hopper itself
	// materializes while ingesting the sample tree use SourceFilesystem or
	// SourceExploded. "harvest" persists on legacy pre-rename rows. Queries span
	// every Source value rather than filtering to one — see FeedQuery.Source="".
	Source    string
	Feed      string
	Ecosystem string
	ID        int64
}

// RetiredSampleLocation is an append-only record of a location removed from
// the active ledger. Managed moves and missing-file pruning retain the old
// path here so physical provenance is not lost when sample_locations changes.
//
// The embedded location must come first (an embedded field cannot be ordered
// among the plain ones), which costs 8 pointer bytes over what fieldalignment
// would pick: SampleLocation's own trailing scalar lands mid-struct here.
type RetiredSampleLocation struct { //nolint:govet // fieldalignment: see above
	SampleLocation

	RetiredAt     time.Time
	Reason        string
	SuccessorPath string
}

// Source values for rows hopper materializes itself, as distinct from a
// collector's direct insert ("forager") or an interactive upload ("upload"):
//   - SourceFilesystem: a top-level file the load-walk found on disk that no
//     collector had inserted (e.g. the bespoke bad-feed corpora, which write
//     bytes+sidecars but do not direct-insert).
//   - SourceExploded: an archive member hopper extracted; the parent lineage is
//     kept in Parent, so the member's own Source names its immediate producer.
//
// Legacy rows written before the collector rename carry "harvest"; it is not
// re-emitted. Consumers must not exclude these values — reports span all
// sources (FeedQuery.Source=="") so hopper-materialized rows are never dropped.
const (
	SourceFilesystem = "fs"
	SourceExploded   = "x"
)

// Rel is the edge type from a sample to its parent, mirroring cleave's `rel`.
// It answers one question: does the parent *contain* these bytes, or did it
// merely *point at* them?
//
// The two are routinely conflated, and every consequence of that is a bug. A
// contained member can be recovered from its parent's bytes and shares its
// provenance. A referenced artifact was fetched from somewhere else entirely —
// it carries its own identity, its own verdict, and is inside nothing.
type Rel string

const (
	// RelContained is an ordinary archive member: the parent's bytes contain it.
	RelContained Rel = ""
	// RelUnpacked is a transform product (decompressed, decoded, unpacked) —
	// derived from the parent's bytes, so still recoverable from them.
	RelUnpacked Rel = "unpacked"
	// RelFetched is content retrieved over the network from a locator the parent
	// declares. Never inside the parent.
	RelFetched Rel = "fetched"
	// RelRegistry is a provenance sidecar *about* the parent — a registry record,
	// not content the parent contains.
	RelRegistry Rel = "registry"
)

// IsContainment reports whether this edge claims the parent's bytes contain (or
// derive) the child's. Only a containment edge licenses the things containment
// implies: reassembling the child from its parent, inheriting the parent's
// label, or describing the child as "found in" that archive. A reference edge
// makes no such claim.
func (r Rel) IsContainment() bool {
	return r == RelContained || r == RelUnpacked
}

// containmentRelsSQL is [Rel.IsContainment] as a SQL literal list, for queries
// that must make the same distinction. TestContainmentRelsSQLMatchesPredicate
// asserts the two agree, so neither can drift.
const containmentRelsSQL = `('', 'unpacked')`

// uncontainedSQL matches the samples no archive contains — the artifacts that
// stand on their own and are worth judging, labelling, and listing as
// themselves. A fetched dependency qualifies: some package named it, but nothing
// contains it, and it has its own author, registry entry, and verdict.
//
// `parent = ”` alone is close but not exact: a file submitted standalone and
// later found inside an archive keeps an empty parent, because the conflict
// clauses deliberately refuse to let a member rewrite a standalone row's
// identity. (Filling parent there is not an option — handleFile routes any row
// with a parent through archive extraction, so it would stop serving bytes that
// are sitting right there on disk. See TestExplodeDoesNotClobberWalkerPath.) The
// ledger settles it, and a child can have several parents, so the ledger is the
// only place that can.
//
// Use this where the result set is bounded. The subquery costs a probe per
// candidate row, which a LIMIT-ed page can afford; uncontainedCountSQL is for
// where it cannot.
const uncontainedSQL = `parent = '' AND NOT EXISTS (
	SELECT 1 FROM sample_locations sl
	 WHERE sl.sha256 = samples.sha256
	   AND sl.parent_sha256 <> ''
	   AND sl.rel IN ` + containmentRelsSQL + `)`

// uncontainedCountSQL is uncontainedSQL for count(*), which has no LIMIT to stop
// it early: the subquery would probe the ledger once per top-level row, across a
// table headed for 500M, on every page render. It also forfeits the six partial
// indexes predicated on `parent = ”` — see idx_samples_eco_top_created, whose
// comment records that matching their constant predicates is what makes the
// count an index-only scan and the difference between sub-second and
// multi-second on a large ecosystem. A subquery can never appear in a partial
// index predicate, so precision here costs the index outright.
//
// So the count trades exactness for a bounded plan: it over-counts by the
// standalone-and-also-in-an-archive rows that uncontainedSQL excludes from the
// page itself. That population is small, the error is in the total rather than
// in what anyone reads, and the alternative is the most expensive query in the
// system. Displayed rows stay exact.
//
// Postgres only. The SQLite backend shares one WHERE between its page and count
// queries and keeps the precise form: it backs tests and small deployments,
// where the probe costs nothing and exactness is worth more than a plan. The
// divergence is a marginal over-count on Postgres, never a difference in which
// rows are returned.
const uncontainedCountSQL = `parent = ''`

// containmentColumns projects an observation onto the two samples columns that
// are containment claims rather than facts about the artifact itself:
//
//	parent — "this archive contains these bytes"
//	path   — "the bytes are at this location on disk"
//
// Only a containment edge supports either. A referenced artifact — a fetched
// dependency, a registry sidecar — was *named* by its parent, not contained by
// it: nothing can extract it from that archive, and hopper may hold no bytes for
// it at all until whoever fetched it uploads them. So both come back empty, and
// the observation is recorded in sample_locations, where every edge belongs and
// where the reference stays visible as "referenced by" rather than "found in".
//
// This is the single definition of that projection, and every writer of a
// samples row goes through it — so a reference cannot be recorded as a member by
// forgetting a rule. TestNoWriterRecordsAReferenceAsAMember covers each entry
// point; TestContainmentInvariantHolds is the standing assertion over the data.
//
// Empty columns are safe against re-observation: the ON CONFLICT clause fills
// path only when the incoming one is non-empty, so a later upload carrying real
// bytes heals the row and nothing ever blanks it back.
func containmentColumns(s *Sample) (parent, path string) {
	if !Rel(s.LocationRel).IsContainment() {
		return "", ""
	}
	return s.Parent, s.Path
}

// WorkflowSnapshot is the compact operational view used by Hopper dashboards.
type WorkflowSnapshot struct {
	Health        WorkflowHealth
	Backlogs      []WorkflowBacklog
	LatestAdded   []WorkflowSample
	LatestReady   []WorkflowSample
	OldestPending []WorkflowSample
}

// WorkflowHealth summarizes freshness and queue state across the ingest →
// analysis → Prism-ready pipeline.
type WorkflowHealth struct {
	LatestAdded    time.Time
	LatestUpdated  time.Time
	LatestAnalyzed time.Time
	LatestReady    time.Time
	PendingCleave  int64
	PendingLitmus  int64
}

// WorkflowBacklog groups pending work by source/feed/ecosystem.
type WorkflowBacklog struct {
	OldestPending time.Time
	NewestPending time.Time
	Source        string
	Feed          string
	Ecosystem     string
	PendingCleave int64
	PendingLitmus int64
}

// WorkflowSample is a light sample row for dashboard recency tables.
type WorkflowSample struct {
	CreatedAt       time.Time
	UpdatedAt       time.Time
	AnalyzedAt      *time.Time
	FirstAnalyzedAt *time.Time
	SHA256          string
	Source          string
	Feed            string
	Ecosystem       string
	Filename        string
	Path            string
	HasCleave       bool
	HasLitmus       bool
	Criticality     int
}

// Report is an analysis report produced by cyclotron.
type Report struct {
	CreatedAt  time.Time
	SHA256     string
	Type       string // "re", "gap", "fpr", "second" (completed second-opinion review; TriageSecondOpinion anti-joins on it)
	Content    string
	Provider   string
	ID         int64
	DurationMS int
}

// TopTrait is one entry in a sample's top_traits column: a suspicious-or-worse
// trait id with its criticality level. The column stores up to three as a
// compact JSON array (`[{"id":"objectives/exfil/dns-tunnel","crit":5}]`, ""
// when none reach the bar) so the feed can name a row's headline traits
// without touching the cleave blob. Derived on write by the PG trigger and by
// ParseCleaveResult for the SQLite path — keep the two in sync.
type TopTrait struct {
	ID   string          `json:"id"`
	Dep  json.RawMessage `json:"dep,omitempty"`
	Crit int             `json:"crit"`
}

// topTraitLimit caps the top_traits column at the few chips the feed renders.
const topTraitLimit = 3

// cleaveFileInfo holds per-file metadata extracted from a cleave result.
type cleaveFileInfo struct {
	Formula         string
	Elements        string
	FileType        string
	TopTraits       string // JSON []TopTrait, "" when none; see TopTrait
	Score           int
	MaxCrit         int
	SuspiciousCount int
}

// CleaveParseResult holds all metadata extracted from a single JSON parse
// of a cleave result, combining file info and canonical SHA computation.
type CleaveParseResult struct {
	CanonicalSHA  string
	RootSHA       string // depth-zero digest reported by cleave, when present and valid
	TraitsVersion string // "tv" field from compact report (first 5 chars of traits commit)
	FileInfo      cleaveFileInfo
}

type cleaveTraitEntry struct {
	ID       string          `json:"id"`
	OldID    string          `json:"i"`
	Dep      json.RawMessage `json:"dep"`
	Conf     float64         `json:"conf"`
	OldConf  float64         `json:"c"`
	Level    int             `json:"crit"`
	OldLevel int             `json:"l"`
}

type cleaveCompactFileEntry struct {
	Formula    string             `json:"mol"`
	OldFormula string             `json:"f"`
	SHA256     string             `json:"sha"`
	FileType   string             `json:"type"`
	Traits     []cleaveTraitEntry `json:"traits"` // v8
	V7Traits   []cleaveTraitEntry `json:"find"`   // v7
	OldTraits  []cleaveTraitEntry `json:"ts"`     // v4
	Score      int                `json:"risk"`
	OldScore   int                `json:"x"`
	Depth      int                `json:"depth"` // v8
	OldDepth   int                `json:"dp"`    // v7
}

// ParseCleaveResult extracts file info and canonical SHA from a cleave compact
// result in a single JSON parse. It intentionally reads only stable files[]
// metadata, accepting old fs[] keys for cached rows.
func ParseCleaveResult(sha256 string, result []byte) CleaveParseResult {
	if len(result) == 0 {
		return CleaveParseResult{CanonicalSHA: sha256}
	}
	var report struct {
		TraitsVersion    string                   `json:"rev"` // v8
		OldTraitsVersion string                   `json:"tv"`  // v7
		Files            []cleaveCompactFileEntry `json:"files"`
		OldFiles         []cleaveCompactFileEntry `json:"fs"`
	}
	if json.Unmarshal(result, &report) != nil {
		return CleaveParseResult{CanonicalSHA: sha256}
	}
	if len(report.Files) == 0 || !parsedCleaveFilesLookCompact(report.Files) {
		report.Files = report.OldFiles
	}

	// Canonical SHA: lexicographic minimum across sample and all embedded files.
	canonical := sha256
	rootSHA := ""
	for i := range report.Files {
		f := &report.Files[i]
		if len(f.SHA256) == 64 && f.SHA256 < canonical {
			canonical = f.SHA256
		}
		depth := f.Depth
		if depth == 0 {
			depth = f.OldDepth
		}
		candidate := strings.ToLower(f.SHA256)
		if rootSHA == "" && depth == 0 && isLowerHexSHA256(candidate) {
			rootSHA = candidate
		}
	}

	// File info for the matching entry.
	var fi cleaveFileInfo
	for i := range report.Files {
		f := &report.Files[i]
		if f.SHA256 != "" && !strings.EqualFold(f.SHA256, sha256) {
			continue
		}
		formula := f.Formula
		if formula == "" {
			formula = f.OldFormula
		}
		score := f.Score
		if score == 0 {
			score = f.OldScore
		}
		traits := f.Traits
		if len(traits) == 0 {
			traits = f.V7Traits
		}
		if len(traits) == 0 {
			traits = f.OldTraits
		}
		maxCrit := 0
		suspicious := 0
		var top []TopTrait
		for _, t := range traits {
			level := t.Level
			if level == 0 {
				level = t.OldLevel
			}
			if level > maxCrit {
				maxCrit = level
			}
			if level >= 4 {
				suspicious++
				if id := firstNonEmptyStr(t.ID, t.OldID); id != "" {
					top = append(top, TopTrait{ID: id, Crit: level, Dep: t.Dep})
				}
			}
		}
		fi = cleaveFileInfo{
			Formula:         formula,
			Elements:        stripSubscripts(formula),
			FileType:        f.FileType,
			TopTraits:       encodeTopTraits(top),
			Score:           score,
			MaxCrit:         maxCrit,
			SuspiciousCount: suspicious,
		}
		break
	}

	tv := report.TraitsVersion
	if tv == "" {
		tv = report.OldTraitsVersion
	}
	return CleaveParseResult{CanonicalSHA: canonical, RootSHA: rootSHA, FileInfo: fi, TraitsVersion: tv}
}

func parsedCleaveFilesLookCompact(files []cleaveCompactFileEntry) bool {
	for i := range files {
		f := &files[i]
		if f.SHA256 != "" || f.FileType != "" || f.Depth != 0 || f.OldDepth != 0 || f.Formula != "" || f.OldFormula != "" {
			return true
		}
	}
	return false
}

// parseCleaveFile extracts file info only (for callers that don't need canonical SHA).
func parseCleaveFile(sha256 string, result []byte) cleaveFileInfo {
	return ParseCleaveResult(sha256, result).FileInfo
}

// encodeTopTraits renders the top_traits column value: the highest-criticality
// entries (stable order within a level, mirroring the finding order cleave
// emitted), capped at topTraitLimit, as compact JSON — "" when none qualify.
func encodeTopTraits(top []TopTrait) string {
	if len(top) == 0 {
		return ""
	}
	slices.SortStableFunc(top, func(a, b TopTrait) int { return b.Crit - a.Crit })
	if len(top) > topTraitLimit {
		top = top[:topTraitLimit]
	}
	out, err := json.Marshal(top)
	if err != nil {
		return ""
	}
	return string(out)
}

// firstNonEmptyStr returns the first non-empty string.
func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// stripSubscripts removes Unicode subscript digits (₀-₉) from a formula,
// producing the qualitative element list.
func stripSubscripts(formula string) string {
	var b strings.Builder
	for _, r := range formula {
		if r < '₀' || r > '₉' {
			_, _ = b.WriteRune(r)
		}
	}
	return b.String()
}

// canonicalSHA returns the lexicographic minimum SHA256 across the sample
// itself and all embedded files in the cleave result. Used by collimator for
// deterministic train/test split assignment — archives sharing an inner file
// get the same canonical SHA and land in the same partition.
func canonicalSHA(sha256 string, cleaveResult []byte) string {
	canonical := sha256
	if len(cleaveResult) == 0 {
		return canonical
	}
	var report struct {
		Files []struct {
			SHA256 string `json:"sha"`
		} `json:"files"`
		OldFiles []struct {
			SHA256 string `json:"sha"`
		} `json:"fs"`
	}
	if json.Unmarshal(cleaveResult, &report) != nil {
		return canonical
	}
	if len(report.Files) == 0 {
		report.Files = report.OldFiles
	}
	for _, f := range report.Files {
		if len(f.SHA256) == 64 && f.SHA256 < canonical {
			canonical = f.SHA256
		}
	}
	return canonical
}

// ExplodeArchiveMembers parses the cleave_result of the given sample and
// inserts one row per embedded file (depth > 0). Each member inherits the
// parent's label, label_source, source, feed, and canonical_sha256. Members get
// a single-file cleave_result and a litmus_result for just their file entry.
//
// For bad archives, members without hostile risk or >1 suspicious finding
// are marked skip="skip-benign-archive-item". Duplicate SHA256s are silently skipped.
// Returns the number of new rows inserted.
// memberSamplesFromEnvelope builds the per-member sample rows embedded in an
// archive's full cleave envelope (parent.CleaveResult). Each member inherits the
// parent's label/source/feed/ecosystem/canonical and receives a single-file
// cleave result, its litmus slice, and a per-archive path. It is pure (no DB
// access) so the same members can be persisted inside the parent's store
// transaction by StoreResult, or via ExplodeArchiveMembers. parent.AnalyzedAt
// stamps each member's analyzed_at, which gates the freshness refresh on store.
func memberSamplesFromEnvelope(parent *Sample) []*Sample {
	e := newMemberEnvelope(parent)
	if e == nil {
		return nil
	}
	return e.buildRange(0, e.len())
}

// memberTrait reads a member's per-trait criticality across envelope
// generations: v8 uses crit/conf, pre-v8 used l/c.
type memberTrait struct {
	Crit    int     `json:"crit"`
	OldCrit int     `json:"l"`
	Conf    float64 `json:"conf"`
	OldConf float64 `json:"c"`
}

// memberEnvelope holds an archive's parsed cleave envelope so its members can be
// built in bounded batches rather than all at once: a large archive otherwise
// materializes every member's re-marshaled cleave slice simultaneously, several
// times the envelope size, held across the whole store. The parent litmus
// envelope is parsed once (into litmus), so per-member extraction is O(1) rather
// than the former O(N²) re-parse for every member.
type memberEnvelope struct {
	parent *Sample
	litmus *litmusMemberIndex
	files  []json.RawMessage
}

// newMemberEnvelope parses parent.CleaveResult into its member entries, applying
// the generation fallback (files/fs) and the fan-out cap. A nil result means the
// parent carries no usable envelope, hence no members.
func newMemberEnvelope(parent *Sample) *memberEnvelope {
	if len(parent.CleaveResult) == 0 {
		return nil
	}

	var report struct {
		Files    []json.RawMessage `json:"files"`
		OldFiles []json.RawMessage `json:"fs"`
	}
	if err := json.Unmarshal(parent.CleaveResult, &report); err != nil {
		slog.Warn("parse cleave result for member extraction", "parent", parent.SHA256, "error", err)
		return nil
	}
	files := report.Files
	if len(files) == 0 {
		files = report.OldFiles
	}

	// Bound the fan-out. A cleave result is worker-supplied and capped only by
	// the API body size (256 MiB), so a crafted or pathological `fs` array of
	// millions of tiny entries would otherwise materialize millions of *Sample,
	// a parallel [][]any in the batch insert, and millions of DB rows from a
	// single request — an OOM / DB-pollution lever. The cap is far above any
	// real archive's analyzed member count; truncation is logged so a genuine
	// archive that ever approaches it is visible rather than silently clipped.
	if len(files) > maxArchiveMembers {
		slog.Warn("archive explosion truncated: member count exceeds cap",
			"parent", parent.SHA256, "reported", len(files), "cap", maxArchiveMembers)
		files = files[:maxArchiveMembers]
	}
	return &memberEnvelope{
		parent: parent,
		files:  files,
		litmus: newLitmusMemberIndex(parent.LitmusResult),
	}
}

// len reports the number of member entries before per-entry skips.
func (e *memberEnvelope) len() int {
	if e == nil {
		return 0
	}
	return len(e.files)
}

// buildRange builds the member samples for entries [start,end). The heavy
// per-member cleave and litmus slices are allocated here, so a caller storing in
// batches can build, persist, and release one batch at a time instead of holding
// every member at once. Entries cleave couldn't classify (no depth, bad sha, no
// type or path) are skipped, so the result may be shorter than end-start.
func (e *memberEnvelope) buildRange(start, end int) []*Sample {
	members := make([]*Sample, 0, end-start)
	for id := start; id < end; id++ {
		raw := e.files[id]
		// The members-array key was renamed across envelope generations
		// (v8 "traits", v7 "find", v4 "ts"), as were depth ("depth"/"dp") and
		// size ("size"/"sz"). Decode every generation so old envelopes still
		// explode; the cascade below prefers the newest present.
		var entry struct {
			SHA256   string `json:"sha"`
			FileType string `json:"type"`
			Path     string `json:"path"`
			// Rel is cleave's edge type to the parent: absent for an
			// ordinary contained member, "fetched" for content retrieved
			// from a reference the parent declares (never inside it),
			// "unpacked"/"registry" for transform/sidecar nodes. Carried
			// into sample_locations.rel so consumers can tell "found in
			// this archive" from "referenced by this sample".
			Rel      string        `json:"rel"`
			V8Traits []memberTrait `json:"traits"`
			V7Traits []memberTrait `json:"find"`
			V4Traits []memberTrait `json:"ts"`
			Size     int64         `json:"size"`  // v8 + v7
			V4Size   int64         `json:"sz"`    // v4
			Depth    int           `json:"depth"` // v8
			V4Depth  int           `json:"dp"`    // v4–v7
		}
		if json.Unmarshal(raw, &entry) != nil {
			continue
		}
		depth := entry.Depth
		if depth == 0 {
			depth = entry.V4Depth
		}
		if depth == 0 {
			continue // depth 0 is the container itself, not a member
		}
		traits := entry.V8Traits
		if len(traits) == 0 {
			traits = entry.V7Traits
		}
		if len(traits) == 0 {
			traits = entry.V4Traits
		}
		if entry.Size == 0 {
			entry.Size = entry.V4Size
		}
		// Cleave's hex output is conventionally lowercase, but normalize
		// here so one upstream quirk can't bifurcate the dataset.
		entry.SHA256 = strings.ToLower(entry.SHA256)
		if !isLowerHexSHA256(entry.SHA256) {
			continue
		}

		// Skip members cleave couldn't classify: they have no analytical value
		// and inserting them just pollutes the DB with rows the pipeline will
		// never usefully act on.
		if entry.FileType == "" {
			continue
		}

		// Members without an in-archive path can't be given a meaningful
		// location, so drop them rather than inserting rows with empty path.
		if entry.Path == "" {
			continue
		}

		// Count suspicious+ findings with sufficient confidence for skip logic.
		maxLevel := 0
		suspiciousCount := 0
		for _, t := range traits {
			level := t.Crit
			if level == 0 {
				level = t.OldCrit
			}
			if level > maxLevel {
				maxLevel = level
			}
			if level >= 4 { // suspicious+
				suspiciousCount++
			}
		}

		// A member's label and skip are inherited from the archive: shipping
		// inside a bad package is evidence about the member, and an unremarkable
		// member of one is not worth queueing on its own. Neither argument
		// survives a reference edge. A package naming a dependency says nothing
		// about that dependency's contents — the dependency has its own author,
		// its own registry entry, and its own verdict, and inheriting "bad" here
		// is how a benign library ends up labelled hostile because something
		// hostile depended on it. A referenced artifact stays unlabelled until it
		// is judged on its own bytes — which means labelUnknown, the no-claims
		// pool the triage queues select, and NOT "". An empty label is invisible
		// to every selector (they match 'bad'/'good'/'unknown'/'sighted'
		// exactly), so writing "" here is what would keep the dependency from
		// ever being judged at all. It is also unrecoverable: labelRank scores
		// "" and 'unknown' both 0, and the upsert only promotes on a strictly
		// greater rank, so a later insert carrying 'unknown' cannot heal it.
		containment := Rel(entry.Rel).IsContainment()
		label, labelSource := labelUnknown, ""
		skip := ""
		if containment {
			label, labelSource = e.parent.Label, e.parent.LabelSource
			if e.parent.Label == "bad" && maxLevel < 5 && suspiciousCount <= 1 {
				skip = skipBenignArchiveItem
			}
		}

		singleFile, err := json.Marshal(struct {
			Files []json.RawMessage `json:"files"`
		}{Files: []json.RawMessage{raw}})
		if err != nil {
			continue
		}

		// Cleave emits entry.Path with "!!" as the archive-boundary
		// delimiter. We adopt the same delimiter end-to-end so stored
		// paths preserve cleave's format; the only transformation is
		// replacing cleave's absolute archive prefix with our own
		// relativized parent.Path. Shape:
		//   cleave dp=1  "/abs/foo.tgz!!pkg/index.js"
		//   stored       "bad/foo.tgz!!pkg/index.js"
		// For dp>=2 cleave's prefix is already relative and may contain
		// extra "!"/"!!" layers; we still substitute parent.Path on the
		// left so the outer archive is identified unambiguously.
		inArchive := entry.Path
		if idx := strings.LastIndex(inArchive, "!!"); idx >= 0 {
			inArchive = inArchive[idx+2:]
		}
		memberPath := inArchive
		if e.parent.Path != "" {
			memberPath = e.parent.Path + "!!" + inArchive
		}

		firstAnalyzedAt := e.parent.FirstAnalyzedAt
		if firstAnalyzedAt == nil {
			firstAnalyzedAt = e.parent.AnalyzedAt
		}
		members = append(members, &Sample{
			SHA256:          entry.SHA256,
			Source:          SourceExploded, // hopper extracted this row; parent lineage is in Parent
			Feed:            e.parent.Feed,
			Ecosystem:       e.parent.Ecosystem,
			Filename:        inArchive,
			FileType:        entry.FileType,
			SizeBytes:       entry.Size,
			Label:           label,
			LabelSource:     labelSource,
			Path:            memberPath,
			CleaveResult:    singleFile,
			LitmusResult:    e.litmus.forMember(id),
			CanonicalSHA256: e.parent.CanonicalSHA256,
			Parent:          e.parent.SHA256,
			LocationRel:     entry.Rel,
			Skip:            skip,
			AnalyzedAt:      e.parent.AnalyzedAt,
			FirstAnalyzedAt: firstAnalyzedAt,
		})
	}

	return members
}

// ExplodeArchiveMembers persists an archive's members out-of-band. StoreResult
// now does this atomically with the parent write, so this remains only for
// callers that re-derive members from an already-stored parent (and tests). It
// inserts new members and refreshes any whose stored analysis this archive's
// supersedes. Returns the number of new rows inserted.
func (db *DB) ExplodeArchiveMembers(ctx context.Context, parent *Sample) (int64, error) {
	members := memberSamplesFromEnvelope(parent)
	if len(members) == 0 {
		return 0, nil
	}
	n, _, err := db.InsertSampleBatch(ctx, members)
	if err != nil {
		return n, err
	}
	if _, rerr := db.RefreshStaleMemberAnalysis(ctx, members); rerr != nil {
		slog.Warn("refresh stale member analysis failed", "parent", parent.SHA256, "error", rerr)
	}
	return n, nil
}

// RefreshStaleMemberAnalysis updates existing sample rows whose stored analysis
// predates the supplied members', so a newer archive's richer per-member
// analysis supersedes a stale standalone (or earlier-archive) result that
// InsertSampleBatch's ON CONFLICT leaves frozen. Only cleave_result,
// litmus_result, and analyzed_at move, and only strictly forward in time;
// label/path/skip are never touched (that stays the walker clause's job).
// Members carrying no analysis or no analysis date are skipped, so a refresh can
// never blank an existing result. Returns the number of rows refreshed.
func (db *DB) RefreshStaleMemberAnalysis(ctx context.Context, members []*Sample) (int64, error) {
	rows := make([]staleRefresh, 0, len(members))
	for _, m := range members {
		if m == nil || m.SHA256 == "" || len(m.CleaveResult) == 0 || m.AnalyzedAt == nil {
			continue
		}
		// Only a containment member's analysis is a refinement of the archive's
		// own. What this pushes is a single-file slice of the parent's report,
		// which for a contained member is the whole story. A referenced artifact
		// has its own standalone report — for a dependency that is itself an
		// archive, an entire member tree — and overwriting it with a one-node
		// stub would erase that analysis and re-derive max_crit and
		// suspicious_count from the stub, dropping the dependency out of the
		// triage queues that select on them.
		if !Rel(m.LocationRel).IsContainment() {
			continue
		}
		rows = append(rows, staleRefresh{
			SHA256:       m.SHA256,
			CleaveResult: m.CleaveResult,
			LitmusResult: m.LitmusResult,
			AnalyzedAt:   *m.AnalyzedAt,
		})
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if db.pool != nil {
		n, err := db.refreshStaleMemberAnalysisPG(ctx, rows)
		if err == nil {
			db.forgetSamples(members)
		}
		return n, err
	}
	n, err := db.refreshStaleMemberAnalysisSQLite(ctx, rows)
	if err == nil {
		db.forgetSamples(members)
	}
	return n, err
}

// staleRefresh is one row's freshness-gated analysis refresh: the content to
// write and the analysis time that must beat the stored row's to win.
type staleRefresh struct {
	AnalyzedAt   time.Time
	SHA256       string
	CleaveResult []byte
	LitmusResult []byte
}

// litmusMemberIndex holds a parent litmus envelope parsed once so each member's
// slice can be extracted in O(1). Re-parsing the whole envelope per member (the
// former behavior) is O(N²) over an archive's members — a transient-allocation
// firehose for large archives. A nil *litmusMemberIndex is valid and yields nil
// for every member.
type litmusMemberIndex struct {
	meta    map[string]json.RawMessage // envelope-level metadata applied to every member
	byID    map[int]map[string]json.RawMessage
	byIndex []map[string]json.RawMessage
}

// newLitmusMemberIndex parses a parent litmus envelope into its per-member
// entries. An empty or unparseable envelope yields nil (a valid, all-nil index).
func newLitmusMemberIndex(parent []byte) *litmusMemberIndex {
	if len(parent) == 0 {
		return nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(parent, &envelope); err != nil {
		return nil
	}
	rawFiles := envelope["files"]
	if len(rawFiles) == 0 {
		rawFiles = envelope["fs"]
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(rawFiles, &files); err != nil {
		return nil
	}
	idx := &litmusMemberIndex{meta: envelope, byIndex: files}
	for _, f := range files {
		var got int
		if err := json.Unmarshal(f["id"], &got); err != nil {
			continue
		}
		if idx.byID == nil {
			idx.byID = make(map[int]map[string]json.RawMessage, len(files))
		}
		if _, exists := idx.byID[got]; !exists {
			idx.byID[got] = f // first entry wins, matching the former linear scan
		}
	}
	return idx
}

// forMember returns the litmus slice for the member at id, preferring an entry
// whose "id" field matches and falling back to the positional entry. Returns nil
// when there is no such member or it carries no findings.
func (idx *litmusMemberIndex) forMember(id int) []byte {
	if idx == nil {
		return nil
	}
	member := idx.byID[id]
	if member == nil && id >= 0 && id < len(idx.byIndex) {
		member = idx.byIndex[id]
	}
	if member == nil || len(member["prob"]) == 0 {
		return nil
	}

	out := make(map[string]json.RawMessage, len(member)+4)
	// Pass through envelope-level metadata that applies to every member.
	// `lvl` is the per-100M severity level. For older
	// litmus outputs we also carry `level`/`threshold`/`thresholds` so
	// already-stored results stay readable; these are no-ops on v2 envelopes.
	for _, key := range []string{"v", "version", "thresholds", "threshold", "level", "lvl", "l", "conf", "analyzed_at"} {
		if v := idx.meta[key]; len(v) != 0 {
			out[key] = v
		}
	}
	maps.Copy(out, member)
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// MaxMemberLitmusClass returns the highest [LitmusClass] across an envelope's
// per-member entries, falling back to the envelope's own class when it carries
// no member array.
//
// This is the question TriageHighest's population actually asks. That selector
// keys on a hot MEMBER's litmus_class but returns the member's ROOT ARCHIVE, so
// a consumer holding a fresh scan of the archive cannot answer "does this still
// belong in the queue" from the envelope-level class alone -- the archive
// aggregate is not the member's class. Taking the max over members restores the
// predicate: the archive qualifies while any member still scores hostile.
//
// Each member is resolved through the same merge forMember performs, so a member
// carrying no class of its own inherits the envelope's level exactly as it would
// when stored -- keeping this in lockstep with what the DB column would hold.
func MaxMemberLitmusClass(envelope []byte) int {
	idx := newLitmusMemberIndex(envelope)
	if idx == nil {
		return LitmusClass(envelope)
	}
	seen := false
	best := 0
	consider := func(slice []byte) {
		if len(slice) == 0 {
			return
		}
		seen = true
		if c := LitmusClass(slice); c > best {
			best = c
		}
	}
	for i := range idx.byIndex {
		consider(idx.forMember(i))
	}
	for id := range idx.byID {
		consider(idx.forMember(id))
	}
	if !seen {
		return LitmusClass(envelope)
	}
	return best
}

// litmusResultForMember extracts a single member's litmus slice. It is a
// single-shot wrapper over litmusMemberIndex; callers exploding many members
// should build the index once (memberEnvelope does) to amortize the parse.
func litmusResultForMember(parent []byte, id int) []byte {
	return newLitmusMemberIndex(parent).forMember(id)
}

func cleaveFileIndexForSHA(result []byte, sha256 string) (int, bool) {
	var report struct {
		Files []struct {
			SHA256 string `json:"sha"`
		} `json:"files"`
		OldFiles []struct {
			SHA256 string `json:"sha"`
		} `json:"fs"`
	}
	if json.Unmarshal(result, &report) != nil {
		return 0, false
	}
	if len(report.Files) == 0 {
		report.Files = report.OldFiles
	}
	for i, f := range report.Files {
		if strings.EqualFold(f.SHA256, sha256) {
			return i, true
		}
	}
	return 0, false
}

// SetSkip sets the training-exclusion reason on a sample.
// Pass "" to clear.
func (db *DB) SetSkip(ctx context.Context, sha256, skip string) error {
	if db.pool != nil {
		return db.writeSHA(sha256, db.setSkipPG(ctx, sha256, skip))
	}
	return db.writeSHA(sha256, db.setSkipSQLite(ctx, sha256, skip))
}

// MaxClaimAttempts is the number of times a pending sample may be handed to a
// worker without producing a result before ReapStuck skips it as poison. The
// Tier-1 claim queries also stop offering a sample once it reaches this count,
// so a wedging sample can't keep burning worker capacity while it waits to be
// reaped.
const MaxClaimAttempts = 8

// Unexported alias so the claim queries in pg.go / sqlite.go can reference the
// threshold without the package qualifier.
const maxClaimAttempts = MaxClaimAttempts

// IncrementAttempts bumps the claim-attempt counter for the given samples. It
// does not touch updated_at — a claim is not progress. Called from /api/next
// with the batch a worker just claimed.
func (db *DB) IncrementAttempts(ctx context.Context, shas []string) error {
	var err error
	if db.pool != nil {
		err = db.incrementAttemptsPG(ctx, shas)
	} else {
		err = db.incrementAttemptsSQLite(ctx, shas)
	}
	if err == nil {
		db.forgetSHAs(shas)
	}
	return err
}

// ShasWithProvenance returns the subset of shas whose sample row carries a
// provenance sidecar (a non-null provenance column), as a set for O(1) lookup.
// Used by the claim path to stamp ClaimJob.HasProvenance so a worker fetches a
// sample's registry record only when one exists. A sample with provenance but no
// registry slot is a tolerated false positive — the worker simply finds no
// record — so this stays one cheap presence check rather than a JSONB path probe
// whose syntax differs across backends.
func (db *DB) ShasWithProvenance(ctx context.Context, shas []string) (map[string]bool, error) {
	if len(shas) == 0 {
		return map[string]bool{}, nil
	}
	if db.pool != nil {
		return db.shasWithProvenancePG(ctx, shas)
	}
	return db.shasWithProvenanceSQLite(ctx, shas)
}

// ReapStuck marks pending samples claimed MaxClaimAttempts or more times
// without a result as skip='stuck', removing them from the pending pool.
// Returns the number reaped.
func (db *DB) ReapStuck(ctx context.Context) (int64, error) {
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.reapStuckPG(ctx, maxClaimAttempts)
	} else {
		n, err = db.reapStuckSQLite(ctx, maxClaimAttempts)
	}
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// MaxJobBytes is the largest sample any scan worker will analyze (workers
// advertise the same value as max_bytes on /api/next and reject anything
// larger). Kept in sync with MAX_JOB_BYTES in scan's worker.
const MaxJobBytes = 16 * 1024 * 1024 * 1024

// ReapOversized marks pending samples larger than MaxJobBytes as
// skip='oversized'. Every worker filters its claims to max_bytes ≤ MaxJobBytes,
// so such samples would otherwise sit in the pending pool forever without ever
// being handed out. Returns the number reaped.
func (db *DB) ReapOversized(ctx context.Context) (int64, error) {
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.reapOversizedPG(ctx, MaxJobBytes)
	} else {
		n, err = db.reapOversizedSQLite(ctx, MaxJobBytes)
	}
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// SampleLocationKey identifies one (sha256, path) standalone file.
type SampleLocationKey struct {
	SHA256 string
	Path   string
}

// StartWalkStaging empties walk_staging at the start of a full walk. The walk
// then streams every standalone file it sees into the table via StageLocations,
// and ReconcilePools anti-joins it against samples to find moved/missing files.
func (db *DB) StartWalkStaging(ctx context.Context) error {
	if db.pool != nil {
		return db.startWalkStagingPG(ctx)
	}
	return db.startWalkStagingSQLite(ctx)
}

// StageLocations records (sha256, path) standalone files seen in the current
// walk into walk_staging. Cheap append-only inserts (PG: UNLOGGED, no WAL),
// replacing the per-file last_seen_at UPDATE that previously cost millions of
// indexed writes per walk.
func (db *DB) StageLocations(ctx context.Context, keys []SampleLocationKey) error {
	if len(keys) == 0 {
		return nil
	}
	if db.pool != nil {
		return db.stageLocationsPG(ctx, keys)
	}
	return db.stageLocationsSQLite(ctx, keys)
}

// DeleteSample removes a single sample by SHA256. Returns nil even if no
// row matched (idempotent, like a DELETE with a WHERE clause).
func (db *DB) DeleteSample(ctx context.Context, sha256 string) error {
	var err error
	if db.pool != nil {
		err = db.deleteSamplePG(ctx, sha256)
	} else {
		err = db.deleteSampleSQLite(ctx, sha256)
	}
	return db.writeSHA(sha256, err)
}

// PurgeUnsupported deletes all samples that were analyzed but for which
// cleave produced no recognized file type — rows that slipped past
// ingest-time classification and carry no analytical value. Returns the
// number of rows deleted. When dryRun is true, the query runs as a
// SELECT count(*) and no rows are removed.
//
// Uses the idx_samples_file_type index, so it's cheap even on large tables.
func (db *DB) PurgeUnsupported(ctx context.Context, dryRun bool) (int64, error) {
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.purgeUnsupportedPG(ctx, dryRun)
	} else {
		n, err = db.purgeUnsupportedSQLite(ctx, dryRun)
	}
	if err == nil && !dryRun && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// CleanupStage identifies a category of dead-end samples — records whose
// skip marker means they can never be re-analyzed (missing on disk, lost
// path, corrupt, encrypted) or have been superseded. Predicates are
// compile-time constants; callers select a stage by name, so no caller
// input is ever interpolated into SQL.
type CleanupStage struct {
	Name        string
	Description string
	predicate   string // SQL fragment applied to the samples table
}

// CleanupStages lists cleanup categories from largest/most-confidently-dead
// to smallest/edge-case. Keep the order stable: the CLI walks it in this
// order and users may rely on it when scripting with --stage.
var CleanupStages = []CleanupStage{
	{"empty_path", "samples whose original path was lost", "skip = 'empty_path'"},
	{"missing", "files marked missing from disk", "skip = 'missing'"},
	{"corrupt", "files too damaged to analyze", "skip = 'corrupt'"},
	{"encrypted", "encrypted files that will never be analyzable", "skip = 'encrypted'"},
	{"replaced", "samples superseded by a newer version", "skip = 'replaced'"},
}

// CleanupStageByName returns the stage with the given short name.
func CleanupStageByName(name string) (CleanupStage, bool) {
	for _, s := range CleanupStages {
		if s.Name == name {
			return s, true
		}
	}
	return CleanupStage{}, false
}

// CountCleanup returns how many rows a cleanup stage would delete.
func (db *DB) CountCleanup(ctx context.Context, stage CleanupStage) (int64, error) {
	if db.pool != nil {
		return db.countCleanupPG(ctx, stage)
	}
	return db.countCleanupSQLite(ctx, stage)
}

// ApplyCleanup deletes the rows matched by stage (plus their reports) in
// a single transaction. Returns the number of sample rows removed.
func (db *DB) ApplyCleanup(ctx context.Context, stage CleanupStage) (int64, error) {
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.applyCleanupPG(ctx, stage)
	} else {
		n, err = db.applyCleanupSQLite(ctx, stage)
	}
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// AppName identifies the connecting service to PostgreSQL. It lands in
// application_name, which is what pg_stat_activity, pg_stat_statements and
// log_line_prefix attribute a backend by.
//
// It is a distinct type rather than a plain string so the DSN cannot be passed
// in its place: an untyped constant ("prism") converts implicitly and reads
// naturally, while a string variable holding a DSN does not compile.
//
// Why Open requires it instead of defaulting: every service on this fleet —
// hopper, prism, promoter, forager, cyclotron, gauntlet — connects to the same
// database as the same `hopper` role. With application_name unset they are one
// undifferentiated block in pg_stat_activity. On 2026-08-21 the publisher sat
// at 90 of max_connections=100 with 64 of those idle, and there was no way to
// tell which service was holding them; the answer had to be inferred from pool
// sizes. A default here would have been silently accepted by every caller and
// left the same hole, so it is a required argument.
type AppName string

// maxAppNameBytes is PostgreSQL's NAMEDATALEN-1. Longer values are accepted by
// the server and silently truncated, which is worse than refusing them: two
// services sharing a 63-byte prefix become indistinguishable again.
const maxAppNameBytes = 63

func (a AppName) valid() error {
	switch {
	case a == "":
		return errors.New("hopper: application name is required (see hopper.AppName)")
	case len(a) > maxAppNameBytes:
		return fmt.Errorf("hopper: application name %q is %d bytes; PostgreSQL truncates at %d",
			string(a), len(a), maxAppNameBytes)
	}
	// PostgreSQL replaces non-printable and non-ASCII bytes in application_name
	// with '?', so reject them here rather than ship a name full of question marks.
	for i := range len(a) {
		if c := a[i]; c < 0x20 || c > 0x7e {
			return fmt.Errorf("hopper: application name %q has a non-printable-ASCII byte at %d", string(a), i)
		}
	}
	return nil
}

// Open connects to the registry. DSNs starting with postgres:// or
// postgresql:// use PostgreSQL; everything else is treated as a SQLite path.
// app names the calling service and is required; see AppName. It is recorded
// as application_name on PostgreSQL and ignored by the SQLite backend, which
// has no equivalent — required there too so a service cannot become anonymous
// by switching backends.
func Open(ctx context.Context, dsn string, app AppName) (*DB, error) {
	if err := app.valid(); err != nil {
		return nil, err
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return openPG(ctx, dsn, app)
	}
	return openSQLite(ctx, dsn)
}

// Close releases all connections.
func (db *DB) Close() {
	if db.pool != nil {
		db.pool.Close()
	}
	if db.lite != nil {
		if err := db.lite.Close(); err != nil {
			slog.Debug("close sqlite failed", "error", err)
		}
	}
}

// Pool returns the underlying PostgreSQL connection pool, or nil for SQLite.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// Migrate creates the schema if it does not exist.
func (db *DB) Migrate(ctx context.Context) error {
	if db.pool != nil {
		if err := db.migratePG(ctx); err != nil {
			return err
		}
	} else {
		if err := db.migrateSQLite(ctx); err != nil {
			return err
		}
	}
	return nil
}

// MigrateServing applies the migrations a server needs before it can accept
// work and returns a function that performs the remaining, deferrable
// migrations — index drops/creates and ANALYZE. The caller should run that
// function in the background after it begins serving: a missing index only
// makes queries slower, never wrong, and building one on a large table can
// take many minutes — long enough to strand workers if it blocks startup.
// The returned function retries on failure until ctx is cancelled; serving
// is more important than finishing the index work (logical-replica COPY can
// hold ACCESS SHARE for hours). On SQLite everything is applied up front
// (local databases are small and have no serving-gap concern) and the
// returned function is a no-op.
func (db *DB) MigrateServing(ctx context.Context) (func(context.Context) error, error) {
	if db.pool != nil {
		// allowRewrite is false: the serving path must never run a
		// table-rewriting migration on a populated samples table, since the
		// ACCESS EXCLUSIVE lock would freeze every reader and writer for the
		// length of the rewrite. Such a migration is deferred to `hopper init`.
		build, err := db.migrateServingPG(ctx, false)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context) error {
			return retryDeferredMigrations(ctx, build)
		}, nil
	}
	if err := db.migrateSQLite(ctx); err != nil {
		return nil, err
	}
	return func(context.Context) error { return nil }, nil
}

const (
	indexMigrationRetry    = 15 * time.Second
	indexMigrationRetryMax = 5 * time.Minute
)

// retryDeferredMigrations keeps trying index/ANALYZE DDL until it succeeds or
// the process is shutting down. Failures are logged and swallowed: the server
// is already accepting work, and a lock timeout behind replica tablesync must
// not become a crash loop.
func retryDeferredMigrations(ctx context.Context, build func(context.Context) error) error {
	backoff := indexMigrationRetry
	for attempt := 1; ; attempt++ {
		err := build(ctx)
		if err == nil {
			return nil
		}
		slog.Warn("background index migration failed; retrying (serving continues)",
			"attempt", attempt, "retry_in", backoff, "error", err)
		select {
		case <-ctx.Done():
			slog.Warn("background index migration abandoned", "error", ctx.Err(), "last_error", err)
			return nil
		case <-time.After(backoff):
		}
		if backoff < indexMigrationRetryMax {
			backoff *= 2
			if backoff > indexMigrationRetryMax {
				backoff = indexMigrationRetryMax
			}
		}
	}
}

// DeleteAll removes all rows from reports and samples, preserving the schema.
func (db *DB) DeleteAll(ctx context.Context) error {
	var err error
	if db.pool != nil {
		err = db.deleteAllPG(ctx)
	} else {
		err = db.deleteAllSQLite(ctx)
	}
	if err == nil {
		db.flushLookups()
	}
	return err
}

// InsertSample adds a sample. Duplicate SHA256 values are silently ignored.
func (db *DB) InsertSample(ctx context.Context, s *Sample) error {
	_, err := db.InsertSampleNew(ctx, s)
	return err
}

// isLowerHexSHA256 returns true if s is exactly 64 lowercase hex characters.
// SHA256 is case-insensitive by value but case-sensitive as a TEXT column,
// so enforcing a single canonical form prevents accidental UNIQUE-constraint
// bypass via mixed-case duplicates.
func isLowerHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validSample enforces the minimum fields required for a sample row to
// carry analytical value: a non-empty sha256 and a non-empty path (real or
// virtual). Empty paths are the main historical source of junk rows. Strict
// lowercase-hex enforcement on sha256 lives at the edges (API validator,
// archive explode) and at the Postgres CHECK constraint — this guard stays
// loose so tests can use short mock shas.
func validSample(s *Sample) bool {
	return s != nil && s.SHA256 != "" && s.Path != ""
}

// normalizeLabel rewrites an unset label to labelUnknown, the canonical
// no-claims value. Both mean "nothing has claimed this sample", but only
// 'unknown' is selectable: every triage query matches the four pool labels
// exactly, so a row stored as "" is invisible to all of them, to the cascade
// backfill, and to the sighted-promotion arm of relabelFromPools. Nothing
// repairs it afterwards either — labelRank scores "" and 'unknown' alike, and
// the upsert promotes only on a strictly greater rank, so a later write
// carrying 'unknown' leaves the "" in place.
//
// The column is NOT NULL DEFAULT 'unknown', but every insert names the label
// column explicitly, so the default never fires and a caller that leaves
// Sample.Label at Go's zero value writes "". This is the guard that makes the
// zero value mean what it reads as.
//
// Applied at the write boundaries rather than inside each backend's SQL, so the
// rule reads the same on both: InsertSampleNew and InsertSampleBatch cover the
// public entry points, sampleStagingRows covers the PG batch and member-staging
// paths that bypass them, and storeResultSQLite covers the SQLite member path.
func normalizeLabel(s *Sample) {
	if s != nil && s.Label == "" {
		s.Label = labelUnknown
	}
}

// InsertSampleNew adds a sample and reports whether the row was actually inserted
// (true) or was a duplicate that was silently skipped (false). Samples with an
// empty sha256 or path are rejected — callers should have derived both before
// reaching the DB layer.
func (db *DB) InsertSampleNew(ctx context.Context, s *Sample) (bool, error) {
	if !validSample(s) {
		slog.Warn("rejecting invalid sample", "sha256", s.SHA256, "path", s.Path)
		return false, nil
	}
	normalizeLabel(s)
	if db.pool != nil {
		ok, err := db.insertSampleNewPG(ctx, s)
		if err == nil {
			db.forgetSample(s)
		}
		return ok, err
	}
	ok, err := db.insertSampleNewSQLite(ctx, s)
	if err == nil {
		db.forgetSample(s)
	}
	return ok, err
}

// InsertSampleBatch inserts multiple samples in a single transaction/COPY.
// Returns the number of new rows inserted (duplicates are silently skipped).
// Much faster than calling InsertSampleNew in a loop, especially for SQLite
// where each individual INSERT acquires the single-writer lock.
// Samples failing validSample are dropped before reaching the DB; their
// count is logged at warn level so the ingest source can be traced.
func (db *DB) InsertSampleBatch(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	if len(samples) == 0 {
		return 0, nil, nil
	}
	valid := samples[:0]
	var skipped int
	for _, s := range samples {
		if !validSample(s) {
			skipped++
			continue
		}
		normalizeLabel(s)
		valid = append(valid, s)
	}
	if skipped > 0 {
		slog.Warn("dropped invalid samples from batch", "skipped", skipped, "batch", len(samples))
	}
	if len(valid) == 0 {
		return 0, nil, nil
	}
	if db.pool != nil {
		n, need, err := db.insertSampleBatchPG(ctx, valid)
		if err == nil {
			db.forgetSamples(valid)
		}
		return n, need, err
	}
	n, need, err := db.insertSampleBatchSQLite(ctx, valid)
	if err == nil {
		db.forgetSamples(valid)
	}
	return n, need, err
}

// UpsertLocation records an observation of a sample at a path. On a
// duplicate (sha256, path) pair, last_seen_at is bumped to now() and
// mtime is refreshed if the caller provided one.
func (db *DB) UpsertLocation(ctx context.Context, loc *SampleLocation) error {
	if loc == nil || loc.SHA256 == "" || loc.Path == "" {
		return nil
	}
	if db.pool != nil {
		return db.upsertLocationPG(ctx, loc)
	}
	return db.upsertLocationSQLite(ctx, loc)
}

// UpsertLocationBatch records many observations in one round-trip — the same
// upsert as UpsertLocation, applied to every row. It is the write path for a
// producer that exploded a container itself (e.g. forager unpacking an ISO) and
// needs to attach thousands of containment edges at once. Rows with an empty
// sha256 or path are dropped. As with UpsertLocation, ON CONFLICT never rewrites
// parent_sha256: a standalone (sha, path) already recorded keeps its identity, so
// a containment edge must carry its own distinct in-archive path.
func (db *DB) UpsertLocationBatch(ctx context.Context, locs []*SampleLocation) error {
	valid := locs[:0]
	for _, l := range locs {
		if l != nil && l.SHA256 != "" && l.Path != "" {
			valid = append(valid, l)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	if db.pool != nil {
		return db.upsertLocationBatchPG(ctx, valid)
	}
	return db.upsertLocationBatchSQLite(ctx, valid)
}

// PathInsideArchive returns the segment of an archive-member sample's
// stored path that follows the last "!!" separator (cleave's archive-
// member delimiter). Empty for paths without a delimiter.
func PathInsideArchive(samplePath string) string {
	idx := strings.LastIndex(samplePath, "!!")
	if idx < 0 {
		return ""
	}
	return samplePath[idx+2:]
}

// ArchivePathOf returns the on-disk archive path of a member — everything
// before the first "!!" delimiter — or "" for a top-level (non-member) path.
// The complement of PathInsideArchive; nesting is one level in practice, so the
// first delimiter is the archive boundary.
func ArchivePathOf(samplePath string) string {
	before, _, ok := strings.Cut(samplePath, "!!")
	if !ok {
		return ""
	}
	return before
}

// Errors returned by StreamArchiveMember (and the ExtractFromArchive wrapper)
// so HTTP callers can map them to status codes before any bytes are written.
var (
	// ErrArchiveMemberNotFound is returned when innerPath is absent.
	ErrArchiveMemberNotFound = errors.New("path not found in archive")
	// ErrArchiveMemberTooLarge is returned when the member exceeds maxBytes.
	ErrArchiveMemberTooLarge = errors.New("file too large")
	// ErrArchiveEncrypted is returned when an archive could not be opened or
	// decoded with any known password (almost always an encrypted sample whose
	// password is not in the list, or a corrupt archive).
	ErrArchiveEncrypted = errors.New("could not decrypt archive")
	// ErrUnsupportedArchive is returned when the container, a nested container,
	// or its compression is a type StreamArchiveMember does not handle. Wraps
	// every "unsupported …" path so the HTTP layer maps them all to 415 rather
	// than letting the nested/compression variants leak into a 500.
	ErrUnsupportedArchive = errors.New("unsupported archive")
)

func streamTarMember(r io.Reader, innerPath string, maxBytes int64, setLen func(int64), w io.Writer) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: %s", ErrArchiveMemberNotFound, innerPath)
		}
		if err != nil {
			return fmt.Errorf("tar entry: %w", err)
		}
		if !archivePathMatches(hdr.Name, innerPath) {
			continue
		}
		if hdr.Size > maxBytes {
			return fmt.Errorf("%w (>%d bytes)", ErrArchiveMemberTooLarge, maxBytes)
		}
		setLen(hdr.Size)
		if _, err := io.Copy(w, io.LimitReader(tr, hdr.Size)); err != nil {
			return fmt.Errorf("stream entry: %w", err)
		}
		return nil
	}
}

func streamZipMember(src io.ReaderAt, size int64, innerPath string, maxBytes int64, setLen func(int64), w io.Writer) error {
	zr, err := zip.NewReader(src, size)
	if err != nil {
		return fmt.Errorf("zip open: %w", err)
	}
	for _, f := range zr.File {
		if !archivePathMatches(f.Name, innerPath) {
			continue
		}
		if maxBytes >= 0 && f.UncompressedSize64 > uint64(maxBytes) {
			return fmt.Errorf("%w (>%d bytes)", ErrArchiveMemberTooLarge, maxBytes)
		}
		if f.UncompressedSize64 > math.MaxInt64 {
			return fmt.Errorf("%w (>%d bytes)", ErrArchiveMemberTooLarge, maxBytes)
		}
		n := int64(f.UncompressedSize64)
		// Stored entries are raw bytes in the archive: copy the file region
		// directly so io.Copy to a TCP socket uses sendfile(2). io.LimitReader
		// over an *os.File is recognised by the kernel-copy fast path; a
		// bytes.Reader (tests) falls through to the generic copy below.
		if file, ok := src.(*os.File); ok && f.Method == zip.Store {
			if off, derr := f.DataOffset(); derr == nil {
				if _, serr := file.Seek(off, io.SeekStart); serr == nil {
					setLen(n)
					if _, cerr := io.Copy(w, io.LimitReader(file, n)); cerr != nil {
						return fmt.Errorf("stream entry: %w", cerr)
					}
					return nil
				}
			}
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("zip entry open: %w", err)
		}
		setLen(n)
		_, cerr := io.Copy(w, io.LimitReader(rc, n))
		_ = rc.Close() //nolint:errcheck // read-only stream, close error ignored
		if cerr != nil {
			return fmt.Errorf("stream entry: %w", cerr)
		}
		return nil
	}
	return fmt.Errorf("%w: %s", ErrArchiveMemberNotFound, innerPath)
}

// ExtractFromArchive is a buffering convenience wrapper over
// StreamArchiveMember for callers that want the member as a byte slice (it
// holds only the single member in memory, never the whole archive). The hot
// download path uses StreamArchiveMember directly.
func ExtractFromArchive(archive []byte, fileType, innerPath string, maxBytes int64) ([]byte, error) {
	var buf bytes.Buffer
	err := StreamArchiveMember(bytes.NewReader(archive), int64(len(archive)), fileType, innerPath, maxBytes, func(n int64) {
		buf.Grow(int(n))
	}, &buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// archivePathMatches accepts an exact match or a match after stripping the
// conventional one-level "package/" or "./" prefix that npm/pypi archives
// wrap their content in. Cleave records the post-strip path so the inner-
// path string we get rarely matches the in-archive header verbatim.
func archivePathMatches(headerName, want string) bool {
	headerName = strings.TrimPrefix(headerName, "./")
	if headerName == want {
		return true
	}
	if _, rest, ok := strings.Cut(headerName, "/"); ok && rest == want {
		return true
	}
	return false
}

// LocationsForSHA returns every known observation of the given sample,
// most recently seen first. Empty slice (not error) when unknown.
func (db *DB) LocationsForSHA(ctx context.Context, sha256 string) ([]*SampleLocation, error) {
	if db.pool != nil {
		return db.locationsForSHAPG(ctx, sha256)
	}
	return db.locationsForSHASQLite(ctx, sha256)
}

// TopLevelLocationsForSHA returns the active on-disk locations for sha256.
// Archive-member observations are excluded because their paths are virtual.
func (db *DB) TopLevelLocationsForSHA(ctx context.Context, sha256 string) ([]*SampleLocation, error) {
	if db.pool != nil {
		return db.topLevelLocationsForSHAPG(ctx, sha256)
	}
	return db.topLevelLocationsForSHASQLite(ctx, sha256)
}

// RetiredLocationsForSHA returns location-retirement events newest first.
func (db *DB) RetiredLocationsForSHA(ctx context.Context, sha256 string) ([]*RetiredSampleLocation, error) {
	if db.pool != nil {
		return db.retiredLocationsForSHAPG(ctx, sha256)
	}
	return db.retiredLocationsForSHASQLite(ctx, sha256)
}

// PromotePrimaryLocation replaces a stale canonical path with a known active
// top-level location. The old path predicate makes this a compare-and-swap, so
// a concurrent move or walk cannot be overwritten by a serving request.
func (db *DB) PromotePrimaryLocation(ctx context.Context, sha256, oldPath, newPath string) (bool, error) {
	var ok bool
	var err error
	if db.pool != nil {
		ok, err = db.promotePrimaryLocationPG(ctx, sha256, oldPath, newPath)
	} else {
		ok, err = db.promotePrimaryLocationSQLite(ctx, sha256, oldPath, newPath)
	}
	if err == nil {
		db.forgetSHA(sha256)
	}
	return ok, err
}

// ReactivatePrimaryLocation restores a physically verified canonical path that
// was previously marked or pruned as missing. If prune retired the active row,
// its latest metadata is copied back from the append-only history ledger.
func (db *DB) ReactivatePrimaryLocation(ctx context.Context, sha256, path string) (bool, error) {
	var ok bool
	var err error
	if db.pool != nil {
		ok, err = db.reactivatePrimaryLocationPG(ctx, sha256, path)
	} else {
		ok, err = db.reactivatePrimaryLocationSQLite(ctx, sha256, path)
	}
	if err == nil {
		db.forgetSHA(sha256)
	}
	return ok, err
}

// OldestIncomingLocations returns top-level files in the hot incoming/ pool,
// oldest mtime first. before provides a finalization grace period and limit
// bounds each drain batch. Rows without an mtime are omitted until the next
// filesystem walk refreshes them.
func (db *DB) OldestIncomingLocations(ctx context.Context, before time.Time, limit int) ([]*SampleLocation, error) {
	if limit <= 0 {
		return nil, nil
	}
	if db.pool != nil {
		return db.oldestIncomingLocationsPG(ctx, before, limit)
	}
	return db.oldestIncomingLocationsSQLite(ctx, before, limit)
}

func (db *DB) prepareLocationMove(
	ctx context.Context, sha256, oldRel, newRel string, relabel *LocationRelabel,
) (bool, error) {
	var ok bool
	var err error
	if db.pool != nil {
		ok, err = db.prepareLocationMovePG(ctx, sha256, oldRel, newRel, relabel)
	} else {
		ok, err = db.prepareLocationMoveSQLite(ctx, sha256, oldRel, newRel, relabel)
	}
	if err == nil {
		db.forgetSHA(sha256)
	}
	return ok, err
}

func (db *DB) finishLocationMove(ctx context.Context, sha256, oldRel, newRel string) (bool, error) {
	var ok bool
	var err error
	if db.pool != nil {
		ok, err = db.finishLocationMovePG(ctx, sha256, oldRel, newRel)
	} else {
		ok, err = db.finishLocationMoveSQLite(ctx, sha256, oldRel, newRel)
	}
	if err == nil {
		db.forgetSHA(sha256)
	}
	return ok, err
}

// PruneSafetyExceeded is returned by PruneMissingLocations when the
// number of rows that would be deleted exceeds the maxFraction safety
// cap. The error carries the counts so the caller can decide whether
// to retry with force=true after a sanity check.
type PruneSafetyExceeded struct { //nolint:errname // follows context.DeadlineExceeded convention
	Total       int     // total sample_locations rows under the data root
	Victims     int     // rows whose path no longer exists
	MaxFraction float64 // configured safety cap, e.g. 0.40
}

func (e *PruneSafetyExceeded) Error() string {
	pct := 0.0
	if e.Total > 0 {
		pct = 100 * float64(e.Victims) / float64(e.Total)
	}
	return fmt.Sprintf(
		"hopper: prune would remove %d of %d rows (%.1f%%) which exceeds %.0f%% safety cap",
		e.Victims, e.Total, pct, e.MaxFraction*100,
	)
}

// PruneMissingLocations removes sample_locations rows whose path no longer
// exists on disk. Walks every location row and stats each path; removes
// rows where stat returns ENOENT. Other stat errors (permission, etc) are
// logged but the row is preserved.
//
// Refuses to proceed if the planned prune exceeds maxFraction of the rows
// under dataRoot, returning *PruneSafetyExceeded without modifying the
// database. Pass maxFraction=1.0 (or higher) to disable the safety check.
//
// Use after migrating files to a new layout, or any operation that moves
// files outside the normal hopper-load lifecycle. Safe to interrupt — runs
// in batches so a kill at the wrong moment leaves a partial prune at worst.
//
// Returns the number of rows removed.
func (db *DB) PruneMissingLocations(ctx context.Context, dataRoot string, maxFraction float64) (int, error) {
	if dataRoot == "" {
		return 0, errors.New("hopper: PruneMissingLocations requires a non-empty dataRoot")
	}
	if maxFraction <= 0 {
		return 0, errors.New("hopper: PruneMissingLocations requires maxFraction > 0")
	}
	absRoot, err := filepath.Abs(dataRoot)
	if err != nil {
		return 0, fmt.Errorf("hopper: resolve dataRoot: %w", err)
	}
	if db.pool != nil {
		n, err := db.pruneMissingLocationsPG(ctx, absRoot, maxFraction)
		if err == nil && n > 0 {
			db.flushLookups()
		}
		return n, err
	}
	n, err := db.pruneMissingLocationsSQLite(ctx, absRoot, maxFraction)
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// prunePathResolve resolves a stored sample_locations path to an on-disk path
// for prune. Locations store paths relative to the data root (the current
// layout), but an absolute path is still accepted and taken as-is. The result
// must stay within absRoot: a relative path that climbs out with ".." or a
// stray absolute path outside the tree returns ok=false so prune never stats —
// and therefore never deletes — a row for a file it cannot safely account for.
func prunePathResolve(absRoot, path string) (resolved string, ok bool) {
	if filepath.IsAbs(path) {
		resolved = filepath.Clean(path)
	} else {
		resolved = filepath.Join(absRoot, path)
	}
	if resolved != absRoot && !strings.HasPrefix(resolved, absRoot+string(filepath.Separator)) {
		return "", false
	}
	return resolved, true
}

// PackageVersionPresent reports whether Hopper holds a non-missing top-level
// sample for the exact package identity and version. It is a read-only probe:
// feed claims belong in the sightings ledger and do not change classification.
func (db *DB) PackageVersionPresent(ctx context.Context, purlBase, version string) (bool, error) {
	if purlBase == "" || version == "" {
		return false, nil
	}
	const pgQuery = `SELECT EXISTS (
		SELECT 1 FROM samples
		WHERE purl_base = $1 AND version = $2 AND parent = '' AND skip <> 'missing'
	)`
	if db.pool != nil {
		var present bool
		if err := db.pool.QueryRow(ctx, pgQuery, purlBase, version).Scan(&present); err != nil {
			return false, fmt.Errorf("hopper: probe package version: %w", err)
		}
		return present, nil
	}
	const sqliteQuery = `SELECT EXISTS (
		SELECT 1 FROM samples
		WHERE purl_base = ? AND version = ? AND parent = '' AND skip <> 'missing'
	)`
	var present bool
	if err := db.lite.QueryRowContext(ctx, sqliteQuery, purlBase, version).Scan(&present); err != nil {
		return false, fmt.Errorf("hopper: probe package version: %w", err)
	}
	return present, nil
}

// distinctVictimSHAs returns the unique sha256s among pruned locations, so the
// caller can mark any sample left with no surviving location as missing.
func distinctVictimSHAs(victims []pruneVictim) []string {
	seen := make(map[string]struct{}, len(victims))
	shas := make([]string, 0, len(victims))
	for _, v := range victims {
		if v.sha256 == "" {
			continue
		}
		if _, ok := seen[v.sha256]; ok {
			continue
		}
		seen[v.sha256] = struct{}{}
		shas = append(shas, v.sha256)
	}
	return shas
}

// SampleBySHA256 retrieves a sample by its hash.
// Returns ErrNotFound if no such sample exists.
func (db *DB) SampleBySHA256(ctx context.Context, sha256 string) (*Sample, error) {
	return db.lookupSampleBySHA256(ctx, sha256)
}

// SampleByPURL returns the newest analyzed top-level sample for a package
// identity. base is the version-less canonical PURL (samples.purl_base);
// version, when non-empty, pins samples.version. This is the point lookup
// behind GET /api/sample?purl= — not the prism feed. Returns ErrNotFound
// when nothing matches.
func (db *DB) SampleByPURL(ctx context.Context, base, version string) (*Sample, error) {
	if base == "" {
		return nil, ErrNotFound
	}
	return db.lookupSampleByPURL(ctx, base, version)
}

// ProvenanceBySHA256 returns just the provenance sidecar bytes for a sample,
// without loading the heavy cleave_result/litmus_result columns SampleBySHA256
// pulls (the sidecar is excluded from the sample column set for exactly that
// reason). Returns ErrNotFound when the sample is unknown, and (nil, nil) when
// it exists but carries no sidecar.
func (db *DB) ProvenanceBySHA256(ctx context.Context, sha256 string) ([]byte, error) {
	if db.pool != nil {
		return db.provenanceBySHA256PG(ctx, sha256)
	}
	return db.provenanceBySHA256SQLite(ctx, sha256)
}

// SetProvenance writes the provenance sidecar for an existing sample, replacing
// whatever provenance the row carried, without touching the sample's bytes, path,
// label, or analysis. Reports whether a row matched — false when the sample is
// absent. Any merge policy (e.g. preserving a prior discovery wrapper while
// refreshing the registry snapshot, via [Sidecar.MergeRefresh]) is the caller's
// responsibility; this is the unconditional write. Scalar identity columns are
// filled only where currently empty, so a refresh never blanks a populated one.
func (db *DB) SetProvenance(ctx context.Context, s *Sample) (bool, error) {
	var ok bool
	var err error
	if db.pool != nil {
		ok, err = db.setProvenancePG(ctx, s)
	} else {
		ok, err = db.setProvenanceSQLite(ctx, s)
	}
	if err == nil {
		db.forgetSample(s)
	}
	return ok, err
}

// knownRetrievableSQL narrows a sha match to the rows whose bytes hopper can
// actually produce. Shared by both backends so the two can never disagree about
// what "known" means; appended to a query whose samples table is aliased `s`.
const knownRetrievableSQL = `
	  AND s.path <> ''
	  AND s.skip <> 'missing'
	  AND (s.parent = '' OR EXISTS (
	        SELECT 1 FROM sample_locations sl
	         WHERE sl.sha256 = s.sha256
	           AND sl.parent_sha256 <> ''
	           AND sl.rel IN ` + containmentRelsSQL + `))`

// triageServablePathSQL excludes samples whose bytes hopper cannot serve.
// Reference edges (rel=registry / rel=fetched) deliberately leave samples.path
// empty via [containmentColumns] — there is nothing on disk and nothing to
// extract — and without this filter triage queues hand those SHAs to cyclotron,
// which HEAD-probes /api/file and logs a permanent "outside allowed directories"
// WARN for every one. Unaliased samples rows only; aliased forms spell
// `<alias>.path <> ”` inline. Partial indexes that back these selectors must
// carry the same predicate or the planner will not match them.
const triageServablePathSQL = ` AND path <> ''`

// KnownSHA256 returns the subset of the given digests whose bytes hopper can
// actually produce, so a bulk producer (a remote forager, a scanner) skips
// transferring only what hopper genuinely holds. Order is unspecified; treat
// the result as a set. Callers must bound the input size; the API edge caps it.
//
// "Known" means retrievable, not merely present as a row — the question the
// caller is really asking. A row alone is not evidence of bytes: explode writes
// rows for content it never stored, so answering from row existence made hopper
// claim artifacts it had never held, and the producer that would have supplied
// them was told not to bother. The two arms mirror how [handleFile] serves
// bytes: a top-level row from its own path on disk, a member by extraction from
// the archive that contains it.
//
// Deliberately conservative. A false "known" loses the bytes permanently; a
// false "unknown" costs one redundant upload. Only the cheap mistake is
// acceptable, so anything hopper cannot justify is reported unknown: rows with
// no path, rows already marked missing, and rows whose only tie to a parent is
// a reference edge — a dependency was never inside the package that named it,
// so there is nothing to extract it from.
func (db *DB) KnownSHA256(ctx context.Context, shas []string) ([]string, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	known := make([]string, 0, len(shas))

	if db.pool != nil {
		rows, err := db.pool.Query(ctx,
			`SELECT sha256 FROM samples s WHERE s.sha256 = ANY($1)`+knownRetrievableSQL, shas)
		if err != nil {
			return nil, fmt.Errorf("hopper: known sha256: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return nil, fmt.Errorf("hopper: known sha256 scan: %w", err)
			}
			known = append(known, s)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("hopper: known sha256 rows: %w", err)
		}
		return known, nil
	}

	// SQLite: an explicit placeholder list. The API edge bounds len(shas) well
	// under SQLite's bound-parameter limit, so no chunking is needed.
	placeholders := make([]string, len(shas))
	args := make([]any, len(shas))
	for i, s := range shas {
		placeholders[i] = "?"
		args[i] = s
	}
	//nolint:gosec // G202: the concatenated text is a fixed "?,?,…" placeholder list; the digests are bound parameters
	rows, err := db.lite.QueryContext(ctx,
		`SELECT sha256 FROM samples s WHERE s.sha256 IN (`+strings.Join(placeholders, ",")+`)`+knownRetrievableSQL, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: known sha256: %w", err)
	}
	defer func() { _ = rows.Close() }() //nolint:errcheck // best-effort close
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("hopper: known sha256 scan: %w", err)
		}
		known = append(known, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hopper: known sha256 rows: %w", err)
	}
	return known, nil
}

// KVGet reads a value from the internal hopper_kv table. Returns
// ErrNotFound when the key is absent.
func (db *DB) KVGet(ctx context.Context, key string) (string, error) {
	var value string
	var err error
	if db.pool != nil {
		err = db.pool.QueryRow(ctx, `SELECT value FROM hopper_kv WHERE key = $1`, key).Scan(&value)
	} else {
		err = db.lite.QueryRowContext(ctx, `SELECT value FROM hopper_kv WHERE key = ?`, key).Scan(&value)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("hopper: kv get %q: %w", key, err)
	}
	return value, nil
}

// KVSetIfAbsent inserts (key, value) into hopper_kv only when the key is
// not yet present. Concurrent callers that lose the race observe no
// error; the next KVGet returns whichever value won. Used by bootstrap
// flows that need to converge across replicas.
func (db *DB) KVSetIfAbsent(ctx context.Context, key, value string) error {
	var err error
	if db.pool != nil {
		_, err = db.pool.Exec(ctx,
			`INSERT INTO hopper_kv (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
			key, value)
	} else {
		_, err = db.lite.ExecContext(ctx,
			`INSERT INTO hopper_kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING`,
			key, value)
	}
	if err != nil {
		return fmt.Errorf("hopper: kv set %q: %w", key, err)
	}
	return nil
}

// KVSet stores an operator-supplied value, replacing any previous value.
// Generated bootstrap values should use KVSetIfAbsent so concurrent starters
// converge.
func (db *DB) KVSet(ctx context.Context, key, value string) error {
	var err error
	if db.pool != nil {
		_, err = db.pool.Exec(ctx, `
			INSERT INTO hopper_kv (key, value) VALUES ($1, $2)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value)
	} else {
		_, err = db.lite.ExecContext(ctx, `
			INSERT INTO hopper_kv (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	}
	if err != nil {
		return fmt.Errorf("hopper: kv set %q: %w", key, err)
	}
	return nil
}

// Keys and chunk size for reconcileLocationParentEdges. The done marker makes
// every boot after completion a single key read; the cursor lets a boot that
// was interrupted mid-backfill resume from where it stopped rather than
// re-scanning from the start.
const (
	locationParentBackfillDoneKey = "backfill:locations:parent:v1"
	locationParentBackfillCurKey  = "backfill:locations:parent:cursor"
	locationParentBackfillBatch   = 5000
)

// reconcileLocationParentEdges backfills sample_locations parent edges for
// archive members whose edge predates the InsertSampleBatch fan-out — the
// original one-shot table backfill ran only when sample_locations was first
// created, so members exploded in any later window where the fan-out had not
// yet shipped have a samples.parent but no edge, and would list no members
// under the locations-based read path.
//
// It is a one-time, resumable reconcile meant to run from migration. Work
// proceeds in small id-range chunks, each a single short autocommit statement,
// so even on a multi-million-row samples table it only ever takes brief
// row-level locks and never holds one long enough to block writers. ON CONFLICT
// DO NOTHING makes every chunk idempotent. A cursor records progress so an
// interrupted boot resumes; a done marker short-circuits every later call.
func (db *DB) reconcileLocationParentEdges(ctx context.Context) error {
	switch done, err := db.KVGet(ctx, locationParentBackfillDoneKey); {
	case err != nil && !errors.Is(err, ErrNotFound):
		return fmt.Errorf("hopper: backfill locations: read marker: %w", err)
	case done == "done":
		return nil
	}
	cursor := int64(0)
	if v, err := db.KVGet(ctx, locationParentBackfillCurKey); err == nil {
		if n, perr := strconv.ParseInt(v, 10, 64); perr == nil {
			cursor = n
		}
	}
	if db.pool != nil {
		return db.reconcileLocationParentEdgesPG(ctx, cursor)
	}
	return db.reconcileLocationParentEdgesSQLite(ctx, cursor)
}

// Keys and chunk size for repairReferenceParents, mirroring the location
// backfill above: a done marker so restarts are cheap no-ops, a cursor so an
// interrupted run resumes instead of restarting.
const (
	referenceParentRepairDoneKey = "repair:samples:reference-parent:v1"
	referenceParentRepairCurKey  = "repair:samples:reference-parent:cursor"
	// A window over sample_locations.id — the reference edges the repair walks,
	// not samples.id.
	referenceParentRepairBatch = 5000
)

// repairReferenceParents clears the containment columns on rows that were
// recorded as archive members but are tied to their parent only by a reference
// edge — the fetched dependencies explode used to mint before it distinguished
// the two. See [containmentColumns] for why those columns are a containment
// claim and why a reference cannot make one.
//
// The columns are insert-only under the ON CONFLICT clause (parent is not in
// its SET list), so these rows cannot heal on their own: the later upload that
// carries the artifact's real path and verdict is rejected by the clause's
// `EXCLUDED.parent = ”` guard. Left alone they stay invisible to every consumer
// that asks `parent = ”` — the bloom pool, promoter, cyclotron, and prism's
// feed — no matter how many times they are re-scanned.
//
// label is cleared with them, and safely: such a row could never have been
// curated. Promotion requires a path under a discovery tree, and hopper's triage
// refuses to relabel a row whose bytes are not on disk — a "<archive>!!<name>"
// path satisfies neither. So any label these rows carry was inherited from the
// archive that named them, and an inherited "good" is the dangerous one: left in
// place, the repair would promote a dependency nobody vouched for into the
// known-good bloom filter, and a known-good coordinate is never fetched again.
//
// Data-only: no schema change, no index rebuild, no column added. One short
// autocommit UPDATE per id window, row locks released immediately.
func (db *DB) repairReferenceParents(ctx context.Context) error {
	switch done, err := db.KVGet(ctx, referenceParentRepairDoneKey); {
	case err != nil && !errors.Is(err, ErrNotFound):
		return fmt.Errorf("hopper: repair reference parents: read marker: %w", err)
	case done == "done":
		return nil
	}
	cursor := int64(0)
	if v, err := db.KVGet(ctx, referenceParentRepairCurKey); err == nil {
		if n, perr := strconv.ParseInt(v, 10, 64); perr == nil {
			cursor = n
		}
	}
	if db.pool != nil {
		return db.repairReferenceParentsPG(ctx, cursor)
	}
	return db.repairReferenceParentsSQLite(ctx, cursor)
}

// referenceParentPredicate matches a samples row making a containment claim the
// ledger does not support: it names a parent, but no observation of it is a
// containment edge. Those are the rows explode wrote for referenced artifacts.
//
// Takes the table alias rather than hardcoding one, so a caller that needs an
// alias (the repair locks `samples s`) and one that does not (the monitor)
// share a single definition of "damaged" instead of one rewriting the other's
// SQL by string substitution.
func referenceParentPredicate(alias string) string {
	return alias + `.parent <> '' AND NOT EXISTS (
		SELECT 1 FROM sample_locations sl
		 WHERE sl.sha256 = ` + alias + `.sha256
		   AND sl.parent_sha256 <> ''
		   AND sl.rel IN ` + containmentRelsSQL + `)`
}

// ContainmentViolations counts rows whose containment columns claim more than
// the ledger supports, stopping at limit. It is the standing proof that
// [containmentColumns] is holding: zero in a healthy database, and it stays zero
// because every writer of a samples row projects through that one function.
//
// Bounded on purpose. The predicate cannot be answered from samples alone, so it
// probes the ledger per candidate row, and the candidates are every row with a
// parent — the archive members, which are most of the table. An unbounded count
// would be a heavier query than the fault it looks for. A monitor only needs to
// know whether the number is zero, so it asks for a handful and alerts on any.
//
// A non-zero result means some writer began recording references as members
// again, and the dependencies it wrote are invisible to promoter, cyclotron, and
// prism's feed until it is fixed and repairReferenceParents re-run.
func (db *DB) ContainmentViolations(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT count(*) FROM (SELECT 1 FROM samples WHERE ` + referenceParentPredicate("samples") +
		` LIMIT $1) t`
	var n int
	var err error
	if db.pool != nil {
		err = db.pool.QueryRow(ctx, q, limit).Scan(&n)
	} else {
		err = db.lite.QueryRowContext(ctx, strings.Replace(q, "$1", "?", 1), limit).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("hopper: containment violations: %w", err)
	}
	return n, nil
}

// ArchiveMember is a lightweight listing of one member of an archive: enough to
// rank and display it without loading its (potentially large) cleave/litmus
// blobs. Path is the member's location within this specific archive (from
// sample_locations), so a content-deduplicated member shows the correct path
// per containing archive. Heavy per-member data is fetched on demand by SHA via
// SamplesBySHAs.
type ArchiveMember struct {
	SHA256   string
	Path     string
	FileType string
	Score    int
	MaxCrit  int
}

// MembersByParent lists an archive's members from sample_locations — the
// authoritative archive↔member edge table, which (unlike the content-addressed
// samples.parent column) records every edge even when a member's content is
// shared across archives. It returns the top members by score (capped at limit)
// plus the total member count, joining only the light score columns so the big
// cleave/litmus blobs are never loaded here; callers fetch those on demand for
// just the members they render (see SamplesBySHAs). The parent_sha256 lookup is
// served index-only by idx_sl_parent_child.
func (db *DB) MembersByParent(ctx context.Context, parentSHA string, limit int) (members []ArchiveMember, total int, err error) {
	if parentSHA == "" || limit <= 0 {
		return nil, 0, nil
	}
	if db.pool != nil {
		return db.membersByParentPG(ctx, parentSHA, limit)
	}
	return db.membersByParentSQLite(ctx, parentSHA, limit)
}

// BadMembersByParent returns the full sample rows of an archive's bad-labeled
// members, resolved through the sample_locations edge so it also catches bad
// content shared across archives (which the content-addressed samples.parent
// column would miss). Callers that just need to find a dangerous member (e.g.
// promoter's bad-archive gate) should prefer this over MembersByParent: it
// filters to label='bad' in SQL, bounding memory to the bad-member count rather
// than materializing every member — and its cleave/litmus blobs — of an archive
// that may have an attacker-chosen number of entries.
func (db *DB) BadMembersByParent(ctx context.Context, parentSHA string) ([]*Sample, error) {
	if parentSHA == "" {
		return nil, nil
	}
	if db.pool != nil {
		return db.badMembersByParentPG(ctx, parentSHA)
	}
	return db.badMembersByParentSQLite(ctx, parentSHA)
}

// MembersWithSamplesByParent hydrates an archive's members: the top-`limit`
// members ranked by score (resolved through the sample_locations edge), plus
// linkedSHAs (members a container-level finding draws from, always included
// regardless of their standalone score), plus fallbackSHAs but only when the
// parent has no sample_locations edges at all (an un-backfilled archive).
// Order is unspecified; callers index the result by SHA.
//
// It runs two deterministic, index-driven queries rather than one clever join:
// topMemberSHAsByParent resolves the SHA set off the indexed sample_locations
// edge (reading only sha256), then SamplesBySHAs loads the full rows via
// `sha256 = ANY(...)`, which is always a primary-key scan. The earlier
// single-query form OR-ed these three SHA sets in the WHERE, which let the
// planner seq-scan the whole (~5M-row) samples table to find ~25 rows — the
// archive detail page's 30–60s timeout. Two indexed lookups cost one extra
// round-trip and can never degrade to a scan.
func (db *DB) MembersWithSamplesByParent(ctx context.Context, parentSHA string, limit int, linkedSHAs, fallbackSHAs []string) ([]*Sample, error) {
	if parentSHA == "" || limit <= 0 {
		return nil, nil
	}
	topn, err := db.topMemberSHAsByParent(ctx, parentSHA, limit)
	if err != nil {
		return nil, err
	}
	wanted := make([]string, 0, len(topn)+len(linkedSHAs)+len(fallbackSHAs))
	wanted = append(wanted, topn...)
	wanted = append(wanted, linkedSHAs...)
	// The envelope fallback hydrates only when the parent has no edges yet.
	if len(topn) == 0 {
		wanted = append(wanted, fallbackSHAs...)
	}
	return db.SamplesBySHAs(ctx, wanted)
}

// topMemberSHAsByParent returns up to limit member SHAs of parentSHA, ranked by
// score (then max_crit, then path). It reads only sha256 off the indexed
// sample_locations→samples edge, so no heavy cleave/litmus blob detoasts here;
// SamplesBySHAs loads those for just the wanted set.
func (db *DB) topMemberSHAsByParent(ctx context.Context, parentSHA string, limit int) ([]string, error) {
	if db.pool != nil {
		return db.topMemberSHAsByParentPG(ctx, parentSHA, limit)
	}
	return db.topMemberSHAsByParentSQLite(ctx, parentSHA, limit)
}

// ParentRef identifies one archive a child sha was extracted from, carrying just
// the fields a "found in" backlink renders. LitmusResult is the parent's raw
// verdict blob (for the classification badge); the heavy cleave_result is never
// loaded.
type ParentRef struct {
	SHA256       string
	Filename     string // parent archive's filename
	SamplePath   string // parent archive's own path (basename fallback for Filename)
	Path         string // path of the child within this parent (from sample_locations)
	Rel          string // edge type: "" contained, "fetched"/"unpacked"/"registry" (SampleLocation.Rel)
	Feed         string // parent's feed, e.g. "osimage" — lets a renderer special-case image members
	Ecosystem    string // parent's ecosystem, e.g. the OS name for an image container
	Version      string // parent's version, e.g. an OS release — the clean value, not parsed from the filename
	Package      string // parent's package id, e.g. "netbsd/amd64" (os/edition) for an image
	AnalyzedAt   *time.Time
	LitmusResult []byte // parent's raw verdict blob; cleave_result is never loaded
}

// ParentArchivesForChild returns, in a single round-trip, the archives a child
// sha appears in: each parent's identity plus the child's path within it, most
// recently recorded first and deduplicated by parent. It replaces the per-parent
// SampleBySHA256 fan-out (an N+1 that detoasted every parent's cleave_result for
// a backlink that needs none) with one light-projection join. Capped at `limit`
// parents.
func (db *DB) ParentArchivesForChild(ctx context.Context, childSHA string, limit int) ([]ParentRef, error) {
	if childSHA == "" || limit <= 0 {
		return nil, nil
	}
	if db.pool != nil {
		return db.parentArchivesForChildPG(ctx, childSHA, limit)
	}
	return db.parentArchivesForChildSQLite(ctx, childSHA, limit)
}

// SamplesBySHAs fetches full sample rows (including cleave/litmus blobs) for the
// given SHAs in a single round-trip. Pairs with MembersByParent: list members
// cheaply, then load heavy data only for the handful actually rendered. Order is
// unspecified; callers index the result by SHA.
func (db *DB) SamplesBySHAs(ctx context.Context, shas []string) ([]*Sample, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	if db.pool != nil {
		return db.samplesBySHAsPG(ctx, shas)
	}
	return db.samplesBySHAsSQLite(ctx, shas)
}

// SampleParentInfo fetches only the fields needed by ExplodeArchiveMembers,
// avoiding the cost of reading the full row (especially the large cleave_result
// JSONB column which the caller already has).
func (db *DB) SampleParentInfo(ctx context.Context, sha256 string) (*Sample, error) {
	const cols = `sha256, path, label, label_source, source, feed, ecosystem, canonical_sha256, litmus_result, analyzed_at, first_analyzed_at`
	var s Sample
	var litmus []byte
	var analyzedAt, firstAnalyzedAt sql.NullTime
	scan := func(row interface{ Scan(...any) error }) error {
		return row.Scan(&s.SHA256, &s.Path, &s.Label, &s.LabelSource,
			&s.Source, &s.Feed, &s.Ecosystem, &s.CanonicalSHA256, &litmus, &analyzedAt, &firstAnalyzedAt)
	}
	var err error
	if db.pool != nil {
		err = scan(db.pool.QueryRow(ctx, `SELECT `+cols+` FROM samples WHERE sha256 = $1`, sha256))
	} else {
		err = scan(db.lite.QueryRowContext(ctx, `SELECT `+cols+` FROM samples WHERE sha256 = ?`, sha256))
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("hopper: sample parent info %s: %w", sha256, err)
	}
	s.LitmusResult = litmus
	if analyzedAt.Valid {
		s.AnalyzedAt = &analyzedAt.Time
	}
	if firstAnalyzedAt.Valid {
		s.FirstAnalyzedAt = &firstAnalyzedAt.Time
	}
	return &s, nil
}

// ErrRescanNotEligible is returned by RequestRescan when the SHA matches
// no top-level non-skipped sample OR when the sample was analyzed within
// the cooldown window. Callers should treat it as a soft user-facing
// error (HTTP 429 / 404), not a system failure.
var ErrRescanNotEligible = errors.New("hopper: sample not eligible for rescan")

// RequestRescan re-queues a previously-analyzed sample for Tier 0 work
// by setting rescan_priority = 2 so workers pick this row before draining
// the Tier 1 (unanalyzed) backlog. The cached cleave/litmus envelope is
// deliberately preserved — readers continue to see the prior analysis
// until UpdateCleaveResult replaces it atomically. Workers re-analyze
// from the file itself, not the cached envelope, so leaving it in place
// has no effect on correctness.
//
// cooldown is the minimum age of the existing analysis before another
// rescan is accepted; a row analyzed more recently returns
// ErrRescanNotEligible UNLESS the row is already pending a forced
// rescan, in which case the call is a no-op success (the original FIFO
// position is preserved). Cooldown is enforced in the same UPDATE as
// the state transition so a race between two operators can never
// double-queue the same SHA.
//
// Returns ErrRescanNotEligible when the sample is missing, is an archive
// child (parent is non-empty), is skipped (skip is non-empty), or fails
// the cooldown check while no rescan is pending. Returns nil on a
// successful re-queue.
func (db *DB) RequestRescan(ctx context.Context, sha256 string, cooldown time.Duration) error {
	if !isLowerHexSHA256(sha256) {
		return ErrRescanNotEligible
	}
	cutoff := time.Now().Add(-cooldown)
	if db.pool != nil {
		return db.writeSHA(sha256, db.requestRescanPG(ctx, sha256, cutoff))
	}
	return db.writeSHA(sha256, db.requestRescanSQLite(ctx, sha256, cutoff))
}

// StoreStats reports what StoreResult persisted, for logging and telemetry.
type StoreStats struct {
	Members       int   // members extracted from the archive envelope (0 = not an archive)
	MembersStored int64 // member rows inserted or freshness-refreshed in this transaction
}

// StoreResult atomically persists a worker's full analysis for a sample and,
// when the sample is an archive, all of its members — parent and members commit
// together or not at all. This replaces the previous "truncate the parent now,
// recreate members later via a best-effort async pool" design, whose member
// creation could be silently lost, leaving a truncated parent with no members
// (no content, permanent data loss). Here the parent is never truncated unless
// its members land in the same transaction.
//
// The caller is responsible for running this under a context detached from the
// client request (e.g. context.WithoutCancel) so a worker disconnect or request
// timeout cannot abort a partially-applied store; the transaction itself is
// all-or-nothing regardless.
//
// If cleave could not classify the file (FileType == ""), the row is tombstoned
// with skip='unsupported' rather than deleted. The authoritative worker analysis
// is retracting a row the cheaper ingest-time classifier (cleave iter-files)
// created, but preserving the row is what makes that safe: a non-empty skip
// drops it from the claim queue and training set (both gate on an empty skip),
// so it is no longer re-analyzed, while the row staying present lets a concurrent
// store of the same content SHA update it instead of hitting an absent-sample
// error and retrying forever. This mirrors how a worker-reported "unsupported" error is
// tombstoned, and remains the belt-and-suspenders complement to the ingest-time
// filter; a later purge-unsupported sweep reaps these.
func (db *DB) StoreResult(ctx context.Context, sha256 string, cleaveRaw, litmusML, llm []byte, parsed *CleaveParseResult, traitsVersion string) (StoreStats, error) {
	var p CleaveParseResult
	if parsed != nil {
		p = *parsed
	} else {
		p = ParseCleaveResult(sha256, cleaveRaw)
	}
	if p.FileInfo.FileType == "" {
		slog.Info("tombstoning unsupported sample (cleave returned no file type)", "sha256", sha256)
		return StoreStats{}, db.SetSkip(ctx, sha256, "unsupported")
	}
	now := time.Now().UTC()
	var stats StoreStats
	var err error
	if db.pool != nil {
		stats, err = db.storeResultPG(ctx, sha256, cleaveRaw, litmusML, llm, p, traitsVersion, now)
	} else {
		stats, err = db.storeResultSQLite(ctx, sha256, cleaveRaw, litmusML, llm, p, traitsVersion, now)
	}
	if err == nil {
		db.forgetSHA(sha256)
	}
	return stats, err
}

// UpdateCleaveResult stores analysis output for a sample.
// Pass a pre-parsed CleaveParseResult to avoid redundant JSON parsing,
// or nil to parse the result automatically.
//
// If cleave could not classify the file (fi.FileType == ""), the row is
// deleted instead of updated: an unclassified row carries no analytical
// value and only pollutes later queries. This is the belt-and-suspenders
// complement to the ingest-time filter in cleave iter-files.
func (db *DB) UpdateCleaveResult(ctx context.Context, sha256 string, result []byte, parsed *CleaveParseResult, traitsVersion string) error {
	var p CleaveParseResult
	if parsed != nil {
		p = *parsed
	} else {
		p = ParseCleaveResult(sha256, result)
	}
	if p.FileInfo.FileType == "" {
		return db.DeleteSample(ctx, sha256)
	}
	result = compactCleaveResultForStorage(result)
	if db.pool != nil {
		return db.writeSHA(sha256, db.updateCleaveResultPG(ctx, sha256, result, p.CanonicalSHA, p.FileInfo, traitsVersion))
	}
	return db.writeSHA(sha256, db.updateCleaveResultSQLite(ctx, sha256, result, p.CanonicalSHA, p.FileInfo, traitsVersion))
}

// UpdateLitmusResult stores the litmus classification envelope for a sample.
// The result should be the litmus response JSON without the embedded cleave field.
// litmus_score is a GENERATED column on samples and updates automatically from
// the new envelope — no separate score parameter needed.
func (db *DB) UpdateLitmusResult(ctx context.Context, sha256 string, result []byte) error {
	if db.pool != nil {
		return db.writeSHA(sha256, db.updateLitmusResultPG(ctx, sha256, result))
	}
	return db.writeSHA(sha256, db.updateLitmusResultSQLite(ctx, sha256, result))
}

// UpdateLLMResult stores the optional LLM interpretation (envelope `llm`) for a
// sample. The interpretation pass is gated, so most results carry none; an empty
// result clears the column to NULL so a rescan that drops the pass doesn't leave
// a stale interpretation behind.
func (db *DB) UpdateLLMResult(ctx context.Context, sha256 string, result []byte) error {
	if db.pool != nil {
		return db.writeSHA(sha256, db.updateLLMResultPG(ctx, sha256, result))
	}
	return db.writeSHA(sha256, db.updateLLMResultSQLite(ctx, sha256, result))
}

// MarkCyclotronAttempt stamps cyclotron_attempted_at = now() so the sample
// drops out of the FP/FN seed pool for seedReanalysisCooldown. Cyclotron calls
// this when it first commits to working on a sample (initial status seed) so a
// sample that resists remediation can't tight-loop through the seed queue.
func (db *DB) MarkCyclotronAttempt(ctx context.Context, sha256 string) error {
	if db.pool != nil {
		_, err := db.pool.Exec(ctx,
			`UPDATE samples SET cyclotron_attempted_at = now() WHERE sha256 = $1`, sha256)
		return db.writeSHA(sha256, err)
	}
	_, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET cyclotron_attempted_at = ? WHERE sha256 = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), sha256)
	return db.writeSHA(sha256, err)
}

// Reclassify changes a sample's label.
func (db *DB) Reclassify(ctx context.Context, sha256, label, source string) error {
	if db.pool != nil {
		return db.writeSHA(sha256, db.reclassifyPG(ctx, sha256, label, source))
	}
	return db.writeSHA(sha256, db.reclassifySQLite(ctx, sha256, label, source))
}

// CascadeLabel relabels an archive (sha256) to label/source and propagates the
// verdict to its members, returning the number of members changed. Membership
// is resolved through sample_locations (the same source of truth as
// [DB.BadMembersByParent]); labels live on the content hash, so a member shared
// by other archives shares this label globally — hence the asymmetry below.
//
// Promote (label == "good"): every member still unlabeled (unknown) follows the
// parent to good, and any member this same parent previously cascade-demoted is
// reverted to good. Members independently labeled bad are left untouched so a
// clean archive cannot whitewash content that is malicious elsewhere.
//
// Demote (label == "bad"): only unlabeled members carrying real suspicion
// (score >= [CascadeDemoteScore]) follow the parent to bad, tagged with
// [cascadeSource] so the demotion is reversible. Members already labeled good or
// bad are left untouched.
//
// Any other label updates only the parent. Each member transition is recorded
// in label_events within the same transaction as the change.
func (db *DB) CascadeLabel(ctx context.Context, sha256, label, source string) (int, error) {
	var n int
	var err error
	if db.pool != nil {
		n, err = db.cascadeLabelPG(ctx, sha256, label, source)
	} else {
		n, err = db.cascadeLabelSQLite(ctx, sha256, label, source)
	}
	if err == nil {
		db.flushLookups()
	}
	return n, err
}

// CascadeBackfillStats reports the outcome of [DB.CascadeBackfill].
type CascadeBackfillStats struct {
	BadArchives     int // bad archives with members that were processed
	GoodArchives    int // good archives with members that were processed
	MembersDemoted  int // members the bad pass demoted (or would, in dry-run)
	MembersPromoted int // members the good pass promoted or reverted to good
}

// record folds one processed archive's member count into the stats, keyed by
// the archive's label.
func (s *CascadeBackfillStats) record(label string, members int) {
	switch label {
	case labelBad:
		s.BadArchives++
		s.MembersDemoted += members
	case labelGood:
		s.GoodArchives++
		s.MembersPromoted += members
	}
}

// CascadeBackfillPending reports whether any good/bad top-level archive still
// holds an 'unknown' member — i.e. whether [DB.CascadeBackfill] has work to do.
// It is an index-assisted probe so the common "nothing to do" case is cheap.
func (db *DB) CascadeBackfillPending(ctx context.Context) (bool, error) {
	if db.pool != nil {
		return db.cascadeBackfillPendingPG(ctx)
	}
	return db.cascadeBackfillPendingSQLite(ctx)
}

// CascadeBackfill re-applies the member cascade to every already-labeled archive
// so children labeled before [DB.CascadeLabel] existed are brought into
// agreement: bad archives are processed before good ones (precedence
// bad > good > unknown), each in its own transaction. dryRun counts the members
// that would change without writing. It is idempotent and safe to re-run.
func (db *DB) CascadeBackfill(ctx context.Context, dryRun bool) (CascadeBackfillStats, error) {
	var stats CascadeBackfillStats
	var err error
	if db.pool != nil {
		stats, err = db.cascadeBackfillPG(ctx, dryRun)
	} else {
		stats, err = db.cascadeBackfillSQLite(ctx, dryRun)
	}
	if err == nil && !dryRun {
		db.flushLookups()
	}
	return stats, err
}

// Unanalyzed returns up to limit samples lacking a cleave result.
func (db *DB) Unanalyzed(ctx context.Context, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.unanalyzedPG(ctx, limit)
	}
	return db.unanalyzedSQLite(ctx, limit)
}

// ReconcileStats summarizes one reconciliation pass.
type ReconcileStats struct {
	ObservedLocations int64 // staged paths newly added to the active location ledger
	Relabeled         int64 // top-level samples whose pool label/skip changed
	MarkedMissing     int64 // standalone files gone from disk
	MarkedUnsupported int64 // standalone files present but not enumerated
	CascadedMissing   int64 // archive members orphaned by a missing parent
	Revived           int64 // members whose containing archive reappeared
}

// logRelabelSkipChange emits one Info line for a reconcile relabel that changed a
// sample's skip — the cases worth surfacing per file: a previously missing or
// unsupported sample revived by reappearing in a pool, or a sample newly in
// conflict (asserted in both good/ and bad/ at once). Plain bad<->good moves that
// leave skip unchanged are covered by the aggregate relabel count, not logged
// individually.
func logRelabelSkipChange(sha, fromLabel, toLabel, fromSkip, toSkip string) {
	switch {
	case toSkip == "" && (fromSkip == "missing" || fromSkip == "unsupported"):
		slog.Info("reconcile relabel revived sample (re-observed in pool)",
			"sha256", sha, "from_skip", fromSkip, "label", toLabel)
	case toSkip == "conflict":
		slog.Info("reconcile relabel marked conflict (in both pools)",
			"sha256", sha, "from_label", fromLabel, "from_skip", fromSkip)
	default:
		slog.Info("reconcile relabel changed skip",
			"sha256", sha, "from_label", fromLabel, "to_label", toLabel,
			"from_skip", fromSkip, "to_skip", toSkip)
	}
}

// ReconcilePools makes samples.label/skip authoritative against the current
// state of the good/ and bad/ pool directories. It runs at the end of a full
// walk and reconciles the derived label/skip cache to the truth — correcting
// the monotonic, one-observation-at-a-time approximation the insert-time upsert
// can only build mid-walk — using sample_locations as the source of truth for
// presence and containment.
//
// It does five things, in order:
//  1. Learns newly observed standalone paths, including same-inode renames that
//     the hash cache can identify without another sample upsert.
//  2. Relabels top-level samples from the pools they currently live in: a file
//     moved bad→good is demoted to good, good→bad is promoted to bad, and a file
//     asserted in both pools at once resolves to bad with skip='conflict'.
//  3. Marks standalone files not seen this walk as skip='missing' (gone) or
//     'unsupported' (present on disk but not enumerated).
//  4. Cascades skip='missing' to archive members orphaned by a missing parent —
//     unless the member is still reachable through another live archive (the
//     supply-chain case: a benign file shared with a present package survives).
//  5. Revives members whose containing archive reappeared.
//
// Presence is read from walk_staging, which the caller fills (StartWalkStaging
// then StageLocations) with every standalone file seen this walk. diskPath maps
// a stored path to a local filesystem path so a stale standalone file can be
// classified missing vs unsupported. Every transition is recorded in
// label_events in the same transaction as the change. Aggregate and per-pool
// missing rates above 15% abort before any missing write, on the assumption the
// walk or storage topology is incomplete rather than legitimately emptied.
//
// markMissing=false (the --dataset-incomplete deployment) runs step 1 only: the
// data root deliberately holds just part of the corpus, so a locally-absent file
// is "not on this host", not "gone from the corpus". Steps 2–4 — which would mark
// it skip='missing'/'unsupported' and cascade that to archive members — are
// suppressed so those records stay trainable and the marking never replicates to
// the primary. Relabel still applies pool moves among the locally-present files.
func (db *DB) ReconcilePools(ctx context.Context, diskPath func(string) string, markMissing bool) (ReconcileStats, error) {
	var stats ReconcileStats
	var err error

	// 1. Merge every newly observed standalone path into the active location
	//    ledger. This is what makes a same-inode rename or an additional hardlink
	//    visible even when the hash cache proves the bytes were already inserted.
	if db.pool != nil {
		stats.ObservedLocations, err = db.observeStagedLocationsPG(ctx)
	} else {
		stats.ObservedLocations, err = db.observeStagedLocationsSQLite(ctx)
	}
	if err != nil {
		return stats, fmt.Errorf("hopper: reconcile observe locations: %w", err)
	}
	if stats.ObservedLocations > 0 {
		slog.Info("reconcile learned sample locations", "count", stats.ObservedLocations)
	}

	// 2. Relabel top-level, non-marker samples from the pools their standalone
	//    copies live in this walk (demote bad→good, promote good→bad, both→conflict).
	if db.pool != nil {
		stats.Relabeled, err = db.relabelFromPoolsPG(ctx)
	} else {
		stats.Relabeled, err = db.relabelFromPoolsSQLite(ctx)
	}
	if err != nil {
		return stats, fmt.Errorf("hopper: reconcile relabel: %w", err)
	}

	if !markMissing {
		// Dataset-incomplete: local disk is not authoritative for presence, so
		// stop after relabel — skip the stale-scan, missing/unsupported marking,
		// and archive-member cascade (steps 2–4).
		slog.Info("reconcile: missing-marking suppressed (dataset-incomplete)",
			"relabeled", stats.Relabeled)
		db.flushLookups()
		return stats, nil
	}

	// 3. Find top-level samples (skip empty or 'conflict') not seen this walk,
	//    with aggregate and per-pool guards checked before any missing write.
	var stale []SampleLocationKey
	var eligible int64
	var eligibleByRoot map[string]int64
	if db.pool != nil {
		stale, eligible, err = db.staleStandaloneSamplesPG(ctx)
	} else {
		stale, eligible, err = db.staleStandaloneSamplesSQLite(ctx)
	}
	if err != nil {
		return stats, fmt.Errorf("hopper: reconcile stale scan: %w", err)
	}
	if db.pool != nil {
		eligibleByRoot, err = db.eligibleStandaloneRootsPG(ctx)
	} else {
		eligibleByRoot, err = db.eligibleStandaloneRootsSQLite(ctx)
	}
	if err != nil {
		return stats, fmt.Errorf("hopper: reconcile root counts: %w", err)
	}
	const minBulkMarkGuardSamples = 100
	const maxMissingPercent int64 = 15
	if eligible >= minBulkMarkGuardSamples && int64(len(stale))*100 > eligible*maxMissingPercent {
		return stats, fmt.Errorf(
			"hopper: reconcile: refusing to mark %d of %d standalone samples missing"+
				" (>%d%%); this likely indicates an incomplete walk or storage failure",
			len(stale), eligible, maxMissingPercent,
		)
	}
	staleByRoot := make(map[string]int64)
	for _, s := range stale {
		staleByRoot[samplePathRoot(s.Path)]++
	}
	for root, missing := range staleByRoot {
		total := eligibleByRoot[root]
		if total >= minBulkMarkGuardSamples && missing*100 > total*maxMissingPercent {
			return stats, fmt.Errorf(
				"hopper: reconcile: refusing to mark %d of %d %q pool samples missing"+
					" (>%d%%); this likely indicates an incomplete pool walk or missing mount",
				missing, total, root, maxMissingPercent)
		}
	}

	// 4. Classify each stale standalone file: gone → missing, present → unsupported.
	for _, s := range stale {
		skip := "unsupported" // present on disk but not enumerated by iter-files
		if _, statErr := os.Stat(diskPath(s.Path)); statErr != nil {
			skip = "missing" // gone from disk
		}
		var changed bool
		if db.pool != nil {
			changed, err = db.setSkipWithEventPG(ctx, s.SHA256, skip, skip)
		} else {
			changed, err = db.setSkipWithEventSQLite(ctx, s.SHA256, skip, skip)
		}
		if err != nil {
			return stats, fmt.Errorf("hopper: reconcile mark %s: %w", skip, err)
		}
		if !changed {
			continue
		}
		slog.Info("marking stale sample", "sha256", s.SHA256, "path", s.Path, "skip", skip)
		if skip == "missing" {
			stats.MarkedMissing++
		} else {
			stats.MarkedUnsupported++
		}
	}

	// 4. Cascade missing to members orphaned by a missing parent (shared-archive
	//    veto applies), and revive members whose archive reappeared.
	if db.pool != nil {
		stats.CascadedMissing, stats.Revived, err = db.cascadeMembersPG(ctx)
	} else {
		stats.CascadedMissing, stats.Revived, err = db.cascadeMembersSQLite(ctx)
	}
	if err != nil {
		return stats, fmt.Errorf("hopper: reconcile cascade: %w", err)
	}
	db.flushLookups()
	return stats, nil
}

func samplePathRoot(path string) string {
	path = strings.TrimPrefix(filepath.ToSlash(path), "/")
	root, _, _ := strings.Cut(path, "/")
	return root
}

// Pull-based work scheduling.

// ClaimJob is a work item returned to a litmus worker.
type ClaimJob struct {
	SHA256    string `json:"sha256"`
	Path      string `json:"path"`
	FileType  string `json:"file_type"`
	SizeBytes int64  `json:"size_bytes"`
	// HasProvenance reports whether hopper holds a provenance sidecar for this
	// sample, so the worker fetches /api/provenance/{sha256} for its registry
	// record only when there is one — avoiding a wasted round-trip on the
	// majority of samples that carry none. Stamped per claim batch, not selected
	// by each tier query. Omitted from the wire when false.
	HasProvenance bool `json:"has_provenance,omitempty"`
}

// Worker is a litmus worker's latest heartbeat data.
type Worker struct {
	LastSeen time.Time `json:"last_seen"`
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Traits   string    `json:"traits"`
	Analyzed int64     `json:"analyzed"`
	Errors   int64     `json:"errors"`
	Slots    int       `json:"slots"`
}

// WorkerClaim describes one in-flight job claim, used by the dashboard to
// show what each worker is currently working on.
type WorkerClaim struct {
	ClaimedAt time.Time
	Worker    string
	Path      string
}

// NewestAnalyzedAt returns the most recent analyzed_at timestamp, or zero if none.
func (db *DB) NewestAnalyzedAt(ctx context.Context) (time.Time, error) {
	if db.pool != nil {
		return db.newestAnalyzedAtPG(ctx)
	}
	return db.newestAnalyzedAtSQLite(ctx)
}

// UnanalyzedCandidates returns up to limit Tier 1 jobs (samples that have
// never been analyzed). Claim ownership lives in memory in the API server —
// this is a pure SELECT.
func (db *DB) UnanalyzedCandidates(ctx context.Context, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.unanalyzedCandidatesPG(ctx, hopperStart, limit)
	}
	return db.unanalyzedCandidatesSQLite(ctx, hopperStart, limit)
}

// BigArchiveCandidates returns up to limit unanalyzed samples larger than
// minBytes (multi-GB ISOs and the like). Offered to capable workers ahead of
// the random-pivot backlog: big archives are rare and large, so one seldom
// falls inside a busy worker's small poll window — without a dedicated lookup it
// would be claimed almost only by large startup polls and could sit unscanned
// while ordinary work streams past. Largest first. Pure SELECT; claim ownership
// lives in the API server's in-memory tracker.
func (db *DB) BigArchiveCandidates(ctx context.Context, minBytes int64, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.bigArchiveCandidatesPG(ctx, minBytes, hopperStart, limit)
	}
	return db.bigArchiveCandidatesSQLite(ctx, minBytes, hopperStart, limit)
}

// ForcedRescanCandidates returns up to limit Tier 0 jobs: samples an operator
// explicitly re-queued via RequestRescan (rescan_priority = 2). Workers drain
// this before Tier 1 (unanalyzed) so a user-requested rescan jumps the queue
// regardless of how big the backlog is. Ordered by rescan_requested_at
// ascending (oldest request first) for FIFO fairness across operators.
//
// Samples that failed analysis since hopperStart are held back, the same way
// Tier 1 and the big-archive tier hold them back. Without that guard a sample
// that cannot be analyzed would sit at the head of this FIFO and be re-offered
// on every poll — and because Tier 0 drains first, it would starve every other
// forced rescan behind it.
func (db *DB) ForcedRescanCandidates(ctx context.Context, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.forcedRescanCandidatesPG(ctx, hopperStart, limit)
	}
	return db.forcedRescanCandidatesSQLite(ctx, hopperStart, limit)
}

// RepairCandidates returns up to limit jobs flagged for re-analysis via the
// rescan column. Drained by Tier 1b — AFTER the unanalyzed backlog — so bulk
// background repair (e.g. archives left memberless by the old async explosion)
// never starves freshly-ingested archives. Worst (highest score) first. The
// flag is set by QueueMissingMembersForRepair / QueueRescan and cleared by
// StoreResult once fresh analysis lands.
func (db *DB) RepairCandidates(ctx context.Context, limit int) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.repairCandidatesPG(ctx, limit)
	}
	return db.repairCandidatesSQLite(ctx, limit)
}

// QueueRescan flags the given SHAs for re-analysis in the repair tier
// (rescan_priority 1). Only top-level, non-skipped samples are touched, and a
// sample already queued at a higher priority is left alone. Returns the number
// flagged. This is the CLI/operator entry point for rescanning files behind new
// work.
func (db *DB) QueueRescan(ctx context.Context, shas []string) (int64, error) {
	if len(shas) == 0 {
		return 0, nil
	}
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.queueRescanPG(ctx, shas)
	} else {
		n, err = db.queueRescanSQLite(ctx, shas)
	}
	if err == nil && n > 0 {
		db.forgetSHAs(shas)
	}
	return n, err
}

// QueueMissingMembersForRepair flags every top-level archive whose stored
// cleave_result was truncated (members factored out) but which has no member
// rows — the data-loss state the former async explosion could leave behind. The
// detecting NOT EXISTS scan runs once here, not per claim poll; thereafter Tier
// 1b drains the cheap rescan flag. Returns the number flagged.
func (db *DB) QueueMissingMembersForRepair(ctx context.Context) (int64, error) {
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.queueMissingMembersForRepairPG(ctx)
	} else {
		n, err = db.queueMissingMembersForRepairSQLite(ctx)
	}
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// SampleAnalyzed reports whether a sample with the given SHA-256 exists
// in the DB and, if so, whether its cleave_result is populated. Used by
// prism's SSE wait endpoint for sub-100ms upload→render notification: a
// tight poll loop that fetches the full sample row would pull megabytes
// of cleave_result on every tick.
func (db *DB) SampleAnalyzed(ctx context.Context, sha256 string) (exists, analyzed bool, err error) {
	if db.pool != nil {
		return db.sampleAnalyzedPG(ctx, sha256)
	}
	return db.sampleAnalyzedSQLite(ctx, sha256)
}

// UploadCandidates returns up to limit interactive-upload jobs: samples
// posted by a user through prism's /upload (Source="upload") that haven't
// been analyzed yet. Drained ahead of every other tier so the user sees
// their result as fast as possible. Ordered by id ASC (insertion order)
// for FIFO fairness — uploads are rare enough that the existing
// idx_samples_claimable partial index covers this scan cheaply.
func (db *DB) UploadCandidates(ctx context.Context, limit int) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.uploadCandidatesPG(ctx, limit)
	}
	return db.uploadCandidatesSQLite(ctx, limit)
}

// ForceRescanCandidates returns up to limit Tier 2 jobs: previously analyzed
// samples under the named path prefixes whose analysis predates hopperStart.
func (db *DB) ForceRescanCandidates(ctx context.Context, hopperStart time.Time, prefixes []string, limit int) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.forceRescanCandidatesPG(ctx, hopperStart, prefixes, limit)
	}
	return db.forceRescanCandidatesSQLite(ctx, hopperStart, prefixes, limit)
}

// StaleTraitsCandidates returns up to limit Tier 3 jobs: samples analyzed
// with a different traits_version more than rescanAge ago, ordered by
// label-disagreement priority.
func (db *DB) StaleTraitsCandidates(
	ctx context.Context, currentTraits string, rescanAge time.Duration,
	hopperStart time.Time, limit int,
) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.staleTraitsCandidatesPG(ctx, currentTraits, rescanAge, hopperStart, limit)
	}
	return db.staleTraitsCandidatesSQLite(ctx, currentTraits, rescanAge, hopperStart, limit)
}

// UpsertWorker records a worker heartbeat for dashboard display.
func (db *DB) UpsertWorker(ctx context.Context, w Worker) error {
	if db.pool != nil {
		return db.upsertWorkerPG(ctx, w)
	}
	return db.upsertWorkerSQLite(ctx, w)
}

// ActiveWorkers returns workers seen within the given duration.
func (db *DB) ActiveWorkers(ctx context.Context, since time.Duration) ([]Worker, error) {
	if db.pool != nil {
		return db.activeWorkersPG(ctx, since)
	}
	return db.activeWorkersSQLite(ctx, since)
}

// SamplesByLabel returns up to limit samples with the given label, ordered by id.
func (db *DB) SamplesByLabel(ctx context.Context, label string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.samplesByLabelPG(ctx, label, limit)
	}
	return db.samplesByLabelSQLite(ctx, label, limit)
}

// CountByLabel returns sample counts grouped by label.
func (db *DB) CountByLabel(ctx context.Context) (map[string]int, error) {
	if db.pool != nil {
		return db.countByLabelPG(ctx)
	}
	return db.countByLabelSQLite(ctx)
}

// SetNote sets an operational annotation on a sample (e.g. error message).
// Pass "" to clear.
func (db *DB) SetNote(ctx context.Context, sha256, note string) error {
	if db.pool != nil {
		return db.writeSHA(sha256, db.setNotePG(ctx, sha256, note))
	}
	return db.writeSHA(sha256, db.setNoteSQLite(ctx, sha256, note))
}

// SetStatus updates the pipeline status and updated_at timestamp.
// Clears note on status change (assumes success).
func (db *DB) SetStatus(ctx context.Context, sha256, status string) error {
	if db.pool != nil {
		return db.writeSHA(sha256, db.setStatusPG(ctx, sha256, status))
	}
	return db.writeSHA(sha256, db.setStatusSQLite(ctx, sha256, status))
}

// SamplesInPipelineStage returns up to limit samples currently parked in the
// given cyclotron pipeline status (e.g. "bad-review", "good-analyzed"), ordered
// by impact: highest litmus_score first, then cleave score, then oldest update.
func (db *DB) SamplesInPipelineStage(ctx context.Context, status string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.samplesInPipelineStagePG(ctx, status, limit)
	}
	return db.samplesInPipelineStageSQLite(ctx, status, limit)
}

// SamplesInPipelineStageLight is like SamplesInPipelineStage but omits
// CleaveResult and LitmusResult to reduce memory usage when only metadata is needed.
func (db *DB) SamplesInPipelineStageLight(ctx context.Context, status string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.samplesInPipelineStageLightPG(ctx, status, limit)
	}
	return db.samplesInPipelineStageLightSQLite(ctx, status, limit)
}

// FalsePositives returns analyzed top-level good-labeled samples that trigger detection
// (max_crit >= 5 OR suspicious_count >= 2). These are candidates for
// false-positive resolution.
// Only returns samples with empty status (not yet claimed by a pipeline).
func (db *DB) FalsePositives(ctx context.Context, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falsePositivesPG(ctx, limit)
	}
	return db.falsePositivesSQLite(ctx, limit)
}

// TruePositives returns analyzed bad-labeled samples with score >= threshold.
// These are known-bad files that cleave also scores as bad.
// Only returns samples with empty status and no training-skip marker.
func (db *DB) TruePositives(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.truePositivesPG(ctx, scoreThreshold, limit)
	}
	return db.truePositivesSQLite(ctx, scoreThreshold, limit)
}

// FalseNegatives returns analyzed top-level bad-labeled samples that do not trigger
// detection (max_crit < 5 AND suspicious_count < 2). These are candidates
// for gap-and-fix.
// Only returns samples with empty status (not yet claimed by a pipeline).
func (db *DB) FalseNegatives(ctx context.Context, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falseNegativesPG(ctx, limit)
	}
	return db.falseNegativesSQLite(ctx, limit)
}

// FalsePositivesLight is like FalsePositives but omits CleaveResult/LitmusResult.
func (db *DB) FalsePositivesLight(ctx context.Context, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falsePositivesLightPG(ctx, limit)
	}
	return db.falsePositivesLightSQLite(ctx, limit)
}

// FalseNegativesLight is like FalseNegatives but omits CleaveResult/LitmusResult.
func (db *DB) FalseNegativesLight(ctx context.Context, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falseNegativesLightPG(ctx, limit)
	}
	return db.falseNegativesLightSQLite(ctx, limit)
}

// BenignReview returns known-bad files that were flipped to good by a BENIGN
// marker, but whose score still looks bad enough to warrant manual review.
// Only returns marker-labeled misclassifications with empty status.
func (db *DB) BenignReview(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.benignReviewPG(ctx, scoreThreshold, limit)
	}
	return db.benignReviewSQLite(ctx, scoreThreshold, limit)
}

// BadReview returns known-good files that were flipped to bad by a BAD marker,
// but whose score still looks benign enough to warrant manual review.
// Only returns marker-labeled misclassifications with empty status.
func (db *DB) BadReview(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.badReviewPG(ctx, scoreThreshold, limit)
	}
	return db.badReviewSQLite(ctx, scoreThreshold, limit)
}

// TriageFilter optionally narrows triage queries to a specific ecosystem and/or file type.
type TriageFilter struct {
	// Field order is chosen for alignment (time.Time, then strings, then the
	// int) rather than for reading order; govet's fieldalignment enforces it.

	// MinAnalyzedAt, when non-zero, drops rows analyzed before it. A row's
	// queue membership (max_crit, suspicious_count, litmus_class) is whatever
	// its last scan computed, so an old analysis is a stale claim: current
	// traits may already catch a sample the queue still lists as a miss.
	// Bounding the window trades reach for a verdict worth spending a premium
	// triage on. Zero means no bound — take the stalest rows in the table and
	// let ExcludeReportType clear out the ones that turn out to be already
	// fixed.
	MinAnalyzedAt time.Time

	Ecosystem string // e.g. "wolfi", "archlinux" — empty means no filter
	FileType  string // e.g. "apk", "pkg.tar.zst" — empty means no filter

	// ExcludeReportType, when set, drops rows carrying a report of this type
	// filed after their last analysis. This is what keeps a TriageStale queue
	// from jamming: unlike the newest-first queues, which are pushed along by
	// fresh arrivals, a stale queue's head does not move on its own, so a
	// sample nothing can be done about would sit at the top being re-selected
	// every cooldown expiry forever. Filing a report parks it. Comparing
	// against analyzed_at (rather than suppressing outright) is what makes it
	// self-resetting: a re-scan produces a new verdict and the sample becomes
	// eligible again, which is exactly the question a staleness queue asks.
	ExcludeReportType string

	// AttemptReportType, with MaxAttempts > 0, limits how many completed
	// attempts of that report type a sample may receive. Unlike
	// ExcludeReportType this is a lifetime budget: callers use a distinct type
	// per queue, and an operator can explicitly clear or rename those reports to
	// re-admit a stalled sample. Infrastructure failures should not be reported
	// as attempts.
	AttemptReportType string

	// Order ranks the queue. See TriageOrder.
	Order       TriageOrder
	MaxAttempts int
}

// TriageOrder selects how a triage queue ranks its candidates.
type TriageOrder int

const (
	// TriageNewest ranks most-recently-added first (created_at DESC, id DESC).
	// The queues self-drain — a row leaves when the fix lands — and fresh
	// arrivals continuously refresh the head, so an unfixable sample sinks on
	// its own. That property is why this ordering needs no drain machinery, and
	// also why it never reaches the backlog: while arrivals outpace triage the
	// cursor never descends past the newest few days.
	TriageNewest TriageOrder = iota

	// TriageStale ranks least-recently-analyzed first (analyzed_at ASC NULLS
	// LAST) — the rows whose verdict rests on the oldest trait set. Reaches the
	// backlog the newest-first ordering cannot, and unlike ordering by
	// created_at it is self-advancing: re-analysis bumps analyzed_at and moves
	// the row to the back of its own queue. Requires the matching
	// idx_samples_*_stale partial index; see the migration list.
	TriageStale

	// TriageInteresting ranks externally corroborated and strongly detected
	// samples first, then the oldest analysis within equal evidence. It is for
	// adjudication queues such as review and new; repair queues have different
	// notions of value and retain their queue-specific ordering.
	TriageInteresting
)

// TriageBad returns analyzed top-level bad-labeled samples that Cleave did not
// detect: no hostile finding and fewer than two suspicious-or-hostile findings
// (max_crit < 5 AND suspicious_count < 2). This is the exact inverse of
// Cyclotron's AnalysisReport.Detected predicate, so a successful repair leaves
// the queue without requiring a separate drain marker.
//
// Skipped rows are excluded (skip = ”), matching TriageHighest/TriageLowest.
// A skip means the sample cannot be worked: 'missing' and 'corrupt' have no
// bytes to fetch, 'unsupported' is a type cleave cannot parse, so no trait can
// be written for it. Selecting them spent a batch slot to reach a dead end.
// Empty paths are excluded too ([triageServablePathSQL]): reference-only rows
// (registry sidecars, fetched deps not yet uploaded) are permanently unservable.
func (db *DB) TriageBad(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageBadPG(ctx, limit, f)
	}
	return db.triageBadSQLite(ctx, limit, f)
}

// TriageGood returns analyzed top-level good-labeled samples that trip Cleave
// detection — a hostile trait (max_crit >= 5) or a second
// suspicious-or-hostile trait (suspicious_count >= 2) — taking up to limit of
// the most recently added (created_at). Litmus-only disagreements belong to
// TriageHighest's premium, route-balanced label review; mixing them into this
// repair queue made trait-clean rows cycle without a trait to fix.
func (db *DB) TriageGood(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageGoodPG(ctx, limit, f)
	}
	return db.triageGoodSQLite(ctx, limit, f)
}

// TriageHighest returns good-labeled samples at the TOP of their own
// file_type's score distribution — each route's top-K by litmus_score
// (triagePerRouteK), every route's #1 ranked before any route's #2. These are
// the rows that pin each route's operating point: a per-route threshold is an
// interpolated quantile over the slice's highest-scoring benigns, so a single
// mislabelled or genuinely hard benign caps the recall reported for its whole
// filetype.
//
// Two properties of the 2026-08-03 redesign are deliberate:
//   - No litmus_class gate. The threshold-pinning band sits just BELOW the
//     hostile cutoff by construction (the threshold is placed at/above the
//     top benign), so a `class >= hostile` gate could only ever see
//     already-flagged FPs, never the files that actually set the threshold.
//     Class-NULL backfill lag stops mattering for the same reason.
//   - Per-route windows, not a global score window. A global top-N never
//     exits the tie band at score 1.0 (~70k good members), so routes whose
//     FPs top out below 1.0 (PE: 0.997) were structurally unreachable.
//
// The unit of work is the archive, not the member: the query finds hot good
// members (no parent = ” predicate — 95.8% of benign PE scoring >= 0.9999 are
// members, which every other selector excludes), then collapses them to their
// root archive and returns one row per archive, ranked by its hottest member.
// The worker fetches and judges that whole archive, so its provenance and
// sibling files inform the call; the drain is keyed on the root, so one ruling
// covers every hot member inside. A root is returned only when its own sample
// is labelled good or unknown — a bad-labelled archive belongs to TriageLowest,
// whose members it holds. skip = ” matches collimator's LABELED_WHERE, so the
// queue only holds rows that actually reach training; fixing a row the trainer
// already ignores moves nothing. createdBefore keeps the queue off TriageGood's
// newest-first end of the table.
//
// Members whose path carries no "!!" archive delimiter, or whose parent row is
// itself absent, are excluded: the API cannot extract them (it answers 422 /
// "parent not found", permanently), so a presence probe would spend a round
// trip to learn what the row already says.
//
// Samples carrying a ReportTypeMissing marker newer than missingBefore are
// suppressed: on an incomplete mirror ~70% of the top of this queue by score
// has no bytes on disk, and without an expiring marker those rows would never
// drain and would eventually fill the selection window.
func (db *DB) TriageHighest(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageHighestPG(ctx, limit, createdBefore, missingBefore, f)
	}
	return db.triageHighestSQLite(ctx, limit, createdBefore, missingBefore, f)
}

// TriageLowest is TriageHighest's mirror: each file_type's bottom-K
// bad-labeled samples by ascending litmus_score (triagePerRouteK, rank-first
// across routes) — the best-hidden detection misses. Like the mirror it
// carries no litmus_class gate (2026-08-03): per-route bottom-K IS "scored
// clean" without depending on class derivation or its backfill.
//
// It drains per member rather than per archive, unlike TriageHighest. A bad
// archive's malice lives in a few files while the rest is inert content that
// inherited the label at explode time (hopper.go: members take the parent's
// label under containment), so each member needs its own verdict and one
// archive-level ruling must not speak for files it never opened.
//
// skip = ” does most of the filtering here: ~97% of low-scoring bad members
// already carry skip-benign-archive-item, which collimator's LABELED_WHERE
// excludes from training, so their inherited label harms nothing and they are
// not worth a review. What remains — ~25k members and ~190k top-level rows —
// is labelled bad, scored clean, and actually in the training set.
// The ReportTypeMissing marker is keyed on the root even though the queue's own
// drain is per-member: a verdict applies to one file, but vanished bytes are the
// parent archive's and take every member with them.
func (db *DB) TriageLowest(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageLowestPG(ctx, limit, createdBefore, missingBefore, f)
	}
	return db.triageLowestSQLite(ctx, limit, createdBefore, missingBefore, f)
}

// TriageStranded returns bad-labeled parent archives that still contain
// good-labeled members with real findings (score > 0, max_crit >= notable)
// whose benign label was inherited before the parent's conviction — never
// individually reviewed (label_source not cyclotron:*). Those members sit in
// the benign training and threshold pools while living inside convicted
// archives; measured 2026-08-03: ~77k stranded members, ~36k scoring >= 0.9.
//
// Unit of work is the ARCHIVE (dedup by parent, ranked by its riskiest
// member's score descending) — the worker fetches and judges the whole
// package for context — but the drain is PER MEMBER ('stranded' reports), so
// an archive resurfaces until every qualifying member has been examined, and
// a ruling never silently covers members the judge did not see. Companion
// StrandedMembers lists the members awaiting verdicts for one root.
func (db *DB) TriageStranded(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageStrandedPG(ctx, limit, createdBefore, missingBefore, f)
	}
	return db.triageStrandedSQLite(ctx, limit, createdBefore, missingBefore, f)
}

// StrandedMembers lists root's stranded members still awaiting a per-member
// verdict — the same population TriageStranded's inner scan walks, filtered
// to one archive, risk-score descending. The worker uses it to name the
// members in the batch prompt and to know which shas to rule and drain.
func (db *DB) StrandedMembers(ctx context.Context, root string) ([]*Sample, error) {
	if db.pool != nil {
		rows, err := db.pool.Query(ctx,
			`SELECT `+pgSampleCols+` FROM samples
			 WHERE label = 'good' AND cleave_result IS NOT NULL AND skip = ''
			   AND parent = $1 AND path LIKE '%!!%'
			   AND score > 0 AND max_crit >= `+strconv.Itoa(notableCrit)+`
			   AND label_source NOT LIKE 'cyclotron:%'
			   AND NOT EXISTS (SELECT 1 FROM reports r
			                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'stranded')
			 ORDER BY score DESC, id DESC`, root)
		if err != nil {
			return nil, fmt.Errorf("hopper: stranded members: %w", err)
		}
		return scanPGSamples(rows)
	}
	//nolint:gosec // G202: the concatenated parts are the constant column list and a constant int; root is bound as a ? parameter.
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND skip = ''
		   AND parent = ? AND path LIKE '%!!%'
		   AND score > 0 AND max_crit >= `+strconv.Itoa(notableCrit)+`
		   AND label_source NOT LIKE 'cyclotron:%'
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'stranded')
		 ORDER BY score DESC, id DESC`, root)
	if err != nil {
		return nil, fmt.Errorf("hopper: stranded members: %w", err)
	}
	return scanLiteSamples(rows)
}

// TriageNew returns analyzed top-level unknown-labeled samples outside the
// review pool that cleave flagged with at least one suspicious-or-hostile
// finding (suspicious_count >= 1), taking up to limit of the most recently
// added (created_at). The review pool is a separate, explicit queue; keeping it
// out of this selector prevents two workers from judging the same sample.
// Empty paths are excluded ([triageServablePathSQL]): explode records
// registry/fetched references with samples.path ” and no bytes to fetch.
func (db *DB) TriageNew(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageNewPG(ctx, limit, f)
	}
	return db.triageNewSQLite(ctx, limit, f)
}

// TriageReview returns every analyzed top-level unknown-labeled sample in the
// review pool, taking up to limit of the most recently added. Review membership
// is the disposition: promoter puts a sample there after exactly one bad signal,
// including signals that do not appear in cleave_result, so this selector must
// not add a detection predicate. A good/bad ruling moves and relabels the sample
// out of the pool, which drains the queue.
func (db *DB) TriageReview(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageReviewPG(ctx, limit, f)
	}
	return db.triageReviewSQLite(ctx, limit, f)
}

// TriageSighted returns analyzed top-level sighted-labeled samples — feed
// claims pending verification — taking up to limit of the most recently added
// (created_at). Unlike TriageBad/TriageGood there is no detection-gap
// predicate: every sighted sample is an unconfirmed claim that needs triage
// and a real label, so all of them qualify until a ruling relabels them out of
// the pool (bad or good). Skipped rows are excluded (skip = ”): a sample whose
// bytes are missing or whose type cleave cannot parse can be neither verified
// nor relabelled, so selecting it only burns a batch slot.
func (db *DB) TriageSighted(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageSightedPG(ctx, limit, f)
	}
	return db.triageSightedSQLite(ctx, limit, f)
}

// TriageFallout returns analyzed top-level litmus-hostile samples (class 2)
// that are either UNDESCRIBED or UNCORROBORATED, taking up to limit of the most
// recently added (created_at), restricted to rows created after createdAfter.
//
// Undescribed means llm_result is NULL or its interpretation is empty (a failed
// pass stores only an error): the page shows a hostile verdict with no rationale
// line. Uncorroborated means samples.corroborated is false: we call it hostile
// and no outside source has ever cited it.
//
// One queue rather than two because measurement said they are one population.
// Over a 7-day window: 337 samples on the page, 11 undescribed, 229
// uncorroborated, and every undescribed sample was also uncorroborated — the
// undescribed set was a strict subset, contributing nothing of its own. Two
// queues over those populations would have run the same worker against the same
// rows for two reasons, and the smaller reason would have been 5% of the work.
//
// The two halves want different products, which the reviewer's prompt handles
// rather than the selector: an undescribed sample needs a rationale (the
// write-back's interpret pass stores it), an uncorroborated one needs its
// hostile verdict re-examined now that nobody outside has backed it up. A
// completed judgement satisfies whichever applied.
// This is the population prism's /fallout page renders with no rationale line:
// litmus classified the bytes hostile but no reasoning pass ever ran (arrivals
// outpace the new queue, which ranks a litmus-hostile sample no higher than any
// other suspicious unknown) or the pass failed. There is deliberately no label
// predicate — the page has none either, and most of the population is unlabeled.
// Two drains: storing an interpretation (the write-back scan's interpret pass)
// removes the row from the predicate, and rows carrying a reports row of type
// "fallout" are skipped permanently — the reviewer files it on a completed
// judgement, which covers samples whose interpret pass errors (large renders
// overflow the endpoint) and would otherwise re-select every cooldown until
// they aged out of the createdAfter window.
// Registry sidecars are excluded (file_type), empty paths are excluded
// ([triageServablePathSQL] — covers fetched deps that share the same
// unservable shape), and containment is judged by the sample_locations ledger,
// all mirroring the feed query the page is built on.
func (db *DB) TriageFallout(ctx context.Context, limit int, createdAfter time.Time, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageFalloutPG(ctx, limit, createdAfter, f)
	}
	return db.triageFalloutSQLite(ctx, limit, createdAfter, f)
}

// TrustedBadSources are the sighting sources that independently host or curate
// malware rather than merely predict it — forager's straight-to-bad feeds
// (ThreatFeed Category "bad") plus the hash corpora it records via
// RecordHashSightings. A claim from any one of them is strong enough on its own
// to dispute a good label; vendor-prediction feeds (aikido, socket, safedep, …)
// are not listed and only count toward the two-independent-sources bar.
var TrustedBadSources = []string{
	"bazaar",    // MalwareBazaar: hosts the bytes
	"virussign", // VirusSign: hosts the bytes
	"malshare",  // MalShare: hosts the bytes
	"vxug",      // vx-underground: hosts the bytes
	"osm",       // opensourcemalware.com: curated malware-report registry
	"osv",       // OSV MAL-* advisories
	"ghsa",      // GitHub malware advisories
	"extsentry", // browser-extension malware registry
	"vsxsentry", // VS Code extension malware registry
}

// TriageSecondOpinion returns analyzed top-level good-labeled samples whose
// benign label an outside source disputes — a sighting from one of the trusted
// sources, or sightings from two-plus distinct sources — taking up to limit of
// the most recently added (created_at). Samples that trip detection are
// excluded: those are exactly TriageGood's set, and keeping the two queues
// disjoint preserves the invariant that no two triage workers ever hold the
// same sample (they share per-sha tmp dirs); a disputed sample flows here only
// after the good queue resolves its detection gap. Rows analyzed at or after
// analyzedBefore are skipped (a settling window so a just-analyzed sample
// isn't immediately second-guessed), and rows carrying a reports row of type
// "second" newer than the newest trusted sighting are skipped — recording that
// report is how a reviewer drains the queue when the good label stands, and a
// trusted source citing the sample AFTER its review is new evidence that
// re-admits it for one more pass. Candidacy also requires
// samples.corroborated, the denormalized sightings flag; a sample inserted
// after its (unchanged) purl sighting can miss the flip and be invisible here,
// which is accepted — the flag is the system-wide corroboration join and any
// gap is its to heal, not this query's.
func (db *DB) TriageSecondOpinion(ctx context.Context, limit int, trusted []string, analyzedBefore time.Time, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageSecondOpinionPG(ctx, limit, trusted, analyzedBefore, f)
	}
	return db.triageSecondOpinionSQLite(ctx, limit, trusted, analyzedBefore, f)
}

// TriageAcquit returns analyzed top-level bad-labeled samples whose conviction
// no outside evidence supports: the sample carries a provenance sidecar (a
// collector fetched it — walked-in dataset corpora have none) with no
// threat-feed record (nothing told us to download it as malware), and no
// sighting has ever cited its sha256 or purl_base. Only strongly detected rows
// qualify (max_crit >= 5 AND suspicious_count >= 2), a deliberately higher bar
// than ordinary detection. This remains disjoint from TriageBad, while samples
// at the confidence boundary belong to neither queue. Rows created at or after
// createdBefore are skipped (a grace window so
// feeds have time to corroborate a fresh conviction), conflict rows are
// skipped (pool reconciliation owns their label; a ruling would be flipped
// right back), and rows carrying a reports row of type "acquit" are skipped
// permanently — recording that report is how a reviewer drains the queue when
// the conviction stands.
func (db *DB) TriageAcquit(ctx context.Context, limit int, createdBefore time.Time, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageAcquitPG(ctx, limit, createdBefore, f)
	}
	return db.triageAcquitSQLite(ctx, limit, createdBefore, f)
}

// PromotionCandidates returns up to limit top-level, unknown-labeled samples
// whose stored path is under pathPrefix and whose on-disk mtime is older than
// olderThan, excluding training-skipped rows. Results are ordered by sha256 and
// restricted to sha256 > afterSHA, so a caller pages the indexed sha256 keyspace
// with keyset pagination (an index range-scan, not an ORDER BY random() full
// sort) and can anchor a sweep at a random sha for pseudo-random, unbiased
// coverage. Pass afterSHA="" to start at the keyspace floor.
//
// It is the remote replacement for promoter's local filesystem walk: pathPrefix
// is the source tree (e.g. "pending/foraged/", with the trailing slash so the
// review queue ("review/foraged/") is excluded). Stored paths are
// slash-relative to the data root.
func (db *DB) PromotionCandidates(ctx context.Context, pathPrefix string, olderThan time.Time, afterSHA string, limit int) ([]*Sample, error) {
	return db.CandidatesByLabel(ctx, labelUnknown, pathPrefix, olderThan, afterSHA, limit)
}

// CandidatesByLabel generalizes PromotionCandidates to any pool label: it
// returns up to limit top-level samples carrying label under pathPrefix with
// on-disk mtime older than olderThan, keyset-paginated by sha256 > afterSHA.
// Promoter's sighted→bad pass uses it with label "sighted" and prefix
// "sighted/foraged/".
func (db *DB) CandidatesByLabel(ctx context.Context, label, pathPrefix string, olderThan time.Time, afterSHA string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.candidatesByLabelPG(ctx, label, pathPrefix, olderThan, afterSHA, limit)
	}
	return db.candidatesByLabelSQLite(ctx, label, pathPrefix, olderThan, afterSHA, limit)
}

// SHACitedUnknowns returns unknown-labeled top-level samples under pathPrefix
// whose exact sha256 has a sightings-ledger entry. Results use the same sha256
// keyset pagination as CandidatesByLabel. PURL-only sightings are deliberately
// excluded: a package citation does not prove that a particular version's
// bytes are the cited artifact.
func (db *DB) SHACitedUnknowns(ctx context.Context, pathPrefix, afterSHA string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.shaCitedUnknownsPG(ctx, pathPrefix, afterSHA, limit)
	}
	return db.shaCitedUnknownsSQLite(ctx, pathPrefix, afterSHA, limit)
}

// ConflictReview returns samples flagged with a good+bad pool conflict
// (label='bad', skip='conflict'): the same content was asserted both benign
// and malicious in different pool directories. These are resolved to bad
// operationally but excluded from training until a human picks a side.
func (db *DB) ConflictReview(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.conflictReviewPG(ctx, scoreThreshold, limit)
	}
	return db.conflictReviewSQLite(ctx, scoreThreshold, limit)
}

// CountByStatus returns sample counts grouped by status.
func (db *DB) CountByStatus(ctx context.Context) (map[string]int, error) {
	if db.pool != nil {
		return db.countByStatusPG(ctx)
	}
	return db.countByStatusSQLite(ctx)
}

// CountAnalyzed returns the number of samples with analysis results.
func (db *DB) CountAnalyzed(ctx context.Context) (int64, error) {
	if db.pool != nil {
		return db.countAnalyzedPG(ctx)
	}
	return db.countAnalyzedSQLite(ctx)
}

// CountPending returns the number of samples awaiting analysis
// (matching the claim query criteria: no cleave result, not skipped, not a child).
func (db *DB) CountPending(ctx context.Context) (int64, error) {
	const q = `SELECT count(*) FROM samples ` +
		`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`
	var n int64
	var err error
	if db.pool != nil {
		err = db.pool.QueryRow(ctx, q).Scan(&n)
	} else {
		err = db.lite.QueryRowContext(ctx, q).Scan(&n)
	}
	return n, err
}

// CountRescanPending returns the number of previously analyzed samples
// eligible for re-analysis due to stale traits (matching the tier-2 claim
// criteria: stale traits version AND analyzed longer ago than rescanAge).
// Returns 0 if currentTraits is empty (rescan disabled).
func (db *DB) CountRescanPending(ctx context.Context, currentTraits string, rescanAge time.Duration) (int64, error) {
	if currentTraits == "" {
		return 0, nil
	}
	cutoff := time.Now().Add(-rescanAge).UTC()
	var n int64
	var err error
	if db.pool != nil {
		err = db.pool.QueryRow(ctx,
			`SELECT count(*) FROM samples `+
				`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = '' `+
				`AND traits_version != $1 `+
				`AND analyzed_at < $2`,
			currentTraits, cutoff).Scan(&n)
	} else {
		err = db.lite.QueryRowContext(ctx,
			`SELECT count(*) FROM samples `+
				`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = '' `+
				`AND traits_version != ? `+
				`AND analyzed_at < ?`,
			currentTraits, cutoff.Format(time.RFC3339Nano)).Scan(&n)
	}
	return n, err
}

// AnalysisRates summarizes top-level (parent = ”) analysis throughput over a
// window. Children of exploded archives are excluded on purpose: they are
// created already-analyzed in bulk when their parent is processed, so counting
// them inflates throughput by ~80x and makes any ETA against the top-level
// backlog (pending / rescan counts, which are all parent = ”) meaningless.
type AnalysisRates struct {
	TopLevel int64 // top-level samples (re)analyzed in the window
	Rescans  int64 // subset that were re-analyzed (first analysis predates this one)
}

// AnalysisRatesSince counts top-level analyses in the window, split into rescans
// (first_analyzed_at < analyzed_at) and the rest. A first-time analysis stamps
// first_analyzed_at and analyzed_at together, so the strict inequality isolates
// genuine rescans. Divided by the window these give the live top-level and
// rescan rates the dashboard uses for honest queue ETAs: rescans are the lowest
// claim tier, so their rate is a fraction of the overall analysis rate, and the
// overall analysis rate is itself far below the raw files/sec the fleet reports
// once archive members are excluded.
func (db *DB) AnalysisRatesSince(ctx context.Context, window time.Duration) (AnalysisRates, error) {
	since := time.Now().Add(-window).UTC()
	const rescanExpr = `count(CASE WHEN first_analyzed_at IS NOT NULL AND first_analyzed_at < analyzed_at THEN 1 END)`
	var r AnalysisRates
	var err error
	if db.pool != nil {
		err = db.pool.QueryRow(ctx,
			`SELECT count(*), `+rescanExpr+
				` FROM samples WHERE analyzed_at >= $1 AND parent = ''`,
			since).Scan(&r.TopLevel, &r.Rescans)
	} else {
		err = db.lite.QueryRowContext(ctx,
			`SELECT count(*), `+rescanExpr+
				` FROM samples WHERE analyzed_at >= ? AND parent = ''`,
			since.Format(time.RFC3339Nano)).Scan(&r.TopLevel, &r.Rescans)
	}
	return r, err
}

// WorkflowSnapshot returns a compact dashboard-oriented view of freshness,
// queue shape, and recent samples.
func (db *DB) WorkflowSnapshot(ctx context.Context, limit int) (WorkflowSnapshot, error) {
	if limit <= 0 {
		limit = 5
	}
	health, err := db.WorkflowHealth(ctx)
	if err != nil {
		return WorkflowSnapshot{}, err
	}
	backlogs, err := db.WorkflowBacklogs(ctx, limit)
	if err != nil {
		return WorkflowSnapshot{}, err
	}
	latestAdded, err := db.WorkflowLatestAdded(ctx, limit)
	if err != nil {
		return WorkflowSnapshot{}, err
	}
	latestReady, err := db.WorkflowLatestReady(ctx, limit)
	if err != nil {
		return WorkflowSnapshot{}, err
	}
	oldestPending, err := db.WorkflowOldestPending(ctx, limit)
	if err != nil {
		return WorkflowSnapshot{}, err
	}
	return WorkflowSnapshot{
		Health:        health,
		Backlogs:      backlogs,
		LatestAdded:   latestAdded,
		LatestReady:   latestReady,
		OldestPending: oldestPending,
	}, nil
}

// WorkflowHealth returns queue freshness counters for the dashboard.
func (db *DB) WorkflowHealth(ctx context.Context) (WorkflowHealth, error) {
	if db.pool != nil {
		return db.workflowHealthPG(ctx)
	}
	return db.workflowHealthSQLite(ctx)
}

// WorkflowBacklogs returns pending-work grouped by source/feed/ecosystem.
func (db *DB) WorkflowBacklogs(ctx context.Context, limit int) ([]WorkflowBacklog, error) {
	if limit <= 0 {
		limit = 5
	}
	if db.pool != nil {
		return db.workflowBacklogsPG(ctx, limit)
	}
	return db.workflowBacklogsSQLite(ctx, limit)
}

// WorkflowLatestAdded returns the most recently inserted samples.
func (db *DB) WorkflowLatestAdded(ctx context.Context, limit int) ([]WorkflowSample, error) {
	if limit <= 0 {
		limit = 5
	}
	if db.pool != nil {
		return db.workflowLatestAddedPG(ctx, limit)
	}
	return db.workflowLatestAddedSQLite(ctx, limit)
}

// WorkflowLatestReady returns the most recently analyzed samples.
func (db *DB) WorkflowLatestReady(ctx context.Context, limit int) ([]WorkflowSample, error) {
	if limit <= 0 {
		limit = 5
	}
	if db.pool != nil {
		return db.workflowLatestReadyPG(ctx, limit)
	}
	return db.workflowLatestReadySQLite(ctx, limit)
}

// WorkflowOldestPending returns the longest-waiting unanalyzed samples.
func (db *DB) WorkflowOldestPending(ctx context.Context, limit int) ([]WorkflowSample, error) {
	if limit <= 0 {
		limit = 5
	}
	if db.pool != nil {
		return db.workflowOldestPendingPG(ctx, limit)
	}
	return db.workflowOldestPendingSQLite(ctx, limit)
}

// RelativizePaths rewrites sample paths that start with dataRoot so only
// the suffix (relative to dataRoot) is stored. Paths that don't live under
// dataRoot are left untouched — callers pass the dataRoot currently being
// loaded, and anything outside of it is an observation from a different
// deployment that we shouldn't rewrite.
func (db *DB) RelativizePaths(ctx context.Context, dataRoot string) (int64, error) {
	prefix := ""
	if dataRoot != "" {
		prefix = filepath.ToSlash(filepath.Clean(dataRoot)) + "/"
	}
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.relativizePathsPG(ctx, prefix)
	} else {
		n, err = db.relativizePathsSQLite(ctx, prefix)
	}
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// UpdateSample updates status, cleave result, and updated_at in one operation.
//
// If cleave could not classify the file (fi.FileType == ""), the row is
// deleted instead of updated — matches UpdateCleaveResult's belt-and-suspenders
// rule so the two analysis-save paths stay consistent.
func (db *DB) UpdateSample(ctx context.Context, sha256, status string, result []byte, canonicalSHA256 string) error {
	p := ParseCleaveResult(sha256, result)
	if p.FileInfo.FileType == "" {
		return db.DeleteSample(ctx, sha256)
	}
	if canonicalSHA256 == "" {
		canonicalSHA256 = p.CanonicalSHA
	}
	result = compactCleaveResultForStorage(result)
	if db.pool != nil {
		return db.writeSHA(sha256, db.updateSamplePG(ctx, sha256, status, result, canonicalSHA256, p.FileInfo))
	}
	return db.writeSHA(sha256, db.updateSampleSQLite(ctx, sha256, status, result, canonicalSHA256, p.FileInfo))
}

// SamplesByStatusInPaths returns samples matching status whose path
// starts with one of the given prefixes, ordered by updated_at ASC.
func (db *DB) SamplesByStatusInPaths(ctx context.Context, status string, prefixes []string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.samplesByStatusInPathsPG(ctx, status, prefixes, limit)
	}
	return db.samplesByStatusInPathsSQLite(ctx, status, prefixes, limit)
}

// FalsePositivesInPaths returns good-labeled samples under the given prefixes
// that trigger detection, with empty status and not marked skip.
func (db *DB) FalsePositivesInPaths(ctx context.Context, prefixes []string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.seedCandidatesInPathsPG(ctx, prefixes, "good", limit, false)
	}
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "good", limit, false)
}

// FalseNegativesInPaths returns bad-labeled samples under the given prefixes
// that do not trigger detection, with empty status and not marked skip.
func (db *DB) FalseNegativesInPaths(ctx context.Context, prefixes []string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.seedCandidatesInPathsPG(ctx, prefixes, "bad", limit, false)
	}
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "bad", limit, false)
}

// FalsePositivesLightInPaths is like FalsePositivesInPaths but omits CleaveResult/LitmusResult.
func (db *DB) FalsePositivesLightInPaths(ctx context.Context, prefixes []string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.seedCandidatesInPathsPG(ctx, prefixes, "good", limit, true)
	}
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "good", limit, true)
}

// FalseNegativesLightInPaths is like FalseNegativesInPaths but omits CleaveResult/LitmusResult.
func (db *DB) FalseNegativesLightInPaths(ctx context.Context, prefixes []string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.seedCandidatesInPathsPG(ctx, prefixes, "bad", limit, true)
	}
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "bad", limit, true)
}

// CountByStatusInPaths returns sample counts grouped by status, filtered to
// samples whose path starts with one of the given prefixes.
func (db *DB) CountByStatusInPaths(ctx context.Context, prefixes []string) (map[string]int, error) {
	if db.pool != nil {
		return db.countByStatusInPathsPG(ctx, prefixes)
	}
	return db.countByStatusInPathsSQLite(ctx, prefixes)
}

// AgesByPaths returns a map of path → updated_at for samples under the given
// prefixes. Results are limited to avoid unbounded memory usage; pass 0 for
// a reasonable default (10000).
func (db *DB) AgesByPaths(ctx context.Context, prefixes []string, limit int) (map[string]time.Time, error) {
	if limit <= 0 {
		limit = 10000
	}
	if db.pool != nil {
		return db.agesByPathsPG(ctx, prefixes, limit)
	}
	return db.agesByPathsSQLite(ctx, prefixes, limit)
}

// StaleSamples returns samples under the given path prefixes whose updated_at
// is older than the given threshold, up to limit. Useful for finding samples
// that need re-analysis without loading all ages into memory.
func (db *DB) StaleSamples(ctx context.Context, prefixes []string, olderThan time.Time, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.staleSamplesPG(ctx, prefixes, olderThan, limit)
	}
	return db.staleSamplesSQLite(ctx, prefixes, olderThan, limit)
}

// SamplesByEmbeddedSHA256 returns samples whose cleave_result contains an
// embedded file with the given SHA256. This enables cross-sample dedup and
// incident response queries without fetching JSONB blobs into application code.
//
// PostgreSQL 17+ only (uses JSON_TABLE). Returns an error on SQLite.
func (db *DB) SamplesByEmbeddedSHA256(ctx context.Context, sha256 string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.samplesByEmbeddedSHA256PG(ctx, sha256, limit)
	}
	return db.samplesByEmbeddedSHA256SQLite(ctx, sha256, limit)
}

// BackfillStats reports the outcome of a Backfill run.
type BackfillStats struct {
	Scanned        int64 // rows examined
	Updated        int64 // rows where at least one derivable column changed
	MarkersCleared int64 // skip='misclassified' rows reset to skip='' under the new heuristic
}

// BackfillPending reports how much work each Backfill pass currently has.
type BackfillPending struct {
	CleaveColumns         int64 // elements / max_crit / suspicious_count from cleave_result
	FileTypeEmpties       int64 // file_type/score/formula left '' by the pre-v7 'fs'-only expression
	ArchiveMemberLitmus   int64 // archive members that still carry the parent's litmus_result blob
	ArchiveMemberAnalyzed int64 // archive members missing analyzed_at while their parent has it
	StaleGoodMarkers      int64 // good marker misclassification skips that can be cleared
	StaleBadMarkers       int64 // bad marker misclassification skips that can be cleared
}

// TotalRows is the sum of all pending backfill rows across passes.
func (p BackfillPending) TotalRows() int64 {
	return p.CleaveColumns + p.FileTypeEmpties + p.ArchiveMemberLitmus + p.ArchiveMemberAnalyzed + p.StaleGoodMarkers + p.StaleBadMarkers
}

const (
	archiveMemberLitmusBackfillBatch = 5000
	archiveMemberLitmusWorkers       = 24
)

// Backfill re-derives mutable columns from cleave_result and litmus_result,
// updating rows where the stored values disagree with what the parsers produce.
// Useful after parser changes or for rows that pre-date a column being
// populated on write.
//
// Currently backfills: elements, max_crit, suspicious_count, archive member
// litmus_result, archive member analyzed_at, and stale misclassified markers.
func (db *DB) Backfill(ctx context.Context) (BackfillStats, error) {
	var stats BackfillStats
	var err error
	if db.pool != nil {
		stats, err = db.backfillPG(ctx)
	} else {
		stats, err = db.backfillSQLite(ctx)
	}
	if err == nil {
		db.flushLookups()
	}
	return stats, err
}

// BackfillPending counts rows matched by each explicit Backfill pass.
func (db *DB) BackfillPending(ctx context.Context) (BackfillPending, error) {
	if db.pool != nil {
		return db.backfillPendingPG(ctx)
	}
	return db.backfillPendingSQLite(ctx)
}

// RehealCleaveCrit repairs max_crit/suspicious_count for rows the Postgres
// samples_derive_cleave_cols trigger zeroed before it learned the v8 'traits'
// trait key (see rehealCleaveCritPG). It is Postgres-only: the SQLite path
// derives these columns in Go via ParseCleaveResult, which has been v8-aware
// since the format landed, so SQLite rows were never affected. Returns the
// number of rows repaired.
func (db *DB) RehealCleaveCrit(ctx context.Context) (int64, error) {
	if db.pool == nil {
		return 0, nil
	}
	n, err := db.rehealCleaveCritPG(ctx)
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// BackfillPURL fills samples.purl_base for top-level rows that have a package
// coordinate but no stored PURL identity, rebuilding it from the ecosystem +
// package columns via the shared pkgparse builder (see backfillPURLPG). It never
// overwrites an existing purl_base. Postgres-only; the SQLite path is unused for
// this repair. Returns the number of rows filled.
func (db *DB) BackfillPURL(ctx context.Context) (int64, error) {
	if db.pool == nil {
		return 0, nil
	}
	n, err := db.backfillPURLPG(ctx)
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// CanonicalizePURLBases rewrites stored samples.purl_base values onto the
// current canonical spelling, in id-cursor batches that never lock more than
// one batch of rows at a time (see canonicalizePURLBasesPG). Idempotent and
// resumable; dryRun only reports. Postgres-only; the SQLite path is unused for
// this repair. Returns the number of rows rewritten (or that would be).
func (db *DB) CanonicalizePURLBases(ctx context.Context, dryRun bool) (int64, error) {
	if db.pool == nil {
		return 0, nil
	}
	n, err := db.canonicalizePURLBasesPG(ctx, dryRun)
	if err == nil && !dryRun && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// RepairStandaloneParents clears samples.parent on rows whose bytes are stored
// on disk under their own sha, so handleFile serves them directly instead of
// trying to extract them from an archive (see repairStandaloneParentsPG).
// Idempotent and resumable; dryRun only reports. Postgres-only. Returns the
// number of rows repaired (or that would be).
func (db *DB) RepairStandaloneParents(ctx context.Context, dryRun bool) (int64, error) {
	if db.pool == nil {
		return 0, nil
	}
	n, err := db.repairStandaloneParentsPG(ctx, dryRun)
	if err == nil && !dryRun && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// RemarkCorroborated re-derives samples.corroborated from the whole sightings
// ledger, returning how many samples were newly flagged. Postgres-only, like
// the canonicalisers it follows; the SQLite backend has no such maintenance
// path. See remarkCorroboratedPG for why it only ever sets the flag.
func (db *DB) RemarkCorroborated(ctx context.Context) (int64, error) {
	if db.pool == nil {
		return 0, nil
	}
	return db.remarkCorroboratedPG(ctx)
}

// CanonicalizeSightingSubjects rewrites stored sightings.subject values onto
// the ledger keying convention (see normalizeSubject): lowercase sha256,
// canonical version-less purl_base. Rows whose canonical spelling collides
// with an existing (source, subject) row are merged into it (the older row
// wins, preserving its first_seen). Idempotent; dryRun only reports.
// Postgres-only, like CanonicalizePURLBases. Returns rows rewritten.
func (db *DB) CanonicalizeSightingSubjects(ctx context.Context, dryRun bool) (int64, error) {
	if db.pool != nil {
		return db.canonicalizeSightingSubjectsPG(ctx, dryRun)
	}
	return 0, nil
}

// RecomputeCanonicalSHA256 recalculates canonical_sha256 for all analyzed
// samples using SQL-side JSON_TABLE, avoiding the need to fetch cleave_result
// blobs into Go. Returns the number of rows updated.
func (db *DB) RecomputeCanonicalSHA256(ctx context.Context) (int64, error) {
	var n int64
	var err error
	if db.pool != nil {
		n, err = db.recomputeCanonicalSHA256PG(ctx)
	} else {
		n, err = db.recomputeCanonicalSHA256SQLite(ctx)
	}
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// FeedQuery specifies filters for paginated feed queries.
type FeedQuery struct {
	Source     string   // "forager" or "upload" ("harvest" matches legacy rows)
	Label      string   // "bad", "good", "unknown", or "" (match any)
	OrderBy    string   // "mtime" (default), "created_at", or "analyzed_at"
	Formula    string   // optional: filter by exact cleave chemical formula
	Search     string   // optional free-text: case-insensitive filename substring OR exact sha256 OR exact package name
	Feeds      []string // optional: filter by feed column values
	Ecosystems []string // optional: filter by ecosystem column values
	Domains    []string // optional: filter by domain column values
	// PURLBase restricts the feed to one package identity: an exact match on
	// the indexed samples.purl_base column (the version-less canonical PURL,
	// e.g. "pkg:npm/lodash"). PURLVersion, when also set, pins the exact
	// release (samples.version). Both are exact equality — callers pass an
	// already-canonicalized value (see pkgparse.CanonicalizePURL /
	// VersionlessPURL); an empty field matches everything.
	PURLBase    string
	PURLVersion string
	// ClaimName / ClaimSigner restrict the feed to samples some identity
	// claim — registry or analyzer, via the asset_claims view — asserts to
	// carry this name / signer (exact equality, both view branches indexed).
	// ClaimSigner alone lists everything by one signer; with ClaimName it
	// pins the (name, voucher) pair a version-timeline UI groups by.
	ClaimName     string
	ClaimSigner   string
	LitmusClasses []int // optional: filter by litmus_result class values
	RequireLitmus bool  // require any litmus_result without filtering by class
	Corroborated  bool  // only samples cited by an external threat feed (samples.corroborated)
	TopLevelOnly  bool  // only samples that appear in no archive: parent = '' AND no parented sample_locations row (children may have multiple parents; the locations ledger is the authority)
	Offset        int   // pagination offset
	Limit         int   // page size (clamped to 1–1000)
	// CriticalLevel pins the hostile/suspicious cutoff used when deriving
	// criticality from a v6 envelope's `ml.l` (see LitmusClasses). Callers
	// set it to their own consumer-side definition so the class derivation
	// stays consistent across repos; a zero (unset) value falls back to the
	// package default [CriticalLevel].
	CriticalLevel int
}

// FeedSamples returns analyzed samples matching the query, newest first.
func (db *DB) FeedSamples(ctx context.Context, q *FeedQuery) ([]*Sample, error) {
	q.clamp()
	if db.pool != nil {
		return db.feedSamplesPG(ctx, q)
	}
	return db.feedSamplesSQLite(ctx, q)
}

// FeedSamplesCount returns the total number of samples matching the query.
func (db *DB) FeedSamplesCount(ctx context.Context, q *FeedQuery) (int, error) {
	if db.pool != nil {
		return db.feedSamplesCountPG(ctx, q)
	}
	return db.feedSamplesCountSQLite(ctx, q)
}

// FeedSources returns distinct feed values for samples matching source and label.
func (db *DB) FeedSources(ctx context.Context, source, label string) ([]string, error) {
	if db.pool != nil {
		return db.feedSourcesPG(ctx, source, label)
	}
	return db.feedSourcesSQLite(ctx, source, label)
}

// FeedEcosystems returns distinct ecosystem values for samples matching
// source and label. Pass source="" to span all sources (legacy "harvest"
// rows + new "forager" rows + manual uploads). A non-zero since restricts
// the result to ecosystems with at least one sample created at or after
// that time; a zero since spans all history.
func (db *DB) FeedEcosystems(ctx context.Context, source, label string, since time.Time) ([]string, error) {
	if db.pool != nil {
		return db.feedEcosystemsPG(ctx, source, label, since)
	}
	return db.feedEcosystemsSQLite(ctx, source, label, since)
}

// DistinctEcosystems returns every distinct non-empty ecosystem value
// currently stored across the samples and sample_locations tables. The
// ecosystem-normalization repair uses it to find legacy values that need
// remapping; it is not filtered by source or recency on purpose.
func (db *DB) DistinctEcosystems(ctx context.Context) ([]string, error) {
	if db.pool != nil {
		return db.distinctEcosystemsPG(ctx)
	}
	return db.distinctEcosystemsSQLite(ctx)
}

// UpdateEcosystems remaps stored ecosystem values per mapping (old → new),
// across both the samples and sample_locations tables, returning the total
// rows changed. A new value of "" clears the column — how labels that are no
// longer recognized runtimes (feed names, junk classifiers) are dropped.
//
// The whole remap runs as one statement per table rather than one per
// distinct value. That matters at scale: sample_locations has no index on
// ecosystem, so a per-value loop would seq-scan the (multi-million-row)
// table once for every value being rewritten. Callers should omit no-op
// entries (value mapping to itself); an empty mapping is a no-op.
func (db *DB) UpdateEcosystems(ctx context.Context, mapping map[string]string) (int64, error) {
	if len(mapping) == 0 {
		return 0, nil
	}
	if db.pool != nil {
		n, err := db.updateEcosystemsPG(ctx, mapping)
		if err == nil && n > 0 {
			db.flushLookups()
		}
		return n, err
	}
	n, err := db.updateEcosystemsSQLite(ctx, mapping)
	if err == nil && n > 0 {
		db.flushLookups()
	}
	return n, err
}

// sortedKeys returns m's keys in sorted order, so the generated SQL and its
// bound parameters are deterministic (stable logs, reproducible tests).
func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}

// FeedDomains returns distinct domain values (eTLD+1 of where bytes were
// fetched from) for samples matching source and label. Pass source=""
// to span all sources.
func (db *DB) FeedDomains(ctx context.Context, source, label string) ([]string, error) {
	if db.pool != nil {
		return db.feedDomainsPG(ctx, source, label)
	}
	return db.feedDomainsSQLite(ctx, source, label)
}

func (q *FeedQuery) clamp() {
	if q.Limit < 1 {
		q.Limit = 1
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
}

// criticalLevel resolves the hostile/suspicious cutoff for deriving criticality
// from a v6 litmus envelope's `ml.l`. A caller-pinned [FeedQuery.CriticalLevel]
// wins so the derivation matches its definition of hostile; an unset (zero)
// value falls back to the package default [CriticalLevel].
func (q *FeedQuery) criticalLevel() int {
	if q.CriticalLevel > 0 {
		return q.CriticalLevel
	}
	return CriticalLevel
}

// requireLitmus reports whether the feed query can be restricted to rows with a
// non-null litmus_result. It is true when the caller asked for it explicitly
// (RequireLitmus) and, additionally, whenever the criticality filter selects
// only non-benign classes: the class derivation maps a null litmus_result to
// class 0 (benign), so a LitmusClasses set that excludes 0 can never match a
// null-litmus row. Adding the predicate is therefore result-preserving, and it
// lets both the sample and count queries use idx_samples_eco_top_created (whose
// partial predicate includes litmus_result IS NOT NULL) instead of falling back
// to a heap recheck.
func (q *FeedQuery) requireLitmus() bool {
	if q.RequireLitmus {
		return true
	}
	if len(q.LitmusClasses) == 0 {
		return false
	}
	return !slices.Contains(q.LitmusClasses, 0)
}

// feedClassExpr returns the SQL expression that yields a sample's criticality
// class (0=benign, 1=suspicious, 2=hostile) for the feed's class filter. When
// the query's cutoff is the default CriticalLevel it returns the trigger-
// maintained litmus_class column, which idx_samples_eco_class_created can index
// — turning a rare class in a large ecosystem from a per-row JSONB scan into an
// ordered seek. A non-default [FeedQuery.CriticalLevel] re-derives the class from
// litmus_result inline (litmus_class is pinned to CriticalLevel, so it cannot
// answer a different cutoff). The cutoff is an int from trusted config, inlined
// as a literal — the same approach as workflowSamplesPG — rather than a bound
// parameter: a conditionally-referenced parameter would dangle untyped when the
// column path is taken instead, which Postgres rejects (SQLSTATE 42P18). The
// inline form is identical to the trigger's, workflowSamplesPG's, and
// backfillLitmusClassPG's — including the SuspiciousCeiling cap above which a
// firing reads benign; keep all four in sync.
func (q *FeedQuery) feedClassExpr() string {
	if q.criticalLevel() == CriticalLevel {
		return "litmus_class"
	}
	cutoff := strconv.Itoa(q.criticalLevel())
	ceiling := strconv.Itoa(SuspiciousCeiling)
	return `COALESCE(
				(litmus_result->>'class')::int,
				CASE
					WHEN litmus_result IS NULL THEN 0
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l') IS NULL THEN 2
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int < 0 THEN 0
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int <= ` + cutoff + ` THEN 2
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int <= ` + ceiling + ` THEN 1
					ELSE 0
				END)`
}

// likeEscaper neutralizes the LIKE wildcards (% and _) and the escape
// character itself so a free-text term matches literally. Pair with
// `ESCAPE '\'` in the SQL.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// searchTerm normalizes [FeedQuery.Search] for the feed predicate: lowercased
// so an exact sha256 matches the lowercase-stored column (filename matching is
// case-insensitive regardless), with LIKE metacharacters escaped so the term
// is a literal substring in the filename ILIKE rather than a wildcard pattern.
// The same escaped value backs the `sha256 = $n` equality: a valid sha256 is
// 64 hex chars, which contain no LIKE metacharacters, so escaping never alters
// a value that could match. Empty Search yields "", which the SQL guards read
// as "match everything".
func (q *FeedQuery) searchTerm() string {
	if q.Search == "" {
		return ""
	}
	return likeEscaper.Replace(strings.ToLower(q.Search))
}

// packageTerm normalizes [FeedQuery.Search] for the exact package-name disjunct
// of the feed predicate. It is lowercased — registry names in the ecosystems
// that matter (npm, pypi, …) are lowercase-normalized, and callers lowercase the
// box term too — but, unlike [searchTerm], it is NOT LIKE-escaped: it backs a
// `package = $n` equality against the indexed package column, not a LIKE
// pattern, so escaping would corrupt the common names that carry '_' (e.g.
// python_dateutil). This turns a bare package name typed into the search box
// into an indexed exact hit even when the filename embeds no such substring
// (e.g. "xz-utils" against xz-5.6.1.tar.gz). Empty Search yields "".
func (q *FeedQuery) packageTerm() string {
	if q.Search == "" {
		return ""
	}
	return strings.ToLower(q.Search)
}

// sortBy returns the full ORDER BY direction clause for the configured
// column, including the right NULLS placement so the planner can use the
// matching partial index as an ordered scan rather than falling back to a
// top-N heapsort. The column-specific NULLS clauses match the indexes
// created in pg.go (idx_samples_feed_source / _mtime carry NULLS LAST;
// the created_at indexes do not — and don't need to since the column is
// NOT NULL).
func (q *FeedQuery) sortBy() string {
	switch q.OrderBy {
	case "created_at":
		// created_at is NOT NULL, so a NULLS clause is redundant and
		// would prevent the planner from using DESC indexes (which
		// default to NULLS FIRST for DESC). Omit it.
		return "created_at DESC"
	case "analyzed_at":
		return "analyzed_at DESC NULLS LAST"
	default:
		return "mtime DESC NULLS LAST"
	}
}

// Sighting is one external-corroboration record: an outside source (threat
// feed, scanner, blog, advisory) cited a subject.
//
// Subject is either a lowercase-hex sha256 or a PURL. For a PURL the canonical
// form is the VERSION-LESS purl_base (pkg:npm/lodash, not pkg:npm/lodash@1.2.3):
// it is what samples.purl_base holds and what prism queries, so both the
// corroborated-flag match and SightingsFor are clean exact-equality lookups. A
// source that flagged one specific version records that version in Note or URL,
// not in Subject. The zero value is a harmless no-op that AddSightings skips.
type Sighting struct {
	FirstSeen time.Time // set by the store on first insert; ignored on write
	Source    string    // 'aikido','osv','socket','clamav','cyclotron:bleepingcomputer'
	Subject   string    // a sha256, or a version-less PURL (purl_base)
	URL       string    // advisory / blog / report link (optional)
	Note      string    // source's own tag: 'malware','MAL-2024-1234' (optional)
}

// sightingFamilies maps sighting sources that repackage a shared upstream
// corpus to one family name, so corroboration counts distinct evidence, not
// distinct mirrors. Measured 2026-07: ghsa and supplychain
// (supplychainattack.org, curated "predominantly from the GitHub Advisory
// Database" per its own description) shared 131 of supplychain's 145
// subjects; OSV.dev's MAL- records ARE the OSSF malicious-packages corpus.
// aikido and ossf overlap on 41 subjects but have distinct pipelines — kept
// separate for now; re-measure if aikido corroborations look inflated.
var sightingFamilies = map[string]string{
	"ghsa":        "github-advisories",
	"supplychain": "github-advisories",
	"osv":         "ossf-malpkgs",
	"ossf":        "ossf-malpkgs",
}

// SightingFamily returns the evidence family a sighting source belongs to.
// Sources without a mapping are their own family (including per-feed
// "cyclotron:<url>" sources and "clamav"). Promotion rules that require N
// independent sources must count distinct families, not distinct sources —
// two mirrors of the same advisory database are one piece of evidence.
func SightingFamily(source string) string {
	if fam, ok := sightingFamilies[source]; ok {
		return fam
	}
	return source
}

// valid reports whether the sighting carries the minimum to be stored: a source
// and a subject that is a sha256 or a PURL. Callers should normalize a sha256 to
// lowercase before this; a PURL is matched by its "pkg:" prefix.
func (s Sighting) valid() bool {
	if s.Source == "" || s.Subject == "" {
		return false
	}
	return isSHA256Hex(s.Subject) || strings.HasPrefix(s.Subject, "pkg:")
}

// normalizeSubject folds a sighting subject onto the ledger's keying
// convention so every consumer's exact-equality join (corroborated flag,
// SightingsFor, promoter's family counting, the sha-cited sweep) hits:
// sha256 subjects lowercase, PURL subjects on the canonical version-less
// purl_base spelling — the same normalization samples.purl_base carries
// (pkgparse.CanonicalizePURL + VersionlessPURL; a source that flagged one
// specific version records it in Note or URL, never in Subject). Anything
// else is passed through for valid() to reject.
//
// A PURL whose name component is itself a sha256 is folded back to the bare
// digest. Hash corpora cite BYTES, and a producer that pairs a digest with an
// ecosystem mints pkg:<eco>/<64 hex> without noticing — a 64-character hex
// string is a legal package name in every registry that takes free-form names,
// so nothing upstream refuses it. The result matches no package and no file:
// 1,050 such rows accumulated from bazaar and triage, 901 of them naming
// samples we hold, and 767 of those were convicted malware that then read as
// UNCORROBORATED to the queue whose job is overturning convictions.
//
// Coerced rather than rejected, deliberately. The citation is real and the
// digest is right there in the string; refusing it would discard evidence
// abuse.ch correctly reported. Because CanonicalizeSightingSubjects re-runs
// this over stored rows, teaching it the shape also repairs the existing ones
// in place — keeping each row's source, url and first_seen — rather than
// needing them deleted and re-fetched.
func normalizeSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if lower := strings.ToLower(subject); isSHA256Hex(lower) {
		return lower
	}
	if sha, ok := digestWearingAPURL(subject); ok {
		return sha
	}
	if canon := pkgparse.VersionlessPURL(pkgparse.CanonicalizePURL(subject)); canon != "" {
		return canon
	}
	return subject
}

// digestWearingAPURL reports the sha256 inside a purl whose name component is a
// digest, e.g. pkg:npm/<64 hex>. Any version, qualifier or subpath is ignored:
// the digest identifies the bytes and the rest is noise a producer added.
func digestWearingAPURL(subject string) (string, bool) {
	if !strings.HasPrefix(subject, "pkg:") {
		return "", false
	}
	name := subject[strings.LastIndex(subject, "/")+1:]
	if i := strings.IndexAny(name, "@?#"); i >= 0 {
		name = name[:i]
	}
	if lower := strings.ToLower(name); isSHA256Hex(lower) {
		return lower, true
	}
	return "", false
}

// splitSightingSubjects partitions ledger subjects into sha256 digests and
// purl_base keys. Mark-corroborated updates MUST hit each column separately:
// a single `sha256 = ANY(...) OR purl_base = ANY(...)` predicate forces a
// sequential scan of samples (tens of millions of rows), which blows the
// /api/sightings timeout. PK / idx_samples_purl_base look-ups stay cheap.
func splitSightingSubjects(subs []string) (shas, purls []string) {
	for _, s := range subs {
		if isSHA256Hex(s) {
			shas = append(shas, s)
		} else {
			purls = append(purls, s)
		}
	}
	return shas, purls
}

// AddSightings idempotently upserts external-corroboration records and flips
// samples.corroborated true for any sample whose sha256 or purl_base a newly
// changed sighting matches. Subjects are normalized onto the ledger's keying
// convention first (see normalizeSubject), so producers may send whatever
// spelling they hold. Re-recording an unchanged sighting is a no-op (the
// delta-guarded upsert writes nothing), so a producer may safely re-push a whole
// feed snapshot on every poll. Invalid entries (missing source, or a subject
// that is neither a sha256 nor a PURL) are skipped. Returns the number of
// sightings inserted or updated.
func (db *DB) AddSightings(ctx context.Context, s []Sighting) (int, error) {
	// Dedupe by (source, subject) within the batch — first occurrence wins.
	// Producers naturally repeat pairs (two versions of one package share a
	// purl_base; normalization can collapse two spellings into one subject),
	// and Postgres rejects an upsert that touches the same row twice
	// (SQLSTATE 21000).
	seen := make(map[[2]string]struct{}, len(s))
	valid := s[:0:0]
	for _, x := range s {
		x.Subject = normalizeSubject(x.Subject)
		if !x.valid() {
			continue
		}
		key := [2]string{x.Source, x.Subject}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		valid = append(valid, x)
	}
	if len(valid) == 0 {
		return 0, nil
	}
	if db.pool != nil {
		return db.addSightingsPG(ctx, valid)
	}
	return db.addSightingsSQLite(ctx, valid)
}

// SightingsFor returns every sighting whose subject is in subjects, grouped by
// subject. Callers pool the sha256 and purl_base of the samples they are
// rendering (one page, or one sample's [sha, purl]) and read the map back. An
// empty subjects slice returns an empty map.
func (db *DB) SightingsFor(ctx context.Context, subjects []string) (map[string][]Sighting, error) {
	out := make(map[string][]Sighting, len(subjects))
	if len(subjects) == 0 {
		return out, nil
	}
	if db.pool != nil {
		return db.sightingsForPG(ctx, subjects)
	}
	return db.sightingsForSQLite(ctx, subjects)
}

// InsertReport stores an analysis report. Multiple reports per sample are allowed;
// LatestReport returns the most recent.
func (db *DB) InsertReport(ctx context.Context, r *Report) error {
	if db.pool != nil {
		return db.insertReportPG(ctx, r)
	}
	return db.insertReportSQLite(ctx, r)
}

// TryClaimSample acquires an expiring exclusive lease on sha256. The lease is
// stored on the sample row, so every process sharing the database observes the
// same owner. A stale lease may be replaced after ttl; a live lease, including
// one held by the same owner string, is not re-entrant. Callers should therefore
// use a unique owner per unit of work and release it when all feedback is done.
func (db *DB) TryClaimSample(ctx context.Context, sha256, owner string, ttl time.Duration) (bool, error) {
	if sha256 == "" || owner == "" || ttl <= 0 {
		return false, nil
	}
	staleBefore := time.Now().Add(-ttl)
	var ok bool
	var err error
	if db.pool != nil {
		ok, err = db.tryClaimSamplePG(ctx, sha256, owner, staleBefore)
	} else {
		ok, err = db.tryClaimSampleSQLite(ctx, sha256, owner, staleBefore)
	}
	if err == nil && ok {
		db.forgetSHA(sha256)
	}
	return ok, err
}

// ReleaseSampleClaim releases sha256 only when owner still holds its lease.
// It is idempotent: expiry, replacement, or a repeated release is a no-op.
func (db *DB) ReleaseSampleClaim(ctx context.Context, sha256, owner string) error {
	if sha256 == "" || owner == "" {
		return nil
	}
	if db.pool != nil {
		return db.writeSHA(sha256, db.releaseSampleClaimPG(ctx, sha256, owner))
	}
	return db.writeSHA(sha256, db.releaseSampleClaimSQLite(ctx, sha256, owner))
}

// ReportsBySHA256 returns all reports for a sample, newest first.
func (db *DB) ReportsBySHA256(ctx context.Context, sha256 string) ([]*Report, error) {
	if db.pool != nil {
		return db.reportsBySHA256PG(ctx, sha256)
	}
	return db.reportsBySHA256SQLite(ctx, sha256)
}

// LatestReport returns the most recent report of a given type for a sample.
// Returns ErrNotFound if no such report exists.
func (db *DB) LatestReport(ctx context.Context, sha256, reportType string) (*Report, error) {
	if db.pool != nil {
		return db.latestReportPG(ctx, sha256, reportType)
	}
	return db.latestReportSQLite(ctx, sha256, reportType)
}

// ReportIngestStats summarizes one IngestReportsDir run.
type ReportIngestStats struct {
	Scanned              int
	Inserted             int
	SkippedExisting      int
	SkippedMissingSample int
	SkippedInvalid       int
}

// IngestReportsDir walks dir for files named "<sha256>.md" and inserts each
// as a report of the given type and provider. Reports whose content matches
// the latest stored report for that sample are skipped. Reports for samples
// hopper has never seen are counted under SkippedMissingSample and ignored.
//
// This is the single ingest path used by both the `hopper ingest-reports`
// CLI and cyclotron's startup self-heal — keep them in sync by editing here.
func (db *DB) IngestReportsDir(ctx context.Context, dir, reportType, provider string) (ReportIngestStats, error) {
	var stats ReportIngestStats
	if dir == "" {
		return stats, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return stats, fmt.Errorf("stat reports dir: %w", err)
	}
	if !info.IsDir() {
		return stats, fmt.Errorf("reports path is not a directory: %s", dir)
	}
	walkErr := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			if path != dir && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		stats.Scanned++
		name := entry.Name()
		if filepath.Ext(name) != ".md" {
			stats.SkippedInvalid++
			return nil
		}
		sha := strings.TrimSuffix(name, ".md")
		if !isLowerHexSHA256(sha) {
			stats.SkippedInvalid++
			return nil
		}
		if _, err := db.SampleBySHA256(ctx, sha); err != nil {
			if errors.Is(err, ErrNotFound) {
				stats.SkippedMissingSample++
				return nil
			}
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if existing, err := db.LatestReport(ctx, sha, reportType); err == nil {
			if existing.Content == string(content) {
				stats.SkippedExisting++
				return nil
			}
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := db.InsertReport(ctx, &Report{
			SHA256:   sha,
			Type:     reportType,
			Content:  string(content),
			Provider: provider,
		}); err != nil {
			return err
		}
		stats.Inserted++
		return nil
	})
	if walkErr != nil {
		return stats, fmt.Errorf("walk reports dir: %w", walkErr)
	}
	return stats, nil
}
