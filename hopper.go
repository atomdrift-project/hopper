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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
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
// (manual-mode hostile) is hostile. Mirrors DefaultSeverityLevel in collimator,
// litmus, autocollie, prism, and promoter — see
// collimator/src/collimator/thresholds/__init__.py for the cross-repo group.
//
// It is the default for feed queries that don't pin their own cutoff via
// [FeedQuery.CriticalLevel]; callers should pin it so a future divergence in
// any one repo can't silently desync the class derivation.
const CriticalLevel = 4

// Pool labels, ordered by precedence: bad > good > unknown.
const (
	labelUnknown = "unknown"
	labelGood    = "good"
	labelBad     = "bad"
)

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
// outranks unknown. Used to decide whether a re-observation promotes a sample.
func labelRank(label string) int {
	switch label {
	case labelBad:
		return 2
	case labelGood:
		return 1
	default:
		return 0
	}
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
	parent, leaves, err := Split(mustMarshal(map[string]json.RawMessage{"raw": json.RawMessage(result)}))
	if err != nil || len(leaves) == 0 {
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
	backfillProgress atomic.Pointer[BackfillProgressFn]
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
	SHA256          string
	Source          string
	Feed            string
	Ecosystem       string
	URL             string // canonical URL the bytes were fetched from
	Domain          string // registered domain (eTLD+1), populated via golang.org/x/net/publicsuffix
	Package         string // software package this file belongs to, e.g. "lodash" or "@vue/cli"
	Version         string // package version, e.g. "4.17.21"
	PURLBase        string // version-less canonical PURL, e.g. "pkg:npm/lodash"; "" if not a known package ecosystem
	Filename        string
	FileType        string
	Label           string // "bad", "good", "unknown"
	LabelSource     string
	Path            string
	Status          string
	Note            string
	CanonicalSHA256 string // min SHA256 across sample + embedded files; for train/test split
	Parent          string // SHA256 of archive this was extracted from; "" for top-level
	Skip            string // non-empty = excluded from training, value = reason
	Formula         string // cleave chemical formula (behavioral signature)
	Elements        string // formula without counts (qualitative composition)
	TraitsVersion   string // short prefix of traits repo commit used for analysis
	AnalyzedAt      *time.Time
	FirstAnalyzedAt *time.Time
	LastErrorAt     *time.Time
	Mtime           *time.Time
	MarkerMtime     *time.Time
	FetchedAt       *time.Time // when the collector fetched the artifact (UTC); distinct from CreatedAt
	CleaveResult    []byte     // raw cleave JSON, nil if unanalyzed
	LitmusResult    []byte     // litmus classification envelope JSON, nil if unclassified
	LLMResult       []byte     // LLM interpretation JSON (envelope `llm`), nil when no interpretation pass ran
	Provenance      []byte     // collector provenance sidecar JSON, nil if none
	LitmusScore     float64    // litmus confidence score (0.0-1.0)
	ID              int64
	SizeBytes       int64
	Score           int // cleave raw score
	MaxCrit         int // max trait criticality level (5=hostile, 4=suspicious, ...)
	SuspiciousCount int // count of traits with level>=4 (suspicious or hostile)
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
// upsert-keyed on (sha256, path): re-observing the same pair bumps
// last_seen_at and refreshes mtime.
type SampleLocation struct {
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
	Mtime        *time.Time
	SHA256       string
	Path         string
	ParentSHA256 string // sha of the archive this observation was extracted from; "" if top-level
	Filename     string
	Source       string // "forager", "upload", ... ("harvest" persists on legacy rows)
	Feed         string
	Ecosystem    string
	ID           int64
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
	Type       string // "re", "gap", "fpr"
	Content    string
	Provider   string
	ID         int64
	DurationMS int
}

// cleaveFileInfo holds per-file metadata extracted from a cleave result.
type cleaveFileInfo struct {
	Formula         string
	Elements        string
	FileType        string
	Score           int
	MaxCrit         int
	SuspiciousCount int
}

// CleaveParseResult holds all metadata extracted from a single JSON parse
// of a cleave result, combining file info and canonical SHA computation.
type CleaveParseResult struct {
	CanonicalSHA  string
	TraitsVersion string // "tv" field from compact report (first 5 chars of traits commit)
	FileInfo      cleaveFileInfo
}

type cleaveTraitEntry struct {
	Conf     float64 `json:"conf"`
	OldConf  float64 `json:"c"`
	Level    int     `json:"crit"`
	OldLevel int     `json:"l"`
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
	for i := range report.Files {
		f := &report.Files[i]
		if len(f.SHA256) == 64 && f.SHA256 < canonical {
			canonical = f.SHA256
		}
	}

	// File info for the matching entry.
	var fi cleaveFileInfo
	for i := range report.Files {
		f := &report.Files[i]
		depth := f.Depth
		if depth == 0 {
			depth = f.OldDepth
		}
		if f.SHA256 != sha256 && depth != 0 {
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
			}
		}
		fi = cleaveFileInfo{
			Formula:         formula,
			Elements:        stripSubscripts(formula),
			FileType:        f.FileType,
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
	return CleaveParseResult{CanonicalSHA: canonical, FileInfo: fi, TraitsVersion: tv}
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
			SHA256   string        `json:"sha"`
			FileType string        `json:"type"`
			Path     string        `json:"path"`
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

		skip := ""
		if e.parent.Label == "bad" && maxLevel < 5 && suspiciousCount <= 1 {
			skip = skipBenignArchiveItem
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
			Source:          e.parent.Source,
			Feed:            e.parent.Feed,
			Ecosystem:       e.parent.Ecosystem,
			Filename:        inArchive,
			FileType:        entry.FileType,
			SizeBytes:       entry.Size,
			Label:           e.parent.Label,
			LabelSource:     e.parent.LabelSource,
			Path:            memberPath,
			CleaveResult:    singleFile,
			LitmusResult:    e.litmus.forMember(id),
			CanonicalSHA256: e.parent.CanonicalSHA256,
			Parent:          e.parent.SHA256,
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
		return db.refreshStaleMemberAnalysisPG(ctx, rows)
	}
	return db.refreshStaleMemberAnalysisSQLite(ctx, rows)
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
		return db.setSkipPG(ctx, sha256, skip)
	}
	return db.setSkipSQLite(ctx, sha256, skip)
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
	if db.pool != nil {
		return db.incrementAttemptsPG(ctx, shas)
	}
	return db.incrementAttemptsSQLite(ctx, shas)
}

// ReapStuck marks pending samples claimed MaxClaimAttempts or more times
// without a result as skip='stuck', removing them from the pending pool.
// Returns the number reaped.
func (db *DB) ReapStuck(ctx context.Context) (int64, error) {
	if db.pool != nil {
		return db.reapStuckPG(ctx, maxClaimAttempts)
	}
	return db.reapStuckSQLite(ctx, maxClaimAttempts)
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
	if db.pool != nil {
		return db.deleteSamplePG(ctx, sha256)
	}
	return db.deleteSampleSQLite(ctx, sha256)
}

// PurgeUnsupported deletes all samples that were analyzed but for which
// cleave produced no recognized file type — rows that slipped past
// ingest-time classification and carry no analytical value. Returns the
// number of rows deleted. When dryRun is true, the query runs as a
// SELECT count(*) and no rows are removed.
//
// Uses the idx_samples_file_type index, so it's cheap even on large tables.
func (db *DB) PurgeUnsupported(ctx context.Context, dryRun bool) (int64, error) {
	if db.pool != nil {
		return db.purgeUnsupportedPG(ctx, dryRun)
	}
	return db.purgeUnsupportedSQLite(ctx, dryRun)
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
	if db.pool != nil {
		return db.applyCleanupPG(ctx, stage)
	}
	return db.applyCleanupSQLite(ctx, stage)
}

// Open connects to the registry. DSNs starting with postgres:// or
// postgresql:// use PostgreSQL; everything else is treated as a SQLite path.
func Open(ctx context.Context, dsn string) (*DB, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return openPG(ctx, dsn)
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
// migrations — the index builds. The caller should run that function in the
// background after it begins serving: a missing index only makes queries
// slower, never wrong, and building one on a large table can take many minutes
// — long enough to strand workers if it blocks startup. On SQLite everything is
// applied up front (local databases are small and have no serving-gap concern)
// and the returned function is a no-op.
func (db *DB) MigrateServing(ctx context.Context) (func(context.Context) error, error) {
	if db.pool != nil {
		// allowRewrite is false: the serving path must never run a
		// table-rewriting migration on a populated samples table, since the
		// ACCESS EXCLUSIVE lock would freeze every reader and writer for the
		// length of the rewrite. Such a migration is deferred to `hopper init`.
		return db.migrateServingPG(ctx, false)
	}
	if err := db.migrateSQLite(ctx); err != nil {
		return nil, err
	}
	return func(context.Context) error { return nil }, nil
}

// DeleteAll removes all rows from reports and samples, preserving the schema.
func (db *DB) DeleteAll(ctx context.Context) error {
	if db.pool != nil {
		return db.deleteAllPG(ctx)
	}
	return db.deleteAllSQLite(ctx)
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

// InsertSampleNew adds a sample and reports whether the row was actually inserted
// (true) or was a duplicate that was silently skipped (false). Samples with an
// empty sha256 or path are rejected — callers should have derived both before
// reaching the DB layer.
func (db *DB) InsertSampleNew(ctx context.Context, s *Sample) (bool, error) {
	if !validSample(s) {
		slog.Warn("rejecting invalid sample", "sha256", s.SHA256, "path", s.Path)
		return false, nil
	}
	if db.pool != nil {
		return db.insertSampleNewPG(ctx, s)
	}
	return db.insertSampleNewSQLite(ctx, s)
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
		valid = append(valid, s)
	}
	if skipped > 0 {
		slog.Warn("dropped invalid samples from batch", "skipped", skipped, "batch", len(samples))
	}
	if len(valid) == 0 {
		return 0, nil, nil
	}
	if db.pool != nil {
		return db.insertSampleBatchPG(ctx, valid)
	}
	return db.insertSampleBatchSQLite(ctx, valid)
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
		return db.pruneMissingLocationsPG(ctx, absRoot, maxFraction)
	}
	return db.pruneMissingLocationsSQLite(ctx, absRoot, maxFraction)
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

// PURLPromotion reports the outcome of PromoteLabelByPURL.
type PURLPromotion struct {
	// Present is true when hopper already holds a non-missing sample for the
	// queried (purlBase, version); the collector can skip re-downloading.
	Present bool
	// Promoted counts samples whose label or skip the feed observation changed.
	Promoted int
}

// labelResolution is the post-precedence state of a sample after an incoming
// (label, source) observation, mirroring the sample-upsert conflict clause.
type labelResolution struct {
	label, labelSource, skip string
	changed                  bool
}

// resolveIncomingLabel applies an incoming (incLabel, incSource) observation to
// a sample currently at (curLabel, curSource, curSkip) and returns the resolved
// state. It mirrors sampleConflictUpdate{SQLite,PG} (the INSERT...ON CONFLICT
// label/label_source/skip CASE ladders) exactly, so a label asserted without a
// re-download resolves identically to one carried by a walk:
//   - a marker observation wins; an existing marker is overridden by a
//     non-marker observation (as the upsert does);
//   - opposite poles (good vs bad) resolve to bad/conflict;
//   - otherwise a strictly higher-ranked label wins; ties keep the current one.
//
// It deviates in exactly one, deliberate way: it never resurrects a sample whose
// skip is 'missing' or 'unsupported'. The upsert clears those because re-seeing
// a file proves the bytes are back; a feed sighting carries no bytes, so the
// label is promoted but skip is preserved — the row is restored (and skip
// cleared) only by an actual re-download.
func resolveIncomingLabel(curLabel, curSource, curSkip, incLabel, incSource string) labelResolution {
	opposite := (curLabel == labelGood && incLabel == labelBad) || (curLabel == labelBad && incLabel == labelGood)
	higher := labelRank(incLabel) > labelRank(curLabel)

	out := labelResolution{label: curLabel, labelSource: curSource, skip: curSkip}

	switch {
	case incSource == labelSourceMarker:
		out.label, out.labelSource = incLabel, labelSourceMarker
	case curSource == labelSourceMarker:
		out.label, out.labelSource = incLabel, incSource
	case opposite:
		out.label, out.labelSource = labelBad, labelSourceConflict
	case higher:
		out.label, out.labelSource = incLabel, incSource
	}

	// Bytes are not proven present here, so a missing/unsupported sample keeps
	// its skip even as its label is promoted (see doc comment).
	if curSkip != "missing" && curSkip != "unsupported" {
		switch {
		case incSource == labelSourceMarker:
			out.skip = skipMisclassified
		case curSource == labelSourceMarker && curSkip == skipMisclassified:
			out.skip = ""
		case opposite && (curSkip == "" || curSkip == skipMisclassified || curSkip == skipConflict):
			out.skip = skipConflict
		case higher && (curSkip == skipMisclassified || curSkip == skipConflict):
			out.skip = ""
		}
	}

	out.changed = out.label != curLabel || out.labelSource != curSource || out.skip != curSkip
	return out
}

// PromoteLabelByPURL records that a feed reported the package identity purlBase
// at version with (label, labelSource), promoting every top-level sample hopper
// already holds for that exact package@version per resolveIncomingLabel and
// writing a label_event for each change. It also reports whether a non-missing
// copy already exists, so a collector can skip re-downloading bytes hopper
// already has while still upgrading an 'unknown' row to 'bad'.
//
// The scan is a single indexed probe (idx_samples_purl_base) touching only the
// handful of rows for one package@version. A blank purlBase, version, or label
// is a no-op.
func (db *DB) PromoteLabelByPURL(ctx context.Context, purlBase, version, label, labelSource, feed string) (PURLPromotion, error) {
	if purlBase == "" || version == "" || label == "" {
		return PURLPromotion{}, nil
	}
	if db.pool != nil {
		return db.promoteLabelByPURLPG(ctx, purlBase, version, label, labelSource, feed)
	}
	return db.promoteLabelByPURLSQLite(ctx, purlBase, version, label, labelSource, feed)
}

// purlCandidate is one sample matched by (purl_base, version) during promotion.
type purlCandidate struct {
	sha, label, source, skip string
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
	if db.pool != nil {
		return db.sampleBySHA256PG(ctx, sha256)
	}
	return db.sampleBySHA256SQLite(ctx, sha256)
}

// KnownSHA256 returns the subset of the given digests that already have a
// sample row. It is a deliberately minimal existence probe — a single
// index-only scan of the unique sha256 key, hydrating no row data — so a bulk
// producer (a remote forager) can skip transferring bytes hopper already holds.
// Order is unspecified; treat the result as a set. Callers must bound the input
// size; the API edge caps it.
func (db *DB) KnownSHA256(ctx context.Context, shas []string) ([]string, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	known := make([]string, 0, len(shas))

	if db.pool != nil {
		rows, err := db.pool.Query(ctx, `SELECT sha256 FROM samples WHERE sha256 = ANY($1)`, shas)
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
	rows, err := db.lite.QueryContext(ctx, `SELECT sha256 FROM samples WHERE sha256 IN (`+strings.Join(placeholders, ",")+`)`, args...)
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
// flows that need a self-generated secret to converge across replicas.
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
		return db.requestRescanPG(ctx, sha256, cutoff)
	}
	return db.requestRescanSQLite(ctx, sha256, cutoff)
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
// If cleave could not classify the file (FileType == ""), the row is deleted —
// the belt-and-suspenders complement to cleave's ingest-time filter.
func (db *DB) StoreResult(ctx context.Context, sha256 string, cleaveRaw, litmusML, llm []byte, parsed *CleaveParseResult, traitsVersion string) (StoreStats, error) {
	var p CleaveParseResult
	if parsed != nil {
		p = *parsed
	} else {
		p = ParseCleaveResult(sha256, cleaveRaw)
	}
	if p.FileInfo.FileType == "" {
		return StoreStats{}, db.DeleteSample(ctx, sha256)
	}
	now := time.Now().UTC()
	if db.pool != nil {
		return db.storeResultPG(ctx, sha256, cleaveRaw, litmusML, llm, p, traitsVersion, now)
	}
	return db.storeResultSQLite(ctx, sha256, cleaveRaw, litmusML, llm, p, traitsVersion, now)
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
		return db.updateCleaveResultPG(ctx, sha256, result, p.CanonicalSHA, p.FileInfo, traitsVersion)
	}
	return db.updateCleaveResultSQLite(ctx, sha256, result, p.CanonicalSHA, p.FileInfo, traitsVersion)
}

// UpdateLitmusResult stores the litmus classification envelope for a sample.
// The result should be the litmus response JSON without the embedded cleave field.
// litmus_score is a GENERATED column on samples and updates automatically from
// the new envelope — no separate score parameter needed.
func (db *DB) UpdateLitmusResult(ctx context.Context, sha256 string, result []byte) error {
	if db.pool != nil {
		return db.updateLitmusResultPG(ctx, sha256, result)
	}
	return db.updateLitmusResultSQLite(ctx, sha256, result)
}

// UpdateLLMResult stores the optional LLM interpretation (envelope `llm`) for a
// sample. The interpretation pass is gated, so most results carry none; an empty
// result clears the column to NULL so a rescan that drops the pass doesn't leave
// a stale interpretation behind.
func (db *DB) UpdateLLMResult(ctx context.Context, sha256 string, result []byte) error {
	if db.pool != nil {
		return db.updateLLMResultPG(ctx, sha256, result)
	}
	return db.updateLLMResultSQLite(ctx, sha256, result)
}

// MarkCyclotronAttempt stamps cyclotron_attempted_at = now() so the sample
// drops out of the FP/FN seed pool for seedReanalysisCooldown. Cyclotron calls
// this when it first commits to working on a sample (initial status seed) so a
// sample that resists remediation can't tight-loop through the seed queue.
func (db *DB) MarkCyclotronAttempt(ctx context.Context, sha256 string) error {
	if db.pool != nil {
		_, err := db.pool.Exec(ctx,
			`UPDATE samples SET cyclotron_attempted_at = now() WHERE sha256 = $1`, sha256)
		return err
	}
	_, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET cyclotron_attempted_at = ? WHERE sha256 = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), sha256)
	return err
}

// Reclassify changes a sample's label.
func (db *DB) Reclassify(ctx context.Context, sha256, label, source string) error {
	if db.pool != nil {
		return db.reclassifyPG(ctx, sha256, label, source)
	}
	return db.reclassifySQLite(ctx, sha256, label, source)
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
	Relabeled         int64 // top-level samples whose pool label/skip changed
	MarkedMissing     int64 // standalone files gone from disk
	MarkedUnsupported int64 // standalone files present but not enumerated
	CascadedMissing   int64 // archive members orphaned by a missing parent
	Revived           int64 // members whose containing archive reappeared
}

// ReconcilePools makes samples.label/skip authoritative against the current
// state of the good/ and bad/ pool directories. It runs at the end of a full
// walk and reconciles the derived label/skip cache to the truth — correcting
// the monotonic, one-observation-at-a-time approximation the insert-time upsert
// can only build mid-walk — using sample_locations as the source of truth for
// presence and containment.
//
// It does four things, in order:
//  1. Relabels top-level samples from the pools they currently live in: a file
//     moved bad→good is demoted to good, good→bad is promoted to bad, and a file
//     asserted in both pools at once resolves to bad with skip='conflict'.
//  2. Marks standalone files not seen this walk as skip='missing' (gone) or
//     'unsupported' (present on disk but not enumerated).
//  3. Cascades skip='missing' to archive members orphaned by a missing parent —
//     unless the member is still reachable through another live archive (the
//     supply-chain case: a benign file shared with a present package survives).
//  4. Revives members whose containing archive reappeared.
//
// Presence is read from walk_staging, which the caller fills (StartWalkStaging
// then StageLocations) with every standalone file seen this walk. diskPath maps
// a stored path to a local filesystem path so a stale standalone file can be
// classified missing vs unsupported. Every transition is recorded in
// label_events in the same transaction as the change. A >50% missing rate aborts
// before any write, on the assumption the data directory is misconfigured rather
// than legitimately emptied.
func (db *DB) ReconcilePools(ctx context.Context, diskPath func(string) string) (ReconcileStats, error) {
	var stats ReconcileStats
	var err error

	// 1. Relabel top-level, non-marker samples from the pools their standalone
	//    copies live in this walk (demote bad→good, promote good→bad, both→conflict).
	if db.pool != nil {
		stats.Relabeled, err = db.relabelFromPoolsPG(ctx)
	} else {
		stats.Relabeled, err = db.relabelFromPoolsSQLite(ctx)
	}
	if err != nil {
		return stats, fmt.Errorf("hopper: reconcile relabel: %w", err)
	}

	// 2. Find top-level samples (skip empty or 'conflict') not seen this walk,
	//    with the >50% guard checked before any write.
	var stale []SampleLocationKey
	var eligible int64
	if db.pool != nil {
		stale, eligible, err = db.staleStandaloneSamplesPG(ctx)
	} else {
		stale, eligible, err = db.staleStandaloneSamplesSQLite(ctx)
	}
	if err != nil {
		return stats, fmt.Errorf("hopper: reconcile stale scan: %w", err)
	}
	const minBulkMarkGuardSamples = 100
	if eligible >= minBulkMarkGuardSamples && int64(len(stale))*2 > eligible {
		return stats, fmt.Errorf(
			"hopper: reconcile: refusing to mark %d of %d standalone samples missing"+
				" (>50%%); this likely indicates a misconfigured data directory",
			len(stale), eligible,
		)
	}

	// 3. Classify each stale standalone file: gone → missing, present → unsupported.
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
	return stats, nil
}

// Pull-based work scheduling.

// ClaimJob is a work item returned to a litmus worker.
type ClaimJob struct {
	SHA256    string `json:"sha256"`
	Path      string `json:"path"`
	FileType  string `json:"file_type"`
	SizeBytes int64  `json:"size_bytes"`
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

// ForcedRescanCandidates returns up to limit Tier 0 jobs: samples an operator
// explicitly re-queued via RequestRescan (rescan_priority = 2). Workers drain
// this before Tier 1 (unanalyzed) so a user-requested rescan jumps the queue
// regardless of how big the backlog is. Ordered by rescan_requested_at
// ascending (oldest request first) for FIFO fairness across operators.
func (db *DB) ForcedRescanCandidates(ctx context.Context, limit int) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.forcedRescanCandidatesPG(ctx, limit)
	}
	return db.forcedRescanCandidatesSQLite(ctx, limit)
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
	if db.pool != nil {
		return db.queueRescanPG(ctx, shas)
	}
	return db.queueRescanSQLite(ctx, shas)
}

// QueueMissingMembersForRepair flags every top-level archive whose stored
// cleave_result was truncated (members factored out) but which has no member
// rows — the data-loss state the former async explosion could leave behind. The
// detecting NOT EXISTS scan runs once here, not per claim poll; thereafter Tier
// 1b drains the cheap rescan flag. Returns the number flagged.
func (db *DB) QueueMissingMembersForRepair(ctx context.Context) (int64, error) {
	if db.pool != nil {
		return db.queueMissingMembersForRepairPG(ctx)
	}
	return db.queueMissingMembersForRepairSQLite(ctx)
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
		return db.setNotePG(ctx, sha256, note)
	}
	return db.setNoteSQLite(ctx, sha256, note)
}

// SetStatus updates the pipeline status and updated_at timestamp.
// Clears note on status change (assumes success).
func (db *DB) SetStatus(ctx context.Context, sha256, status string) error {
	if db.pool != nil {
		return db.setStatusPG(ctx, sha256, status)
	}
	return db.setStatusSQLite(ctx, sha256, status)
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
	Ecosystem string // e.g. "wolfi", "archlinux" — empty means no filter
	FileType  string // e.g. "apk", "pkg.tar.zst" — empty means no filter
}

// TriageBad returns analyzed top-level bad-labeled samples that cleave did not
// confidently flag — lacking either a hostile finding or a second
// suspicious-or-hostile finding (max_crit < 5 OR suspicious_count < 2) — taking
// up to limit of the most recently added (created_at). No skip/status filters —
// intended for manual triage.
func (db *DB) TriageBad(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageBadPG(ctx, limit, f)
	}
	return db.triageBadSQLite(ctx, limit, f)
}

// TriageGood returns analyzed top-level good-labeled samples that cleave flagged
// with at least one suspicious-or-hostile finding (suspicious_count >= 1),
// taking up to limit of the most recently added (created_at). No skip/status
// filters — intended for manual triage.
func (db *DB) TriageGood(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageGoodPG(ctx, limit, f)
	}
	return db.triageGoodSQLite(ctx, limit, f)
}

// TriageNew returns analyzed top-level unknown-labeled samples that cleave
// flagged with at least one suspicious-or-hostile finding (suspicious_count >=
// 1), taking up to limit of the most recently added (created_at). No skip/status
// filters — intended for manual triage.
func (db *DB) TriageNew(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageNewPG(ctx, limit, f)
	}
	return db.triageNewSQLite(ctx, limit, f)
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
	if db.pool != nil {
		return db.relativizePathsPG(ctx, prefix)
	}
	return db.relativizePathsSQLite(ctx, prefix)
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
		return db.updateSamplePG(ctx, sha256, status, result, canonicalSHA256, p.FileInfo)
	}
	return db.updateSampleSQLite(ctx, sha256, status, result, canonicalSHA256, p.FileInfo)
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
	if db.pool != nil {
		return db.backfillPG(ctx)
	}
	return db.backfillSQLite(ctx)
}

// BackfillPending counts rows matched by each explicit Backfill pass.
func (db *DB) BackfillPending(ctx context.Context) (BackfillPending, error) {
	if db.pool != nil {
		return db.backfillPendingPG(ctx)
	}
	return db.backfillPendingSQLite(ctx)
}

// RecomputeCanonicalSHA256 recalculates canonical_sha256 for all analyzed
// samples using SQL-side JSON_TABLE, avoiding the need to fetch cleave_result
// blobs into Go. Returns the number of rows updated.
func (db *DB) RecomputeCanonicalSHA256(ctx context.Context) (int64, error) {
	if db.pool != nil {
		return db.recomputeCanonicalSHA256PG(ctx)
	}
	return db.recomputeCanonicalSHA256SQLite(ctx)
}

// FeedQuery specifies filters for paginated feed queries.
type FeedQuery struct {
	Source        string   // "forager" or "upload" ("harvest" matches legacy rows)
	Label         string   // "bad", "good", "unknown", or "" (match any)
	OrderBy       string   // "mtime" (default), "created_at", or "analyzed_at"
	Formula       string   // optional: filter by exact cleave chemical formula
	Search        string   // optional free-text: case-insensitive filename substring OR exact sha256
	Feeds         []string // optional: filter by feed column values
	Ecosystems    []string // optional: filter by ecosystem column values
	Domains       []string // optional: filter by domain column values
	LitmusClasses []int    // optional: filter by litmus_result class values
	RequireLitmus bool     // require any litmus_result without filtering by class
	TopLevelOnly  bool     // only samples with no archive parent
	Offset        int      // pagination offset
	Limit         int      // page size (clamped to 1–1000)
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
		return db.updateEcosystemsPG(ctx, mapping)
	}
	return db.updateEcosystemsSQLite(ctx, mapping)
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
// inline form is identical to the trigger's and to workflowSamplesPG's; keep all
// three in sync.
func (q *FeedQuery) feedClassExpr() string {
	if q.criticalLevel() == CriticalLevel {
		return "litmus_class"
	}
	cutoff := strconv.Itoa(q.criticalLevel())
	return `COALESCE(
				(litmus_result->>'class')::int,
				CASE
					WHEN litmus_result IS NULL THEN 0
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l') IS NULL THEN 2
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int < 0 THEN 0
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int <= ` + cutoff + ` THEN 2
					ELSE 1
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

// InsertReport stores an analysis report. Multiple reports per sample are allowed;
// LatestReport returns the most recent.
func (db *DB) InsertReport(ctx context.Context, r *Report) error {
	if db.pool != nil {
		return db.insertReportPG(ctx, r)
	}
	return db.insertReportSQLite(ctx, r)
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
