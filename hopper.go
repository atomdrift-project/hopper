// Package hopper is a sample registry backed by PostgreSQL or SQLite.
//
// It stores binary samples, analysis results, and reverse engineering
// reports for the atomdrift malware detection pipeline.
//
// Use a postgres:// DSN for PostgreSQL, or a file path for SQLite.
package hopper

import (
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
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

const skipBenignArchiveItem = "skip-benign-archive-item"

func closeSQLiteBestEffort(db *sql.DB) {
	if err := db.Close(); err != nil {
		slog.Debug("close sqlite failed", "error", err)
	}
}

// sanitizeJSONB fixes JSON that is valid in lenient parsers but rejected by
// PostgreSQL's strict JSONB parser:
//   - \u0000 (null bytes): PG uses C-style null-terminated strings internally
//   - \xNN (hex escapes): not valid JSON, must be \u00NN
//
// Both are common in malware analysis output where cleave reports binary
// strings as-is. Only single-backslash sequences are replaced; \\u0000 and
// \\xNN (escaped backslash + literal text) are left intact.
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
			// \xNN → \u00NN, but drop \x00 entirely (it becomes \u0000)
			if b[i+2] == '0' && b[i+3] == '0' {
				i += 3
			} else {
				out = append(out, `\u00`...)
				out = append(out, b[i+2], b[i+3])
				i += 3
			}

		case next == 'u' && needsNull && i+5 < len(b) && b[i+2] == '0' && b[i+3] == '0' && b[i+4] == '0' && b[i+5] == '0':
			// \u0000 → drop entirely
			i += 5

		default:
			out = append(out, b[i])
		}
	}
	return out
}

func randomSHA256Pivot() string {
	var b [32]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		sum := cryptosha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(b[:])
}

func compactCleaveResultForStorage(sha256 string, result []byte) []byte {
	if len(result) == 0 {
		return result
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(result, &envelope) != nil {
		return result
	}
	var files []json.RawMessage
	if json.Unmarshal(envelope["fs"], &files) != nil || len(files) <= 1 {
		return result
	}

	top := 0
	for i, raw := range files {
		var f struct {
			SHA256 string `json:"sha"`
			Depth  int    `json:"dp"`
		}
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		if f.SHA256 == sha256 {
			top = i
			break
		}
		if f.Depth == 0 {
			top = i
		}
	}

	compactFS, err := json.Marshal([]json.RawMessage{files[top]})
	if err != nil {
		return result
	}
	envelope["fs"] = compactFS
	envelope["truncated"] = json.RawMessage(`true`)
	envelope["omitted_files"] = json.RawMessage(strconv.Itoa(len(files) - 1))
	compact, err := json.Marshal(envelope)
	if err != nil {
		return result
	}
	return compact
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
	CleaveResult    []byte  // raw cleave JSON, nil if unanalyzed
	LitmusResult    []byte  // litmus classification envelope JSON, nil if unclassified
	LitmusScore     float64 // litmus confidence score (0.0-1.0)
	ID              int64
	SizeBytes       int64
	Score           int // cleave raw score
	MaxCrit         int // max trait criticality level (5=hostile, 4=suspicious, ...)
	SuspiciousCount int // count of traits with level>=4 (suspicious or hostile)
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

// ParseCleaveResult extracts file info and canonical SHA from a cleave result
// in a single JSON parse, avoiding the redundant parsing that happens when
// parseCleaveFile and canonicalSHA are called separately.
func ParseCleaveResult(sha256 string, result []byte) CleaveParseResult {
	if len(result) == 0 {
		return CleaveParseResult{CanonicalSHA: sha256}
	}
	var report struct {
		TraitsVersion string `json:"tv"`
		Files         []struct {
			Formula  string `json:"f"`
			SHA256   string `json:"sha"`
			FileType string `json:"type"`
			Traits   []struct {
				Conf  float64 `json:"c"`
				Level int     `json:"l"`
			} `json:"ts"`
			Score int `json:"x"`
			Depth int `json:"dp"`
		} `json:"fs"`
	}
	if json.Unmarshal(result, &report) != nil {
		return CleaveParseResult{CanonicalSHA: sha256}
	}

	// Canonical SHA: lexicographic minimum across sample and all embedded files.
	canonical := sha256
	for _, f := range report.Files {
		if len(f.SHA256) == 64 && f.SHA256 < canonical {
			canonical = f.SHA256
		}
	}

	// File info for the matching entry.
	var fi cleaveFileInfo
	for _, f := range report.Files {
		if f.SHA256 != sha256 && f.Depth != 0 {
			continue
		}
		maxCrit := 0
		suspicious := 0
		for _, t := range f.Traits {
			if t.Level > maxCrit {
				maxCrit = t.Level
			}
			if t.Level >= 4 {
				suspicious++
			}
		}
		fi = cleaveFileInfo{
			Formula:         f.Formula,
			Elements:        stripSubscripts(f.Formula),
			FileType:        f.FileType,
			Score:           f.Score,
			MaxCrit:         maxCrit,
			SuspiciousCount: suspicious,
		}
		break
	}

	return CleaveParseResult{CanonicalSHA: canonical, FileInfo: fi, TraitsVersion: report.TraitsVersion}
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
		} `json:"fs"`
	}
	if json.Unmarshal(cleaveResult, &report) != nil {
		return canonical
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
func (db *DB) ExplodeArchiveMembers(ctx context.Context, parent *Sample) (int64, error) {
	if len(parent.CleaveResult) == 0 {
		return 0, nil
	}

	var report struct {
		Files []json.RawMessage `json:"fs"`
	}
	if err := json.Unmarshal(parent.CleaveResult, &report); err != nil {
		return 0, fmt.Errorf("hopper: parse cleave result for explosion: %w", err)
	}

	var members []*Sample
	for id, raw := range report.Files {
		var entry struct {
			SHA256   string `json:"sha"`
			FileType string `json:"type"`
			Path     string `json:"path"`
			Traits   []struct {
				Level int     `json:"l"`
				Conf  float64 `json:"c"`
			} `json:"ts"`
			Size  int64 `json:"sz"`
			Depth int   `json:"dp"`
		}
		if json.Unmarshal(raw, &entry) != nil || entry.Depth == 0 {
			continue
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
		for _, t := range entry.Traits {
			if t.Level > maxLevel {
				maxLevel = t.Level
			}
			if t.Level >= 4 { // suspicious+
				suspiciousCount++
			}
		}

		skip := ""
		if parent.Label == "bad" && maxLevel < 5 && suspiciousCount <= 1 {
			skip = skipBenignArchiveItem
		}

		singleFile, err := json.Marshal(struct {
			Files []json.RawMessage `json:"fs"`
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
		if parent.Path != "" {
			memberPath = parent.Path + "!!" + inArchive
		}

		members = append(members, &Sample{
			SHA256:          entry.SHA256,
			Source:          parent.Source,
			Feed:            parent.Feed,
			Ecosystem:       parent.Ecosystem,
			Filename:        inArchive,
			FileType:        entry.FileType,
			SizeBytes:       entry.Size,
			Label:           parent.Label,
			LabelSource:     parent.LabelSource,
			Path:            memberPath,
			CleaveResult:    singleFile,
			LitmusResult:    litmusResultForMember(parent.LitmusResult, id),
			CanonicalSHA256: parent.CanonicalSHA256,
			Parent:          parent.SHA256,
			Skip:            skip,
			AnalyzedAt:      parent.AnalyzedAt,
			FirstAnalyzedAt: firstNonNilTime(parent.FirstAnalyzedAt, parent.AnalyzedAt),
		})
	}

	if len(members) == 0 {
		return 0, nil
	}
	n, _, err := db.InsertSampleBatch(ctx, members)
	return n, err
}

func firstNonNilTime(times ...*time.Time) *time.Time {
	for _, t := range times {
		if t != nil {
			return t
		}
	}
	return nil
}

func litmusResultForMember(parent []byte, id int) []byte {
	if len(parent) == 0 {
		return nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(parent, &envelope); err != nil {
		return nil
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(envelope["fs"], &files); err != nil {
		return nil
	}

	var member map[string]json.RawMessage
	for _, f := range files {
		var got int
		if err := json.Unmarshal(f["id"], &got); err == nil && got == id {
			member = f
			break
		}
	}
	if member == nil && id >= 0 && id < len(files) {
		member = files[id]
	}
	if member == nil || len(member["prob"]) == 0 {
		return nil
	}

	out := make(map[string]json.RawMessage, len(member)+4)
	for _, key := range []string{"v", "version", "thresholds", "analyzed_at"} {
		if v := envelope[key]; len(v) != 0 {
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

func cleaveFileIndexForSHA(result []byte, sha256 string) (int, bool) {
	var report struct {
		Files []struct {
			SHA256 string `json:"sha"`
		} `json:"fs"`
	}
	if json.Unmarshal(result, &report) != nil {
		return 0, false
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
		closeSQLiteBestEffort(db.lite)
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
type PruneSafetyExceeded struct {
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
		e.Victims, e.Total, pct, e.MaxFraction*100)
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

// SampleBySHA256 retrieves a sample by its hash.
// Returns ErrNotFound if no such sample exists.
func (db *DB) SampleBySHA256(ctx context.Context, sha256 string) (*Sample, error) {
	if db.pool != nil {
		return db.sampleBySHA256PG(ctx, sha256)
	}
	return db.sampleBySHA256SQLite(ctx, sha256)
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
	result = compactCleaveResultForStorage(sha256, result)
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

// MarkMissingSamples marks unanalyzed samples that can't be analyzed:
//   - skip='missing' if the file doesn't exist on disk
//   - skip='unsupported' if the file exists but wasn't in the iter-files output
//
// wasWalked reports whether a resolved path was emitted by cleave iter-files
// during the current load. Returns the number of samples marked.
func (db *DB) MarkMissingSamples(ctx context.Context, wasWalked func(string) bool) (int64, error) {
	return db.MarkMissingSamplesResolved(ctx, wasWalked, nil, nil)
}

// MarkMissingSamplesResolved is MarkMissingSamples with caller-provided path
// normalization. comparablePath maps DB paths into the same namespace used by
// wasWalked; diskPath maps DB paths to local filesystem paths for os.Stat.
func (db *DB) MarkMissingSamplesResolved(
	ctx context.Context,
	wasWalked func(string) bool,
	comparablePath func(string) string,
	diskPath func(string) string,
) (int64, error) {
	const batchSize = 50_000
	samples, err := db.Unanalyzed(ctx, batchSize)
	if err != nil {
		return 0, fmt.Errorf("hopper: mark missing: %w", err)
	}
	if comparablePath == nil {
		comparablePath = func(p string) string { return p }
	}
	if diskPath == nil {
		diskPath = func(p string) string { return p }
	}

	// Resolve symlinks in DB paths so they match the resolved walkedPaths keys.
	// Prior runs may have stored unresolved symlink paths (e.g. ~/data → /srv/data).
	resolvedPath := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return comparablePath(r)
		}
		return comparablePath(p)
	}
	seen := func(p string) bool {
		return wasWalked(comparablePath(p)) || wasWalked(resolvedPath(p))
	}

	// Dry-run: count how many would be marked before writing anything.
	// Skip archive children (parent != "") — they don't have standalone
	// files on disk; they get analysis through their parent archive.
	var eligible, wouldMark int64
	for _, s := range samples {
		if s.Skip != "" || s.Parent != "" {
			continue
		}
		eligible++
		if !seen(s.Path) {
			wouldMark++
		}
	}
	const minBulkMarkGuardSamples = 100
	if eligible >= minBulkMarkGuardSamples && wouldMark*2 > eligible {
		return 0, fmt.Errorf(
			"hopper: mark missing: refusing to mark %d of %d unanalyzed"+
				" samples (>50%%); this likely indicates a misconfigured data directory",
			wouldMark, eligible)
	}

	var marked int64
	for _, s := range samples {
		if s.Skip != "" || s.Parent != "" {
			continue
		}
		if seen(s.Path) {
			continue
		}
		_, statErr := os.Stat(diskPath(s.Path))
		skip := "unsupported" // file exists but iter-files filtered it out
		if statErr != nil {
			skip = "missing" // file is gone from disk
		}
		slog.Info("marking stale sample", "sha256", s.SHA256, "path", s.Path, "skip", skip)
		if err := db.SetSkip(ctx, s.SHA256, skip); err != nil {
			return marked, fmt.Errorf("hopper: mark missing: %w", err)
		}
		marked++
	}
	return marked, nil
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

func (db *DB) WorkflowHealth(ctx context.Context) (WorkflowHealth, error) {
	if db.pool != nil {
		return db.workflowHealthPG(ctx)
	}
	return db.workflowHealthSQLite(ctx)
}

func (db *DB) WorkflowBacklogs(ctx context.Context, limit int) ([]WorkflowBacklog, error) {
	if limit <= 0 {
		limit = 5
	}
	if db.pool != nil {
		return db.workflowBacklogsPG(ctx, limit)
	}
	return db.workflowBacklogsSQLite(ctx, limit)
}

func (db *DB) WorkflowLatestAdded(ctx context.Context, limit int) ([]WorkflowSample, error) {
	if limit <= 0 {
		limit = 5
	}
	if db.pool != nil {
		return db.workflowLatestAddedPG(ctx, limit)
	}
	return db.workflowLatestAddedSQLite(ctx, limit)
}

func (db *DB) WorkflowLatestReady(ctx context.Context, limit int) ([]WorkflowSample, error) {
	if limit <= 0 {
		limit = 5
	}
	if db.pool != nil {
		return db.workflowLatestReadyPG(ctx, limit)
	}
	return db.workflowLatestReadySQLite(ctx, limit)
}

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
	if canonicalSHA256 == "" {
		canonicalSHA256 = canonicalSHA(sha256, result)
	}
	fi := parseCleaveFile(sha256, result)
	if fi.FileType == "" {
		return db.DeleteSample(ctx, sha256)
	}
	result = compactCleaveResultForStorage(sha256, result)
	if db.pool != nil {
		return db.updateSamplePG(ctx, sha256, status, result, canonicalSHA256, fi)
	}
	return db.updateSampleSQLite(ctx, sha256, status, result, canonicalSHA256, fi)
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
	ArchiveMemberLitmus   int64 // archive members that still carry the parent's litmus_result blob
	ArchiveMemberAnalyzed int64 // archive members missing analyzed_at while their parent has it
	StaleGoodMarkers      int64 // good marker misclassification skips that can be cleared
	StaleBadMarkers       int64 // bad marker misclassification skips that can be cleared
}

// TotalRows is the sum of all pending backfill rows across passes.
func (p BackfillPending) TotalRows() int64 {
	return p.CleaveColumns + p.ArchiveMemberLitmus + p.ArchiveMemberAnalyzed + p.StaleGoodMarkers + p.StaleBadMarkers
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
	Feeds         []string // optional: filter by feed column values
	Ecosystems    []string // optional: filter by ecosystem column values
	LitmusClasses []int    // optional: filter by litmus_result class values
	RequireLitmus bool     // require any litmus_result without filtering by class
	TopLevelOnly  bool     // only samples with no archive parent
	Offset        int      // pagination offset
	Limit         int      // page size (clamped to 1–100)
}

// FeedSamples returns analyzed samples matching the query, newest first.
func (db *DB) FeedSamples(ctx context.Context, q FeedQuery) ([]*Sample, error) {
	q.clamp()
	if db.pool != nil {
		return db.feedSamplesPG(ctx, q)
	}
	return db.feedSamplesSQLite(ctx, q)
}

// FeedSamplesCount returns the total number of samples matching the query.
func (db *DB) FeedSamplesCount(ctx context.Context, q FeedQuery) (int, error) {
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

// FeedEcosystems returns distinct ecosystem values for samples matching source and label.
func (db *DB) FeedEcosystems(ctx context.Context, source, label string) ([]string, error) {
	if db.pool != nil {
		return db.feedEcosystemsPG(ctx, source, label)
	}
	return db.feedEcosystemsSQLite(ctx, source, label)
}

func (q *FeedQuery) clamp() {
	if q.Limit < 1 {
		q.Limit = 1
	}
	if q.Limit > 100 {
		q.Limit = 100
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
}

func (q *FeedQuery) sortBy() string {
	switch q.OrderBy {
	case "created_at":
		return "created_at"
	case "analyzed_at":
		return "analyzed_at"
	default:
		return "mtime"
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
