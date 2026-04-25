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
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

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
	pool *pgxpool.Pool
	lite *sql.DB
}

// Sample is a binary in the registry.
type Sample struct {
	CreatedAt       time.Time
	UpdatedAt       time.Time
	SHA256          string
	Source          string
	Feed            string
	Ecosystem       string
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
	Source       string // "harvest", "upload", ...
	Feed         string
	Ecosystem    string
	ID           int64
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
// parent's label, label_source, source, feed, and canonical_sha256. Members
// get a single-file cleave_result wrapping just their file entry.
//
// For bad archives, members without hostile risk or >1 suspicious finding
// are marked skip="weak-findings". Duplicate SHA256s are silently skipped.
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
	for _, raw := range report.Files {
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
			skip = "weak-findings"
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
			LitmusResult:    parent.LitmusResult,
			LitmusScore:     parent.LitmusScore,
			CanonicalSHA256: parent.CanonicalSHA256,
			Parent:          parent.SHA256,
			Skip:            skip,
		})
	}

	if len(members) == 0 {
		return 0, nil
	}
	n, _, err := db.InsertSampleBatch(ctx, members)
	return n, err
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

// Migrate creates the schema if it does not exist, then backfills any
// rows missing derivable columns. The backfill is gated on the file_type
// column being empty so it's a single indexed count on already-migrated
// databases.
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
	slog.Info("starting post-migrate backfill")
	stats, err := db.Backfill(ctx)
	if err != nil {
		return fmt.Errorf("hopper: post-migrate backfill: %w", err)
	}
	if stats.Updated > 0 || stats.MarkersCleared > 0 {
		slog.Info("post-migrate backfill", "scanned", stats.Scanned, "updated", stats.Updated, "markers_cleared", stats.MarkersCleared)
	}
	slog.Info("post-migrate backfill complete")
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
	const cols = `sha256, path, label, label_source, source, feed, ecosystem, canonical_sha256, litmus_result`
	var s Sample
	var litmus []byte
	scan := func(row interface{ Scan(...any) error }) error {
		return row.Scan(&s.SHA256, &s.Path, &s.Label, &s.LabelSource,
			&s.Source, &s.Feed, &s.Ecosystem, &s.CanonicalSHA256, &litmus)
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

	// Dry-run: count how many would be marked before writing anything.
	// Skip archive children (parent != "") — they don't have standalone
	// files on disk; they get analysis through their parent archive.
	var eligible, wouldMark int64
	for _, s := range samples {
		if s.Skip != "" || s.Parent != "" {
			continue
		}
		eligible++
		if !wasWalked(resolvedPath(s.Path)) {
			wouldMark++
		}
	}
	if eligible > 0 && wouldMark*2 > eligible {
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
		if wasWalked(resolvedPath(s.Path)) {
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

// WorkerClaim describes the oldest active claim for a given worker.
type WorkerClaim struct {
	ClaimedAt time.Time
	Worker    string
	Path      string
}

// OldestClaims returns the oldest active claim per worker.
// Claims older than maxAge are considered stale and excluded.
func (db *DB) OldestClaims(ctx context.Context, maxAge time.Duration) ([]WorkerClaim, error) {
	if db.pool != nil {
		return db.oldestClaimsPG(ctx, maxAge)
	}
	return db.oldestClaimsSQLite(ctx, maxAge)
}

// NewestAnalyzedAt returns the most recent analyzed_at timestamp, or zero if none.
func (db *DB) NewestAnalyzedAt(ctx context.Context) (time.Time, error) {
	if db.pool != nil {
		return db.newestAnalyzedAtPG(ctx)
	}
	return db.newestAnalyzedAtSQLite(ctx)
}

// ClaimJobs atomically claims up to limit unanalyzed samples for the named
// worker. Expired claims (older than expiry) are reclaimed. When no unanalyzed
// samples remain, workers fall through to two rescan tiers (in order):
// force-rescan paths (samples under forceRescanPrefixes whose analysis
// predates hopperStart) and traits-stale rescan (samples analyzed with a
// different traits_version more than rescanAge ago). Neither rescan tier
// clears stored analysis — UpdateSample overwrites in place when new results
// arrive, so a crashed or expired rescan never leaves a row visibly empty.
func (db *DB) ClaimJobs(
	ctx context.Context, worker string, limit int,
	expiry time.Duration, currentTraits string, rescanAge time.Duration,
	hopperStart time.Time, forceRescanPrefixes []string,
) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.claimJobsPG(ctx, worker, limit, expiry, currentTraits, rescanAge, hopperStart, forceRescanPrefixes)
	}
	return db.claimJobsSQLite(ctx, worker, limit, expiry, currentTraits, rescanAge, hopperStart, forceRescanPrefixes)
}

// UnclaimAll releases all outstanding claims. Call on startup to clear
// stale claims from previous runs so those samples get re-queued.
func (db *DB) UnclaimAll(ctx context.Context) (int64, error) {
	if db.pool != nil {
		return db.unclaimAllPG(ctx)
	}
	return db.unclaimAllSQLite(ctx)
}

// UnclaimJobs releases claims for the given SHA256s so other workers can try.
func (db *DB) UnclaimJobs(ctx context.Context, shas []string) error {
	if db.pool != nil {
		return db.unclaimJobsPG(ctx, shas)
	}
	return db.unclaimJobsSQLite(ctx, shas)
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

// SamplesByStatus returns up to limit samples with the given status, oldest first.
func (db *DB) SamplesByStatus(ctx context.Context, status string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.samplesByStatusPG(ctx, status, limit)
	}
	return db.samplesByStatusSQLite(ctx, status, limit)
}

// SamplesByStatusLight is like SamplesByStatus but omits CleaveResult and
// LitmusResult to reduce memory usage when only metadata is needed.
func (db *DB) SamplesByStatusLight(ctx context.Context, status string, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.samplesByStatusLightPG(ctx, status, limit)
	}
	return db.samplesByStatusLightSQLite(ctx, status, limit)
}

// FalsePositives returns analyzed good-labeled samples that trigger detection
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

// FalseNegatives returns analyzed bad-labeled samples that do not trigger
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

// Backfill re-derives columns from cleave_result and litmus_result for every
// sample with at least one of those blobs, updating rows where the stored
// values disagree with what the parsers produce. Useful after parser changes
// or for rows that pre-date a column being populated on write.
//
// Currently backfills: formula, elements, score, file_type (from cleave_result)
// and litmus_score (from litmus_result).
func (db *DB) Backfill(ctx context.Context) (BackfillStats, error) {
	if db.pool != nil {
		return db.backfillPG(ctx)
	}
	return db.backfillSQLite(ctx)
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
	Source     string   // "harvest" or "upload"
	Label      string   // "bad", "good", "unknown", or "" (match any)
	OrderBy    string   // "mtime" (default) or "analyzed_at"
	Feeds      []string // optional: filter by feed column values
	Ecosystems []string // optional: filter by ecosystem column values
	Offset     int      // pagination offset
	Limit      int      // page size (clamped to 1–100)
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
