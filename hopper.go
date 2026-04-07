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
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

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
	AnalyzedAt      *time.Time
	Mtime           *time.Time
	CleaveResult    []byte // raw cleave JSON, nil if unanalyzed
	LitmusResult    []byte // litmus classification envelope JSON, nil if unclassified
	LitmusScore     float64 // litmus confidence score (0.0-1.0)
	ID              int64
	SizeBytes       int64
	Score           int    // cleave raw score
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
	Formula  string
	Elements string
	Score    int
}

// parseCleaveFile extracts formula, elements, and score from a cleave result
// for the file matching the given SHA256 (depth 0 / first file).
func parseCleaveFile(sha256 string, result []byte) cleaveFileInfo {
	if len(result) == 0 {
		return cleaveFileInfo{}
	}
	var report struct {
		Files []struct {
			SHA256  string `json:"sha"`
			Formula string `json:"f"`
			Score   int    `json:"x"`
			Depth   int    `json:"dp"`
		} `json:"fs"`
	}
	if json.Unmarshal(result, &report) != nil {
		return cleaveFileInfo{}
	}
	for _, f := range report.Files {
		if f.SHA256 == sha256 || f.Depth == 0 {
			return cleaveFileInfo{
				Formula:  f.Formula,
				Elements: stripSubscripts(f.Formula),
				Score:    f.Score,
			}
		}
	}
	return cleaveFileInfo{}
}

// stripSubscripts removes Unicode subscript digits (₀-₉) from a formula,
// producing the qualitative element list.
func stripSubscripts(formula string) string {
	var b strings.Builder
	for _, r := range formula {
		if r < '₀' || r > '₉' {
			b.WriteRune(r)
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
		if json.Unmarshal(raw, &entry) != nil || entry.Depth == 0 || len(entry.SHA256) != 64 {
			continue
		}

		// Count suspicious+ findings with sufficient confidence for skip logic.
		maxLevel := 0
		suspiciousCount := 0
		for _, t := range entry.Traits {
			conf := t.Conf
			if conf == 0 {
				conf = 1.0
			}
			if t.Level > maxLevel {
				maxLevel = t.Level
			}
			if conf >= 0.65 && t.Level >= 4 { // suspicious+
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

		members = append(members, &Sample{
			SHA256:          entry.SHA256,
			Source:          parent.Source,
			Feed:            parent.Feed,
			Ecosystem:       parent.Ecosystem,
			Filename:        entry.Path,
			FileType:        entry.FileType,
			SizeBytes:       entry.Size,
			Label:           parent.Label,
			LabelSource:     parent.LabelSource,
			CleaveResult:    singleFile,
			LitmusResult:    parent.LitmusResult,
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
		db.lite.Close() //nolint:errcheck,gosec // best-effort cleanup
	}
}

// Pool returns the underlying PostgreSQL connection pool, or nil for SQLite.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// Migrate creates the schema if it does not exist.
func (db *DB) Migrate(ctx context.Context) error {
	if db.pool != nil {
		return db.migratePG(ctx)
	}
	return db.migrateSQLite(ctx)
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

// InsertSampleNew adds a sample and reports whether the row was actually inserted
// (true) or was a duplicate that was silently skipped (false).
func (db *DB) InsertSampleNew(ctx context.Context, s *Sample) (bool, error) {
	if db.pool != nil {
		return db.insertSampleNewPG(ctx, s)
	}
	return db.insertSampleNewSQLite(ctx, s)
}

// InsertSampleBatch inserts multiple samples in a single transaction/COPY.
// Returns the number of new rows inserted (duplicates are silently skipped).
// Much faster than calling InsertSampleNew in a loop, especially for SQLite
// where each individual INSERT acquires the single-writer lock.
// InsertSampleBatch inserts a batch of samples.
// Returns the number of newly inserted samples and a list of SHAs that lack analysis results.
func (db *DB) InsertSampleBatch(ctx context.Context, samples []*Sample) (int64, []string, error) {
	if len(samples) == 0 {
		return 0, nil, nil
	}
	if db.pool != nil {
		return db.insertSampleBatchPG(ctx, samples)
	}
	return db.insertSampleBatchSQLite(ctx, samples)
}

// SampleBySHA256 retrieves a sample by its hash.
// Returns ErrNotFound if no such sample exists.
func (db *DB) SampleBySHA256(ctx context.Context, sha256 string) (*Sample, error) {
	if db.pool != nil {
		return db.sampleBySHA256PG(ctx, sha256)
	}
	return db.sampleBySHA256SQLite(ctx, sha256)
}

// UpdateCleaveResult stores analysis output for a sample.
// Pass canonicalSHA256 as the minimum SHA256 across the sample and its embedded
// files (for train/test splits). Pass "" to compute it from result automatically.
func (db *DB) UpdateCleaveResult(ctx context.Context, sha256 string, result []byte, canonicalSHA256 string) error {
	if canonicalSHA256 == "" {
		canonicalSHA256 = canonicalSHA(sha256, result)
	}
	fi := parseCleaveFile(sha256, result)
	if db.pool != nil {
		return db.updateCleaveResultPG(ctx, sha256, result, canonicalSHA256, fi)
	}
	return db.updateCleaveResultSQLite(ctx, sha256, result, canonicalSHA256, fi)
}

// UpdateLitmusResult stores the litmus classification envelope for a sample.
// The result should be the litmus response JSON without the embedded cleave field.
func (db *DB) UpdateLitmusResult(ctx context.Context, sha256 string, result []byte) error {
	var prob float64
	var envelope struct {
		Prob float64 `json:"prob"`
	}
	if json.Unmarshal(result, &envelope) == nil {
		prob = envelope.Prob
	}

	if db.pool != nil {
		return db.updateLitmusResultPG(ctx, sha256, result, prob)
	}
	return db.updateLitmusResultSQLite(ctx, sha256, result, prob)
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

// UpdateSample updates status, cleave result, and updated_at in one operation.
func (db *DB) UpdateSample(ctx context.Context, sha256, status string, result []byte, canonicalSHA256 string) error {
	if canonicalSHA256 == "" {
		canonicalSHA256 = canonicalSHA(sha256, result)
	}
	fi := parseCleaveFile(sha256, result)
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
	Feeds      []string // optional: filter by feed column values
	Ecosystems []string // optional: filter by ecosystem column values
	OrderBy    string   // "mtime" (default) or "analyzed_at"
	Limit      int      // page size (clamped to 1–100)
	Offset     int      // pagination offset
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

func (q FeedQuery) sortBy() string {
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
