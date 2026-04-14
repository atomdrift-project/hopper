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
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

func closeSQLiteBestEffort(db *sql.DB) {
	if err := db.Close(); err != nil {
		return
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
	SuspiciousCount int // count of traits with level>=4 and confidence>=0.65
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

// parseCleaveFile extracts formula, elements, score, file type, max trait
// criticality, and suspicious-trait count from a cleave result for the
// file matching the given SHA256 (preferring an exact SHA match, then
// falling back to depth 0). SuspiciousCount counts traits with level >= 4
// (suspicious or hostile) at confidence >= 0.65, matching the convention
// used by ExplodeArchiveMembers.
func parseCleaveFile(sha256 string, result []byte) cleaveFileInfo {
	if len(result) == 0 {
		return cleaveFileInfo{}
	}
	var report struct {
		Files []struct {
			SHA256   string `json:"sha"`
			Formula  string `json:"f"`
			FileType string `json:"type"`
			Score    int    `json:"x"`
			Depth    int    `json:"dp"`
			Traits   []struct {
				Level int     `json:"l"`
				Conf  float64 `json:"c"`
			} `json:"ts"`
		} `json:"fs"`
	}
	if json.Unmarshal(result, &report) != nil {
		return cleaveFileInfo{}
	}
	for _, f := range report.Files {
		if f.SHA256 == sha256 || f.Depth == 0 {
			maxCrit := 0
			suspicious := 0
			for _, t := range f.Traits {
				if t.Level > maxCrit {
					maxCrit = t.Level
				}
				conf := t.Conf
				if conf == 0 {
					conf = 1.0
				}
				if conf >= 0.65 && t.Level >= 4 {
					suspicious++
				}
			}
			return cleaveFileInfo{
				Formula:         f.Formula,
				Elements:        stripSubscripts(f.Formula),
				FileType:        f.FileType,
				Score:           f.Score,
				MaxCrit:         maxCrit,
				SuspiciousCount: suspicious,
			}
		}
	}
	return cleaveFileInfo{}
}

// parseLitmusProb extracts the litmus confidence score from a litmus result
// envelope. Returns 0 if the envelope is missing or unparseable.
func parseLitmusProb(result []byte) float64 {
	if len(result) == 0 {
		return 0
	}
	var envelope struct {
		Prob float64 `json:"prob"`
	}
	if json.Unmarshal(result, &envelope) != nil {
		return 0
	}
	return envelope.Prob
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
		if json.Unmarshal(raw, &entry) != nil || entry.Depth == 0 || len(entry.SHA256) != 64 {
			continue
		}

		// Skip members cleave couldn't classify: they have no analytical value
		// and inserting them just pollutes the DB with rows the pipeline will
		// never usefully act on.
		if entry.FileType == "" {
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
	stats, err := db.Backfill(ctx)
	if err != nil {
		return fmt.Errorf("hopper: post-migrate backfill: %w", err)
	}
	if stats.Updated > 0 || stats.MarkersCleared > 0 {
		slog.Info("post-migrate backfill", "scanned", stats.Scanned, "updated", stats.Updated, "markers_cleared", stats.MarkersCleared)
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
func (db *DB) InsertSampleBatch(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
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
//
// If cleave could not classify the file (fi.FileType == ""), the row is
// deleted instead of updated: an unclassified row carries no analytical
// value and only pollutes later queries. This is the belt-and-suspenders
// complement to the ingest-time filter in cleave iter-files.
func (db *DB) UpdateCleaveResult(ctx context.Context, sha256 string, result []byte, canonicalSHA256 string) error {
	if canonicalSHA256 == "" {
		canonicalSHA256 = canonicalSHA(sha256, result)
	}
	fi := parseCleaveFile(sha256, result)
	if fi.FileType == "" {
		return db.DeleteSample(ctx, sha256)
	}
	if db.pool != nil {
		return db.updateCleaveResultPG(ctx, sha256, result, canonicalSHA256, fi)
	}
	return db.updateCleaveResultSQLite(ctx, sha256, result, canonicalSHA256, fi)
}

// UpdateLitmusResult stores the litmus classification envelope for a sample.
// The result should be the litmus response JSON without the embedded cleave field.
func (db *DB) UpdateLitmusResult(ctx context.Context, sha256 string, result []byte) error {
	prob := parseLitmusProb(result)
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

// MarkMissingSamples marks unanalyzed samples that can't be analyzed:
//   - skip='missing' if the file doesn't exist on disk
//   - skip='unsupported' if the file exists but wasn't in the iter-files output
//
// walkedPaths is the set of all paths emitted by cleave iter-files during
// the current load. Returns the number of samples marked.
func (db *DB) MarkMissingSamples(ctx context.Context, walkedPaths map[string]struct{}) (int64, error) {
	samples, err := db.Unanalyzed(ctx, 1_000_000)
	if err != nil {
		return 0, fmt.Errorf("hopper: mark missing: %w", err)
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
		if _, walked := walkedPaths[s.Path]; !walked {
			wouldMark++
		}
	}
	if eligible > 0 && wouldMark*2 > eligible {
		return 0, fmt.Errorf("hopper: mark missing: refusing to mark %d of %d unanalyzed samples (>50%%); this likely indicates a misconfigured data directory", wouldMark, eligible)
	}

	var marked int64
	for _, s := range samples {
		if s.Skip != "" || s.Parent != "" {
			continue
		}
		if _, walked := walkedPaths[s.Path]; walked {
			continue
		}
		_, statErr := os.Stat(s.Path)
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
	SizeBytes int64  `json:"size_bytes"`
	FileType  string `json:"file_type"`
}

// Worker is a litmus worker's latest heartbeat data.
type Worker struct {
	Name     string    `json:"name"`
	LastSeen time.Time `json:"last_seen"`
	Slots    int       `json:"slots"`
	Version  string    `json:"version"`
	Traits   string    `json:"traits"`
	Analyzed int64     `json:"analyzed"`
	Errors   int64     `json:"errors"`
}

// WorkerClaim describes the oldest active claim for a given worker.
type WorkerClaim struct {
	Worker    string
	Path      string
	ClaimedAt time.Time
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
// worker. Expired claims (older than expiry) are reclaimed.
func (db *DB) ClaimJobs(ctx context.Context, worker string, limit int, expiry time.Duration) ([]ClaimJob, error) {
	if db.pool != nil {
		return db.claimJobsPG(ctx, worker, limit, expiry)
	}
	return db.claimJobsSQLite(ctx, worker, limit, expiry)
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

// FalsePositives returns analyzed good-labeled samples with score >= threshold
// (cleave detects them as bad). These are candidates for false-positive resolution.
// Only returns samples with empty status (not yet claimed by a pipeline).
func (db *DB) FalsePositives(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falsePositivesPG(ctx, scoreThreshold, limit)
	}
	return db.falsePositivesSQLite(ctx, scoreThreshold, limit)
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

// FalseNegatives returns analyzed bad-labeled samples with score <= threshold
// (cleave does not detect them). These are candidates for gap-and-fix.
// Only returns samples with empty status (not yet claimed by a pipeline).
func (db *DB) FalseNegatives(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falseNegativesPG(ctx, scoreThreshold, limit)
	}
	return db.falseNegativesSQLite(ctx, scoreThreshold, limit)
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

// FalsePositivesInPaths returns unlabeled-queue good samples under the given
// prefixes whose cleave score is at or above scoreFloor and that are not marked skip.
func (db *DB) FalsePositivesInPaths(ctx context.Context, prefixes []string, scoreFloor, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falsePositivesInPathsPG(ctx, prefixes, scoreFloor, limit)
	}
	return db.falsePositivesInPathsSQLite(ctx, prefixes, scoreFloor, limit)
}

// FalseNegativesInPaths returns unlabeled-queue bad samples under the given
// prefixes whose cleave score is at or below scoreCeiling and that are not marked skip.
func (db *DB) FalseNegativesInPaths(ctx context.Context, prefixes []string, scoreCeiling, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.falseNegativesInPathsPG(ctx, prefixes, scoreCeiling, limit)
	}
	return db.falseNegativesInPathsSQLite(ctx, prefixes, scoreCeiling, limit)
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
type FeedQuery struct { //nolint:govet // filter fields are grouped for readability.
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
