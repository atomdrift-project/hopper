package hopper

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
)

// MigrateLegacy reads samples from a legacy cyclotron SQLite database and
// inserts them into dst. The legacy schema stores status as the label
// indicator (bad*, good*) and updated_at as a Unix timestamp.
//
// Pass afterRowID > 0 to resume from the last logged rowid.
func MigrateLegacy(ctx context.Context, dst *DB, legacyPath string, afterRowID int64) (int, error) {
	slog.Info("opening legacy source database", "path", legacyPath)
	src, err := sql.Open("sqlite3", legacyPath+"?mode=ro&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return 0, fmt.Errorf("open legacy db: %w", err)
	}
	defer src.Close() //nolint:errcheck // best-effort cleanup

	// Estimate source rows using max(rowid) — instant on SQLite vs a full
	// table scan for count(*). The estimate is an upper bound when resuming.
	var total int64
	if err := src.QueryRowContext(ctx, `SELECT max(rowid) - ? FROM samples`, afterRowID).Scan(&total); err != nil {
		slog.Warn("could not estimate legacy rows", "error", err)
	} else {
		slog.Info("legacy source rows to process (estimated)", "total", total)
	}

	slog.Info("querying legacy samples", "after_rowid", afterRowID)
	rows, err := src.QueryContext(ctx, `
		SELECT rowid, sha256, path, status, updated_at, cleave_json, risk, finding_count
		FROM samples
		WHERE rowid > ?
		ORDER BY rowid`, afterRowID)
	if err != nil {
		return 0, fmt.Errorf("query legacy samples: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup

	if dst.pool != nil {
		return migrateLegacyPG(ctx, dst, rows, total)
	}
	return migrateLegacySQLite(ctx, dst, rows, total)
}

// Legacy to SQLite batched transactions.

func migrateLegacySQLite(ctx context.Context, dst *DB, rows *sql.Rows, total int64) (int, error) {
	const batchSize = 1000
	slog.Info("legacy import to sqlite", "batch_size", batchSize)
	imported := 0
	scanned := 0
	batch := 0
	start := time.Now()

	tx, err := dst.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	commit := func() error {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit: %w", err)
		}
		var err2 error
		tx, err2 = dst.lite.BeginTx(ctx, nil)
		return err2
	}

	var lastRowID int64
	for rows.Next() {
		if ctx.Err() != nil {
			tx.Rollback() //nolint:errcheck,gosec // context cancelled
			return imported, ctx.Err()
		}

		var rowid int64
		var sha256, path, status string
		var updatedAt int64
		var cleaveJSON, risk sql.NullString
		var findingCount int

		if err := rows.Scan(&rowid, &sha256, &path, &status, &updatedAt, &cleaveJSON, &risk, &findingCount); err != nil {
			tx.Rollback() //nolint:errcheck,gosec // scan error
			return imported, fmt.Errorf("scan row: %w", err)
		}
		lastRowID = rowid
		scanned++

		label := labelFromLegacyStatus(status)
		var cleaveResult sql.NullString
		if cleaveJSON.Valid && cleaveJSON.String != "" {
			cleaveResult = cleaveJSON
		}

		canonical := sha256
		if cleaveResult.Valid {
			canonical = canonicalSHA(sha256, []byte(cleaveResult.String))
		}

		ts := now()
		var analyzedAt sql.NullString
		if cleaveResult.Valid {
			analyzedAt = sql.NullString{String: ts, Valid: true}
		}
		var updatedTS string
		if updatedAt > 0 {
			updatedTS = time.Unix(updatedAt, 0).UTC().Format(time.RFC3339Nano)
		} else {
			updatedTS = ts
		}

		res, err := tx.ExecContext(ctx, `
			INSERT INTO samples (sha256, source, filename, label, label_source,
				path, status, cleave_result,
				canonical_sha256, analyzed_at, updated_at)
			VALUES (?, 'legacy', ?, ?, 'legacy', ?, ?, ?, ?, ?, ?)
			ON CONFLICT (sha256) DO NOTHING`,
			sha256, filepath.Base(path), label, path, status,
			cleaveResult,
			canonical, analyzedAt, updatedTS)
		if err != nil {
			slog.Warn("skipping legacy sample", "sha256", sha256, "error", err)
			continue
		}
		if affected, err := res.RowsAffected(); err == nil && affected == 0 {
			continue // duplicate
		}

		imported++
		batch++
		if batch >= batchSize {
			if err := commit(); err != nil {
				return imported, err
			}
			batch = 0
			slog.Info("legacy import progress", "scanned", scanned, "imported", imported,
				"total", total, "rowid", lastRowID,
				"rows_per_sec", int(float64(scanned)/time.Since(start).Seconds()))
		}
	}

	if err := tx.Commit(); err != nil {
		return imported, fmt.Errorf("final commit: %w", err)
	}
	slog.Info("legacy import finished", "scanned", scanned, "imported", imported,
		"total", total, "rowid", lastRowID,
		"elapsed", time.Since(start).Round(time.Millisecond))
	return imported, rows.Err()
}

// Legacy to PG via COPY batches into a staging table.

const legacyBatchSize = 1000

var legacyStagingCols = []string{
	"sha256", "source", "filename", "label", "label_source",
	"path", "status", "cleave_result",
	"canonical_sha256", "analyzed_at", "updated_at",
}

const legacyStagingDDL = `CREATE TEMP TABLE _staging (
	sha256 TEXT, source TEXT, filename TEXT, label TEXT, label_source TEXT,
	path TEXT, status TEXT,
	cleave_result JSONB, canonical_sha256 TEXT,
	analyzed_at TIMESTAMPTZ, updated_at TIMESTAMPTZ
) ON COMMIT DROP`

const legacyStagingInsert = `INSERT INTO samples (sha256, source, filename, label, label_source,
	path, status, cleave_result,
	canonical_sha256, analyzed_at, updated_at)
SELECT sha256, source, filename, label, label_source,
	path, status, cleave_result,
	canonical_sha256, analyzed_at, updated_at
FROM _staging
ON CONFLICT (sha256) DO NOTHING`

func migrateLegacyPG(ctx context.Context, dst *DB, rows *sql.Rows, total int64) (int, error) {
	slog.Info("legacy import to postgres", "batch_size", legacyBatchSize)
	imported := 0
	scanned := 0
	batch := make([][]any, 0, legacyBatchSize)
	start := time.Now()
	var lastRowID int64

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := copyBatchPG(ctx, dst, legacyStagingDDL, legacyStagingInsert, legacyStagingCols, batch)
		if err != nil {
			return err
		}
		imported += int(n)
		batch = batch[:0]
		slog.Info("legacy import progress", "scanned", scanned, "imported", imported,
			"total", total, "rowid", lastRowID,
			"rows_per_sec", int(float64(scanned)/time.Since(start).Seconds()))
		return nil
	}

	for rows.Next() {
		if ctx.Err() != nil {
			return imported, ctx.Err()
		}

		var rowid int64
		var sha256, path, status string
		var updatedAt int64
		var cleaveJSON, risk sql.NullString
		var findingCount int

		if err := rows.Scan(&rowid, &sha256, &path, &status, &updatedAt, &cleaveJSON, &risk, &findingCount); err != nil {
			return imported, fmt.Errorf("scan row: %w", err)
		}
		lastRowID = rowid
		scanned++

		label := labelFromLegacyStatus(status)
		var cleaveResult []byte
		if cleaveJSON.Valid && cleaveJSON.String != "" {
			cleaveResult = sanitizeJSONB([]byte(cleaveJSON.String))
		}
		// PG JSONB has a 256MB limit per value.
		const maxJSONB = 268_435_455
		if len(cleaveResult) > maxJSONB {
			slog.Warn("cleave result exceeds PG JSONB limit, storing without result",
				"sha256", sha256, "size_bytes", len(cleaveResult))
			cleaveResult = nil
		}
		canonical := canonicalSHA(sha256, cleaveResult)

		var analyzedAt *time.Time
		if cleaveResult != nil {
			t := time.Now().UTC()
			analyzedAt = &t
		}
		var updatedTS time.Time
		if updatedAt > 0 {
			updatedTS = time.Unix(updatedAt, 0).UTC()
		} else {
			updatedTS = time.Now().UTC()
		}

		batch = append(batch, []any{
			sha256, "legacy", filepath.Base(path), label, "legacy",
			path, status, cleaveResult,
			canonical, analyzedAt, updatedTS,
		})

		if len(batch) >= legacyBatchSize {
			if err := flush(); err != nil {
				return imported, err
			}
		}
	}

	if err := flush(); err != nil {
		return imported, err
	}
	return imported, rows.Err()
}

// Database transfer with streaming reads and batched writes.

const transferBatchSize = 1000

// TransferSamples copies samples and reports from src to dst, streaming rows
// to avoid loading the full dataset into memory. Pass afterSampleID /
// afterReportID > 0 to resume a previous transfer from the last logged IDs.
func TransferSamples(ctx context.Context, dst, src *DB, afterSampleID, afterReportID int64) (samples int, reports int, err error) {
	slog.Info("transfer phase 1/2: samples")
	samples, err = transferSamplesPhase(ctx, dst, src, afterSampleID)
	if err != nil {
		return samples, 0, fmt.Errorf("transfer samples: %w", err)
	}
	slog.Info("transfer phase 1/2 complete", "samples", samples)

	slog.Info("transfer phase 2/2: reports")
	reports, err = transferReportsPhase(ctx, dst, src, afterReportID)
	if err != nil {
		return samples, reports, fmt.Errorf("transfer reports: %w", err)
	}
	slog.Info("transfer phase 2/2 complete", "reports", reports)
	return samples, reports, nil
}

func transferSamplesPhase(ctx context.Context, dst, src *DB, afterID int64) (int, error) {
	imported := 0
	scanned := 0
	batch := make([]*Sample, 0, transferBatchSize)
	start := time.Now()
	var lastID int64

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		var n int64
		var err error
		if dst.pool != nil {
			n, err = flushSamplesPG(ctx, dst, batch)
		} else {
			n, err = flushSamplesSQLite(ctx, dst, batch)
		}
		if err != nil {
			return err
		}
		imported += int(n)
		batch = batch[:0]
		elapsed := time.Since(start).Seconds()
		if elapsed > 0 {
			slog.Info("sample transfer progress", "scanned", scanned, "imported", imported,
				"source_id", lastID,
				"rows_per_sec", int(float64(scanned)/elapsed))
		}
		return nil
	}

	err := eachSample(ctx, src, afterID, func(s *Sample) error {
		lastID = s.ID
		scanned++
		batch = append(batch, s)
		if len(batch) >= transferBatchSize {
			return flush()
		}
		return nil
	})
	if err != nil {
		return imported, err
	}
	if err := flush(); err != nil {
		return imported, err
	}
	return imported, nil
}

func transferReportsPhase(ctx context.Context, dst, src *DB, afterID int64) (int, error) {
	imported := 0
	scanned := 0
	batch := make([]*Report, 0, transferBatchSize)
	start := time.Now()
	var lastID int64

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		var n int64
		var err error
		if dst.pool != nil {
			n, err = flushReportsPG(ctx, dst, batch)
		} else {
			n, err = flushReportsSQLite(ctx, dst, batch)
		}
		if err != nil {
			return err
		}
		imported += int(n)
		batch = batch[:0]
		elapsed := time.Since(start).Seconds()
		if elapsed > 0 {
			slog.Info("report transfer progress", "scanned", scanned, "imported", imported,
				"source_id", lastID,
				"rows_per_sec", int(float64(scanned)/elapsed))
		}
		return nil
	}

	err := eachReport(ctx, src, afterID, func(r *Report) error {
		lastID = r.ID
		scanned++
		batch = append(batch, r)
		if len(batch) >= transferBatchSize {
			return flush()
		}
		return nil
	})
	if err != nil {
		return imported, err
	}
	if err := flush(); err != nil {
		return imported, err
	}
	return imported, nil
}

// Source streaming iterators.

func eachSample(ctx context.Context, db *DB, afterID int64, fn func(*Sample) error) error {
	if db.pool != nil {
		return eachSamplePG(ctx, db, afterID, fn)
	}
	return eachSampleSQLite(ctx, db, afterID, fn)
}

func eachSamplePG(ctx context.Context, db *DB, afterID int64, fn func(*Sample) error) error {
	rows, err := db.pool.Query(ctx, `SELECT `+pgSampleCols+` FROM samples WHERE id > $1 ORDER BY id`, afterID)
	if err != nil {
		return fmt.Errorf("query samples: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		s := &Sample{}
		if err := rows.Scan(pgSampleDest(s)...); err != nil {
			return fmt.Errorf("scan sample: %w", err)
		}
		if err := fn(s); err != nil {
			return err
		}
	}
	return rows.Err()
}

func eachSampleSQLite(ctx context.Context, db *DB, afterID int64, fn func(*Sample) error) error {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE id > ? ORDER BY id`, afterID)
	if err != nil {
		return fmt.Errorf("query samples: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	for rows.Next() {
		s := &Sample{}
		var cleaveResult, litmusResult, status sql.NullString
		var analyzedAt, mtime sql.NullTime
		if err := rows.Scan(&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
			&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult,
			&s.Path, &status, &s.Note, &s.CanonicalSHA256,
			&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score, &s.CreatedAt, &s.UpdatedAt, &analyzedAt, &mtime); err != nil {
			return fmt.Errorf("scan sample: %w", err)
		}
		if cleaveResult.Valid {
			s.CleaveResult = []byte(cleaveResult.String)
		}
		if litmusResult.Valid {
			s.LitmusResult = []byte(litmusResult.String)
		}
		s.Status = status.String
		if analyzedAt.Valid {
			s.AnalyzedAt = &analyzedAt.Time
		}
		if mtime.Valid {
			s.Mtime = &mtime.Time
		}
		if err := fn(s); err != nil {
			return err
		}
	}
	return rows.Err()
}

func eachReport(ctx context.Context, db *DB, afterID int64, fn func(*Report) error) error {
	if db.pool != nil {
		return eachReportPG(ctx, db, afterID, fn)
	}
	return eachReportSQLite(ctx, db, afterID, fn)
}

func eachReportPG(ctx context.Context, db *DB, afterID int64, fn func(*Report) error) error {
	rows, err := db.pool.Query(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE id > $1 ORDER BY id`, afterID)
	if err != nil {
		return fmt.Errorf("query reports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		r := &Report{}
		if err := rows.Scan(&r.ID, &r.SHA256, &r.Type, &r.Content, &r.Provider, &r.DurationMS, &r.CreatedAt); err != nil {
			return fmt.Errorf("scan report: %w", err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

func eachReportSQLite(ctx context.Context, db *DB, afterID int64, fn func(*Report) error) error {
	rows, err := db.lite.QueryContext(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE id > ? ORDER BY id`, afterID)
	if err != nil {
		return fmt.Errorf("query reports: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	for rows.Next() {
		r := &Report{}
		if err := rows.Scan(&r.ID, &r.SHA256, &r.Type, &r.Content, &r.Provider, &r.DurationMS, &r.CreatedAt); err != nil {
			return fmt.Errorf("scan report: %w", err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Destination flushing: PG uses COPY plus staging, SQLite uses batched tx.

// Sample staging for PG COPY.

var sampleStagingCols = []string{
	"sha256", "source", "feed", "ecosystem", "filename", "file_type",
	"size_bytes", "label", "label_source", "path", "status",
	"note", "canonical_sha256", "parent", "skip", "formula", "elements", "score",
	"cleave_result", "litmus_result",
	"analyzed_at", "created_at", "updated_at", "mtime",
}

const sampleStagingDDL = `CREATE TEMP TABLE _staging (
	sha256 TEXT, source TEXT, feed TEXT, ecosystem TEXT, filename TEXT,
	file_type TEXT, size_bytes BIGINT, label TEXT, label_source TEXT,
	path TEXT, status TEXT, note TEXT, canonical_sha256 TEXT,
	parent TEXT, skip TEXT, formula TEXT, elements TEXT, score INTEGER,
	cleave_result JSONB, litmus_result JSONB,
	analyzed_at TIMESTAMPTZ, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ, mtime TIMESTAMPTZ
) ON COMMIT DROP`

const sampleStagingInsert = `INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, path, status, note, canonical_sha256,
	parent, skip, formula, elements, score, cleave_result, litmus_result, analyzed_at, created_at, updated_at, mtime)
SELECT sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, path, status, note, canonical_sha256,
	parent, skip, formula, elements, score, cleave_result, litmus_result, analyzed_at, created_at, updated_at, mtime
FROM _staging
ON CONFLICT (sha256) DO NOTHING`

func flushSamplesPG(ctx context.Context, dst *DB, samples []*Sample) (int64, error) {
	rows := make([][]any, len(samples))
	for i, s := range samples {
		rows[i] = []any{
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
			s.Note, s.CanonicalSHA256, s.Parent, s.Skip, s.Formula, s.Elements, s.Score,
			sanitizeJSONB(s.CleaveResult), sanitizeJSONB(s.LitmusResult),
			s.AnalyzedAt, s.CreatedAt, s.UpdatedAt, s.Mtime,
		}
	}
	return copyBatchPG(ctx, dst, sampleStagingDDL, sampleStagingInsert, sampleStagingCols, rows)
}

func flushSamplesSQLite(ctx context.Context, dst *DB, samples []*Sample) (int64, error) {
	tx, err := dst.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	var inserted int64
	for _, s := range samples {
		var cr, lr sql.NullString
		if s.CleaveResult != nil {
			cr = sql.NullString{String: string(s.CleaveResult), Valid: true}
		}
		if s.LitmusResult != nil {
			lr = sql.NullString{String: string(s.LitmusResult), Valid: true}
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
				size_bytes, label, label_source, path, status, note, canonical_sha256,
				parent, skip, formula, elements, score, cleave_result, litmus_result, analyzed_at, created_at, updated_at, mtime)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (sha256) DO NOTHING`,
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
			s.Note, s.CanonicalSHA256, s.Parent, s.Skip, s.Formula, s.Elements, s.Score, cr, lr,
			s.AnalyzedAt, s.CreatedAt, s.UpdatedAt, s.Mtime)
		if err != nil {
			tx.Rollback() //nolint:errcheck,gosec // insert error
			return inserted, fmt.Errorf("insert sample %s: %w", s.SHA256, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			inserted += n
		}
	}

	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("commit: %w", err)
	}
	return inserted, nil
}

// Report staging for PG COPY.

var reportStagingCols = []string{"sha256", "report_type", "content", "provider", "duration_ms", "created_at"}

const reportStagingDDL = `CREATE TEMP TABLE _staging (
	sha256 TEXT, report_type TEXT, content TEXT, provider TEXT,
	duration_ms INTEGER, created_at TIMESTAMPTZ
) ON COMMIT DROP`

const reportStagingInsert = `INSERT INTO reports (sha256, report_type, content, provider, duration_ms, created_at)
SELECT sha256, report_type, content, provider, duration_ms, created_at
FROM _staging`

func flushReportsPG(ctx context.Context, dst *DB, reports []*Report) (int64, error) {
	rows := make([][]any, len(reports))
	for i, r := range reports {
		rows[i] = []any{r.SHA256, r.Type, r.Content, r.Provider, r.DurationMS, r.CreatedAt}
	}
	return copyBatchPG(ctx, dst, reportStagingDDL, reportStagingInsert, reportStagingCols, rows)
}

func flushReportsSQLite(ctx context.Context, dst *DB, reports []*Report) (int64, error) {
	tx, err := dst.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}

	var inserted int64
	for _, r := range reports {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO reports (sha256, report_type, content, provider, duration_ms, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			r.SHA256, r.Type, r.Content, r.Provider, r.DurationMS, r.CreatedAt)
		if err != nil {
			slog.Warn("skipping report", "sha256", r.SHA256, "type", r.Type, "error", err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("commit: %w", err)
	}
	return inserted, nil
}

// Shared helpers.

// copyBatchPG writes rows to PG via COPY into a temp staging table, then
// inserts into the real table with ON CONFLICT handling. The staging table
// is created with ON COMMIT DROP so it is cleaned up automatically.
//
// If COPY fails (e.g. invalid Unicode in JSONB), falls back to row-by-row
// inserts so only the bad rows are skipped.
func copyBatchPG(ctx context.Context, dst *DB, ddl, insertSQL string, cols []string, rows [][]any) (int64, error) {
	n, err := copyBatchPGFast(ctx, dst, ddl, insertSQL, cols, rows)
	if err == nil {
		return n, nil
	}

	// Log the COPY error with batch context and fall back to row-by-row.
	firstSHA := "<unknown>"
	if len(rows) > 0 && len(rows[0]) > 0 {
		if s, ok := rows[0][0].(string); ok {
			firstSHA = s
		}
	}
	slog.Warn("COPY batch failed, falling back to row-by-row",
		"error", err, "batch_size", len(rows), "first_sha256", firstSHA)

	return copyBatchPGSlow(ctx, dst, ddl, insertSQL, cols, rows)
}

func copyBatchPGFast(ctx context.Context, dst *DB, ddl, insertSQL string, cols []string, rows [][]any) (int64, error) {
	tx, err := dst.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	if _, err := tx.Exec(ctx, ddl); err != nil {
		return 0, fmt.Errorf("create staging: %w", err)
	}

	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_staging"}, cols, pgx.CopyFromRows(rows)); err != nil {
		return 0, fmt.Errorf("copy to staging: %w", err)
	}

	tag, err := tx.Exec(ctx, insertSQL)
	if err != nil {
		return 0, fmt.Errorf("insert from staging: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return tag.RowsAffected(), nil
}

// copyBatchPGSlow inserts rows one at a time via individual transactions,
// logging and skipping any that fail. Used as a fallback when COPY hits
// encoding or data errors.
func copyBatchPGSlow(ctx context.Context, dst *DB, ddl, insertSQL string, cols []string, rows [][]any) (int64, error) {
	var inserted int64
	for _, row := range rows {
		n, err := copyBatchPGFast(ctx, dst, ddl, insertSQL, cols, [][]any{row})
		if err != nil {
			sha := "<unknown>"
			if len(row) > 0 {
				if s, ok := row[0].(string); ok {
					sha = s
				}
			}
			slog.Warn("skipping row", "sha256", sha, "error", err)
			continue
		}
		inserted += n
	}
	return inserted, nil
}

func labelFromLegacyStatus(status string) string {
	switch status {
	case "good", "good-review", "good-analyzed", "good-exhausted", "bad-benign":
		return "good"
	case "bad", "bad-review", "bad-reversed", "bad-gapped", "bad-exhausted", "good-malicious":
		return "bad"
	default:
		return "unknown"
	}
}
