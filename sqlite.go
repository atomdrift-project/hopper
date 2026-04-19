package hopper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

func openSQLite(ctx context.Context, dsn string) (*DB, error) {
	lite, err := sql.Open("sqlite3", dsn+"?_journal_mode=WAL&_busy_timeout=30000&_foreign_keys=ON&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("hopper: open sqlite: %w", err)
	}
	// SQLite does not support concurrent writers; restrict to a single
	// connection so database/sql never opens parallel write transactions.
	lite.SetMaxOpenConns(1)
	if err := lite.PingContext(ctx); err != nil {
		if closeErr := lite.Close(); closeErr != nil {
			slog.Debug("close sqlite after failed ping", "error", closeErr)
		}
		return nil, fmt.Errorf("hopper: ping sqlite: %w", err)
	}
	return &DB{lite: lite}, nil
}

func pragmaHasColumn(ctx context.Context, db *sql.DB, column string) int {
	var count int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM pragma_table_info('samples') WHERE name = ?", column,
	).Scan(&count); err != nil {
		slog.Debug("pragma_table_info failed", "column", column, "error", err)
		return 0
	}
	return count
}

func (db *DB) migrateSQLite(ctx context.Context) error {
	slog.Debug("executing initial schema ddl")
	if _, err := db.lite.ExecContext(ctx, schemaSQLite); err != nil {
		return fmt.Errorf("hopper: migrate sqlite: %w", err)
	}

	// Add columns introduced after initial schema. SQLite lacks
	// ALTER TABLE ... IF NOT EXISTS, so check column existence via PRAGMA.
	hasParent := pragmaHasColumn(ctx, db.lite, "parent")
	if hasParent == 0 {
		for _, ddl := range []string{
			`ALTER TABLE samples ADD COLUMN parent TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE samples ADD COLUMN skip TEXT NOT NULL DEFAULT ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != ''`,
		} {
			slog.Debug("executing migration ddl", "ddl", ddl)
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	hasFormula := pragmaHasColumn(ctx, db.lite, "formula")
	if hasFormula == 0 {
		for _, ddl := range []string{
			`ALTER TABLE samples ADD COLUMN formula TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE samples ADD COLUMN elements TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE samples ADD COLUMN score INTEGER NOT NULL DEFAULT 0`,
			`CREATE INDEX IF NOT EXISTS idx_samples_formula ON samples(formula) WHERE formula != ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_elements ON samples(elements) WHERE elements != ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_score ON samples(score) WHERE score != 0`,
			`CREATE INDEX IF NOT EXISTS idx_samples_feed_source ON samples(source, label, analyzed_at DESC) WHERE cleave_result IS NOT NULL`,
			`CREATE INDEX IF NOT EXISTS idx_samples_feed ON samples(feed) WHERE feed != ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_ecosystem ON samples(ecosystem) WHERE ecosystem != ''`,
		} {
			slog.Debug("executing migration ddl", "ddl", ddl)
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	// Add litmus_result column.
	hasLitmusResult := pragmaHasColumn(ctx, db.lite, "litmus_result")
	if hasLitmusResult == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN litmus_result TEXT`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	// Add litmus_score column.
	hasLitmusScore := pragmaHasColumn(ctx, db.lite, "litmus_score")
	if hasLitmusScore == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN litmus_score REAL NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	// Add mtime column.
	hasMtime := pragmaHasColumn(ctx, db.lite, "mtime")
	if hasMtime == 0 {
		for _, ddl := range []string{
			`ALTER TABLE samples ADD COLUMN mtime DATETIME`,
			`CREATE INDEX IF NOT EXISTS idx_samples_mtime ON samples(mtime) WHERE mtime IS NOT NULL`,
			`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_mtime ON samples(source, label, mtime DESC) WHERE cleave_result IS NOT NULL`,
		} {
			slog.Debug("executing migration ddl", "ddl", ddl)
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	hasMarkerMtime := pragmaHasColumn(ctx, db.lite, "marker_mtime")
	if hasMarkerMtime == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN marker_mtime DATETIME`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	if _, err := db.lite.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type)`); err != nil {
		return fmt.Errorf("hopper: migrate sqlite: %w", err)
	}

	hasMaxCrit := pragmaHasColumn(ctx, db.lite, "max_crit")
	if hasMaxCrit == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN max_crit INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	hasSuspicious := pragmaHasColumn(ctx, db.lite, "suspicious_count")
	if hasSuspicious == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN suspicious_count INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	// Pull-based work scheduling: claim tracking columns.
	hasClaimedBy := pragmaHasColumn(ctx, db.lite, "claimed_by")
	if hasClaimedBy == 0 {
		for _, ddl := range []string{
			`ALTER TABLE samples ADD COLUMN claimed_by TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE samples ADD COLUMN claimed_at DATETIME`,
			`CREATE INDEX IF NOT EXISTS idx_samples_claimable ON samples(id) WHERE cleave_result IS NULL AND claimed_by = ''`,
		} {
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	// Traits-version rescan column.
	hasTraitsVersion := pragmaHasColumn(ctx, db.lite, "traits_version")
	if hasTraitsVersion == 0 {
		for _, ddl := range []string{
			`ALTER TABLE samples ADD COLUMN traits_version TEXT NOT NULL DEFAULT ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_stale_traits ` +
				`ON samples(traits_version, analyzed_at) ` +
				`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''`,
		} {
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	// Worker heartbeat table for dashboard.
	if _, err := db.lite.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS workers (
		name      TEXT PRIMARY KEY,
		last_seen DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		slots     INTEGER NOT NULL DEFAULT 1,
		version   TEXT NOT NULL DEFAULT '',
		traits    TEXT NOT NULL DEFAULT '',
		analyzed  INTEGER NOT NULL DEFAULT 0,
		errors    INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return fmt.Errorf("hopper: migrate sqlite: %w", err)
	}

	// Partial indexes matching PG for review and dashboard queries.
	for _, ddl := range []string{
		// falsePositives / truePositives / falseNegatives
		`CREATE INDEX IF NOT EXISTS idx_samples_review ` +
			`ON samples(label, score) ` +
			`WHERE cleave_result IS NOT NULL AND status = '' AND skip = ''`,
		// benignReview / badReview
		`CREATE INDEX IF NOT EXISTS idx_samples_misclassified_review ` +
			`ON samples(label, max_crit, suspicious_count) ` +
			`WHERE label_source = 'marker' AND skip = 'misclassified' ` +
			`AND cleave_result IS NOT NULL AND status = ''`,
		// CountAnalyzed
		`CREATE INDEX IF NOT EXISTS idx_samples_litmus_done ` +
			`ON samples(id) WHERE litmus_result IS NOT NULL`,
		// CountPending / claimable ordering
		`DROP INDEX IF EXISTS idx_samples_claimable`,
		`CREATE INDEX IF NOT EXISTS idx_samples_claimable ` +
			`ON samples(updated_at, id) ` +
			`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`,
		// NewestAnalyzedAt
		`CREATE INDEX IF NOT EXISTS idx_samples_analyzed_at ` +
			`ON samples(analyzed_at) WHERE analyzed_at IS NOT NULL`,
		// OldestClaims
		`CREATE INDEX IF NOT EXISTS idx_samples_claimed ` +
			`ON samples(claimed_by, claimed_at) WHERE claimed_by != '' AND cleave_result IS NULL`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite index: %w", err)
		}
	}

	return nil
}

const liteSampleCols = `id, sha256, source, feed, ecosystem,
	filename, file_type, size_bytes, label, label_source,
	cleave_result, litmus_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip,
	formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, mtime, marker_mtime,
	traits_version`

func scanLiteSample(row *sql.Row) (*Sample, error) {
	s := &Sample{}
	var cleaveResult, litmusResult, status sql.NullString
	var analyzedAt, mtime, markerMtime sql.NullTime
	err := row.Scan(
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult, &s.LitmusScore,
		&s.Path, &status, &s.Note, &s.CanonicalSHA256, &s.Parent, &s.Skip, &s.Formula,
		&s.Elements, &s.Score, &s.MaxCrit, &s.SuspiciousCount, &s.CreatedAt, &s.UpdatedAt, &analyzedAt, &mtime, &markerMtime,
		&s.TraitsVersion,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
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
	if markerMtime.Valid {
		s.MarkerMtime = &markerMtime.Time
	}
	return s, nil
}

func scanLiteSamples(rows *sql.Rows) ([]*Sample, error) {
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		var cleaveResult, litmusResult, status sql.NullString
		var analyzedAt, mtime, markerMtime sql.NullTime
		if err := rows.Scan(
			&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
			&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult, &s.LitmusScore,
			&s.Path, &status, &s.Note, &s.CanonicalSHA256,
			&s.Parent, &s.Skip, &s.Formula, &s.Elements,
			&s.Score, &s.MaxCrit, &s.SuspiciousCount,
			&s.CreatedAt, &s.UpdatedAt, &analyzedAt, &mtime, &markerMtime,
			&s.TraitsVersion,
		); err != nil {
			return nil, err
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
		if markerMtime.Valid {
			s.MarkerMtime = &markerMtime.Time
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (db *DB) insertSampleNewSQLite(ctx context.Context, s *Sample) (bool, error) {
	res, err := db.lite.ExecContext(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
			size_bytes, label, label_source, path, status,
			canonical_sha256, parent, skip, formula, elements,
			score, max_crit, suspicious_count, mtime, marker_mtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256) DO UPDATE SET path = excluded.path, mtime = excluded.mtime
			WHERE samples.path != excluded.path`,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
		s.SHA256, s.Parent, s.Skip, s.Formula, s.Elements,
		s.Score, s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime)
	if err != nil {
		return false, fmt.Errorf("hopper: insert sample: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("hopper: rows affected: %w", err)
	}
	if n == 0 && s.MarkerMtime != nil {
		if _, err := db.lite.ExecContext(ctx, `UPDATE samples SET marker_mtime = ? WHERE sha256 = ?`, s.MarkerMtime, s.SHA256); err != nil {
			return false, fmt.Errorf("hopper: refresh marker mtime: %w", err)
		}
	}
	return n > 0, nil
}

func (db *DB) insertSampleBatchSQLite(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: begin batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is best-effort after commit // commit or rollback

	cols := []string{
		"sha256", "source", "feed", "ecosystem", "filename", "file_type",
		"size_bytes", "label", "label_source", "path", "status", "canonical_sha256",
		"parent", "skip", "formula", "elements", "score", "max_crit", "suspicious_count", "mtime", "marker_mtime",
	}
	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = "?"
	}

	query := fmt.Sprintf( //nolint:gosec // column list and placeholders are derived from fixed local constants.
		`
		INSERT INTO samples (%s)
		VALUES (%s)
		ON CONFLICT (sha256) DO UPDATE SET path = excluded.path, mtime = excluded.mtime
			WHERE samples.path != excluded.path`,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "))

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: prepare batch: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // best-effort cleanup

	for _, s := range samples {
		res, err := stmt.ExecContext(ctx,
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
			s.SHA256, s.Parent, s.Skip, s.Formula, s.Elements,
			s.Score, s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime)
		if err != nil {
			return 0, nil, fmt.Errorf("hopper: batch insert %s: %w", s.SHA256, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			inserted += n
		}
		if s.MarkerMtime != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE samples SET marker_mtime = ? WHERE sha256 = ?`, s.MarkerMtime, s.SHA256); err != nil {
				return 0, nil, fmt.Errorf("hopper: refresh marker mtime %s: %w", s.SHA256, err)
			}
		}
	}

	// Find SHAs that lack analysis results.
	if _, err := tx.ExecContext(ctx, "CREATE TEMP TABLE IF NOT EXISTS _batch_shas (sha256 TEXT)"); err != nil {
		return 0, nil, fmt.Errorf("hopper: create batch staging: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM _batch_shas"); err != nil {
		return 0, nil, fmt.Errorf("hopper: clear batch staging: %w", err)
	}

	stagingStmt, err := tx.PrepareContext(ctx, "INSERT INTO _batch_shas (sha256) VALUES (?)")
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: prepare batch staging: %w", err)
	}
	defer func() {
		if closeErr := stagingStmt.Close(); closeErr != nil {
			slog.Debug("close staging statement failed", "error", closeErr)
		}
	}()

	for _, s := range samples {
		if _, err := stagingStmt.ExecContext(ctx, s.SHA256); err != nil {
			return 0, nil, fmt.Errorf("hopper: staging exec: %w", err)
		}
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT s.sha256 FROM samples s
		JOIN _batch_shas b ON s.sha256 = b.sha256
		WHERE s.litmus_result IS NULL`)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: query needs analysis: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			slog.Debug("close needs-analysis rows failed", "error", closeErr)
		}
	}()

	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return 0, nil, fmt.Errorf("hopper: scan needs analysis: %w", err)
		}
		needsAnalysis = append(needsAnalysis, sha)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("hopper: rows needs analysis: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, nil, fmt.Errorf("hopper: commit batch: %w", err)
	}
	return inserted, needsAnalysis, nil
}

func (db *DB) sampleBySHA256SQLite(ctx context.Context, sha256 string) (*Sample, error) {
	s, err := scanLiteSample(db.lite.QueryRowContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE sha256 = ?`, sha256))
	if err != nil {
		return nil, fmt.Errorf("hopper: sample %s: %w", sha256, err)
	}
	return s, nil
}

func (db *DB) updateCleaveResultSQLite(
	ctx context.Context, sha256 string, result []byte, canonical string,
	fi cleaveFileInfo, traitsVersion string,
) error {
	n := now()
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET cleave_result = ?,
			canonical_sha256 = ?, formula = ?, elements = ?, score = ?, max_crit = ?, suspicious_count = ?,
			file_type = CASE WHEN ? = '' THEN file_type ELSE ? END,
			litmus_result = NULL, litmus_score = 0,
			traits_version = ?,
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`,
		string(result), canonical, fi.Formula, fi.Elements,
		fi.Score, fi.MaxCrit, fi.SuspiciousCount,
		fi.FileType, fi.FileType, traitsVersion, n, n, sha256)
	if err != nil {
		return fmt.Errorf("hopper: update cleave result: %w", err)
	}
	return nil
}

func (db *DB) updateLitmusResultSQLite(ctx context.Context, sha256 string, result []byte, score float64) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET litmus_result = ?, litmus_score = ?, updated_at = ?
		WHERE sha256 = ?`, string(result), score, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: update litmus result: %w", err)
	}
	return nil
}

func (db *DB) reclassifySQLite(ctx context.Context, sha256, label, source string) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET label = ?, label_source = ?, updated_at = ? WHERE sha256 = ?`,
		label, source, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: reclassify: %w", err)
	}
	return nil
}

func (db *DB) unanalyzedSQLite(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE cleave_result IS NULL ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: unanalyzed: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) samplesByLabelSQLite(ctx context.Context, label string, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE label = ? ORDER BY id LIMIT ?`, label, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by label: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) countByLabelSQLite(ctx context.Context) (map[string]int, error) {
	rows, err := db.lite.QueryContext(ctx, `SELECT label, count(*) FROM samples GROUP BY label`)
	if err != nil {
		return nil, fmt.Errorf("hopper: count by label: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	return scanLiteCounts(rows)
}

func (db *DB) setNoteSQLite(ctx context.Context, sha256, note string) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET note = ?, updated_at = ? WHERE sha256 = ?`,
		note, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: set note: %w", err)
	}
	return nil
}

func (db *DB) setStatusSQLite(ctx context.Context, sha256, status string) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET status = ?, note = '', updated_at = ? WHERE sha256 = ?`,
		status, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: set status: %w", err)
	}
	return nil
}

func (db *DB) samplesByStatusSQLite(ctx context.Context, status string, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE status = ? ORDER BY updated_at ASC LIMIT ?`,
		status, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by status: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) falsePositivesSQLite(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND status = '' AND skip = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2)
		 ORDER BY updated_at ASC LIMIT ?`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false positives: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) truePositivesSQLite(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND score >= ? AND status = '' AND skip = ''
		 ORDER BY score DESC LIMIT ?`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: true positives: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) falseNegativesSQLite(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND status = '' AND skip = ''
		   AND max_crit < 5 AND suspicious_count < 2
		 ORDER BY updated_at ASC LIMIT ?`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) benignReviewSQLite(ctx context.Context, _, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL AND status = ''
			AND (max_crit >= 5 OR suspicious_count >= 2)
		 ORDER BY max_crit DESC, suspicious_count DESC LIMIT ?`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: benign review: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) badReviewSQLite(ctx context.Context, _, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL AND status = ''
			AND max_crit < 5 AND suspicious_count <= 1
		 ORDER BY suspicious_count ASC, max_crit ASC LIMIT ?`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: bad review: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) countByStatusSQLite(ctx context.Context) (map[string]int, error) {
	rows, err := db.lite.QueryContext(ctx, `SELECT status, count(*) FROM samples WHERE status != '' GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("hopper: count by status: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	return scanLiteCounts(rows)
}

func (db *DB) countAnalyzedSQLite(ctx context.Context) (int64, error) {
	var n int64
	err := db.lite.QueryRowContext(ctx, "SELECT count(*) FROM samples WHERE litmus_result IS NOT NULL").Scan(&n)
	return n, err
}

func (db *DB) updateSampleSQLite(ctx context.Context, sha256, status string, result []byte, canonical string, fi cleaveFileInfo) error {
	n := now()
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET status = ?, cleave_result = ?,
			canonical_sha256 = ?, formula = ?, elements = ?, score = ?, max_crit = ?, suspicious_count = ?,
			file_type = CASE WHEN ? = '' THEN file_type ELSE ? END,
			litmus_result = NULL, litmus_score = 0,
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`,
		status, string(result), canonical, fi.Formula,
		fi.Elements, fi.Score, fi.MaxCrit, fi.SuspiciousCount,
		fi.FileType, fi.FileType, n, n, sha256)
	if err != nil {
		return fmt.Errorf("hopper: update sample: %w", err)
	}
	return nil
}

func (db *DB) samplesByStatusInPathsSQLite(ctx context.Context, status string, prefixes []string, limit int) ([]*Sample, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	var clauses []string
	args := []any{status}
	for _, p := range prefixes {
		clauses = append(clauses, "path GLOB ?")
		args = append(args, p+"/*")
	}
	args = append(args, limit)
	//nolint:gosec // query structure is built from constants, values are parameterized
	query := `SELECT ` + liteSampleCols + ` FROM samples WHERE status = ? AND (` +
		strings.Join(clauses, " OR ") + `) ORDER BY updated_at ASC LIMIT ?`
	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by status in paths: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) falsePositivesInPathsSQLite(ctx context.Context, prefixes []string, limit int) ([]*Sample, error) {
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "good", limit)
}

func (db *DB) falseNegativesInPathsSQLite(ctx context.Context, prefixes []string, limit int) ([]*Sample, error) {
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "bad", limit)
}

func (db *DB) seedCandidatesInPathsSQLite(ctx context.Context, prefixes []string, label string, limit int) ([]*Sample, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	var clauses []string
	args := []any{label}
	for _, p := range prefixes {
		clauses = append(clauses, "path GLOB ?")
		args = append(args, p+"/*")
	}
	args = append(args, limit)
	// Apply detection-equivalent filter so the DB only returns samples that
	// will pass the Go-side Detected() / !Detected() post-filter.
	var detectionFilter string
	if label == "good" {
		detectionFilter = " AND (max_crit >= 5 OR suspicious_count >= 2)"
	} else {
		detectionFilter = " AND max_crit < 5 AND suspicious_count < 2"
	}

	//nolint:gosec // query structure is built from constants, values are parameterized
	query := `SELECT ` + liteSampleCols + ` FROM samples` +
		` WHERE status = '' AND label = ? AND skip = ''` +
		` AND cleave_result IS NOT NULL` +
		` AND (` + strings.Join(clauses, " OR ") + `)` +
		detectionFilter +
		` ORDER BY updated_at ASC LIMIT ?`
	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: seed candidates in paths: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) countByStatusInPathsSQLite(ctx context.Context, prefixes []string) (map[string]int, error) {
	if len(prefixes) == 0 {
		return db.countByStatusSQLite(ctx)
	}
	var clauses []string
	var args []any
	for _, p := range prefixes {
		clauses = append(clauses, "path GLOB ?")
		args = append(args, p+"/*")
	}
	//nolint:gosec // query structure is built from constants, values are parameterized
	query := `SELECT status, count(*) FROM samples WHERE status != '' AND (` +
		strings.Join(clauses, " OR ") + `) GROUP BY status`
	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: count by status in paths: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	return scanLiteCounts(rows)
}

func (db *DB) agesByPathsSQLite(ctx context.Context, prefixes []string, limit int) (map[string]time.Time, error) {
	if len(prefixes) == 0 {
		return make(map[string]time.Time), nil
	}
	var clauses []string
	var args []any
	for _, p := range prefixes {
		clauses = append(clauses, "path GLOB ?")
		args = append(args, p+"/*")
	}
	args = append(args, limit)
	//nolint:gosec // query structure is built from constants, values are parameterized
	query := `SELECT path, updated_at FROM samples WHERE (` + strings.Join(clauses, " OR ") + `) ORDER BY updated_at ASC LIMIT ?`
	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: ages by paths: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	ages := make(map[string]time.Time)
	for rows.Next() {
		var path string
		var t time.Time
		if err := rows.Scan(&path, &t); err != nil {
			return nil, err
		}
		ages[path] = t
	}
	return ages, rows.Err()
}

func (db *DB) staleSamplesSQLite(ctx context.Context, prefixes []string, olderThan time.Time, limit int) ([]*Sample, error) {
	threshold := olderThan.UTC().Format(time.RFC3339Nano)
	if len(prefixes) == 0 {
		rows, err := db.lite.QueryContext(ctx,
			`SELECT `+liteSampleCols+` FROM samples WHERE updated_at < ? ORDER BY updated_at ASC LIMIT ?`,
			threshold, limit)
		if err != nil {
			return nil, fmt.Errorf("hopper: stale samples: %w", err)
		}
		return scanLiteSamples(rows)
	}
	var clauses []string
	args := []any{threshold}
	for _, p := range prefixes {
		clauses = append(clauses, "path GLOB ?")
		args = append(args, p+"/*")
	}
	args = append(args, limit)
	//nolint:gosec // query structure is built from constants, values are parameterized
	query := `SELECT ` + liteSampleCols + ` FROM samples WHERE updated_at < ? AND (` +
		strings.Join(clauses, " OR ") + `) ORDER BY updated_at ASC LIMIT ?`
	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: stale samples: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) insertReportSQLite(ctx context.Context, r *Report) error {
	_, err := db.lite.ExecContext(ctx, `
		INSERT INTO reports (sha256, report_type, content, provider, duration_ms)
		VALUES (?, ?, ?, ?, ?)`,
		r.SHA256, r.Type, r.Content, r.Provider, r.DurationMS)
	if err != nil {
		return fmt.Errorf("hopper: insert report: %w", err)
	}
	return nil
}

func (db *DB) reportsBySHA256SQLite(ctx context.Context, sha256 string) ([]*Report, error) {
	rows, err := db.lite.QueryContext(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE sha256 = ? ORDER BY created_at DESC`, sha256)
	if err != nil {
		return nil, fmt.Errorf("hopper: reports for %s: %w", sha256, err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []*Report
	for rows.Next() {
		r := &Report{}
		if err := rows.Scan(&r.ID, &r.SHA256, &r.Type, &r.Content, &r.Provider, &r.DurationMS, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) latestReportSQLite(ctx context.Context, sha256, reportType string) (*Report, error) {
	r := &Report{}
	err := db.lite.QueryRowContext(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE sha256 = ? AND report_type = ?
		ORDER BY created_at DESC LIMIT 1`, sha256, reportType).Scan(
		&r.ID, &r.SHA256, &r.Type, &r.Content, &r.Provider, &r.DurationMS, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("hopper: latest report: %w", err)
	}
	return r, nil
}

func (db *DB) samplesByEmbeddedSHA256SQLite(ctx context.Context, sha256 string, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx, `
		SELECT `+liteSampleCols+` FROM samples WHERE id IN (
			SELECT DISTINCT s.id
			FROM samples s, json_each(s.cleave_result, '$.files')
			WHERE json_extract(value, '$.sha256') = ?
		)
		ORDER BY id
		LIMIT ?`, sha256, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by embedded sha256: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) recomputeCanonicalSHA256SQLite(ctx context.Context) (int64, error) {
	const batchSize = 5000
	var total int64
	var lastID int64
	for {
		ts := now()
		res, err := db.lite.ExecContext(ctx, `
			UPDATE samples SET canonical_sha256 = (
				SELECT MIN(v) FROM (
					SELECT samples.sha256 AS v
					UNION ALL
					SELECT json_extract(value, '$.sha256') AS v
					FROM json_each(samples.cleave_result, '$.files')
					WHERE length(v) = 64
				)
			), updated_at = ?
			WHERE rowid IN (
				SELECT rowid FROM samples
				WHERE cleave_result IS NOT NULL AND id > ?
				ORDER BY id LIMIT ?
			)`, ts, lastID, batchSize)
		if err != nil {
			return total, fmt.Errorf("hopper: recompute canonical sha256: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("hopper: rows affected recompute canonical sha256: %w", err)
		}
		total += n
		// Advance cursor: find the max id in this batch.
		if err := db.lite.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(id), 0) FROM samples
			WHERE cleave_result IS NOT NULL AND id > ?
			ORDER BY id LIMIT ?`, lastID, batchSize).Scan(&lastID); err != nil {
			return total, fmt.Errorf("hopper: recompute cursor: %w", err)
		}
		if n < batchSize {
			break
		}
		slog.Info("recompute canonical sha256 batch", "batch", n, "total", total)
	}
	return total, nil
}

// stripSubscriptsSQL is the SQLite expression equivalent of stripSubscripts:
// chained replace() over each Unicode subscript digit. Ugly but keeps the
// work in SQL where it's free compared to streaming blobs to Go.
const stripSubscriptsSQL = `replace(replace(replace(replace(replace(` +
	`replace(replace(replace(replace(replace(` +
	`%s, '₀',''),'₁',''),'₂',''),'₃',''),'₄',''),` +
	`'₅',''),'₆',''),'₇',''),'₈',''),'₉','')`

// backfillSQLite mirrors backfillPG: SQL-side re-derivation gated on an
// empty file_type column so already-backfilled rows are skipped cheaply.
// See backfillPG for the rationale.
func (db *DB) backfillSQLite(ctx context.Context) (BackfillStats, error) {
	var stats BackfillStats
	ts := now()

	if err := db.lite.QueryRowContext(ctx, `
		SELECT count(*) FROM samples
		WHERE file_type = ''
			AND (cleave_result IS NOT NULL OR litmus_result IS NOT NULL)`).Scan(&stats.Scanned); err != nil {
		return stats, fmt.Errorf("hopper: backfill count: %w", err)
	}

	// Pass 1: formula / elements / score / file_type / max_crit from cleave_result.
	// json_each over $.fs, filter to the depth-0 entry. Rows without one
	// are silently skipped (matches PG behavior). stripSubscriptsSQL is a
	// compile-time format string filled with a compile-time expression,
	// so there's no tainted input despite the string concatenation.
	// max_crit is computed via a correlated SELECT MAX over $.ts on the
	// matched depth-0 entry. Batched to avoid one huge transaction.
	elementsExpr := fmt.Sprintf(stripSubscriptsSQL, "COALESCE(j.f, '')")
	const backfillBatch = 5000
	for {
		//nolint:gosec // constant SQL fragments, no tainted input.
		cleaveSQL := `
			WITH batch AS (
				SELECT sha256 FROM samples
				WHERE file_type = '' AND cleave_result IS NOT NULL
				LIMIT ?
			),
			cleave_extract AS (
				SELECT s.sha256,
					json_extract(je.value, '$.f') AS f,
					json_extract(je.value, '$.x') AS x,
					json_extract(je.value, '$.type') AS t,
					(SELECT COALESCE(MAX(CAST(json_extract(te.value, '$.l') AS INTEGER)), 0)
					 FROM json_each(je.value, '$.ts') te) AS mc,
					(SELECT COUNT(*)
					 FROM json_each(je.value, '$.ts') te
					 WHERE CAST(json_extract(te.value, '$.l') AS INTEGER) >= 4) AS sc
				FROM samples s
				JOIN batch b ON b.sha256 = s.sha256,
					json_each(s.cleave_result, '$.fs') je
				WHERE json_extract(je.value, '$.dp') = 0
			)
			UPDATE samples SET
				formula = COALESCE(j.f, ''),
				elements = ` + elementsExpr + `,
				score = COALESCE(j.x, 0),
				max_crit = COALESCE(j.mc, 0),
				suspicious_count = COALESCE(j.sc, 0),
				file_type = CASE WHEN COALESCE(j.t, '') = '' THEN samples.file_type ELSE j.t END,
				updated_at = ?
			FROM cleave_extract j
			WHERE samples.sha256 = j.sha256
				AND samples.file_type = ''`
		cleaveRes, err := db.lite.ExecContext(ctx, cleaveSQL, backfillBatch, ts)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill cleave columns: %w", err)
		}
		n, err := cleaveRes.RowsAffected()
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill rows affected: %w", err)
		}
		stats.Updated += n
		if n < backfillBatch {
			break
		}
		slog.Info("backfill cleave batch", "batch", n, "total", stats.Updated)
	}

	// Pass 2: litmus_score from litmus_result.prob, same scope.
	litmusRes, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET
			litmus_score = COALESCE(json_extract(litmus_result, '$.prob'), 0),
			updated_at = ?
		WHERE file_type = ''
			AND litmus_result IS NOT NULL
			AND litmus_score IS NOT COALESCE(json_extract(litmus_result, '$.prob'), 0)`, ts)
	if err != nil {
		return stats, fmt.Errorf("hopper: backfill litmus_score: %w", err)
	}
	if n, err := litmusRes.RowsAffected(); err == nil {
		stats.Updated += n
	}

	// Pass 3: clear stale skip='misclassified' markers whose underlying
	// trait counts no longer disagree with the marker. The old score-based
	// rule was noisy on large tarballs and parked many rows here that the
	// new max_crit/suspicious_count rule would never have flagged.
	goodRes, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = '', updated_at = ?
		WHERE label = 'good' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL
			AND max_crit < 5 AND suspicious_count <= 1`, ts)
	if err != nil {
		return stats, fmt.Errorf("hopper: backfill reset benign markers: %w", err)
	}
	if n, err := goodRes.RowsAffected(); err == nil {
		stats.MarkersCleared += n
	}

	badRes, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = '', updated_at = ?
		WHERE label = 'bad' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL
			AND (max_crit >= 5 OR suspicious_count >= 2)`, ts)
	if err != nil {
		return stats, fmt.Errorf("hopper: backfill reset bad markers: %w", err)
	}
	if n, err := badRes.RowsAffected(); err == nil {
		stats.MarkersCleared += n
	}

	return stats, nil
}

func (db *DB) setSkipSQLite(ctx context.Context, sha256, skip string) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = ?, claimed_by = '', claimed_at = NULL, updated_at = ? WHERE sha256 = ?`,
		skip, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: set skip: %w", err)
	}
	return nil
}

func (db *DB) deleteSampleSQLite(ctx context.Context, sha256 string) error {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("hopper: begin delete: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is best-effort after commit // commit or rollback

	if _, err := tx.ExecContext(ctx, `DELETE FROM reports WHERE sha256 = ?`, sha256); err != nil {
		return fmt.Errorf("hopper: delete sample reports: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM samples WHERE sha256 = ?`, sha256); err != nil {
		return fmt.Errorf("hopper: delete sample: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hopper: commit delete: %w", err)
	}
	return nil
}

func (db *DB) purgeUnsupportedSQLite(ctx context.Context, dryRun bool) (int64, error) {
	if dryRun {
		var n int64
		err := db.lite.QueryRowContext(ctx, `
			SELECT count(*) FROM samples
			WHERE cleave_result IS NOT NULL AND file_type = ''`).Scan(&n)
		if err != nil {
			return 0, fmt.Errorf("hopper: count unsupported: %w", err)
		}
		return n, nil
	}

	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin purge: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is best-effort after commit // commit or rollback

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM reports WHERE sha256 IN (
			SELECT sha256 FROM samples
			WHERE cleave_result IS NOT NULL AND file_type = ''
		)`); err != nil {
		return 0, fmt.Errorf("hopper: purge unsupported reports: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		DELETE FROM samples
		WHERE cleave_result IS NOT NULL AND file_type = ''`)
	if err != nil {
		return 0, fmt.Errorf("hopper: purge unsupported: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("hopper: purge unsupported rows affected: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hopper: commit purge: %w", err)
	}
	return n, nil
}

func (db *DB) deleteAllSQLite(ctx context.Context) error {
	_, err := db.lite.ExecContext(ctx, `DELETE FROM reports`)
	if err != nil {
		return fmt.Errorf("hopper: delete reports: %w", err)
	}
	_, err = db.lite.ExecContext(ctx, `DELETE FROM samples`)
	if err != nil {
		return fmt.Errorf("hopper: delete samples: %w", err)
	}
	return nil
}

func (db *DB) feedSamplesSQLite(ctx context.Context, q FeedQuery) ([]*Sample, error) {
	where, args := q.whereSQLite()
	query := `SELECT ` + liteSampleCols + ` FROM samples ` + where + //nolint:gosec // built from fixed query fragments and validated sort key.
		` ORDER BY ` + q.sortBy() + ` DESC LIMIT ? OFFSET ?`
	args = append(args, q.Limit, q.Offset)

	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed samples: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) feedSamplesCountSQLite(ctx context.Context, q FeedQuery) (int, error) {
	where, args := q.whereSQLite()
	var n int
	err := db.lite.QueryRowContext(ctx, `SELECT count(*) FROM samples `+where, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("hopper: feed samples count: %w", err)
	}
	return n, nil
}

func (q *FeedQuery) whereSQLite() (where string, args []any) {
	clauses := []string{"source = ?", "cleave_result IS NOT NULL"}
	args = []any{q.Source}

	if q.Label != "" {
		clauses = append(clauses, "label = ?")
		args = append(args, q.Label)
	}

	if len(q.Feeds) > 0 {
		placeholders := make([]string, len(q.Feeds))
		for i := range q.Feeds {
			placeholders[i] = "?"
			args = append(args, q.Feeds[i])
		}
		clauses = append(clauses, "feed IN ("+strings.Join(placeholders, ", ")+")")
	}

	if len(q.Ecosystems) > 0 {
		placeholders := make([]string, len(q.Ecosystems))
		for i := range q.Ecosystems {
			placeholders[i] = "?"
			args = append(args, q.Ecosystems[i])
		}
		clauses = append(clauses, "ecosystem IN ("+strings.Join(placeholders, ", ")+")")
	}

	return "WHERE " + strings.Join(clauses, " AND "), args
}

func (db *DB) feedSourcesSQLite(ctx context.Context, source, label string) ([]string, error) {
	query := `SELECT DISTINCT feed FROM samples WHERE source = ? AND (? = '' OR label = ?) AND feed != '' ORDER BY feed`
	rows, err := db.lite.QueryContext(ctx, query, source, label, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed sources: %w", err)
	}
	return scanLiteStrings(rows)
}

func (db *DB) feedEcosystemsSQLite(ctx context.Context, source, label string) ([]string, error) {
	query := `SELECT DISTINCT ecosystem FROM samples WHERE source = ? AND (? = '' OR label = ?) AND ecosystem != '' ORDER BY ecosystem`
	rows, err := db.lite.QueryContext(ctx, query, source, label, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed ecosystems: %w", err)
	}
	return scanLiteStrings(rows)
}

// Pull-based work scheduling (SQLite).

func (db *DB) claimJobsSQLite(ctx context.Context, worker string, limit int, expiry time.Duration, currentTraits string) ([]ClaimJob, error) {
	// SQLite serializes writers via SetMaxOpenConns(1) on the pool, so
	// concurrent claim requests are safe without row-level locking.
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("hopper: claim jobs begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is best-effort after commit

	cutoff := time.Now().Add(-expiry).UTC().Format(time.RFC3339Nano)

	// Tier 1: unanalyzed samples (highest priority).
	selected, err := queryLiteClaimRows(ctx, tx,
		`SELECT id, sha256, path, size_bytes, file_type FROM samples
		WHERE cleave_result IS NULL AND skip = '' AND parent = ''
		  AND (claimed_by = '' OR claimed_at < ?)
		ORDER BY updated_at ASC, id LIMIT ?`, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: claim jobs: %w", err)
	}

	// Tier 2: stale-traits rescan — only when no unanalyzed samples remain.
	stale := false
	if len(selected) == 0 && currentTraits != "" {
		staleAge := time.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		selected, err = queryLiteClaimRows(ctx, tx,
			`SELECT id, sha256, path, size_bytes, file_type FROM samples
			WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''
			  AND traits_version != ?
			  AND analyzed_at < ?
			  AND (claimed_by = '' OR claimed_at < ?)
			ORDER BY analyzed_at ASC, id LIMIT ?`, currentTraits, staleAge, cutoff, limit)
		if err != nil {
			return nil, fmt.Errorf("hopper: claim stale-traits jobs: %w", err)
		}
		stale = len(selected) > 0
	}

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	var jobs []ClaimJob
	for _, r := range selected {
		if stale {
			// Tier 2: reset analysis state and claim in a single UPDATE.
			if _, err := tx.ExecContext(ctx,
				`UPDATE samples SET claimed_by = ?, claimed_at = ?,
					cleave_result = NULL, litmus_result = NULL,
					litmus_score = 0, traits_version = ''
				WHERE id = ?`,
				worker, ts, r.id); err != nil {
				return nil, fmt.Errorf("hopper: claim stale-traits update: %w", err)
			}
		} else {
			if _, err := tx.ExecContext(ctx,
				`UPDATE samples SET claimed_by = ?, claimed_at = ? WHERE id = ?`,
				worker, ts, r.id); err != nil {
				return nil, fmt.Errorf("hopper: claim jobs update: %w", err)
			}
		}
		jobs = append(jobs, ClaimJob{SHA256: r.sha256, Path: r.path, SizeBytes: r.sizeBytes, FileType: r.fileType})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("hopper: claim jobs commit: %w", err)
	}
	return jobs, nil
}

type liteClaimRow struct {
	sha256    string
	path      string
	fileType  string
	id        int64
	sizeBytes int64
}

func queryLiteClaimRows(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]liteClaimRow, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []liteClaimRow
	for rows.Next() {
		var r liteClaimRow
		if err := rows.Scan(&r.id, &r.sha256, &r.path, &r.sizeBytes, &r.fileType); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) oldestClaimsSQLite(ctx context.Context, maxAge time.Duration) ([]WorkerClaim, error) {
	cutoff := time.Now().Add(-maxAge).UTC().Format(time.RFC3339Nano)
	rows, err := db.lite.QueryContext(ctx, `
		SELECT s.claimed_by, s.path, s.claimed_at
		FROM samples s
		INNER JOIN (
			SELECT claimed_by, MIN(claimed_at) AS min_at
			FROM samples
			WHERE claimed_by != '' AND claimed_at IS NOT NULL AND cleave_result IS NULL
				AND claimed_at >= ?
			GROUP BY claimed_by
		) g ON s.claimed_by = g.claimed_by AND s.claimed_at = g.min_at
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("hopper: oldest claims: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []WorkerClaim
	for rows.Next() {
		var wc WorkerClaim
		var ts string
		if err := rows.Scan(&wc.Worker, &wc.Path, &ts); err != nil {
			return nil, fmt.Errorf("hopper: oldest claims scan: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			wc.ClaimedAt = t
		}
		out = append(out, wc)
	}
	return out, rows.Err()
}

func (db *DB) newestAnalyzedAtSQLite(ctx context.Context) (time.Time, error) {
	var ts sql.NullString
	err := db.lite.QueryRowContext(ctx,
		`SELECT MAX(analyzed_at) FROM samples WHERE analyzed_at IS NOT NULL`,
	).Scan(&ts)
	if err != nil || !ts.Valid {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, ts.String)
	return t, err
}

func (db *DB) unclaimAllSQLite(ctx context.Context) (int64, error) {
	res, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET claimed_by = '', claimed_at = NULL
		 WHERE claimed_by != '' AND cleave_result IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("hopper: unclaim all: %w", err)
	}
	n, _ := res.RowsAffected() //nolint:errcheck // best-effort
	return n, nil
}

func (db *DB) unclaimJobsSQLite(ctx context.Context, shas []string) error {
	if len(shas) == 0 {
		return nil
	}
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("hopper: unclaim begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is best-effort after commit
	for _, sha := range shas {
		if _, err := tx.ExecContext(ctx,
			`UPDATE samples SET claimed_by = '', claimed_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE sha256 = ?`, sha); err != nil {
			return fmt.Errorf("hopper: unclaim: %w", err)
		}
	}
	return tx.Commit()
}

func (db *DB) upsertWorkerSQLite(ctx context.Context, w Worker) error {
	_, err := db.lite.ExecContext(ctx, `
		INSERT INTO workers (name, last_seen, slots, version, traits, analyzed, errors)
		VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?, ?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET
			last_seen = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
			slots = excluded.slots,
			version = excluded.version,
			traits = excluded.traits,
			analyzed = excluded.analyzed,
			errors = excluded.errors`,
		w.Name, w.Slots, w.Version, w.Traits, w.Analyzed, w.Errors)
	if err != nil {
		return fmt.Errorf("hopper: upsert worker: %w", err)
	}
	return nil
}

func (db *DB) activeWorkersSQLite(ctx context.Context, since time.Duration) ([]Worker, error) {
	cutoff := time.Now().Add(-since).UTC().Format(time.RFC3339Nano)
	rows, err := db.lite.QueryContext(ctx,
		`SELECT name, last_seen, slots, version, traits, analyzed, errors
		 FROM workers WHERE last_seen > ? ORDER BY name`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("hopper: active workers: %w", err)
	}
	defer rows.Close() //nolint:errcheck // deferred close is best-effort
	var out []Worker
	for rows.Next() {
		var w Worker
		var lastSeen string
		if err := rows.Scan(&w.Name, &lastSeen, &w.Slots, &w.Version, &w.Traits, &w.Analyzed, &w.Errors); err != nil {
			return nil, fmt.Errorf("hopper: active workers scan: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, lastSeen); err == nil {
			w.LastSeen = t
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func scanLiteStrings(rows *sql.Rows) ([]string, error) {
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanLiteCounts(rows *sql.Rows) (map[string]int, error) {
	counts := make(map[string]int)
	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			return nil, err
		}
		counts[key] = n
	}
	return counts, rows.Err()
}
