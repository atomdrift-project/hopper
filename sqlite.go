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
		fmt.Sprintf("SELECT count(*) FROM pragma_table_info('samples') WHERE name = '%s'", column),
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

	return nil
}

const liteSampleCols = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, cleave_result, litmus_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, created_at, updated_at, analyzed_at, mtime, marker_mtime`

func scanLiteSample(row *sql.Row) (*Sample, error) {
	s := &Sample{}
	var cleaveResult, litmusResult, status sql.NullString
	var analyzedAt, mtime, markerMtime sql.NullTime
	err := row.Scan(
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult, &s.LitmusScore,
		&s.Path, &status, &s.Note, &s.CanonicalSHA256, &s.Parent, &s.Skip, &s.Formula,
		&s.Elements, &s.Score, &s.CreatedAt, &s.UpdatedAt, &analyzedAt, &mtime, &markerMtime,
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
			&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score, &s.CreatedAt, &s.UpdatedAt, &analyzedAt, &mtime, &markerMtime,
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
			size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score, mtime, marker_mtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256) DO NOTHING`,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256, s.Parent, s.Skip, s.Formula, s.Elements, s.Score, s.Mtime, s.MarkerMtime)
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
	defer tx.Rollback() //nolint:errcheck // commit or rollback

	cols := []string{
		"sha256", "source", "feed", "ecosystem", "filename", "file_type",
		"size_bytes", "label", "label_source", "path", "status", "canonical_sha256",
		"parent", "skip", "formula", "elements", "score", "mtime", "marker_mtime",
	}
	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = "?"
	}

	query := fmt.Sprintf( //nolint:gosec // column list and placeholders are derived from fixed local constants.
		`
		INSERT INTO samples (%s)
		VALUES (%s)
		ON CONFLICT (sha256) DO NOTHING`,
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
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256, s.Parent, s.Skip, s.Formula, s.Elements, s.Score, s.Mtime, s.MarkerMtime)
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

func (db *DB) updateCleaveResultSQLite(ctx context.Context, sha256 string, result []byte, canonical string, fi cleaveFileInfo) error {
	n := now()
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET cleave_result = ?,
			canonical_sha256 = ?, formula = ?, elements = ?, score = ?,
			litmus_result = NULL, litmus_score = 0,
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`, string(result), canonical, fi.Formula, fi.Elements, fi.Score, n, n, sha256)
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

func (db *DB) falsePositivesSQLite(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND score >= ? AND status = '' AND skip = ''
		 ORDER BY score DESC LIMIT ?`,
		scoreThreshold, limit)
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

func (db *DB) falseNegativesSQLite(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND score <= ? AND status = '' AND skip = ''
		 ORDER BY score ASC LIMIT ?`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) benignReviewSQLite(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL AND score >= ? AND status = ''
		 ORDER BY score DESC LIMIT ?`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: benign review: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) badReviewSQLite(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL AND score <= ? AND status = ''
		 ORDER BY score ASC LIMIT ?`,
		scoreThreshold, limit)
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
			canonical_sha256 = ?, formula = ?, elements = ?, score = ?,
			litmus_result = NULL, litmus_score = 0,
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`, status, string(result), canonical, fi.Formula, fi.Elements, fi.Score, n, n, sha256)
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

func (db *DB) falsePositivesInPathsSQLite(ctx context.Context, prefixes []string, scoreFloor, limit int) ([]*Sample, error) {
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "good", ">=", scoreFloor, limit)
}

func (db *DB) falseNegativesInPathsSQLite(ctx context.Context, prefixes []string, scoreCeiling, limit int) ([]*Sample, error) {
	return db.seedCandidatesInPathsSQLite(ctx, prefixes, "bad", "<=", scoreCeiling, limit)
}

func (db *DB) seedCandidatesInPathsSQLite(ctx context.Context, prefixes []string, label, op string, score, limit int) ([]*Sample, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	var clauses []string
	args := []any{label, score}
	for _, p := range prefixes {
		clauses = append(clauses, "path GLOB ?")
		args = append(args, p+"/*")
	}
	args = append(args, limit)
	//nolint:gosec // query structure is built from constants, values are parameterized
	query := `SELECT ` + liteSampleCols + ` FROM samples WHERE status = '' AND label = ? AND skip = '' AND score ` + op + ` ? AND (` +
		strings.Join(clauses, " OR ") + `) ORDER BY updated_at ASC LIMIT ?`
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
		WHERE cleave_result IS NOT NULL`, now())
	if err != nil {
		return 0, fmt.Errorf("hopper: recompute canonical sha256: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("hopper: rows affected recompute canonical sha256: %w", err)
	}
	return n, nil
}

func (db *DB) setSkipSQLite(ctx context.Context, sha256, skip string) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = ?, updated_at = ? WHERE sha256 = ?`,
		skip, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: set skip: %w", err)
	}
	return nil
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
