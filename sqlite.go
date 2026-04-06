package hopper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
		lite.Close() //nolint:errcheck,gosec // best-effort cleanup on failed ping
		return nil, fmt.Errorf("hopper: ping sqlite: %w", err)
	}
	return &DB{lite: lite}, nil
}

func (db *DB) migrateSQLite(ctx context.Context) error {
	if _, err := db.lite.ExecContext(ctx, schemaSQLite); err != nil {
		return fmt.Errorf("hopper: migrate sqlite: %w", err)
	}

	// Add columns introduced after initial schema. SQLite lacks
	// ALTER TABLE ... IF NOT EXISTS, so check column existence via PRAGMA.
	var hasParent int
	//nolint:errcheck,gosec // best-effort column check; 0 on error triggers migration
	db.lite.QueryRowContext(ctx,
		"SELECT count(*) FROM pragma_table_info('samples') WHERE name = 'parent'",
	).Scan(&hasParent)
	if hasParent == 0 {
		for _, ddl := range []string{
			`ALTER TABLE samples ADD COLUMN parent TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE samples ADD COLUMN skip TEXT NOT NULL DEFAULT ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != ''`,
		} {
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	var hasFormula int
	//nolint:errcheck,gosec // best-effort column check
	db.lite.QueryRowContext(ctx,
		"SELECT count(*) FROM pragma_table_info('samples') WHERE name = 'formula'",
	).Scan(&hasFormula)
	if hasFormula == 0 {
		for _, ddl := range []string{
			`ALTER TABLE samples ADD COLUMN formula TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE samples ADD COLUMN elements TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE samples ADD COLUMN score INTEGER NOT NULL DEFAULT 0`,
			`CREATE INDEX IF NOT EXISTS idx_samples_formula ON samples(formula) WHERE formula != ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_elements ON samples(elements) WHERE elements != ''`,
			`CREATE INDEX IF NOT EXISTS idx_samples_score ON samples(score) WHERE score != 0`,
		} {
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	// Add litmus_result column.
	var hasLitmusResult int
	//nolint:errcheck,gosec // best-effort column check
	db.lite.QueryRowContext(ctx,
		"SELECT count(*) FROM pragma_table_info('samples') WHERE name = 'litmus_result'",
	).Scan(&hasLitmusResult)
	if hasLitmusResult == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN litmus_result TEXT`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	return nil
}

const liteSampleCols = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, cleave_result, litmus_result,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, created_at, updated_at, analyzed_at`

func scanLiteSample(row *sql.Row) (*Sample, error) {
	s := &Sample{}
	var cleaveResult, litmusResult, status sql.NullString
	var analyzedAt sql.NullTime
	err := row.Scan(&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult,
		&s.Path, &status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score, &s.CreatedAt, &s.UpdatedAt, &analyzedAt)
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
	return s, nil
}

func scanLiteSamples(rows *sql.Rows) ([]*Sample, error) {
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		var cleaveResult, litmusResult, status sql.NullString
		var analyzedAt sql.NullTime
		if err := rows.Scan(&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
			&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult,
			&s.Path, &status, &s.Note, &s.CanonicalSHA256,
			&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score, &s.CreatedAt, &s.UpdatedAt, &analyzedAt); err != nil {
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
		out = append(out, s)
	}
	return out, rows.Err()
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (db *DB) insertSampleNewSQLite(ctx context.Context, s *Sample) (bool, error) {
	res, err := db.lite.ExecContext(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
			size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256) DO NOTHING`,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256, s.Parent, s.Skip, s.Formula, s.Elements, s.Score)
	if err != nil {
		return false, fmt.Errorf("hopper: insert sample: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("hopper: rows affected: %w", err)
	}
	return n > 0, nil
}

func (db *DB) insertSampleBatchSQLite(ctx context.Context, samples []*Sample) (int64, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin batch: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
			size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, score)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256) DO NOTHING`)
	if err != nil {
		tx.Rollback() //nolint:errcheck,gosec // best-effort rollback on prepare error
		return 0, fmt.Errorf("hopper: prepare batch: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // best-effort cleanup

	var inserted int64
	for _, s := range samples {
		res, err := stmt.ExecContext(ctx,
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256, s.Parent, s.Skip, s.Formula, s.Score)
		if err != nil {
			tx.Rollback() //nolint:errcheck,gosec // best-effort rollback on insert error
			return inserted, fmt.Errorf("hopper: batch insert %s: %w", s.SHA256, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			inserted += n
		}
	}

	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("hopper: commit batch: %w", err)
	}
	return inserted, nil
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
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`, string(result), canonical, fi.Formula, fi.Elements, fi.Score, n, n, sha256)
	if err != nil {
		return fmt.Errorf("hopper: update cleave result: %w", err)
	}
	return nil
}

func (db *DB) updateLitmusResultSQLite(ctx context.Context, sha256 string, result []byte) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET litmus_result = ?, updated_at = ?
		WHERE sha256 = ?`, string(result), now(), sha256)
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

func (db *DB) countByStatusSQLite(ctx context.Context) (map[string]int, error) {
	rows, err := db.lite.QueryContext(ctx, `SELECT status, count(*) FROM samples WHERE status != '' GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("hopper: count by status: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	return scanLiteCounts(rows)
}

func (db *DB) updateSampleSQLite(ctx context.Context, sha256, status string, result []byte, canonical string, fi cleaveFileInfo) error {
	n := now()
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET status = ?, cleave_result = ?,
			canonical_sha256 = ?, formula = ?, elements = ?, score = ?,
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
	return nil, errors.New("hopper: FeedSamples not implemented for SQLite")
}

func (db *DB) feedSamplesCountSQLite(ctx context.Context, q FeedQuery) (int, error) {
	return 0, errors.New("hopper: FeedSamplesCount not implemented for SQLite")
}

func (db *DB) feedSourcesSQLite(ctx context.Context, source, label string) ([]string, error) {
	return nil, errors.New("hopper: FeedSources not implemented for SQLite")
}

func (db *DB) feedEcosystemsSQLite(ctx context.Context, source, label string) ([]string, error) {
	return nil, errors.New("hopper: FeedEcosystems not implemented for SQLite")
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
