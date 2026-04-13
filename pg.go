package hopper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func openPG(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("hopper: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("hopper: ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (db *DB) migratePG(ctx context.Context) error {
	slog.Debug("executing initial schema ddl")
	if _, err := db.pool.Exec(ctx, schemaPG); err != nil {
		return fmt.Errorf("hopper: migrate: %w", err)
	}
	// Add columns introduced after initial schema.
	for _, ddl := range []string{
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS parent TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS skip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS formula TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS elements TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS max_crit INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS suspicious_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_result JSONB`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_score DOUBLE PRECISION NOT NULL DEFAULT 0`,
		`CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_formula ON samples(formula) WHERE formula != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_elements ON samples(elements) WHERE elements != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_score ON samples(score) WHERE score != 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS mtime TIMESTAMPTZ`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS marker_mtime TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source ON samples(source, label, analyzed_at DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_mtime ON samples(source, label, mtime DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed ON samples(feed) WHERE feed != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_ecosystem ON samples(ecosystem) WHERE ecosystem != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_mtime ON samples(mtime) WHERE mtime IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type)`,
		// idx_samples_unanalyzed indexes sha256 but unanalyzedPG orders by id;
		// this index lets that query avoid a sort at 100M rows.
		`CREATE INDEX IF NOT EXISTS idx_samples_unanalyzed_id ON samples(id) WHERE cleave_result IS NULL`,
		// Covers falsePositivesPG / truePositivesPG / falseNegativesPG / benignReviewPG /
		// badReviewPG — all filter (label, score, cleave_result IS NOT NULL, status='', skip='').
		`CREATE INDEX IF NOT EXISTS idx_samples_review ON samples(label, score DESC) WHERE cleave_result IS NOT NULL AND status = '' AND skip = ''`,
		// countAnalyzedPG: SELECT count(*) WHERE litmus_result IS NOT NULL — no index existed.
		`CREATE INDEX IF NOT EXISTS idx_samples_litmus_done ON samples(id) WHERE litmus_result IS NOT NULL`,
		// Pull-based work scheduling: claim tracking columns + index.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS claimed_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_samples_claimable ON samples(id) WHERE cleave_result IS NULL AND claimed_by = ''`,
		// Worker heartbeat table for dashboard.
		`CREATE TABLE IF NOT EXISTS workers (
			name      TEXT PRIMARY KEY,
			last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
			slots     INTEGER NOT NULL DEFAULT 1,
			version   TEXT NOT NULL DEFAULT '',
			traits    TEXT NOT NULL DEFAULT '',
			analyzed  BIGINT NOT NULL DEFAULT 0,
			errors    BIGINT NOT NULL DEFAULT 0
		)`,
	} {
		slog.Debug("executing migration ddl", "ddl", ddl)
		if _, err := db.pool.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate: %w", err)
		}
	}
	return nil
}

const pgSampleCols = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, cleave_result, litmus_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, mtime, marker_mtime`

func pgSampleDest(s *Sample) []any {
	return []any{
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.CleaveResult, &s.LitmusResult, &s.LitmusScore,
		&s.Path, &s.Status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score, &s.MaxCrit, &s.SuspiciousCount, &s.CreatedAt, &s.UpdatedAt, &s.AnalyzedAt, &s.Mtime, &s.MarkerMtime,
	}
}

func scanPGSample(row pgx.Row) (*Sample, error) {
	s := &Sample{}
	err := row.Scan(pgSampleDest(s)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func scanPGSamples(rows pgx.Rows) ([]*Sample, error) {
	defer rows.Close()
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		if err := rows.Scan(pgSampleDest(s)...); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) insertSampleNewPG(ctx context.Context, s *Sample) (bool, error) {
	tag, err := db.pool.Exec(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
			size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count, mtime, marker_mtime)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $1, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (sha256) DO NOTHING`,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.Parent, s.Skip, s.Formula, s.Elements, s.Score, s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime)
	if err != nil {
		return false, fmt.Errorf("hopper: insert sample: %w", err)
	}
	if tag.RowsAffected() == 0 && s.MarkerMtime != nil {
		if _, err := db.pool.Exec(ctx, `UPDATE samples SET marker_mtime = $2 WHERE sha256 = $1`, s.SHA256, s.MarkerMtime); err != nil {
			return false, fmt.Errorf("hopper: refresh marker mtime: %w", err)
		}
	}
	return tag.RowsAffected() > 0, nil
}

var insertBatchStagingCols = []string{
	"sha256", "source", "feed", "ecosystem", "filename", "file_type",
	"size_bytes", "label", "label_source", "path", "status", "canonical_sha256",
	"parent", "skip", "formula", "elements", "score", "max_crit", "suspicious_count", "mtime", "marker_mtime",
}

const insertBatchStagingDDL = `CREATE TEMP TABLE _staging (
	sha256 TEXT, source TEXT, feed TEXT, ecosystem TEXT, filename TEXT,
	file_type TEXT, size_bytes BIGINT, label TEXT, label_source TEXT,
	path TEXT, status TEXT, canonical_sha256 TEXT,
	parent TEXT, skip TEXT, formula TEXT, elements TEXT, score INTEGER, max_crit INTEGER, suspicious_count INTEGER, mtime TIMESTAMPTZ, marker_mtime TIMESTAMPTZ
) ON COMMIT DROP`

const insertBatchStagingInsert = `INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count, mtime, marker_mtime)
SELECT sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count, mtime, marker_mtime
FROM _staging
ON CONFLICT (sha256) DO NOTHING`

func (db *DB) insertSampleBatchPG(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	rows := make([][]any, len(samples))
	for i, s := range samples {
		rows[i] = []any{
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256,
			s.Parent, s.Skip, s.Formula, s.Elements, s.Score, s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
		}
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: begin batch: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	if _, err := tx.Exec(ctx, insertBatchStagingDDL); err != nil {
		return 0, nil, fmt.Errorf("hopper: create staging: %w", err)
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_staging"}, insertBatchStagingCols, pgx.CopyFromRows(rows)); err != nil {
		return 0, nil, fmt.Errorf("hopper: copy to staging: %w", err)
	}

	tag, err := tx.Exec(ctx, insertBatchStagingInsert)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: insert from staging: %w", err)
	}
	inserted = tag.RowsAffected()

	if _, err := tx.Exec(ctx, `
		UPDATE samples s
		SET marker_mtime = st.marker_mtime
		FROM _staging st
		WHERE s.sha256 = st.sha256
			AND st.marker_mtime IS NOT NULL`); err != nil {
		return 0, nil, fmt.Errorf("hopper: refresh marker mtime: %w", err)
	}

	// Find SHAs that lack analysis results (including ones we just skipped).
	query := `SELECT s.sha256 FROM samples s
		JOIN _staging st ON s.sha256 = st.sha256
		WHERE s.litmus_result IS NULL`
	queryRows, err := tx.Query(ctx, query)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: query needs analysis: %w", err)
	}
	defer queryRows.Close()

	for queryRows.Next() {
		var sha string
		if err := queryRows.Scan(&sha); err != nil {
			return 0, nil, fmt.Errorf("hopper: scan needs analysis: %w", err)
		}
		needsAnalysis = append(needsAnalysis, sha)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, nil, fmt.Errorf("hopper: commit batch: %w", err)
	}

	return inserted, needsAnalysis, nil
}

func (db *DB) sampleBySHA256PG(ctx context.Context, sha256 string) (*Sample, error) {
	s, err := scanPGSample(db.pool.QueryRow(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE sha256 = $1`, sha256))
	if err != nil {
		return nil, fmt.Errorf("hopper: sample %s: %w", sha256, err)
	}
	return s, nil
}

func (db *DB) updateCleaveResultPG(ctx context.Context, sha256 string, result []byte, canonical string, fi cleaveFileInfo) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET cleave_result = $2,
			canonical_sha256 = $3, formula = $4, elements = $5, score = $6, max_crit = $7, suspicious_count = $8,
			file_type = COALESCE(NULLIF($9, ''), file_type),
			litmus_result = NULL, litmus_score = 0,
			analyzed_at = now(), updated_at = now()
		WHERE sha256 = $1`, sha256, sanitizeJSONB(result), canonical, fi.Formula, fi.Elements, fi.Score, fi.MaxCrit, fi.SuspiciousCount, fi.FileType)
	if err != nil {
		return fmt.Errorf("hopper: update cleave result: %w", err)
	}
	return nil
}

func (db *DB) updateLitmusResultPG(ctx context.Context, sha256 string, result []byte, score float64) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET litmus_result = $2, litmus_score = $3, updated_at = now()
		WHERE sha256 = $1`, sha256, sanitizeJSONB(result), score)
	if err != nil {
		return fmt.Errorf("hopper: update litmus result: %w", err)
	}
	return nil
}

func (db *DB) reclassifyPG(ctx context.Context, sha256, label, source string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET label = $2, label_source = $3, updated_at = now() WHERE sha256 = $1`,
		sha256, label, source)
	if err != nil {
		return fmt.Errorf("hopper: reclassify: %w", err)
	}
	return nil
}

func (db *DB) unanalyzedPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE cleave_result IS NULL ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: unanalyzed: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) samplesByLabelPG(ctx context.Context, label string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE label = $1 ORDER BY id LIMIT $2`, label, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by label: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) countByLabelPG(ctx context.Context) (map[string]int, error) {
	rows, err := db.pool.Query(ctx, `SELECT label, count(*) FROM samples GROUP BY label`)
	if err != nil {
		return nil, fmt.Errorf("hopper: count by label: %w", err)
	}
	defer rows.Close()
	return scanPGCounts(rows)
}

func (db *DB) setNotePG(ctx context.Context, sha256, note string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET note = $2, updated_at = now() WHERE sha256 = $1`,
		sha256, note)
	if err != nil {
		return fmt.Errorf("hopper: set note: %w", err)
	}
	return nil
}

func (db *DB) setStatusPG(ctx context.Context, sha256, status string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET status = $2, note = '', updated_at = now() WHERE sha256 = $1`,
		sha256, status)
	if err != nil {
		return fmt.Errorf("hopper: set status: %w", err)
	}
	return nil
}

func (db *DB) samplesByStatusPG(ctx context.Context, status string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE status = $1 ORDER BY updated_at ASC LIMIT $2`,
		status, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by status: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falsePositivesPG(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND score >= $1 AND status = '' AND skip = ''
		 ORDER BY score DESC LIMIT $2`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false positives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) truePositivesPG(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND score >= $1 AND status = '' AND skip = ''
		 ORDER BY score DESC LIMIT $2`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: true positives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falseNegativesPG(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND score <= $1 AND status = '' AND skip = ''
		 ORDER BY score ASC LIMIT $2`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) benignReviewPG(ctx context.Context, _, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'good' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL AND status = ''
			AND (max_crit >= 5 OR suspicious_count >= 2)
		 ORDER BY max_crit DESC, suspicious_count DESC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: benign review: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) badReviewPG(ctx context.Context, _, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'bad' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL AND status = ''
			AND max_crit < 5 AND suspicious_count <= 1
		 ORDER BY suspicious_count ASC, max_crit ASC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: bad review: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) countByStatusPG(ctx context.Context) (map[string]int, error) {
	rows, err := db.pool.Query(ctx, `SELECT status, count(*) FROM samples WHERE status != '' GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("hopper: count by status: %w", err)
	}
	defer rows.Close()
	return scanPGCounts(rows)
}

func (db *DB) countAnalyzedPG(ctx context.Context) (int64, error) {
	var n int64
	err := db.pool.QueryRow(ctx, "SELECT count(*) FROM samples WHERE litmus_result IS NOT NULL").Scan(&n)
	return n, err
}

func (db *DB) updateSamplePG(ctx context.Context, sha256, status string, result []byte, canonical string, fi cleaveFileInfo) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET status = $2, cleave_result = $3,
			canonical_sha256 = $4, formula = $5, elements = $6, score = $7, max_crit = $8, suspicious_count = $9,
			file_type = COALESCE(NULLIF($10, ''), file_type),
			litmus_result = NULL, litmus_score = 0,
			analyzed_at = now(), updated_at = now()
		WHERE sha256 = $1`, sha256, status, sanitizeJSONB(result), canonical, fi.Formula, fi.Elements, fi.Score, fi.MaxCrit, fi.SuspiciousCount, fi.FileType)
	if err != nil {
		return fmt.Errorf("hopper: update sample: %w", err)
	}
	return nil
}

func (db *DB) samplesByStatusInPathsPG(ctx context.Context, status string, prefixes []string, limit int) ([]*Sample, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	patterns := make([]string, len(prefixes))
	for i, p := range prefixes {
		patterns[i] = p + "/%"
	}
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE status = $1 AND path LIKE ANY($2) ORDER BY updated_at ASC LIMIT $3`,
		status, patterns, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by status in paths: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falsePositivesInPathsPG(ctx context.Context, prefixes []string, scoreFloor, limit int) ([]*Sample, error) {
	return db.seedCandidatesInPathsPG(ctx, prefixes, "good", ">=", scoreFloor, limit)
}

func (db *DB) falseNegativesInPathsPG(ctx context.Context, prefixes []string, scoreCeiling, limit int) ([]*Sample, error) {
	return db.seedCandidatesInPathsPG(ctx, prefixes, "bad", "<=", scoreCeiling, limit)
}

func (db *DB) seedCandidatesInPathsPG(ctx context.Context, prefixes []string, label, op string, score, limit int) ([]*Sample, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	patterns := make([]string, len(prefixes))
	for i, p := range prefixes {
		patterns[i] = p + "/%"
	}
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE status = '' AND label = $1 AND skip = '' AND score `+op+` $2
		   AND cleave_result IS NOT NULL
		   AND path LIKE ANY($3)
		 ORDER BY updated_at ASC LIMIT $4`,
		label, score, patterns, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: seed candidates in paths: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) countByStatusInPathsPG(ctx context.Context, prefixes []string) (map[string]int, error) {
	var rows pgx.Rows
	var err error
	if len(prefixes) == 0 {
		rows, err = db.pool.Query(ctx, `SELECT status, count(*) FROM samples WHERE status != '' GROUP BY status`)
	} else {
		patterns := make([]string, len(prefixes))
		for i, p := range prefixes {
			patterns[i] = p + "/%"
		}
		rows, err = db.pool.Query(ctx,
			`SELECT status, count(*) FROM samples WHERE status != '' AND path LIKE ANY($1) GROUP BY status`,
			patterns)
	}
	if err != nil {
		return nil, fmt.Errorf("hopper: count by status in paths: %w", err)
	}
	defer rows.Close()
	return scanPGCounts(rows)
}

func (db *DB) agesByPathsPG(ctx context.Context, prefixes []string, limit int) (map[string]time.Time, error) {
	if len(prefixes) == 0 {
		return make(map[string]time.Time), nil
	}
	patterns := make([]string, len(prefixes))
	for i, p := range prefixes {
		patterns[i] = p + "/%"
	}
	rows, err := db.pool.Query(ctx,
		`SELECT path, updated_at FROM samples WHERE path LIKE ANY($1) ORDER BY updated_at ASC LIMIT $2`, patterns, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: ages by paths: %w", err)
	}
	defer rows.Close()
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

func (db *DB) staleSamplesPG(ctx context.Context, prefixes []string, olderThan time.Time, limit int) ([]*Sample, error) {
	if len(prefixes) == 0 {
		rows, err := db.pool.Query(ctx,
			`SELECT `+pgSampleCols+` FROM samples WHERE updated_at < $1 ORDER BY updated_at ASC LIMIT $2`,
			olderThan, limit)
		if err != nil {
			return nil, fmt.Errorf("hopper: stale samples: %w", err)
		}
		return scanPGSamples(rows)
	}
	patterns := make([]string, len(prefixes))
	for i, p := range prefixes {
		patterns[i] = p + "/%"
	}
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE updated_at < $1 AND path LIKE ANY($2) ORDER BY updated_at ASC LIMIT $3`,
		olderThan, patterns, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: stale samples: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) insertReportPG(ctx context.Context, r *Report) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO reports (sha256, report_type, content, provider, duration_ms)
		VALUES ($1, $2, $3, $4, $5)`,
		r.SHA256, r.Type, r.Content, r.Provider, r.DurationMS)
	if err != nil {
		return fmt.Errorf("hopper: insert report: %w", err)
	}
	return nil
}

func (db *DB) reportsBySHA256PG(ctx context.Context, sha256 string) ([]*Report, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE sha256 = $1 ORDER BY created_at DESC`, sha256)
	if err != nil {
		return nil, fmt.Errorf("hopper: reports for %s: %w", sha256, err)
	}
	defer rows.Close()
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

func (db *DB) latestReportPG(ctx context.Context, sha256, reportType string) (*Report, error) {
	r := &Report{}
	err := db.pool.QueryRow(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE sha256 = $1 AND report_type = $2
		ORDER BY created_at DESC LIMIT 1`, sha256, reportType).Scan(
		&r.ID, &r.SHA256, &r.Type, &r.Content, &r.Provider, &r.DurationMS, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("hopper: latest report: %w", err)
	}
	return r, nil
}

// samplesByEmbeddedSHA256PG uses JSON_TABLE (PG17+) to find samples whose
// cleave_result contains an embedded file matching the given SHA256.
func (db *DB) samplesByEmbeddedSHA256PG(ctx context.Context, sha256 string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT `+pgSampleCols+`
		FROM samples,
			JSON_TABLE(cleave_result, '$.files[*]' COLUMNS (
				file_sha256 TEXT PATH '$.sha256'
			)) AS jt
		WHERE jt.file_sha256 = $1
		ORDER BY id
		LIMIT $2`, sha256, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by embedded sha256: %w", err)
	}
	return scanPGSamples(rows)
}

// recomputeCanonicalSHA256PG uses JSON_TABLE (PG17+) to backfill
// canonical_sha256 in SQL without fetching blobs into Go. Returns the
// number of rows updated.
func (db *DB) recomputeCanonicalSHA256PG(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples SET canonical_sha256 = computed.canonical, updated_at = now()
		FROM (
			SELECT s.sha256,
				LEAST(s.sha256, MIN(jt.file_sha256)) AS canonical
			FROM samples s,
				JSON_TABLE(s.cleave_result, '$.files[*]' COLUMNS (
					file_sha256 TEXT PATH '$.sha256'
				)) AS jt
			WHERE length(jt.file_sha256) = 64
			GROUP BY s.sha256
		) AS computed
		WHERE samples.sha256 = computed.sha256
			AND samples.canonical_sha256 IS DISTINCT FROM computed.canonical`)
	if err != nil {
		return 0, fmt.Errorf("hopper: recompute canonical sha256: %w", err)
	}
	return tag.RowsAffected(), nil
}

// backfillPG re-derives parseCleaveFile / parseLitmusProb columns entirely
// in SQL using JSON_TABLE (PG17+), avoiding the cost of streaming JSONB
// blobs into Go.
//
// Only rows whose file_type column is empty are touched. file_type is the
// most recently added column populated by writes, so an empty value is a
// reliable signal that the row pre-dates the unified backfill path and may
// be missing other derivable columns too. Rows backfilled previously are
// skipped cheaply by an index lookup, so this is safe to run repeatedly.
func (db *DB) backfillPG(ctx context.Context) (BackfillStats, error) {
	var stats BackfillStats

	// Candidate rows: have analysis output and file_type was never set.
	// Used for the Scanned stat only — passes 1 and 2 are index-gated on
	// file_type='' so they're effectively no-ops once the cohort is empty,
	// and pass 3 (marker reset) runs unconditionally.
	if err := db.pool.QueryRow(ctx, `
		SELECT count(*) FROM samples
		WHERE file_type = ''
			AND (cleave_result IS NOT NULL OR litmus_result IS NOT NULL)`).Scan(&stats.Scanned); err != nil {
		return stats, fmt.Errorf("hopper: backfill count: %w", err)
	}

	// Pass 1: formula / elements / score / file_type / max_crit from cleave_result.
	// JSON_TABLE filters to the depth-0 entry; rows without one are skipped.
	// elements = formula with Unicode subscripts ₀..₉ stripped.
	// max_crit is the max trait level on the depth-0 entry, computed via a
	// nested SELECT over the traits array.
	cleaveTag, err := db.pool.Exec(ctx, `
		UPDATE samples s SET
			formula = COALESCE(j.f, ''),
			elements = translate(COALESCE(j.f, ''), '₀₁₂₃₄₅₆₇₈₉', ''),
			score = COALESCE(j.x, 0),
			max_crit = COALESCE(j.mc, 0),
			suspicious_count = COALESCE(j.sc, 0),
			file_type = COALESCE(NULLIF(j.t, ''), s.file_type),
			updated_at = now()
		FROM (
			SELECT s2.sha256, jt.f, jt.x, jt.t,
				(SELECT COALESCE(MAX((tr->>'l')::int), 0)
				 FROM jsonb_array_elements(COALESCE(jt.ts, '[]'::jsonb)) AS tr) AS mc,
				(SELECT COUNT(*)
				 FROM jsonb_array_elements(COALESCE(jt.ts, '[]'::jsonb)) AS tr
				 WHERE (tr->>'l')::int >= 4
				   AND COALESCE((tr->>'c')::double precision, 1.0) >= 0.65) AS sc
			FROM samples s2,
				JSON_TABLE(s2.cleave_result, '$.fs[*] ? (@.dp == 0)' COLUMNS (
					f TEXT PATH '$.f',
					x INTEGER PATH '$.x',
					t TEXT PATH '$.type',
					ts JSONB PATH '$.ts'
				)) AS jt
			WHERE s2.file_type = ''
				AND s2.cleave_result IS NOT NULL
		) AS j
		WHERE s.sha256 = j.sha256
			AND s.file_type = ''`)
	if err != nil {
		return stats, fmt.Errorf("hopper: backfill cleave columns: %w", err)
	}
	stats.Updated += cleaveTag.RowsAffected()

	// Pass 2: litmus_score from litmus_result.prob, scoped to the same
	// "stale" set so we don't pay JSON parsing on already-backfilled rows.
	litmusTag, err := db.pool.Exec(ctx, `
		UPDATE samples SET
			litmus_score = COALESCE((litmus_result->>'prob')::double precision, 0),
			updated_at = now()
		WHERE file_type = ''
			AND litmus_result IS NOT NULL
			AND litmus_score IS DISTINCT FROM COALESCE((litmus_result->>'prob')::double precision, 0)`)
	if err != nil {
		return stats, fmt.Errorf("hopper: backfill litmus_score: %w", err)
	}
	stats.Updated += litmusTag.RowsAffected()

	// Pass 3: clear stale skip='misclassified' markers whose underlying
	// trait counts no longer disagree with the marker. The old score-based
	// rule was noisy on large tarballs and parked many rows here that the
	// new max_crit/suspicious_count rule would never have flagged.
	//
	// good marker stays misclassified only while it still looks bad
	// (max_crit >= 5 OR suspicious_count >= 2). Otherwise reset.
	goodTag, err := db.pool.Exec(ctx, `
		UPDATE samples SET skip = '', updated_at = now()
		WHERE label = 'good' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL
			AND max_crit < 5 AND suspicious_count <= 1`)
	if err != nil {
		return stats, fmt.Errorf("hopper: backfill reset benign markers: %w", err)
	}
	stats.MarkersCleared += goodTag.RowsAffected()

	// bad marker stays misclassified only while it still looks benign
	// (max_crit < 5 AND suspicious_count <= 1). Otherwise reset.
	badTag, err := db.pool.Exec(ctx, `
		UPDATE samples SET skip = '', updated_at = now()
		WHERE label = 'bad' AND label_source = 'marker' AND skip = 'misclassified'
			AND cleave_result IS NOT NULL
			AND (max_crit >= 5 OR suspicious_count >= 2)`)
	if err != nil {
		return stats, fmt.Errorf("hopper: backfill reset bad markers: %w", err)
	}
	stats.MarkersCleared += badTag.RowsAffected()

	return stats, nil
}

func (db *DB) setSkipPG(ctx context.Context, sha256, skip string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET skip = $2, updated_at = now() WHERE sha256 = $1`,
		sha256, skip)
	if err != nil {
		return fmt.Errorf("hopper: set skip: %w", err)
	}
	return nil
}

func (db *DB) deleteSamplePG(ctx context.Context, sha256 string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("hopper: begin delete: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	if _, err := tx.Exec(ctx, `DELETE FROM reports WHERE sha256 = $1`, sha256); err != nil {
		return fmt.Errorf("hopper: delete sample reports: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM samples WHERE sha256 = $1`, sha256); err != nil {
		return fmt.Errorf("hopper: delete sample: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("hopper: commit delete: %w", err)
	}
	return nil
}

func (db *DB) purgeUnsupportedPG(ctx context.Context, dryRun bool) (int64, error) {
	if dryRun {
		var n int64
		err := db.pool.QueryRow(ctx, `
			SELECT count(*) FROM samples
			WHERE cleave_result IS NOT NULL AND file_type = ''`).Scan(&n)
		if err != nil {
			return 0, fmt.Errorf("hopper: count unsupported: %w", err)
		}
		return n, nil
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin purge: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	// Remove dependent reports first so foreign-key relationships (if any) stay clean.
	if _, err := tx.Exec(ctx, `
		DELETE FROM reports WHERE sha256 IN (
			SELECT sha256 FROM samples
			WHERE cleave_result IS NOT NULL AND file_type = ''
		)`); err != nil {
		return 0, fmt.Errorf("hopper: purge unsupported reports: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM samples
		WHERE cleave_result IS NOT NULL AND file_type = ''`)
	if err != nil {
		return 0, fmt.Errorf("hopper: purge unsupported: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("hopper: commit purge: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (db *DB) deleteAllPG(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, `TRUNCATE reports, samples`)
	if err != nil {
		return fmt.Errorf("hopper: delete all: %w", err)
	}
	return nil
}

func (db *DB) feedSamplesPG(ctx context.Context, q FeedQuery) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT `+pgSampleCols+` FROM samples
		WHERE source = $1
			AND ($2 = '' OR label = $2)
			AND cleave_result IS NOT NULL
			AND (cardinality($3::text[]) = 0 OR feed = ANY($3))
			AND (cardinality($4::text[]) = 0 OR ecosystem = ANY($4))
		ORDER BY `+q.sortBy()+` DESC NULLS LAST
		LIMIT $5 OFFSET $6`,
		q.Source, q.Label, q.Feeds, q.Ecosystems, q.Limit, q.Offset)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed samples: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) feedSamplesCountPG(ctx context.Context, q FeedQuery) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx, `
		SELECT count(*) FROM samples
		WHERE source = $1
			AND ($2 = '' OR label = $2)
			AND cleave_result IS NOT NULL
			AND (cardinality($3::text[]) = 0 OR feed = ANY($3))
			AND (cardinality($4::text[]) = 0 OR ecosystem = ANY($4))`,
		q.Source, q.Label, q.Feeds, q.Ecosystems).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("hopper: feed samples count: %w", err)
	}
	return n, nil
}

func (db *DB) feedSourcesPG(ctx context.Context, source, label string) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT feed FROM samples
		WHERE source = $1 AND ($2 = '' OR label = $2) AND feed != ''
		ORDER BY feed`, source, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed sources: %w", err)
	}
	return scanPGStrings(rows)
}

func (db *DB) feedEcosystemsPG(ctx context.Context, source, label string) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT ecosystem FROM samples
		WHERE source = $1 AND ($2 = '' OR label = $2) AND ecosystem != ''
		ORDER BY ecosystem`, source, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed ecosystems: %w", err)
	}
	return scanPGStrings(rows)
}

func scanPGStrings(rows pgx.Rows) ([]string, error) {
	defer rows.Close()
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

func scanPGCounts(rows pgx.Rows) (map[string]int, error) {
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

// Pull-based work scheduling (PostgreSQL).

func (db *DB) claimJobsPG(ctx context.Context, worker string, limit int, expiry time.Duration) ([]ClaimJob, error) {
	rows, err := db.pool.Query(ctx, `
		WITH claimable AS (
			SELECT id FROM samples
			WHERE cleave_result IS NULL
			  AND (claimed_by = '' OR claimed_at < now() - $2::interval)
			ORDER BY mtime DESC NULLS LAST, id
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE samples SET claimed_by = $1, claimed_at = now()
		FROM claimable WHERE samples.id = claimable.id
		RETURNING samples.sha256, samples.path, samples.size_bytes`,
		worker, expiry, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: claim jobs: %w", err)
	}
	defer rows.Close()
	var jobs []ClaimJob
	for rows.Next() {
		var j ClaimJob
		if err := rows.Scan(&j.SHA256, &j.Path, &j.SizeBytes); err != nil {
			return nil, fmt.Errorf("hopper: claim jobs scan: %w", err)
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (db *DB) unclaimJobsPG(ctx context.Context, shas []string) error {
	if len(shas) == 0 {
		return nil
	}
	_, err := db.pool.Exec(ctx,
		`UPDATE samples SET claimed_by = '', claimed_at = NULL WHERE sha256 = ANY($1)`, shas)
	if err != nil {
		return fmt.Errorf("hopper: unclaim jobs: %w", err)
	}
	return nil
}

func (db *DB) upsertWorkerPG(ctx context.Context, w Worker) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO workers (name, last_seen, slots, version, traits, analyzed, errors)
		VALUES ($1, now(), $2, $3, $4, $5, $6)
		ON CONFLICT (name) DO UPDATE SET
			last_seen = now(),
			slots = EXCLUDED.slots,
			version = EXCLUDED.version,
			traits = EXCLUDED.traits,
			analyzed = EXCLUDED.analyzed,
			errors = EXCLUDED.errors`,
		w.Name, w.Slots, w.Version, w.Traits, w.Analyzed, w.Errors)
	if err != nil {
		return fmt.Errorf("hopper: upsert worker: %w", err)
	}
	return nil
}

func (db *DB) activeWorkersPG(ctx context.Context, since time.Duration) ([]Worker, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT name, last_seen, slots, version, traits, analyzed, errors
		 FROM workers WHERE last_seen > now() - $1::interval ORDER BY name`, since)
	if err != nil {
		return nil, fmt.Errorf("hopper: active workers: %w", err)
	}
	defer rows.Close()
	var out []Worker
	for rows.Next() {
		var w Worker
		if err := rows.Scan(&w.Name, &w.LastSeen, &w.Slots, &w.Version, &w.Traits, &w.Analyzed, &w.Errors); err != nil {
			return nil, fmt.Errorf("hopper: active workers scan: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
