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
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_result JSONB`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_score DOUBLE PRECISION NOT NULL DEFAULT 0`,
		`CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_formula ON samples(formula) WHERE formula != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_elements ON samples(elements) WHERE elements != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_score ON samples(score) WHERE score != 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS mtime TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source ON samples(source, label, analyzed_at DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_mtime ON samples(source, label, mtime DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed ON samples(feed) WHERE feed != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_ecosystem ON samples(ecosystem) WHERE ecosystem != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_mtime ON samples(mtime) WHERE mtime IS NOT NULL`,
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
	path, status, note, canonical_sha256, parent, skip, formula, elements, score,
	created_at, updated_at, analyzed_at, mtime`

func pgSampleDest(s *Sample) []any {
	return []any{
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.CleaveResult, &s.LitmusResult, &s.LitmusScore,
		&s.Path, &s.Status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score, &s.CreatedAt, &s.UpdatedAt, &s.AnalyzedAt, &s.Mtime,
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
			size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score, mtime)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $1, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (sha256) DO NOTHING`,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.Parent, s.Skip, s.Formula, s.Elements, s.Score, s.Mtime)
	if err != nil {
		return false, fmt.Errorf("hopper: insert sample: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

var insertBatchStagingCols = []string{
	"sha256", "source", "feed", "ecosystem", "filename", "file_type",
	"size_bytes", "label", "label_source", "path", "status", "canonical_sha256",
	"parent", "skip", "formula", "elements", "score", "mtime",
}

const insertBatchStagingDDL = `CREATE TEMP TABLE _staging (
	sha256 TEXT, source TEXT, feed TEXT, ecosystem TEXT, filename TEXT,
	file_type TEXT, size_bytes BIGINT, label TEXT, label_source TEXT,
	path TEXT, status TEXT, canonical_sha256 TEXT,
	parent TEXT, skip TEXT, formula TEXT, elements TEXT, score INTEGER, mtime TIMESTAMPTZ
) ON COMMIT DROP`

const insertBatchStagingInsert = `INSERT INTO samples (sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score, mtime)
SELECT sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, path, status, canonical_sha256, parent, skip, formula, elements, score, mtime
FROM _staging
ON CONFLICT (sha256) DO NOTHING`

func (db *DB) insertSampleBatchPG(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	rows := make([][]any, len(samples))
	for i, s := range samples {
		rows[i] = []any{
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename, s.FileType,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256,
			s.Parent, s.Skip, s.Formula, s.Elements, s.Score, s.Mtime,
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
			canonical_sha256 = $3, formula = $4, elements = $5, score = $6,
			litmus_result = NULL, litmus_score = 0,
			analyzed_at = now(), updated_at = now()
		WHERE sha256 = $1`, sha256, sanitizeJSONB(result), canonical, fi.Formula, fi.Elements, fi.Score)
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
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND score >= $1 AND status = ''
		 ORDER BY score DESC LIMIT $2`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false positives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falseNegativesPG(ctx context.Context, scoreThreshold, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND score <= $1 AND status = ''
		 ORDER BY score ASC LIMIT $2`,
		scoreThreshold, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives: %w", err)
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
			canonical_sha256 = $4, formula = $5, elements = $6, score = $7,
			litmus_result = NULL, litmus_score = 0,
			analyzed_at = now(), updated_at = now()
		WHERE sha256 = $1`, sha256, status, sanitizeJSONB(result), canonical, fi.Formula, fi.Elements, fi.Score)
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

func (db *DB) setSkipPG(ctx context.Context, sha256, skip string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET skip = $2, updated_at = now() WHERE sha256 = $1`,
		sha256, skip)
	if err != nil {
		return fmt.Errorf("hopper: set skip: %w", err)
	}
	return nil
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
