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
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("hopper: parse dsn: %w", err)
	}
	cfg.MaxConns = 32
	cfg.MinConns = 4
	cfg.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
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
	slog.Info("executing initial schema ddl")
	if _, err := db.pool.Exec(ctx, schemaPG); err != nil {
		return fmt.Errorf("hopper: migrate: %w", err)
	}
	slog.Info("initial schema applied")
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
		// Covers falsePositivesPG / truePositivesPG / falseNegativesPG — all filter
		// (label, score, cleave_result IS NOT NULL, status='', skip='').
		`CREATE INDEX IF NOT EXISTS idx_samples_review ON samples(label, score DESC) WHERE cleave_result IS NOT NULL AND status = '' AND skip = ''`,
		// countAnalyzedPG: SELECT count(*) WHERE litmus_result IS NOT NULL — no index existed.
		`CREATE INDEX IF NOT EXISTS idx_samples_litmus_done ON samples(id) WHERE litmus_result IS NOT NULL`,
		// Pull-based work scheduling: claim tracking columns + index.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS claimed_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ`,
		`DROP INDEX IF EXISTS idx_samples_claimable`,
		`CREATE INDEX IF NOT EXISTS idx_samples_claimable ` +
			`ON samples(updated_at ASC NULLS FIRST, id) ` +
			`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`,
		// Covers the dashboard's OldestClaims query (DISTINCT ON claimed_by, ORDER BY claimed_at).
		`CREATE INDEX IF NOT EXISTS idx_samples_claimed ON samples(claimed_by, claimed_at) WHERE claimed_by != ''`,
		// newestAnalyzedAtPG: MAX(analyzed_at) — index-only max scan.
		`CREATE INDEX IF NOT EXISTS idx_samples_analyzed_at ON samples(analyzed_at DESC) WHERE analyzed_at IS NOT NULL`,
		// benignReviewPG / badReviewPG filter on skip='misclassified' which is excluded
		// from idx_samples_review (WHERE skip=''). Separate partial index for misclassified review.
		`CREATE INDEX IF NOT EXISTS idx_samples_misclassified_review ` +
			`ON samples(label, max_crit DESC, suspicious_count DESC) ` +
			`WHERE label_source = 'marker' AND skip = 'misclassified' ` +
			`AND cleave_result IS NOT NULL AND status = ''`,
		// staleSamplesPG: WHERE updated_at < $1 ORDER BY updated_at — no status prefix.
		`CREATE INDEX IF NOT EXISTS idx_samples_updated_at ON samples(updated_at)`,
		// Traits-version rescan: find analyzed samples with stale traits.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS traits_version TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_stale_traits ` +
			`ON samples(traits_version, analyzed_at) ` +
			`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''`,
		// feedSourcesPG / feedEcosystemsPG: DISTINCT feed/ecosystem WHERE source = $1.
		`CREATE INDEX IF NOT EXISTS idx_samples_source_feed ON samples(source, feed) WHERE feed != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_source_ecosystem ON samples(source, ecosystem) WHERE ecosystem != ''`,
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
		// sha256/parent/canonical_sha256 are plain TEXT; the UNIQUE index on
		// sha256 treats case as significant, so "abc…"/"ABC…" would be stored
		// as distinct rows. Pin them to canonical lowercase-hex via CHECK so
		// any writer bypassing the Go validators still can't drift.
		//
		// Two-step add: NOT VALID first (catalog-only, AccessExclusiveLock
		// for milliseconds), then VALIDATE CONSTRAINT (ShareUpdateExclusive
		// lock, doesn't block writes, scans in the background). On a
		// multi-million-row table the one-shot form would lock the table
		// for minutes; this form is near-invisible.
		`DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'samples_sha256_hex') THEN
				ALTER TABLE samples ADD CONSTRAINT samples_sha256_hex
					CHECK (sha256 ~ '^[0-9a-f]{64}$') NOT VALID;
			END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'samples_parent_hex') THEN
				ALTER TABLE samples ADD CONSTRAINT samples_parent_hex
					CHECK (parent = '' OR parent ~ '^[0-9a-f]{64}$') NOT VALID;
			END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'samples_canonical_sha256_hex') THEN
				ALTER TABLE samples ADD CONSTRAINT samples_canonical_sha256_hex
					CHECK (canonical_sha256 = '' OR canonical_sha256 ~ '^[0-9a-f]{64}$') NOT VALID;
			END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'reports_sha256_hex') THEN
				ALTER TABLE reports ADD CONSTRAINT reports_sha256_hex
					CHECK (sha256 ~ '^[0-9a-f]{64}$') NOT VALID;
			END IF;
		END$$`,
		// Validation pass: cheap lock, background scan. Idempotent —
		// VALIDATE CONSTRAINT on an already-valid constraint is a no-op that
		// only reads pg_constraint. Safe to re-run on every startup.
		`ALTER TABLE samples VALIDATE CONSTRAINT samples_sha256_hex`,
		`ALTER TABLE samples VALIDATE CONSTRAINT samples_parent_hex`,
		`ALTER TABLE samples VALIDATE CONSTRAINT samples_canonical_sha256_hex`,
		`ALTER TABLE reports VALIDATE CONSTRAINT reports_sha256_hex`,

		// sample_locations: one row per (sha256, path) observation. A sample
		// can have many locations — the same jquery.min.js shows up in
		// thousands of packages, the same stub in many droppers. Per-
		// observation fields (path, source, feed, parent, mtime) that used
		// to live on samples and get clobbered on re-ingest live here going
		// forward.
		`CREATE TABLE IF NOT EXISTS sample_locations (
			id            BIGSERIAL PRIMARY KEY,
			sha256        TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
			path          TEXT NOT NULL CHECK (path <> ''),
			parent_sha256 TEXT NOT NULL DEFAULT ''
				CHECK (parent_sha256 = '' OR parent_sha256 ~ '^[0-9a-f]{64}$'),
			filename      TEXT NOT NULL DEFAULT '',
			source        TEXT NOT NULL DEFAULT '',
			feed          TEXT NOT NULL DEFAULT '',
			ecosystem     TEXT NOT NULL DEFAULT '',
			mtime         TIMESTAMPTZ,
			first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (sha256, path)
		)`,
		// Indexes tuned for the expected read patterns.
		// Primary lookup: "where is this sha seen?" → idx_sl_sha256.
		// Feed/source rollups stay selective via the partial predicate.
		// Parent lookups are rare (exploded-from query) and stay partial.
		`CREATE INDEX IF NOT EXISTS idx_sl_sha256 ON sample_locations(sha256)`,
		`CREATE INDEX IF NOT EXISTS idx_sl_source ON sample_locations(source, feed) WHERE feed <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_sl_parent ON sample_locations(parent_sha256) WHERE parent_sha256 <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_sl_last_seen ON sample_locations(last_seen_at)`,

		// One-shot backfill from the existing denormalized columns. Guarded
		// by a table-emptiness check so restarts are cheap no-ops; re-running
		// the migration never re-scans the 3M-row samples table once done.
		// ON CONFLICT DO NOTHING also guards against partial prior attempts.
		`DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM sample_locations LIMIT 1) THEN
				INSERT INTO sample_locations
					(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at)
				SELECT sha256, path, parent, filename, source, feed, ecosystem, mtime, created_at, updated_at
				  FROM samples
				 WHERE path <> ''
				ON CONFLICT (sha256, path) DO NOTHING;
			END IF;
		END$$`,

		// Derived columns: convert from plain columns (written by Go) to
		// GENERATED … STORED (computed by PG from the JSONB source). This
		// makes drift structurally impossible — a writer can't forget to
		// set them because they're no longer settable. Existing rows get
		// recomputed as part of the ADD COLUMN, which also fixes the ~20K
		// archive members that had litmus_score=0 despite non-zero JSON prob.
		//
		// Guard: attgenerated='s' means "stored generated". If the column is
		// already in that state (second-run of the migration), do nothing.
		`DO $$
		BEGIN
			-- litmus_score: read prob from the JSONB envelope
			IF NOT EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'litmus_score'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples DROP COLUMN IF EXISTS litmus_score;
				ALTER TABLE samples ADD COLUMN litmus_score DOUBLE PRECISION
					GENERATED ALWAYS AS
						(COALESCE((litmus_result->>'prob')::double precision, 0))
					STORED;
			END IF;

			-- file_type: cleave's classification for the top-level file
			IF NOT EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'file_type'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples DROP COLUMN IF EXISTS file_type;
				ALTER TABLE samples ADD COLUMN file_type TEXT NOT NULL
					GENERATED ALWAYS AS
						(COALESCE(cleave_result->'fs'->0->>'type', ''))
					STORED;
			END IF;

			-- score: cleave's cumulative severity (fs[0].x)
			IF NOT EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'score'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples DROP COLUMN IF EXISTS score;
				ALTER TABLE samples ADD COLUMN score INTEGER NOT NULL
					GENERATED ALWAYS AS
						(COALESCE((cleave_result->'fs'->0->>'x')::int, 0))
					STORED;
			END IF;

			-- formula: cleave's behavioral signature (fs[0].f)
			IF NOT EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'formula'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples DROP COLUMN IF EXISTS formula;
				ALTER TABLE samples ADD COLUMN formula TEXT NOT NULL
					GENERATED ALWAYS AS
						(COALESCE(cleave_result->'fs'->0->>'f', ''))
					STORED;
			END IF;
		END$$`,

		// Re-create the indexes that DROP COLUMN cascaded away. Each IF NOT
		// EXISTS so this is a no-op on re-runs after the first conversion.
		`CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type)`,
		`CREATE INDEX IF NOT EXISTS idx_samples_formula   ON samples(formula)   WHERE formula   != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_score     ON samples(score)     WHERE score     != 0`,
	} {
		slog.Info("executing migration ddl", "ddl", ddl)
		if _, err := db.pool.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate: %w", err)
		}
	}
	slog.Info("all migrations applied")
	return nil
}

const pgSampleCols = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, cleave_result, litmus_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, mtime, marker_mtime, traits_version`

// pgSampleColsLight excludes cleave_result and litmus_result to avoid loading
// potentially large JSON blobs when only metadata is needed (e.g. claim queries).
const pgSampleColsLight = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, mtime, marker_mtime, traits_version`

func pgSampleDest(s *Sample) []any {
	return []any{
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.CleaveResult, &s.LitmusResult, &s.LitmusScore,
		&s.Path, &s.Status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score,
		&s.MaxCrit, &s.SuspiciousCount,
		&s.CreatedAt, &s.UpdatedAt, &s.AnalyzedAt, &s.Mtime, &s.MarkerMtime,
		&s.TraitsVersion,
	}
}

func pgSampleDestLight(s *Sample) []any {
	return []any{
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.LitmusScore,
		&s.Path, &s.Status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score,
		&s.MaxCrit, &s.SuspiciousCount,
		&s.CreatedAt, &s.UpdatedAt, &s.AnalyzedAt, &s.Mtime, &s.MarkerMtime,
		&s.TraitsVersion,
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

func scanPGSamplesLight(rows pgx.Rows) ([]*Sample, error) {
	defer rows.Close()
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		if err := rows.Scan(pgSampleDestLight(s)...); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) insertSampleNewPG(ctx context.Context, s *Sample) (bool, error) {
	// One transaction so the sample row and its sample_locations
	// observation are created (or rolled back) atomically.
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("hopper: begin insert: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	// cleave_result and litmus_result are the only analysis fields the
	// writer sets — file_type, score, formula, and litmus_score are
	// GENERATED STORED columns derived from the JSONB, so writing to them
	// is neither required nor legal. ON CONFLICT leaves existing analysis
	// alone so a walker-comes-after-Explode case doesn't wipe real results.
	tag, err := tx.Exec(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename,
			size_bytes, label, label_source, path, status,
			canonical_sha256, parent, skip, elements,
			max_crit, suspicious_count, mtime, marker_mtime,
			cleave_result, litmus_result)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$1, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		ON CONFLICT (sha256) DO UPDATE SET
			path  = CASE WHEN EXCLUDED.path  <> ''   THEN EXCLUDED.path  ELSE samples.path  END,
			mtime = CASE WHEN EXCLUDED.mtime IS NOT NULL THEN EXCLUDED.mtime ELSE samples.mtime END
		WHERE EXCLUDED.parent = ''
		  AND ((EXCLUDED.path  <> ''   AND samples.path  IS DISTINCT FROM EXCLUDED.path)
		    OR (EXCLUDED.mtime IS NOT NULL AND samples.mtime IS DISTINCT FROM EXCLUDED.mtime))`,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
		s.Parent, s.Skip, s.Elements,
		s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
		sanitizeJSONB(s.CleaveResult), sanitizeJSONB(s.LitmusResult))
	if err != nil {
		return false, fmt.Errorf("hopper: insert sample: %w", err)
	}
	if tag.RowsAffected() == 0 && s.MarkerMtime != nil {
		if _, err := tx.Exec(ctx, `UPDATE samples SET marker_mtime = $2 WHERE sha256 = $1`, s.SHA256, s.MarkerMtime); err != nil {
			return false, fmt.Errorf("hopper: refresh marker mtime: %w", err)
		}
	}
	// Record the observation. validSample already guarantees s.Path != ""
	// at the dispatch layer, but keep the guard here so a direct-call bug
	// doesn't violate the CHECK constraint and abort the whole transaction.
	if s.Path != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sample_locations
				(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (sha256, path) DO UPDATE SET
				last_seen_at = now(),
				mtime = COALESCE(EXCLUDED.mtime, sample_locations.mtime)`,
			s.SHA256, s.Path, s.Parent, s.Filename, s.Source, s.Feed, s.Ecosystem, s.Mtime); err != nil {
			return false, fmt.Errorf("hopper: upsert location: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("hopper: commit insert: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

var insertBatchStagingCols = []string{
	"sha256", "source", "feed", "ecosystem", "filename",
	"size_bytes", "label", "label_source", "path", "status", "canonical_sha256",
	"parent", "skip", "elements", "max_crit", "suspicious_count",
	"mtime", "marker_mtime", "cleave_result", "litmus_result",
}

const insertBatchStagingDDL = `CREATE TEMP TABLE _staging (
	sha256 TEXT, source TEXT, feed TEXT, ecosystem TEXT, filename TEXT,
	size_bytes BIGINT, label TEXT, label_source TEXT,
	path TEXT, status TEXT, canonical_sha256 TEXT,
	parent TEXT, skip TEXT, elements TEXT,
	max_crit INTEGER, suspicious_count INTEGER,
	mtime TIMESTAMPTZ, marker_mtime TIMESTAMPTZ,
	cleave_result JSONB, litmus_result JSONB
) ON COMMIT DROP`

// file_type, score, formula, and litmus_score are GENERATED columns on
// samples, auto-computed from cleave_result / litmus_result. We don't
// reference them here — writing to a generated column is an error.
// ON CONFLICT leaves existing analysis alone: a walker row arriving
// after Explode must not wipe results we already stored.
const insertBatchStagingInsert = `INSERT INTO samples (
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result)
SELECT DISTINCT ON (sha256)
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result
FROM _staging
ON CONFLICT (sha256) DO UPDATE SET
	path  = CASE WHEN EXCLUDED.path  <> ''   THEN EXCLUDED.path  ELSE samples.path  END,
	mtime = CASE WHEN EXCLUDED.mtime IS NOT NULL THEN EXCLUDED.mtime ELSE samples.mtime END
-- Only walker writes (parent='') are allowed to refresh samples.path /
-- samples.mtime on conflict. Explode writes (parent=<archive-sha>) must
-- never clobber the top-level row: a content hash collision between a
-- top-level file and an archive member would otherwise leave samples
-- pointing at a virtual archive-member path that doesn't exist on disk.
WHERE EXCLUDED.parent = ''
  AND ((EXCLUDED.path  <> ''   AND samples.path  IS DISTINCT FROM EXCLUDED.path)
    OR (EXCLUDED.mtime IS NOT NULL AND samples.mtime IS DISTINCT FROM EXCLUDED.mtime))`

func (db *DB) insertSampleBatchPG(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	rows := make([][]any, len(samples))
	for i, s := range samples {
		rows[i] = []any{
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256,
			s.Parent, s.Skip, s.Elements, s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
			sanitizeJSONB(s.CleaveResult), sanitizeJSONB(s.LitmusResult),
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

	// Fan the staging rows out into sample_locations in the same
	// transaction. DISTINCT ON collapses duplicates within the batch
	// (same sha+path twice → one row). ON CONFLICT upserts last_seen_at
	// on re-observations without clobbering an existing mtime.
	if _, err := tx.Exec(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime)
		SELECT DISTINCT ON (sha256, path)
			sha256, path, parent, filename, source, feed, ecosystem, mtime
		  FROM _staging
		 WHERE path <> ''
		ON CONFLICT (sha256, path) DO UPDATE SET
			last_seen_at = now(),
			mtime = COALESCE(EXCLUDED.mtime, sample_locations.mtime)`); err != nil {
		return 0, nil, fmt.Errorf("hopper: upsert locations from staging: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE samples s
		SET marker_mtime = st.marker_mtime
		FROM _staging st
		WHERE s.sha256 = st.sha256
			AND st.marker_mtime IS NOT NULL`); err != nil {
		return 0, nil, fmt.Errorf("hopper: refresh marker mtime: %w", err)
	}

	// Mark stale rows whose path now belongs to a different SHA256.
	// This happens when a file is replaced on disk — the walk inserts a
	// new row for the new content but the old row lingers in the queue.
	if _, err := tx.Exec(ctx, `
		UPDATE samples s
		SET skip = 'replaced'
		FROM _staging st
		WHERE s.path = st.path
			AND st.path != ''
			AND s.sha256 != st.sha256
			AND s.skip = ''
			AND s.cleave_result IS NULL`); err != nil {
		return 0, nil, fmt.Errorf("hopper: mark replaced: %w", err)
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

const pgLocationCols = `id, sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at`

func scanPGLocation(row interface{ Scan(...any) error }) (*SampleLocation, error) {
	var loc SampleLocation
	if err := row.Scan(&loc.ID, &loc.SHA256, &loc.Path, &loc.ParentSHA256,
		&loc.Filename, &loc.Source, &loc.Feed, &loc.Ecosystem,
		&loc.Mtime, &loc.FirstSeenAt, &loc.LastSeenAt); err != nil {
		return nil, err
	}
	return &loc, nil
}

func (db *DB) upsertLocationPG(ctx context.Context, loc *SampleLocation) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (sha256, path) DO UPDATE SET
			last_seen_at = now(),
			mtime = COALESCE(EXCLUDED.mtime, sample_locations.mtime)`,
		loc.SHA256, loc.Path, loc.ParentSHA256, loc.Filename,
		loc.Source, loc.Feed, loc.Ecosystem, loc.Mtime)
	if err != nil {
		return fmt.Errorf("hopper: upsert location %s: %w", loc.SHA256, err)
	}
	return nil
}

func (db *DB) locationsForSHAPG(ctx context.Context, sha256 string) ([]*SampleLocation, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgLocationCols+` FROM sample_locations WHERE sha256 = $1 ORDER BY last_seen_at DESC`, sha256)
	if err != nil {
		return nil, fmt.Errorf("hopper: locations %s: %w", sha256, err)
	}
	defer rows.Close()
	var out []*SampleLocation
	for rows.Next() {
		loc, err := scanPGLocation(rows)
		if err != nil {
			return nil, fmt.Errorf("hopper: scan location: %w", err)
		}
		out = append(out, loc)
	}
	return out, rows.Err()
}

func (db *DB) updateCleaveResultPG(
	ctx context.Context, sha256 string, result []byte, canonical string,
	fi cleaveFileInfo, traitsVersion string,
) error {
	// file_type, score, formula, litmus_score are GENERATED from
	// cleave_result / litmus_result — they can't be SET directly. Setting
	// litmus_result = NULL implicitly resets litmus_score to 0 (via the
	// COALESCE in its generation expression).
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET cleave_result = $2,
			canonical_sha256 = $3, elements = $4,
			max_crit = $5, suspicious_count = $6,
			litmus_result = NULL,
			traits_version = $7,
			analyzed_at = now(), updated_at = now()
		WHERE sha256 = $1`,
		sha256, sanitizeJSONB(result), canonical,
		fi.Elements, fi.MaxCrit, fi.SuspiciousCount, traitsVersion)
	if err != nil {
		return fmt.Errorf("hopper: update cleave result: %w", err)
	}
	return nil
}

func (db *DB) updateLitmusResultPG(ctx context.Context, sha256 string, result []byte) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET litmus_result = $2, updated_at = now()
		WHERE sha256 = $1`, sha256, sanitizeJSONB(result))
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

func (db *DB) samplesByStatusLightPG(ctx context.Context, status string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples WHERE status = $1 ORDER BY updated_at ASC LIMIT $2`,
		status, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by status (light): %w", err)
	}
	return scanPGSamplesLight(rows)
}

func (db *DB) falsePositivesPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND status = '' AND skip = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2)
		 ORDER BY updated_at ASC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false positives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falsePositivesLightPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND status = '' AND skip = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2)
		 ORDER BY updated_at ASC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false positives (light): %w", err)
	}
	return scanPGSamplesLight(rows)
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

func (db *DB) falseNegativesPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND status = '' AND skip = ''
		   AND max_crit < 5 AND suspicious_count < 2
		 ORDER BY updated_at ASC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falseNegativesLightPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND status = '' AND skip = ''
		   AND max_crit < 5 AND suspicious_count < 2
		 ORDER BY updated_at ASC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives (light): %w", err)
	}
	return scanPGSamplesLight(rows)
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

func (db *DB) relativizePathsPG(ctx context.Context, prefix string) (int64, error) {
	if prefix == "" {
		return 0, nil
	}
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples SET path = substring(path from char_length($1) + 1), updated_at = now()
		WHERE starts_with(path, $1)`, prefix)
	if err != nil {
		return 0, fmt.Errorf("hopper: relativize paths: %w", err)
	}

	// Rewrite sample_locations in three steps so the UNIQUE (sha256, path)
	// constraint is never violated:
	//   1. delete absolute rows whose target already exists as a distinct
	//      relative row (the relative peer wins),
	//   2. dedup peers that would converge on the same (sha, new-path)
	//      (keep most-recent),
	//   3. UPDATE what remains; each survivor now has a unique target.
	// The naïve single-UPDATE WHERE NOT EXISTS approach fails because two
	// rows in the same UPDATE can each see no current conflict but still
	// collide once one of them has rewritten.
	if _, err := db.pool.Exec(ctx, `
		DELETE FROM sample_locations sl
		 WHERE starts_with(sl.path, $1)
		   AND EXISTS (
		       SELECT 1 FROM sample_locations x
		        WHERE x.sha256 = sl.sha256
		          AND x.path   = substring(sl.path from char_length($1) + 1)
		          AND x.id    <> sl.id
		   )`, prefix); err != nil {
		return 0, fmt.Errorf("hopper: relativize locations dedup-vs-existing: %w", err)
	}
	if _, err := db.pool.Exec(ctx, `
		DELETE FROM sample_locations
		 WHERE id IN (
		     SELECT id FROM (
		         SELECT sl.id,
		                row_number() OVER (
		                    PARTITION BY sl.sha256, substring(sl.path from char_length($1) + 1)
		                    ORDER BY sl.last_seen_at DESC, sl.id ASC
		                ) AS rn
		           FROM sample_locations sl
		          WHERE starts_with(sl.path, $1)
		     ) t
		     WHERE rn > 1
		 )`, prefix); err != nil {
		return 0, fmt.Errorf("hopper: relativize locations dedup-peers: %w", err)
	}
	if _, err := db.pool.Exec(ctx, `
		UPDATE sample_locations SET
			path = substring(path from char_length($1) + 1),
			last_seen_at = now()
		 WHERE starts_with(path, $1)`, prefix); err != nil {
		return 0, fmt.Errorf("hopper: relativize locations update: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (db *DB) updateSamplePG(ctx context.Context, sha256, status string, result []byte, canonical string, fi cleaveFileInfo) error {
	// file_type, score, formula, litmus_score are GENERATED; setting
	// litmus_result = NULL implicitly resets litmus_score to 0.
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET status = $2, cleave_result = $3,
			canonical_sha256 = $4, elements = $5,
			max_crit = $6, suspicious_count = $7,
			litmus_result = NULL,
			analyzed_at = now(), updated_at = now()
		WHERE sha256 = $1`,
		sha256, status, sanitizeJSONB(result), canonical,
		fi.Elements, fi.MaxCrit, fi.SuspiciousCount)
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

func (db *DB) seedCandidatesInPathsPG(ctx context.Context, prefixes []string, label string, limit int, light bool) ([]*Sample, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	patterns := make([]string, len(prefixes))
	for i, p := range prefixes {
		patterns[i] = p + "/%"
	}

	// Apply detection-equivalent filter so the DB only returns samples that
	// will pass the Go-side Detected() / !Detected() post-filter.
	// FP seeds (good label) want detected:   max_crit >= 5 OR suspicious_count >= 2
	// FN seeds (bad label)  want undetected:  max_crit < 5 AND suspicious_count < 2
	var detectionFilter string
	if label == "good" {
		detectionFilter = "AND (max_crit >= 5 OR suspicious_count >= 2)"
	} else {
		detectionFilter = "AND max_crit < 5 AND suspicious_count < 2"
	}

	cols := pgSampleCols
	if light {
		cols = pgSampleColsLight
	}

	rows, err := db.pool.Query(ctx,
		`SELECT `+cols+` FROM samples
		 WHERE status = '' AND label = $1 AND skip = ''
		   AND cleave_result IS NOT NULL
		   AND path LIKE ANY($2)
		   `+detectionFilter+`
		 ORDER BY updated_at ASC LIMIT $3`,
		label, patterns, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: seed candidates in paths: %w", err)
	}
	if light {
		return scanPGSamplesLight(rows)
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
	const batchSize = 5000
	var total int64
	var lastID int64
	for {
		tag, err := db.pool.Exec(ctx, `
			WITH batch AS (
				SELECT id, sha256 FROM samples
				WHERE cleave_result IS NOT NULL AND id > $2
				ORDER BY id LIMIT $1
			)
			UPDATE samples SET canonical_sha256 = computed.canonical, updated_at = now()
			FROM (
				SELECT s.sha256,
					LEAST(s.sha256, MIN(jt.file_sha256)) AS canonical
				FROM samples s
				JOIN batch b ON b.sha256 = s.sha256,
					JSON_TABLE(s.cleave_result, '$.files[*]' COLUMNS (
						file_sha256 TEXT PATH '$.sha256'
					)) AS jt
				WHERE length(jt.file_sha256) = 64
				GROUP BY s.sha256
			) AS computed
			WHERE samples.sha256 = computed.sha256
				AND samples.canonical_sha256 IS DISTINCT FROM computed.canonical`, batchSize, lastID)
		if err != nil {
			return total, fmt.Errorf("hopper: recompute canonical sha256: %w", err)
		}
		n := tag.RowsAffected()
		total += n
		// Advance cursor.
		var maxID int64
		if err := db.pool.QueryRow(ctx,
			`SELECT COALESCE(MAX(id), 0) FROM samples WHERE cleave_result IS NOT NULL AND id > $1 ORDER BY id LIMIT $2`,
			lastID, batchSize).Scan(&maxID); err != nil {
			return total, fmt.Errorf("hopper: recompute cursor: %w", err)
		}
		if maxID == lastID {
			break
		}
		lastID = maxID
		if n < batchSize {
			break
		}
		slog.Info("recompute canonical sha256 batch", "batch", n, "total", total)
	}
	return total, nil
}

// backfillPG fixes legacy rows whose non-generated derivable columns
// (elements, max_crit, suspicious_count) are stale, then clears misclassified
// skip markers that no longer disagree with the new trait-based heuristic.
//
// Note: file_type / score / formula / litmus_score are GENERATED from the
// JSONB source, so their values can't drift and don't need a backfill pass.
// Before the generated-column migration this function also recomputed those
// columns; that work is now a schema invariant.
func (db *DB) backfillPG(ctx context.Context) (BackfillStats, error) {
	var stats BackfillStats

	// Candidate rows: have cleave_result but elements wasn't derived yet.
	// elements is the only analysis-derived non-generated column, so empty
	// elements on a row with cleave_result is the reliable "needs backfill"
	// signal now that file_type is computed.
	if err := db.pool.QueryRow(ctx, `
		SELECT count(*) FROM samples
		WHERE cleave_result IS NOT NULL AND elements = ''`).Scan(&stats.Scanned); err != nil {
		return stats, fmt.Errorf("hopper: backfill count: %w", err)
	}

	// Pass 1: elements / max_crit / suspicious_count from cleave_result,
	// in batches. formula / score / file_type / litmus_score are generated
	// columns — don't touch them.
	//
	// Implementation note: earlier versions used UPDATE samples s ... FROM
	// (SELECT ... FROM samples s2 JOIN batch ...) with JSON_TABLE. PG rejects
	// that shape with "column file_type can only be updated to DEFAULT"
	// (SQLSTATE 428C9) when samples has STORED GENERATED columns — the
	// self-reference via FROM trips the generated-column check even though
	// file_type is not in the SET list. Inlining the JSON extraction on the
	// target row sidesteps that.
	const backfillBatch = 5000
	for {
		cleaveTag, err := db.pool.Exec(ctx, `
			UPDATE samples SET
				elements = translate(
					COALESCE(cleave_result->'fs'->0->>'f', ''),
					'₀₁₂₃₄₅₆₇₈₉', ''),
				max_crit = COALESCE((
					SELECT MAX((tr->>'l')::int)
					FROM jsonb_array_elements(
						COALESCE(cleave_result->'fs'->0->'ts', '[]'::jsonb)
					) AS tr
				), 0),
				suspicious_count = (
					SELECT COUNT(*)::int
					FROM jsonb_array_elements(
						COALESCE(cleave_result->'fs'->0->'ts', '[]'::jsonb)
					) AS tr
					WHERE (tr->>'l')::int >= 4
				),
				updated_at = now()
			WHERE sha256 IN (
				SELECT sha256 FROM samples
				WHERE cleave_result IS NOT NULL AND elements = ''
				LIMIT $1
			)`, backfillBatch)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill cleave columns: %w", err)
		}
		n := cleaveTag.RowsAffected()
		stats.Updated += n
		if n < backfillBatch {
			break
		}
		slog.Info("backfill cleave batch", "batch", n, "total", stats.Updated)
	}

	// Pass 2: clear stale skip='misclassified' markers whose underlying
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
		UPDATE samples SET skip = $2, claimed_by = '', claimed_at = NULL, updated_at = now() WHERE sha256 = $1`,
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
	// CASCADE covers the FK from sample_locations / reports to samples;
	// RESTART IDENTITY resets the id sequences so a post-reset ingest
	// starts at 1 instead of continuing from pre-reset max.
	_, err := db.pool.Exec(ctx,
		`TRUNCATE samples, sample_locations, reports RESTART IDENTITY CASCADE`)
	if err != nil {
		return fmt.Errorf("hopper: delete all: %w", err)
	}
	return nil
}

func (db *DB) countCleanupPG(ctx context.Context, stage CleanupStage) (int64, error) {
	var n int64
	err := db.pool.QueryRow(ctx,
		"SELECT count(*) FROM samples WHERE "+stage.predicate).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("hopper: count cleanup %s: %w", stage.Name, err)
	}
	return n, nil
}

func (db *DB) applyCleanupPG(ctx context.Context, stage CleanupStage) (int64, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin cleanup %s: %w", stage.Name, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	if _, err := tx.Exec(ctx,
		"DELETE FROM reports WHERE sha256 IN (SELECT sha256 FROM samples WHERE "+stage.predicate+")"); err != nil {
		return 0, fmt.Errorf("hopper: cleanup %s reports: %w", stage.Name, err)
	}
	tag, err := tx.Exec(ctx, "DELETE FROM samples WHERE "+stage.predicate)
	if err != nil {
		return 0, fmt.Errorf("hopper: cleanup %s samples: %w", stage.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("hopper: commit cleanup %s: %w", stage.Name, err)
	}
	return tag.RowsAffected(), nil
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

func (db *DB) claimJobsPG(
	ctx context.Context, worker string, limit int,
	expiry time.Duration, currentTraits string, rescanAge time.Duration,
	hopperStart time.Time, forceRescanPrefixes []string,
) ([]ClaimJob, error) {
	// Tier 1: unanalyzed samples (highest priority).
	// ORDER BY random() spreads work across different packages/sources so a
	// batch of structurally similar archives can't monopolize all workers.
	rows, err := db.pool.Query(ctx, `
		WITH claimable AS (
			SELECT id FROM samples
			WHERE cleave_result IS NULL AND skip = '' AND parent = ''
			  AND (claimed_by = '' OR claimed_at < now() - $2::interval)
			ORDER BY random()
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE samples SET claimed_by = $1, claimed_at = now()
		FROM claimable WHERE samples.id = claimable.id
		RETURNING samples.sha256, samples.path, samples.size_bytes, samples.file_type`,
		worker, expiry, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: claim jobs: %w", err)
	}
	jobs, err := scanClaimRows(rows)
	if err != nil {
		return nil, err
	}
	if len(jobs) > 0 {
		return jobs, nil
	}

	// Tier 2: force-rescan — re-analyze samples under the named path prefixes
	// whose analysis predates this hopper run.
	if len(forceRescanPrefixes) > 0 {
		patterns := pathPatterns(forceRescanPrefixes)
		rows, err = db.pool.Query(ctx, `
			WITH reclaimable AS (
				SELECT id FROM samples
				WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''
				  AND analyzed_at < $4
				  AND (path = ANY($5) OR path LIKE ANY($5))
				  AND (claimed_by = '' OR claimed_at < now() - $2::interval)
				ORDER BY random()
				LIMIT $3
				FOR UPDATE SKIP LOCKED
			)
			UPDATE samples SET claimed_by = $1, claimed_at = now()
			FROM reclaimable WHERE samples.id = reclaimable.id
			RETURNING samples.sha256, samples.path, samples.size_bytes, samples.file_type`,
			worker, expiry, limit, hopperStart.UTC(), patterns)
		if err != nil {
			return nil, fmt.Errorf("hopper: claim force-rescan jobs: %w", err)
		}
		jobs, err = scanClaimRows(rows)
		if err != nil {
			return nil, err
		}
		if len(jobs) > 0 {
			return jobs, nil
		}
	}

	if currentTraits == "" {
		return nil, nil
	}

	// Tier 3: stale-traits rescan — samples analyzed with an older traits
	// version. ORDER BY random() for the same reason as tier 1.
	rows, err = db.pool.Query(ctx, `
		WITH reclaimable AS (
			SELECT id FROM samples
			WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''
			  AND traits_version != $4
			  AND analyzed_at < $5
			  AND (claimed_by = '' OR claimed_at < now() - $2::interval)
			ORDER BY random()
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE samples SET claimed_by = $1, claimed_at = now()
		FROM reclaimable WHERE samples.id = reclaimable.id
		RETURNING samples.sha256, samples.path, samples.size_bytes, samples.file_type`,
		worker, expiry, limit, currentTraits, time.Now().Add(-rescanAge).UTC())
	if err != nil {
		return nil, fmt.Errorf("hopper: claim stale-traits jobs: %w", err)
	}
	return scanClaimRows(rows)
}

// pathPatterns expands each path prefix into both its exact form and its
// subtree form (prefix + "/%") so SQL can match either with a single array.
func pathPatterns(prefixes []string) []string {
	patterns := make([]string, 0, len(prefixes)*2)
	for _, p := range prefixes {
		patterns = append(patterns, p, p+"/%")
	}
	return patterns
}

func scanClaimRows(rows pgx.Rows) ([]ClaimJob, error) {
	defer rows.Close()
	var jobs []ClaimJob
	for rows.Next() {
		var j ClaimJob
		if err := rows.Scan(&j.SHA256, &j.Path, &j.SizeBytes, &j.FileType); err != nil {
			return nil, fmt.Errorf("hopper: claim jobs scan: %w", err)
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (db *DB) oldestClaimsPG(ctx context.Context, maxAge time.Duration) ([]WorkerClaim, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT ON (claimed_by) claimed_by, path, claimed_at
		FROM samples
		WHERE claimed_by != '' AND claimed_at IS NOT NULL
			AND claimed_at >= now() - $1::interval
		ORDER BY claimed_by, claimed_at
	`, maxAge.String())
	if err != nil {
		return nil, fmt.Errorf("hopper: oldest claims: %w", err)
	}
	defer rows.Close()
	var out []WorkerClaim
	for rows.Next() {
		var wc WorkerClaim
		if err := rows.Scan(&wc.Worker, &wc.Path, &wc.ClaimedAt); err != nil {
			return nil, fmt.Errorf("hopper: oldest claims scan: %w", err)
		}
		out = append(out, wc)
	}
	return out, rows.Err()
}

func (db *DB) newestAnalyzedAtPG(ctx context.Context) (time.Time, error) {
	var t *time.Time
	err := db.pool.QueryRow(ctx,
		`SELECT MAX(analyzed_at) FROM samples WHERE analyzed_at IS NOT NULL`,
	).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}

func (db *DB) unclaimAllPG(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx,
		`UPDATE samples SET claimed_by = '', claimed_at = NULL
		 WHERE claimed_by != ''`)
	if err != nil {
		return 0, fmt.Errorf("hopper: unclaim all: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (db *DB) unclaimJobsPG(ctx context.Context, shas []string) error {
	if len(shas) == 0 {
		return nil
	}
	_, err := db.pool.Exec(ctx,
		`UPDATE samples SET claimed_by = '', claimed_at = NULL, updated_at = now() WHERE sha256 = ANY($1)`, shas)
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
