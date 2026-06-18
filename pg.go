package hopper

import (
	"context"
	cryptosha256 "crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"
)

func openPG(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("hopper: parse dsn: %w", err)
	}
	// Sized for concurrent /api/next + /api/result + dashboard + ad-hoc psql
	// inspection. With long result-store transactions (UpdateCleaveResult
	// can cascade into ExplodeArchiveMembers) holding a connection for
	// seconds, 32 was tight enough to starve the dashboard's queries.
	cfg.MaxConns = 64
	cfg.MinConns = 8
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

// migratePG applies every migration synchronously — core DDL (tables, columns,
// extensions) followed by all index builds. Used by one-shot commands (init,
// import) where nothing is serving yet and a fully-indexed database is wanted
// before bulk work begins. The serving path (load/serve) calls migrateServingPG
// instead, which defers index builds to a background goroutine. allowRewrite is
// true here: a one-shot command is the only context permitted to run a
// table-rewriting migration on a populated samples table.
func (db *DB) migratePG(ctx context.Context) error {
	build, err := db.migrateServingPG(ctx, true)
	if err != nil {
		return err
	}
	return build(ctx)
}

// pgRuntimeMigrations is the ordered post-schema DDL list. Extracted into its
// own function so the synchronous (migratePG) and serving (migrateServingPG)
// paths share one source of truth; the serving path partitions it with
// isDeferrableIndexDDL. Index DDL may appear anywhere in the list — every
// CREATE INDEX depends only on columns added earlier, never on another index,
// so building all columns before any index preserves correctness.
func pgRuntimeMigrations() []string { //nolint:revive,maintidx // long sequential migration list; splitting reduces clarity
	return []string{
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS parent TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS skip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS formula TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS elements TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS max_crit INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS suspicious_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_result JSONB`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS llm_result JSONB`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_score DOUBLE PRECISION NOT NULL DEFAULT 0`,
		`CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_formula ON samples(formula) WHERE formula != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_elements ON samples(elements) WHERE elements != ''`,
		// Drains itself as backfill completes: rows leave the index when elements
		// is populated. Without it, each batch's gating SELECT seq-scans the heap.
		`CREATE INDEX IF NOT EXISTS idx_samples_backfill_pending ON samples(sha256) WHERE cleave_result IS NOT NULL AND elements = ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_score ON samples(score) WHERE score != 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS mtime TIMESTAMPTZ`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS first_analyzed_at TIMESTAMPTZ`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS marker_mtime TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source ON samples(source, label, analyzed_at DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_mtime ON samples(source, label, mtime DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_created ON samples(source, label, created_at DESC) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_top_created_done ` +
			`ON samples(source, label, created_at DESC) ` +
			`WHERE cleave_result IS NOT NULL AND parent = '' AND litmus_result IS NOT NULL`,
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
		`DO $$
		DECLARE
			idxdef text;
		BEGIN
			SELECT pg_get_indexdef(to_regclass('idx_samples_claimable'))
			  INTO idxdef;

			IF idxdef IS NOT NULL
			   AND (idxdef NOT ILIKE '%ON public.samples USING btree (updated_at NULLS FIRST, id)%'
			    OR idxdef NOT ILIKE '%WHERE ((cleave_result IS NULL) AND (skip = ''''::text) AND (parent = ''''::text))%') THEN
				DROP INDEX idx_samples_claimable;
			END IF;
		END$$`,
		`CREATE INDEX IF NOT EXISTS idx_samples_claimable ` +
			`ON samples(updated_at ASC NULLS FIRST, id) ` +
			`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_claimable_sha ` +
			`ON samples(sha256) ` +
			`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`,
		// Covers the dashboard's OldestClaims query (DISTINCT ON claimed_by, ORDER BY claimed_at).
		`CREATE INDEX IF NOT EXISTS idx_samples_claimed ON samples(claimed_by, claimed_at) WHERE claimed_by != ''`,
		// newestAnalyzedAtPG: MAX(analyzed_at) — index-only max scan.
		`CREATE INDEX IF NOT EXISTS idx_samples_analyzed_at ON samples(analyzed_at DESC) WHERE analyzed_at IS NOT NULL`,
		// Grafana ingest-rate panels: count/bucket samples by created_at without
		// the parent/cleave predicates the other created_at indexes carry.
		`CREATE INDEX IF NOT EXISTS idx_samples_created_at ON samples(created_at DESC)`,
		// Grafana analysis-latency panels bucket reports by created_at over wide
		// ranges; idx_reports_sha256_type doesn't help time-range scans.
		`CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC)`,
		// benignReviewPG / badReviewPG filter on skip='misclassified' which is excluded
		// from idx_samples_review (WHERE skip=''). Separate partial index for misclassified review.
		`CREATE INDEX IF NOT EXISTS idx_samples_misclassified_review ` +
			`ON samples(label, max_crit DESC, suspicious_count DESC) ` +
			`WHERE label_source = 'marker' AND skip = 'misclassified' ` +
			`AND cleave_result IS NOT NULL AND status = ''`,
		// conflictReviewPG: good+bad conflicts flagged skip='conflict'.
		`CREATE INDEX IF NOT EXISTS idx_samples_conflict_review ` +
			`ON samples(updated_at DESC) ` +
			`WHERE skip = 'conflict' AND status = ''`,
		// staleSamplesPG: WHERE updated_at < $1 ORDER BY updated_at — no status prefix.
		`CREATE INDEX IF NOT EXISTS idx_samples_updated_at ON samples(updated_at)`,
		// Workflow dashboard freshness: global top-level recency cannot use the
		// feed-prefixed indexes because there is no source/label predicate.
		`CREATE INDEX IF NOT EXISTS idx_samples_top_created ` +
			`ON samples(created_at DESC, id) ` +
			`WHERE parent = ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_top_ready_created ` +
			`ON samples(created_at DESC, id) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL`,
		// prism's feed filtered by ecosystem (FeedQuery.Ecosystems) orders by
		// created_at DESC. The date-only indexes above force the planner to walk
		// the global recency order discarding every other ecosystem's rows — a
		// rare ecosystem made it scan ~3.2M rows to collect 500 (21s). Prefixing
		// ecosystem lets it seek the one ecosystem and walk created_at DESC in
		// order, stopping at LIMIT with no sort.
		//
		// The predicate is idx_samples_top_ready_created's, prefixed by ecosystem:
		// every prism feed query carries parent='' (TopLevelOnly) and
		// cleave_result IS NOT NULL unconditionally, and litmus_result IS NOT NULL
		// either explicitly (RequireLitmus) or via FeedQuery.requireLitmus (the
		// criticality-band path adds it — a hostile/suspicious class can never be a
		// null-litmus row, so it is result-preserving). Matching all three constant
		// predicates lets feedSamplesCountPG count by index-only scan (the table is
		// ~97% all-visible) instead of heap-rechecking every row — the difference
		// between a sub-second count and a multi-second one on a large ecosystem.
		// ecosystem<>'' keeps the empty-ecosystem block out (a specific-ecosystem
		// qual implies it). Built CONCURRENTLY by createIndexConcurrently.
		`CREATE INDEX IF NOT EXISTS idx_samples_eco_top_created ` +
			`ON samples(ecosystem, created_at DESC) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL ` +
			`AND litmus_result IS NOT NULL AND ecosystem <> ''`,
		// Adds litmus_class between ecosystem and created_at so a feed filtered by
		// BOTH ecosystem and criticality (feedSamplesPG with LitmusClasses set,
		// cutoff = CriticalLevel) is an ordered seek to (ecosystem, class) walked
		// created_at DESC — no per-row JSONB read, no sort — and the matching count
		// is an index-only scan. The class-less ecosystem feed keeps using
		// idx_samples_eco_top_created above (created_at is contiguous there; here it
		// is only contiguous within a class). Same partial predicate, so a row
		// healed by the litmus_class backfill enters both consistently.
		`CREATE INDEX IF NOT EXISTS idx_samples_eco_class_created ` +
			`ON samples(ecosystem, litmus_class, created_at DESC) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL ` +
			`AND litmus_result IS NOT NULL AND ecosystem <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_top_ready_first_analyzed ` +
			`ON samples(first_analyzed_at DESC, id) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL AND first_analyzed_at IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_top_ready_first_analyzed_coalesce ` +
			`ON samples((COALESCE(first_analyzed_at, analyzed_at)) DESC, id) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL AND COALESCE(first_analyzed_at, analyzed_at) IS NOT NULL`,
		// Workflow dashboard backlog grouping. Keep these separate so each side
		// of the queue can be counted without a heap-wide OR scan.
		`CREATE INDEX IF NOT EXISTS idx_samples_pending_cleave_group ` +
			`ON samples(source, feed, ecosystem, updated_at) ` +
			`WHERE parent = '' AND skip = '' AND cleave_result IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_pending_litmus_group ` +
			`ON samples(source, feed, ecosystem, updated_at) ` +
			`WHERE parent = '' AND skip = '' AND cleave_result IS NOT NULL AND litmus_result IS NULL`,
		`ANALYZE samples`,
		// Traits-version rescan: find analyzed samples with stale traits.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS traits_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS cyclotron_attempted_at TIMESTAMPTZ`,
		// Poison-sample protection: count claims that never produced a result
		// and record skip timing. No dedicated index — the reaper's
		// "attempts >= N" sweep runs every few minutes and rides the existing
		// idx_samples_unanalyzed (the pending set is small), and an index on
		// attempts would take a write on the hot claim path for every bump.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS skipped_at TIMESTAMPTZ`,
		// Covers FP/FN seed queries (falsePositivesPG, falseNegativesPG, light
		// variants, seedCandidatesInPathsPG) ordered by impact. The detection
		// filter (max_crit / suspicious_count) and cyclotron_attempted_at
		// cooldown apply as residual predicates after the indexed scan.
		`CREATE INDEX IF NOT EXISTS idx_samples_seed_pool ` +
			`ON samples(label, litmus_score DESC NULLS LAST, score DESC, analyzed_at ASC NULLS FIRST) ` +
			`WHERE cleave_result IS NOT NULL AND status = '' AND skip = ''`,
		// Covers SamplesInPipelineStage drain (impact-ordered mid-pipeline pull).
		`CREATE INDEX IF NOT EXISTS idx_samples_pipeline_stage ` +
			`ON samples(status, litmus_score DESC NULLS LAST, score DESC, updated_at ASC) ` +
			`WHERE status != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_stale_traits ` +
			`ON samples(traits_version, analyzed_at) ` +
			`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''`,
		// staleTraitsCandidatesPG orders by a priority expression (label-
		// disagreement bucket, then |litmus_score-0.5|, then analyzed_at). The
		// index above is keyed (traits_version, analyzed_at), which can't serve
		// that ordering: with traits_version filtered by inequality (!= current),
		// Postgres scanned every eligible row and top-N sorted the lot — ~3.8M
		// rows / 18s per poll once the backlog aged in, starving every worker
		// that fell through to the rescan tier. This expression index stores rows
		// in the ORDER BY order, so the planner walks it and stops at LIMIT,
		// applying traits_version != current and the age/cooldown as residual
		// filters (both pass for ~all rows, so it terminates after ~LIMIT). The
		// column expressions must stay byte-identical to the ORDER BY in
		// staleTraitsCandidatesPG or the planner won't match them.
		`CREATE INDEX IF NOT EXISTS idx_samples_stale_traits_pri ` +
			`ON samples(` +
			`(CASE WHEN label = 'good' AND (max_crit >= 5 OR suspicious_count >= 2) THEN 0 ` +
			`WHEN label = 'bad' AND max_crit < 5 AND suspicious_count < 2 THEN 0 ELSE 1 END), ` +
			`(ABS(litmus_score - 0.5)), ` +
			`analyzed_at) ` +
			`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''`,
		// feedSourcesPG / feedEcosystemsPG: DISTINCT feed/ecosystem WHERE source = $1.
		`CREATE INDEX IF NOT EXISTS idx_samples_source_feed ON samples(source, feed) WHERE feed != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_source_ecosystem ON samples(source, ecosystem) WHERE ecosystem != ''`,
		// Forager direct-insert provenance. url is the canonical URL the
		// bytes were fetched from; domain is the registered domain (eTLD+1)
		// of that url, populated by the Go writer via publicsuffix.
		// name+version describe the package, enabling supply-chain queries
		// ("same name+version, different SHA-256" = silent payload swap).
		// Per-content (samples-level), not per-observation: the URL bytes
		// "are from" doesn't legitimately vary across re-fetches.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS package TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_domain ON samples(domain) WHERE domain != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_package_version ON samples(package, version) WHERE package != ''`,
		// Collector provenance sidecar (forager) + artifact fetch time. JSONB so
		// the registry/feed records inside are directly queryable.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS provenance JSONB`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS fetched_at TIMESTAMPTZ`,
		`UPDATE samples SET skip = 'skip-benign-archive-item' WHERE skip = 'weak-findings'`,
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
		// Covering index for the reconcile reachability walk (cascadeMembersPG):
		// finding a parent's child sha256 is then index-only — no heap fetch —
		// which is what lets the BFS expand the alive set by index lookups instead
		// of seq-scanning + sorting all of sample_locations.
		`CREATE INDEX IF NOT EXISTS idx_sl_parent_child ON sample_locations(parent_sha256) INCLUDE (sha256) WHERE parent_sha256 <> ''`,
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

		// Logical replication and pg_restore can leave BIGSERIAL sequences
		// behind the restored/copied row ids. Advance only forward so a
		// promoted replica or restored master does not reuse primary keys.
		`SELECT setval('samples_id_seq',
			GREATEST(
				(SELECT COALESCE(max(id), 0) FROM samples),
				(SELECT last_value FROM samples_id_seq)
			),
			true)`,
		`SELECT setval('sample_locations_id_seq',
			GREATEST(
				(SELECT COALESCE(max(id), 0) FROM sample_locations),
				(SELECT last_value FROM sample_locations_id_seq)
			),
			true)`,
		`SELECT setval('reports_id_seq',
			GREATEST(
				(SELECT COALESCE(max(id), 0) FROM reports),
				(SELECT last_value FROM reports_id_seq)
			),
			true)`,

		// Derived analysis columns.
		//
		// EVERY derived column here — litmus_score, file_type, score, formula —
		// is a PLAIN column kept current by a BEFORE INSERT/UPDATE trigger, never
		// a STORED GENERATED column. This is deliberate and load-bearing: adding
		// (or re-adding) a STORED generated column rewrites every row of samples
		// (~350GB) under an ACCESS EXCLUSIVE lock, freezing every reader and
		// writer — workers, the dashboard, even a plain SELECT — until it
		// finishes. See isTableRewriteDDL for the rule and the cheap alternatives.
		//
		// litmus_score: its source key (prob) never moved, so wherever the column
		// is already populated its values are correct. If a prior build left it as
		// a STORED generated column, convert it back in place — ALTER COLUMN …
		// DROP EXPRESSION is metadata-only (no rewrite, existing values retained).
		// The samples_derive_litmus_score trigger below maintains it from here on,
		// and backfillPG fills any rows still sitting at the DEFAULT 0. The base
		// schema already added the plain column, so there is nothing to ADD.
		//
		// file_type / score / formula were ALSO generated, but their expression
		// was pinned to the pre-v7 'fs' envelope key. v7 renamed that key to
		// 'files', so every record stored in the new format generated '' / 0. Same
		// fix: DROP EXPRESSION to a plain column, then derive via the
		// samples_derive_cleave_cols trigger (which reads both the v7 'files' key
		// and the legacy 'fs' key). Existing 'files'-format rows (file_type = '')
		// are healed by the bounded empties backfill in backfillPG.
		//
		// Guard: attgenerated='s' means "stored generated". Each branch is a
		// no-op once the column is already plain (its target state).
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'litmus_score'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples ALTER COLUMN litmus_score DROP EXPRESSION;
				ALTER TABLE samples ALTER COLUMN litmus_score SET DEFAULT 0;
			END IF;

			IF EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'file_type'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples ALTER COLUMN file_type DROP EXPRESSION;
				ALTER TABLE samples ALTER COLUMN file_type SET DEFAULT '';
			END IF;

			IF EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'score'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples ALTER COLUMN score DROP EXPRESSION;
				ALTER TABLE samples ALTER COLUMN score SET DEFAULT 0;
			END IF;

			IF EXISTS (
				SELECT 1 FROM pg_attribute
				 WHERE attrelid = 'samples'::regclass AND attname = 'formula'
				   AND attgenerated = 's'
			) THEN
				ALTER TABLE samples ALTER COLUMN formula DROP EXPRESSION;
				ALTER TABLE samples ALTER COLUMN formula SET DEFAULT '';
			END IF;
		END$$`,

		// Trigger that derives every cleave-sourced column (file_type, score,
		// formula, elements, max_crit, suspicious_count) from the cleave result
		// on every write, reading the v7 'files' key first and falling back to
		// the legacy 'fs' key for cached rows. BEFORE INSERT covers the bulk
		// archive-member insert path (which otherwise never set elements/
		// max_crit/suspicious_count, leaving every member permanently in the
		// backfill-pending set); UPDATE OF cleave_result covers analysis stores
		// without firing on unrelated column updates. Deriving here is cheaper
		// than backfilling: NEW.cleave_result is already in memory, so there is
		// no TOAST re-read. The expressions mirror backfillPG's Pass 1/1b so a
		// row written by the trigger never re-enters either backfill gate.
		//
		// Changing only this function body (not the trigger definition below)
		// keeps redeploys lock-free: CREATE OR REPLACE FUNCTION locks pg_proc,
		// not samples, so it can't be blocked by a long reader.
		`CREATE OR REPLACE FUNCTION samples_derive_cleave_cols() RETURNS trigger
		LANGUAGE plpgsql AS $$
		DECLARE
			finds jsonb := COALESCE(NEW.cleave_result->'files'->0->'find',
									NEW.cleave_result->'fs'->0->'ts', '[]'::jsonb);
		BEGIN
			NEW.file_type := COALESCE(NEW.cleave_result->'files'->0->>'type',
									   NEW.cleave_result->'fs'->0->>'type', '');
			NEW.score := COALESCE((NEW.cleave_result->'files'->0->>'risk')::int,
								   (NEW.cleave_result->'fs'->0->>'x')::int, 0);
			NEW.formula := COALESCE(NEW.cleave_result->'files'->0->>'mol',
									NEW.cleave_result->'fs'->0->>'f', '');
			NEW.elements := translate(NEW.formula, '₀₁₂₃₄₅₆₇₈₉', '');
			NEW.max_crit := COALESCE((
				SELECT MAX((COALESCE(t->>'crit', t->>'l'))::int)
				FROM jsonb_array_elements(finds) AS t
				WHERE COALESCE(t->>'crit', t->>'l') IS NOT NULL), 0);
			NEW.suspicious_count := (
				SELECT COUNT(*)::int
				FROM jsonb_array_elements(finds) AS t
				WHERE COALESCE(t->>'crit', t->>'l') IS NOT NULL
					AND (COALESCE(t->>'crit', t->>'l'))::int >= 4);
			RETURN NEW;
		END;
		$$`,
		`CREATE OR REPLACE TRIGGER samples_derive_cleave_cols_trg
			BEFORE INSERT OR UPDATE OF cleave_result ON samples
			FOR EACH ROW EXECUTE FUNCTION samples_derive_cleave_cols()`,

		// litmus_class is the materialized criticality (0=benign, 1=suspicious,
		// 2=hostile) used to make prism's feed-by-criticality sub-second: it can be
		// an index column (idx_samples_eco_class_created) whereas the equivalent
		// JSONB derivation cannot, so a rare class in a large ecosystem becomes an
		// ordered seek instead of a per-row TOAST read of litmus_result. Nullable
		// with no default so ADD COLUMN is metadata-only (no rewrite) and the
		// backfill gate (litmus_class IS NULL) shrinks monotonically — unlike a
		// NOT NULL DEFAULT 0, which would leave every benign row in the gate to be
		// re-scanned each batch. The derive trigger fills it on every write; the
		// Pass 1d backfill heals pre-trigger rows. feedClassExpr reads it only when
		// the query cutoff equals CriticalLevel (what it is derived against).
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_class SMALLINT`,

		// Derives litmus_score (from litmus_result->>'prob') and litmus_class (the
		// criticality, pinned to CriticalLevel as the hostile/suspicious cutoff) on
		// every write, so both stay plain columns rather than STORED generated ones
		// — which would force a full-table ACCESS EXCLUSIVE rewrite to (re)create
		// (see the DO block above and isTableRewriteDDL). Narrow firing (UPDATE OF
		// litmus_result) keeps result stores cheap and covers the
		// litmus_result := NULL reset in updateCleaveResultPG: litmus_score falls to
		// 0 and litmus_class to 0 (benign), matching the old reset semantics.
		// BEFORE INSERT covers the archive-member insert path. As with
		// samples_derive_cleave_cols, CREATE OR REPLACE FUNCTION locks pg_proc, not
		// samples, so redeploys that change only the body stay lock-free — including
		// a changed CriticalLevel, which just re-runs this and re-heals via Pass 1d.
		// The litmus_class formula mirrors feedClassExpr / workflowSamplesPG exactly.
		fmt.Sprintf(`CREATE OR REPLACE FUNCTION samples_derive_litmus_score() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			NEW.litmus_score := COALESCE((NEW.litmus_result->>'prob')::double precision, 0);
			NEW.litmus_class := COALESCE(
				(NEW.litmus_result->>'class')::smallint,
				CASE
					WHEN NEW.litmus_result IS NULL THEN 0
					WHEN COALESCE(NEW.litmus_result->>'lvl', NEW.litmus_result->>'l') IS NULL THEN 2
					WHEN COALESCE(NEW.litmus_result->>'lvl', NEW.litmus_result->>'l')::int < 0 THEN 0
					WHEN COALESCE(NEW.litmus_result->>'lvl', NEW.litmus_result->>'l')::int <= %d THEN 2
					ELSE 1
				END);
			RETURN NEW;
		END;
		$$`, CriticalLevel),
		`CREATE OR REPLACE TRIGGER samples_derive_litmus_score_trg
			BEFORE INSERT OR UPDATE OF litmus_result ON samples
			FOR EACH ROW EXECUTE FUNCTION samples_derive_litmus_score()`,

		// Indexes on the derived columns (no-op after first creation). These
		// are not cascaded away by DROP EXPRESSION (the columns persist), but
		// the IF NOT EXISTS keeps them correct on a fresh database too.
		`CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type)`,
		`CREATE INDEX IF NOT EXISTS idx_samples_formula   ON samples(formula)   WHERE formula   != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_score     ON samples(score)     WHERE score     != 0`,

		// Drives the one-time Pass 1b heal in backfillPG: rows stored under the
		// v7 'files' key while file_type/score/formula were generated from the
		// legacy 'fs' key, so file_type is '' even though the JSON carries a
		// type. Self-draining — a row leaves the index the moment the backfill
		// (or the derive trigger) sets a non-empty file_type. The predicate
		// must stay in sync with pgFileTypeBackfillWhere. Built CONCURRENTLY by
		// the migration runner, so it never blocks writes.
		`CREATE INDEX IF NOT EXISTS idx_samples_filetype_pending ON samples(sha256) ` +
			`WHERE cleave_result IS NOT NULL AND file_type = '' ` +
			`AND COALESCE(cleave_result->'files'->0->>'type', cleave_result->'fs'->0->>'type', '') <> ''`,

		// Claim state moved to memory (see workerTracker in cmd/hopper/api.go).
		// idx_samples_claimed exists only to serve OldestClaims, which is gone;
		// the claimed_by / claimed_at columns are no longer written. Drop the
		// index now to recover its bloat; the columns can be dropped in a
		// follow-up once we're sure no rollback is needed.
		`DROP INDEX IF EXISTS idx_samples_claimed`,

		// Operator-initiated re-queue (Tier 0). Set by RequestRescan; cleared
		// by updateCleaveResult when a worker submits fresh analysis. Workers
		// drain Tier 0 before the Tier 1 (unanalyzed) backlog so a user-
		// requested rescan jumps the queue regardless of the random SHA-pivot
		// rotation Tier 1 uses. Partial index keeps the scan tiny (the set is
		// transient — entries clear themselves as workers finish them).
		//
		// The predicate intentionally does NOT include `cleave_result IS NULL`:
		// an earlier version did, which forced RequestRescan to null the
		// cached envelope to make a row eligible. That created a window
		// (request → worker finishes) in which readers (litmus, dashboard,
		// API) saw the row as unanalyzed. Keeping cleave_result intact lets
		// the stale-but-real envelope stay visible until updateCleaveResult
		// atomically replaces it.
		// Rescan queue. A pending re-analysis is one row: rescan_priority says
		// which tier drains it (2 = interactive, ahead of the unanalyzed backlog,
		// for a user waiting on prism's rescan button; 1 = bulk/background repair,
		// behind new ingestion, e.g. archives left memberless by the old async
		// explosion; 0 = not queued). rescan_requested_at is when it was queued —
		// FIFO ordering within a tier and operator visibility. Both ADD COLUMNs are
		// metadata-only (constant/NULL default → a brief catalog lock, never a
		// table rewrite). This supersedes the timestamp-only forced_rescan_at,
		// whose "forced = ahead of new" meaning is now priority 2; its handful of
		// pending rows aren't worth preserving, so the column is simply dropped
		// (also a metadata-only operation — the new queue starts empty).
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS rescan_priority SMALLINT NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS rescan_requested_at TIMESTAMPTZ`,
		`DROP INDEX IF EXISTS idx_samples_forced_rescan`,
		`ALTER TABLE samples DROP COLUMN IF EXISTS forced_rescan_at`,
		// Tiny partial index over queued rows only; covers both tier filters
		// (rescan_priority = 1|2) and FIFO ordering by request time. Built
		// CONCURRENTLY by the migration framework, so no lock.
		`CREATE INDEX IF NOT EXISTS idx_samples_rescan_queue ` +
			`ON samples(rescan_priority, rescan_requested_at) WHERE rescan_priority > 0`,

		// Aggressive autovacuum on the hot table. Defaults wait for 20% dead
		// tuples / 10% changed rows before kicking in, which on a 5M-row table
		// means autovacuum lags by a million rows — and a stale visibility map
		// turns "index-only" scans into million-fetch heap probes. With these
		// settings autovacuum reacts at ~100K-row deltas and is given enough
		// cost budget to actually finish a cycle.
		`ALTER TABLE samples SET (
			autovacuum_vacuum_scale_factor = 0.02,
			autovacuum_analyze_scale_factor = 0.02,
			autovacuum_vacuum_insert_scale_factor = 0.02,
			autovacuum_vacuum_cost_limit = 2000
		)`,

		// Internal key/value store. Used for the upload-token bootstrap
		// (prism reads it to discover the bearer token for /api/upload).
		`CREATE TABLE IF NOT EXISTS hopper_kv (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,

		// label_events: append-only audit of every label/skip transition
		// applied by pool reconciliation. Lets a data scientist reconstruct a
		// sample's ground-truth at a point in time and audit demote/conflict/
		// missing decisions; never read on the hot path.
		`CREATE TABLE IF NOT EXISTS label_events (
			id          BIGSERIAL PRIMARY KEY,
			sha256      TEXT NOT NULL,
			from_label  TEXT NOT NULL DEFAULT '',
			to_label    TEXT NOT NULL DEFAULT '',
			from_skip   TEXT NOT NULL DEFAULT '',
			to_skip     TEXT NOT NULL DEFAULT '',
			reason      TEXT NOT NULL,
			observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_label_events_sha ON label_events(sha256, observed_at)`,

		// walk_staging holds (sha256, path) for every standalone file seen in the
		// current walk. Reconciliation anti-joins it against samples to find moved
		// /missing files instead of touching last_seen_at on every cache hit
		// (millions of UPDATEs per walk). UNLOGGED: it is truncated and rebuilt
		// each walk, so crash-durability is pointless and skipping WAL is a big win.
		`CREATE UNLOGGED TABLE IF NOT EXISTS walk_staging (
			sha256 TEXT NOT NULL,
			path   TEXT NOT NULL
		)`,

		// Supports the reconcile anti-join / eligible count over the active
		// top-level working set without scanning the full samples heap.
		`CREATE INDEX IF NOT EXISTS idx_samples_reconcile_toplevel ON samples(sha256)
			WHERE parent = '' AND (skip = '' OR skip = 'conflict')`,
	}
}

// trgmExtensionDDL and trgmIndexDDL back the web-UI filename search
// (FeedQuery.Search's `filename ILIKE '%term%'`): pg_trgm's GIN operator class
// indexes the leading-wildcard substring match a btree can't serve, and the
// partial predicate mirrors the feed query (top-level, analyzed) so the index
// stays small. The extension is applied as core DDL; the GIN index is deferred
// with the other indexes. Both are best-effort — a missing contrib package
// must never crash-loop the ingester; search just falls back to a seq-scan, and
// an unrecorded DDL is retried on a later boot once the extension is installed.
const trgmExtensionDDL = `CREATE EXTENSION IF NOT EXISTS pg_trgm`

const trgmIndexDDL = `CREATE INDEX IF NOT EXISTS idx_samples_filename_trgm ` +
	`ON samples USING gin (filename gin_trgm_ops) ` +
	`WHERE cleave_result IS NOT NULL AND parent = ''`

// isDeferrableIndexDDL reports whether ddl is a CREATE INDEX that can be built
// in the background after the server starts. A missing index only makes
// queries slower; building one on a large table holds an ACCESS-blocking lock
// or a long concurrent scan, which would strand workers if it ran on the
// startup critical path.
func isDeferrableIndexDDL(ddl string) bool {
	return strings.HasPrefix(strings.TrimSpace(ddl), "CREATE INDEX")
}

// migrateServingPG applies the migrations a server needs before it can safely
// accept work — the base schema, columns, and the pg_trgm extension — and
// returns a function that builds the deferrable indexes. The caller runs that
// function in the background once it is serving, so a new index build never
// blocks workers. On an established database every index already exists, so the
// returned function is a fast sequence of ledger-skipped no-ops.
func (db *DB) migrateServingPG(ctx context.Context, allowRewrite bool) (func(context.Context) error, error) {
	if err := db.ensurePGMigrationLedger(ctx); err != nil {
		return nil, fmt.Errorf("hopper: migrate: %w", err)
	}
	// Base schema is ledger-gated like every other migration. Although every
	// statement in it is idempotent (CREATE … IF NOT EXISTS), a no-op CREATE
	// INDEX still takes a ShareLock on samples to perform its check — and that
	// lock request queues behind any open transaction (e.g. a long pool
	// reconcile) and head-of-line-blocks every writer behind it. Skipping the
	// blob outright once it is recorded keeps an unchanged-schema restart
	// completely lock-free.
	if err := db.execPGMigrationDDL(ctx, schemaPG, allowRewrite); err != nil {
		return nil, fmt.Errorf("hopper: migrate: %w", err)
	}

	// Core DDL (columns, tables, cleanup) runs now; index builds are collected
	// for the background phase.
	var deferred []string
	for _, ddl := range pgRuntimeMigrations() {
		if isDeferrableIndexDDL(ddl) {
			deferred = append(deferred, ddl)
			continue
		}
		if err := db.execPGMigrationDDL(ctx, ddl, allowRewrite); err != nil {
			return nil, fmt.Errorf("hopper: migrate: %w", err)
		}
	}

	trgmReady := true
	if err := db.execPGMigrationDDL(ctx, trgmExtensionDDL, allowRewrite); err != nil {
		slog.Warn("optional migration skipped; continuing without it", "ddl", trgmExtensionDDL, "error", err)
		trgmReady = false
	}
	slog.Info("core migrations applied", "deferred_indexes", len(deferred))

	return func(ctx context.Context) error {
		for _, ddl := range deferred {
			if err := db.execPGMigrationDDL(ctx, ddl, allowRewrite); err != nil {
				return fmt.Errorf("hopper: migrate index: %w", err)
			}
		}
		if trgmReady {
			if err := db.execPGMigrationDDL(ctx, trgmIndexDDL, allowRewrite); err != nil {
				slog.Warn("optional migration skipped; continuing without it", "ddl", trgmIndexDDL, "error", err)
			}
		}
		slog.Info("index migrations applied", "count", len(deferred))
		// One-time, chunked, resumable; a non-fatal failure just resumes next
		// boot, so a transient hiccup never blocks startup.
		if err := db.reconcileLocationParentEdges(ctx); err != nil {
			slog.Warn("sample_locations parent-edge backfill incomplete; will resume on next boot", "error", err)
		}
		return nil
	}, nil
}

func (db *DB) execPGMigrationDDL(ctx context.Context, ddl string, allowRewrite bool) error {
	ddl = strings.TrimSpace(ddl)
	id := migrationID(ddl)
	applied, err := db.pgMigrationApplied(ctx, id)
	if err != nil {
		return err
	}
	if applied {
		slog.Debug("migration ddl skipped", "reason", "applied", "id", id, "ddl", ddl)
		return nil
	}

	satisfied, err := db.pgMigrationAlreadySatisfied(ctx, ddl)
	if err != nil {
		return err
	}
	if satisfied {
		if err := db.recordPGMigration(ctx, id, ddl); err != nil {
			return err
		}
		slog.Info("migration ddl already satisfied", "id", id, "ddl", ddl)
		return nil
	}

	// This statement is genuinely about to execute (not applied, not already
	// satisfied). A table-rewriting migration takes ACCESS EXCLUSIVE on samples
	// for the length of the rewrite, locking out every reader and writer (see
	// isTableRewriteDDL). An empty table rewrites instantly, so that is always
	// allowed; on a populated table we refuse unless the operator has explicitly
	// arranged a maintenance window:
	//   - serving path (load/serve, allowRewrite=false): never rewrites — defer
	//     to an explicit `hopper init`.
	//   - init/import (allowRewrite=true): refuse unless HOPPER_FORCE_REWRITE=1,
	//     so a stray `hopper init`/`import` pointed at a live database (the
	//     incident that froze the primary for 44 minutes) errors up front instead
	//     of locking everyone out. The operator stops the workers, sets the flag,
	//     and runs it in a window.
	if isTableRewriteDDL(ddl) {
		nonEmpty, err := db.pgSamplesNonEmpty(ctx)
		if err != nil {
			return err
		}
		// A populated table is the only dangerous case; an empty one rewrites
		// instantly. The serving path never rewrites a populated table; the
		// init/import/migrate path may, but only with an explicit opt-in.
		if nonEmpty && !allowRewrite {
			return fmt.Errorf("hopper: refusing table-rewriting migration %s on a populated samples table while serving; "+
				"run `hopper init` in a maintenance window first", id)
		}
		if nonEmpty && allowRewrite && os.Getenv("HOPPER_FORCE_REWRITE") != "1" {
			return fmt.Errorf("hopper: refusing table-rewriting migration %s on a populated samples table: "+
				"it would hold ACCESS EXCLUSIVE and lock out every reader and writer (workers, dashboard, even plain SELECTs) "+
				"for the length of the rewrite. Stop the workers/server and re-run with HOPPER_FORCE_REWRITE=1 in a maintenance window", id)
		}
	}

	if idx, ok := concurrentIndexDDL(ddl); ok {
		if err := db.createIndexConcurrently(ctx, ddl, idx); err != nil {
			return err
		}
		return db.recordPGMigration(ctx, id, ddl)
	}

	start := time.Now()
	slog.Info("executing migration ddl", "id", id, "ddl", ddl)
	if err := db.execMigrationWithLockRetry(ctx, ddl); err != nil {
		return err
	}
	elapsed := time.Since(start)
	if err := db.recordPGMigration(ctx, id, ddl); err != nil {
		return err
	}
	slog.Info("migration ddl complete", "id", id, "elapsed", elapsed.String())
	return nil
}

const (
	// migrationLockTimeout bounds how long one migration attempt waits for its
	// table lock. Kept short so a waiting ACCESS EXCLUSIVE never queues readers
	// for long; the metadata change itself is instant once the lock is held.
	migrationLockTimeout = 3 * time.Second
	// migrationLockAttempts is the initial try plus retries. The rescan-column
	// migration is metadata-only but still needs a brief ACCESS EXCLUSIVE, which
	// can lose the race to a long-running reader on a perpetually-busy table;
	// retrying lets a single contended boot succeed instead of failing startup.
	migrationLockAttempts = 4 // 1 try + 3 retries
	// migrationLockBackoff lets the blocking reader drain between attempts.
	migrationLockBackoff = 2 * time.Second
)

// execMigrationWithLockRetry runs one migration statement under a short
// per-statement lock_timeout, retrying on lock_not_available (SQLSTATE 55P03).
// DDL here is metadata-only (ADD/DROP COLUMN, CREATE/REPLACE FUNCTION/TRIGGER) —
// instant once its brief lock is held — but acquiring that lock on a
// continuously-read table can time out behind a long reader. A short timeout
// keeps a waiting exclusive from stalling readers for long, and the back-off
// lets the blocker finish before the next try, so a busy first deploy no longer
// fails startup. Concurrent index builds take a different path (createIndex
// Concurrently) and never reach here.
func (db *DB) execMigrationWithLockRetry(ctx context.Context, ddl string) error {
	var lastErr error
	for attempt := 1; attempt <= migrationLockAttempts; attempt++ {
		err := func() error {
			tx, err := db.pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds
			// set_config(..., true) is SET LOCAL — scoped to this transaction, so
			// it never leaks the short timeout onto the pooled connection.
			if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
				strconv.FormatInt(migrationLockTimeout.Milliseconds(), 10)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, ddl); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" { // lock_not_available
			return err
		}
		lastErr = err
		slog.Warn("migration ddl lost the lock race; retrying",
			"attempt", attempt, "max", migrationLockAttempts, "error", err)
		if attempt < migrationLockAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(migrationLockBackoff):
			}
		}
	}
	return fmt.Errorf("hopper: migration ddl could not acquire its lock after %d attempts: %w", migrationLockAttempts, lastErr)
}

func (db *DB) ensurePGMigrationLedger(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS hopper_migrations (
			id         TEXT PRIMARY KEY,
			ddl        TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	return err
}

func migrationID(ddl string) string {
	sum := cryptosha256.Sum256([]byte(normalizeMigrationDDL(ddl)))
	return hex.EncodeToString(sum[:8])
}

func normalizeMigrationDDL(ddl string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(ddl)), " ")
}

func (db *DB) pgMigrationApplied(ctx context.Context, id string) (bool, error) {
	var applied bool
	if err := db.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM hopper_migrations WHERE id = $1)`, id).Scan(&applied); err != nil {
		return false, err
	}
	return applied, nil
}

func (db *DB) recordPGMigration(ctx context.Context, id, ddl string) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO hopper_migrations (id, ddl)
		VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE
		SET ddl = EXCLUDED.ddl,
		    applied_at = now()`,
		id, ddl)
	return err
}

func (db *DB) pgMigrationAlreadySatisfied(ctx context.Context, ddl string) (bool, error) {
	// The cleave-derived-column conversion is a DO block of metadata-only ALTERs
	// (DROP EXPRESSION / SET DEFAULT). The migration ledger keys on a hash of the
	// DDL text, so an unrelated edit to this block's comments changes its hash and
	// the "already applied" lookup misses — re-running the block needlessly takes a
	// brief ACCESS EXCLUSIVE lock on a live table. Gate it on the catalog instead:
	// when samples is already in the converted end-state every branch of the
	// block is a guaranteed no-op, so record it satisfied without executing it.
	if isCleaveDeriveColumnsDDL(ddl) {
		return db.pgCleaveDeriveColumnsConverted(ctx)
	}
	switch normalizeMigrationDDL(ddl) {
	case `ALTER TABLE samples ADD COLUMN IF NOT EXISTS traits_version TEXT NOT NULL DEFAULT ''`:
		return db.pgColumnExists(ctx, "samples", "traits_version")
	default:
		return false, nil
	}
}

// isTableRewriteDDL reports whether a migration statement would rewrite the
// whole samples table under an ACCESS EXCLUSIVE lock — the single most
// dangerous thing a migration can do to this database.
//
// ⚠️  LOCKOUT HAZARD — READ THIS BEFORE ADDING A MIGRATION  ⚠️
//
// A statement that rewrites samples holds ACCESS EXCLUSIVE for the ENTIRE
// rewrite — minutes to hours on a ~350GB table. For that whole window every
// reader and writer blocks: workers storing results, the dashboard, and even a
// plain SELECT (a bare read normally never waits on row locks, but it cannot get
// its ACCESS SHARE lock while a rewrite holds ACCESS EXCLUSIVE). They then fail
// with lock_timeout (SQLSTATE 55P03). One such statement — a STORED generated
// column re-created by `hopper init` against the live primary — froze all
// ingestion for 44 minutes. Do not add another.
//
// Operations that FORCE a full rewrite of samples (never do these here):
//   - ADD COLUMN ... GENERATED ALWAYS AS (...) STORED  — computes every row
//   - ALTER COLUMN ... TYPE / SET DATA TYPE            — re-encodes every row
//   - ADD COLUMN ... DEFAULT <volatile expr>           — evaluated per row
//
// Cheap, rewrite-FREE alternatives — always prefer these:
//   - A PLAIN column kept current by a BEFORE INSERT/UPDATE trigger (see
//     samples_derive_cleave_cols and samples_derive_litmus_score), plus a
//     batched online backfill in backfillPG for historical rows (row locks
//     only — never blocks readers, yields to writers). This is how EVERY
//     derived column here is maintained; never a STORED generated column.
//   - ADD COLUMN with a constant default (PG11+ records it in the catalog: a
//     fast metadata change, not a rewrite).
//   - ALTER COLUMN ... DROP EXPRESSION (metadata-only; retains existing values).
//
// Anything this returns true for is refused on a populated samples table while
// other client backends are connected — on the serving path always, and on the
// init/import/migrate path unless HOPPER_FORCE_REWRITE=1 (run it in a real
// maintenance window with workers stopped). See execPGMigrationDDL. Keep this
// conservative but correct: a false negative re-opens the lockout.
func isTableRewriteDDL(ddl string) bool {
	u := strings.ToUpper(ddl)
	if !strings.Contains(u, "SAMPLES") {
		return false
	}
	// (Re)creating a STORED generated column recomputes and rewrites every row.
	if strings.Contains(u, "GENERATED ALWAYS AS") && strings.Contains(u, "STORED") {
		return true
	}
	// A column type change re-encodes every row.
	if strings.Contains(u, "ALTER COLUMN") &&
		(strings.Contains(u, " TYPE ") || strings.Contains(u, "SET DATA TYPE")) {
		return true
	}
	return false
}

// pgSamplesNonEmpty reports whether the samples table holds at least one row.
// EXISTS stops at the first row, so this stays cheap on a huge table. samples is
// always present here: the base schema (which creates it) runs before any
// rewrite-class migration.
func (db *DB) pgSamplesNonEmpty(ctx context.Context) (bool, error) {
	var nonEmpty bool
	if err := db.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM samples)`).Scan(&nonEmpty); err != nil {
		return false, err
	}
	return nonEmpty, nil
}

// isCleaveDeriveColumnsDDL identifies the one-time DO block that converts the
// cleave-derived columns (litmus_score, file_type, score, formula) to their
// plain, trigger-fed shape. Matched on stable column references rather than
// exact text so a comment edit can never slip the block past
// pgMigrationAlreadySatisfied. The block touches litmus_score and is the only
// migration that issues DROP EXPRESSION, so those two markers identify it
// uniquely.
func isCleaveDeriveColumnsDDL(ddl string) bool {
	return strings.Contains(ddl, "litmus_score") &&
		strings.Contains(ddl, "DROP EXPRESSION")
}

// pgCleaveDeriveColumnsConverted reports whether samples is already in the
// end-state the cleave-derive DO block produces: litmus_score, file_type, score
// and formula are ALL plain columns (fed by the samples_derive_litmus_score and
// samples_derive_cleave_cols triggers), none STORED-generated. In that state
// every branch of the block is a no-op, so skipping it is equivalent to running
// it. Returns false (run the block) on a database where any column is still
// generated, where the conversion is genuinely still needed.
func (db *DB) pgCleaveDeriveColumnsConverted(ctx context.Context) (bool, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT attname, attgenerated::text FROM pg_attribute
		WHERE attrelid = to_regclass('samples')
		  AND attname IN ('litmus_score', 'file_type', 'score', 'formula')
		  AND NOT attisdropped`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	gen := make(map[string]string, 4)
	for rows.Next() {
		var name, generated string
		if err := rows.Scan(&name, &generated); err != nil {
			return false, err
		}
		gen[name] = generated
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	// All four columns must already exist and be plain (attgenerated anything
	// but 's'); only then is the block inert.
	return len(gen) == 4 &&
		gen["litmus_score"] != "s" &&
		gen["file_type"] != "s" &&
		gen["score"] != "s" &&
		gen["formula"] != "s", nil
}

func (db *DB) pgColumnExists(ctx context.Context, table, column string) (bool, error) {
	var exists bool
	err := db.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_attribute
			WHERE attrelid = to_regclass($1)
			  AND attname = $2
			  AND NOT attisdropped
		)`, table, column).Scan(&exists)
	return exists, err
}

func concurrentIndexDDL(ddl string) (string, bool) {
	const prefix = "CREATE INDEX IF NOT EXISTS "
	if !strings.HasPrefix(ddl, prefix) {
		return "", false
	}
	fields := strings.Fields(ddl)
	if len(fields) < 6 {
		return "", false
	}
	return fields[5], true
}

func (db *DB) createIndexConcurrently(ctx context.Context, ddl, indexName string) error {
	// CREATE/DROP INDEX CONCURRENTLY briefly needs ShareUpdateExclusive and waits
	// for concurrent transactions to drain. The server-wide lock_timeout (kept low
	// to protect the hot write path) would otherwise cancel the build with
	// SQLSTATE 55P03 — exactly what failed idx_sl_parent_child against a busy
	// 105M-row table. Run the build on a dedicated connection with lock_timeout
	// disabled, resetting it before the connection returns to the pool so no other
	// caller inherits an unbounded lock wait. CONCURRENTLY can't run in a
	// transaction, so each statement auto-commits on this connection.
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if _, derr := conn.Exec(context.WithoutCancel(ctx), `SET lock_timeout = DEFAULT`); derr != nil {
			slog.Warn("failed to reset lock_timeout after index build; dropping connection", "error", derr)
			conn.Conn().Close(context.WithoutCancel(ctx)) //nolint:errcheck,gosec // discarding the tainted conn
		}
		conn.Release()
	}()
	if _, err := conn.Exec(ctx, `SET lock_timeout = 0`); err != nil {
		return fmt.Errorf("hopper: disable lock_timeout for index build: %w", err)
	}

	invalid, err := db.invalidPGIndex(ctx, indexName)
	if err != nil {
		return err
	}
	if invalid {
		drop := "DROP INDEX CONCURRENTLY IF EXISTS " + indexName
		slog.Info("dropping invalid migration index", "index", indexName, "ddl", drop)
		if _, err := conn.Exec(ctx, drop); err != nil {
			return err
		}
	}

	ddl = strings.Replace(ddl, "CREATE INDEX IF NOT EXISTS ", "CREATE INDEX CONCURRENTLY IF NOT EXISTS ", 1)
	start := time.Now()
	slog.Info("executing migration ddl", "ddl", ddl)
	if _, err := conn.Exec(ctx, ddl); err != nil {
		return err
	}
	slog.Info("migration ddl complete", "elapsed", time.Since(start).String())
	return nil
}

func (db *DB) invalidPGIndex(ctx context.Context, indexName string) (bool, error) {
	var invalid bool
	if err := db.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM pg_class c
			  JOIN pg_namespace n ON n.oid = c.relnamespace
			  JOIN pg_index i ON i.indexrelid = c.oid
			 WHERE n.nspname = current_schema()
			   AND c.relname = $1
			   AND NOT i.indisvalid
		)`, indexName).Scan(&invalid); err != nil {
		return false, err
	}
	return invalid, nil
}

const pgSampleCols = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, cleave_result, litmus_result, llm_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime, traits_version,
	url, domain, package, version`

// pgSampleColsLight excludes cleave_result and litmus_result to avoid loading
// potentially large JSON blobs when only metadata is needed (e.g. claim queries).
const pgSampleColsLight = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime, traits_version,
	url, domain, package, version`

func pgSampleDest(s *Sample) []any {
	return []any{
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.CleaveResult, &s.LitmusResult, &s.LLMResult, &s.LitmusScore,
		&s.Path, &s.Status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score,
		&s.MaxCrit, &s.SuspiciousCount,
		&s.CreatedAt, &s.UpdatedAt, &s.AnalyzedAt, &s.FirstAnalyzedAt, &s.LastErrorAt, &s.Mtime, &s.MarkerMtime,
		&s.TraitsVersion,
		&s.URL, &s.Domain, &s.Package, &s.Version,
	}
}

func pgSampleDestLight(s *Sample) []any {
	return []any{
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.LitmusScore,
		&s.Path, &s.Status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score,
		&s.MaxCrit, &s.SuspiciousCount,
		&s.CreatedAt, &s.UpdatedAt, &s.AnalyzedAt, &s.FirstAnalyzedAt, &s.LastErrorAt, &s.Mtime, &s.MarkerMtime,
		&s.TraitsVersion,
		&s.URL, &s.Domain, &s.Package, &s.Version,
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
	s.restoreJSONB()
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
		s.restoreJSONB()
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

func (db *DB) workflowHealthPG(ctx context.Context) (WorkflowHealth, error) {
	var h WorkflowHealth
	var latestAdded, latestUpdated, latestAnalyzed, latestReady sql.NullTime
	err := db.pool.QueryRow(ctx, `
		SELECT
			(SELECT created_at FROM samples WHERE parent = '' ORDER BY created_at DESC LIMIT 1),
			(SELECT max(updated_at) FROM samples WHERE parent = ''),
			(SELECT max(analyzed_at) FROM samples WHERE parent = '' AND analyzed_at IS NOT NULL),
			(SELECT COALESCE(first_analyzed_at, analyzed_at) FROM samples
				WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL
					AND COALESCE(first_analyzed_at, analyzed_at) IS NOT NULL
				ORDER BY COALESCE(first_analyzed_at, analyzed_at) DESC LIMIT 1),
			(SELECT count(*) FROM samples WHERE parent = '' AND skip = '' AND cleave_result IS NULL),
			(SELECT count(*) FROM samples WHERE parent = '' AND skip = '' AND cleave_result IS NOT NULL AND litmus_result IS NULL)`,
	).Scan(&latestAdded, &latestUpdated, &latestAnalyzed, &latestReady, &h.PendingCleave, &h.PendingLitmus)
	if err != nil {
		return h, fmt.Errorf("hopper: workflow health: %w", err)
	}
	h.LatestAdded = nullTime(latestAdded)
	h.LatestUpdated = nullTime(latestUpdated)
	h.LatestAnalyzed = nullTime(latestAnalyzed)
	h.LatestReady = nullTime(latestReady)
	return h, nil
}

func (db *DB) workflowBacklogsPG(ctx context.Context, limit int) ([]WorkflowBacklog, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT source, feed, ecosystem,
			min(updated_at), max(updated_at),
			sum(pending_cleave), sum(pending_litmus)
		FROM (
			SELECT source, feed, ecosystem, updated_at,
				1::integer AS pending_cleave,
				0::integer AS pending_litmus
			FROM samples
			WHERE parent = '' AND skip = '' AND cleave_result IS NULL
			UNION ALL
			SELECT source, feed, ecosystem, updated_at,
				0::integer AS pending_cleave,
				1::integer AS pending_litmus
			FROM samples
			WHERE parent = '' AND skip = ''
			  AND cleave_result IS NOT NULL AND litmus_result IS NULL
		) pending
		GROUP BY source, feed, ecosystem
		ORDER BY (sum(pending_cleave) + sum(pending_litmus)) DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: workflow backlogs: %w", err)
	}
	defer rows.Close()
	out := make([]WorkflowBacklog, 0, limit)
	for rows.Next() {
		var b WorkflowBacklog
		var oldest, newest sql.NullTime
		if err := rows.Scan(&b.Source, &b.Feed, &b.Ecosystem, &oldest, &newest, &b.PendingCleave, &b.PendingLitmus); err != nil {
			return nil, fmt.Errorf("hopper: scan workflow backlog: %w", err)
		}
		b.OldestPending = nullTime(oldest)
		b.NewestPending = nullTime(newest)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (db *DB) workflowLatestAddedPG(ctx context.Context, limit int) ([]WorkflowSample, error) {
	return db.workflowSamplesPG(ctx, `WHERE parent = '' ORDER BY created_at DESC LIMIT $1`, limit)
}

func (db *DB) workflowLatestReadyPG(ctx context.Context, limit int) ([]WorkflowSample, error) {
	return db.workflowSamplesPG(ctx,
		`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL `+
			`AND COALESCE(first_analyzed_at, analyzed_at) IS NOT NULL `+
			`ORDER BY COALESCE(first_analyzed_at, analyzed_at) DESC, id LIMIT $1`, limit)
}

func (db *DB) workflowOldestPendingPG(ctx context.Context, limit int) ([]WorkflowSample, error) {
	return db.workflowSamplesPG(ctx,
		`WHERE parent = '' AND cleave_result IS NULL AND skip = '' ORDER BY updated_at ASC NULLS FIRST, id LIMIT $1`, limit)
}

func (db *DB) workflowSamplesPG(ctx context.Context, where string, limit int) ([]WorkflowSample, error) {
	rows, err := db.pool.Query(ctx, fmt.Sprintf(`
		SELECT sha256, source, feed, ecosystem, filename, path,
			created_at, updated_at, analyzed_at, COALESCE(first_analyzed_at, analyzed_at),
			cleave_result IS NOT NULL,
			litmus_result IS NOT NULL,
			-- Criticality (0=benign, 1=suspicious, 2=hostile): legacy records
			-- (v4/v5) carried class directly; v6/v7 use lvl/l (the strictest
			-- grid level at which the file fires, or -1 for never-fires). Try
			-- class first; otherwise derive from the level using CriticalLevel %d as
			-- the hostile/suspicious cutoff (null is manual-mode hostile,
			-- treated as hostile fail-safe).
			COALESCE(
				(litmus_result->>'class')::int,
				CASE
					WHEN litmus_result IS NULL THEN 0
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l') IS NULL THEN 2
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int < 0 THEN 0
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int <= %d THEN 2
					ELSE 1
				END
			)
		FROM samples `+where, CriticalLevel, CriticalLevel), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: workflow samples: %w", err)
	}
	defer rows.Close()
	return scanWorkflowSamplesPG(rows, limit)
}

func scanWorkflowSamplesPG(rows pgx.Rows, limit int) ([]WorkflowSample, error) {
	out := make([]WorkflowSample, 0, limit)
	for rows.Next() {
		var s WorkflowSample
		var analyzed, firstAnalyzed sql.NullTime
		if err := rows.Scan(&s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename, &s.Path,
			&s.CreatedAt, &s.UpdatedAt, &analyzed, &firstAnalyzed, &s.HasCleave, &s.HasLitmus, &s.Criticality); err != nil {
			return nil, fmt.Errorf("hopper: scan workflow sample: %w", err)
		}
		if analyzed.Valid {
			s.AnalyzedAt = &analyzed.Time
		}
		if firstAnalyzed.Valid {
			s.FirstAnalyzedAt = &firstAnalyzed.Time
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func nullTime(t sql.NullTime) time.Time {
	if t.Valid {
		return t.Time
	}
	return time.Time{}
}

func (db *DB) insertSampleNewPG(ctx context.Context, s *Sample) (bool, error) {
	s.scrubNULs() // PG TEXT can't hold 0x00 (SQLSTATE 22021); see scrubNULs.
	// One transaction so the sample row and its sample_locations
	// observation are created (or rolled back) atomically.
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("hopper: begin insert: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	// cleave_result and litmus_result are the only analysis fields the
	// writer sets — file_type, score, formula are derived DB-side by the
	// samples_derive_cleave_cols trigger and litmus_score by the
	// samples_derive_litmus_score trigger, so the writer never sets them. ON
	// CONFLICT leaves existing analysis alone
	// so a walker-comes-after-Explode case doesn't wipe real results.
	tag, err := tx.Exec(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename,
			size_bytes, label, label_source, path, status,
			canonical_sha256, parent, skip, elements,
			max_crit, suspicious_count, mtime, marker_mtime,
			cleave_result, litmus_result,
			url, domain, package, version, provenance, fetched_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$1, $11, $12, $13, $14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25)
		`+sampleConflictUpdatePG,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
		s.Parent, s.Skip, s.Elements,
		s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
		sanitizeJSONB(s.CleaveResult), sanitizeJSONB(s.LitmusResult),
		s.URL, s.Domain, s.Package, s.Version, sanitizeJSONB(s.Provenance), s.FetchedAt)
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
				source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE sample_locations.source END,
				feed = CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE sample_locations.feed END,
				ecosystem = CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE sample_locations.ecosystem END,
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

// refreshStaleMemberAnalysisPG rewrites analysis columns for rows whose stored
// analysis is older than the incoming one, in a single set-based UPDATE. Only
// cleave_result/litmus_result/analyzed_at move; the samples_derive_cleave_cols
// trigger re-derives file_type/max_crit/etc since it fires on UPDATE OF
// cleave_result. litmus_result keeps its stored value when the incoming member
// carries none, so a refresh never blanks a classification.
func (db *DB) refreshStaleMemberAnalysisPG(ctx context.Context, rows []staleRefresh) (int64, error) {
	shas := make([]string, len(rows))
	cleaves := make([]string, len(rows))
	litmus := make([]*string, len(rows))
	ats := make([]time.Time, len(rows))
	for i, r := range rows {
		shas[i] = r.SHA256
		cleaves[i] = string(sanitizeJSONB(r.CleaveResult))
		if len(r.LitmusResult) > 0 {
			s := string(sanitizeJSONB(r.LitmusResult))
			litmus[i] = &s
		}
		ats[i] = r.AnalyzedAt
	}
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples s SET
			cleave_result = d.cleave::jsonb,
			litmus_result = COALESCE(d.litmus::jsonb, s.litmus_result),
			analyzed_at   = d.at
		FROM (
			SELECT unnest($1::text[])        AS sha256,
			       unnest($2::text[])        AS cleave,
			       unnest($3::text[])        AS litmus,
			       unnest($4::timestamptz[]) AS at
		) d
		WHERE s.sha256 = d.sha256
		  AND (s.analyzed_at IS NULL OR d.at > s.analyzed_at)`,
		shas, cleaves, litmus, ats)
	if err != nil {
		return 0, fmt.Errorf("hopper: refresh stale member analysis: %w", err)
	}
	return tag.RowsAffected(), nil
}

var insertBatchStagingCols = []string{
	"sha256", "source", "feed", "ecosystem", "filename",
	"size_bytes", "label", "label_source", "path", "status", "canonical_sha256",
	"parent", "skip", "elements", "max_crit", "suspicious_count",
	"mtime", "marker_mtime", "cleave_result", "litmus_result", "analyzed_at", "first_analyzed_at",
	"url", "domain", "package", "version", "provenance", "fetched_at",
}

const insertBatchStagingDDL = `CREATE TEMP TABLE _staging (
	sha256 TEXT, source TEXT, feed TEXT, ecosystem TEXT, filename TEXT,
	size_bytes BIGINT, label TEXT, label_source TEXT,
	path TEXT, status TEXT, canonical_sha256 TEXT,
	parent TEXT, skip TEXT, elements TEXT,
	max_crit INTEGER, suspicious_count INTEGER,
	mtime TIMESTAMPTZ, marker_mtime TIMESTAMPTZ,
	cleave_result JSONB, litmus_result JSONB, analyzed_at TIMESTAMPTZ, first_analyzed_at TIMESTAMPTZ,
	url TEXT, domain TEXT, package TEXT, version TEXT, provenance JSONB, fetched_at TIMESTAMPTZ
) ON COMMIT DROP`

// file_type, score, formula are derived DB-side by the
// samples_derive_cleave_cols trigger and litmus_score by the
// samples_derive_litmus_score trigger, all from cleave_result / litmus_result.
// We don't reference them here — the triggers own them.
// ON CONFLICT leaves existing analysis alone: a walker row arriving
// after Explode must not wipe results we already stored.
// sampleConflictUpdatePG is the shared ON CONFLICT clause for top-level
// re-observations, used by both the single-row (insertSampleNewPG) and batch
// (insertBatchStagingInsert) upserts so their resolution logic can't drift.
//
// Pool-precedence label resolution (rank: bad>good>unknown), evaluated in
// order — see classifyLabelTransition for the mirror used by logging:
//  1. incoming marker present        → take the marker's label, re-quarantine
//  2. stored marker, none incoming   → marker gone, the directory governs again
//  3. good+bad across pools          → resolve to bad, quarantine as 'conflict'
//  4. incoming outranks stored       → promote
//  5. otherwise                      → keep the stored label
//
// Only walker writes (parent=”) may touch the row; explode writes
// (parent=<archive-sha>) are excluded by the WHERE so an archive member never
// changes a top-level label or clobbers its path on a content-hash collision.
const sampleConflictUpdatePG = `ON CONFLICT (sha256) DO UPDATE SET
	label = CASE
		WHEN EXCLUDED.label_source = 'marker' THEN EXCLUDED.label
		WHEN samples.label_source = 'marker' THEN EXCLUDED.label
		WHEN (samples.label = 'good' AND EXCLUDED.label = 'bad')
		  OR (samples.label = 'bad' AND EXCLUDED.label = 'good') THEN 'bad'
		WHEN (CASE EXCLUDED.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		   > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END) THEN EXCLUDED.label
		ELSE samples.label
	END,
	label_source = CASE
		WHEN EXCLUDED.label_source = 'marker' THEN 'marker'
		WHEN samples.label_source = 'marker' THEN EXCLUDED.label_source
		WHEN (samples.label = 'good' AND EXCLUDED.label = 'bad')
		  OR (samples.label = 'bad' AND EXCLUDED.label = 'good') THEN 'conflict'
		WHEN (CASE EXCLUDED.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		   > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END) THEN EXCLUDED.label_source
		ELSE samples.label_source
	END,
	feed  = CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE samples.feed END,
	ecosystem = CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE samples.ecosystem END,
	path  = CASE WHEN EXCLUDED.path  <> ''   THEN EXCLUDED.path  ELSE samples.path  END,
	mtime = CASE WHEN EXCLUDED.mtime IS NOT NULL THEN EXCLUDED.mtime ELSE samples.mtime END,
	url     = CASE WHEN samples.url     = '' THEN EXCLUDED.url     ELSE samples.url     END,
	domain  = CASE WHEN samples.domain  = '' THEN EXCLUDED.domain  ELSE samples.domain  END,
	package    = CASE WHEN samples.package    = '' THEN EXCLUDED.package    ELSE samples.package    END,
	version = CASE WHEN samples.version = '' THEN EXCLUDED.version ELSE samples.version END,
	-- Capture-time provenance is written once by the collector's direct-insert;
	-- a later walk carries none, so keep whatever is already there.
	provenance = CASE WHEN samples.provenance IS NOT NULL THEN samples.provenance ELSE EXCLUDED.provenance END,
	fetched_at = CASE WHEN samples.fetched_at IS NOT NULL THEN samples.fetched_at ELSE EXCLUDED.fetched_at END,
	-- Label-related skips ('misclassified'/'conflict') track the resolution;
	-- the walker also clears 'missing'/'unsupported' so a re-observed file
	-- rejoins the analysis queue. Hard skips (corrupt/encrypted/replaced/
	-- empty_path/skip-benign-archive-item) stick. See insertSampleNewPG.
	skip  = CASE
		WHEN EXCLUDED.label_source = 'marker' THEN 'misclassified'
		WHEN samples.label_source = 'marker' AND samples.skip = 'misclassified' THEN ''
		WHEN ((samples.label = 'good' AND EXCLUDED.label = 'bad')
		   OR (samples.label = 'bad' AND EXCLUDED.label = 'good'))
		  AND samples.skip IN ('', 'misclassified', 'conflict', 'missing', 'unsupported') THEN 'conflict'
		WHEN (CASE EXCLUDED.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		   > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		  AND samples.skip IN ('misclassified', 'conflict') THEN ''
		WHEN samples.skip IN ('missing','unsupported') THEN ''
		ELSE samples.skip
	END
WHERE EXCLUDED.parent = ''
  AND ((EXCLUDED.path  <> ''   AND samples.path  IS DISTINCT FROM EXCLUDED.path)
    OR (EXCLUDED.mtime IS NOT NULL AND samples.mtime IS DISTINCT FROM EXCLUDED.mtime)
    OR (EXCLUDED.feed <> '' AND samples.feed IS DISTINCT FROM EXCLUDED.feed)
    OR (EXCLUDED.ecosystem <> '' AND samples.ecosystem IS DISTINCT FROM EXCLUDED.ecosystem)
    OR (samples.url = '' AND EXCLUDED.url <> '')
    OR (samples.package = '' AND EXCLUDED.package <> '')
    OR samples.skip IN ('missing','unsupported')
    -- Pool-precedence transitions must fire even when path/mtime are unchanged.
    OR ((CASE EXCLUDED.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
      > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END))
    OR ((samples.label = 'good' AND EXCLUDED.label = 'bad')
      OR (samples.label = 'bad' AND EXCLUDED.label = 'good'))
    OR (EXCLUDED.label_source = 'marker'
        AND (samples.label <> EXCLUDED.label OR samples.label_source <> 'marker' OR samples.skip <> 'misclassified'))
    OR (samples.label_source = 'marker' AND EXCLUDED.label_source <> 'marker'))`

const insertBatchStagingInsert = `INSERT INTO samples (
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result, analyzed_at, first_analyzed_at,
	url, domain, package, version, provenance, fetched_at)
SELECT DISTINCT ON (sha256)
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result, analyzed_at, first_analyzed_at,
	url, domain, package, version, provenance, fetched_at
FROM _staging
` + sampleConflictUpdatePG

// logLabelTransitionsPG logs each top-level re-observation in _staging whose
// label resolution will change under sampleConflictUpdatePG. The filter mirrors
// classifyLabelTransition's true-cases so every returned row is log-worthy.
// Best-effort: the upsert is authoritative, so a query error is logged and
// ignored rather than failing the batch.
func logLabelTransitionsPG(ctx context.Context, tx pgx.Tx) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT ON (st.sha256)
			st.sha256, st.path, s.label, s.label_source, s.skip, st.label, st.label_source
		FROM _staging st
		JOIN samples s ON s.sha256 = st.sha256
		WHERE st.parent = '' AND s.parent = ''
		  AND st.label_source <> 'marker'
		  AND ((s.label_source = 'marker' AND (s.label <> st.label OR s.skip = 'misclassified'))
		    OR (s.label_source <> 'marker'
		        AND ((s.label = 'good' AND st.label = 'bad')
		          OR (s.label = 'bad' AND st.label = 'good')
		          OR (CASE st.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		           > (CASE s.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END))))`)
	if err != nil {
		slog.Warn("label transition log query failed", "error", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sha, path, sLabel, sSrc, sSkip, inLabel, inSrc string
		if err := rows.Scan(&sha, &path, &sLabel, &sSrc, &sSkip, &inLabel, &inSrc); err != nil {
			slog.Warn("label transition scan failed", "error", err)
			return
		}
		logLabelTransition(sha, path, sLabel, sSrc, sSkip, inLabel, inSrc)
	}
}

// sampleStagingRows builds the COPY tuples for the _staging temp table in
// insertBatchStagingCols order. Shared by insertSampleBatchPG and storeResultPG
// so the column order can't drift between the two writers.
func sampleStagingRows(samples []*Sample) [][]any {
	rows := make([][]any, len(samples))
	for i, s := range samples {
		s.scrubNULs() // PG TEXT can't hold 0x00 (SQLSTATE 22021); see scrubNULs.
		firstAnalyzedAt := s.FirstAnalyzedAt
		if firstAnalyzedAt == nil {
			firstAnalyzedAt = s.AnalyzedAt
		}
		rows[i] = []any{
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256,
			s.Parent, s.Skip, s.Elements, s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
			sanitizeJSONB(s.CleaveResult), sanitizeJSONB(s.LitmusResult), s.AnalyzedAt, firstAnalyzedAt,
			s.URL, s.Domain, s.Package, s.Version, sanitizeJSONB(s.Provenance), s.FetchedAt,
		}
	}
	return rows
}

// locationsFromStagingPG fans _staging rows out into sample_locations. DISTINCT
// ON collapses duplicates within the batch; ON CONFLICT bumps last_seen_at on
// re-observation without clobbering an existing mtime. Shared by the batch
// insert and the atomic store.
const locationsFromStagingPG = `
	INSERT INTO sample_locations
		(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime)
	SELECT DISTINCT ON (sha256, path)
		sha256, path, parent, filename, source, feed, ecosystem, mtime
	  FROM _staging
	 WHERE path <> ''
	ON CONFLICT (sha256, path) DO UPDATE SET
		last_seen_at = now(),
		source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE sample_locations.source END,
		feed = CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE sample_locations.feed END,
		ecosystem = CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE sample_locations.ecosystem END,
		mtime = COALESCE(EXCLUDED.mtime, sample_locations.mtime)`

func (db *DB) insertSampleBatchPG(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	rows := sampleStagingRows(samples)

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

	logLabelTransitionsPG(ctx, tx)

	tag, err := tx.Exec(ctx, insertBatchStagingInsert)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: insert from staging: %w", err)
	}
	inserted = tag.RowsAffected()

	// Fan the staging rows out into sample_locations in the same transaction.
	if _, err := tx.Exec(ctx, locationsFromStagingPG); err != nil {
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

// memberConflictUpdatePG refreshes ONLY analysis columns of an existing member
// row, and only when this archive's analysis is strictly newer. It never touches
// label/path/skip/parent (a member must not rewrite a standalone row's identity)
// and never blanks litmus. New members fall through to a plain INSERT. The
// samples_derive_cleave_cols trigger re-derives file_type/max_crit/etc on the
// cleave_result write.
const memberConflictUpdatePG = `ON CONFLICT (sha256) DO UPDATE SET
	cleave_result = EXCLUDED.cleave_result,
	litmus_result = COALESCE(EXCLUDED.litmus_result, samples.litmus_result),
	analyzed_at = EXCLUDED.analyzed_at,
	first_analyzed_at = COALESCE(samples.first_analyzed_at, EXCLUDED.first_analyzed_at),
	updated_at = now()
WHERE EXCLUDED.analyzed_at > samples.analyzed_at OR samples.analyzed_at IS NULL`

// insertMembersFromStagingPG is insertBatchStagingInsert with the member
// conflict clause: insert new members, freshness-refresh stale ones, identity
// untouched.
const insertMembersFromStagingPG = `INSERT INTO samples (
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result, analyzed_at, first_analyzed_at,
	url, domain, package, version, provenance, fetched_at)
SELECT DISTINCT ON (sha256)
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result, analyzed_at, first_analyzed_at,
	url, domain, package, version, provenance, fetched_at
FROM _staging
` + memberConflictUpdatePG

// storeResultPG atomically writes a sample's analysis and, for an archive, all
// its members in one transaction: the parent is never truncated unless its
// members land in the same commit. See StoreResult for the contract.
func (db *DB) storeResultPG(
	ctx context.Context, sha256 string, cleaveRaw, litmusML, llm []byte,
	p CleaveParseResult, traitsVersion string, now time.Time,
) (StoreStats, error) {
	truncated := compactCleaveResultForStorage(cleaveRaw)

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return StoreStats{}, fmt.Errorf("hopper: begin store: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	// Read (and lock) the identity fields members inherit from the parent, so a
	// concurrent write can't shift the parent out from under the members.
	var parent Sample
	var firstAnalyzed sql.NullTime
	if err := tx.QueryRow(ctx,
		`SELECT label, label_source, source, feed, ecosystem, path, first_analyzed_at
		   FROM samples WHERE sha256 = $1 FOR UPDATE`, sha256).
		Scan(&parent.Label, &parent.LabelSource, &parent.Source, &parent.Feed,
			&parent.Ecosystem, &parent.Path, &firstAnalyzed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StoreStats{}, fmt.Errorf("hopper: store result for absent sample %s: %w", sha256, ErrNotFound)
		}
		return StoreStats{}, fmt.Errorf("hopper: read parent for store %s: %w", sha256, err)
	}

	var litmusVal, llmVal []byte
	if len(litmusML) > 0 {
		litmusVal = sanitizeJSONB(litmusML)
	}
	if len(llm) > 0 {
		llmVal = sanitizeJSONB(llm)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE samples SET cleave_result = $2,
			canonical_sha256 = $3, elements = $4,
			max_crit = $5, suspicious_count = $6,
			litmus_result = $7, llm_result = $8,
			note = '', last_error_at = NULL,
			traits_version = $9, rescan_priority = 0, rescan_requested_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, $10),
			analyzed_at = $10, updated_at = $10
		WHERE sha256 = $1`,
		sha256, sanitizeJSONB(truncated), p.CanonicalSHA,
		p.FileInfo.Elements, p.FileInfo.MaxCrit, p.FileInfo.SuspiciousCount,
		litmusVal, llmVal, traitsVersion, now); err != nil {
		return StoreStats{}, fmt.Errorf("hopper: update parent: %w", err)
	}

	// Build members from the FULL envelope, inheriting the parent's identity and
	// stamped with this analysis time so the freshness gate orders refreshes.
	parent.SHA256 = sha256
	parent.CleaveResult = cleaveRaw
	parent.LitmusResult = litmusML
	parent.CanonicalSHA256 = p.CanonicalSHA
	parent.AnalyzedAt = &now
	if firstAnalyzed.Valid {
		parent.FirstAnalyzedAt = &firstAnalyzed.Time
	} else {
		parent.FirstAnalyzedAt = &now
	}
	members := memberSamplesFromEnvelope(&parent)

	var stats StoreStats
	stats.Members = len(members)
	if len(members) > 0 {
		if _, err := tx.Exec(ctx, insertBatchStagingDDL); err != nil {
			return StoreStats{}, fmt.Errorf("hopper: create member staging: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_staging"}, insertBatchStagingCols, pgx.CopyFromRows(sampleStagingRows(members))); err != nil {
			return StoreStats{}, fmt.Errorf("hopper: copy members to staging: %w", err)
		}
		tag, err := tx.Exec(ctx, insertMembersFromStagingPG)
		if err != nil {
			return StoreStats{}, fmt.Errorf("hopper: upsert members: %w", err)
		}
		stats.MembersStored = tag.RowsAffected()
		if _, err := tx.Exec(ctx, locationsFromStagingPG); err != nil {
			return StoreStats{}, fmt.Errorf("hopper: upsert member locations: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return StoreStats{}, fmt.Errorf("hopper: commit store: %w", err)
	}
	return stats, nil
}

func (db *DB) sampleBySHA256PG(ctx context.Context, sha256 string) (*Sample, error) {
	s, err := scanPGSample(db.pool.QueryRow(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE sha256 = $1`, sha256))
	if err != nil {
		return nil, fmt.Errorf("hopper: sample %s: %w", sha256, err)
	}
	return s, nil
}

func (db *DB) membersByParentPG(ctx context.Context, parentSHA string, limit int) ([]ArchiveMember, int, error) {
	var total int
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM sample_locations WHERE parent_sha256 = $1`, parentSHA).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("hopper: count members by parent %s: %w", parentSHA, err)
	}
	if total == 0 {
		return nil, 0, nil
	}
	rows, err := db.pool.Query(ctx, `
		SELECT s.sha256, sl.path, s.file_type, s.score, s.max_crit
		  FROM sample_locations sl
		  JOIN samples s ON s.sha256 = sl.sha256
		 WHERE sl.parent_sha256 = $1
		 ORDER BY s.score DESC, s.max_crit DESC, sl.path
		 LIMIT $2`, parentSHA, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("hopper: members by parent %s: %w", parentSHA, err)
	}
	defer rows.Close()
	var out []ArchiveMember
	for rows.Next() {
		var m ArchiveMember
		if err := rows.Scan(&m.SHA256, &m.Path, &m.FileType, &m.Score, &m.MaxCrit); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

func (db *DB) samplesBySHAsPG(ctx context.Context, shas []string) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE sha256 = ANY($1)`, shas)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by shas: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) badMembersByParentPG(ctx context.Context, parentSHA string) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		  WHERE label = 'bad'
		    AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = $1)
		  ORDER BY path`, parentSHA)
	if err != nil {
		return nil, fmt.Errorf("hopper: bad members by parent %s: %w", parentSHA, err)
	}
	return scanPGSamples(rows)
}

func (db *DB) reconcileLocationParentEdgesPG(ctx context.Context, cursor int64) error {
	var maxID int64
	if err := db.pool.QueryRow(ctx,
		`SELECT COALESCE(max(id), 0) FROM samples WHERE parent <> ''`).Scan(&maxID); err != nil {
		return fmt.Errorf("hopper: backfill locations: bounds: %w", err)
	}
	for cursor < maxID {
		if err := ctx.Err(); err != nil {
			return err
		}
		hi := cursor + locationParentBackfillBatch
		// One short autocommit statement per id window: a PK range scan bounded
		// to the batch, inserting only the edges still missing. Row-level locks
		// only, released immediately — no long-held lock on samples.
		if _, err := db.pool.Exec(ctx, `
			INSERT INTO sample_locations
				(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at)
			SELECT sha256, path, parent, filename, source, feed, ecosystem, mtime, created_at, updated_at
			  FROM samples
			 WHERE id > $1 AND id <= $2 AND parent <> '' AND path <> ''
			ON CONFLICT (sha256, path) DO NOTHING`, cursor, hi); err != nil {
			return fmt.Errorf("hopper: backfill locations: chunk (%d,%d]: %w", cursor, hi, err)
		}
		cursor = hi
		if _, err := db.pool.Exec(ctx,
			`INSERT INTO hopper_kv (key, value) VALUES ($1, $2)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
			locationParentBackfillCurKey, strconv.FormatInt(cursor, 10)); err != nil {
			return fmt.Errorf("hopper: backfill locations: save cursor: %w", err)
		}
	}
	if _, err := db.pool.Exec(ctx,
		`INSERT INTO hopper_kv (key, value) VALUES ($1, 'done')
		 ON CONFLICT (key) DO UPDATE SET value = 'done'`,
		locationParentBackfillDoneKey); err != nil {
		return fmt.Errorf("hopper: backfill locations: done marker: %w", err)
	}
	slog.Info("sample_locations parent-edge backfill complete", "max_id", maxID)
	return nil
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

// pruneMissingLocationsPG mirrors pruneMissingLocationsSQLite for the
// PostgreSQL backend.
func (db *DB) pruneMissingLocationsPG(ctx context.Context, absRoot string, maxFraction float64) (int, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, path FROM sample_locations WHERE path LIKE $1`, absRoot+"/%")
	if err != nil {
		return 0, fmt.Errorf("hopper: scan locations for prune: %w", err)
	}
	var victims []pruneVictim
	total := 0
	for rows.Next() {
		var v pruneVictim
		if err := rows.Scan(&v.id, &v.path); err != nil {
			rows.Close()
			return 0, fmt.Errorf("hopper: scan location row: %w", err)
		}
		total++
		path := v.path
		if !filepath.IsAbs(path) {
			path = filepath.Join(absRoot, path)
		}
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			victims = append(victims, v)
		} else if err != nil {
			slog.Warn("hopper: stat failed during prune; preserving row", "path", path, "error", err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if total > 0 && float64(len(victims))/float64(total) > maxFraction {
		return 0, &PruneSafetyExceeded{Total: total, Victims: len(victims), MaxFraction: maxFraction}
	}

	for _, v := range victims {
		if _, err := db.pool.Exec(ctx, `DELETE FROM sample_locations WHERE id = $1`, v.id); err != nil {
			return 0, fmt.Errorf("hopper: delete location %d: %w", v.id, err)
		}
	}
	return len(victims), nil
}

func (db *DB) updateCleaveResultPG(
	ctx context.Context, sha256 string, result []byte, canonical string,
	fi cleaveFileInfo, traitsVersion string,
) error {
	// file_type, score, formula are re-derived from the new cleave_result by
	// the samples_derive_cleave_cols trigger (UPDATE OF cleave_result fires
	// it); litmus_score by the samples_derive_litmus_score trigger (UPDATE OF
	// litmus_result fires it), so setting litmus_result = NULL resets it to 0
	// via the trigger's COALESCE. None are SET here.
	// The rescan queue (rescan_priority/rescan_requested_at) clears here so the
	// row drops out once a worker has produced fresh analysis; without this the
	// partial index would carry stale entries.
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET cleave_result = $2,
			canonical_sha256 = $3, elements = $4,
			max_crit = $5, suspicious_count = $6,
			litmus_result = NULL,
			note = '', last_error_at = NULL,
			traits_version = $7,
			rescan_priority = 0, rescan_requested_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, now()),
			analyzed_at = now(), updated_at = now()
		WHERE sha256 = $1`,
		sha256, sanitizeJSONB(result), canonical,
		fi.Elements, fi.MaxCrit, fi.SuspiciousCount, traitsVersion)
	if err != nil {
		return fmt.Errorf("hopper: update cleave result: %w", err)
	}
	return nil
}

// requestRescanPG queues an interactive rescan (rescan_priority = 2), drained
// ahead of the unanalyzed backlog. Analysis fields (cleave_result,
// litmus_result, analyzed_at, traits_version, note, last_error_at) are
// deliberately left alone so readers see the prior envelope until a worker
// stores fresh results — StoreResult replaces them and clears the queue fields.
//
// `COALESCE(rescan_requested_at, now())` makes repeat requests idempotent: a
// row already queued keeps its original FIFO position (and a repair-queued row
// is promoted to interactive without losing its place). The WHERE accepts a
// re-request when the cooldown has elapsed OR the row is already queued — so a
// caller is never told ErrRescanNotEligible for a SHA already about to rescan.
func (db *DB) requestRescanPG(ctx context.Context, sha256 string, cooldownCutoff time.Time) error {
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples
		SET rescan_priority = 2,
		    rescan_requested_at = COALESCE(rescan_requested_at, now()),
		    updated_at = now()
		WHERE sha256 = $1 AND parent = '' AND skip = ''
		  AND (rescan_priority > 0
		       OR analyzed_at IS NULL
		       OR analyzed_at < $2)`,
		sha256, cooldownCutoff)
	if err != nil {
		return fmt.Errorf("hopper: request rescan: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRescanNotEligible
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

func (db *DB) updateLLMResultPG(ctx context.Context, sha256 string, result []byte) error {
	// An absent interpretation must store SQL NULL, not an empty string that
	// fails JSONB parsing — normalize empty to nil so pgx sends NULL.
	var val []byte
	if len(result) > 0 {
		val = sanitizeJSONB(result)
	}
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET llm_result = $2, updated_at = now()
		WHERE sha256 = $1`, sha256, val)
	if err != nil {
		return fmt.Errorf("hopper: update llm result: %w", err)
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
		UPDATE samples
		SET note = $2,
			last_error_at = CASE WHEN $2 = '' THEN NULL ELSE now() END,
			updated_at = now()
		WHERE sha256 = $1`,
		sha256, note)
	if err != nil {
		return fmt.Errorf("hopper: set note: %w", err)
	}
	return nil
}

func (db *DB) setStatusPG(ctx context.Context, sha256, status string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET status = $2, note = '', last_error_at = NULL, updated_at = now() WHERE sha256 = $1`,
		sha256, status)
	if err != nil {
		return fmt.Errorf("hopper: set status: %w", err)
	}
	return nil
}

// pipelineStageOrder ranks parked / candidate samples by impact: highest
// litmus_score first, falling back to cleave score for older rows where
// litmus has not yet run, with oldest update as a final tiebreaker.
const pipelineStageOrder = `ORDER BY litmus_score DESC NULLS LAST, score DESC, updated_at ASC`

// seedCandidateOrder is pipelineStageOrder with analyzed_at as the tiebreaker —
// fresh seeds always carry analyzed_at (cleave_result IS NOT NULL) so it's a
// more meaningful ordering than updated_at, which gets bumped by status writes.
const seedCandidateOrder = `ORDER BY litmus_score DESC NULLS LAST, score DESC, analyzed_at ASC NULLS FIRST`

// seedReanalysisCooldown skips seed candidates cyclotron has already attempted
// within this window. Prevents tight loops on samples that resist remediation:
// after the pipeline runs and the sample (somehow) ends up back in the seed
// pool, we sit out the cooldown before another attempt. Fresh-cleaved samples
// have cyclotron_attempted_at = NULL and are exempt — picked up immediately.
// In-pipeline samples (SamplesInPipelineStage) are exempt regardless.
const seedReanalysisCooldown = 8 * time.Hour

func seedFreshnessCutoff() time.Time {
	return time.Now().UTC().Add(-seedReanalysisCooldown)
}

func (db *DB) samplesInPipelineStagePG(ctx context.Context, status string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples WHERE status = $1 `+pipelineStageOrder+` LIMIT $2`,
		status, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples in pipeline stage: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) samplesInPipelineStageLightPG(ctx context.Context, status string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples WHERE status = $1 `+pipelineStageOrder+` LIMIT $2`,
		status, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples in pipeline stage (light): %w", err)
	}
	return scanPGSamplesLight(rows)
}

func (db *DB) falsePositivesPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2)
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < $1)
		 `+seedCandidateOrder+` LIMIT $2`,
		seedFreshnessCutoff(), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false positives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falsePositivesLightPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2)
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < $1)
		 `+seedCandidateOrder+` LIMIT $2`,
		seedFreshnessCutoff(), limit)
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
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND max_crit < 5 AND suspicious_count < 2
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < $1)
		 `+seedCandidateOrder+` LIMIT $2`,
		seedFreshnessCutoff(), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) falseNegativesLightPG(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND max_crit < 5 AND suspicious_count < 2
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < $1)
		 `+seedCandidateOrder+` LIMIT $2`,
		seedFreshnessCutoff(), limit)
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

func (db *DB) conflictReviewPG(ctx context.Context, _, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = 'bad' AND skip = 'conflict' AND status = ''
		 ORDER BY updated_at DESC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: conflict review: %w", err)
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
	// file_type, score, formula are re-derived by the
	// samples_derive_cleave_cols trigger (UPDATE OF cleave_result fires it);
	// litmus_score by the samples_derive_litmus_score trigger (UPDATE OF
	// litmus_result fires it), so setting litmus_result = NULL resets it to 0.
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET status = $2, cleave_result = $3,
			canonical_sha256 = $4, elements = $5,
			max_crit = $6, suspicious_count = $7,
			litmus_result = NULL,
			note = '', last_error_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, now()),
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
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < $3)
		   `+detectionFilter+`
		 `+seedCandidateOrder+` LIMIT $4`,
		label, patterns, seedFreshnessCutoff(), limit)
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
		FROM reports WHERE sha256 = $1 ORDER BY created_at DESC, id DESC`, sha256)
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
	// id DESC tiebreaks when two rows share a created_at — strftime('%f') and
	// now() are millisecond-resolution, and rapid InsertReport calls collide
	// on the same value. Without id DESC, "latest" is non-deterministic.
	err := db.pool.QueryRow(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE sha256 = $1 AND report_type = $2
		ORDER BY created_at DESC, id DESC LIMIT 1`, sha256, reportType).Scan(
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
			JSON_TABLE(COALESCE(cleave_result->'files', cleave_result->'fs', '[]'::jsonb), '$[*]' COLUMNS (
				file_sha256 TEXT PATH '$.sha256',
				file_sha TEXT PATH '$.sha'
			)) AS jt
		WHERE COALESCE(jt.file_sha256, jt.file_sha) = $1
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
					LEAST(s.sha256, MIN(COALESCE(jt.file_sha256, jt.file_sha))) AS canonical
				FROM samples s
				JOIN batch b ON b.sha256 = s.sha256,
					JSON_TABLE(COALESCE(s.cleave_result->'files', s.cleave_result->'fs', '[]'::jsonb), '$[*]' COLUMNS (
						file_sha256 TEXT PATH '$.sha256',
						file_sha TEXT PATH '$.sha'
					)) AS jt
				WHERE length(COALESCE(jt.file_sha256, jt.file_sha)) = 64
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

const pgCleaveBackfillWhere = `cleave_result IS NOT NULL
	AND elements = ''
	AND COALESCE(cleave_result->'files'->0->>'mol', cleave_result->'fs'->0->>'f', '') > ''`

// pgFileTypeBackfillWhere selects rows whose file_type/score/formula were left
// empty by the pre-v7 fs-only generated expression: file_type is blank yet the
// JSON carries a type to derive. Must stay in sync with
// idx_samples_filetype_pending so the gate stays index-backed and self-draining.
const pgFileTypeBackfillWhere = `cleave_result IS NOT NULL
	AND file_type = ''
	AND COALESCE(cleave_result->'files'->0->>'type', cleave_result->'fs'->0->>'type', '') <> ''`

func (db *DB) backfillPendingPG(ctx context.Context) (BackfillPending, error) {
	var pending BackfillPending
	if err := db.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM samples WHERE `+pgCleaveBackfillWhere+`),
			(SELECT count(*) FROM samples WHERE `+pgFileTypeBackfillWhere+`),
			(SELECT count(*)
			 FROM samples c
			 JOIN samples p ON p.sha256 = c.parent
			 WHERE c.parent <> ''
				AND c.litmus_result IS NOT NULL
				AND pg_column_size(c.litmus_result) = pg_column_size(p.litmus_result)
				AND c.litmus_result = p.litmus_result
				AND p.cleave_result IS NOT NULL
				AND p.litmus_result IS NOT NULL),
			(SELECT count(*)
			 FROM samples c
			 JOIN samples p ON p.sha256 = c.parent
			 WHERE c.parent <> ''
				AND c.analyzed_at IS NULL
				AND c.cleave_result IS NOT NULL
				AND c.litmus_result IS NOT NULL
				AND p.analyzed_at IS NOT NULL),
			(SELECT count(*)
			 FROM samples
			 WHERE label = 'good' AND label_source = 'marker' AND skip = 'misclassified'
				AND cleave_result IS NOT NULL
				AND max_crit < 5 AND suspicious_count <= 1),
			(SELECT count(*)
			 FROM samples
			 WHERE label = 'bad' AND label_source = 'marker' AND skip = 'misclassified'
				AND cleave_result IS NOT NULL
				AND (max_crit >= 5 OR suspicious_count >= 2))`,
	).Scan(
		&pending.CleaveColumns,
		&pending.FileTypeEmpties,
		&pending.ArchiveMemberLitmus,
		&pending.ArchiveMemberAnalyzed,
		&pending.StaleGoodMarkers,
		&pending.StaleBadMarkers,
	); err != nil {
		return pending, fmt.Errorf("hopper: backfill pending count: %w", err)
	}
	return pending, nil
}

// backfillPG fixes legacy rows whose derivable columns (elements, max_crit,
// suspicious_count in Pass 1; file_type, score, formula in Pass 1b) are stale,
// then clears misclassified skip markers that no longer disagree with the new
// trait-based heuristic.
//
// file_type / score / formula are derived DB-side by the
// samples_derive_cleave_cols trigger going forward, but rows written while
// those columns were generated from the pre-v7 'fs' key need a one-time heal
// (Pass 1b). litmus_score is derived by the samples_derive_litmus_score trigger
// from litmus_result->>'prob'; rows analyzed before that trigger existed are
// healed by Pass 1c.
func (db *DB) backfillPG(ctx context.Context) (BackfillStats, error) {
	var stats BackfillStats

	const backfillBatch = 50000

	// Pass 1b runs first because it is small and index-backed: heal file_type /
	// score / formula for rows stored under the v7 'files' key while those
	// columns were still generated from the legacy 'fs' key (every such row has
	// file_type=''). The pgFileTypeBackfillWhere gate is served by
	// idx_samples_filetype_pending and self-drains — a row leaves it the moment
	// file_type becomes non-empty — so this finishes fast and is never held
	// behind the much larger elements pass below. The derive trigger fixes
	// writes from here on; this drains the pre-trigger rows using the same
	// dual-key expressions. Does not bump updated_at — healing a derived column
	// is not a real change and must not reshuffle queues ordered by updated_at.
	for {
		ftTag, err := db.pool.Exec(ctx, `
			UPDATE samples SET
				file_type = COALESCE(cleave_result->'files'->0->>'type', cleave_result->'fs'->0->>'type', ''),
				score = COALESCE((cleave_result->'files'->0->>'risk')::int, (cleave_result->'fs'->0->>'x')::int, 0),
				formula = COALESCE(cleave_result->'files'->0->>'mol', cleave_result->'fs'->0->>'f', '')
			WHERE sha256 IN (
				SELECT sha256 FROM samples WHERE `+pgFileTypeBackfillWhere+`
				LIMIT $1
			)`, backfillBatch)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill file_type: %w", err)
		}
		n := ftTag.RowsAffected()
		stats.Updated += n
		db.reportBackfill(stats.Updated, stats.Scanned)
		if n < backfillBatch {
			break
		}
		slog.Info("backfill file_type batch", "batch", n, "total", stats.Updated)
	}

	// Pass 1c: litmus_score for rows analyzed before it became a trigger-fed
	// column — or while it was a STORED generated column that was later converted
	// in place by DROP EXPRESSION (which retains values but leaves never-populated
	// rows at the DEFAULT 0). Gate: a row whose litmus_result carries a non-zero
	// 'prob' while litmus_score is still 0. The third clause keeps the gate
	// self-draining and loop-safe — a row whose prob is genuinely 0/absent never
	// matches, so it can't be UPDATEd to 0 and re-match forever. The
	// samples_derive_litmus_score trigger fixes writes from here on; this drains
	// the pre-trigger backlog. Like Pass 1b it does not bump updated_at — healing a
	// derived column is not a real change and must not reshuffle updated_at queues.
	for {
		lsTag, err := db.pool.Exec(ctx, `
			UPDATE samples SET
				litmus_score = COALESCE((litmus_result->>'prob')::double precision, 0)
			WHERE sha256 IN (
				SELECT sha256 FROM samples
				WHERE litmus_result IS NOT NULL AND litmus_score = 0
				  AND COALESCE((litmus_result->>'prob')::double precision, 0) <> 0
				LIMIT $1
			)`, backfillBatch)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill litmus_score: %w", err)
		}
		n := lsTag.RowsAffected()
		stats.Updated += n
		db.reportBackfill(stats.Updated, stats.Scanned)
		if n < backfillBatch {
			break
		}
		slog.Info("backfill litmus_score batch", "batch", n, "total", stats.Updated)
	}

	// Pass 1d: litmus_class for litmus-bearing rows analyzed before it became a
	// trigger-fed column. Extracted (like the archive-member pass below) to keep
	// backfillPG within length limits.
	lc, err := db.backfillLitmusClassPG(ctx, backfillBatch)
	if err != nil {
		return stats, err
	}
	stats.Updated += lc
	db.reportBackfill(stats.Updated, stats.Scanned)

	// Pass 1: elements / max_crit / suspicious_count for rows whose cleave
	// columns predate the derive trigger. Candidate rows have cleave_result but
	// elements wasn't derived yet AND the JSON would actually produce a
	// non-empty elements value. The third clause (in pgCleaveBackfillWhere)
	// excludes "stuck" rows where cleave_result lacks a files[0].mol field —
	// without it those rows match the gate, get UPDATEd to elements='' (no-op),
	// and re-match next batch, risking an infinite loop. New writes get these
	// columns from the derive trigger, so this backlog only shrinks: it is a
	// one-time drain of rows written before the trigger existed.
	//
	// Implementation note: this inlines the JSON extraction on the target row
	// rather than using UPDATE samples s ... FROM (SELECT ... JOIN batch). PG used
	// to reject that self-referential shape with "column … can only be updated to
	// DEFAULT" (SQLSTATE 428C9) while samples carried a STORED GENERATED column
	// (litmus_score); that column is now plain (trigger-fed), so the restriction no
	// longer applies — but the inline form is retained: it is correct and avoids a
	// needless self-join.
	if err := db.pool.QueryRow(ctx, `
		SELECT count(*) FROM samples WHERE `+pgCleaveBackfillWhere).Scan(&stats.Scanned); err != nil {
		return stats, fmt.Errorf("hopper: backfill count: %w", err)
	}
	db.reportBackfill(stats.Updated, stats.Scanned)
	for {
		cleaveTag, err := db.pool.Exec(ctx, `
			UPDATE samples SET
				elements = translate(
					COALESCE(cleave_result->'files'->0->>'mol', cleave_result->'fs'->0->>'f', ''),
					'₀₁₂₃₄₅₆₇₈₉', ''),
				max_crit = COALESCE((
					SELECT MAX((COALESCE(tr->>'crit', tr->>'l'))::int)
					FROM jsonb_array_elements(
						COALESCE(cleave_result->'files'->0->'find', cleave_result->'fs'->0->'ts', '[]'::jsonb)
					) AS tr
					WHERE COALESCE(tr->>'crit', tr->>'l') IS NOT NULL
				), 0),
				suspicious_count = (
					SELECT COUNT(*)::int
					FROM jsonb_array_elements(
						COALESCE(cleave_result->'files'->0->'find', cleave_result->'fs'->0->'ts', '[]'::jsonb)
					) AS tr
					WHERE COALESCE(tr->>'crit', tr->>'l') IS NOT NULL
						AND (COALESCE(tr->>'crit', tr->>'l'))::int >= 4
				),
				updated_at = now()
			WHERE sha256 IN (
				SELECT sha256 FROM samples WHERE `+pgCleaveBackfillWhere+`
				LIMIT $1
			)`, backfillBatch)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill cleave columns: %w", err)
		}
		n := cleaveTag.RowsAffected()
		stats.Updated += n
		db.reportBackfill(stats.Updated, stats.Scanned)
		if n < backfillBatch {
			break
		}
		slog.Info("backfill cleave batch", "batch", n, "total", stats.Updated)
	}

	n, err := db.backfillArchiveMemberLitmusPG(ctx)
	if err != nil {
		return stats, err
	}
	stats.Updated += n
	db.reportBackfill(stats.Updated, stats.Scanned)

	// Pass 2: archive members written before analyzed_at was persisted by
	// InsertSampleBatch should inherit the parent's analysis timestamp.
	for {
		childTag, err := db.pool.Exec(ctx, `
			WITH batch AS (
				SELECT c.sha256, p.analyzed_at
				FROM samples c
				JOIN samples p ON p.sha256 = c.parent
				WHERE c.parent <> ''
					AND c.analyzed_at IS NULL
					AND c.cleave_result IS NOT NULL
					AND c.litmus_result IS NOT NULL
					AND p.analyzed_at IS NOT NULL
				LIMIT $1
			)
			UPDATE samples s SET analyzed_at = batch.analyzed_at, updated_at = now()
			FROM batch
			WHERE s.sha256 = batch.sha256`, backfillBatch)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill archive member analyzed_at: %w", err)
		}
		n := childTag.RowsAffected()
		stats.Updated += n
		if n < backfillBatch {
			break
		}
		slog.Info("backfill archive member analyzed_at batch", "batch", n, "total", stats.Updated)
	}

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

// backfillLitmusClassPG heals litmus_class for litmus-bearing rows analyzed
// before it became a trigger-fed column (the column is nullable, so those rows
// are NULL until healed). The samples_derive_litmus_score trigger fills it on
// every write from here on; this drains the pre-trigger backlog in batches of
// limit. The IS NULL gate shrinks monotonically — every UPDATE sets a non-null
// class, so a healed row never re-enters — so unlike the litmus_score pass it
// never re-scans the (large) already-correct set. CriticalLevel is the pinned
// cutoff, matching the trigger and feedClassExpr's default-cutoff path; the WHERE
// guarantees litmus_result IS NOT NULL, so the trigger's null branch is omitted.
// No updated_at bump: healing a derived column must not reshuffle update queues.
func (db *DB) backfillLitmusClassPG(ctx context.Context, limit int) (int64, error) {
	var total int64
	for {
		tag, err := db.pool.Exec(ctx, fmt.Sprintf(`
			UPDATE samples SET litmus_class = COALESCE(
				(litmus_result->>'class')::smallint,
				CASE
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l') IS NULL THEN 2
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int < 0 THEN 0
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int <= %d THEN 2
					ELSE 1
				END)
			WHERE sha256 IN (
				SELECT sha256 FROM samples
				WHERE litmus_result IS NOT NULL AND litmus_class IS NULL
				LIMIT $1
			)`, CriticalLevel), limit)
		if err != nil {
			return total, fmt.Errorf("hopper: backfill litmus_class: %w", err)
		}
		n := tag.RowsAffected()
		total += n
		if n < int64(limit) {
			return total, nil
		}
		slog.Info("backfill litmus_class batch", "batch", n, "total", total)
	}
}

func (db *DB) backfillArchiveMemberLitmusPG(ctx context.Context) (int64, error) {
	// Iterate by parent. Earlier shape JOINed children to parents and fetched
	// (childSHA, childLitmus, parentCleave, parentLitmus) per child — for a
	// tarball with thousands of matching members the parent's multi-MB JSONBs
	// were duplicated thousands of times in the pgx fetch buffer, blowing
	// past 40 GB on real workloads. Loading each parent exactly once keeps
	// memory bounded by the largest single parent.
	//
	// Phase 1 enumerates parents that have at least one qualifying child,
	// using a server-side cursor on a read-only snapshot. Phase 2 (per
	// parent) fetches the matching child SHAs on the main pool and rewrites
	// each child's litmus_result. Since the matching predicate is
	// litmus_result = parent.litmus_result, we don't need to re-fetch the
	// child blob — the parent's bytes are the WHERE-clause guard.
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, fmt.Errorf("hopper: backfill archive member litmus begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	if _, err := tx.Exec(ctx, `
		DECLARE archive_parent_cur NO SCROLL CURSOR FOR
		SELECT p.sha256, p.cleave_result, p.litmus_result
		FROM samples p
		WHERE p.cleave_result IS NOT NULL
			AND p.litmus_result IS NOT NULL
			AND EXISTS (
				SELECT 1 FROM samples c
				WHERE c.parent = p.sha256
					AND c.litmus_result IS NOT NULL
					AND pg_column_size(c.litmus_result) = pg_column_size(p.litmus_result)
					AND c.litmus_result = p.litmus_result
			)`); err != nil {
		return 0, fmt.Errorf("hopper: backfill archive member litmus declare: %w", err)
	}

	var total int64
	for {
		var parentSHA string
		var parentCleave, parentLitmus []byte

		rows, err := tx.Query(ctx, `FETCH 1 FROM archive_parent_cur`)
		if err != nil {
			return total, fmt.Errorf("hopper: backfill archive member litmus fetch parent: %w", err)
		}
		got := false
		if rows.Next() {
			got = true
			if err := rows.Scan(&parentSHA, &parentCleave, &parentLitmus); err != nil {
				rows.Close()
				return total, fmt.Errorf("hopper: backfill archive member litmus scan parent: %w", err)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return total, fmt.Errorf("hopper: backfill archive member litmus rows: %w", err)
		}
		rows.Close()
		if !got {
			return total, nil
		}

		childRows, err := db.pool.Query(ctx, `
			SELECT sha256 FROM samples
			WHERE parent = $1
				AND litmus_result IS NOT NULL
				AND pg_column_size(litmus_result) = pg_column_size($2::jsonb)
				AND litmus_result = $2::jsonb`, parentSHA, parentLitmus)
		if err != nil {
			return total, fmt.Errorf("hopper: backfill archive member litmus children: %w", err)
		}
		var childSHAs []string
		for childRows.Next() {
			var s string
			if err := childRows.Scan(&s); err != nil {
				childRows.Close()
				return total, fmt.Errorf("hopper: backfill archive member litmus scan child: %w", err)
			}
			childSHAs = append(childSHAs, s)
		}
		if err := childRows.Err(); err != nil {
			childRows.Close()
			return total, fmt.Errorf("hopper: backfill archive member litmus child rows: %w", err)
		}
		childRows.Close()

		var fixed atomic.Int64
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(archiveMemberLitmusWorkers)
		for _, sha := range childSHAs {
			g.Go(func() error {
				id, ok := cleaveFileIndexForSHA(parentCleave, sha)
				if !ok {
					return nil
				}
				memberLitmus := litmusResultForMember(parentLitmus, id)
				if len(memberLitmus) == 0 {
					return nil
				}
				tag, err := db.pool.Exec(gctx, `
					UPDATE samples
					SET litmus_result = $1, updated_at = now()
					WHERE sha256 = $2 AND litmus_result = $3`,
					sanitizeJSONB(memberLitmus), sha, parentLitmus)
				if err != nil {
					return fmt.Errorf("hopper: backfill archive member litmus update %s: %w", sha, err)
				}
				fixed.Add(tag.RowsAffected())
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return total, err
		}

		batchFixed := fixed.Load()
		total += batchFixed
		if batchFixed > 0 {
			slog.Info("backfill archive member litmus parent",
				"parent", parentSHA, "fixed", batchFixed, "total", total)
		}
	}
}

func (db *DB) setSkipPG(ctx context.Context, sha256, skip string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE samples SET skip = $2, skipped_at = now(), updated_at = now() WHERE sha256 = $1`,
		sha256, skip)
	if err != nil {
		return fmt.Errorf("hopper: set skip: %w", err)
	}
	return nil
}

// incrementAttemptsPG bumps the claim-attempt counter for the given samples.
// It deliberately does not touch updated_at: a claim is not progress, and
// bumping updated_at would corrupt the oldest-pending view. Called from the
// /api/next hot path with the batch a worker just claimed.
func (db *DB) incrementAttemptsPG(ctx context.Context, shas []string) error {
	if len(shas) == 0 {
		return nil
	}
	_, err := db.pool.Exec(ctx,
		`UPDATE samples SET attempts = attempts + 1 WHERE sha256 = ANY($1)`, shas)
	if err != nil {
		return fmt.Errorf("hopper: increment attempts: %w", err)
	}
	return nil
}

// reapStuckPG marks pending samples that have been claimed maxAttempts or more
// times without ever producing a result. These are poison samples — they wedge
// or crash a worker before it can POST a result or an error, so no other gate
// (note / last_error_at) ever sees them. Returns the number reaped.
func (db *DB) reapStuckPG(ctx context.Context, maxAttempts int) (int64, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples SET skip = 'stuck', skipped_at = now(), updated_at = now()
		WHERE cleave_result IS NULL AND skip = '' AND attempts >= $1`, maxAttempts)
	if err != nil {
		return 0, fmt.Errorf("hopper: reap stuck: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (db *DB) startWalkStagingPG(ctx context.Context) error {
	if _, err := db.pool.Exec(ctx, `TRUNCATE walk_staging`); err != nil {
		return fmt.Errorf("hopper: clear walk staging: %w", err)
	}
	return nil
}

func (db *DB) stageLocationsPG(ctx context.Context, keys []SampleLocationKey) error {
	shas := make([]string, len(keys))
	paths := make([]string, len(keys))
	for i, k := range keys {
		shas[i] = k.SHA256
		paths[i] = k.Path
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO walk_staging (sha256, path)
		SELECT sha256, path FROM unnest($1::text[], $2::text[]) AS v(sha256, path)`,
		shas, paths)
	if err != nil {
		return fmt.Errorf("hopper: stage locations: %w", err)
	}
	return nil
}

func (db *DB) relabelFromPoolsPG(ctx context.Context) (int64, error) {
	// One statement: a writable CTE updates the changed rows and the final
	// INSERT audits them. PG executes every data-modifying CTE exactly once, so
	// the UPDATE runs even though the INSERT reads pre-update values from
	// `changed`. Atomic by construction.
	tag, err := db.pool.Exec(ctx, `
		WITH pools AS (
			SELECT sha256,
				bool_or(path LIKE 'bad/%')  AS in_bad,
				bool_or(path LIKE 'good/%') AS in_good
			FROM walk_staging
			GROUP BY sha256
		),
		target AS (
			SELECT s.sha256, s.label AS old_label, s.skip AS old_skip,
				CASE WHEN p.in_bad THEN 'bad' WHEN p.in_good THEN 'good' ELSE s.label END AS new_label,
				CASE WHEN p.in_bad AND p.in_good THEN 'conflict'
				     WHEN s.skip IN ('conflict', 'missing', 'unsupported') THEN ''
				     ELSE s.skip END AS new_skip,
				CASE WHEN p.in_bad AND p.in_good THEN 'conflict'
				     WHEN s.label_source = 'conflict' THEN ''
				     ELSE s.label_source END AS new_source
			FROM samples s JOIN pools p ON p.sha256 = s.sha256
			WHERE s.parent = '' AND s.label_source <> 'marker'
		),
		changed AS (
			SELECT sha256, old_label, old_skip, new_label, new_skip, new_source
			FROM target WHERE new_label <> old_label OR new_skip <> old_skip
		),
		upd AS (
			UPDATE samples s SET label = c.new_label, skip = c.new_skip,
				label_source = c.new_source, updated_at = now()
			FROM changed c WHERE s.sha256 = c.sha256
			RETURNING s.sha256
		)
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, old_label, new_label, old_skip, new_skip,
			CASE WHEN new_skip = 'conflict' THEN 'conflict' ELSE 'relabel' END, now()
		FROM changed`)
	if err != nil {
		return 0, fmt.Errorf("hopper: relabel: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (db *DB) staleStandaloneSamplesPG(ctx context.Context) ([]SampleLocationKey, int64, error) {
	var eligible int64
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*) FROM samples WHERE parent = '' AND skip IN ('', 'conflict')`).Scan(&eligible); err != nil {
		return nil, 0, fmt.Errorf("hopper: stale count: %w", err)
	}
	rows, err := db.pool.Query(ctx, `
		SELECT s.sha256, s.path FROM samples s
		WHERE s.parent = '' AND s.skip IN ('', 'conflict')
		  AND NOT EXISTS (SELECT 1 FROM walk_staging w WHERE w.sha256 = s.sha256)`)
	if err != nil {
		return nil, 0, fmt.Errorf("hopper: stale scan: %w", err)
	}
	defer rows.Close()
	var out []SampleLocationKey
	for rows.Next() {
		var k SampleLocationKey
		if err := rows.Scan(&k.SHA256, &k.Path); err != nil {
			return nil, 0, fmt.Errorf("hopper: stale scan row: %w", err)
		}
		out = append(out, k)
	}
	return out, eligible, rows.Err()
}

func (db *DB) setSkipWithEventPG(ctx context.Context, sha256, skip, reason string) (bool, error) {
	tag, err := db.pool.Exec(ctx, `
		WITH cur AS (
			SELECT label, skip FROM samples WHERE sha256 = $1 AND skip <> $2
		),
		ev AS (
			INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
			SELECT $1, label, label, skip, $2, $3, now() FROM cur
		)
		UPDATE samples SET skip = $2, updated_at = now()
		WHERE sha256 = $1 AND EXISTS (SELECT 1 FROM cur)`,
		sha256, skip, reason)
	if err != nil {
		return false, fmt.Errorf("hopper: set skip event: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// cascadeBatch bounds how many samples rows a single reconcile UPDATE locks at
// once. Large enough to drain a sizable backlog in a few round-trips, small
// enough that the row locks it holds clear quickly for foreground workers.
const cascadeBatch = 10000

func (db *DB) cascadeMembersPG(ctx context.Context) (cascaded, revived int64, err error) {
	// Reachability set: every standalone file in the current walk, plus every
	// member transitively reachable from one through the sample_locations edge
	// set (~80M rows). Materialized ONCE into a session-local temp table so the
	// two reconcile passes below become fast anti-/semi-joins against its primary
	// key. The whole pass runs on a single dedicated connection: the temp table
	// is private to that session — safe against a concurrent reconcile — yet
	// survives across the independent per-batch transactions.
	//
	// The earlier form ran both reconciling UPDATEs unbounded inside ONE
	// transaction, locking every matching samples row at once and holding those
	// locks until commit — head-of-line-blocking every worker's result store
	// until lock_timeout fired (SQLSTATE 55P03). Each UPDATE now drains in
	// bounded batches, each its own transaction selecting victims FOR UPDATE SKIP
	// LOCKED under a short lock_timeout, so the sweep always yields to — and
	// never blocks — a worker holding a row lock.
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("hopper: acquire reconcile conn: %w", err)
	}
	// Drop the temp tables before the connection returns to the pool so a later
	// reuse starts clean. WithoutCancel so cleanup still runs when ctx is already
	// cancelled; buildReconcileAliveSet also drops first, so any residue
	// self-heals on the next pass regardless.
	defer func() {
		if _, derr := conn.Exec(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS reconcile_alive, reconcile_frontier`); derr != nil {
			slog.Warn("reconcile temp table cleanup failed; will self-heal on next pass", "error", derr)
		}
		conn.Release()
	}()

	if err := buildReconcileAliveSet(ctx, conn); err != nil {
		return 0, 0, err
	}

	// Cascade missing to members orphaned by a missing parent. The WHERE skip=''
	// guarantees from_skip='', so the audit needs no pre-read; a member with an
	// edge to any alive archive is in reconcile_alive and survives (supply-chain
	// veto). Self-draining: each row moves skip ''→'missing' and leaves the
	// candidate set, so the loop terminates when a batch changes nothing.
	cascaded, err = drainReconcile(ctx, conn, `
		WITH casc AS (
			UPDATE samples s SET skip = 'missing', updated_at = now()
			WHERE s.sha256 IN (
				SELECT s2.sha256 FROM samples s2
				WHERE s2.parent <> '' AND s2.skip = ''
				  AND NOT EXISTS (SELECT 1 FROM reconcile_alive a WHERE a.sha256 = s2.sha256)
				LIMIT $1
				FOR UPDATE SKIP LOCKED
			)
			RETURNING s.sha256, s.label
		)
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, label, label, '', 'missing', 'cascade-missing', now() FROM casc`)
	if err != nil {
		return cascaded, 0, err
	}

	revived, err = drainReconcile(ctx, conn, `
		WITH rev AS (
			UPDATE samples s SET skip = '', updated_at = now()
			WHERE s.sha256 IN (
				SELECT s2.sha256 FROM samples s2
				WHERE s2.parent <> '' AND s2.skip = 'missing'
				  AND EXISTS (SELECT 1 FROM reconcile_alive a WHERE a.sha256 = s2.sha256)
				LIMIT $1
				FOR UPDATE SKIP LOCKED
			)
			RETURNING s.sha256, s.label
		)
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, label, label, 'missing', '', 'revive', now() FROM rev`)
	if err != nil {
		return cascaded, revived, err
	}
	return cascaded, revived, nil
}

// aliveExpandBatch bounds how many frontier sha256 a single BFS expansion step
// processes. Each step is one statement (its own implicit transaction), so this
// keeps every transaction short: the reconcile must never hold a long-open
// transaction, which would pin the logical-replication slot's restart_lsn and
// stall WAL release on the primary.
const aliveExpandBatch = 50000

// buildReconcileAliveSet materializes the reconcile reachability set into the
// session-local temp table reconcile_alive on conn: every walked standalone file
// (walk_staging) plus every member transitively reachable from one through the
// sample_locations parent->child edge set.
//
// It is an iterative breadth-first expansion, NOT one recursive-CTE INSERT. The
// recursive form planned as a merge join that seq-scanned and sorted the whole
// ~105M-row sample_locations table (spilling past work_mem='4GB') on every pass
// — hours on a host whose data blocks aren't cached — and, being one statement,
// held a single long transaction that pinned the replication slot. The BFS
// instead expands a bounded frontier per step using idx_sl_parent_child (an
// index-only child lookup), dedups via the alive PK with ON CONFLICT, and
// commits every step, so it never sorts the whole table and never holds a
// long-open transaction. It reads only walk_staging/sample_locations, so it
// takes no lock on samples. The temp tables omit ON COMMIT DROP so they outlive
// each step's transaction and stay visible to the drain batches on this conn.
func buildReconcileAliveSet(ctx context.Context, conn *pgxpool.Conn) error {
	// (Re)create the alive set and the frontier scratch. DROP first so residue
	// left on this pooled connection by a cancelled cleanup never poisons this
	// pass. Each Exec on conn is its own implicit transaction.
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS reconcile_alive, reconcile_frontier`,
		`CREATE TEMP TABLE reconcile_alive (sha256 TEXT PRIMARY KEY)`,
		`CREATE TEMP TABLE reconcile_frontier (sha256 TEXT PRIMARY KEY)`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("hopper: alive setup: %w", err)
		}
	}

	// Seed: every walked standalone file is alive. ON CONFLICT dedups
	// walk_staging's repeated sha256 via the PK — no DISTINCT needed. The seed
	// set is also the initial frontier.
	if _, err := conn.Exec(ctx, `
		INSERT INTO reconcile_alive (sha256)
		SELECT sha256 FROM walk_staging
		ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("hopper: seed alive: %w", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO reconcile_frontier (sha256)
		SELECT sha256 FROM reconcile_alive`); err != nil {
		return fmt.Errorf("hopper: seed frontier: %w", err)
	}

	// Expand level by level: pop a bounded batch off the frontier, add its
	// not-yet-alive children to the alive set, and enqueue those new children as
	// the next frontier — all in one self-committing statement (the added/enqueue
	// data-modifying CTEs run to completion regardless of the top-level SELECT).
	// Terminates when the frontier drains (a round pops nothing). Every sha256
	// enters the frontier at most once — only when first inserted into alive — so
	// cycles can't loop and the walk is finite.
	for {
		var popped int64
		if err := conn.QueryRow(ctx, `
			WITH batch AS (
				DELETE FROM reconcile_frontier
				WHERE sha256 IN (SELECT sha256 FROM reconcile_frontier LIMIT $1)
				RETURNING sha256
			),
			added AS (
				INSERT INTO reconcile_alive (sha256)
				SELECT sl.sha256
				FROM batch b
				-- The redundant-looking parent_sha256 <> '' is load-bearing: it
				-- lets the planner use the partial idx_sl_parent_child /
				-- idx_sl_parent (both WHERE parent_sha256 <> '') for an index
				-- nested loop. Without it the planner can't prove the join keys
				-- are non-empty and falls back to a 105M-row seq scan + sort. The
				-- frontier holds only real 64-hex sha256, so it changes no rows.
				JOIN sample_locations sl
				  ON sl.parent_sha256 = b.sha256 AND sl.parent_sha256 <> ''
				ON CONFLICT (sha256) DO NOTHING
				RETURNING sha256
			),
			enqueue AS (
				INSERT INTO reconcile_frontier (sha256)
				SELECT sha256 FROM added
				ON CONFLICT DO NOTHING
				RETURNING sha256
			)
			SELECT count(*) FROM batch`, aliveExpandBatch).Scan(&popped); err != nil {
			return fmt.Errorf("hopper: expand alive: %w", err)
		}
		if popped == 0 {
			return nil
		}
	}
}

// drainReconcile runs one batched reconcile statement on conn repeatedly until a
// batch changes no rows. stmt must take $1 (the batch limit) and report the
// number of rows changed via its command tag. Each batch is its own transaction
// with a short lock_timeout, and the statement selects its victims FOR UPDATE
// SKIP LOCKED, so the sweep never waits on a worker-held row lock — momentarily
// locked rows are simply left for the next reconcile pass. Runs on conn so the
// statements see the session-local reconcile_alive temp table.
func drainReconcile(ctx context.Context, conn *pgxpool.Conn, stmt string) (int64, error) {
	var total int64
	for {
		var affected int64
		err := func() error {
			tx, err := conn.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
			if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '3s'`); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, stmt, cascadeBatch)
			if err != nil {
				return err
			}
			affected = tag.RowsAffected()
			return tx.Commit(ctx)
		}()
		if err != nil {
			return total, fmt.Errorf("hopper: reconcile batch: %w", err)
		}
		total += affected
		if affected == 0 {
			return total, nil
		}
	}
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

func (db *DB) feedSamplesPG(ctx context.Context, q *FeedQuery) ([]*Sample, error) {
	// The class filter reads the indexed litmus_class column at the default
	// cutoff and re-derives from litmus_result otherwise; see feedClassExpr.
	rows, err := db.pool.Query(ctx, `
		SELECT `+pgSampleCols+` FROM samples
		WHERE ($1 = '' OR source = $1)
			AND ($2 = '' OR label = $2)
			AND cleave_result IS NOT NULL
			AND (coalesce(cardinality($3::text[]), 0) = 0 OR feed = ANY($3))
			AND (coalesce(cardinality($4::text[]), 0) = 0 OR ecosystem = ANY($4))
			AND (coalesce(cardinality($5::int[]), 0) = 0 OR `+q.feedClassExpr()+` = ANY($5))
			AND (NOT $6 OR parent = '')
			AND ($7 = '' OR formula = $7)
			AND (NOT $8 OR litmus_result IS NOT NULL)
			AND (coalesce(cardinality($9::text[]), 0) = 0 OR domain = ANY($9))
			AND ($12 = '' OR filename ILIKE '%' || $12 || '%' ESCAPE '\'
				OR sha256 = $12)
		ORDER BY `+q.sortBy()+`
		LIMIT $10 OFFSET $11`,
		q.Source, q.Label, q.Feeds, q.Ecosystems, q.LitmusClasses, q.TopLevelOnly,
		q.Formula, q.requireLitmus(), q.Domains, q.Limit, q.Offset,
		q.searchTerm())
	if err != nil {
		return nil, fmt.Errorf("hopper: feed samples: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) feedSamplesCountPG(ctx context.Context, q *FeedQuery) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx, `
		SELECT count(*) FROM samples
		WHERE ($1 = '' OR source = $1)
			AND ($2 = '' OR label = $2)
			AND cleave_result IS NOT NULL
			AND (coalesce(cardinality($3::text[]), 0) = 0 OR feed = ANY($3))
			AND (coalesce(cardinality($4::text[]), 0) = 0 OR ecosystem = ANY($4))
			AND (coalesce(cardinality($5::int[]), 0) = 0 OR `+q.feedClassExpr()+` = ANY($5))
			AND (NOT $6 OR parent = '')
			AND ($7 = '' OR formula = $7)
			AND (NOT $8 OR litmus_result IS NOT NULL)
			AND (coalesce(cardinality($9::text[]), 0) = 0 OR domain = ANY($9))
			AND ($10 = '' OR filename ILIKE '%' || $10 || '%' ESCAPE '\'
				OR sha256 = $10)`,
		q.Source, q.Label, q.Feeds, q.Ecosystems, q.LitmusClasses, q.TopLevelOnly,
		q.Formula, q.requireLitmus(), q.Domains, q.searchTerm()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("hopper: feed samples count: %w", err)
	}
	return n, nil
}

func (db *DB) feedSourcesPG(ctx context.Context, source, label string) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT feed FROM samples
		WHERE ($1 = '' OR source = $1) AND ($2 = '' OR label = $2) AND feed != ''
		ORDER BY feed`, source, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed sources: %w", err)
	}
	return scanPGStrings(rows)
}

func (db *DB) feedEcosystemsPG(ctx context.Context, source, label string, since time.Time) ([]string, error) {
	var sincePtr *time.Time
	if !since.IsZero() {
		u := since.UTC()
		sincePtr = &u
	}
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT ecosystem FROM samples
		WHERE ($1 = '' OR source = $1) AND ($2 = '' OR label = $2) AND ecosystem != ''
		  AND ($3::timestamptz IS NULL OR created_at >= $3)
		ORDER BY ecosystem`, source, label, sincePtr)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed ecosystems: %w", err)
	}
	return scanPGStrings(rows)
}

func (db *DB) distinctEcosystemsPG(ctx context.Context) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT ecosystem FROM samples WHERE ecosystem <> ''
		UNION
		SELECT ecosystem FROM sample_locations WHERE ecosystem <> ''
		ORDER BY ecosystem`)
	if err != nil {
		return nil, fmt.Errorf("hopper: distinct ecosystems: %w", err)
	}
	return scanPGStrings(rows)
}

func (db *DB) updateEcosystemsPG(ctx context.Context, mapping map[string]string) (int64, error) {
	// One CASE statement per table, filtered to the remapped values via an
	// array param so the partial idx_samples_ecosystem can drive the scan on
	// samples; sample_locations is seq-scanned exactly once.
	keys := sortedKeys(mapping)
	var caseExpr strings.Builder
	args := make([]any, 0, len(keys)*2+1)
	caseExpr.WriteString("CASE ecosystem")
	for _, k := range keys {
		fmt.Fprintf(&caseExpr, " WHEN $%d THEN $%d", len(args)+1, len(args)+2)
		args = append(args, k, mapping[k])
	}
	caseExpr.WriteString(" END")
	args = append(args, keys)
	filter := fmt.Sprintf("$%d::text[]", len(args))

	var total int64
	for _, table := range []string{"samples", "sample_locations"} {
		// #nosec G201 -- table is a fixed local literal; all values are bound params.
		q := fmt.Sprintf("UPDATE %s SET ecosystem = %s WHERE ecosystem = ANY(%s)", table, caseExpr.String(), filter)
		tag, err := db.pool.Exec(ctx, q, args...)
		if err != nil {
			return total, fmt.Errorf("hopper: update %s ecosystem: %w", table, err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}

func (db *DB) feedDomainsPG(ctx context.Context, source, label string) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT domain FROM samples
		WHERE ($1 = '' OR source = $1) AND ($2 = '' OR label = $2) AND domain != ''
		ORDER BY domain`, source, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed domains: %w", err)
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
//
// These return up to limit candidate jobs in priority order. Claim ownership
// is tracked entirely in memory by workerTracker — see cmd/hopper/api.go for
// rationale. The handler over-fetches and uses tryClaimBatch to skip jobs
// already held by other workers.

// unanalyzedCandidatesPG returns Tier 1 work (samples that have never been
// analyzed). A random SHA pivot avoids time/path clustering and spreads
// concurrent pollers across the queue without ORDER BY random().
func (db *DB) unanalyzedCandidatesPG(ctx context.Context, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	pivot := randomSHA256Pivot()
	rows, err := db.pool.Query(ctx, `
		WITH picked AS (
			SELECT sha256, path, size_bytes, file_type, 0 AS pass
			FROM samples
			WHERE sha256 >= $2
			  AND cleave_result IS NULL AND skip = '' AND parent = ''
			  AND (note = '' OR last_error_at IS NULL OR last_error_at < $1)
			  AND attempts < $4
			ORDER BY sha256
			LIMIT $3
		),
		wrapped AS (
			SELECT sha256, path, size_bytes, file_type, 1 AS pass
			FROM samples
			WHERE sha256 < $2
			  AND cleave_result IS NULL AND skip = '' AND parent = ''
			  AND (note = '' OR last_error_at IS NULL OR last_error_at < $1)
			  AND attempts < $4
			ORDER BY sha256
			LIMIT $3
		)
		SELECT sha256, path, size_bytes, file_type
		FROM (
			SELECT sha256, path, size_bytes, file_type, pass FROM picked
			UNION ALL
			SELECT sha256, path, size_bytes, file_type, pass FROM wrapped
		) q
		ORDER BY pass, sha256
		LIMIT $3`,
		hopperStart.UTC(), pivot, limit, maxClaimAttempts)
	if err != nil {
		return nil, fmt.Errorf("hopper: unanalyzed candidates: %w", err)
	}
	return scanClaimRows(rows)
}

// forcedRescanCandidatesPG returns Tier 0 work: samples explicitly re-
// queued by RequestRescan (rescan_priority = 2). The idx_samples_rescan_queue
// partial index keeps this scan O(active queued count) regardless of table
// size. Rows leave the index as workers complete them (StoreResult clears the
// queue fields) so the index stays tiny.
//
// The query does NOT filter on `cleave_result IS NULL`: requestRescanPG
// leaves the prior envelope in place so readers see it during the rescan
// window. Tier 1 (`cleave_result IS NULL`) therefore can't overlap with
// this tier, and overlap with Tier 2/3 is harmless because Tier 0 drains
// first and tryClaimBatch dedupes in-memory.
func (db *DB) forcedRescanCandidatesPG(ctx context.Context, limit int) ([]ClaimJob, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE rescan_priority = 2
		  AND skip = '' AND parent = ''
		ORDER BY rescan_requested_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: forced rescan candidates: %w", err)
	}
	return scanClaimRows(rows)
}

// repairCandidatesPG returns repair-tier jobs (rescan_priority = 1), FIFO by
// request time with worst score as tiebreak, via the idx_samples_rescan_queue
// partial index — cheap regardless of backlog size.
func (db *DB) repairCandidatesPG(ctx context.Context, limit int) ([]ClaimJob, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE rescan_priority = 1 AND skip = '' AND parent = ''
		ORDER BY rescan_requested_at ASC, score DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: repair candidates: %w", err)
	}
	return scanClaimRows(rows)
}

// queueRescanPG flags specific top-level samples for repair-tier re-analysis,
// leaving any already queued at a higher priority untouched.
func (db *DB) queueRescanPG(ctx context.Context, shas []string) (int64, error) {
	tag, err := db.pool.Exec(ctx,
		`UPDATE samples SET rescan_priority = 1,
		     rescan_requested_at = COALESCE(rescan_requested_at, now()), updated_at = now()
		 WHERE sha256 = ANY($1) AND parent = '' AND skip = '' AND rescan_priority = 0`, shas)
	if err != nil {
		return 0, fmt.Errorf("hopper: queue rescan: %w", err)
	}
	return tag.RowsAffected(), nil
}

// queueMissingMembersForRepairPG flags every truncated top-level archive that
// has no member rows. The "truncated" marker is only ever set (never false —
// clearCompactionMarkers deletes it on reassembly), so its presence is the
// signal. One-time NOT EXISTS scan; the repair tier then drains the flag cheaply.
func (db *DB) queueMissingMembersForRepairPG(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples p SET rescan_priority = 1, rescan_requested_at = now(), updated_at = now()
		WHERE p.parent = '' AND p.skip = '' AND p.rescan_priority = 0
		  AND p.cleave_result IS NOT NULL
		  AND (p.cleave_result->>'truncated') IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM samples m WHERE m.parent = p.sha256)`)
	if err != nil {
		return 0, fmt.Errorf("hopper: queue missing-member archives: %w", err)
	}
	return tag.RowsAffected(), nil
}

// sampleAnalyzedPG is the PG implementation of SampleAnalyzed. Reads two
// booleans via the primary-key index; never pulls cleave_result bytes.
func (db *DB) sampleAnalyzedPG(ctx context.Context, sha256 string) (exists, analyzed bool, err error) {
	err = db.pool.QueryRow(ctx,
		`SELECT cleave_result IS NOT NULL FROM samples WHERE sha256 = $1`, sha256,
	).Scan(&analyzed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("hopper: sample analyzed lookup: %w", err)
	}
	return true, analyzed, nil
}

// uploadCandidatesPG returns interactive uploads waiting for analysis,
// ordered by insertion (id ASC). Drained ahead of every other tier in
// claimJobs so prism users see results as soon as a worker is free.
func (db *DB) uploadCandidatesPG(ctx context.Context, limit int) ([]ClaimJob, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE source = 'upload' AND cleave_result IS NULL
		  AND skip = '' AND parent = ''
		ORDER BY id ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: upload candidates: %w", err)
	}
	return scanClaimRows(rows)
}

// forceRescanCandidatesPG returns Tier 2 work: previously analyzed samples
// under the named path prefixes whose analysis predates hopperStart.
func (db *DB) forceRescanCandidatesPG(ctx context.Context, hopperStart time.Time, prefixes []string, limit int) ([]ClaimJob, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''
		  AND analyzed_at < $1
		  AND (path = ANY($2) OR path LIKE ANY($2))
		  AND (note = '' OR last_error_at IS NULL OR last_error_at < $1)
		ORDER BY updated_at ASC, id
		LIMIT $3`,
		hopperStart.UTC(), pathPatterns(prefixes), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: force-rescan candidates: %w", err)
	}
	return scanClaimRows(rows)
}

// staleTraitsCandidatesPG returns Tier 3 work: samples analyzed with a
// different traits_version more than rescanAge ago. Prioritizes label
// disagreements and boundary-confidence rows.
func (db *DB) staleTraitsCandidatesPG(
	ctx context.Context, currentTraits string, rescanAge time.Duration,
	hopperStart time.Time, limit int,
) ([]ClaimJob, error) {
	if currentTraits == "" {
		return nil, nil
	}
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''
		  AND traits_version != $1
		  AND analyzed_at < $2
		  AND (note = '' OR last_error_at IS NULL OR last_error_at < $3)
		ORDER BY
		  CASE
		    WHEN label = 'good' AND (max_crit >= 5 OR suspicious_count >= 2) THEN 0
		    WHEN label = 'bad' AND max_crit < 5 AND suspicious_count < 2 THEN 0
		    ELSE 1
		  END,
		  ABS(litmus_score - 0.5),
		  analyzed_at ASC NULLS LAST
		LIMIT $4`,
		currentTraits, time.Now().Add(-rescanAge).UTC(), hopperStart.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: stale-traits candidates: %w", err)
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
			return nil, fmt.Errorf("hopper: candidate scan: %w", err)
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
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
