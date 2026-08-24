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
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/atomdrift-project/hopper/pkgparse"
)

func openPG(ctx context.Context, dsn string, app AppName) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("hopper: parse dsn: %w", err)
	}
	// Sized for concurrent /api/next + /api/result + dashboard + ad-hoc psql
	// inspection. With long result-store transactions (UpdateCleaveResult
	// can cascade into ExplodeArchiveMembers) holding a connection for
	// seconds, 32 was tight enough to starve the dashboard's queries.
	// Observed steady state is ~8 in use (pool metrics), so 32 leaves ample
	// headroom without reserving 64×work_mem on the memory-tight PG host.
	cfg.MaxConns = 32
	cfg.MinConns = 8
	cfg.MaxConnIdleTime = 5 * time.Minute
	// Name the connections so pg_stat_activity can attribute them; see AppName
	// for why this is a required argument rather than a default. Set after
	// ParseConfig so it wins over any application_name in the DSN — the caller's
	// identity is not something a connection string should be able to spoof.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = string(app)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("hopper: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("hopper: ping: %w", err)
	}
	db := newDB()
	db.pool = pool
	return db, nil
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

// cleaveTraitArrayKeys lists every key the cleave compact report has used for a
// file's trait array, newest first: 'traits' (v8+), 'find' (v7), 'ts' (v4). Every
// place that derives max_crit/suspicious_count — the samples_derive_cleave_cols
// trigger, backfillPG Pass 1, rehealCleaveCritPG — must COALESCE across all of
// them, or rows in the missing format silently derive crit 0. When cleave renames
// the array again, prepend the new key here and to those three COALESCEs;
// TestCleaveTriggerKnowsAllTraitKeys fails until the trigger learns it. (The Go
// mirror lives in cleaveCompactFileEntry's struct tags in hopper.go.)
var cleaveTraitArrayKeys = []string{"traits", "find", "ts"}

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
		// top_traits: JSON []TopTrait of the few strongest suspicious+ trait
		// ids (see TopTrait). Nullable with no default, like litmus_class:
		// ADD COLUMN stays metadata-only and the backfill gate (top_traits
		// IS NULL) shrinks monotonically. The derive trigger fills it on
		// every write; backfillTopTraitsPG heals pre-trigger rows.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS top_traits TEXT`,
		// Drains itself as the top_traits backfill completes, keeping each
		// batch's gating SELECT off the heap (same pattern as elements).
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_result JSONB`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS llm_result JSONB`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS litmus_score DOUBLE PRECISION NOT NULL DEFAULT 0`,
		`CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_formula ON samples(formula) WHERE formula != ''`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS mtime TIMESTAMPTZ`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS first_analyzed_at TIMESTAMPTZ`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS marker_mtime TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source ON samples(source, label, analyzed_at DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_mtime ON samples(source, label, mtime DESC NULLS LAST) WHERE cleave_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_top_created_done ` +
			`ON samples(source, label, created_at DESC) ` +
			`WHERE cleave_result IS NOT NULL AND parent = '' AND litmus_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_feed ON samples(feed) WHERE feed != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_ecosystem ON samples(ecosystem) WHERE ecosystem != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_mtime ON samples(mtime) WHERE mtime IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type)`,
		// unanalyzedPG orders by id, so the pending set is indexed on id rather
		// than sha256 — that lets the query avoid a sort at 100M rows.
		`CREATE INDEX IF NOT EXISTS idx_samples_unanalyzed_id ON samples(id) WHERE cleave_result IS NULL`,
		// bigArchiveCandidatesPG hands the largest pending samples to
		// big-slot workers, ORDER BY size_bytes DESC. Without this index the
		// planner scanned a fat index and sorted — 4.5s/call, #5 by total
		// exec time (pg_stat_statements, 2026-08-22) — inside every
		// /api/next poll from a capable worker. Pending-set-only, so it
		// stays a few MB regardless of corpus size.
		`CREATE INDEX IF NOT EXISTS idx_samples_pending_size ON samples(size_bytes DESC) ` +
			`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`,
		// The walk's mark-replaced UPDATE joins staged paths against live
		// pending rows (s.path = st.sample_path AND skip = '' AND
		// cleave_result IS NULL). samples has no other path index, so every
		// walk batch seq-scanned the 143GB heap — 8.8s/call, #4 by total
		// exec time. Same tiny pending-set footprint as above.
		`CREATE INDEX IF NOT EXISTS idx_samples_pending_path ON samples(path) ` +
			`WHERE cleave_result IS NULL AND skip = ''`,
		// Covers falsePositivesPG / truePositivesPG / falseNegativesPG — all filter
		// (label, score, cleave_result IS NOT NULL, status='', skip='').
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
		// Cyclotron's durable retry budgets count one queue-specific report type
		// per sample. Including created_at also covers the existing analysis-relative
		// report exclusions without a heap walk.
		`CREATE INDEX IF NOT EXISTS idx_reports_sha256_type_created ` +
			`ON reports(sha256, report_type, created_at DESC)`,
		// External-corroboration ledger (see schema.sql) and the denormalized
		// samples.corroborated flag it maintains. The ADD COLUMN has a constant
		// default, so it is a metadata-only change (no table rewrite) on PG11+.
		`CREATE TABLE IF NOT EXISTS sightings (
			source     TEXT NOT NULL,
			subject    TEXT NOT NULL,
			url        TEXT NOT NULL DEFAULT '',
			note       TEXT NOT NULL DEFAULT '',
			first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (source, subject)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sightings_subject ON sightings(subject)`,
		// A claim is more than "somebody flagged this". Each column here was a
		// question the flattened row could not answer: which body of evidence
		// (so mirrors of one corpus count once), which releases, how strong a
		// claim, and when the SOURCE said it as opposed to when we heard it.
		`ALTER TABLE sightings ADD COLUMN IF NOT EXISTS operator TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sightings ADD COLUMN IF NOT EXISTS affected TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sightings ADD COLUMN IF NOT EXISTS claim TEXT NOT NULL DEFAULT 'malicious'`,
		`ALTER TABLE sightings ADD COLUMN IF NOT EXISTS filename TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sightings ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ`,
		// Rows written before the operator column meant their source's family;
		// filling them from the same map keeps corroboration counts identical
		// across the migration instead of briefly treating mirrors as
		// independent.
		`UPDATE sightings SET operator = 'github-advisories' WHERE operator = '' AND source IN ('ghsa','supplychain')`,
		`UPDATE sightings SET operator = 'ossf-malpkgs' WHERE operator = '' AND source IN ('osv','ossf')`,
		`UPDATE sightings SET operator = source WHERE operator = ''`,
		// The key gains the version. One source can make two separate claims
		// about one package — ossf carries a report for @whalent/agent
		// 0.3.230-0.3.302 and another for 0.3.358 — and the old key kept
		// whichever landed last.
		//
		// It stays a PRIMARY KEY rather than becoming a unique index because
		// sightings is a PUBLISHED table (see scripts/replica/
		// replicated-tables.sh): logical replication needs a replica identity
		// for every UPDATE and DELETE, and a primary key is the one every
		// other table here uses. A plain unique index would have left this
		// table's identity unset and broken apply on the replica.
		//
		// Guarded on the column count rather than run unconditionally: the
		// only two keys this table ever has are the legacy pair and this
		// triple, and rebuilding a primary key on every startup would cost an
		// index rebuild for nothing. Existing rows all have affected = '', so
		// the widened key cannot collide.
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conrelid = 'sightings'::regclass AND contype = 'p'
				  AND array_length(conkey, 1) <> 3
			) THEN
				ALTER TABLE sightings DROP CONSTRAINT sightings_pkey;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conrelid = 'sightings'::regclass AND contype = 'p'
			) THEN
				ALTER TABLE sightings ADD PRIMARY KEY (source, subject, affected);
			END IF;
		END $$`,
		// The cohort query: what entered our world recently, strongest claims
		// first. Partial, because a benchmark drawing a fresh cohort is asking
		// about malware and the suspicious rows outnumber it.
		`CREATE INDEX IF NOT EXISTS idx_sightings_recent ON sightings(first_seen DESC) WHERE claim = 'malicious'`,
		// Sighted triage has two ordered walks: digest claims and PURL claims. The
		// leading expression lets both seek their half of the ledger and then read
		// first_seen in queue order, stopping as soon as the requested batch fills.
		// INCLUDE keeps subject/version scope off the heap. This is intentionally
		// separate from idx_sightings_recent: cohort readers do not constrain the
		// subject kind and need first_seen itself to remain the leading key.
		`CREATE INDEX IF NOT EXISTS idx_sightings_review_queue ` +
			`ON sightings ((starts_with(subject, 'pkg:')), first_seen DESC) ` +
			`INCLUDE (subject, affected) WHERE claim IN ('malicious', 'suspicious')`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS corroborated BOOLEAN NOT NULL DEFAULT false`,
		// Partial indexes holding only corroborated top-level ready rows: the
		// "?feeds=1" filter (FeedQuery.Corroborated) walks these in created_at
		// order and stops at LIMIT without a sort, and because the subset is a
		// small fraction of samples the index stays tiny. One plain-recency and
		// one ecosystem-prefixed variant, mirroring idx_samples_top_ready_created
		// / idx_samples_eco_top_created so an ecosystem-filtered corroborated feed
		// is also an ordered seek.
		`CREATE INDEX IF NOT EXISTS idx_samples_corroborated_created ` +
			`ON samples(created_at DESC) ` +
			`WHERE corroborated AND parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL`,
		// conflictReviewPG: good+bad conflicts flagged skip='conflict'.
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
		// Per-route triage windows (TriageHighest/TriageLowest, 2026-08-03
		// redesign): each file_type's top/bottom-K by litmus_score. The
		// leading file_type key lets the per-route LATERAL walk each route's
		// score tail as a short ordered scan. litmus_score IS NOT NULL is in
		// the predicate (never-scanned rows rank nowhere), so no NULLS
		// spelling gymnastics are needed for planner matching. The older
		// class-gated idx_samples_{good_hostile,bad_clean}_score indexes
		// stay for any remaining class-band consumers.
		`CREATE INDEX IF NOT EXISTS idx_samples_good_route_score ` +
			`ON samples(file_type, litmus_score DESC) ` +
			`WHERE label = 'good' AND litmus_score IS NOT NULL AND cleave_result IS NOT NULL AND skip = ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_bad_route_score ` +
			`ON samples(file_type, litmus_score ASC) ` +
			`WHERE label = 'bad' AND litmus_score IS NOT NULL AND cleave_result IS NOT NULL AND skip = ''`,
		// TriageStranded's member walk: good members with real findings,
		// risk-score descending; parent's bad label is probed per row via
		// the sha256 unique index (cross-row predicates can't live in a
		// partial index). StrandedMembers reuses it via the parent column.
		`CREATE INDEX IF NOT EXISTS idx_samples_stranded_member ` +
			`ON samples(score DESC, id DESC) ` +
			`WHERE label = 'good' AND parent != '' AND score > 0 AND max_crit >= 3 AND cleave_result IS NOT NULL AND skip = ''`,
		// The five newest-first selectors (TriageBad/Good/New/Review/Sighted). Without
		// these the planner walks idx_samples_top_created — which carries only
		// parent = '' — and applies label plus the detection predicate as a
		// filter, so cost scales with how RARE the queue's population is, not
		// how large. Measured against the live table at LIMIT 64: sighted 99.1s
		// (~1.3k matching rows in a ~10.2M-entry index, so it scans almost all
		// of it), good 7.97s, bad 7.85s, new 1.00s — every one of them an
		// Incremental Sort or quicksort rather than an ordered walk. The stale
		// selectors over the same populations run in 3.7-4.7ms because they
		// have a matching partial index; these are the missing mirrors.
		//
		// created_at is NOT NULL, so unlike idx_samples_good_hostile_score no
		// NULLS spelling is needed for the DESC key to match the ORDER BY.
		// Each WHERE must stay byte-identical to its selector's predicate,
		// skip = '' and path <> '' included, or the planner will not match the
		// partial. path <> '' drops reference-only rows (registry/fetched)
		// that triage would otherwise hand to cyclotron with no bytes to fetch,
		// and that the stale-traits claim tier would otherwise hand to a worker
		// as a claim it can never satisfy.
		//
		// Recreate when an older definition is missing path <> '': CREATE INDEX
		// IF NOT EXISTS will not rewrite a pre-existing partial predicate.
		`DO $$
		DECLARE
			idx text;
			def text;
		BEGIN
			FOREACH idx IN ARRAY ARRAY[
				'idx_samples_bad_miss_newest',
				'idx_samples_good_repair_newest',
				'idx_samples_unknown_newest',
				'idx_samples_new_interesting',
				'idx_samples_bad_miss_stale',
				'idx_samples_good_repair_stale',
				'idx_samples_new_stale',
				'idx_samples_stale_traits',
				'idx_samples_stale_traits_pri'
			]
			LOOP
				SELECT pg_get_indexdef(to_regclass(idx)) INTO def;
				IF def IS NOT NULL AND def NOT ILIKE '%path <>%' THEN
					EXECUTE format('DROP INDEX %I', idx);
				END IF;
			END LOOP;
		END$$`,
		`CREATE INDEX IF NOT EXISTS idx_samples_bad_miss_newest ` +
			`ON samples(created_at DESC, id DESC) ` +
			`WHERE label = 'bad' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path <> '' AND max_crit < 5 AND suspicious_count < 2`,
		`CREATE INDEX IF NOT EXISTS idx_samples_good_repair_newest ` +
			`ON samples(created_at DESC, id DESC) ` +
			`WHERE label = 'good' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path <> '' AND (max_crit >= 5 OR suspicious_count >= 2)`,
		`CREATE INDEX IF NOT EXISTS idx_samples_unknown_newest ` +
			`ON samples(created_at DESC, id DESC) ` +
			`WHERE label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path <> '' AND suspicious_count >= 1`,
		`CREATE INDEX IF NOT EXISTS idx_samples_review_newest ` +
			`ON samples(created_at DESC, id DESC) ` +
			`WHERE label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path LIKE 'review/%'`,
		`CREATE INDEX IF NOT EXISTS idx_samples_review_interesting ` +
			`ON samples(corroborated DESC, max_crit DESC, suspicious_count DESC, ` +
			`litmus_score DESC NULLS LAST, analyzed_at, id) ` +
			`WHERE label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path LIKE 'review/%'`,
		`CREATE INDEX IF NOT EXISTS idx_samples_new_interesting ` +
			`ON samples(corroborated DESC, max_crit DESC, suspicious_count DESC, ` +
			`litmus_score DESC NULLS LAST, analyzed_at, id) ` +
			`WHERE label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path <> '' AND suspicious_count >= 1 AND path NOT LIKE 'review/%'`,
		// Sighted selection is now a ledger join ordered by sighting first_seen;
		// the old label+sample-created ordering index has no reader.
		`DROP INDEX IF EXISTS idx_samples_sighted_newest`,
		// The three TriageStale selectors: same populations as TriageBad /
		// TriageGood / TriageNew, ranked least-recently-analyzed first so triage
		// reaches verdicts rendered by old trait sets instead of re-working the
		// newest arrivals forever. Each index's WHERE must stay byte-identical
		// to its selector's predicate or the planner won't match the partial.
		//
		// These are not optional. Without them the planner falls back to
		// idx_samples_analyzed_at (which carries no label or detection
		// predicate), scans the whole analyzed-since window, and filters — the
		// bad queue measured 2m23s for a single LIMIT 64 poll against a live
		// table, the same failure idx_samples_stale_traits_pri was added to fix.
		// analyzed_at leads so the ORDER BY is an ordered scan that stops at
		// LIMIT. No NULLS spelling needed: ASC already defaults to NULLS LAST,
		// matching the selectors' `analyzed_at ASC NULLS LAST`.
		`CREATE INDEX IF NOT EXISTS idx_samples_bad_miss_stale ` +
			`ON samples(analyzed_at, id) ` +
			`WHERE label = 'bad' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path <> '' AND max_crit < 5 AND suspicious_count < 2`,
		`CREATE INDEX IF NOT EXISTS idx_samples_good_repair_stale ` +
			`ON samples(analyzed_at, id) ` +
			`WHERE label = 'good' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path <> '' AND (max_crit >= 5 OR suspicious_count >= 2)`,
		`CREATE INDEX IF NOT EXISTS idx_samples_new_stale ` +
			`ON samples(analyzed_at, id) ` +
			`WHERE label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' ` +
			`AND skip = '' AND path <> '' AND suspicious_count >= 1`,
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
		// idx_samples_unanalyzed_id (the pending set is small), and an index on
		// attempts would take a write on the hot claim path for every bump.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS skipped_at TIMESTAMPTZ`,
		// Covers FP/FN seed queries (falsePositivesPG, falseNegativesPG, light
		// variants, seedCandidatesInPathsPG) ordered by impact. The detection
		// filter (max_crit / suspicious_count) and cyclotron_attempted_at
		// cooldown apply as residual predicates after the indexed scan.
		// Covers SamplesInPipelineStage drain (impact-ordered mid-pipeline pull).
		`CREATE INDEX IF NOT EXISTS idx_samples_stale_traits ` +
			`ON samples(traits_version, analyzed_at) ` +
			`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = '' AND path <> ''`,
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
			`WHERE cleave_result IS NOT NULL AND skip = '' AND parent = '' AND path <> ''`,
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
		// purl_base: version-less canonical PURL, the package identity across
		// versions. Indexed (partial, skipping non-package files) so GROUP BY /
		// lookups by package are fast.
		`ALTER TABLE samples ADD COLUMN IF NOT EXISTS purl_base TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_domain ON samples(domain) WHERE domain != ''`,
		// Mirror of idx_samples_eco_top_created for the domain-filtered feed
		// (feedSamplesPG with domain = ANY($9)): an ordered seek to the domain
		// walked created_at DESC that stops at LIMIT with no sort and no per-row
		// JSONB read. Without it a popular domain (e.g. registry.npmjs.org) scans
		// hundreds of thousands of idx_samples_domain rows then sorts. Same partial
		// predicate as the ecosystem feed index, so the planner uses it whenever the
		// feed's TopLevelOnly + litmus-done flags are set (the normal feed path).
		// Built CONCURRENTLY by createIndexConcurrently.
		`CREATE INDEX IF NOT EXISTS idx_samples_package_version ON samples(package, version) WHERE package != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_purl_base ON samples(purl_base) WHERE purl_base != ''`,
		// GET /api/sample?purl= (SampleByPURL): equality on purl_base + version,
		// newest analyzed_at, analyzed rows only. idx_samples_purl_base is a
		// single-column identity index and cannot satisfy ORDER BY analyzed_at
		// DESC LIMIT 1; the prism feed query's ($n = '' OR col = $n) shape plus
		// that ORDER BY made the planner walk idx_samples_analyzed_at until a
		// purl hit (or the whole table, on a miss). Beamline times out at 2s.
		// Built CONCURRENTLY by createIndexConcurrently.
		//
		// Predicated exactly on sampleByPURLSQL's constants — no `parent = ''`,
		// which that query no longer tests (see sampleByPURLSQL). Created before
		// the old index is dropped so the lookup is never left uncovered.
		`CREATE INDEX IF NOT EXISTS idx_samples_purl_lookup ` +
			`ON samples (purl_base, version, analyzed_at DESC NULLS LAST) ` +
			`WHERE purl_base != '' AND litmus_result IS NOT NULL AND cleave_result IS NOT NULL`,
		`DROP INDEX IF EXISTS idx_samples_purl_analyzed`,
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
			rel           TEXT NOT NULL DEFAULT '',
			filename      TEXT NOT NULL DEFAULT '',
			source        TEXT NOT NULL DEFAULT '',
			feed          TEXT NOT NULL DEFAULT '',
			ecosystem     TEXT NOT NULL DEFAULT '',
			mtime         TIMESTAMPTZ,
			first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (sha256, path)
		)`,
		// Edge type to parent_sha256 ("" contained, "fetched", "unpacked",
		// "registry") — see SampleLocation.Rel. Metadata-only on PG 11+.
		`ALTER TABLE sample_locations ADD COLUMN IF NOT EXISTS rel TEXT NOT NULL DEFAULT ''`,
		// Indexes tuned for the expected read patterns.
		// Primary lookup: "where is this sha seen?" → idx_sl_sha256.
		// Feed/source rollups stay selective via the partial predicate.
		// Parent lookups are rare (exploded-from query) and stay partial.
		`CREATE INDEX IF NOT EXISTS idx_sl_sha256 ON sample_locations(sha256)`,
		// idx_sl_parent (parent_sha256 partial) was dropped 2026-08-22: it was
		// fully shadowed by idx_sl_parent_child below — same key, same partial
		// predicate, plus INCLUDE (sha256) — and idx_scan confirmed the planner
		// always preferred the covering variant. 8.3 GB of pure write tax.
		// Draino asks only for the oldest top-level hot-pool locations. Keeping
		// this partial makes that query proportional to the incoming pool rather
		// than the full historical location ledger.
		`CREATE INDEX IF NOT EXISTS idx_sl_incoming_mtime ON sample_locations(mtime, sha256, path) ` +
			`WHERE parent_sha256 = '' AND path LIKE 'incoming/%' AND mtime IS NOT NULL`,
		// Covering index for the reconcile reachability walk (cascadeMembersPG):
		// finding a parent's child sha256 is then index-only — no heap fetch —
		// which is what lets the BFS expand the alive set by index lookups instead
		// of seq-scanning + sorting all of sample_locations.
		`CREATE INDEX IF NOT EXISTS idx_sl_parent_child ON sample_locations(parent_sha256) INCLUDE (sha256) WHERE parent_sha256 <> ''`,
		// Reverse edge for the page's "found in" backlinks
		// (ParentArchivesForChild): a child sha -> the archives containing it.
		//
		// Keyed (sha256, parent_sha256, id), not covering, because this query
		// needs ORDER and not payload. Its predecessor idx_sl_sha256_parents put
		// parent_sha256 in an INCLUDE list, which buys index-only access but no
		// ordering — so DISTINCT ON (parent_sha256) had to sort every matching
		// row, and the planner preferred idx_sl_sha256 plus an explicit sort over
		// the 339 GB index built for the query. Measured 2026-08-21 on the
		// empty-file sha (e3b0c442…, ~6.5M locations): 183s and 1.6 GB spilled to
		// temp, with that covering index present and unused.
		//
		// Leading sha256 then parent_sha256 makes one child's entries arrive
		// already grouped by parent, so the DISTINCT ON is a streaming Unique over
		// an index-only scan and the LIMIT stops it early — O(limit), not
		// O(locations). id trails so "newest location for this parent" needs no
		// heap visit. id is DESC in the key on purpose: the ORDER BY below is
		// (parent_sha256 ASC, id DESC), and a forward scan can only satisfy that if
		// the index declares the same mixed direction — otherwise the planner sorts.
		//
		// The tail is what forces this. Fan-out is savagely skewed: p50 is 1
		// location and p99 is 40, but the empty file sits in ~6.5M and the next
		// worst in ~4.8M. Any plan proportional to locations is a timeout there,
		// covering index or not.
		//
		// It is also ~95 GB against the old 339 GB, because INCLUDE columns
		// disable btree deduplication — idx_sl_parent and idx_sl_parent_child
		// differ only by an INCLUDE and measure 8.2 GB against 109 GB.
		`CREATE INDEX IF NOT EXISTS idx_sl_child_parents ON sample_locations ` +
			`(sha256, parent_sha256, id DESC) WHERE parent_sha256 <> ''`,
		// Superseded by idx_sl_child_parents. Created before this drop so the
		// lookup is never left uncovered — same discipline as the purl_lookup /
		// purl_analyzed swap above.
		`DROP INDEX IF EXISTS idx_sl_sha256_parents`,
		// "Is this sha contained by any archive?" — the question that separates an
		// artifact worth judging on its own from an archive member that isn't.
		// Asked by the feed's TopLevelOnly, by KnownSHA256 before deciding whether
		// a producer must send bytes, and by the reference-parent repair.
		//
		// Partial on the containment rels, so it indexes only the edges that can
		// answer yes: reference edges (a fetched dependency, a registry sidecar)
		// are the majority on a package corpus and are excluded entirely, keeping
		// the index a fraction of the ledger. sha256 alone is the key — the
		// predicate settles rel and parent_sha256, so the probe is index-only and
		// never touches the heap.
		`CREATE INDEX IF NOT EXISTS idx_sl_containment ON sample_locations(sha256) ` +
			`WHERE parent_sha256 <> '' AND rel IN ` + containmentRelsSQL,
		// The inverse of idx_sl_containment: reference edges only — a package
		// naming a dependency, a registry sidecar. Enumerates "everything ever
		// referenced by something" without touching the containment edges that
		// dominate the ledger.
		//
		// Keyed on id with sha256 included so a paged walk is index-only. That is
		// what lets repairReferenceParents cost the number of referenced artifacts
		// rather than the number of archive members, and it answers "what pulled
		// this in" for the same price.
		`CREATE INDEX IF NOT EXISTS idx_sl_reference ON sample_locations(id) ` +
			`INCLUDE (sha256) WHERE parent_sha256 <> '' AND rel NOT IN ` + containmentRelsSQL,

		// The standalone counterpart to idx_sl_reference: ledger rows whose bytes
		// are stored under their own sha, no archive involved. Keyed on id with
		// sha256 included so repairStandaloneParentsPG pages it index-only, the
		// same shape and for the same reason as the reference walk above.
		//
		// Every other partial index on this table covers parent_sha256 <> ''.
		// This is the only one that answers "is this artifact stored standalone",
		// which is what the repair asks. Without it that question is a seq scan of
		// the whole ledger — and because the planner drives the semi-join from
		// this side rather than from samples, it is one scan per batch, which no
		// cursor on samples.id can prune.
		`CREATE INDEX IF NOT EXISTS idx_sl_standalone ON sample_locations(id) ` +
			`INCLUDE (sha256) WHERE parent_sha256 = ''`,

		// Retired locations are kept outside the active ledger: serving and
		// workflow queries stay small, while moves/prunes preserve path history.
		// Deliberately no FK: deleting a sample must not erase its provenance.
		`CREATE TABLE IF NOT EXISTS sample_location_history (
			id             BIGSERIAL PRIMARY KEY,
			sha256         TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
			path           TEXT NOT NULL CHECK (path <> ''),
			parent_sha256  TEXT NOT NULL DEFAULT '',
			rel            TEXT NOT NULL DEFAULT '',
			filename       TEXT NOT NULL DEFAULT '',
			source         TEXT NOT NULL DEFAULT '',
			feed           TEXT NOT NULL DEFAULT '',
			ecosystem      TEXT NOT NULL DEFAULT '',
			mtime          TIMESTAMPTZ,
			first_seen_at  TIMESTAMPTZ NOT NULL,
			last_seen_at   TIMESTAMPTZ NOT NULL,
			retired_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
			reason         TEXT NOT NULL CHECK (reason <> ''),
			successor_path TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_slh_sha256_retired ON sample_location_history(sha256, retired_at DESC, id DESC)`,

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
		`SELECT setval('sample_location_history_id_seq',
			GREATEST(
				(SELECT COALESCE(max(id), 0) FROM sample_location_history),
				(SELECT last_value FROM sample_location_history_id_seq)
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
		// formula, elements, max_crit, suspicious_count, top_traits) from the
		// cleave result on every write, reading the v7 'files' key first and
		// falling back to the legacy 'fs' key for cached rows. top_traits
		// mirrors encodeTopTraits (crit desc, original order within a level
		// via WITH ORDINALITY, capped at 3) — keep the two in sync. The per-file trait array was named
		// 'find' through v7 and renamed 'traits' in v8; max_crit/suspicious_count
		// read 'traits' first, then 'find', then the v4 'ts' key, so a missed
		// rename can't silently zero the criticality of every new sample (it did:
		// v8 landed ~2026-06-15 and every v8 row derived max_crit=0 until this
		// COALESCE learned 'traits'). BEFORE INSERT covers the bulk
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
			finds jsonb := COALESCE(NEW.cleave_result->'files'->0->'traits',
									NEW.cleave_result->'files'->0->'find',
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
			-- Benign rows (the vast majority, including bulk-inserted archive
			-- members) can never have top traits: suspicious_count = 0 means
			-- no entry clears the >= 4 bar, so skip the sort/agg entirely.
			IF NEW.suspicious_count = 0 THEN
				NEW.top_traits := '';
			ELSE
				-- jsonb_strip_nulls drops 'dep' for the (vast majority of)
				-- traits that don't carry one, keeping entries at {id, crit}.
				NEW.top_traits := COALESCE((
					SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('id', q.id, 'crit', q.crit, 'dep', q.dep)))::text
					FROM (
						SELECT COALESCE(t->>'id', t->>'i') AS id,
							   (COALESCE(t->>'crit', t->>'l'))::int AS crit,
							   t->'dep' AS dep
						FROM jsonb_array_elements(finds) WITH ORDINALITY AS f(t, ord)
						WHERE COALESCE(t->>'crit', t->>'l') IS NOT NULL
							AND (COALESCE(t->>'crit', t->>'l'))::int >= 4
							AND COALESCE(t->>'id', t->>'i') IS NOT NULL
						ORDER BY (COALESCE(t->>'crit', t->>'l'))::int DESC, ord
						LIMIT 3
					) AS q), '');
			END IF;
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
					WHEN COALESCE(NEW.litmus_result->>'lvl', NEW.litmus_result->>'l')::int <= %d THEN 1
					ELSE 0
				END);
			RETURN NEW;
		END;
		$$`, CriticalLevel, SuspiciousCeiling),
		`CREATE OR REPLACE TRIGGER samples_derive_litmus_score_trg
			BEFORE INSERT OR UPDATE OF litmus_result ON samples
			FOR EACH ROW EXECUTE FUNCTION samples_derive_litmus_score()`,

		// Indexes on the derived columns (no-op after first creation). These
		// are not cascaded away by DROP EXPRESSION (the columns persist), but
		// the IF NOT EXISTS keeps them correct on a fresh database too.
		`CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type)`,
		`CREATE INDEX IF NOT EXISTS idx_samples_formula   ON samples(formula)   WHERE formula   != ''`,

		// Drives the one-time Pass 1b heal in backfillPG: rows stored under the
		// v7 'files' key while file_type/score/formula were generated from the
		// legacy 'fs' key, so file_type is '' even though the JSON carries a
		// type. Self-draining — a row leaves the index the moment the backfill
		// (or the derive trigger) sets a non-empty file_type. The predicate
		// must stay in sync with pgFileTypeBackfillWhere. Built CONCURRENTLY by
		// the migration runner, so it never blocks writes.

		// Analyzer claim state moved to memory (see workerTracker in
		// cmd/hopper/api.go). Cyclotron reuses claimed_by / claimed_at for its
		// sparse, cross-process triage leases, but those point updates use the
		// sha256 index and do not need the old dashboard-oriented index.
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

		// Internal key/value store for resumable maintenance and migration state.
		`CREATE TABLE IF NOT EXISTS hopper_kv (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,

		// popular_packages: which package identities are worth extra scrutiny,
		// and how much. Written by poppy on each daily catalog refresh (~4k rows
		// per ecosystem, upserted), read by cyclotron's "popular" queue.
		//
		// Keyed on purl_base — the version-less identity — for the reason that
		// makes the whole mechanism work: a marker set on the package applies to
		// releases that do not exist yet, so tomorrow's version is already in
		// scope without anyone re-marking it. samples.purl_base is indexed
		// already, so the join costs nothing.
		//
		// Deliberately not a sighting. Sightings have the opposite polarity and
		// two existing queues read them: a "this is popular" sighting would
		// count toward TriageSecondOpinion's two-source quorum and would empty
		// TriageAcquit, which requires that no sighting has ever cited the
		// subject. Popularity is not evidence about a sample; it is a statement
		// about how much a mistake would cost.
		//
		// `source` is what generalizes it — a customer SBOM or an internal
		// allowlist is another source in the same table, no schema change.
		`CREATE TABLE IF NOT EXISTS popular_packages (
			purl_base  TEXT PRIMARY KEY,
			ecosystem  TEXT        NOT NULL,
			rank       INTEGER     NOT NULL,
			source     TEXT        NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// The queue orders by rank: a miss on the third most-used package
		// outranks a miss on the nine-hundredth.
		`CREATE INDEX IF NOT EXISTS idx_popular_rank ON popular_packages(rank)`,

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

		// claims: append-only ledger of analyzer-derived identity assertions —
		// files[].ident (PE version resources, bundle manifests, code
		// signatures) projected at StoreResult time. Registry identity stays
		// on samples (package/version/purl_base); the asset_claims view below
		// unions the two. See claims.go.
		`CREATE TABLE IF NOT EXISTS claims (
			sha256      TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
			source      TEXT NOT NULL,
			name        TEXT NOT NULL,
			version     TEXT NOT NULL DEFAULT '',
			signer      TEXT NOT NULL DEFAULT '',
			verified    BOOLEAN NOT NULL DEFAULT false,
			trust       TEXT NOT NULL DEFAULT '',
			observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (sha256, source)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_claims_name ON claims(name, version)`,
		`CREATE INDEX IF NOT EXISTS idx_claims_signer ON claims(signer) WHERE signer != ''`,

		// asset_claims: the one query surface for "who says these bytes are
		// what" — registry claims and filename parses (both from samples)
		// unioned with analyzer claims. Every branch is exact-match indexed
		// (idx_samples_package_version, idx_claims_name), so a name= or
		// purl-derived filter pushes down into each. The 'filename' branch
		// is the pre-registry population: identity parsed from the name the
		// file travels under (pkgparse, at walk/upload time), the weakest
		// claim and labeled as such — thirty years of wuftpd-10.9.2.tgz
		// belong in the same query as pkg:npm/lodash.
		`CREATE OR REPLACE VIEW asset_claims AS
			SELECT sha256, 'registry' AS source, package AS name, version,
			       '' AS signer, false AS verified, '' AS trust, domain,
			       created_at AS observed_at
			  FROM samples WHERE purl_base != ''
			UNION ALL
			SELECT sha256, 'filename' AS source, package AS name, version,
			       '' AS signer, false AS verified, '' AS trust, domain,
			       created_at AS observed_at
			  FROM samples WHERE purl_base = '' AND package != ''
			UNION ALL
			SELECT sha256, source, name, version, signer, verified, trust,
			       '' AS domain, observed_at
			  FROM claims`,
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

// isDeferrableIndexDDL reports whether ddl is index or stats work that can
// wait until after the server is serving. A missing or stale index only makes
// queries slower; a regular DROP/CREATE INDEX takes ACCESS EXCLUSIVE, which
// cannot run while a logical-replication tablesync COPY holds ACCESS SHARE
// (hours on samples). ANALYZE is the same class: useful, never required to
// accept work. Startup must not die on any of these.
func isDeferrableIndexDDL(ddl string) bool {
	s := strings.TrimSpace(ddl)
	u := strings.ToUpper(s)
	switch {
	case strings.HasPrefix(s, "CREATE INDEX"), strings.HasPrefix(u, "DROP INDEX"):
		return true
	case strings.HasPrefix(u, "ANALYZE "):
		return true
	case strings.HasPrefix(u, "DO $$") && strings.Contains(u, "DROP INDEX"):
		return true
	default:
		return false
	}
}

// migrateServingPG applies the migrations a server needs before it can safely
// accept work — the base schema, columns, and the pg_trgm extension — and
// returns a function that builds the deferrable indexes (and ANALYZE). The
// caller runs that function in the background once it is serving, so a new
// index build or stale-index rewrite never blocks workers. On an established
// database every index already exists, so the returned function is a fast
// sequence of ledger-skipped no-ops.
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
	var declined int
	for _, ddl := range pgRuntimeMigrations() {
		if isDeferrableIndexDDL(ddl) {
			// In replica mode, decline the indexes slim-indexes.sh would drop
			// anyway rather than build them first. Not recorded in the ledger:
			// see SetReplicaIndexPolicy.
			skip, err := db.skipReplicaIndex(ddl)
			if err != nil {
				return nil, fmt.Errorf("hopper: migrate: %w", err)
			}
			if skip {
				declined++
				slog.Debug("replica index policy: declining index", "ddl", ddl)
				continue
			}
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
	// The trgm index sits on a published table, so it answers to the same
	// replica policy as every other index — it is built in the closure below,
	// but the decision belongs here with its peers.
	buildTrgmIndex := trgmReady
	if buildTrgmIndex {
		skip, err := db.skipReplicaIndex(trgmIndexDDL)
		if err != nil {
			return nil, fmt.Errorf("hopper: migrate: %w", err)
		}
		if skip {
			declined++
			buildTrgmIndex = false
		}
	}
	slog.Info("core migrations applied",
		"deferred_indexes", len(deferred), "declined_replica_indexes", declined)

	return func(ctx context.Context) error {
		for _, ddl := range deferred {
			if err := db.execPGMigrationDDL(ctx, ddl, allowRewrite); err != nil {
				// Serving already started; a lock timeout here (e.g. ACCESS
				// EXCLUSIVE behind a logical-replication COPY) must not take
				// hopper down. The caller retries until this returns nil.
				return fmt.Errorf("hopper: migrate index: %w", err)
			}
		}
		if buildTrgmIndex {
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
		// Runs after the edge backfill, which is what its predicate reads: a row
		// whose edges have not been backfilled yet would look parentless and be
		// repaired on no evidence.
		if err := db.repairReferenceParents(ctx); err != nil {
			slog.Warn("reference-parent repair incomplete; will resume on next boot", "error", err)
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
	if name, ok := concurrentDropIndexDDL(ddl); ok {
		if err := db.dropIndexConcurrently(ctx, name); err != nil {
			return err
		}
		return db.recordPGMigration(ctx, id, ddl)
	}
	if isIndexRewriteDO(ddl) {
		if err := db.execIndexRewriteDO(ctx, ddl); err != nil {
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
	if isIndexRewriteDO(ddl) {
		return db.pgIndexRewriteAlreadySatisfied(ctx, ddl)
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

func concurrentDropIndexDDL(ddl string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(ddl))
	if len(fields) < 3 || !strings.EqualFold(fields[0], "DROP") || !strings.EqualFold(fields[1], "INDEX") {
		return "", false
	}
	i := 2
	if i < len(fields) && strings.EqualFold(fields[i], "CONCURRENTLY") {
		i++
	}
	if i+1 < len(fields) && strings.EqualFold(fields[i], "IF") && strings.EqualFold(fields[i+1], "EXISTS") {
		i += 2
	}
	if i >= len(fields) {
		return "", false
	}
	return strings.Trim(fields[i], ";"), true
}

func isIndexRewriteDO(ddl string) bool {
	s := strings.TrimSpace(ddl)
	u := strings.ToUpper(s)
	return strings.HasPrefix(u, "DO $$") && strings.Contains(u, "DROP INDEX")
}

func indexNamesInDDL(ddl string) []string {
	var names []string
	seen := map[string]struct{}{}
	for s := ddl; ; {
		i := strings.Index(s, "idx_")
		if i < 0 {
			return names
		}
		j := i + len("idx_")
		for j < len(s) {
			c := s[j]
			if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				break
			}
			j++
		}
		name := s[i:j]
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
		s = s[j:]
	}
}

func indexRewriteHasKnownPredicate(ddl string) bool {
	return strings.Contains(ddl, "NOT ILIKE '%path <>%'") ||
		(strings.Contains(ddl, "idx_samples_claimable") && strings.Contains(ddl, "updated_at NULLS FIRST"))
}

func indexDefNeedsRewrite(ddl, def string) bool {
	lower := strings.ToLower(def)
	if strings.Contains(ddl, "NOT ILIKE '%path <>%'") {
		return !strings.Contains(lower, "path <>")
	}
	if strings.Contains(ddl, "idx_samples_claimable") {
		return !strings.Contains(lower, "on public.samples using btree (updated_at nulls first, id)") ||
			!strings.Contains(lower, "where ((cleave_result is null) and (skip = ''::text) and (parent = ''::text))")
	}
	return true
}

func (db *DB) pgIndexDef(ctx context.Context, name string) (def string, exists bool, err error) {
	var s *string
	if err := db.pool.QueryRow(ctx, `SELECT pg_get_indexdef(to_regclass($1))`, name).Scan(&s); err != nil {
		return "", false, err
	}
	if s == nil || *s == "" {
		return "", false, nil
	}
	return *s, true, nil
}

func (db *DB) pgIndexRewriteAlreadySatisfied(ctx context.Context, ddl string) (bool, error) {
	if !indexRewriteHasKnownPredicate(ddl) {
		return false, nil
	}
	names := indexNamesInDDL(ddl)
	if len(names) == 0 {
		return false, nil
	}
	for _, name := range names {
		def, exists, err := db.pgIndexDef(ctx, name)
		if err != nil {
			return false, err
		}
		if exists && indexDefNeedsRewrite(ddl, def) {
			return false, nil
		}
	}
	return true, nil
}

func (db *DB) execIndexRewriteDO(ctx context.Context, ddl string) error {
	// DROP INDEX CONCURRENTLY cannot run inside a DO block (it is not
	// transaction-safe). A regular DROP INDEX takes ACCESS EXCLUSIVE, which
	// waits forever behind a logical-replication COPY. Evaluate the catalog
	// predicate in Go and drop only the stale indexes concurrently.
	if !indexRewriteHasKnownPredicate(ddl) {
		return db.execMigrationWithLockRetry(ctx, ddl)
	}
	for _, name := range indexNamesInDDL(ddl) {
		def, exists, err := db.pgIndexDef(ctx, name)
		if err != nil {
			return err
		}
		if !exists || !indexDefNeedsRewrite(ddl, def) {
			continue
		}
		slog.Info("dropping stale migration index", "index", name)
		if err := db.dropIndexConcurrently(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) withUnlockedMigrationConn(ctx context.Context, fn func(*pgxpool.Conn) error) error {
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
		return fmt.Errorf("hopper: disable lock_timeout for index migration: %w", err)
	}
	return fn(conn)
}

func (db *DB) dropIndexConcurrently(ctx context.Context, indexName string) error {
	drop := "DROP INDEX CONCURRENTLY IF EXISTS " + indexName
	start := time.Now()
	slog.Info("executing migration ddl", "ddl", drop)
	err := db.withUnlockedMigrationConn(ctx, func(conn *pgxpool.Conn) error {
		_, err := conn.Exec(ctx, drop)
		return err
	})
	if err != nil {
		return err
	}
	slog.Info("migration ddl complete", "elapsed", time.Since(start).String())
	return nil
}

func (db *DB) createIndexConcurrently(ctx context.Context, ddl, indexName string) error {
	return db.withUnlockedMigrationConn(ctx, func(conn *pgxpool.Conn) error {
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
	})
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
	url, domain, package, version, purl_base,
	COALESCE(top_traits, '') AS top_traits`

// pgSampleColsLight excludes all result blobs to avoid loading potentially
// large JSON when only metadata is needed (e.g. claim queries).
const pgSampleColsLight = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime, traits_version,
	url, domain, package, version, purl_base,
	COALESCE(top_traits, '') AS top_traits`

// pgSampleColsFeed is pgSampleCols with cleave_result — the one JSONB blob the
// feed never renders (the archive member tree, up to megabytes) — replaced by a
// NULL literal. Selecting a literal rather than the column keeps the projection
// positionally identical to pgSampleCols, so pgSampleDest / scanPGSamples read
// it unchanged (CleaveResult scans as nil), while the planner skips the
// heap-TOAST detoast of that column for every one of the up-to-500 feed rows.
// litmus_result stays: the feed derives each row's criticality from it.
// llm_result stays too: it is one small object (a one-sentence rationale plus
// confidence) and the feed renders it on every suspicious/hostile row. Only
// feedSamplesPG uses this; the detail page (SampleBySHA256) still selects the
// full row.
const pgSampleColsFeed = `id, sha256, source, feed, ecosystem, filename, file_type,
	size_bytes, label, label_source, NULL::jsonb AS cleave_result, litmus_result, llm_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip, formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime, traits_version,
	url, domain, package, version, purl_base,
	COALESCE(top_traits, '') AS top_traits`

// pgSampleColsRegistryExtra appends the registry-record scalars prism renders —
// the marketplace display title, short description (capped here so an
// essay-length listing can't bloat the projection), and install/download
// count — extracted from the provenance sidecar's registry record. Selected
// only by FeedSamples and SampleBySHA256: extracting them detoasts
// provenance, a cost the claim projections don't pay. scanPGSamplesFeed and
// scanPGSample are the matching readers.
const pgSampleColsRegistryExtra = `,
	COALESCE(provenance->'registry'->'record'->>'title', '') AS registry_title,
	COALESCE(LEFT(provenance->'registry'->'record'->>'description', 300), '') AS registry_description,
	COALESCE((provenance->'registry'->'record'->>'downloads_total')::bigint, 0) AS registry_downloads,
	corroborated`

func pgSampleDest(s *Sample) []any {
	return []any{
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.CleaveResult, &s.LitmusResult, &s.LLMResult, &s.LitmusScore,
		&s.Path, &s.Status, &s.Note, &s.CanonicalSHA256,
		&s.Parent, &s.Skip, &s.Formula, &s.Elements, &s.Score,
		&s.MaxCrit, &s.SuspiciousCount,
		&s.CreatedAt, &s.UpdatedAt, &s.AnalyzedAt, &s.FirstAnalyzedAt, &s.LastErrorAt, &s.Mtime, &s.MarkerMtime,
		&s.TraitsVersion,
		&s.URL, &s.Domain, &s.Package, &s.Version, &s.PURLBase,
		&s.TopTraits,
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
		&s.URL, &s.Domain, &s.Package, &s.Version, &s.PURLBase,
		&s.TopTraits,
	}
}

// scanPGSample reads one full sample row plus the registry extras — its only
// caller (sampleBySHA256PG) selects pgSampleCols + pgSampleColsRegistryExtra.
func scanPGSample(row pgx.Row) (*Sample, error) {
	s := &Sample{}
	err := row.Scan(append(pgSampleDest(s), &s.RegistryTitle, &s.RegistryDescription, &s.RegistryDownloads, &s.Corroborated)...)
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
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int <= %d THEN 1
					ELSE 0
				END
			)
		FROM samples `+where, CriticalLevel, CriticalLevel, SuspiciousCeiling), limit)
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
	// The samples row records the artifact; the locations row below records this
	// observation of it. parent/path are containment claims and belong only to
	// the former — see containmentColumns.
	samplesParent, samplesPath := containmentColumns(s)
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
			url, domain, package, version, provenance, fetched_at, purl_base)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$1, $11, $12, $13, $14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25, $26)
		`+sampleConflictUpdatePG,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
		s.SizeBytes, s.Label, s.LabelSource, samplesPath, s.Status,
		samplesParent, s.Skip, s.Elements,
		s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
		sanitizeJSONB(s.CleaveResult), sanitizeJSONB(s.LitmusResult),
		s.URL, s.Domain, s.Package, s.Version, sanitizeJSONB(s.Provenance), s.FetchedAt, s.PURLBase)
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
				(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (sha256, path) DO UPDATE SET
				rel = CASE WHEN EXCLUDED.rel <> '' THEN EXCLUDED.rel ELSE sample_locations.rel END,
				source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE sample_locations.source END,
				feed = CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE sample_locations.feed END,
				ecosystem = CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE sample_locations.ecosystem END,
				mtime = COALESCE(EXCLUDED.mtime, sample_locations.mtime)`+locationChangedPG,
			s.SHA256, s.Path, s.Parent, s.LocationRel, s.Filename, s.Source, s.Feed, s.Ecosystem, s.Mtime); err != nil {
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
	"parent", "rel", "skip", "elements", "max_crit", "suspicious_count",
	"mtime", "marker_mtime", "cleave_result", "litmus_result", "analyzed_at", "first_analyzed_at",
	"url", "domain", "package", "version", "provenance", "fetched_at",
	// The containment projection of parent/path, computed once in Go by
	// containmentColumns. Staging carries both spellings because the two
	// destinations want different ones: sample_locations records the
	// observation as it happened (parent/path/rel), samples records only what
	// the observation licenses as a containment claim.
	"sample_parent", "sample_path",
}

const insertBatchStagingCore = `CREATE TEMP TABLE _staging (
	sha256 TEXT, source TEXT, feed TEXT, ecosystem TEXT, filename TEXT,
	size_bytes BIGINT, label TEXT, label_source TEXT,
	path TEXT, status TEXT, canonical_sha256 TEXT,
	parent TEXT, rel TEXT, skip TEXT, elements TEXT,
	max_crit INTEGER, suspicious_count INTEGER,
	mtime TIMESTAMPTZ, marker_mtime TIMESTAMPTZ,
	cleave_result JSONB, litmus_result JSONB, analyzed_at TIMESTAMPTZ, first_analyzed_at TIMESTAMPTZ,
	url TEXT, domain TEXT, package TEXT, version TEXT, provenance JSONB, fetched_at TIMESTAMPTZ,
	sample_parent TEXT, sample_path TEXT
)`

// insertBatchStagingSessionDDL is the cross-transaction form used by
// insertSampleBatchPG, which stages once and then runs SEVERAL transactions
// over the same rows (see that function for why). The table is session-scoped,
// so the function must drop it before releasing its connection back to the
// pool — a leaked _staging on a pooled connection makes the next borrower's
// CREATE TEMP TABLE _staging fail.
const insertBatchStagingSessionDDL = insertBatchStagingCore

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
// Pool-precedence label resolution (rank: bad>good>sighted>unknown, see
// labelRank/labelRankSQL), evaluated in order — see classifyLabelTransition
// for the mirror used by logging:
//  1. incoming marker present        → take the marker's label, re-quarantine
//  2. stored marker, none incoming   → marker gone, the directory governs again
//  3. good+bad across pools          → resolve to bad, quarantine as 'conflict'
//  4. incoming outranks stored       → promote
//  5. otherwise                      → keep the stored label
//
// Only walker writes (parent=”) may touch the row; explode writes
// (parent=<archive-sha>) are excluded by the WHERE so an archive member never
// changes a top-level label or clobbers its path on a content-hash collision.
var sampleConflictUpdatePG = `ON CONFLICT (sha256) DO UPDATE SET
	label = CASE
		WHEN EXCLUDED.label_source = 'marker' THEN EXCLUDED.label
		WHEN samples.label_source = 'marker' THEN EXCLUDED.label
		WHEN (samples.label = 'good' AND EXCLUDED.label = 'bad')
		  OR (samples.label = 'bad' AND EXCLUDED.label = 'good') THEN 'bad'
		WHEN ` + labelRankSQL("EXCLUDED.label") + `
		   > ` + labelRankSQL("samples.label") + ` THEN EXCLUDED.label
		ELSE samples.label
	END,
	label_source = CASE
		WHEN EXCLUDED.label_source = 'marker' THEN 'marker'
		WHEN samples.label_source = 'marker' THEN EXCLUDED.label_source
		WHEN (samples.label = 'good' AND EXCLUDED.label = 'bad')
		  OR (samples.label = 'bad' AND EXCLUDED.label = 'good') THEN 'conflict'
		WHEN ` + labelRankSQL("EXCLUDED.label") + `
		   > ` + labelRankSQL("samples.label") + ` THEN EXCLUDED.label_source
		ELSE samples.label_source
	END,
	feed  = CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE samples.feed END,
	ecosystem = CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE samples.ecosystem END,
	path  = CASE WHEN EXCLUDED.path  <> ''   THEN EXCLUDED.path  ELSE samples.path  END,
	-- Track filename with path: a walk that relocates the bytes also renames the
	-- display name, so a stale sha-named filename (left by a relocation transient)
	-- heals to the current on-disk / sidecar-recorded name.
	filename = CASE WHEN EXCLUDED.path <> '' THEN EXCLUDED.filename ELSE samples.filename END,
	mtime = CASE WHEN EXCLUDED.mtime IS NOT NULL THEN EXCLUDED.mtime ELSE samples.mtime END,
	url     = CASE WHEN samples.url     = '' THEN EXCLUDED.url     ELSE samples.url     END,
	domain  = CASE WHEN samples.domain  = '' THEN EXCLUDED.domain  ELSE samples.domain  END,
	package    = CASE WHEN samples.package    = '' THEN EXCLUDED.package    ELSE samples.package    END,
	version = CASE WHEN samples.version = '' THEN EXCLUDED.version ELSE samples.version END,
	purl_base = CASE WHEN samples.purl_base = '' THEN EXCLUDED.purl_base ELSE samples.purl_base END,
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
		WHEN ` + labelRankSQL("EXCLUDED.label") + `
		   > ` + labelRankSQL("samples.label") + `
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
    OR (samples.purl_base = '' AND EXCLUDED.purl_base <> '')
    OR samples.skip IN ('missing','unsupported')
    -- Pool-precedence transitions must fire even when path/mtime are unchanged.
    OR (` + labelRankSQL("EXCLUDED.label") + `
      > ` + labelRankSQL("samples.label") + `)
    OR ((samples.label = 'good' AND EXCLUDED.label = 'bad')
      OR (samples.label = 'bad' AND EXCLUDED.label = 'good'))
    OR (EXCLUDED.label_source = 'marker'
        AND (samples.label <> EXCLUDED.label OR samples.label_source <> 'marker' OR samples.skip <> 'misclassified'))
    OR (samples.label_source = 'marker' AND EXCLUDED.label_source <> 'marker'))`

// insertBatchStagingInsert upserts the staged walk rows into samples. The
// trailing ORDER BY sha256 mirrors insertMembersFromStagingPG: walk batches and
// member stores frequently touch the SAME rows (an archive member exploded into
// samples is often also a file on disk the walker finds), and with both writers
// acquiring row locks in sha256 order they queue instead of deadlocking, and
// the queueing itself stays orderly. Measured 2026-08-22: this statement was
// 70% of all DB execution time with 10-deep transactionid convoys — ordering is
// load-bearing, not cosmetic. The leading column also satisfies DISTINCT ON.
var insertBatchStagingInsert = `INSERT INTO samples (
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result, analyzed_at, first_analyzed_at,
	url, domain, package, version, provenance, fetched_at)
SELECT DISTINCT ON (sha256)
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, sample_path, status,
	canonical_sha256, sample_parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result, analyzed_at, first_analyzed_at,
	url, domain, package, version, provenance, fetched_at
FROM _staging
ORDER BY sha256
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
		WHERE st.sample_parent = '' AND s.parent = ''
		  AND st.label_source <> 'marker'
		  AND ((s.label_source = 'marker' AND (s.label <> st.label OR s.skip = 'misclassified'))
		    OR (s.label_source <> 'marker'
		        AND ((s.label = 'good' AND st.label = 'bad')
		          OR (s.label = 'bad' AND st.label = 'good')
		          OR `+labelRankSQL("st.label")+`
		           > `+labelRankSQL("s.label")+`)))`)
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
		s.scrubNULs()     // PG TEXT can't hold 0x00 (SQLSTATE 22021); see scrubNULs.
		normalizeLabel(s) // "" is not a selectable label; see normalizeLabel.
		firstAnalyzedAt := s.FirstAnalyzedAt
		if firstAnalyzedAt == nil {
			firstAnalyzedAt = s.AnalyzedAt
		}
		samplesParent, samplesPath := containmentColumns(s)
		rows[i] = []any{
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status, s.SHA256,
			s.Parent, s.LocationRel, s.Skip, s.Elements, s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
			sanitizeJSONB(s.CleaveResult), sanitizeJSONB(s.LitmusResult), s.AnalyzedAt, firstAnalyzedAt,
			s.URL, s.Domain, s.Package, s.Version, sanitizeJSONB(s.Provenance), s.FetchedAt,
			samplesParent, samplesPath,
		}
	}
	return rows
}

// locationChangedPG guards the ON CONFLICT arms below so that re-observing an
// unchanged location writes nothing at all. Every walk re-observes nearly the
// whole corpus, and the old upsert rewrote each row unconditionally: it stamped
// last_seen_at = now() and the CASE arms wrote the existing value back when the
// incoming field was blank. Postgres has no same-value-skip, so each of those
// was a fresh row version — and because last_seen_at then rode in the INCLUDE
// list of idx_sl_sha256_parents no such update could ever be HOT, so one no-op
// re-observation cost a heap tuple plus an entry in all ten indexes. That churn,
// not new data, was what buried the logical replicas in WAL. last_seen_at is no
// longer maintained: nothing compares it against a threshold and nothing outside
// this package reads it.
//
// idx_sl_sha256_parents was replaced by idx_sl_child_parents on 2026-08-21 and
// last_seen_at is in no index at all now, so re-stamping it would be HOT-able
// again. That is not an invitation to resume: the column still has no reader,
// and this guard is what keeps an unchanged re-observation from writing any row
// version whatsoever. locationsForSHA256PG and the two dashboard queries still
// ORDER BY it; they sort by last-write, which is honest but is not the "last
// seen" their names imply — worth revisiting when someone touches them.
//
// Keep the predicate aligned with the SET list it guards — a field that is set
// but not tested here would silently stop being refreshed.
const locationChangedPG = `
	WHERE (EXCLUDED.rel <> ''       AND EXCLUDED.rel       IS DISTINCT FROM sample_locations.rel)
	   OR (EXCLUDED.source <> ''    AND EXCLUDED.source    IS DISTINCT FROM sample_locations.source)
	   OR (EXCLUDED.feed <> ''      AND EXCLUDED.feed      IS DISTINCT FROM sample_locations.feed)
	   OR (EXCLUDED.ecosystem <> '' AND EXCLUDED.ecosystem IS DISTINCT FROM sample_locations.ecosystem)
	   OR (EXCLUDED.mtime IS NOT NULL AND EXCLUDED.mtime IS DISTINCT FROM sample_locations.mtime)`

// locationsFromStagingPG fans _staging rows out into sample_locations. DISTINCT
// ON collapses duplicates within the batch; ON CONFLICT backfills fields that
// actually changed, without clobbering an existing mtime. Shared by the batch
// insert and the atomic store.
const locationsFromStagingPG = `
	INSERT INTO sample_locations
		(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
	SELECT DISTINCT ON (sha256, path)
		sha256, path, parent, rel, filename, source, feed, ecosystem, mtime
	  FROM _staging
	 WHERE path <> ''
	ON CONFLICT (sha256, path) DO UPDATE SET
		rel = CASE WHEN EXCLUDED.rel <> '' THEN EXCLUDED.rel ELSE sample_locations.rel END,
		source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE sample_locations.source END,
		feed = CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE sample_locations.feed END,
		ecosystem = CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE sample_locations.ecosystem END,
		mtime = COALESCE(EXCLUDED.mtime, sample_locations.mtime)` + locationChangedPG

// insertSampleBatchPG upserts one walk batch. It deliberately runs as TWO
// transactions over one session-scoped staging table, not one:
//
// The samples upsert takes ON CONFLICT row locks on every sha in the batch,
// and those rows are shared with the result-store path (archive members
// exploded into samples are usually also files on disk the walker sees). As a
// single transaction, those locks were held across the sample_locations
// fan-out and two more UPDATEs — multi-second work against a table whose
// indexes dwarf the buffer cache — and every concurrent store queued behind
// them. Measured 2026-08-22: this statement alone was ~70% of database
// execution time, 3.5s mean with a 1.5% cache-miss rate (pure lock wait), with
// 10-deep transactionid convoys behind single batches. Committing the samples
// upsert FIRST releases the contended locks in milliseconds-to-a-second;
// the derived writes then run without anyone queueing on them.
//
// Crash/failure window this buys into: tx1 committed, tx2 failed → sample
// rows exist with their location fan-out missing. That is benign and
// self-healing: the caller reports the batch failed, so the hash cache never
// records these files, and the next walk re-stages them — tx1 re-runs as a
// delta-guarded no-op and tx2 gets its retry. (The same shape as a crash
// between the two, which the single-transaction form also could not survive
// without the re-walk.)
func (db *DB) insertSampleBatchPG(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	rows := sampleStagingRows(samples)

	// One connection for the whole batch: the staging table is session-scoped
	// so it can outlive tx1. It MUST be dropped before the connection returns
	// to the pool — the next borrower's CREATE TEMP TABLE _staging would
	// collide — and the drop uses a detached context so a canceled batch
	// can't leak the table onto a healthy pooled connection.
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: acquire batch conn: %w", err)
	}
	defer conn.Release()
	defer func() {
		dropCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, derr := conn.Exec(dropCtx, `DROP TABLE IF EXISTS _staging`); derr != nil {
			// The connection is likely broken; poison it so the pool discards
			// it instead of handing the leftover table to the next borrower.
			slog.Warn("drop batch staging table failed; discarding connection", "error", derr)
			conn.Conn().Close(dropCtx) //nolint:errcheck,gosec // already tearing down
		}
	}()

	if _, err := conn.Exec(ctx, insertBatchStagingSessionDDL); err != nil {
		return 0, nil, fmt.Errorf("hopper: create staging: %w", err)
	}
	if _, err := conn.Conn().CopyFrom(ctx, pgx.Identifier{"_staging"}, insertBatchStagingCols, pgx.CopyFromRows(rows)); err != nil {
		return 0, nil, fmt.Errorf("hopper: copy to staging: %w", err)
	}

	// tx1: ONLY the contended samples upsert, so its row locks are released
	// the moment the batch's identity resolution lands.
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: begin batch: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	logLabelTransitionsPG(ctx, tx)

	tag, err := tx.Exec(ctx, insertBatchStagingInsert)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: insert from staging: %w", err)
	}
	inserted = tag.RowsAffected()
	if err := tx.Commit(ctx); err != nil {
		return 0, nil, fmt.Errorf("hopper: commit batch: %w", err)
	}

	// tx2: derived writes. These touch disjoint or per-row-cheap state (the
	// locations ledger, marker refresh, replaced marking) and no longer extend
	// the samples locks' hold time.
	tx2, err := conn.Begin(ctx)
	if err != nil {
		return inserted, nil, fmt.Errorf("hopper: begin batch fanout: %w", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck // commit or rollback

	if _, err := tx2.Exec(ctx, locationsFromStagingPG); err != nil {
		return inserted, nil, fmt.Errorf("hopper: upsert locations from staging: %w", err)
	}

	if _, err := tx2.Exec(ctx, `
		UPDATE samples s
		SET marker_mtime = st.marker_mtime
		FROM _staging st
		WHERE s.sha256 = st.sha256
			AND st.marker_mtime IS NOT NULL`); err != nil {
		return inserted, nil, fmt.Errorf("hopper: refresh marker mtime: %w", err)
	}

	// Mark stale rows whose path now belongs to a different SHA256.
	// This happens when a file is replaced on disk — the walk inserts a
	// new row for the new content but the old row lingers in the queue.
	if _, err := tx2.Exec(ctx, `
		UPDATE samples s
		SET skip = 'replaced'
		FROM _staging st
		WHERE s.path = st.sample_path
			AND st.sample_path != ''
			AND s.sha256 != st.sha256
			AND s.skip = ''
			AND s.cleave_result IS NULL`); err != nil {
		return inserted, nil, fmt.Errorf("hopper: mark replaced: %w", err)
	}

	if err := tx2.Commit(ctx); err != nil {
		return inserted, nil, fmt.Errorf("hopper: commit batch fanout: %w", err)
	}

	// Find SHAs that lack analysis results (including ones we just skipped).
	// A plain read over committed state — no transaction to hold open for it.
	queryRows, err := conn.Query(ctx, `SELECT s.sha256 FROM samples s
		JOIN _staging st ON s.sha256 = st.sha256
		WHERE s.litmus_result IS NULL`)
	if err != nil {
		return inserted, nil, fmt.Errorf("hopper: query needs analysis: %w", err)
	}
	defer queryRows.Close()

	for queryRows.Next() {
		var sha string
		if err := queryRows.Scan(&sha); err != nil {
			return inserted, nil, fmt.Errorf("hopper: scan needs analysis: %w", err)
		}
		needsAnalysis = append(needsAnalysis, sha)
	}
	if err := queryRows.Err(); err != nil {
		return inserted, nil, fmt.Errorf("hopper: needs analysis rows: %w", err)
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
// untouched. The trailing ORDER BY sha256 makes concurrent stores acquire their
// member row locks in the same order, so two archives sharing members can't form
// a lock cycle (deadlock); it also makes the residual contention orderly. The
// leading column matches DISTINCT ON (sha256), which Postgres requires.
//
// The LEFT JOIN pre-filter is what keeps that residual contention small, and it
// is not an optimization of the write — it is an elimination of a LOCK. Postgres
// takes an exclusive row lock on every conflicting row BEFORE it evaluates the
// DO UPDATE's WHERE, and holds it to commit, so a member whose stored analysis is
// already at least as fresh was locked for the whole transaction while writing
// nothing (verified directly: a DO UPDATE with a false WHERE blocks another
// session's UPDATE of that row). That is the common case by far — popular
// dependencies are members of thousands of archives, and every concurrent store
// that shares one queued behind the others. Measured 2026-08-23: worker-lane
// stores averaged 175-366 s and held 93% of all ingestion-slot time, with
// ~22 of 28 member upserts blocked on each other at any moment.
//
// The predicate mirrors memberConflictUpdatePG's WHERE exactly, so a row is
// filtered out here only when the conflict clause would have declined to write
// it. The clause stays as the authority: the join reads an MVCC snapshot, so a
// row that changes between the SELECT and the INSERT is still guarded there.
const insertMembersFromStagingPG = `INSERT INTO samples (
	sha256, source, feed, ecosystem, filename,
	size_bytes, label, label_source, path, status,
	canonical_sha256, parent, skip, elements,
	max_crit, suspicious_count, mtime, marker_mtime,
	cleave_result, litmus_result, analyzed_at, first_analyzed_at,
	url, domain, package, version, provenance, fetched_at)
SELECT DISTINCT ON (st.sha256)
	st.sha256, st.source, st.feed, st.ecosystem, st.filename,
	st.size_bytes, st.label, st.label_source, st.sample_path, st.status,
	st.canonical_sha256, st.sample_parent, st.skip, st.elements,
	st.max_crit, st.suspicious_count, st.mtime, st.marker_mtime,
	st.cleave_result, st.litmus_result, st.analyzed_at, st.first_analyzed_at,
	st.url, st.domain, st.package, st.version, st.provenance, st.fetched_at
FROM _staging st
LEFT JOIN samples s ON s.sha256 = st.sha256
WHERE s.sha256 IS NULL
   OR s.analyzed_at IS NULL
   OR st.analyzed_at > s.analyzed_at
ORDER BY st.sha256
` + memberConflictUpdatePG

// memberStoreBatch caps how many member rows a single store transaction writes.
// A large archive holds thousands of member sha256s; upserting them all in one
// transaction pins every one of those row locks until commit — under the
// metadata-only DB cache that commit is IO-bound and can run for minutes,
// stalling any concurrent store that shares a member behind lock_timeout
// (55P03) and forcing a full retry. Splitting the members into batches bounds
// the lock-hold window to one batch's worth of rows, sized to amortise the
// per-batch staging + COPY round trips while keeping that window short.
const memberStoreBatch = 1000

// memberBatchTimeout bounds ONE member batch, inside the caller's overall store
// deadline (resultStoreTimeout, 10m). Without it a single batch inherits the
// whole 10 minutes, and because it holds a pooled connection for that entire
// time it converts one slow archive into pool starvation for everything else —
// which is what "begin member batch: context deadline exceeded" is: pool.Begin
// waiting out the full store deadline for a connection that never frees.
//
// The publisher runs near its connection ceiling (90 of max_connections=100 on
// 2026-08-21, shared with prism/promoter/forager on the same role), so a
// connection held for minutes is the scarce resource, not the batch itself.
// Failing a batch at 90s frees it ~6.7x sooner and still leaves the store room
// to complete several batches within its own deadline.
const memberBatchTimeout = 90 * time.Second

// storeMemberRowsPG upserts one batch of archive-member rows in its own
// transaction: stage, COPY, analysis-only upsert, then fan the same rows out
// into sample_locations. Both writes are internally ordered by sha256 (the
// upsert's ORDER BY, the locations' DISTINCT ON), so every batch acquires its
// shared member locks in the same order and concurrent archives cannot form a
// deadlock cycle. Returns the number of member rows inserted or freshness-
// refreshed. The caller drives the batching; see storeResultPG.
// storeClaimsPG batch-upserts analyzer identity claims. The samples join
// drops claims for members that never became rows (explosion skips) instead
// of failing the FK; the delta guard leaves unchanged rows untouched so a
// re-analysis of the same bytes is a pure no-op.
func (db *DB) storeClaimsPG(ctx context.Context, claims []Claim) error {
	if len(claims) == 0 {
		return nil
	}
	n := len(claims)
	shas := make([]string, n)
	sources := make([]string, n)
	names := make([]string, n)
	versions := make([]string, n)
	signers := make([]string, n)
	verified := make([]bool, n)
	trusts := make([]string, n)
	for i, c := range claims {
		shas[i], sources[i], names[i] = c.SHA256, c.Source, c.Name
		versions[i], signers[i], verified[i], trusts[i] = c.Version, c.Signer, c.Verified, c.Trust
	}
	if _, err := db.pool.Exec(ctx, `
		INSERT INTO claims (sha256, source, name, version, signer, verified, trust)
		SELECT c.sha256, c.source, c.name, c.version, c.signer, c.verified, c.trust
		  FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::boolean[], $7::text[])
		       AS c(sha256, source, name, version, signer, verified, trust)
		  JOIN samples s ON s.sha256 = c.sha256
		ON CONFLICT (sha256, source) DO UPDATE SET
			name = EXCLUDED.name, version = EXCLUDED.version, signer = EXCLUDED.signer,
			verified = EXCLUDED.verified, trust = EXCLUDED.trust
		WHERE (claims.name, claims.version, claims.signer, claims.verified, claims.trust)
		      IS DISTINCT FROM
		      (EXCLUDED.name, EXCLUDED.version, EXCLUDED.signer, EXCLUDED.verified, EXCLUDED.trust)`,
		shas, sources, names, versions, signers, verified, trusts); err != nil {
		return fmt.Errorf("hopper: store claims: %w", err)
	}
	return nil
}

// storeMemberRowsPG writes one member batch as TWO transactions over a
// session staging table, exactly mirroring insertSampleBatchPG and for the
// same measured reason: the member upsert's ON CONFLICT row locks are the
// fleet-wide contention point (this statement was ~70% of all DB execution
// time on 2026-08-22 — initially misattributed to the walk upsert, whose text
// shares the same first 64 characters), and holding them across the
// sample_locations fan-out (a multi-second write against 526GB of indexes)
// convoyed every concurrent store and walk batch behind a single archive.
// tx1 commits the members and releases the contended locks; tx2 writes the
// locations ledger with nobody queueing on it.
//
// Failure window: members committed, locations fan-out failed. The caller
// fails the whole store, the worker retries the result, and the batch re-runs
// idempotently (the upsert is analyzed_at-gated), landing the edges then.
// StoreResult's crash contract is unchanged: the parent's truncating UPDATE
// still runs only after every member batch has fully succeeded.
func (db *DB) storeMemberRowsPG(ctx context.Context, rows [][]any) (int64, error) {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("hopper: acquire member batch conn: %w", err)
	}
	defer conn.Release()
	defer func() {
		dropCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, derr := conn.Exec(dropCtx, `DROP TABLE IF EXISTS _staging`); derr != nil {
			slog.Warn("drop member staging table failed; discarding connection", "error", derr)
			conn.Conn().Close(dropCtx) //nolint:errcheck,gosec // G104: already tearing down; the drop failure above is what was reported
		}
	}()

	if _, err := conn.Exec(ctx, insertBatchStagingSessionDDL); err != nil {
		return 0, fmt.Errorf("hopper: create member staging: %w", err)
	}
	if _, err := conn.Conn().CopyFrom(ctx, pgx.Identifier{"_staging"}, insertBatchStagingCols, pgx.CopyFromRows(rows)); err != nil {
		return 0, fmt.Errorf("hopper: copy members to staging: %w", err)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin member batch: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	tag, err := tx.Exec(ctx, insertMembersFromStagingPG)
	if err != nil {
		return 0, fmt.Errorf("hopper: upsert members: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("hopper: commit member batch: %w", err)
	}

	tx2, err := conn.Begin(ctx)
	if err != nil {
		return tag.RowsAffected(), fmt.Errorf("hopper: begin member locations: %w", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck // commit or rollback
	if _, err := tx2.Exec(ctx, locationsFromStagingPG); err != nil {
		return tag.RowsAffected(), fmt.Errorf("hopper: upsert member locations: %w", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		return tag.RowsAffected(), fmt.Errorf("hopper: commit member locations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// storeResultPG writes a sample's analysis and, for an archive, all its members.
// Members are written first — in bounded batches, each its own transaction — and
// the parent's truncating UPDATE runs last, only after every member is durably
// stored. This keeps StoreResult's contract (the parent's heavy member payload
// is never dropped unless the member rows exist) and extends it across a crash:
// an interrupted store leaves the members present but the parent un-truncated
// and un-analyzed, so a later rescan simply redoes it. See StoreResult.
//
// All envelope parsing and row construction happen before any Begin, so each
// transaction is a back-to-back burst of SQL with no application compute between
// statements. Holding the whole archive in one transaction pinned the parent and
// every member row lock for as long as the (IO-bound) commit ran — under load,
// minutes — stalling every concurrent store of a shared row behind lock_timeout
// (55P03); the batched members and the lone parent UPDATE each hold their locks
// for a fraction of that.
func (db *DB) storeResultPG(
	ctx context.Context, sha256 string, cleaveRaw, litmusML, llm []byte,
	parsed CleaveParseResult, traitsVersion string, now time.Time,
) (StoreStats, error) {
	// Read the identity fields members inherit from the parent. A plain read,
	// not SELECT … FOR UPDATE: the store is an idempotent, analyzed_at-gated
	// merge that needs no identity lock, and the worst a relabel racing this
	// read can do is leave members one cycle stale until pool reconcile heals
	// them. Reading here, before Begin, lets us build the members outside the
	// transaction.
	var parent Sample
	var firstAnalyzed sql.NullTime
	var priorAnalyzed sql.NullTime
	var priorTraits, purlBase string
	if err := db.pool.QueryRow(ctx,
		`SELECT label, label_source, source, feed, ecosystem, path, first_analyzed_at,
		        analyzed_at, traits_version, purl_base
		   FROM samples WHERE sha256 = $1`, sha256).
		Scan(&parent.Label, &parent.LabelSource, &parent.Source, &parent.Feed,
			&parent.Ecosystem, &parent.Path, &firstAnalyzed,
			&priorAnalyzed, &priorTraits, &purlBase); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StoreStats{}, fmt.Errorf("hopper: store result for absent sample %s: %w", sha256, ErrNotFound)
		}
		return StoreStats{}, fmt.Errorf("hopper: read parent for store %s: %w", sha256, err)
	}

	// What this store is about to replace. Captured before the UPDATE overwrites
	// it, so the handler can log a re-analysis and say whether it learned
	// anything (see StoreStats.Redundant).
	var stats StoreStats
	if priorAnalyzed.Valid {
		stats.PriorAnalyzedAt = priorAnalyzed.Time
	}
	stats.PriorTraitsVersion = priorTraits
	stats.PURLBase = purlBase

	// Build members from the FULL envelope, inheriting the parent's identity and
	// stamped with this analysis time so the freshness gate orders refreshes.
	parent.SHA256 = sha256
	parent.CleaveResult = cleaveRaw
	parent.LitmusResult = litmusML
	parent.CanonicalSHA256 = parsed.CanonicalSHA
	parent.AnalyzedAt = &now
	if firstAnalyzed.Valid {
		parent.FirstAnalyzedAt = &firstAnalyzed.Time
	} else {
		parent.FirstAnalyzedAt = &now
	}
	env := newMemberEnvelope(&parent)

	truncated := compactCleaveResultForStorage(cleaveRaw)
	var litmusVal, llmVal []byte
	if len(litmusML) > 0 {
		litmusVal = sanitizeJSONB(litmusML)
	}
	if len(llm) > 0 {
		llmVal = sanitizeJSONB(llm)
	}

	// Members first: build, write, and release them one bounded batch at a time,
	// each committed on its own, before the parent's truncating UPDATE below. The
	// member upsert is idempotent (analyzed_at-gated), so a retry of the whole
	// store after a lock_timeout on one batch re-runs the committed batches as
	// no-ops. Building per batch (rather than all members up front) keeps a large
	// archive from materializing every member's re-marshaled cleave/litmus slice
	// at once — several times the envelope size — held across the whole store;
	// each batch falls out of scope and is reclaimed before the next.
	for start := 0; start < env.len(); start += memberStoreBatch {
		batch := env.buildRange(start, min(start+memberStoreBatch, env.len()))
		stats.Members += len(batch)
		if len(batch) == 0 {
			continue
		}
		// Own deadline per batch, cancelled before the next iteration rather
		// than deferred, so a stalled batch releases its pooled connection
		// instead of pinning it for the rest of the store deadline.
		batchCtx, cancelBatch := context.WithTimeout(ctx, memberBatchTimeout)
		n, err := db.storeMemberRowsPG(batchCtx, sampleStagingRows(batch))
		cancelBatch()
		if err != nil {
			// Distinguish "this batch ran out of its own time" from "the whole
			// store ran out": the first is a slow batch worth retrying, the
			// second means the caller's budget is gone and a retry is futile.
			if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				return StoreStats{}, fmt.Errorf(
					"hopper: member batch at offset %d exceeded %s: %w",
					start, memberBatchTimeout, err)
			}
			return StoreStats{}, err
		}
		stats.MembersStored += n
	}

	// Analyzer identity claims from the same envelope — after the members so
	// each claim's row exists, before the parent UPDATE so a retried store
	// re-runs them as no-ops like everything else here.
	if err := db.storeClaimsPG(ctx, ClaimsFromEnvelope(cleaveRaw)); err != nil {
		return StoreStats{}, err
	}

	// Parent last, in its own short transaction. Truncating it only after the
	// members are durably stored is what upholds the contract across a crash.
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return StoreStats{}, fmt.Errorf("hopper: begin store: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	res, err := tx.Exec(ctx, `
		UPDATE samples SET cleave_result = $2,
			canonical_sha256 = $3, elements = $4,
			max_crit = $5, suspicious_count = $6,
			litmus_result = $7, llm_result = $8,
			note = '', last_error_at = NULL,
			traits_version = $9, rescan_priority = 0, rescan_requested_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, $10),
			analyzed_at = $10, updated_at = $10
		WHERE sha256 = $1`,
		sha256, sanitizeJSONB(truncated), parsed.CanonicalSHA,
		parsed.FileInfo.Elements, parsed.FileInfo.MaxCrit, parsed.FileInfo.SuspiciousCount,
		litmusVal, llmVal, traitsVersion, now)
	if err != nil {
		return StoreStats{}, fmt.Errorf("hopper: update parent for store %s: %w", sha256, err)
	}
	if res.RowsAffected() == 0 {
		// The row was deleted between the identity read and this update. Any
		// member rows already written are reaped by pool reconcile's
		// missing-parent cascade.
		return StoreStats{}, fmt.Errorf("hopper: store result for absent sample %s: %w", sha256, ErrNotFound)
	}

	if err := tx.Commit(ctx); err != nil {
		return StoreStats{}, fmt.Errorf("hopper: commit store: %w", err)
	}
	return stats, nil
}

func (db *DB) sampleBySHA256PG(ctx context.Context, sha256 string) (*Sample, error) {
	s, err := scanPGSample(db.pool.QueryRow(ctx,
		`SELECT `+pgSampleCols+pgSampleColsRegistryExtra+` FROM samples WHERE sha256 = $1`, sha256))
	if err != nil {
		return nil, fmt.Errorf("hopper: sample %s: %w", sha256, err)
	}
	return s, nil
}

// sampleByPURLSQL is the sargable point lookup for GET /api/sample?purl=.
// Every predicate is a constant — never the feed's empty-or-equal disjunction
// over a parameter — so they match idx_samples_purl_lookup. purl_base is
// pinned non-empty even though base is already checked non-empty in Go: the
// planner cannot prove that of a parameter, and without the literal it cannot
// use a partial index predicated on it. Full pgSampleCols — not the feed projection —
// so the envelope keeps raw (cleave_result).
//
// Deliberately no containment test. uncontainedSQL exists to keep archive
// members — a lib/index.js pulled out of a tarball — from being listed and
// judged as artifacts in their own right, and members carry no package
// identity: explodeMembers copies feed, ecosystem and label from the parent
// but never package, version or purl_base. So `purl_base = $1` has already
// excluded every member before containment could weigh in, and the only rows
// left for it to reject are ones that *do* carry a registry identity —
// provenance, a fetch URL, a version. Those are exactly the artifacts this
// endpoint exists to answer for; that some archive also bundles a copy is a
// fact about the archive. Requiring uncontained here could only ever produce
// false negatives, and did: foraged npm and golang releases went unfindable
// because something, somewhere, embedded them. The feed and triage queries
// still use it, and there it is load-bearing — those are not filtered by
// purl_base, so members really are candidates.
const sampleByPURLSQL = `SELECT ` + pgSampleCols + ` FROM samples
		WHERE purl_base = $1
		  AND purl_base <> ''
		  AND litmus_result IS NOT NULL
		  AND cleave_result IS NOT NULL
		  AND file_type <> 'registry'`

func (db *DB) sampleByPURLPG(ctx context.Context, base, version string) (*Sample, error) {
	query := sampleByPURLSQL
	args := []any{base}
	if version != "" {
		query += ` AND version = $2`
		args = append(args, version)
	}
	query += ` ORDER BY analyzed_at DESC NULLS LAST LIMIT 1`
	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: sample purl %s@%s: %w", base, version, err)
	}
	samples, err := scanPGSamples(rows)
	if err != nil {
		return nil, fmt.Errorf("hopper: sample purl %s@%s: %w", base, version, err)
	}
	if len(samples) == 0 {
		return nil, ErrNotFound
	}
	return samples[0], nil
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

// topMemberSHAsByParentPG returns up to limit member SHAs of parentSHA ranked
// by score. It reads only sha256 off idx_sl_parent_child's edge and the PK
// join to samples, so nothing heavy detoasts here.
func (db *DB) topMemberSHAsByParentPG(ctx context.Context, parentSHA string, limit int) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT s.sha256
		  FROM sample_locations sl
		  JOIN samples s ON s.sha256 = sl.sha256
		 WHERE sl.parent_sha256 = $1
		 ORDER BY s.score DESC, s.max_crit DESC, sl.path
		 LIMIT $2`, parentSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: top member shas by parent %s: %w", parentSHA, err)
	}
	return scanPGStrings(rows)
}

// parentArchivesForChildPG resolves a child sha to its parent archives in one
// light-projection join. DISTINCT ON keeps each parent's most-recent location;
// the outer ORDER BY then ranks parents by recency and caps the set.
func (db *DB) parentArchivesForChildPG(ctx context.Context, childSHA string, limit int) ([]ParentRef, error) {
	// Bound the work at $2 parents, not at the number of locations. With
	// idx_sl_child_parents the matching rows arrive already grouped by
	// parent_sha256, so DISTINCT ON is a streaming Unique over an index-only
	// scan and the LIMIT stops the scan — O(limit), not O(locations). That is
	// the whole design: the fan-out tail is extreme (the empty-file sha is in
	// ~6.5M locations), and the previous shape, which applied LIMIT after the
	// DISTINCT ON and ordered by last_seen_at, sorted every one of them — 183s
	// and 1.6 GB of temp spill.
	//
	// The cost is that these are the lexically-first N parents, not the N most
	// recent. Nothing regresses: last_seen_at stopped being maintained when
	// locationChangedPG landed, so the ordering this replaces was already
	// arbitrary while claiming recency — and for a file present in millions of
	// archives no cross-parent ranking is meaningful anyway. Within a parent,
	// id DESC still selects that parent's most recently recorded location.
	//
	// Limiting before the join also keeps the heavy TOASTed litmus_result to N
	// detoasts rather than one per location row.
	rows, err := db.pool.Query(ctx, `
		WITH top_parents AS (
			SELECT DISTINCT ON (parent_sha256)
			       parent_sha256, path AS loc_path, rel, id
			  FROM sample_locations
			 WHERE sha256 = $1 AND parent_sha256 <> ''
			 ORDER BY parent_sha256, id DESC
			 LIMIT $2
		)
		SELECT s.sha256, s.filename, s.path, tp.loc_path, tp.rel, s.feed, s.ecosystem, s.version, s.package, s.litmus_result, s.analyzed_at
		  FROM top_parents tp
		  JOIN samples s ON s.sha256 = tp.parent_sha256
		 ORDER BY tp.parent_sha256`, childSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: parent archives for child %s: %w", childSHA, err)
	}
	defer rows.Close()
	var out []ParentRef
	for rows.Next() {
		var p ParentRef
		if err := rows.Scan(
			&p.SHA256, &p.Filename, &p.SamplePath, &p.Path, &p.Rel, &p.Feed,
			&p.Ecosystem, &p.Version, &p.Package, &p.LitmusResult, &p.AnalyzedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
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

// repairReferenceParentsPG repairs the rows explode damaged, driving from the
// ledger's reference edges rather than from samples.
//
// Direction is the whole cost. Scanning samples means testing every row that has
// a parent — the archive members, most of a 500M-row table — and probing the
// ledger for each, to find a comparatively tiny set. Every damaged row
// necessarily carries a reference edge (that is what explode mis-recorded), so
// enumerating those edges reaches exactly the same rows while doing work
// proportional to referenced artifacts. idx_sl_reference makes the walk
// index-only.
//
// The full predicate still runs per candidate, so a sha that also has a genuine
// containment edge is left alone: the edge list finds candidates, it does not
// decide them.
func (db *DB) repairReferenceParentsPG(ctx context.Context, cursor int64) error {
	var repaired, windows int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Keyset pagination over the reference index, not fixed id windows: ids
		// are sparse (a ~1.8B id space over ~440M rows, and reference edges are a
		// few percent of those), so stepping the id space in fixed strides would
		// spend hundreds of thousands of round trips on windows containing nothing.
		// Taking the next N edges from the index instead makes the iteration count
		// proportional to the edges that actually exist.
		//
		// `targets` locks the rows it will update in sha256 order, matching the
		// ordering every other writer of member rows uses (see
		// insertMembersFromStagingPG's ORDER BY). Without it the planner acquires
		// row locks in hash order, and a concurrent archive store touching the same
		// shas in sha256 order closes a deadlock cycle — which aborts the whole
		// repair, not just the window.
		//
		// One statement per window: pick the batch, lock and repair only the damaged
		// rows in it, and return the new cursor and the repair count together. Each
		// autocommits, so locks are held for one window, never across the run.
		var nextCursor, n int64
		err := db.pool.QueryRow(ctx, `
			WITH batch AS (
				SELECT id, sha256 FROM sample_locations
				 WHERE id > $1 AND parent_sha256 <> '' AND rel NOT IN `+containmentRelsSQL+`
				 ORDER BY id LIMIT $2
			), targets AS (
				SELECT s.sha256 FROM samples s
				 WHERE s.sha256 IN (SELECT sha256 FROM batch)
				   AND `+referenceParentPredicate("s")+`
				 ORDER BY s.sha256
				 FOR UPDATE OF s
			), upd AS (
				UPDATE samples
				   SET parent = '',
				       -- Only a virtual in-archive path is a lie. A row whose
				       -- path was healed to real bytes on disk (an upload that
				       -- landed after explode froze parent) keeps it: clearing
				       -- it would strand bytes hopper actually holds.
				       path = CASE WHEN path LIKE '%!!%' THEN '' ELSE path END,
				       label = 'unknown', label_source = ''
				 WHERE sha256 IN (SELECT sha256 FROM targets)
				RETURNING 1
			)
			SELECT COALESCE((SELECT max(id) FROM batch), 0),
			       (SELECT count(*) FROM upd)`,
			cursor, referenceParentRepairBatch).Scan(&nextCursor, &n)
		if err != nil {
			return fmt.Errorf("hopper: repair reference parents: window from %d: %w", cursor, err)
		}
		if nextCursor == 0 {
			break // no reference edges past the cursor; done
		}
		repaired += n
		windows++
		cursor = nextCursor
		if _, err := db.pool.Exec(ctx,
			`INSERT INTO hopper_kv (key, value) VALUES ($1, $2)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
			referenceParentRepairCurKey, strconv.FormatInt(cursor, 10)); err != nil {
			return fmt.Errorf("hopper: repair reference parents: save cursor: %w", err)
		}
	}
	if _, err := db.pool.Exec(ctx,
		`INSERT INTO hopper_kv (key, value) VALUES ($1, 'done')
		 ON CONFLICT (key) DO UPDATE SET value = 'done'`,
		referenceParentRepairDoneKey); err != nil {
		return fmt.Errorf("hopper: repair reference parents: done marker: %w", err)
	}
	slog.Info("reference-parent repair complete", "repaired", repaired, "windows", windows)
	return nil
}

const pgLocationCols = `id, sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at`

const pgRetiredLocationCols = pgLocationCols + `, retired_at, reason, successor_path`

func scanPGLocation(row interface{ Scan(...any) error }) (*SampleLocation, error) {
	var loc SampleLocation
	if err := row.Scan(&loc.ID, &loc.SHA256, &loc.Path, &loc.ParentSHA256, &loc.Rel,
		&loc.Filename, &loc.Source, &loc.Feed, &loc.Ecosystem,
		&loc.Mtime, &loc.FirstSeenAt, &loc.LastSeenAt); err != nil {
		return nil, err
	}
	return &loc, nil
}

func scanPGRetiredLocation(row interface{ Scan(...any) error }) (*RetiredSampleLocation, error) {
	var loc RetiredSampleLocation
	if err := row.Scan(&loc.ID, &loc.SHA256, &loc.Path, &loc.ParentSHA256, &loc.Rel,
		&loc.Filename, &loc.Source, &loc.Feed, &loc.Ecosystem,
		&loc.Mtime, &loc.FirstSeenAt, &loc.LastSeenAt,
		&loc.RetiredAt, &loc.Reason, &loc.SuccessorPath); err != nil {
		return nil, err
	}
	return &loc, nil
}

func (db *DB) upsertLocationPG(ctx context.Context, loc *SampleLocation) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (sha256, path) DO UPDATE SET
			rel = CASE WHEN EXCLUDED.rel <> '' THEN EXCLUDED.rel ELSE sample_locations.rel END,
			mtime = COALESCE(EXCLUDED.mtime, sample_locations.mtime)
		WHERE (EXCLUDED.rel <> '' AND EXCLUDED.rel IS DISTINCT FROM sample_locations.rel)
		   OR (EXCLUDED.mtime IS NOT NULL AND EXCLUDED.mtime IS DISTINCT FROM sample_locations.mtime)`,
		loc.SHA256, loc.Path, loc.ParentSHA256, loc.Rel, loc.Filename,
		loc.Source, loc.Feed, loc.Ecosystem, loc.Mtime)
	if err != nil {
		return fmt.Errorf("hopper: upsert location %s: %w", loc.SHA256, err)
	}
	return nil
}

// upsertLocationBatchPG applies the upsertLocationPG upsert to every row in one
// round-trip via unnest — no per-row Exec and no staging table. Column arrays are
// positional; keep them aligned with the INSERT list.
func (db *DB) upsertLocationBatchPG(ctx context.Context, locs []*SampleLocation) error {
	n := len(locs)
	sha := make([]string, n)
	path := make([]string, n)
	parent := make([]string, n)
	rel := make([]string, n)
	filename := make([]string, n)
	source := make([]string, n)
	feed := make([]string, n)
	eco := make([]string, n)
	for i, l := range locs {
		sha[i], path[i], parent[i], rel[i] = l.SHA256, l.Path, l.ParentSHA256, l.Rel
		filename[i], source[i], feed[i], eco[i] = l.Filename, l.Source, l.Feed, l.Ecosystem
	}
	//nolint:unqueryvet // the wildcard is over unnest() of eight explicitly typed arrays, whose columns are positional by construction.
	_, err := db.pool.Exec(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem)
		SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[],
			$5::text[], $6::text[], $7::text[], $8::text[])
		ON CONFLICT (sha256, path) DO UPDATE SET
			rel = CASE WHEN EXCLUDED.rel <> '' THEN EXCLUDED.rel ELSE sample_locations.rel END,
			source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE sample_locations.source END,
			feed = CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE sample_locations.feed END,
			ecosystem = CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE sample_locations.ecosystem END
		WHERE (EXCLUDED.rel <> ''       AND EXCLUDED.rel       IS DISTINCT FROM sample_locations.rel)
		   OR (EXCLUDED.source <> ''    AND EXCLUDED.source    IS DISTINCT FROM sample_locations.source)
		   OR (EXCLUDED.feed <> ''      AND EXCLUDED.feed      IS DISTINCT FROM sample_locations.feed)
		   OR (EXCLUDED.ecosystem <> '' AND EXCLUDED.ecosystem IS DISTINCT FROM sample_locations.ecosystem)`,
		sha, path, parent, rel, filename, source, feed, eco)
	if err != nil {
		return fmt.Errorf("hopper: upsert location batch (%d): %w", n, err)
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

func (db *DB) topLevelLocationsForSHAPG(ctx context.Context, sha256 string) ([]*SampleLocation, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT `+pgLocationCols+` FROM sample_locations
		 WHERE sha256 = $1 AND parent_sha256 = ''
		 ORDER BY last_seen_at DESC, id DESC`, sha256)
	if err != nil {
		return nil, fmt.Errorf("hopper: top-level locations %s: %w", sha256, err)
	}
	defer rows.Close()
	var out []*SampleLocation
	for rows.Next() {
		loc, err := scanPGLocation(rows)
		if err != nil {
			return nil, fmt.Errorf("hopper: scan top-level location: %w", err)
		}
		out = append(out, loc)
	}
	return out, rows.Err()
}

func (db *DB) retiredLocationsForSHAPG(ctx context.Context, sha256 string) ([]*RetiredSampleLocation, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT `+pgRetiredLocationCols+` FROM sample_location_history
		 WHERE sha256 = $1 ORDER BY retired_at DESC, id DESC`, sha256)
	if err != nil {
		return nil, fmt.Errorf("hopper: retired locations %s: %w", sha256, err)
	}
	defer rows.Close()
	var out []*RetiredSampleLocation
	for rows.Next() {
		loc, err := scanPGRetiredLocation(rows)
		if err != nil {
			return nil, fmt.Errorf("hopper: scan retired location: %w", err)
		}
		out = append(out, loc)
	}
	return out, rows.Err()
}

func (db *DB) promotePrimaryLocationPG(ctx context.Context, sha256, oldPath, newPath string) (bool, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples
		   SET path = $3,
		       skip = CASE WHEN skip = 'missing' THEN '' ELSE skip END,
		       skipped_at = CASE WHEN skip = 'missing' THEN NULL ELSE skipped_at END,
		       updated_at = now()
		 WHERE sha256 = $1 AND path = $2
		   AND EXISTS (SELECT 1 FROM sample_locations
		                WHERE sha256 = $1 AND path = $3 AND parent_sha256 = '')`,
		sha256, oldPath, newPath)
	if err != nil {
		return false, fmt.Errorf("hopper: promote primary location %s: %w", sha256, err)
	}
	return tag.RowsAffected() > 0, nil
}

func (db *DB) reactivatePrimaryLocationPG(ctx context.Context, sha256, path string) (bool, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("hopper: reactivate primary location begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	if _, err := tx.Exec(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
			 mtime, first_seen_at, last_seen_at)
		SELECT h.sha256, h.path, '', h.rel, h.filename, h.source, h.feed, h.ecosystem,
		       h.mtime, h.first_seen_at, now()
		  FROM sample_location_history h
		  JOIN samples s ON s.sha256 = h.sha256 AND s.path = h.path
		 WHERE h.sha256 = $1 AND h.path = $2 AND h.parent_sha256 = ''
		 ORDER BY h.retired_at DESC, h.id DESC LIMIT 1
		ON CONFLICT (sha256, path) DO NOTHING`, sha256, path); err != nil {
		return false, fmt.Errorf("hopper: restore retired primary location: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE samples
		   SET skip = '', skipped_at = NULL, updated_at = now()
		 WHERE sha256 = $1 AND path = $2 AND skip = 'missing'
		   AND EXISTS (SELECT 1 FROM sample_locations
		                WHERE sha256 = $1 AND path = $2 AND parent_sha256 = '')`, sha256, path)
	if err != nil {
		return false, fmt.Errorf("hopper: clear recovered primary location: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("hopper: reactivate primary location commit: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (db *DB) oldestIncomingLocationsPG(ctx context.Context, before time.Time, limit int) ([]*SampleLocation, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT `+pgLocationCols+` FROM sample_locations
		 WHERE parent_sha256 = '' AND path LIKE 'incoming/%'
		   AND mtime IS NOT NULL AND mtime < $1
		 ORDER BY mtime, sha256, path LIMIT $2`, before.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: oldest incoming locations: %w", err)
	}
	defer rows.Close()
	var out []*SampleLocation
	for rows.Next() {
		loc, err := scanPGLocation(rows)
		if err != nil {
			return nil, fmt.Errorf("hopper: scan oldest incoming location: %w", err)
		}
		out = append(out, loc)
	}
	return out, rows.Err()
}

func (db *DB) prepareLocationMovePG(
	ctx context.Context, sha256, oldRel, newRel string, relabel *LocationRelabel,
) (bool, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("hopper: prepare location move begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	var oldID int64
	err = tx.QueryRow(ctx, `
		SELECT id FROM sample_locations
		 WHERE sha256 = $1 AND path = $2 AND parent_sha256 = ''
		 FOR UPDATE`, sha256, oldRel).Scan(&oldID)
	oldExists := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		var destinationExists bool
		if err := tx.QueryRow(ctx, `
				SELECT EXISTS(SELECT 1 FROM sample_locations
				 WHERE sha256 = $1 AND path = $2 AND parent_sha256 = '')`, sha256, newRel).Scan(&destinationExists); err != nil {
			return false, fmt.Errorf("hopper: prepare location move lookup: %w", err)
		}
		if !destinationExists {
			return false, nil
		}
	} else if err != nil {
		return false, fmt.Errorf("hopper: prepare location move lock: %w", err)
	}

	if oldExists {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sample_locations
				(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
				 mtime, first_seen_at, last_seen_at)
		SELECT sha256, $2, parent_sha256, rel, filename, source, feed, ecosystem,
		       mtime, first_seen_at, now()
			  FROM sample_locations WHERE id = $1
			ON CONFLICT (sha256, path) DO NOTHING`, oldID, newRel); err != nil {
			return false, fmt.Errorf("hopper: prepare destination location: %w", err)
		}
	}

	if relabel != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
			SELECT sha256, label, $2, skip, '', 'triage', now()
			  FROM samples WHERE sha256 = $1 AND label <> $2`, sha256, relabel.Label); err != nil {
			return false, fmt.Errorf("hopper: prepare location move audit: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE samples
			   SET label = $2, label_source = $3,
			       path = CASE WHEN path = $4 THEN $5 ELSE path END,
			       skip = '', skipped_at = NULL, updated_at = now()
			 WHERE sha256 = $1`, sha256, relabel.Label, relabel.Source, oldRel, newRel); err != nil {
			return false, fmt.Errorf("hopper: prepare sample relabel: %w", err)
		}
	} else if _, err := tx.Exec(ctx, `
		UPDATE samples SET path = $3, updated_at = now()
		 WHERE sha256 = $1 AND path = $2`, sha256, oldRel, newRel); err != nil {
		return false, fmt.Errorf("hopper: prepare primary path: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("hopper: prepare location move commit: %w", err)
	}
	return true, nil
}

func (db *DB) finishLocationMovePG(ctx context.Context, sha256, oldRel, newRel string) (bool, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("hopper: finish location move begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	if _, err := tx.Exec(ctx, `
		INSERT INTO sample_location_history
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
			 mtime, first_seen_at, last_seen_at, retired_at, reason, successor_path)
		SELECT old.sha256, old.path, old.parent_sha256, old.rel, old.filename,
		       old.source, old.feed, old.ecosystem, old.mtime,
		       old.first_seen_at, old.last_seen_at, now(), 'move', $3
		  FROM sample_locations old
		 WHERE old.sha256 = $1 AND old.path = $2 AND old.parent_sha256 = ''
		   AND EXISTS (SELECT 1 FROM sample_locations new
		                WHERE new.sha256 = $1 AND new.path = $3 AND new.parent_sha256 = '')`,
		sha256, oldRel, newRel); err != nil {
		return false, fmt.Errorf("hopper: finish location move archive source: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM sample_locations old
		 WHERE old.sha256 = $1 AND old.path = $2 AND old.parent_sha256 = ''
		   AND EXISTS (SELECT 1 FROM sample_locations new
		                WHERE new.sha256 = $1 AND new.path = $3 AND new.parent_sha256 = '')`,
		sha256, oldRel, newRel); err != nil {
		return false, fmt.Errorf("hopper: finish location move delete source: %w", err)
	}
	var destinationExists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM sample_locations
		 WHERE sha256 = $1 AND path = $2 AND parent_sha256 = '')`, sha256, newRel).Scan(&destinationExists); err != nil {
		return false, fmt.Errorf("hopper: finish location move lookup: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("hopper: finish location move commit: %w", err)
	}
	return destinationExists, nil
}

// pruneMissingLocationsPG mirrors pruneMissingLocationsSQLite for the
// PostgreSQL backend.
func (db *DB) pruneMissingLocationsPG(ctx context.Context, absRoot string, maxFraction float64) (int, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, sha256, path FROM sample_locations
		WHERE (parent_sha256 IS NULL OR parent_sha256 = '')
		  AND (path NOT LIKE '/%' OR path LIKE $1)`, absRoot+"/%")
	if err != nil {
		return 0, fmt.Errorf("hopper: scan locations for prune: %w", err)
	}
	var victims []pruneVictim
	total := 0
	for rows.Next() {
		var v pruneVictim
		if err := rows.Scan(&v.id, &v.sha256, &v.path); err != nil {
			rows.Close()
			return 0, fmt.Errorf("hopper: scan location row: %w", err)
		}
		total++
		resolved, ok := prunePathResolve(absRoot, v.path)
		if !ok {
			slog.Warn("hopper: location path escapes data root; preserving row", "path", v.path)
			continue
		}
		if _, err := os.Stat(resolved); errors.Is(err, os.ErrNotExist) {
			victims = append(victims, v)
		} else if err != nil {
			slog.Warn("hopper: stat failed during prune; preserving row", "path", resolved, "error", err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if total > 0 && float64(len(victims))/float64(total) > maxFraction {
		return 0, &PruneSafetyExceeded{Total: total, Victims: len(victims), MaxFraction: maxFraction}
	}
	if len(victims) == 0 {
		return 0, nil
	}

	ids := make([]int64, len(victims))
	for i, v := range victims {
		ids[i] = v.id
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin prune: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	if _, err := tx.Exec(ctx, `
		INSERT INTO sample_location_history
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
			 mtime, first_seen_at, last_seen_at, retired_at, reason, successor_path)
		SELECT sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
		       mtime, first_seen_at, last_seen_at, now(), 'prune', ''
		  FROM sample_locations WHERE id = ANY($1)`, ids); err != nil {
		return 0, fmt.Errorf("hopper: archive %d pruned locations: %w", len(ids), err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sample_locations WHERE id = ANY($1)`, ids); err != nil {
		return 0, fmt.Errorf("hopper: delete %d locations: %w", len(ids), err)
	}
	shas := distinctVictimSHAs(victims)
	if len(shas) > 0 {
		// A re-observed file flips skip back to '' via the samples upsert
		// conflict clause; only skip='' is promoted so manual/label skips stick.
		if _, err := tx.Exec(ctx, `
			INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
			SELECT sha256, label, label, skip, 'missing', 'prune-missing', now()
			FROM samples
			WHERE parent = '' AND skip = '' AND sha256 = ANY($1)
			  AND NOT EXISTS (SELECT 1 FROM sample_locations sl WHERE sl.sha256 = samples.sha256)`, shas); err != nil {
			return 0, fmt.Errorf("hopper: prune missing audit: %w", err)
		}
		tag, err := tx.Exec(ctx, `
			UPDATE samples SET skip = 'missing', updated_at = now()
			WHERE parent = '' AND skip = '' AND sha256 = ANY($1)
			  AND NOT EXISTS (SELECT 1 FROM sample_locations sl WHERE sl.sha256 = samples.sha256)`, shas)
		if err != nil {
			return 0, fmt.Errorf("hopper: prune mark missing: %w", err)
		}
		if n := tag.RowsAffected(); n > 0 {
			slog.Info("prune marked samples missing (no surviving location)", "count", n)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("hopper: commit prune: %w", err)
	}
	slog.Info("sample locations retired by prune", "count", len(victims))
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

func (db *DB) cascadeLabelPG(ctx context.Context, sha256, label, source string) (int, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin cascade: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback

	if _, err := tx.Exec(ctx,
		`UPDATE samples SET label = $2, label_source = $3, updated_at = now() WHERE sha256 = $1`,
		sha256, label, source); err != nil {
		return 0, fmt.Errorf("hopper: cascade parent: %w", err)
	}
	children, err := cascadeMembersForParentPG(ctx, tx, sha256, label, source, false)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("hopper: commit cascade: %w", err)
	}
	return children, nil
}

// cascadeMembersForParentPG applies the member cascade for an archive already
// labeled `label` (with label_source `source`), without touching the parent row.
// It is the shared unit behind both live relabeling (cascadeLabelPG) and the
// historical backfill (cascadeBackfillPG); dryRun counts the eligible members
// without writing. It returns the number of members changed (or that would be).
func cascadeMembersForParentPG(ctx context.Context, tx pgx.Tx, parent, label, source string, dryRun bool) (int, error) {
	// Each query selects the members (via sample_locations, the membership
	// source of truth) eligible for a transition. $1 is the parent; later
	// placeholders bind extra args.
	// Unverified members (unknown, or sighted by a feed) follow a verified
	// parent in both directions: a good parent vouches for its sighted members;
	// a bad parent drags suspicious sighted members along.
	const promoteMembers = `SELECT sha256, label FROM samples
		WHERE label IN ('unknown', 'sighted')
		  AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = $1)`
	const revertMembers = `SELECT sha256, label FROM samples
		WHERE label = 'bad' AND label_source = $2
		  AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = $1)`
	const demoteMembers = `SELECT sha256, label FROM samples
		WHERE label IN ('unknown', 'sighted') AND score >= $2
		  AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = $1)`

	children := 0
	switch label {
	case labelGood:
		// Unlabeled members follow the parent to good.
		n, err := cascadeMembersPG(ctx, tx, promoteMembers, []any{parent}, labelGood, source, "cascade-promote", dryRun)
		if err != nil {
			return 0, err
		}
		children += n
		// Members this same parent previously demoted are reverted to good.
		n, err = cascadeMembersPG(ctx, tx, revertMembers, []any{parent, cascadeSource(parent)}, labelGood, source, "cascade-revert", dryRun)
		if err != nil {
			return 0, err
		}
		children += n
	case labelBad:
		// Only unlabeled members carrying real suspicion follow the parent to bad.
		n, err := cascadeMembersPG(ctx, tx, demoteMembers, []any{parent, CascadeDemoteScore},
			labelBad, cascadeSource(parent), "cascade-demote", dryRun)
		if err != nil {
			return 0, err
		}
		children += n
	default:
		// Other labels (e.g. unknown) have no member cascade.
	}
	return children, nil
}

// cascadeMembersPG runs query (which selects sha256, label and binds args) and
// relabels every returned member to toLabel/toSource, recording each transition
// in label_events under reason. dryRun returns the eligible count without
// writing. It returns the number of members changed (or that would be).
func cascadeMembersPG(ctx context.Context, tx pgx.Tx, query string, args []any, toLabel, toSource, reason string, dryRun bool) (int, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("hopper: cascade scan members: %w", err)
	}
	type change struct{ sha, from string }
	var changes []change
	for rows.Next() {
		var c change
		if err := rows.Scan(&c.sha, &c.from); err != nil {
			rows.Close()
			return 0, fmt.Errorf("hopper: cascade scan member: %w", err)
		}
		changes = append(changes, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if dryRun {
		return len(changes), nil
	}
	applied := 0
	for _, c := range changes {
		// Compare-and-set on the scanned label: if concurrent live traffic
		// relabeled the row since the scan, RowsAffected is 0 and we leave it
		// (and skip the audit) rather than clobber the newer verdict.
		tag, err := tx.Exec(ctx, `
			UPDATE samples SET label = $2, label_source = $3, updated_at = now()
			WHERE sha256 = $1 AND label = $4`,
			c.sha, toLabel, toSource, c.from)
		if err != nil {
			return 0, fmt.Errorf("hopper: cascade member: %w", err)
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
			VALUES ($1, $2, $3, '', '', $4, now())`,
			c.sha, c.from, toLabel, reason); err != nil {
			return 0, fmt.Errorf("hopper: cascade audit: %w", err)
		}
		applied++
	}
	return applied, nil
}

// cascadeBackfillPendingPG reports whether any good/bad top-level archive still
// holds an 'unknown' member — i.e. whether cascadeBackfillPG has work to do.
// It drives from the (small) labeled-archive set so the common "nothing to do"
// answer stays an index-assisted probe rather than a full member scan.
func (db *DB) cascadeBackfillPendingPG(ctx context.Context) (bool, error) {
	var pending bool
	err := db.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM samples p
			JOIN sample_locations l ON l.parent_sha256 = p.sha256
			JOIN samples m ON m.sha256 = l.sha256
			WHERE p.parent = '' AND m.label IN ('unknown', 'sighted')
			  AND (p.label = 'good' OR (p.label = 'bad' AND m.score >= $1))
		)`, CascadeDemoteScore).Scan(&pending)
	if err != nil {
		return false, fmt.Errorf("hopper: cascade backfill pending: %w", err)
	}
	return pending, nil
}

// cascadeBackfillPG re-applies the member cascade to every already-labeled
// archive so children labeled before CascadeLabel existed are brought into
// agreement. Bad archives are processed before good ones: a member shared by a
// bad and a good archive must end up bad (precedence bad > good > sighted >
// unknown), and
// since demote claims only unknown members while promote never overrides bad,
// bad-first yields that outcome — good-first would whitewash it. Each archive
// commits in its own transaction so the pass never holds a table-wide lock and
// is resumable; it is idempotent. dryRun counts without writing. The parent rows
// are left untouched (they are already labeled); only members change.
func (db *DB) cascadeBackfillPG(ctx context.Context, dryRun bool) (CascadeBackfillStats, error) {
	// Select only archives that actually have an eligible member, so the
	// per-archive loop skips the (vast majority of) labeled archives whose
	// members were already settled at extraction time. The EXISTS predicate
	// mirrors cascadeMembersForParent's selection for each direction; the
	// 'cascade:' literal mirrors cascadeSource.
	const badArchives = `
		SELECT sha256, label_source FROM samples s
		WHERE parent = '' AND label = 'bad'
		  AND EXISTS (
			SELECT 1 FROM sample_locations l JOIN samples m ON m.sha256 = l.sha256
			WHERE l.parent_sha256 = s.sha256 AND m.label IN ('unknown', 'sighted') AND m.score >= $1)
		ORDER BY id`
	const goodArchives = `
		SELECT sha256, label_source FROM samples s
		WHERE parent = '' AND label = 'good'
		  AND EXISTS (
			SELECT 1 FROM sample_locations l JOIN samples m ON m.sha256 = l.sha256
			WHERE l.parent_sha256 = s.sha256
			  AND (m.label IN ('unknown', 'sighted') OR (m.label = 'bad' AND m.label_source = 'cascade:' || s.sha256)))
		ORDER BY id`

	var st CascadeBackfillStats
	for _, label := range []string{labelBad, labelGood} {
		query, args := goodArchives, []any(nil)
		if label == labelBad {
			query, args = badArchives, []any{CascadeDemoteScore}
		}
		rows, err := db.pool.Query(ctx, query, args...)
		if err != nil {
			return st, fmt.Errorf("hopper: backfill scan archives: %w", err)
		}
		type archive struct{ sha, source string }
		var archives []archive
		for rows.Next() {
			var a archive
			if err := rows.Scan(&a.sha, &a.source); err != nil {
				rows.Close()
				return st, fmt.Errorf("hopper: backfill scan archive: %w", err)
			}
			archives = append(archives, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return st, err
		}

		slog.Info("cascade backfill pass starting", "label", label, "archives", len(archives), "dry_run", dryRun)
		passMembers := 0
		for i, a := range archives {
			tx, err := db.pool.Begin(ctx)
			if err != nil {
				return st, fmt.Errorf("hopper: backfill begin: %w", err)
			}
			n, err := cascadeMembersForParentPG(ctx, tx, a.sha, label, a.source, dryRun)
			if err != nil {
				tx.Rollback(ctx) //nolint:errcheck,gosec // returning the prior error
				return st, err
			}
			if dryRun {
				tx.Rollback(ctx) //nolint:errcheck,gosec // dry-run: discard
			} else if err := tx.Commit(ctx); err != nil {
				return st, fmt.Errorf("hopper: backfill commit: %w", err)
			}
			st.record(label, n)
			passMembers += n
			if (i+1)%cascadeBackfillLogEvery == 0 {
				slog.Info("cascade backfill progress", "label", label,
					"archives_done", i+1, "archives_total", len(archives), "members_changed", passMembers)
			}
		}
		slog.Info("cascade backfill pass complete", "label", label, "archives", len(archives), "members_changed", passMembers)
	}
	return st, nil
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

func (db *DB) candidatesByLabelPG(ctx context.Context, label, pathPrefix string, olderThan time.Time, afterSHA string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE label = $1 AND parent = '' AND skip = ''
		   AND starts_with(path, $2)
		   AND mtime IS NOT NULL AND mtime < $3
		   AND sha256 > $4
		 ORDER BY sha256 LIMIT $5`,
		label, pathPrefix, olderThan.UTC(), afterSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: candidates by label: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) shaCitedUnknownsPG(ctx context.Context, pathPrefix, afterSHA string, limit int) ([]*Sample, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples s
		 WHERE s.label = 'unknown' AND s.parent = '' AND s.skip = ''
		   AND starts_with(s.path, $1)
		   AND s.sha256 > $2
		   AND EXISTS (SELECT 1 FROM sightings g WHERE g.subject = s.sha256)
		 ORDER BY s.sha256 LIMIT $3`,
		pathPrefix, afterSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: sha-cited unknowns: %w", err)
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

func triageFilterClausePG(f TriageFilter, startIdx int, sampleAlias string) (clause string, args []any) {
	col := func(name string) string { return sampleAlias + "." + name }
	return triageFilterClausePGKey(f, startIdx, sampleAlias, col("sha256"))
}

func triageFilterClausePGKey(f TriageFilter, startIdx int, sampleAlias, reportKey string) (clause string, args []any) {
	col := func(name string) string { return sampleAlias + "." + name }
	if f.Ecosystem != "" {
		args = append(args, f.Ecosystem)
		clause += fmt.Sprintf(" AND %s = $%d", col("ecosystem"), startIdx+len(args)-1)
	}
	if f.FileType != "" {
		args = append(args, f.FileType)
		clause += fmt.Sprintf(" AND %s = $%d", col("file_type"), startIdx+len(args)-1)
	}
	if !f.MinAnalyzedAt.IsZero() {
		args = append(args, f.MinAnalyzedAt.UTC())
		clause += fmt.Sprintf(" AND %s >= $%d", col("analyzed_at"), startIdx+len(args)-1)
	}
	if f.ExcludeReportType != "" {
		args = append(args, f.ExcludeReportType)
		clause += fmt.Sprintf(
			` AND NOT EXISTS (SELECT 1 FROM reports r`+
				` WHERE r.sha256 = %s AND r.report_type = $%d`+
				` AND r.created_at > %s)`, reportKey, startIdx+len(args)-1, col("analyzed_at"))
	}
	if f.AttemptReportType != "" && f.MaxAttempts > 0 {
		args = append(args, f.AttemptReportType, f.MaxAttempts)
		typeIdx := startIdx + len(args) - 2
		maxIdx := startIdx + len(args) - 1
		clause += fmt.Sprintf(
			` AND (SELECT count(*) FROM reports r`+
				` WHERE r.sha256 = %s AND r.report_type = $%d) < $%d`,
			reportKey, typeIdx, maxIdx)
	}
	return clause, args
}

// triageOrderSQL renders the ORDER BY for a triage selector. The stale spelling
// must stay byte-compatible with the idx_samples_*_stale indexes (analyzed_at
// leading, ASC, NULLS LAST) or the planner sorts the whole partition instead of
// walking the index — see the migration list for what that costs.
func triageOrderSQL(f TriageFilter) string {
	switch f.Order {
	case TriageStale:
		return "ORDER BY analyzed_at ASC NULLS LAST, id ASC"
	case TriageInteresting:
		return "ORDER BY corroborated DESC, max_crit DESC, suspicious_count DESC, " +
			"litmus_score DESC NULLS LAST, analyzed_at ASC NULLS LAST, id ASC"
	default:
		return "ORDER BY created_at DESC, id DESC"
	}
}

func (db *DB) triageBadPG(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClausePG(f, 1, "samples")
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE `+triageBadWhere+extra+`
		 `+triageOrderSQL(f)+` LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage bad: %w", err)
	}
	return scanPGSamplesLight(rows)
}

func (db *DB) triageGoodPG(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClausePG(f, 1, "samples")
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE `+triageGoodWhere+extra+`
		 `+triageOrderSQL(f)+` LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage good: %w", err)
	}
	return scanPGSamplesLight(rows)
}

func (db *DB) triageNewPG(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClausePG(f, 1, "samples")
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE `+triageNewWherePG+extra+`
		 `+triageOrderSQL(f)+` LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage new: %w", err)
	}
	return scanPGSamplesLight(rows)
}

func (db *DB) triageReviewPG(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClausePG(f, 1, "samples")
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''
		   AND path LIKE 'review/%'`+extra+`
		 `+triageOrderSQL(f)+` LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage review: %w", err)
	}
	return scanPGSamplesLight(rows)
}

func (db *DB) triageSightedPG(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClausePG(f, 1, "samples")
	limitIdx := len(args) + 1
	// Each arm is bounded before digest/PURL matches are combined. The extra
	// room absorbs the uncommon case where the same bytes have both identities
	// (or several stored locations) and DISTINCT ON collapses them. Unlike the
	// old all-ledger join, work is therefore proportional to the requested batch,
	// not to every version of every cited package in the corpus.
	overfetch := limit + 256
	overIdx := len(args) + 2
	args = append(args, limit, overfetch)
	//nolint:unqueryvet // Derived-row schemas are fixed by pgSampleColsLight; the final projection is explicit.
	rows, err := db.pool.Query(ctx,
		`WITH candidates AS (
			(SELECT sm.*, c.sighted_at
			   FROM (
				SELECT subject, affected, first_seen AS sighted_at
				  FROM sightings
				 WHERE claim IN ('malicious', 'suspicious')
				   AND NOT starts_with(subject, 'pkg:')
				 ORDER BY first_seen DESC
			   ) c
			   CROSS JOIN LATERAL (
				SELECT `+pgSampleColsLight+` FROM samples
				 WHERE samples.sha256 = c.subject AND `+triageSightedWhere+extra+`
				 ORDER BY samples.created_at DESC, samples.id DESC
				 LIMIT $`+strconv.Itoa(overIdx)+`
			   ) sm
			  ORDER BY c.sighted_at DESC, sm.created_at DESC, sm.id DESC
			  LIMIT $`+strconv.Itoa(overIdx)+`)
			UNION ALL
			(SELECT sm.*, c.sighted_at
			   FROM (
				SELECT subject, affected, first_seen AS sighted_at
				  FROM sightings
				 WHERE claim IN ('malicious', 'suspicious')
				   AND starts_with(subject, 'pkg:')
				 ORDER BY first_seen DESC
			   ) c
			   CROSS JOIN LATERAL (
				SELECT `+pgSampleColsLight+` FROM samples
				 WHERE samples.purl_base = c.subject AND samples.purl_base != ''
				   AND (c.affected = '' OR c.affected = samples.version)
				   AND `+triageSightedWhere+extra+`
				 ORDER BY samples.created_at DESC, samples.id DESC
				 LIMIT $`+strconv.Itoa(overIdx)+`
			   ) sm
			  ORDER BY c.sighted_at DESC, sm.created_at DESC, sm.id DESC
			  LIMIT $`+strconv.Itoa(overIdx)+`)
		), latest AS (
			SELECT DISTINCT ON (sha256) * FROM candidates
			 ORDER BY sha256, sighted_at DESC, created_at DESC, id DESC
		)
		SELECT `+pgSampleColsLight+` FROM latest
		 ORDER BY sighted_at DESC, created_at DESC, id DESC
		 LIMIT $`+strconv.Itoa(limitIdx),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage sighted: %w", err)
	}
	return scanPGSamplesLight(rows)
}

// triageSecondOpinionPG: see TriageSecondOpinion. The sightings probes match a
// sample by either subject spelling (sha256 or version-less purl_base); the
// purl arm is guarded so a sample with no purl identity can't join sightings
// with an empty subject. An empty trusted list simply disables that arm.
func (db *DB) triageSecondOpinionPG(ctx context.Context, limit int, trusted []string, analyzedBefore time.Time, f TriageFilter) ([]*Sample, error) {
	if trusted == nil {
		trusted = []string{}
	}
	extra, fargs := triageFilterClausePG(f, 3, "samples")
	args := append([]any{analyzedBefore, trusted}, fargs...)
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND parent = ''`+
			triageServablePathSQL+`
		   AND corroborated
		   AND NOT (max_crit >= 5 OR suspicious_count >= 2)
		   AND analyzed_at < $1
		   AND (EXISTS (SELECT 1 FROM sightings s
		                WHERE (s.subject = samples.sha256
		                       OR (samples.purl_base != '' AND s.subject = samples.purl_base))
		                  AND s.source = ANY($2))
		        OR (SELECT count(DISTINCT s.operator) FROM sightings s
		            WHERE s.subject = samples.sha256
		               OR (samples.purl_base != '' AND s.subject = samples.purl_base)) >= 2)
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'second'
		                     AND r.created_at > COALESCE(
		                       (SELECT max(s2.first_seen) FROM sightings s2
		                        WHERE (s2.subject = samples.sha256
		                               OR (samples.purl_base != '' AND s2.subject = samples.purl_base))
		                          AND s2.source = ANY($2)),
		                       '-infinity'::timestamptz))`+extra+`
		 ORDER BY created_at DESC, id DESC LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage second opinion: %w", err)
	}
	return scanPGSamplesLight(rows)
}

// Predicate fragments for the recursive skip-scan that enumerates distinct
// file_types (Postgres has no loose index scan; DISTINCT over the ~11M-row
// partial index costs ~100s, the recursive probe ~80 index descents / ~ms).
// Must stay byte-compatible with idx_samples_{good,bad}_route_score's WHERE.
const (
	triageGoodScoredWherePG        = `label = 'good' AND litmus_score IS NOT NULL AND cleave_result IS NOT NULL AND skip = '' AND path <> ''`
	triageGoodScoredWherePGAliased = `s.label = 'good' AND s.litmus_score IS NOT NULL AND s.cleave_result IS NOT NULL ` +
		`AND s.skip = '' AND s.path <> ''`
	triageBadScoredWherePG        = `label = 'bad' AND litmus_score IS NOT NULL AND cleave_result IS NOT NULL AND skip = '' AND path <> ''`
	triageBadScoredWherePGAliased = `s.label = 'bad' AND s.litmus_score IS NOT NULL AND s.cleave_result IS NOT NULL AND s.skip = '' AND s.path <> ''`
)

// triageHighestPG: see TriageHighest. Returns one row per archive (the root
// sample), not per hot member: the worker fetches and judges the whole archive,
// so selecting its 40 hot members separately would re-fetch the same bytes 40
// times and judge files in isolation. The member->parent existence check the
// old query carried is gone: the outer root join already requires the parent
// row (an orphan member wastes one of its route's K slots, nothing more).
//
// Shape: a LATERAL per distinct file_type walks that route's score-ordered
// partial index (idx_samples_good_route_score) and stops after
// triagePerRouteK eligible members, tagging each with its per-route rank.
// DISTINCT ON collapses members to their root (keeping the hottest member's
// score+rank), and the outer join resolves each root to its own sample row —
// restricted to good/unknown parents, since a bad-labelled archive is
// TriageLowest's domain. The final ORDER BY is rank-first: every route's #1
// pinner sorts before any route's #2, so no route's tail (or the ~70k-member
// score-1.0 tie band that archives own) can monopolize a batch.
// The empty file_type is its own partition — rows there are rare (analyzed
// rows carry a type) and excluding them would hide real pinners.
func (db *DB) triageHighestPG(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClausePGKey(f, 3, "s0",
		"CASE WHEN s0.parent = '' THEN s0.sha256 ELSE s0.parent END")
	args := append([]any{createdBefore, missingBefore}, fargs...)
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`WITH RECURSIVE fts AS (
		   (SELECT file_type FROM samples
		     WHERE `+triageGoodScoredWherePG+`
		     ORDER BY file_type LIMIT 1)
		   UNION ALL
		   SELECT (SELECT s.file_type FROM samples s
		           WHERE `+triageGoodScoredWherePGAliased+` AND s.file_type > fts.file_type
		           ORDER BY s.file_type LIMIT 1)
		   FROM fts WHERE fts.file_type IS NOT NULL
		 )
		 SELECT `+pgSampleColsLight+` FROM (
		   SELECT DISTINCT ON (root) root, best, rank FROM (
		     SELECT k.root, k.best, k.rank
		     FROM (SELECT file_type FROM fts WHERE file_type IS NOT NULL) f
		     CROSS JOIN LATERAL (
		       SELECT CASE WHEN s0.parent = '' THEN s0.sha256 ELSE s0.parent END AS root,
		              s0.litmus_score AS best,
		              ROW_NUMBER() OVER (ORDER BY s0.litmus_score DESC) AS rank
		       FROM samples s0
		       WHERE s0.label = 'good' AND s0.cleave_result IS NOT NULL AND s0.skip = ''
		         AND s0.litmus_score IS NOT NULL
		         AND s0.file_type = f.file_type
		         AND (s0.parent = '' OR s0.path LIKE '%!!%')
		         AND s0.created_at < $1
		         AND NOT EXISTS (SELECT 1 FROM reports r
		                         WHERE r.sha256 = CASE WHEN s0.parent = '' THEN s0.sha256 ELSE s0.parent END
		                           AND (r.report_type = 'highest'
		                                OR (r.report_type = '`+ReportTypeMissing+`' AND r.created_at > $2)))`+extra+`
		       ORDER BY s0.litmus_score DESC
		       LIMIT `+strconv.Itoa(triagePerRouteK)+`
		     ) k
		   ) hot ORDER BY root, best DESC, rank ASC
		 ) roots
		 JOIN samples ON samples.sha256 = roots.root AND samples.label IN ('good', 'unknown')
		 ORDER BY roots.rank ASC, roots.best DESC NULLS LAST, samples.id DESC LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage highest: %w", err)
	}
	return scanPGSamplesLight(rows)
}

// triageLowestPG: see TriageLowest. Diverges from triageHighestPG on the drain
// key. A good archive vouches for its contents as a whole, so one ruling covers
// every member; a bad archive's malice lives in a few members while the rest is
// inert content that inherited the label, so each member needs its own verdict
// and its own report row. Keying this drain on the parent would let one ruling
// speak for files it never examined.
func (db *DB) triageLowestPG(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClausePG(f, 3, "s0")
	args := append([]any{createdBefore, missingBefore}, fargs...)
	args = append(args, limit)
	//nolint:unqueryvet // k.*/s0.* feed the LATERAL join and window function; the outer select names its columns via pgSampleColsLight.
	rows, err := db.pool.Query(ctx,
		`WITH RECURSIVE fts AS (
		   (SELECT file_type FROM samples
		     WHERE `+triageBadScoredWherePG+`
		     ORDER BY file_type LIMIT 1)
		   UNION ALL
		   SELECT (SELECT s.file_type FROM samples s
		           WHERE `+triageBadScoredWherePGAliased+` AND s.file_type > fts.file_type
		           ORDER BY s.file_type LIMIT 1)
		   FROM fts WHERE fts.file_type IS NOT NULL
		 )
		 SELECT `+pgSampleColsLight+` FROM (
		   SELECT k.*
		   FROM (SELECT file_type FROM fts WHERE file_type IS NOT NULL) f
		   CROSS JOIN LATERAL (
		     SELECT s0.*, ROW_NUMBER() OVER (ORDER BY s0.litmus_score ASC) AS rank
		     FROM samples s0
		     WHERE s0.label = 'bad' AND s0.cleave_result IS NOT NULL AND s0.skip = ''
		       AND s0.litmus_score IS NOT NULL
		       AND s0.file_type = f.file_type
		       AND s0.label_source != 'conflict'
		       AND (s0.parent = '' OR s0.path LIKE '%!!%')
		       AND (s0.parent = '' OR EXISTS (SELECT 1 FROM samples p WHERE p.sha256 = s0.parent))
		       AND s0.created_at < $1
		       AND NOT EXISTS (SELECT 1 FROM reports r
		                       WHERE r.sha256 = s0.sha256 AND r.report_type = 'lowest')
		       AND NOT EXISTS (SELECT 1 FROM reports r
		                       WHERE r.sha256 = CASE WHEN s0.parent = '' THEN s0.sha256 ELSE s0.parent END
		                         AND r.report_type = '`+ReportTypeMissing+`' AND r.created_at > $2)`+extra+`
		     ORDER BY s0.litmus_score ASC
		     LIMIT `+strconv.Itoa(triagePerRouteK)+`
		   ) k
		 ) samples
		 ORDER BY rank ASC, litmus_score ASC NULLS LAST, id DESC LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage lowest: %w", err)
	}
	return scanPGSamplesLight(rows)
}

// triageStrandedPG: see TriageStranded. The inner scan walks good-labeled
// members with real findings (score > 0, max_crit >= notableCrit) whose
// PARENT is bad-labeled, in member risk-score order; the collapse dedups to
// the parent archive (unit of work — the worker fetches and judges the whole
// archive with the member in context); the drain is PER MEMBER
// (report_type='stranded'), so an archive resurfaces as long as any
// qualifying member is unexamined, and never for members already covered.
// label_source NOT LIKE 'cyclotron:%' excludes members whose good label came
// from an individual review (the lowest queue's acquittals are correct state,
// not stranded inheritance).
func (db *DB) triageStrandedPG(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClausePG(f, 3, "m")
	args := append([]any{createdBefore, missingBefore}, fargs...)
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM (
		   SELECT DISTINCT ON (root) root, best FROM (
		     SELECT m.parent AS root, m.score AS best
		     FROM samples m
		     WHERE m.label = 'good' AND m.cleave_result IS NOT NULL AND m.skip = ''
		       AND m.parent != '' AND m.path LIKE '%!!%'
		       AND m.score > 0 AND m.max_crit >= `+strconv.Itoa(notableCrit)+`
		       AND m.label_source NOT LIKE 'cyclotron:%'
		       AND m.created_at < $1
		       AND EXISTS (SELECT 1 FROM samples p WHERE p.sha256 = m.parent AND p.label = 'bad')
		       AND NOT EXISTS (SELECT 1 FROM reports r
		                       WHERE r.sha256 = m.sha256 AND r.report_type = 'stranded')
		       AND NOT EXISTS (SELECT 1 FROM reports r
		                       WHERE r.sha256 = m.parent
		                         AND r.report_type = '`+ReportTypeMissing+`' AND r.created_at > $2)`+extra+`
		     ORDER BY m.score DESC
		     LIMIT `+strconv.Itoa(strandedInnerScan)+`
		   ) hot ORDER BY root, best DESC
		 ) roots
		 JOIN samples ON samples.sha256 = roots.root AND samples.label = 'bad'
		 ORDER BY roots.best DESC, samples.id DESC LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage stranded: %w", err)
	}
	return scanPGSamples(rows)
}

// triageAcquitPG: see TriageAcquit. jsonb operators express the provenance
// tests directly: a sidecar object exists and carries no 'feed' key.
func (db *DB) triageAcquitPG(ctx context.Context, limit int, createdBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClausePG(f, 2, "samples")
	args := append([]any{createdBefore}, fargs...)
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND parent = ''`+
			triageServablePathSQL+`
		   AND skip != 'conflict' AND label_source != 'conflict'
		   AND max_crit >= 5 AND suspicious_count >= 2
		   AND created_at < $1
		   AND provenance IS NOT NULL AND jsonb_typeof(provenance) = 'object'
		   AND NOT provenance ? 'feed'
		   AND NOT EXISTS (SELECT 1 FROM sightings s
		                   WHERE s.subject = samples.sha256
		                      OR (samples.purl_base != '' AND s.subject = samples.purl_base))
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'acquit')`+extra+`
		 ORDER BY created_at DESC, id DESC LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage acquit: %w", err)
	}
	return scanPGSamplesLight(rows)
}

// triageFalloutPG: see TriageFallout. litmus_result IS NOT NULL is implied by
// litmus_class = 2 (the trigger derives the class from the result) but stated
// so the predicate reads against the feed query it mirrors.
func (db *DB) triageFalloutPG(ctx context.Context, limit int, createdAfter time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClausePG(f, 2, "samples")
	args := append([]any{createdAfter}, fargs...)
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE litmus_class = 2 AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL
		   AND skip = '' AND file_type <> 'registry'`+triageServablePathSQL+`
		   AND created_at > $1
		   AND ((llm_result IS NULL OR COALESCE(llm_result->>'interpretation', '') = '')
		        OR NOT corroborated)
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'fallout')
		   AND `+uncontainedSQL+extra+`
		 `+triageOrderSQL(f)+` LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage fallout: %w", err)
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

// Mark-corroborated updates MUST be single-column. OR-ing sha256 and purl_base
// in one predicate forces a sequential scan of samples on large corpora (see
// plan_audit_test.go). Keep these as separate statements and never merge them.
const (
	markCorroboratedBySHASQL = `
		UPDATE samples SET corroborated = true
		WHERE NOT corroborated AND sha256 = ANY($1)`
	markCorroboratedByPURLSQL = `
		UPDATE samples SET corroborated = true
		WHERE purl_base = ANY($1) AND purl_base <> '' AND NOT corroborated`
)

// sightingUpsertChunk bounds one INSERT…unnest statement so a producer pushing a
// whole feed snapshot (tens of thousands of rows) is split into several ordinary
// statements rather than one enormous array literal. AddSightings loops over the
// input in chunks of this size.
const sightingUpsertChunk = 5000

func (db *DB) addSightingsPG(ctx context.Context, s []Sighting) (int, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("hopper: add sightings: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds

	changed := make(map[string]struct{})
	for start := 0; start < len(s); start += sightingUpsertChunk {
		end := min(start+sightingUpsertChunk, len(s))
		batch := s[start:end]
		sources := make([]string, len(batch))
		subjects := make([]string, len(batch))
		urls := make([]string, len(batch))
		notes := make([]string, len(batch))
		operators := make([]string, len(batch))
		affected := make([]string, len(batch))
		claims := make([]string, len(batch))
		filenames := make([]string, len(batch))
		published := make([]*time.Time, len(batch))
		seeded := make([]*time.Time, len(batch))
		for i := range batch {
			x := &batch[i]
			sources[i], subjects[i], urls[i], notes[i] = x.Source, x.Subject, x.URL, x.Note
			operators[i], affected[i] = x.Operator, x.Affected
			claims[i], filenames[i] = string(x.Claim), x.FileName
			if !x.PublishedAt.IsZero() {
				t := x.PublishedAt.UTC()
				published[i] = &t
			}
			// Non-zero only for a source's first bulk import, which
			// AddSightings backdates rather than presenting as today's news.
			if !x.FirstSeen.IsZero() {
				t := x.FirstSeen.UTC()
				seeded[i] = &t
			}
		}
		// Delta-guarded upsert: an unchanged row (same url+note) trips the WHERE
		// and writes nothing, so re-pushing a snapshot is near-free. RETURNING
		// yields only the rows that actually inserted or changed — the real delta
		// we feed into the samples flag update below.
		rows, err := tx.Query(ctx, `
			INSERT INTO sightings
				(source, subject, url, note, operator, affected, claim, filename, published_at, first_seen)
			SELECT src, subj, u, n, op, aff, cl, fn, pub, COALESCE(seed, now())
			FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
			            $6::text[], $7::text[], $8::text[], $9::timestamptz[], $10::timestamptz[])
				AS t(src, subj, u, n, op, aff, cl, fn, pub, seed)
			ON CONFLICT (source, subject, affected) DO UPDATE
				SET url = EXCLUDED.url, note = EXCLUDED.note,
				    operator = EXCLUDED.operator, claim = EXCLUDED.claim,
				    filename = EXCLUDED.filename, published_at = EXCLUDED.published_at
				WHERE sightings.url IS DISTINCT FROM EXCLUDED.url
				   OR sightings.note IS DISTINCT FROM EXCLUDED.note
				   OR sightings.operator IS DISTINCT FROM EXCLUDED.operator
				   OR sightings.claim IS DISTINCT FROM EXCLUDED.claim
				   OR sightings.filename IS DISTINCT FROM EXCLUDED.filename
				   OR sightings.published_at IS DISTINCT FROM EXCLUDED.published_at
			RETURNING subject`,
			sources, subjects, urls, notes, operators, affected, claims, filenames, published, seeded)
		if err != nil {
			return 0, fmt.Errorf("hopper: upsert sightings: %w", err)
		}
		for rows.Next() {
			var subj string
			if err := rows.Scan(&subj); err != nil {
				rows.Close()
				return 0, fmt.Errorf("hopper: scan sighting subject: %w", err)
			}
			changed[subj] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			return 0, fmt.Errorf("hopper: upsert sightings: %w", err)
		}
	}

	if len(changed) > 0 {
		subs := make([]string, 0, len(changed))
		for subj := range changed {
			subs = append(subs, subj)
		}
		// Flip the denormalized flag only for the changed subjects, guarded by
		// NOT corroborated so a re-run touches nothing. Two single-column
		// updates (never OR'd) so Postgres can use the sha256 PK and
		// idx_samples_purl_base instead of seq-scanning samples.
		shas, purls := splitSightingSubjects(subs)
		if len(shas) > 0 {
			if _, err := tx.Exec(ctx, markCorroboratedBySHASQL, shas); err != nil {
				return 0, fmt.Errorf("hopper: mark corroborated: %w", err)
			}
		}
		if len(purls) > 0 {
			if _, err := tx.Exec(ctx, markCorroboratedByPURLSQL, purls); err != nil {
				return 0, fmt.Errorf("hopper: mark corroborated: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("hopper: commit sightings: %w", err)
	}
	return len(changed), nil
}

// remarkCorroboratedPG re-derives samples.corroborated from the whole ledger.
//
// AddSightings marks as it writes, which covers every ordinary path. This exists
// for the case where a subject changes UNDERNEATH the flag: a canonicalisation
// fold, or the digest-wearing-a-purl repair. Those rewrite sightings.subject and
// leave samples untouched, so a citation that finally names a real sample still
// reads as uncorroborated until something re-applies it — which is exactly how
// 767 confirmed-malicious samples stayed visible to the acquit queue.
//
// Only ever sets the flag, never clears it: both statements are guarded by
// NOT corroborated. A sighting that is deleted or re-keyed away does not
// un-corroborate the sample it used to name, because we cannot tell from here
// whether some other source still cites it. That asymmetry is deliberate — the
// safe direction is to keep believing corroboration we once had.
//
// Batched over distinct subjects so no single statement carries a
// hundred-thousand-element array.
func (db *DB) remarkCorroboratedPG(ctx context.Context) (int64, error) {
	rows, err := db.pool.Query(ctx, `SELECT DISTINCT subject FROM sightings ORDER BY subject`)
	if err != nil {
		return 0, fmt.Errorf("hopper: remark corroborated scan: %w", err)
	}
	var subjects []string
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			rows.Close()
			return 0, fmt.Errorf("hopper: remark corroborated row: %w", err)
		}
		subjects = append(subjects, subject)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	const batch = 5000
	var marked int64
	for start := 0; start < len(subjects); start += batch {
		shas, purls := splitSightingSubjects(subjects[start:min(start+batch, len(subjects))])
		for _, step := range []struct {
			sql  string
			args []string
		}{{markCorroboratedBySHASQL, shas}, {markCorroboratedByPURLSQL, purls}} {
			if len(step.args) == 0 {
				continue
			}
			tag, err := db.pool.Exec(ctx, step.sql, step.args)
			if err != nil {
				return marked, fmt.Errorf("hopper: remark corroborated: %w", err)
			}
			marked += tag.RowsAffected()
		}
	}
	return marked, nil
}

func (db *DB) sightingsForPG(ctx context.Context, subjects []string) (map[string][]Sighting, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT source, subject, url, note, first_seen,
		       operator, affected, claim, filename, published_at
		FROM sightings WHERE subject = ANY($1)
		ORDER BY source`, subjects)
	if err != nil {
		return nil, fmt.Errorf("hopper: sightings for subjects: %w", err)
	}
	defer rows.Close()
	out := make(map[string][]Sighting, len(subjects))
	for rows.Next() {
		var x Sighting
		var published *time.Time
		if err := rows.Scan(&x.Source, &x.Subject, &x.URL, &x.Note, &x.FirstSeen,
			&x.Operator, &x.Affected, &x.Claim, &x.FileName, &published); err != nil {
			return nil, fmt.Errorf("hopper: scan sighting: %w", err)
		}
		if published != nil {
			x.PublishedAt = *published
		}
		out[x.Subject] = append(out[x.Subject], x)
	}
	return out, rows.Err()
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

func (db *DB) tryClaimSamplePG(ctx context.Context, sha256, owner string, staleBefore time.Time) (bool, error) {
	var claimed bool
	err := db.pool.QueryRow(ctx, `
		UPDATE samples SET claimed_by = $2, claimed_at = now()
		WHERE sha256 = $1
		  AND (claimed_by = '' OR claimed_at IS NULL OR claimed_at < $3)
		RETURNING true`, sha256, owner, staleBefore.UTC()).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("hopper: claim sample: %w", err)
	}
	return claimed, nil
}

func (db *DB) releaseSampleClaimPG(ctx context.Context, sha256, owner string) error {
	if _, err := db.pool.Exec(ctx, `
		UPDATE samples SET claimed_by = '', claimed_at = NULL
		WHERE sha256 = $1 AND claimed_by = $2`, sha256, owner); err != nil {
		return fmt.Errorf("hopper: release sample claim: %w", err)
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
// JSON carries a type to derive. The matching partial index was dropped as
// unused (0 scans in 34 days), so this gate now costs a scan — recreate
// idx_samples_filetype_pending if the pass ever needs to run hot again.
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
	// file_type=''). The pgFileTypeBackfillWhere gate self-drains — a row leaves
	// it the moment file_type becomes non-empty — so this finishes fast (though
	// it now scans, see pgFileTypeBackfillWhere) and is never held
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

	// Pass 1e: top_traits for rows analyzed before it became a trigger-fed
	// column. Self-draining like Pass 1d (NULL → non-NULL); its partial index
	// was dropped as unused, so the gate now scans.
	tt, err := db.backfillTopTraitsPG(ctx, backfillBatch)
	if err != nil {
		return stats, err
	}
	stats.Updated += tt
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
						COALESCE(cleave_result->'files'->0->'traits', cleave_result->'files'->0->'find', cleave_result->'fs'->0->'ts', '[]'::jsonb)
					) AS tr
					WHERE COALESCE(tr->>'crit', tr->>'l') IS NOT NULL
				), 0),
				suspicious_count = (
					SELECT COUNT(*)::int
					FROM jsonb_array_elements(
						COALESCE(cleave_result->'files'->0->'traits', cleave_result->'files'->0->'find', cleave_result->'fs'->0->'ts', '[]'::jsonb)
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

// rehealCleaveCritPG repairs max_crit/suspicious_count for rows the
// samples_derive_cleave_cols trigger zeroed while it only knew the v7 'find'
// trait key: v8 renamed that array to 'traits' (landed ~2026-06-15), so every
// v8 sample derived max_crit=0 / suspicious_count=0 regardless of its actual
// findings, dropping all post-v8 malware out of the bloom's bad tiers
// (label='bad' AND max_crit>=4) and out of every prism/promoter criticality
// gate. The standard Backfill Pass 1 cannot reach these rows: its gate is
// elements=” (whose partial index was dropped as unused), and the broken trigger still
// derived elements/formula/file_type/score correctly (those keys did not
// rename) — only the two crit columns are wrong. So this is a separate,
// explicit, one-time heal.
//
// It pages by ascending id (PK index, so sparse ids cost nothing) and recomputes
// both columns from the now-correct 'traits'→'find'→'ts' fallback, restricted to
// rows that carry the v8 'traits' key and still read max_crit=0. The final
// predicate (nv.mc>0 OR nv.sc>0) writes only rows whose corrected value actually
// differs, so genuinely-benign v8 rows are never rewritten and the pass is
// idempotent. No updated_at bump: like backfillLitmusClassPG, healing a derived
// column must not reshuffle update queues. Returns the number of rows repaired.
func (db *DB) rehealCleaveCritPG(ctx context.Context) (int64, error) {
	const batchRows = 50000
	var updated, cursor int64
	for {
		var hi *int64
		if err := db.pool.QueryRow(ctx,
			`SELECT max(id) FROM (SELECT id FROM samples WHERE id > $1 ORDER BY id LIMIT $2) q`,
			cursor, batchRows).Scan(&hi); err != nil {
			return updated, fmt.Errorf("hopper: reheal crit cursor: %w", err)
		}
		if hi == nil {
			break // no rows past the cursor; done
		}
		tag, err := db.pool.Exec(ctx, `
			UPDATE samples s SET max_crit = nv.mc, suspicious_count = nv.sc
			FROM (
				SELECT id,
					COALESCE((
						SELECT MAX((COALESCE(tr->>'crit', tr->>'l'))::int)
						FROM jsonb_array_elements(
							COALESCE(
								cleave_result->'files'->0->'traits',
								cleave_result->'files'->0->'find',
								cleave_result->'fs'->0->'ts', '[]'::jsonb)
						) AS tr
						WHERE COALESCE(tr->>'crit', tr->>'l') IS NOT NULL
					), 0) AS mc,
					(
						SELECT COUNT(*)::int
						FROM jsonb_array_elements(
							COALESCE(
								cleave_result->'files'->0->'traits',
								cleave_result->'files'->0->'find',
								cleave_result->'fs'->0->'ts', '[]'::jsonb)
						) AS tr
						WHERE COALESCE(tr->>'crit', tr->>'l') IS NOT NULL
							AND (COALESCE(tr->>'crit', tr->>'l'))::int >= 4
					) AS sc
				FROM samples
				WHERE id > $1 AND id <= $2
					AND cleave_result IS NOT NULL
					AND max_crit = 0
					AND cleave_result->'files'->0 ? 'traits'
			) nv
			WHERE s.id = nv.id AND (nv.mc > 0 OR nv.sc > 0)`, cursor, *hi)
		if err != nil {
			return updated, fmt.Errorf("hopper: reheal crit batch (%d, %d]: %w", cursor, *hi, err)
		}
		updated += tag.RowsAffected()
		cursor = *hi
		slog.Info("reheal crit batch", "through_id", cursor, "repaired_total", updated)
	}
	return updated, nil
}

// backfillPURLPG fills samples.purl_base for top-level rows that carry a package
// coordinate but no stored PURL identity. Two backlogs land here: rows ingested
// before forager derived purl_base on write, and rows whose ecosystem the old
// derivation could not map — it ran the lossy runtime ecosystem string through a
// registry-only table, so javascript/rust/java/ruby/dotnet silently produced no
// PURL, which (with the cleave v8 max_crit miss) is why the bad-PURL bloom froze
// at a handful of entries.
//
// It rebuilds the version-less identity from the stored ecosystem + package
// columns via the shared pkgparse builder, which maps each runtime ecosystem to
// its dominant registry and refuses the ambiguous ones — so a row we cannot map
// confidently is left empty rather than given a wrong PURL. It never overwrites a
// non-empty purl_base (re-running is a no-op and existing identities are
// untouched), and pages by ascending id advancing the cursor past every scanned
// row, so each heap row is visited once and unmappable rows are not retried. No
// updated_at bump: purl_base is a derived identity, not a state change.
func (db *DB) backfillPURLPG(ctx context.Context) (int64, error) {
	const batchRows = 20000
	var updated, cursor int64
	for {
		rows, err := db.pool.Query(ctx, `
			SELECT id, ecosystem, domain, package FROM samples
			WHERE id > $1 AND purl_base = '' AND package <> '' AND parent = ''
			ORDER BY id LIMIT $2`, cursor, batchRows)
		if err != nil {
			return updated, fmt.Errorf("hopper: backfill purl select: %w", err)
		}
		var ids []int64
		var purls []string
		var seen int
		var maxID int64
		for rows.Next() {
			var id int64
			var eco, dom, pkg string
			if err := rows.Scan(&id, &eco, &dom, &pkg); err != nil {
				rows.Close()
				return updated, fmt.Errorf("hopper: backfill purl scan: %w", err)
			}
			seen++
			maxID = id
			if p, ok := pkgparse.SourcePURLIdentity(eco, dom, pkg); ok {
				ids = append(ids, id)
				purls = append(purls, p)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return updated, fmt.Errorf("hopper: backfill purl iterate: %w", err)
		}
		rows.Close()
		if seen == 0 {
			break
		}
		if len(ids) > 0 {
			tag, err := db.pool.Exec(ctx, `
				UPDATE samples s SET purl_base = v.purl
				FROM unnest($1::bigint[], $2::text[]) AS v(id, purl)
				WHERE s.id = v.id AND s.purl_base = ''`, ids, purls)
			if err != nil {
				return updated, fmt.Errorf("hopper: backfill purl update: %w", err)
			}
			updated += tag.RowsAffected()
		}
		cursor = maxID
		slog.Info("backfill purl batch", "through_id", cursor, "filled_total", updated)
		if seen < batchRows {
			break
		}
	}
	return updated, nil
}

// canonicalizePURLBasesPG rewrites every stored samples.purl_base onto the
// current canonical spelling (pkgparse.CanonicalizePURL + VersionlessPURL) —
// the repair for rows written before a fold existed: the qualifier-form AUR
// identity, dotted PyPI names, mixed-case extension ids, legacy bare distro
// types. It never blocks the table: rows stream in id-cursor batches (each
// SELECT is a snapshot read), the canonical form is computed client-side, and
// only rows whose spelling actually changes are written — one short
// batch-sized transaction of row-level locks apiece. The `purl_base = old`
// guard skips any row that changed concurrently, and canonicalization is a
// fixed point, so the sweep is idempotent and safely resumable. purl_base-only
// updates fire no trigger (samples_derive_cleave_cols is `UPDATE OF
// cleave_result`) and bump no updated_at: a respelled identity is not a state
// change. dryRun reports what would be rewritten without writing.
func (db *DB) canonicalizePURLBasesPG(ctx context.Context, dryRun bool) (int64, error) {
	const batchRows = 20000
	var rewritten, cursor int64
	for {
		rows, err := db.pool.Query(ctx, `
			SELECT id, purl_base FROM samples
			WHERE id > $1 AND purl_base <> ''
			ORDER BY id LIMIT $2`, cursor, batchRows)
		if err != nil {
			return rewritten, fmt.Errorf("hopper: canonicalize purl select: %w", err)
		}
		var ids []int64
		var olds, news []string
		var seen int
		var maxID int64
		for rows.Next() {
			var id int64
			var pb string
			if err := rows.Scan(&id, &pb); err != nil {
				rows.Close()
				return rewritten, fmt.Errorf("hopper: canonicalize purl scan: %w", err)
			}
			seen++
			maxID = id
			// VersionlessPURL after canonicalization: the order repair can
			// surface a version a legacy composer had buried in the
			// qualifier tail, and purl_base is the version-less identity.
			canon := pkgparse.VersionlessPURL(pkgparse.CanonicalizePURL(pb))
			if canon != pb && canon != "" {
				ids = append(ids, id)
				olds = append(olds, pb)
				news = append(news, canon)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return rewritten, fmt.Errorf("hopper: canonicalize purl iterate: %w", err)
		}
		rows.Close()
		if seen == 0 {
			break
		}
		if len(ids) > 0 {
			if dryRun {
				rewritten += int64(len(ids))
				slog.Info("canonicalize purl would rewrite",
					"count", len(ids), "example_old", olds[0], "example_new", news[0])
			} else {
				tag, err := db.pool.Exec(ctx, `
					UPDATE samples s SET purl_base = v.new
					FROM unnest($1::bigint[], $2::text[], $3::text[]) AS v(id, old, new)
					WHERE s.id = v.id AND s.purl_base = v.old`, ids, olds, news)
				if err != nil {
					return rewritten, fmt.Errorf("hopper: canonicalize purl update: %w", err)
				}
				rewritten += tag.RowsAffected()
			}
		}
		cursor = maxID
		slog.Info("canonicalize purl batch",
			"through_id", cursor, "rewritten_total", rewritten, "dry_run", dryRun)
		if seen < batchRows {
			break
		}
	}
	return rewritten, nil
}

// repairStandaloneParentsPG clears samples.parent on rows whose bytes are on
// disk under their own path.
//
// `parent` is a storage locator, not a containment fact: handleFile reads it as
// "these bytes are not stored under this sha, stream them out of that archive
// instead". A row that also has a standalone location in the ledger has its
// bytes right there, so a non-empty parent sends handleFile extracting from an
// archive for a file it could have opened — and it answers 422 when that
// archive is gone or no longer holds the member. The uncontainedSQL comment
// names this exact hazard as the reason a member write must never claim a
// standalone row's identity; these are the rows where that already happened,
// because ON CONFLICT never SETs parent and so the first writer keeps it.
//
// Containment is deliberately not consulted. Whether an archive also contains
// this artifact is a question for the ledger and uncontainedSQL; it has no
// bearing on where the bytes are, which is all parent is for. Rows with no
// standalone location keep their parent — extraction is the only way to serve
// them.
//
// Paged over sample_locations.id — the driving table — not samples.id. The
// planner resolves the standalone test as a semi-join driven from the ledger
// side (a scan of every parent_sha256 = ” row, hash-aggregated to distinct
// sha256), so a cursor on samples.id lands as a filter *after* that scan and
// prunes nothing: every batch repeats the same full ledger scan and the same
// sort, then keeps 20k rows of it. Paging the side the scan actually starts
// from is what makes the cursor advance real work, and idx_sl_standalone makes
// each page index-only. No batch locks more than batchRows worth of samples.
//
// Idempotent and resumable. dryRun only counts, and counts a shade high: one
// sha256 can hold several standalone locations, and when they fall in different
// pages the same row is counted once per page. The live path cannot double-count
// — the UPDATE's parent <> ” is already false the second time.
// repairStandaloneParentsPageSQL is one page of the standalone-location walk.
// Ordered by the ledger's own id and bounded by it, so the cursor prunes the
// scan rather than filtering its output — see repairStandaloneParentsPG.
// TestPlanAuditRepairStandaloneParents fails if this stops being an ordered
// index walk of sample_locations.
const repairStandaloneParentsPageSQL = `
	SELECT id, sha256 FROM sample_locations
	WHERE id > $1 AND parent_sha256 = ''
	ORDER BY id LIMIT $2`

func (db *DB) repairStandaloneParentsPG(ctx context.Context, dryRun bool) (int64, error) {
	const batchRows = 20000
	var repaired, cursor int64
	for {
		rows, err := db.pool.Query(ctx, repairStandaloneParentsPageSQL, cursor, batchRows)
		if err != nil {
			return repaired, fmt.Errorf("hopper: repair parents select: %w", err)
		}
		// One sha256 can hold several standalone locations, so dedupe within the
		// page: the UPDATE would be a no-op on the repeats, but they would other-
		// wise bloat the array parameter for no gain.
		shas := make([]string, 0, batchRows)
		seenSHA := make(map[string]struct{}, batchRows)
		var maxID int64
		var seen int
		for rows.Next() {
			var id int64
			var sha string
			if err := rows.Scan(&id, &sha); err != nil {
				rows.Close()
				return repaired, fmt.Errorf("hopper: repair parents scan: %w", err)
			}
			seen++
			maxID = id
			if _, dup := seenSHA[sha]; dup {
				continue
			}
			seenSHA[sha] = struct{}{}
			shas = append(shas, sha)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return repaired, fmt.Errorf("hopper: repair parents iterate: %w", err)
		}
		rows.Close()
		if seen == 0 {
			break
		}
		if dryRun {
			var n int64
			if err := db.pool.QueryRow(ctx, `
				SELECT count(*) FROM samples
				WHERE sha256 = ANY($1) AND parent <> ''`, shas).Scan(&n); err != nil {
				return repaired, fmt.Errorf("hopper: repair parents count: %w", err)
			}
			repaired += n
		} else {
			// parent <> '' both selects the rows worth writing and makes the
			// statement idempotent: a re-run, or a repeated sha256, matches nothing.
			tag, err := db.pool.Exec(ctx, `
				UPDATE samples SET parent = ''
				WHERE sha256 = ANY($1) AND parent <> ''`, shas)
			if err != nil {
				return repaired, fmt.Errorf("hopper: repair parents update: %w", err)
			}
			repaired += tag.RowsAffected()
		}
		cursor = maxID
		slog.Info("repair-parents batch",
			"through_id", cursor, "repaired_total", repaired, "dry_run", dryRun)
		if seen < batchRows {
			break
		}
	}
	return repaired, nil
}

// canonicalizeSightingSubjectsPG rewrites every sightings.subject onto the
// ledger keying convention (see normalizeSubject). The ledger is small
// (thousands of rows), so this is a single read + per-change transaction. A
// canonical collision with an existing (source, subject) row merges into it:
// insert-if-absent then delete the old spelling, keeping the survivor's
// first_seen.
func (db *DB) canonicalizeSightingSubjectsPG(ctx context.Context, dryRun bool) (int64, error) {
	rows, err := db.pool.Query(ctx, `SELECT source, subject FROM sightings ORDER BY source, subject`)
	if err != nil {
		return 0, fmt.Errorf("hopper: canonicalize sightings scan: %w", err)
	}
	type change struct{ source, old, canon string }
	var changes []change
	for rows.Next() {
		var source, subject string
		if err := rows.Scan(&source, &subject); err != nil {
			rows.Close()
			return 0, fmt.Errorf("hopper: canonicalize sightings row: %w", err)
		}
		if canon := normalizeSubject(subject); canon != subject && canon != "" {
			changes = append(changes, change{source, subject, canon})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if dryRun {
		for _, c := range changes {
			slog.Info("canonicalize sighting would rewrite", "source", c.source, "old", c.old, "new", c.canon)
		}
		return int64(len(changes)), nil
	}
	var rewritten int64
	for _, c := range changes {
		tx, err := db.pool.Begin(ctx)
		if err != nil {
			return rewritten, fmt.Errorf("hopper: canonicalize sighting begin: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sightings (source, subject, url, note, first_seen)
			SELECT source, $3, url, note, first_seen FROM sightings
			WHERE source = $1 AND subject = $2
			ON CONFLICT (source, subject) DO NOTHING`, c.source, c.old, c.canon); err != nil {
			rollbackErr := tx.Rollback(ctx)
			return rewritten, errors.Join(fmt.Errorf("hopper: canonicalize sighting insert: %w", err), rollbackErr)
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM sightings WHERE source = $1 AND subject = $2`, c.source, c.old); err != nil {
			rollbackErr := tx.Rollback(ctx)
			return rewritten, errors.Join(fmt.Errorf("hopper: canonicalize sighting delete: %w", err), rollbackErr)
		}
		if err := tx.Commit(ctx); err != nil {
			return rewritten, fmt.Errorf("hopper: canonicalize sighting commit: %w", err)
		}
		rewritten++
	}
	return rewritten, nil
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

// ReplicationLag reports how far behind this instance is. `known` is false
// when it is not a subscriber, or cannot see the answer.
//
// Asked of `pg_stat_subscription` rather than inferred from the data. The
// first cut of this took the age of the newest row — `max(updated_at)` — on the
// reasoning that a reader wants to know whether its answer is current, and that
// idx_samples_updated_at made it an index-only scan. It does, on the publisher.
// The replica *drops* that index on purpose (it is in REPLICA_DROP_INDEXES),
// so on the one machine where the query actually runs it was a sequential scan
// of the whole samples table, and every call timed out. The lesson is narrower
// than "use the right view": a replica does not have the publisher's schema,
// and a query written against one is not a query against the other.
//
// `latest_end_time` is when the apply worker last reported progress to the
// publisher, so its age is the delay a reader would experience. A NULL — no
// subscription, no apply worker, or a role without the privilege to see it —
// returns nil rather than zero, because "I cannot tell you" and "I am current"
// must not be the same answer to a caller deciding whether to trust an absence.
func (db *DB) ReplicationLag(ctx context.Context) (lag time.Duration, known bool, err error) {
	var secs *int64
	err = db.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM (now() - a.latest_end_time))::bigint
		  FROM pg_stat_subscription a
		 WHERE a.relid IS NULL AND a.pid IS NOT NULL
		 ORDER BY a.latest_end_time DESC NULLS LAST
		 LIMIT 1`).Scan(&secs)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Not a subscriber. A publisher has no replication lag, and saying so
		// is different from failing to answer.
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("hopper: replication lag: %w", err)
	case secs == nil:
		return 0, false, nil
	}
	// Clocks disagree; being fractionally ahead is not negative lag.
	return time.Duration(max(*secs, 0)) * time.Second, true, nil
}

// backfillTopTraitsPG heals top_traits for rows written before the derive
// trigger learned the column, in two sweeps so the benign majority never
// costs a cleave_result detoast: rows with suspicious_count = 0 can't have
// top traits, so the first sweep sets ” straight from that scalar column;
// only rows with suspicious traits pay the JSON extraction, whose expression
// mirrors the trigger's (and encodeTopTraits) — crit desc, original order
// within a level, capped at 3 — keep the three in sync. Does not bump
// updated_at: healing a derived column is not a real change.
func (db *DB) backfillTopTraitsPG(ctx context.Context, limit int) (int64, error) {
	var total int64
	for {
		tag, err := db.pool.Exec(ctx, `
			UPDATE samples SET top_traits = ''
			WHERE sha256 IN (
				SELECT sha256 FROM samples
				WHERE top_traits IS NULL AND cleave_result IS NOT NULL
					AND suspicious_count = 0
				LIMIT $1
			)`, limit)
		if err != nil {
			return total, fmt.Errorf("hopper: backfill top_traits (benign): %w", err)
		}
		n := tag.RowsAffected()
		total += n
		if n < int64(limit) {
			break
		}
		slog.Info("backfill top_traits benign batch", "batch", n, "total", total)
	}
	for {
		tag, err := db.pool.Exec(ctx, `
			UPDATE samples SET top_traits = COALESCE((
				SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('id', q.id, 'crit', q.crit, 'dep', q.dep)))::text
				FROM (
					SELECT COALESCE(t->>'id', t->>'i') AS id,
						   (COALESCE(t->>'crit', t->>'l'))::int AS crit,
						   t->'dep' AS dep
					FROM jsonb_array_elements(
						COALESCE(cleave_result->'files'->0->'traits', cleave_result->'files'->0->'find', cleave_result->'fs'->0->'ts', '[]'::jsonb)
					) WITH ORDINALITY AS f(t, ord)
					WHERE COALESCE(t->>'crit', t->>'l') IS NOT NULL
						AND (COALESCE(t->>'crit', t->>'l'))::int >= 4
						AND COALESCE(t->>'id', t->>'i') IS NOT NULL
					ORDER BY (COALESCE(t->>'crit', t->>'l'))::int DESC, ord
					LIMIT 3
				) AS q), '')
			WHERE sha256 IN (
				SELECT sha256 FROM samples
				WHERE top_traits IS NULL AND cleave_result IS NOT NULL
					AND suspicious_count > 0
				LIMIT $1
			)`, limit)
		if err != nil {
			return total, fmt.Errorf("hopper: backfill top_traits: %w", err)
		}
		n := tag.RowsAffected()
		total += n
		if n < int64(limit) {
			return total, nil
		}
		slog.Info("backfill top_traits batch", "batch", n, "total", total)
	}
}

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
					WHEN COALESCE(litmus_result->>'lvl', litmus_result->>'l')::int <= %d THEN 1
					ELSE 0
				END)
			WHERE sha256 IN (
				SELECT sha256 FROM samples
				WHERE litmus_result IS NOT NULL AND litmus_class IS NULL
				LIMIT $1
			)`, CriticalLevel, SuspiciousCeiling), limit)
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

func (db *DB) provenanceBySHA256PG(ctx context.Context, sha256 string) ([]byte, error) {
	var prov []byte
	err := db.pool.QueryRow(ctx,
		`SELECT provenance FROM samples WHERE sha256 = $1`, sha256).Scan(&prov)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("hopper: provenance %s: %w", sha256, err)
	}
	return prov, nil
}

func (db *DB) setProvenancePG(ctx context.Context, s *Sample) (bool, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples SET
			provenance = $2,
			ecosystem  = COALESCE(NULLIF(ecosystem, ''), $3),
			package    = COALESCE(NULLIF(package, ''), $4),
			version    = COALESCE(NULLIF(version, ''), $5),
			purl_base  = COALESCE(NULLIF(purl_base, ''), $6),
			url        = COALESCE(NULLIF(url, ''), $7),
			fetched_at = COALESCE(fetched_at, $8)
		WHERE sha256 = $1`,
		s.SHA256, sanitizeJSONB(s.Provenance),
		s.Ecosystem, s.Package, s.Version, s.PURLBase, s.URL, s.FetchedAt)
	if err != nil {
		return false, fmt.Errorf("hopper: set provenance %s: %w", s.SHA256, err)
	}
	return tag.RowsAffected() > 0, nil
}

func (db *DB) shasWithProvenancePG(ctx context.Context, shas []string) (map[string]bool, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT sha256 FROM samples WHERE sha256 = ANY($1) AND provenance IS NOT NULL`, shas)
	if err != nil {
		return nil, fmt.Errorf("hopper: shas with provenance: %w", err)
	}
	defer rows.Close()
	out := make(map[string]bool, len(shas))
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, fmt.Errorf("hopper: shas with provenance scan: %w", err)
		}
		out[sha] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hopper: shas with provenance rows: %w", err)
	}
	return out, nil
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

// reapOversizedPG marks pending samples no worker will ever claim (larger than
// the advertised per-job cap) as skip='oversized'. See ReapOversized.
func (db *DB) reapOversizedPG(ctx context.Context, maxBytes int64) (int64, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE samples SET skip = 'oversized', skipped_at = now(), updated_at = now()
		WHERE cleave_result IS NULL AND skip = '' AND size_bytes > $1`, maxBytes)
	if err != nil {
		return 0, fmt.Errorf("hopper: reap oversized: %w", err)
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

func (db *DB) observeStagedLocationsPG(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime,
			 first_seen_at, last_seen_at)
		SELECT w.sha256, w.path, '', s.filename, s.source, s.feed, s.ecosystem, s.mtime,
		       now(), now()
		FROM walk_staging w
		JOIN samples s ON s.sha256 = w.sha256
		WHERE s.parent = ''
		ON CONFLICT (sha256, path) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (db *DB) eligibleStandaloneRootsPG(ctx context.Context) (map[string]int64, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT split_part(ltrim(path, '/'), '/', 1) AS root, count(*)
		FROM samples
		WHERE parent = '' AND skip IN ('', 'conflict')
		GROUP BY root`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var root string
		var n int64
		if err := rows.Scan(&root, &n); err != nil {
			return nil, err
		}
		out[root] = n
	}
	return out, rows.Err()
}

func (db *DB) relabelFromPoolsPG(ctx context.Context) (int64, error) {
	// One statement: a writable CTE updates the changed rows and the final
	// INSERT audits them. PG executes every data-modifying CTE exactly once, so
	// the UPDATE runs even though the INSERT reads pre-update values from
	// `changed`. Atomic by construction.
	rows, err := db.pool.Query(ctx, `
		WITH pools AS (
			SELECT sha256,
				bool_or(path LIKE 'bad/%')     AS in_bad,
				bool_or(path LIKE 'good/%')    AS in_good,
				bool_or(path LIKE 'sighted/%') AS in_sighted
			FROM walk_staging
			GROUP BY sha256
		),
		target AS (
			SELECT s.sha256, s.label AS old_label, s.skip AS old_skip,
				-- sighted/ only lifts unknown rows (rank sighted > unknown); it
				-- never demotes a verified good/bad label back to a feed claim.
				CASE WHEN p.in_bad THEN 'bad' WHEN p.in_good THEN 'good'
				     WHEN p.in_sighted AND s.label = 'unknown' THEN 'sighted'
				     ELSE s.label END AS new_label,
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
		FROM changed
		RETURNING sha256, from_label, to_label, from_skip, to_skip`)
	if err != nil {
		return 0, fmt.Errorf("hopper: relabel: %w", err)
	}
	defer rows.Close()

	// Log the operationally interesting relabels (a missing/unsupported file
	// revived by reappearing in a pool, or a new conflict) one line each; the
	// count of all relabels — plain bad<->good moves included — is returned.
	var n int64
	for rows.Next() {
		var sha, fromLabel, toLabel, fromSkip, toSkip string
		if err := rows.Scan(&sha, &fromLabel, &toLabel, &fromSkip, &toSkip); err != nil {
			return 0, fmt.Errorf("hopper: relabel scan: %w", err)
		}
		n++
		if fromSkip != toSkip {
			logRelabelSkipChange(sha, fromLabel, toLabel, fromSkip, toSkip)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("hopper: relabel: %w", err)
	}
	return n, nil
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
				-- lets the planner use the partial idx_sl_parent_child
				-- (WHERE parent_sha256 <> '') for an index
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
		`TRUNCATE samples, sample_locations, sample_location_history, reports RESTART IDENTITY CASCADE`)
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
		SELECT `+pgSampleColsFeed+pgSampleColsRegistryExtra+` FROM samples
		WHERE ($1 = '' OR source = $1)
			AND ($2 = '' OR label = $2)
			AND cleave_result IS NOT NULL
			AND (coalesce(cardinality($3::text[]), 0) = 0 OR feed = ANY($3))
			AND (coalesce(cardinality($4::text[]), 0) = 0 OR ecosystem = ANY($4))
			AND (coalesce(cardinality($5::int[]), 0) = 0 OR `+q.feedClassExpr()+` = ANY($5))
			AND (NOT $6 OR (`+uncontainedSQL+`))
			AND ($7 = '' OR formula = $7)
			AND (NOT $8 OR litmus_result IS NOT NULL)
			AND (coalesce(cardinality($9::text[]), 0) = 0 OR domain = ANY($9))
			AND ($12 = '' OR filename ILIKE '%' || $12 || '%' ESCAPE '\'
				OR sha256 = $12 OR package = $16)
			AND (NOT $13 OR corroborated)
			AND ($14 = '' OR purl_base = $14)
			AND ($15 = '' OR version = $15)
			AND (($17 = '' AND $18 = '') OR EXISTS (
				SELECT 1 FROM asset_claims ac
				 WHERE ac.sha256 = samples.sha256
				   AND ($17 = '' OR ac.name = $17)
				   AND ($18 = '' OR ac.signer = $18)))
			AND file_type <> 'registry'
		ORDER BY `+q.sortBy()+`
		LIMIT $10 OFFSET $11`,
		q.Source, q.Label, q.Feeds, q.Ecosystems, q.LitmusClasses, q.TopLevelOnly,
		q.Formula, q.requireLitmus(), q.Domains, q.Limit, q.Offset,
		q.searchTerm(), q.Corroborated, q.PURLBase, q.PURLVersion, q.packageTerm(),
		q.ClaimName, q.ClaimSigner)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed samples: %w", err)
	}
	return scanPGSamplesFeed(rows)
}

// scanPGSamplesFeed is scanPGSamples plus the two feed-only registry scalars
// pgSampleColsRegistryExtra appends to the projection.
func scanPGSamplesFeed(rows pgx.Rows) ([]*Sample, error) {
	defer rows.Close()
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		if err := rows.Scan(append(pgSampleDest(s), &s.RegistryTitle, &s.RegistryDescription, &s.RegistryDownloads, &s.Corroborated)...); err != nil {
			return nil, err
		}
		s.restoreJSONB()
		out = append(out, s)
	}
	return out, rows.Err()
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
			AND (NOT $6 OR (`+uncontainedCountSQL+`))
			AND ($7 = '' OR formula = $7)
			AND (NOT $8 OR litmus_result IS NOT NULL)
			AND (coalesce(cardinality($9::text[]), 0) = 0 OR domain = ANY($9))
			AND ($10 = '' OR filename ILIKE '%' || $10 || '%' ESCAPE '\'
				OR sha256 = $10 OR package = $14)
			AND (NOT $11 OR corroborated)
			AND ($12 = '' OR purl_base = $12)
			AND ($13 = '' OR version = $13)
			AND (($15 = '' AND $16 = '') OR EXISTS (
				SELECT 1 FROM asset_claims ac
				 WHERE ac.sha256 = samples.sha256
				   AND ($15 = '' OR ac.name = $15)
				   AND ($16 = '' OR ac.signer = $16)))
			AND file_type <> 'registry'`,
		q.Source, q.Label, q.Feeds, q.Ecosystems, q.LitmusClasses, q.TopLevelOnly,
		q.Formula, q.requireLitmus(), q.Domains, q.searchTerm(), q.Corroborated,
		q.PURLBase, q.PURLVersion, q.packageTerm(), q.ClaimName, q.ClaimSigner).Scan(&n)
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
// bigArchiveCandidatesPG selects the largest unanalyzed samples above minBytes.
// A straight indexed scan (no random pivot) — big archives are rare, so the
// whole pending set is small and cheap to order by size.
func (db *DB) bigArchiveCandidatesPG(ctx context.Context, minBytes int64, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type
		FROM samples
		WHERE size_bytes > $1
		  AND cleave_result IS NULL AND skip = '' AND parent = ''
		  AND (note = '' OR last_error_at IS NULL OR last_error_at < $2)
		  AND attempts < $3
		ORDER BY size_bytes DESC
		LIMIT $4`,
		minBytes, hopperStart.UTC(), maxClaimAttempts, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: big archive candidates: %w", err)
	}
	return scanClaimRows(rows)
}

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
//
// It does not filter on `attempts` either, and must not: attempts counts every
// claim a sample has ever had and is never reset, so a sample rescanned
// maxClaimAttempts times over its life would become permanently unrescannable.
// The error-backoff guard below is what keeps a failing sample from looping —
// a row that errors out is parked until the next hopper restart, and once it
// has burned maxClaimAttempts claims ReapStuck marks it skip='stuck', which
// drops it from this tier for good.
func (db *DB) forcedRescanCandidatesPG(ctx context.Context, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE rescan_priority = 2
		  AND skip = '' AND parent = ''
		  AND (note = '' OR last_error_at IS NULL OR last_error_at < $1)
		ORDER BY rescan_requested_at ASC
		LIMIT $2`, hopperStart.UTC(), limit)
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
//
// path <> ” excludes rows whose bytes hopper cannot produce, the same rule
// [triageServablePathSQL] applies to the triage queues. Reference-only rows —
// registry sidecars, and fetched dependencies whose artifact never reached us —
// keep samples.path empty via [containmentColumns], and there is nothing on disk
// to serve and no containing archive to extract from. They are otherwise
// perfectly eligible here: parent = ” by design (a dependency is uncontained),
// and cleave_result is set, so this tier would hand a worker a claim it can
// never satisfy. Nor would anything clean up after it — reapStuck only reaps
// rows with cleave_result IS NULL, and the prune path only marks 'missing' when
// no sample_locations row survives, which these have. Measured 2026-08-23:
// ~47% of otherwise-eligible rows, ~94% of them registry sidecars.
func (db *DB) staleTraitsCandidatesPG(
	ctx context.Context, currentTraits string, rescanAge time.Duration,
	hopperStart time.Time, limit int,
) ([]ClaimJob, error) {
	if currentTraits == "" {
		return nil, nil
	}
	rows, err := db.pool.Query(ctx, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE cleave_result IS NOT NULL AND skip = '' AND parent = '' AND path <> ''
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
