package hopper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
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
	return pragmaHasColumnIn(ctx, db, "samples", column)
}

// pragmaHasColumnIn reports whether the named column exists on the given
// table. Uses pragma_table_xinfo (not table_info) so GENERATED columns are
// counted — without this, legacy ALTER TABLE ADD COLUMN migrations would
// fire duplicates against columns that already exist as generated.
func pragmaHasColumnIn(ctx context.Context, db *sql.DB, table, column string) int {
	var count int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM pragma_table_xinfo(?) WHERE name = ?", table, column,
	).Scan(&count); err != nil {
		slog.Debug("pragma_table_xinfo failed", "table", table, "column", column, "error", err)
		return 0
	}
	return count
}

func (db *DB) migrateSQLite(ctx context.Context) error { //nolint:gocognit,maintidx,revive // sequential migration steps; splitting reduces clarity
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
			// Drains itself as backfill completes: rows leave the index when elements
			// is populated. Without it, each batch's gating SELECT seq-scans the heap.
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

	// Add llm_result column.
	hasLLMResult := pragmaHasColumn(ctx, db.lite, "llm_result")
	if hasLLMResult == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN llm_result TEXT`); err != nil {
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
			`CREATE INDEX IF NOT EXISTS idx_samples_feed_top_created_done ` +
				`ON samples(source, label, created_at DESC) ` +
				`WHERE cleave_result IS NOT NULL AND parent = '' AND litmus_result IS NOT NULL`,
		} {
			slog.Debug("executing migration ddl", "ddl", ddl)
			if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite: %w", err)
			}
		}
	}

	if pragmaHasColumn(ctx, db.lite, "last_error_at") == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN last_error_at DATETIME`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}
	if pragmaHasColumn(ctx, db.lite, "first_analyzed_at") == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN first_analyzed_at DATETIME`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}
	// Poison-sample protection: claim-attempt counter and skip timestamp. No
	// dedicated index — the reaper's periodic "attempts >= N" sweep rides the
	// existing idx_samples_unanalyzed over the small pending set.
	if pragmaHasColumn(ctx, db.lite, "attempts") == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}
	if pragmaHasColumn(ctx, db.lite, "skipped_at") == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN skipped_at DATETIME`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
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
	for _, ddl := range []string{
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_top_created_done ` +
			`ON samples(source, label, created_at DESC) ` +
			`WHERE cleave_result IS NOT NULL AND parent = '' AND litmus_result IS NOT NULL`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
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

	// cyclotron_attempted_at: stamped when cyclotron seeds a sample, used to
	// gate FP/FN seed queries with a per-sample retry cooldown.
	if pragmaHasColumn(ctx, db.lite, "cyclotron_attempted_at") == 0 {
		if _, err := db.lite.ExecContext(ctx, `ALTER TABLE samples ADD COLUMN cyclotron_attempted_at DATETIME`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	// Rescan queue: rescan_priority (2 = interactive/ahead of new, 1 = bulk
	// repair/behind new, 0 = not queued) + rescan_requested_at (when queued, for
	// FIFO ordering). Supersedes the timestamp-only forced_rescan_at, which is
	// dropped without preserving its handful of pending rows. See the matching PG
	// migration for the full rationale.
	if pragmaHasColumn(ctx, db.lite, "rescan_priority") == 0 {
		if _, err := db.lite.ExecContext(ctx,
			`ALTER TABLE samples ADD COLUMN rescan_priority INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}
	if pragmaHasColumn(ctx, db.lite, "rescan_requested_at") == 0 {
		if _, err := db.lite.ExecContext(ctx,
			`ALTER TABLE samples ADD COLUMN rescan_requested_at DATETIME`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}
	if pragmaHasColumn(ctx, db.lite, "forced_rescan_at") == 1 {
		if _, err := db.lite.ExecContext(ctx,
			`ALTER TABLE samples DROP COLUMN forced_rescan_at`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}
	for _, ddl := range []string{
		`DROP INDEX IF EXISTS idx_samples_forced_rescan`,
		`CREATE INDEX IF NOT EXISTS idx_samples_rescan_queue ` +
			`ON samples(rescan_priority, rescan_requested_at) WHERE rescan_priority > 0`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}

	// Forager direct-insert provenance: url, domain (eTLD+1, populated by
	// Go via publicsuffix), name, version. See pg.go for rationale.
	for _, col := range []struct{ name, ddl string }{
		{"url", `ALTER TABLE samples ADD COLUMN url TEXT NOT NULL DEFAULT ''`},
		{"domain", `ALTER TABLE samples ADD COLUMN domain TEXT NOT NULL DEFAULT ''`},
		{"package", `ALTER TABLE samples ADD COLUMN package TEXT NOT NULL DEFAULT ''`},
		{"version", `ALTER TABLE samples ADD COLUMN version TEXT NOT NULL DEFAULT ''`},
		{"purl_base", `ALTER TABLE samples ADD COLUMN purl_base TEXT NOT NULL DEFAULT ''`},
		{"provenance", `ALTER TABLE samples ADD COLUMN provenance TEXT`},
		{"fetched_at", `ALTER TABLE samples ADD COLUMN fetched_at DATETIME`},
		// top_traits: JSON []TopTrait of the strongest suspicious+ trait ids,
		// written by the Go result-store paths (ParseCleaveResult). Defaults
		// to '' — pre-existing dev/test rows simply have no headline traits.
		{"top_traits", `ALTER TABLE samples ADD COLUMN top_traits TEXT NOT NULL DEFAULT ''`},
	} {
		if pragmaHasColumn(ctx, db.lite, col.name) == 0 {
			if _, err := db.lite.ExecContext(ctx, col.ddl); err != nil {
				return fmt.Errorf("hopper: migrate sqlite samples.%s: %w", col.name, err)
			}
		}
	}
	for _, ddl := range []string{
		`CREATE INDEX IF NOT EXISTS idx_samples_domain ON samples(domain) WHERE domain != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_package_version ON samples(package, version) WHERE package != ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_purl_base ON samples(purl_base) WHERE purl_base != ''`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite samples index: %w", err)
		}
	}

	// External-corroboration flag + ledger (see schema.sql). SQLite mirror of the
	// PG migration: the boolean is an INTEGER 0/1 column, maintained by
	// AddSightings, and drives the feed's corroborated-only filter.
	if pragmaHasColumn(ctx, db.lite, "corroborated") == 0 {
		if _, err := db.lite.ExecContext(ctx,
			`ALTER TABLE samples ADD COLUMN corroborated INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite samples.corroborated: %w", err)
		}
	}
	for _, ddl := range []string{
		`CREATE INDEX IF NOT EXISTS idx_samples_corroborated ` +
			`ON samples(created_at) ` +
			`WHERE corroborated = 1 AND parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS sightings (
			source     TEXT NOT NULL,
			subject    TEXT NOT NULL,
			url        TEXT NOT NULL DEFAULT '',
			note       TEXT NOT NULL DEFAULT '',
			first_seen DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
			PRIMARY KEY (source, subject)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sightings_subject ON sightings(subject)`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite sightings: %w", err)
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
		// benignReview / badReview
		`CREATE INDEX IF NOT EXISTS idx_samples_misclassified_review ` +
			`ON samples(label, max_crit, suspicious_count) ` +
			`WHERE label_source = 'marker' AND skip = 'misclassified' ` +
			`AND cleave_result IS NOT NULL AND status = ''`,
		// conflictReview
		// CountAnalyzed
		`CREATE INDEX IF NOT EXISTS idx_samples_litmus_done ` +
			`ON samples(id) WHERE litmus_result IS NOT NULL`,
		// CountPending / claimable ordering
		`DROP INDEX IF EXISTS idx_samples_claimable`,
		`CREATE INDEX IF NOT EXISTS idx_samples_claimable ` +
			`ON samples(updated_at, id) ` +
			`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_claimable_sha ` +
			`ON samples(sha256) ` +
			`WHERE cleave_result IS NULL AND skip = '' AND parent = ''`,
		// NewestAnalyzedAt
		`CREATE INDEX IF NOT EXISTS idx_samples_analyzed_at ` +
			`ON samples(analyzed_at) WHERE analyzed_at IS NOT NULL`,
		// Workflow dashboard freshness and backlog grouping.
		`CREATE INDEX IF NOT EXISTS idx_samples_top_created ` +
			`ON samples(created_at DESC, id) WHERE parent = ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_top_ready_created ` +
			`ON samples(created_at DESC, id) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_top_ready_first_analyzed_coalesce ` +
			`ON samples(COALESCE(first_analyzed_at, analyzed_at) DESC, id) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL AND COALESCE(first_analyzed_at, analyzed_at) IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_pending_cleave_group ` +
			`ON samples(source, feed, ecosystem, updated_at) ` +
			`WHERE parent = '' AND skip = '' AND cleave_result IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_samples_pending_litmus_group ` +
			`ON samples(source, feed, ecosystem, updated_at) ` +
			`WHERE parent = '' AND skip = '' AND cleave_result IS NOT NULL AND litmus_result IS NULL`,
		// Claim state moved to memory; no longer reading these columns.
		`DROP INDEX IF EXISTS idx_samples_claimed`,
		`UPDATE samples SET skip = 'skip-benign-archive-item' WHERE skip = 'weak-findings'`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite index: %w", err)
		}
	}

	// sample_locations: one row per (sha256, path) observation. See the
	// pg.go equivalent for rationale — both backends use the same schema.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS sample_locations (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			sha256        TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
			path          TEXT NOT NULL CHECK (path <> ''),
			parent_sha256 TEXT NOT NULL DEFAULT '',
			rel           TEXT NOT NULL DEFAULT '',
			filename      TEXT NOT NULL DEFAULT '',
			source        TEXT NOT NULL DEFAULT '',
			feed          TEXT NOT NULL DEFAULT '',
			ecosystem     TEXT NOT NULL DEFAULT '',
			mtime         DATETIME,
			first_seen_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
			last_seen_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
			UNIQUE (sha256, path)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sl_sha256 ON sample_locations(sha256)`,
		`CREATE INDEX IF NOT EXISTS idx_sl_parent ON sample_locations(parent_sha256) WHERE parent_sha256 <> ''`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite sample_locations: %w", err)
		}
	}
	// rel: edge type to parent_sha256 ("" contained, "fetched", "unpacked",
	// "registry") — added after the table shipped, so existing DBs need the
	// column grafted on (SQLite has no ADD COLUMN IF NOT EXISTS).
	if pragmaHasColumnIn(ctx, db.lite, "sample_locations", "rel") == 0 {
		if _, err := db.lite.ExecContext(ctx,
			`ALTER TABLE sample_locations ADD COLUMN rel TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite sample_locations rel: %w", err)
		}
	}
	// One-shot backfill, gated on emptiness.
	var locCount int
	if err := db.lite.QueryRowContext(ctx, `SELECT count(*) FROM sample_locations`).Scan(&locCount); err != nil {
		return fmt.Errorf("hopper: count sample_locations: %w", err)
	}
	if locCount == 0 {
		if _, err := db.lite.ExecContext(ctx, `
			INSERT INTO sample_locations
				(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at)
			SELECT sha256, path, parent, filename, source, feed, ecosystem, mtime, created_at, updated_at
			  FROM samples WHERE path <> ''
			ON CONFLICT (sha256, path) DO NOTHING`); err != nil {
			return fmt.Errorf("hopper: backfill sample_locations: %w", err)
		}
	}

	// Internal key/value store. Used for the upload-token bootstrap (prism
	// reads it to discover the bearer token for /api/upload).
	if _, err := db.lite.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS hopper_kv (
		key        TEXT PRIMARY KEY,
		value      TEXT NOT NULL,
		updated_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return fmt.Errorf("hopper: migrate sqlite hopper_kv: %w", err)
	}

	// label_events: append-only audit of every label/skip transition applied
	// by pool reconciliation. Lets a data scientist reconstruct a sample's
	// ground-truth at a point in time and audit demote/conflict/missing
	// decisions; never read on the hot path.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS label_events (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			sha256      TEXT NOT NULL,
			from_label  TEXT NOT NULL DEFAULT '',
			to_label    TEXT NOT NULL DEFAULT '',
			from_skip   TEXT NOT NULL DEFAULT '',
			to_skip     TEXT NOT NULL DEFAULT '',
			reason      TEXT NOT NULL,
			observed_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_label_events_sha ON label_events(sha256, observed_at)`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite label_events: %w", err)
		}
	}

	// walk_staging holds (sha256, path) for every standalone file seen in the
	// current walk; reconciliation anti-joins it against samples. See the pg.go
	// equivalent. SQLite has no UNLOGGED tables, but this DB is the local cache
	// (not the durable store), so a plain table is fine.
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS walk_staging (
			sha256 TEXT NOT NULL,
			path   TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_samples_reconcile_toplevel ON samples(sha256)
			WHERE parent = '' AND (skip = '' OR skip = 'conflict')`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite walk_staging: %w", err)
		}
	}

	// One-time, chunked, resumable backfill of archive member edges; a non-fatal
	// failure just resumes on the next boot rather than blocking startup.
	if err := db.reconcileLocationParentEdges(ctx); err != nil {
		slog.Warn("sample_locations parent-edge backfill incomplete; will resume on next boot", "error", err)
	}
	// After the edge backfill, which is what its predicate reads: a row whose
	// edges have not been backfilled yet would look parentless and be repaired
	// on no evidence.
	if err := db.repairReferenceParents(ctx); err != nil {
		slog.Warn("reference-parent repair incomplete; will resume on next boot", "error", err)
	}

	return nil
}

const liteSampleCols = `id, sha256, source, feed, ecosystem,
	filename, file_type, size_bytes, label, label_source,
	cleave_result, litmus_result, llm_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip,
	formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime,
	traits_version,
	url, domain, package, version, purl_base,
	COALESCE(top_traits, '') AS top_traits`

// liteSampleColsLight excludes cleave_result and litmus_result to avoid
// loading large JSON blobs when only metadata is needed.
const liteSampleColsLight = `id, sha256, source, feed, ecosystem,
	filename, file_type, size_bytes, label, label_source,
	litmus_score,
	path, status, note, canonical_sha256, parent, skip,
	formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime,
	traits_version,
	url, domain, package, version, purl_base,
	COALESCE(top_traits, '') AS top_traits`

// liteSampleColsFeed is the SQLite counterpart of pgSampleColsFeed: liteSampleCols
// with cleave_result — the one blob the feed never renders — replaced by a NULL
// literal so the projection stays positionally identical and scanLiteSamples
// reads it unchanged. litmus_result stays for the row's criticality, and the
// small llm_result stays for the row's rationale. Keeps the two backends' feed
// contract identical (a feed row carries no cleave_result).
const liteSampleColsFeed = `id, sha256, source, feed, ecosystem,
	filename, file_type, size_bytes, label, label_source,
	NULL AS cleave_result, litmus_result, llm_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip,
	formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime,
	traits_version,
	url, domain, package, version, purl_base,
	COALESCE(top_traits, '') AS top_traits`

// liteSampleColsRegistryExtra is the SQLite counterpart of pgSampleColsRegistryExtra:
// the marketplace title, capped short description, and install count from the
// provenance sidecar's registry record, read by scanLiteSamplesFeed.
const liteSampleColsRegistryExtra = `,
	COALESCE(json_extract(provenance, '$.registry.record.title'), '') AS registry_title,
	COALESCE(substr(json_extract(provenance, '$.registry.record.description'), 1, 300), '') AS registry_description,
	COALESCE(json_extract(provenance, '$.registry.record.downloads_total'), 0) AS registry_downloads,
	corroborated`

func scanLiteSamplesLight(rows *sql.Rows) ([]*Sample, error) {
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		var status sql.NullString
		var analyzedAt, firstAnalyzedAt, lastErrorAt, mtime, markerMtime sql.NullTime
		if err := rows.Scan(
			&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
			&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.LitmusScore,
			&s.Path, &status, &s.Note, &s.CanonicalSHA256,
			&s.Parent, &s.Skip, &s.Formula, &s.Elements,
			&s.Score, &s.MaxCrit, &s.SuspiciousCount,
			&s.CreatedAt, &s.UpdatedAt, &analyzedAt, &firstAnalyzedAt, &lastErrorAt, &mtime, &markerMtime,
			&s.TraitsVersion,
			&s.URL, &s.Domain, &s.Package, &s.Version, &s.PURLBase,
			&s.TopTraits,
		); err != nil {
			return nil, err
		}
		s.Status = status.String
		if analyzedAt.Valid {
			s.AnalyzedAt = &analyzedAt.Time
		}
		if firstAnalyzedAt.Valid {
			s.FirstAnalyzedAt = &firstAnalyzedAt.Time
		}
		if lastErrorAt.Valid {
			s.LastErrorAt = &lastErrorAt.Time
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

func (db *DB) workflowHealthSQLite(ctx context.Context) (WorkflowHealth, error) {
	var h WorkflowHealth
	var latestAdded, latestUpdated, latestAnalyzed, latestReady sqliteNullTime
	err := db.lite.QueryRowContext(ctx, `
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
	h.LatestAdded = nullTime(latestAdded.NullTime)
	h.LatestUpdated = nullTime(latestUpdated.NullTime)
	h.LatestAnalyzed = nullTime(latestAnalyzed.NullTime)
	h.LatestReady = nullTime(latestReady.NullTime)
	return h, nil
}

func (db *DB) workflowBacklogsSQLite(ctx context.Context, limit int) ([]WorkflowBacklog, error) {
	rows, err := db.lite.QueryContext(ctx, `
		SELECT source, feed, ecosystem,
			min(updated_at), max(updated_at),
			sum(pending_cleave), sum(pending_litmus)
		FROM (
			SELECT source, feed, ecosystem, updated_at,
				1 AS pending_cleave,
				0 AS pending_litmus
			FROM samples
			WHERE parent = '' AND skip = '' AND cleave_result IS NULL
			UNION ALL
			SELECT source, feed, ecosystem, updated_at,
				0 AS pending_cleave,
				1 AS pending_litmus
			FROM samples
			WHERE parent = '' AND skip = ''
			  AND cleave_result IS NOT NULL AND litmus_result IS NULL
		) pending
		GROUP BY source, feed, ecosystem
		ORDER BY (sum(pending_cleave) + sum(pending_litmus)) DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: workflow backlogs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
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

func (db *DB) workflowLatestAddedSQLite(ctx context.Context, limit int) ([]WorkflowSample, error) {
	return db.workflowSamplesSQLite(ctx, `WHERE parent = '' ORDER BY created_at DESC LIMIT ?`, limit)
}

func (db *DB) workflowLatestReadySQLite(ctx context.Context, limit int) ([]WorkflowSample, error) {
	return db.workflowSamplesSQLite(ctx,
		`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL `+
			`AND COALESCE(first_analyzed_at, analyzed_at) IS NOT NULL `+
			`ORDER BY COALESCE(first_analyzed_at, analyzed_at) DESC, id LIMIT ?`, limit)
}

func (db *DB) workflowOldestPendingSQLite(ctx context.Context, limit int) ([]WorkflowSample, error) {
	return db.workflowSamplesSQLite(ctx,
		`WHERE parent = '' AND cleave_result IS NULL AND skip = '' ORDER BY updated_at ASC, id LIMIT ?`, limit)
}

func (db *DB) workflowSamplesSQLite(ctx context.Context, where string, limit int) ([]WorkflowSample, error) {
	rows, err := db.lite.QueryContext(ctx, fmt.Sprintf(`
		SELECT sha256, source, feed, ecosystem, filename, path,
			created_at, updated_at, analyzed_at, COALESCE(first_analyzed_at, analyzed_at),
			cleave_result IS NOT NULL,
			litmus_result IS NOT NULL,
			-- Criticality (0=benign, 1=suspicious, 2=hostile): legacy records
			-- carried 'class' directly; v6/v7 use 'lvl'/'l' (the strictest
			-- grid level at which the file fires, or -1 for never-fires).
			-- Try class first; otherwise derive from the level using CriticalLevel %d
			-- as the hostile/suspicious cutoff (null means manual-mode
			-- hostile and is treated as hostile fail-safe).
			COALESCE(
				CAST(json_extract(litmus_result, '$.class') AS INTEGER),
				CASE
					WHEN litmus_result IS NULL THEN 0
					WHEN COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) IS NULL THEN 2
					WHEN CAST(COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) AS INTEGER) < 0 THEN 0
					WHEN CAST(COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) AS INTEGER) <= %d THEN 2
					WHEN CAST(COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) AS INTEGER) <= %d THEN 1
					ELSE 0
				END
			)
		FROM samples `+where, CriticalLevel, CriticalLevel, SuspiciousCeiling), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: workflow samples: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	out := make([]WorkflowSample, 0, limit)
	for rows.Next() {
		var s WorkflowSample
		var analyzed, firstAnalyzed sqliteNullTime
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

// scanLiteSample reads one full sample row plus the registry extras — its only
// caller (sampleBySHA256SQLite) selects liteSampleCols + liteSampleColsRegistryExtra.
func scanLiteSample(row *sql.Row) (*Sample, error) {
	s := &Sample{}
	var cleaveResult, litmusResult, llmResult, status sql.NullString
	var analyzedAt, firstAnalyzedAt, lastErrorAt, mtime, markerMtime sql.NullTime
	err := row.Scan(
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult, &llmResult, &s.LitmusScore,
		&s.Path, &status, &s.Note, &s.CanonicalSHA256, &s.Parent, &s.Skip, &s.Formula,
		&s.Elements, &s.Score, &s.MaxCrit, &s.SuspiciousCount,
		&s.CreatedAt, &s.UpdatedAt, &analyzedAt, &firstAnalyzedAt, &lastErrorAt, &mtime, &markerMtime,
		&s.TraitsVersion,
		&s.URL, &s.Domain, &s.Package, &s.Version, &s.PURLBase,
		&s.TopTraits,
		&s.RegistryTitle, &s.RegistryDescription, &s.RegistryDownloads, &s.Corroborated,
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
	if llmResult.Valid {
		s.LLMResult = []byte(llmResult.String)
	}
	s.Status = status.String
	if analyzedAt.Valid {
		s.AnalyzedAt = &analyzedAt.Time
	}
	if firstAnalyzedAt.Valid {
		s.FirstAnalyzedAt = &firstAnalyzedAt.Time
	}
	if lastErrorAt.Valid {
		s.LastErrorAt = &lastErrorAt.Time
	}
	if mtime.Valid {
		s.Mtime = &mtime.Time
	}
	if markerMtime.Valid {
		s.MarkerMtime = &markerMtime.Time
	}
	s.restoreJSONB()
	return s, nil
}

func scanLiteSamples(rows *sql.Rows) ([]*Sample, error) {
	return scanLiteSamplesExtra(rows, nil)
}

// scanLiteSamplesFeed is scanLiteSamples plus the two feed-only registry
// scalars liteSampleColsRegistryExtra appends to the projection.
func scanLiteSamplesFeed(rows *sql.Rows) ([]*Sample, error) {
	return scanLiteSamplesExtra(rows, func(s *Sample) []any {
		return []any{&s.RegistryTitle, &s.RegistryDescription, &s.RegistryDownloads, &s.Corroborated}
	})
}

// scanLiteSamplesExtra reads sample rows, appending extra(s)'s destinations to
// the scan list for projections that select columns beyond liteSampleCols.
func scanLiteSamplesExtra(rows *sql.Rows, extra func(*Sample) []any) ([]*Sample, error) {
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		var cleaveResult, litmusResult, llmResult, status sql.NullString
		var analyzedAt, firstAnalyzedAt, lastErrorAt, mtime, markerMtime sql.NullTime
		dest := []any{
			&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
			&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult, &llmResult, &s.LitmusScore,
			&s.Path, &status, &s.Note, &s.CanonicalSHA256,
			&s.Parent, &s.Skip, &s.Formula, &s.Elements,
			&s.Score, &s.MaxCrit, &s.SuspiciousCount,
			&s.CreatedAt, &s.UpdatedAt, &analyzedAt, &firstAnalyzedAt, &lastErrorAt, &mtime, &markerMtime,
			&s.TraitsVersion,
			&s.URL, &s.Domain, &s.Package, &s.Version, &s.PURLBase,
			&s.TopTraits,
		}
		if extra != nil {
			dest = append(dest, extra(s)...)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		if cleaveResult.Valid {
			s.CleaveResult = []byte(cleaveResult.String)
		}
		if litmusResult.Valid {
			s.LitmusResult = []byte(litmusResult.String)
		}
		if llmResult.Valid {
			s.LLMResult = []byte(llmResult.String)
		}
		s.Status = status.String
		if analyzedAt.Valid {
			s.AnalyzedAt = &analyzedAt.Time
		}
		if firstAnalyzedAt.Valid {
			s.FirstAnalyzedAt = &firstAnalyzedAt.Time
		}
		if lastErrorAt.Valid {
			s.LastErrorAt = &lastErrorAt.Time
		}
		if mtime.Valid {
			s.Mtime = &mtime.Time
		}
		if markerMtime.Valid {
			s.MarkerMtime = &markerMtime.Time
		}
		s.restoreJSONB()
		out = append(out, s)
	}
	return out, rows.Err()
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

type sqliteNullTime struct {
	sql.NullTime
}

func (t *sqliteNullTime) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		t.Valid = false
		t.Time = time.Time{}
		return nil
	case time.Time:
		t.Time = v
		t.Valid = true
		return nil
	case string:
		return t.scanString(v)
	case []byte:
		return t.scanString(string(v))
	default:
		return fmt.Errorf("unsupported sqlite time value %T", value)
	}
}

func (t *sqliteNullTime) scanString(s string) error {
	if s == "" {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		parsed, err := time.Parse(layout, s)
		if err == nil {
			t.Time = parsed
			t.Valid = true
			return nil
		}
	}
	return fmt.Errorf("parse sqlite time %q", s)
}

func nullableErrorTime(note string) any {
	if note == "" {
		return nil
	}
	return now()
}

// jsonTextOrNil returns b as a string for storage in a SQLite TEXT column,
// or nil (→ SQL NULL) when empty. SQLite's driver treats []byte as a blob;
// go-sqlite3 stores "" as an empty blob too, which round-trips oddly for
// JSON columns. Explicit NULL when we have no value keeps the column
// consistent with the "unanalyzed" sentinel state.
func jsonTextOrNil(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// sampleConflictUpdateSQLite is the shared ON CONFLICT clause for top-level
// re-observations, used by both the single-row (insertSampleNewSQLite) and
// batch (insertSampleBatchSQLite) upserts so their resolution can't drift. It
// is the SQLite twin of sampleConflictUpdatePG; see that constant for the
// rule-by-rule explanation of the pool-precedence label resolution.
var sampleConflictUpdateSQLite = `ON CONFLICT (sha256) DO UPDATE SET
	label = CASE
		WHEN excluded.label_source = 'marker' THEN excluded.label
		WHEN samples.label_source = 'marker' THEN excluded.label
		WHEN (samples.label = 'good' AND excluded.label = 'bad')
		  OR (samples.label = 'bad' AND excluded.label = 'good') THEN 'bad'
		WHEN ` + labelRankSQL("excluded.label") + `
		   > ` + labelRankSQL("samples.label") + ` THEN excluded.label
		ELSE samples.label
	END,
	label_source = CASE
		WHEN excluded.label_source = 'marker' THEN 'marker'
		WHEN samples.label_source = 'marker' THEN excluded.label_source
		WHEN (samples.label = 'good' AND excluded.label = 'bad')
		  OR (samples.label = 'bad' AND excluded.label = 'good') THEN 'conflict'
		WHEN ` + labelRankSQL("excluded.label") + `
		   > ` + labelRankSQL("samples.label") + ` THEN excluded.label_source
		ELSE samples.label_source
	END,
	feed  = CASE WHEN excluded.feed  != '' THEN excluded.feed  ELSE samples.feed  END,
	ecosystem = CASE WHEN excluded.ecosystem != '' THEN excluded.ecosystem ELSE samples.ecosystem END,
	path  = CASE WHEN excluded.path  != ''   THEN excluded.path  ELSE samples.path  END,
	-- Track filename with path (SQLite twin of the PG clause): a relocation that
	-- moves the bytes also renames the display name, so a stale sha-named
	-- filename heals to the current on-disk / sidecar-recorded name.
	filename = CASE WHEN excluded.path != '' THEN excluded.filename ELSE samples.filename END,
	mtime = CASE WHEN excluded.mtime IS NOT NULL THEN excluded.mtime ELSE samples.mtime END,
	url     = CASE WHEN samples.url     = '' THEN excluded.url     ELSE samples.url     END,
	domain  = CASE WHEN samples.domain  = '' THEN excluded.domain  ELSE samples.domain  END,
	package    = CASE WHEN samples.package    = '' THEN excluded.package    ELSE samples.package    END,
	version = CASE WHEN samples.version = '' THEN excluded.version ELSE samples.version END,
	purl_base = CASE WHEN samples.purl_base = '' THEN excluded.purl_base ELSE samples.purl_base END,
	-- Capture-time provenance is written once by the collector's direct-insert;
	-- a later walk carries none, so keep whatever is already there.
	provenance = CASE WHEN samples.provenance IS NOT NULL THEN samples.provenance ELSE excluded.provenance END,
	fetched_at = CASE WHEN samples.fetched_at IS NOT NULL THEN samples.fetched_at ELSE excluded.fetched_at END,
	-- Label-related skips ('misclassified'/'conflict') track the resolution;
	-- the walker also clears 'missing'/'unsupported'. Hard skips stick.
	skip  = CASE
		WHEN excluded.label_source = 'marker' THEN 'misclassified'
		WHEN samples.label_source = 'marker' AND samples.skip = 'misclassified' THEN ''
		WHEN ((samples.label = 'good' AND excluded.label = 'bad')
		   OR (samples.label = 'bad' AND excluded.label = 'good'))
		  AND samples.skip IN ('', 'misclassified', 'conflict', 'missing', 'unsupported') THEN 'conflict'
		WHEN ` + labelRankSQL("excluded.label") + `
		   > ` + labelRankSQL("samples.label") + `
		  AND samples.skip IN ('misclassified', 'conflict') THEN ''
		WHEN samples.skip IN ('missing','unsupported') THEN ''
		ELSE samples.skip
	END
WHERE excluded.parent = ''
  AND ((excluded.path  != ''   AND samples.path  != excluded.path)
    OR (excluded.mtime IS NOT NULL AND samples.mtime IS NOT excluded.mtime)
    OR (excluded.feed != '' AND samples.feed != excluded.feed)
    OR (excluded.ecosystem != '' AND samples.ecosystem != excluded.ecosystem)
    OR (samples.url = '' AND excluded.url != '')
    OR (samples.package = '' AND excluded.package != '')
    OR (samples.purl_base = '' AND excluded.purl_base != '')
    OR samples.skip IN ('missing','unsupported')
    -- Pool-precedence transitions must fire even when path/mtime are unchanged.
    OR (` + labelRankSQL("excluded.label") + `
      > ` + labelRankSQL("samples.label") + `)
    OR ((samples.label = 'good' AND excluded.label = 'bad')
      OR (samples.label = 'bad' AND excluded.label = 'good'))
    OR (excluded.label_source = 'marker'
        AND (samples.label != excluded.label OR samples.label_source != 'marker' OR samples.skip != 'misclassified'))
    OR (samples.label_source = 'marker' AND excluded.label_source != 'marker'))`

func (db *DB) insertSampleNewSQLite(ctx context.Context, s *Sample) (bool, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("hopper: begin insert: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback
	// The samples row records the artifact; the locations row below records this
	// observation of it. parent/path are containment claims and belong only to
	// the former — see containmentColumns.
	samplesParent, samplesPath := containmentColumns(s)
	// file_type, score, formula, litmus_score are GENERATED STORED columns
	// (SQLite 3.31+). They auto-derive from cleave_result / litmus_result
	// so writing to them is neither necessary nor legal.
	//nolint:gosec // G202: the appended conflict clause is fixed internal SQL; all sample values remain parameterized
	res, err := tx.ExecContext(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename,
			size_bytes, label, label_source, path, status,
			canonical_sha256, parent, skip, elements,
			max_crit, suspicious_count, top_traits, mtime, marker_mtime,
			cleave_result, litmus_result,
			url, domain, package, version, provenance, fetched_at, purl_base)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`+sampleConflictUpdateSQLite,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
		s.SizeBytes, s.Label, s.LabelSource, samplesPath, s.Status,
		s.SHA256, samplesParent, s.Skip, s.Elements,
		s.MaxCrit, s.SuspiciousCount, s.TopTraits, s.Mtime, s.MarkerMtime,
		jsonTextOrNil(s.CleaveResult), jsonTextOrNil(s.LitmusResult),
		s.URL, s.Domain, s.Package, s.Version, jsonTextOrNil(s.Provenance), s.FetchedAt, s.PURLBase)
	if err != nil {
		return false, fmt.Errorf("hopper: insert sample: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("hopper: rows affected: %w", err)
	}
	if n == 0 && s.MarkerMtime != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE samples SET marker_mtime = ? WHERE sha256 = ?`, s.MarkerMtime, s.SHA256); err != nil {
			return false, fmt.Errorf("hopper: refresh marker mtime: %w", err)
		}
	}
	if s.Path != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sample_locations
				(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256, path) DO UPDATE SET
				rel = CASE WHEN excluded.rel != '' THEN excluded.rel ELSE sample_locations.rel END,
				source = CASE WHEN excluded.source != '' THEN excluded.source ELSE sample_locations.source END,
				feed = CASE WHEN excluded.feed != '' THEN excluded.feed ELSE sample_locations.feed END,
				ecosystem = CASE WHEN excluded.ecosystem != '' THEN excluded.ecosystem ELSE sample_locations.ecosystem END,
				mtime = COALESCE(excluded.mtime, sample_locations.mtime)`+locationChangedSQLite,
			s.SHA256, s.Path, s.Parent, s.LocationRel, s.Filename, s.Source, s.Feed, s.Ecosystem, s.Mtime); err != nil {
			return false, fmt.Errorf("hopper: upsert location: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("hopper: commit insert: %w", err)
	}
	return n > 0, nil
}

// logLabelTransitionsSQLite logs each top-level re-observation in the batch
// whose label resolution will change under sampleConflictUpdateSQLite. It reads
// the pre-upsert state inside the same transaction so the comparison is
// accurate. Best-effort: a query error is logged and ignored rather than
// failing the batch, since the upsert is authoritative.
func logLabelTransitionsSQLite(ctx context.Context, tx *sql.Tx, samples []*Sample) {
	incoming := make(map[string]*Sample, len(samples))
	shas := make([]string, 0, len(samples))
	for _, s := range samples {
		if s.Parent != "" || s.SHA256 == "" {
			continue
		}
		if _, ok := incoming[s.SHA256]; ok {
			continue
		}
		incoming[s.SHA256] = s
		shas = append(shas, s.SHA256)
	}
	const chunk = 500 // stay under SQLite's default bind-variable limit
	for start := 0; start < len(shas); start += chunk {
		if err := logLabelTransitionChunkSQLite(ctx, tx, shas[start:min(start+chunk, len(shas))], incoming); err != nil {
			slog.Warn("label transition log failed", "error", err)
			return
		}
	}
}

func logLabelTransitionChunkSQLite(ctx context.Context, tx *sql.Tx, shas []string, incoming map[string]*Sample) error {
	placeholders := make([]string, len(shas))
	args := make([]any, len(shas))
	for i, sha := range shas {
		placeholders[i] = "?"
		args[i] = sha
	}
	//nolint:gosec // placeholders are '?' bind markers; sha values are parameterized via args.
	q := `SELECT sha256, label, label_source, skip FROM samples WHERE parent = '' AND sha256 IN (` +
		strings.Join(placeholders, ",") + `)`
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	for rows.Next() {
		var sha, sLabel, sSrc, sSkip string
		if err := rows.Scan(&sha, &sLabel, &sSrc, &sSkip); err != nil {
			return err
		}
		if s, ok := incoming[sha]; ok {
			logLabelTransition(sha, s.Path, sLabel, sSrc, sSkip, s.Label, s.LabelSource)
		}
	}
	return rows.Err()
}

func (db *DB) insertSampleBatchSQLite(ctx context.Context, samples []*Sample) (inserted int64, needsAnalysis []string, err error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: begin batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is best-effort after commit // commit or rollback

	cols := []string{
		"sha256", "source", "feed", "ecosystem", "filename",
		"size_bytes", "label", "label_source", "path", "status", "canonical_sha256",
		"parent", "skip", "elements", "max_crit", "suspicious_count",
		"mtime", "marker_mtime", "cleave_result", "litmus_result", "analyzed_at", "first_analyzed_at",
		"url", "domain", "package", "version", "provenance", "fetched_at",
	}
	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = "?"
	}

	query := fmt.Sprintf(
		`
		INSERT INTO samples (%s)
		VALUES (%s)
		`+sampleConflictUpdateSQLite,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "))

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: prepare batch: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // best-effort cleanup

	locStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256, path) DO UPDATE SET
			rel = CASE WHEN excluded.rel != '' THEN excluded.rel ELSE sample_locations.rel END,
			source = CASE WHEN excluded.source != '' THEN excluded.source ELSE sample_locations.source END,
			feed = CASE WHEN excluded.feed != '' THEN excluded.feed ELSE sample_locations.feed END,
			ecosystem = CASE WHEN excluded.ecosystem != '' THEN excluded.ecosystem ELSE sample_locations.ecosystem END,
			mtime = COALESCE(excluded.mtime, sample_locations.mtime)`+locationChangedSQLite)
	if err != nil {
		return 0, nil, fmt.Errorf("hopper: prepare location upsert: %w", err)
	}
	defer locStmt.Close() //nolint:errcheck // best-effort cleanup

	logLabelTransitionsSQLite(ctx, tx, samples)

	for _, s := range samples {
		firstAnalyzedAt := s.FirstAnalyzedAt
		if firstAnalyzedAt == nil {
			firstAnalyzedAt = s.AnalyzedAt
		}
		samplesParent, samplesPath := containmentColumns(s)
		res, err := stmt.ExecContext(ctx,
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
			s.SizeBytes, s.Label, s.LabelSource, samplesPath, s.Status,
			s.SHA256, samplesParent, s.Skip, s.Elements,
			s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
			jsonTextOrNil(s.CleaveResult), jsonTextOrNil(s.LitmusResult), s.AnalyzedAt, firstAnalyzedAt,
			s.URL, s.Domain, s.Package, s.Version, jsonTextOrNil(s.Provenance), s.FetchedAt)
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
		if s.Path != "" {
			if _, err := locStmt.ExecContext(ctx,
				s.SHA256, s.Path, s.Parent, s.LocationRel, s.Filename, s.Source, s.Feed, s.Ecosystem, s.Mtime); err != nil {
				return 0, nil, fmt.Errorf("hopper: upsert location %s: %w", s.SHA256, err)
			}
		}
	}

	// Mark stale rows whose path now belongs to a different SHA256.
	// This happens when a file is replaced on disk — the walk inserts a
	// new row for the new content but the old row lingers in the queue
	// and can never be analyzed because the original bytes are gone.
	for _, s := range samples {
		if s.Path == "" {
			continue
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE samples SET skip = 'replaced'
			WHERE path = ? AND sha256 != ? AND skip = '' AND cleave_result IS NULL`,
			s.Path, s.SHA256)
		if err != nil {
			return 0, nil, fmt.Errorf("hopper: mark replaced %s: %w", s.SHA256, err)
		}
		if n, err := res.RowsAffected(); err == nil && n > 0 {
			slog.Info("marked replaced sample", "path", s.Path, "new_sha256", s.SHA256, "replaced", n)
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

// refreshStaleMemberAnalysisSQLite is the SQLite twin of
// refreshStaleMemberAnalysisPG: per-row UPDATEs in one transaction, gated so
// only strictly-newer analysis overwrites and litmus is never blanked. Times
// bind as *time.Time exactly as the batch insert stores them, so the analyzed_at
// comparison matches the stored serialization.
func (db *DB) refreshStaleMemberAnalysisSQLite(ctx context.Context, rows []staleRefresh) (int64, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin refresh: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort after commit
	stmt, err := tx.PrepareContext(ctx, `
		UPDATE samples SET
			cleave_result = ?,
			litmus_result = COALESCE(?, litmus_result),
			analyzed_at   = ?
		WHERE sha256 = ?
		  AND (analyzed_at IS NULL OR ? > analyzed_at)`)
	if err != nil {
		return 0, fmt.Errorf("hopper: prepare refresh: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // best-effort cleanup
	var refreshed int64
	for _, r := range rows {
		res, err := stmt.ExecContext(ctx,
			jsonTextOrNil(r.CleaveResult), jsonTextOrNil(r.LitmusResult),
			r.AnalyzedAt, r.SHA256, r.AnalyzedAt)
		if err != nil {
			return 0, fmt.Errorf("hopper: refresh %s: %w", r.SHA256, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			refreshed += n
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hopper: commit refresh: %w", err)
	}
	return refreshed, nil
}

func (db *DB) sampleBySHA256SQLite(ctx context.Context, sha256 string) (*Sample, error) {
	s, err := scanLiteSample(db.lite.QueryRowContext(ctx,
		`SELECT `+liteSampleCols+liteSampleColsRegistryExtra+` FROM samples WHERE sha256 = ?`, sha256))
	if err != nil {
		return nil, fmt.Errorf("hopper: sample %s: %w", sha256, err)
	}
	return s, nil
}

func (db *DB) membersByParentSQLite(ctx context.Context, parentSHA string, limit int) ([]ArchiveMember, int, error) {
	var total int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT count(*) FROM sample_locations WHERE parent_sha256 = ?`, parentSHA).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("hopper: count members by parent %s: %w", parentSHA, err)
	}
	if total == 0 {
		return nil, 0, nil
	}
	rows, err := db.lite.QueryContext(ctx, `
		SELECT s.sha256, sl.path, s.file_type, s.score, s.max_crit
		  FROM sample_locations sl
		  JOIN samples s ON s.sha256 = sl.sha256
		 WHERE sl.parent_sha256 = ?
		 ORDER BY s.score DESC, s.max_crit DESC, sl.path
		 LIMIT ?`, parentSHA, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("hopper: members by parent %s: %w", parentSHA, err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
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

func (db *DB) samplesBySHAsSQLite(ctx context.Context, shas []string) ([]*Sample, error) {
	placeholders := make([]string, len(shas))
	args := make([]any, len(shas))
	for i, s := range shas {
		placeholders[i] = "?"
		args[i] = s
	}
	//nolint:gosec // placeholders are '?' bind markers; sha values are parameterized via args.
	q := `SELECT ` + liteSampleCols + ` FROM samples WHERE sha256 IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := db.lite.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by shas: %w", err)
	}
	return scanLiteSamples(rows)
}

// topMemberSHAsByParentSQLite mirrors topMemberSHAsByParentPG.
func (db *DB) topMemberSHAsByParentSQLite(ctx context.Context, parentSHA string, limit int) ([]string, error) {
	rows, err := db.lite.QueryContext(ctx, `
		SELECT s.sha256
		  FROM sample_locations sl
		  JOIN samples s ON s.sha256 = sl.sha256
		 WHERE sl.parent_sha256 = ?
		 ORDER BY s.score DESC, s.max_crit DESC, sl.path
		 LIMIT ?`, parentSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: top member shas by parent %s: %w", parentSHA, err)
	}
	return scanLiteStrings(rows)
}

// parentArchivesForChildSQLite mirrors parentArchivesForChildPG. SQLite has no
// DISTINCT ON, so it leans on the single-max()-per-group rule: with one MAX() in
// the result the bare columns come from the row holding that max — i.e. each
// parent's most-recent location.
func (db *DB) parentArchivesForChildSQLite(ctx context.Context, childSHA string, limit int) ([]ParentRef, error) {
	// Limit before the join (see parentArchivesForChildPG): the top-N distinct
	// parents come from sample_locations alone; samples is joined for only those N.
	rows, err := db.lite.QueryContext(ctx, `
		SELECT s.sha256, s.filename, s.path, tp.loc_path, tp.rel, s.feed, s.ecosystem, s.version, s.package, s.litmus_result, s.analyzed_at, tp.lsa
		  FROM (
		    SELECT parent_sha256, path AS loc_path, rel, MAX(last_seen_at) AS lsa
		      FROM sample_locations
		     WHERE sha256 = ? AND parent_sha256 <> ''
		     GROUP BY parent_sha256
		     ORDER BY lsa DESC
		     LIMIT ?
		  ) tp
		  JOIN samples s ON s.sha256 = tp.parent_sha256
		 ORDER BY tp.lsa DESC`, childSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: parent archives for child %s: %w", childSHA, err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []ParentRef
	for rows.Next() {
		var p ParentRef
		var litmus sql.NullString
		var analyzedAt sql.NullTime
		var lsa sql.NullString // ordering key only; never returned
		if err := rows.Scan(&p.SHA256, &p.Filename, &p.SamplePath, &p.Path, &p.Rel, &p.Feed, &p.Ecosystem, &p.Version, &p.Package, &litmus, &analyzedAt, &lsa); err != nil {
			return nil, err
		}
		if litmus.Valid {
			p.LitmusResult = []byte(litmus.String)
		}
		if analyzedAt.Valid {
			t := analyzedAt.Time
			p.AnalyzedAt = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (db *DB) badMembersByParentSQLite(ctx context.Context, parentSHA string) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		  WHERE label = 'bad'
		    AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = ?)
		  ORDER BY path`, parentSHA)
	if err != nil {
		return nil, fmt.Errorf("hopper: bad members by parent %s: %w", parentSHA, err)
	}
	return scanLiteSamples(rows)
}

// repairReferenceParentsSQLite mirrors repairReferenceParentsPG: driven from the
// ledger's reference edges, one short autocommit statement per window so the
// whole-DB write lock is taken briefly and released between chunks.
func (db *DB) repairReferenceParentsSQLite(ctx context.Context, cursor int64) error {
	var repaired, windows int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Keyset pagination over the reference edges; see the PG twin for why the
		// id space cannot be stepped in fixed strides. SQLite takes two
		// statements — no data-modifying CTE — but each is short and autocommits,
		// so the whole-DB write lock is held only for the update.
		var next sql.NullInt64
		if err := db.lite.QueryRowContext(ctx, `
			SELECT max(id) FROM (
			  SELECT id FROM sample_locations
			   WHERE id > ? AND parent_sha256 <> '' AND rel NOT IN `+containmentRelsSQL+`
			   ORDER BY id LIMIT ?)`,
			cursor, referenceParentRepairBatch).Scan(&next); err != nil {
			return fmt.Errorf("hopper: repair reference parents: window from %d: %w", cursor, err)
		}
		if !next.Valid {
			break // no reference edges past the cursor; done
		}
		//nolint:gosec // G202: all interpolated SQL fragments are fixed internal constants, not input values
		res, err := db.lite.ExecContext(ctx, `
			UPDATE samples
			   SET parent = '',
			       path = CASE WHEN path LIKE '%!!%' THEN '' ELSE path END,
			       label = 'unknown', label_source = ''
			 WHERE sha256 IN (
			       SELECT sha256 FROM sample_locations
			        WHERE id > ? AND id <= ?
			          AND parent_sha256 <> '' AND rel NOT IN `+containmentRelsSQL+`)
			   AND `+referenceParentPredicate("samples"), cursor, next.Int64)
		if err != nil {
			return fmt.Errorf("hopper: repair reference parents: window (%d,%d]: %w", cursor, next.Int64, err)
		}
		if n, aerr := res.RowsAffected(); aerr == nil {
			repaired += n
		}
		windows++
		cursor = next.Int64
		if _, err := db.lite.ExecContext(ctx,
			`INSERT INTO hopper_kv (key, value) VALUES (?, ?)
			 ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			referenceParentRepairCurKey, strconv.FormatInt(cursor, 10)); err != nil {
			return fmt.Errorf("hopper: repair reference parents: save cursor: %w", err)
		}
	}
	if _, err := db.lite.ExecContext(ctx,
		`INSERT INTO hopper_kv (key, value) VALUES (?, 'done')
		 ON CONFLICT (key) DO UPDATE SET value = 'done'`,
		referenceParentRepairDoneKey); err != nil {
		return fmt.Errorf("hopper: repair reference parents: done marker: %w", err)
	}
	slog.Info("reference-parent repair complete", "repaired", repaired, "windows", windows)
	return nil
}

func (db *DB) reconcileLocationParentEdgesSQLite(ctx context.Context, cursor int64) error {
	var maxID int64
	if err := db.lite.QueryRowContext(ctx,
		`SELECT COALESCE(max(id), 0) FROM samples WHERE parent <> ''`).Scan(&maxID); err != nil {
		return fmt.Errorf("hopper: backfill locations: bounds: %w", err)
	}
	for cursor < maxID {
		if err := ctx.Err(); err != nil {
			return err
		}
		hi := cursor + locationParentBackfillBatch
		// Short autocommit statement per id window. SQLite takes a brief
		// whole-DB write lock per chunk and releases it between chunks, so the
		// backfill never blocks the cache for long.
		if _, err := db.lite.ExecContext(ctx, `
			INSERT INTO sample_locations
				(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at)
			SELECT sha256, path, parent, filename, source, feed, ecosystem, mtime, created_at, updated_at
			  FROM samples
			 WHERE id > ? AND id <= ? AND parent <> '' AND path <> ''
			ON CONFLICT (sha256, path) DO NOTHING`, cursor, hi); err != nil {
			return fmt.Errorf("hopper: backfill locations: chunk (%d,%d]: %w", cursor, hi, err)
		}
		cursor = hi
		if _, err := db.lite.ExecContext(ctx,
			`INSERT INTO hopper_kv (key, value) VALUES (?, ?)
			 ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			locationParentBackfillCurKey, strconv.FormatInt(cursor, 10)); err != nil {
			return fmt.Errorf("hopper: backfill locations: save cursor: %w", err)
		}
	}
	if _, err := db.lite.ExecContext(ctx,
		`INSERT INTO hopper_kv (key, value) VALUES (?, 'done')
		 ON CONFLICT (key) DO UPDATE SET value = 'done'`,
		locationParentBackfillDoneKey); err != nil {
		return fmt.Errorf("hopper: backfill locations: done marker: %w", err)
	}
	slog.Info("sample_locations parent-edge backfill complete", "max_id", maxID)
	return nil
}

const liteLocationCols = `id, sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at`

func scanLiteLocation(row interface{ Scan(...any) error }) (*SampleLocation, error) {
	var loc SampleLocation
	if err := row.Scan(&loc.ID, &loc.SHA256, &loc.Path, &loc.ParentSHA256, &loc.Rel,
		&loc.Filename, &loc.Source, &loc.Feed, &loc.Ecosystem,
		&loc.Mtime, &loc.FirstSeenAt, &loc.LastSeenAt); err != nil {
		return nil, err
	}
	return &loc, nil
}

// locationChangedSQLite mirrors locationChangedPG: it makes re-observing an
// unchanged location a no-op instead of a row rewrite. SQLite's `IS NOT` is the
// null-safe inequality, i.e. Postgres's IS DISTINCT FROM. Keep the predicate
// aligned with the SET list it guards. locationChangedRelMtimeSQLite is the
// narrower form for the two sites that only refresh rel and mtime.
const (
	locationChangedSQLite = `
		WHERE (excluded.rel != ''       AND excluded.rel       IS NOT sample_locations.rel)
		   OR (excluded.source != ''    AND excluded.source    IS NOT sample_locations.source)
		   OR (excluded.feed != ''      AND excluded.feed      IS NOT sample_locations.feed)
		   OR (excluded.ecosystem != '' AND excluded.ecosystem IS NOT sample_locations.ecosystem)
		   OR (excluded.mtime IS NOT NULL AND excluded.mtime IS NOT sample_locations.mtime)`

	locationChangedRelMtimeSQLite = `
		WHERE (excluded.rel != '' AND excluded.rel IS NOT sample_locations.rel)
		   OR (excluded.mtime IS NOT NULL AND excluded.mtime IS NOT sample_locations.mtime)`
)

func (db *DB) upsertLocationSQLite(ctx context.Context, loc *SampleLocation) error {
	_, err := db.lite.ExecContext(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256, path) DO UPDATE SET
			rel = CASE WHEN excluded.rel != '' THEN excluded.rel ELSE sample_locations.rel END,
			mtime = COALESCE(excluded.mtime, sample_locations.mtime)`+locationChangedRelMtimeSQLite,
		loc.SHA256, loc.Path, loc.ParentSHA256, loc.Rel, loc.Filename,
		loc.Source, loc.Feed, loc.Ecosystem, loc.Mtime)
	if err != nil {
		return fmt.Errorf("hopper: upsert location %s: %w", loc.SHA256, err)
	}
	return nil
}

// upsertLocationBatchSQLite applies the single-row upsert to every location in
// one transaction — SQLite has no unnest, and one write lock beats one per row.
func (db *DB) upsertLocationBatchSQLite(ctx context.Context, locs []*SampleLocation) error {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("hopper: begin location batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback
	const q = `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256, path) DO UPDATE SET
			rel = CASE WHEN excluded.rel != '' THEN excluded.rel ELSE sample_locations.rel END,
			source = CASE WHEN excluded.source != '' THEN excluded.source ELSE sample_locations.source END,
			feed = CASE WHEN excluded.feed != '' THEN excluded.feed ELSE sample_locations.feed END,
			ecosystem = CASE WHEN excluded.ecosystem != '' THEN excluded.ecosystem ELSE sample_locations.ecosystem END,
			mtime = COALESCE(excluded.mtime, sample_locations.mtime)` + locationChangedSQLite
	for _, l := range locs {
		if _, err := tx.ExecContext(ctx, q, l.SHA256, l.Path, l.ParentSHA256, l.Rel,
			l.Filename, l.Source, l.Feed, l.Ecosystem, l.Mtime); err != nil {
			return fmt.Errorf("hopper: upsert location %s: %w", l.SHA256, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hopper: commit location batch: %w", err)
	}
	return nil
}

func (db *DB) locationsForSHASQLite(ctx context.Context, sha256 string) ([]*SampleLocation, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteLocationCols+` FROM sample_locations WHERE sha256 = ? ORDER BY last_seen_at DESC`, sha256)
	if err != nil {
		return nil, fmt.Errorf("hopper: locations %s: %w", sha256, err)
	}
	defer rows.Close() //nolint:errcheck // read-only query
	var out []*SampleLocation
	for rows.Next() {
		loc, err := scanLiteLocation(rows)
		if err != nil {
			return nil, fmt.Errorf("hopper: scan location: %w", err)
		}
		out = append(out, loc)
	}
	return out, rows.Err()
}

// pruneVictim names a sample_locations row that should be deleted.
type pruneVictim struct {
	path   string
	sha256 string
	id     int64
}

// pruneMissingLocationsSQLite stats every top-level sample_locations path under
// absRoot and deletes the row when the file is gone (ENOENT). Archive members
// (parent_sha256 set) are skipped: they have no standalone file, so statting
// them would mark every member missing. Paths are stored relative to the data
// root; an absolute path is still accepted (prunePathResolve keeps both within
// absRoot). A sample left with no surviving location is marked skip='missing'
// in the same transaction, which a later walk auto-reverts to ” if the bytes
// reappear. Refuses to delete more than maxFraction of the rows it scanned,
// returning *PruneSafetyExceeded. Returns the count of rows deleted.
func (db *DB) pruneMissingLocationsSQLite(ctx context.Context, absRoot string, maxFraction float64) (int, error) {
	rows, err := db.lite.QueryContext(ctx, `
		SELECT id, sha256, path FROM sample_locations
		WHERE (parent_sha256 IS NULL OR parent_sha256 = '')
		  AND (path NOT LIKE '/%' OR path LIKE ?)`, absRoot+"/%")
	if err != nil {
		return 0, fmt.Errorf("hopper: scan locations for prune: %w", err)
	}
	var victims []pruneVictim
	total := 0
	for rows.Next() {
		var v pruneVictim
		if err := rows.Scan(&v.id, &v.sha256, &v.path); err != nil {
			rows.Close() //nolint:errcheck,sqlclosecheck,gosec // best-effort cleanup before error return
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
	rows.Close() //nolint:errcheck,gosec // best-effort cleanup
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if total > 0 && float64(len(victims))/float64(total) > maxFraction {
		return 0, &PruneSafetyExceeded{Total: total, Victims: len(victims), MaxFraction: maxFraction}
	}
	if len(victims) == 0 {
		return 0, nil
	}

	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin prune: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback
	for _, v := range victims {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sample_locations WHERE id = ?`, v.id); err != nil {
			return 0, fmt.Errorf("hopper: delete location %d: %w", v.id, err)
		}
	}
	if err := markPrunedSamplesMissingSQLite(ctx, tx, distinctVictimSHAs(victims)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hopper: commit prune: %w", err)
	}
	return len(victims), nil
}

// markPrunedSamplesMissingSQLite flags any top-level sample among shas that has
// no surviving location as skip='missing', recording a label_event for each.
// Hard/label skips are left untouched (only skip=” is promoted), so a manual
// marker or a conflict resolution is never clobbered. Mirrors the archive-member
// cascade-missing in reconcile; a re-observed file flips skip back to ” via the
// samples upsert conflict clause.
func markPrunedSamplesMissingSQLite(ctx context.Context, tx *sql.Tx, shas []string) error {
	ts := now()
	const chunk = 400 // stay under SQLite's default bind-variable limit
	var marked int64
	for start := 0; start < len(shas); start += chunk {
		batch := shas[start:min(start+chunk, len(shas))]
		ph := strings.Repeat(",?", len(batch))[1:]
		args := make([]any, 0, len(batch)+1)
		args = append(args, ts)
		for _, sha := range batch {
			args = append(args, sha)
		}
		//nolint:gosec // ph is a run of '?' bind markers; sha values are parameterized.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
			SELECT sha256, label, label, skip, 'missing', 'prune-missing', ?
			FROM samples
			WHERE parent = '' AND skip = '' AND sha256 IN (`+ph+`)
			  AND NOT EXISTS (SELECT 1 FROM sample_locations sl WHERE sl.sha256 = samples.sha256)`, args...); err != nil {
			return fmt.Errorf("hopper: prune missing audit: %w", err)
		}
		//nolint:gosec // ph is a run of '?' bind markers; sha values are parameterized.
		res, err := tx.ExecContext(ctx, `
			UPDATE samples SET skip = 'missing', updated_at = ?
			WHERE parent = '' AND skip = '' AND sha256 IN (`+ph+`)
			  AND NOT EXISTS (SELECT 1 FROM sample_locations sl WHERE sl.sha256 = samples.sha256)`, args...)
		if err != nil {
			return fmt.Errorf("hopper: prune mark missing: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil {
			marked += n
		}
	}
	if marked > 0 {
		slog.Info("prune marked samples missing (no surviving location)", "count", marked)
	}
	return nil
}

func (db *DB) promoteLabelByPURLSQLite(ctx context.Context, purlBase, version, incLabel, incSource, feed string) (PURLPromotion, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return PURLPromotion{}, fmt.Errorf("hopper: begin promote: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback

	rows, err := tx.QueryContext(ctx,
		`SELECT sha256, label, label_source, skip FROM samples WHERE purl_base = ? AND version = ? AND parent = ''`,
		purlBase, version)
	if err != nil {
		return PURLPromotion{}, fmt.Errorf("hopper: scan purl candidates: %w", err)
	}
	var cands []purlCandidate
	present := false
	for rows.Next() {
		var c purlCandidate
		if err := rows.Scan(&c.sha, &c.label, &c.source, &c.skip); err != nil {
			rows.Close() //nolint:errcheck,sqlclosecheck,gosec // best-effort cleanup before error return
			return PURLPromotion{}, fmt.Errorf("hopper: scan purl candidate: %w", err)
		}
		if c.skip != "missing" {
			present = true
		}
		cands = append(cands, c)
	}
	rows.Close() //nolint:errcheck,gosec // best-effort cleanup
	if err := rows.Err(); err != nil {
		return PURLPromotion{}, err
	}

	ts := now()
	promoted := 0
	for _, c := range cands {
		r := resolveIncomingLabel(c.label, c.source, c.skip, incLabel, incSource)
		if !r.changed {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
			VALUES (?, ?, ?, ?, ?, 'purl-promote', ?)`,
			c.sha, c.label, r.label, c.skip, r.skip, ts); err != nil {
			return PURLPromotion{}, fmt.Errorf("hopper: promote audit: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE samples
			SET label = ?, label_source = ?, skip = ?,
				feed = CASE WHEN ? != '' THEN ? ELSE feed END,
				updated_at = ?
			WHERE sha256 = ?`,
			r.label, r.labelSource, r.skip, feed, feed, ts, c.sha); err != nil {
			return PURLPromotion{}, fmt.Errorf("hopper: promote update: %w", err)
		}
		promoted++
	}
	if err := tx.Commit(); err != nil {
		return PURLPromotion{}, fmt.Errorf("hopper: commit promote: %w", err)
	}
	return PURLPromotion{Present: present, Promoted: promoted}, nil
}

func (db *DB) updateCleaveResultSQLite(
	ctx context.Context, sha256 string, result []byte, canonical string,
	fi cleaveFileInfo, traitsVersion string,
) error {
	// file_type, score, formula, litmus_score are GENERATED columns;
	// setting litmus_result = NULL auto-resets litmus_score to 0.
	n := now()
	// The rescan queue fields clear here so the row drops out once fresh
	// analysis lands.
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET cleave_result = ?,
			canonical_sha256 = ?, elements = ?,
			max_crit = ?, suspicious_count = ?, top_traits = ?,
			litmus_result = NULL,
			note = '', last_error_at = NULL,
			traits_version = ?,
			rescan_priority = 0, rescan_requested_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, ?),
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`,
		string(result), canonical, fi.Elements,
		fi.MaxCrit, fi.SuspiciousCount, fi.TopTraits,
		traitsVersion, n, n, n, sha256)
	if err != nil {
		return fmt.Errorf("hopper: update cleave result: %w", err)
	}
	return nil
}

// storeResultSQLite is the SQLite twin of storeResultPG: parent analysis and all
// archive members written in one transaction. Per-row member upserts (SQLite has
// no COPY); the member conflict clause touches only analysis columns and only
// when strictly newer, mirroring memberConflictUpdatePG.
func (db *DB) storeResultSQLite(
	ctx context.Context, sha256 string, cleaveRaw, litmusML, llm []byte,
	p CleaveParseResult, traitsVersion string, now time.Time,
) (StoreStats, error) {
	truncated := compactCleaveResultForStorage(cleaveRaw)
	nowStr := now.UTC().Format(time.RFC3339Nano)

	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return StoreStats{}, fmt.Errorf("hopper: begin store: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback

	var parent Sample
	var firstAnalyzed sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT label, label_source, source, feed, ecosystem, path, first_analyzed_at
		   FROM samples WHERE sha256 = ?`, sha256).
		Scan(&parent.Label, &parent.LabelSource, &parent.Source, &parent.Feed,
			&parent.Ecosystem, &parent.Path, &firstAnalyzed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return StoreStats{}, fmt.Errorf("hopper: store result for absent sample %s: %w", sha256, ErrNotFound)
		}
		return StoreStats{}, fmt.Errorf("hopper: read parent for store %s: %w", sha256, err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE samples SET cleave_result = ?,
			canonical_sha256 = ?, elements = ?,
			max_crit = ?, suspicious_count = ?, top_traits = ?,
			litmus_result = ?, llm_result = ?,
			note = '', last_error_at = NULL,
			traits_version = ?, rescan_priority = 0, rescan_requested_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, ?),
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`,
		string(truncated), p.CanonicalSHA, p.FileInfo.Elements,
		p.FileInfo.MaxCrit, p.FileInfo.SuspiciousCount, p.FileInfo.TopTraits,
		jsonTextOrNil(litmusML), jsonTextOrNil(llm),
		traitsVersion, nowStr, nowStr, nowStr, sha256); err != nil {
		return StoreStats{}, fmt.Errorf("hopper: update parent: %w", err)
	}

	parent.SHA256 = sha256
	parent.CleaveResult = cleaveRaw
	parent.LitmusResult = litmusML
	parent.CanonicalSHA256 = p.CanonicalSHA
	parent.AnalyzedAt = &now
	if firstAnalyzed.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, firstAnalyzed.String); perr == nil {
			parent.FirstAnalyzedAt = &t
		}
	}
	if parent.FirstAnalyzedAt == nil {
		parent.FirstAnalyzedAt = &now
	}
	members := memberSamplesFromEnvelope(&parent)
	for _, m := range members {
		normalizeLabel(m) // "" is not a selectable label; see normalizeLabel.
	}

	var stats StoreStats
	stats.Members = len(members)
	if len(members) > 0 {
		memStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO samples (sha256, source, feed, ecosystem, filename,
				size_bytes, label, label_source, path, status, canonical_sha256,
				parent, skip, elements, max_crit, suspicious_count, mtime, marker_mtime,
				cleave_result, litmus_result, analyzed_at, first_analyzed_at,
				url, domain, package, version, provenance, fetched_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (sha256) DO UPDATE SET
				cleave_result = excluded.cleave_result,
				litmus_result = COALESCE(excluded.litmus_result, samples.litmus_result),
				analyzed_at = excluded.analyzed_at,
				first_analyzed_at = COALESCE(samples.first_analyzed_at, excluded.first_analyzed_at),
				updated_at = ?
			WHERE excluded.analyzed_at > samples.analyzed_at OR samples.analyzed_at IS NULL`)
		if err != nil {
			return StoreStats{}, fmt.Errorf("hopper: prepare member upsert: %w", err)
		}
		defer memStmt.Close() //nolint:errcheck // best-effort cleanup
		locStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO sample_locations
				(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem, mtime)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (sha256, path) DO UPDATE SET
				rel = CASE WHEN excluded.rel != '' THEN excluded.rel ELSE sample_locations.rel END,
				mtime = COALESCE(excluded.mtime, sample_locations.mtime)`+locationChangedRelMtimeSQLite)
		if err != nil {
			return StoreStats{}, fmt.Errorf("hopper: prepare member location: %w", err)
		}
		defer locStmt.Close() //nolint:errcheck // best-effort cleanup

		for _, m := range members {
			firstAt := m.FirstAnalyzedAt
			if firstAt == nil {
				firstAt = m.AnalyzedAt
			}
			res, err := memStmt.ExecContext(ctx,
				m.SHA256, m.Source, m.Feed, m.Ecosystem, m.Filename,
				m.SizeBytes, m.Label, m.LabelSource, m.Path, m.Status, m.SHA256,
				m.Parent, m.Skip, m.Elements, m.MaxCrit, m.SuspiciousCount, m.Mtime, m.MarkerMtime,
				jsonTextOrNil(m.CleaveResult), jsonTextOrNil(m.LitmusResult), m.AnalyzedAt, firstAt,
				m.URL, m.Domain, m.Package, m.Version, jsonTextOrNil(m.Provenance), m.FetchedAt,
				nowStr)
			if err != nil {
				return StoreStats{}, fmt.Errorf("hopper: upsert member %s: %w", m.SHA256, err)
			}
			if affected, err := res.RowsAffected(); err == nil {
				stats.MembersStored += affected
			}
			if m.Path != "" {
				if _, err := locStmt.ExecContext(ctx,
					m.SHA256, m.Path, m.Parent, m.LocationRel, m.Filename, m.Source, m.Feed, m.Ecosystem, m.Mtime); err != nil {
					return StoreStats{}, fmt.Errorf("hopper: upsert member location %s: %w", m.SHA256, err)
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return StoreStats{}, fmt.Errorf("hopper: commit store: %w", err)
	}
	return stats, nil
}

// requestRescanSQLite mirrors requestRescanPG. SQLite is used for tests
// and small-scale deployments; the production schema runs on Postgres.
// cooldownCutoff is formatted to RFC3339Nano so the predicate compares
// text-against-text — analyzed_at is stored as a TEXT column by the
// migration, so a raw time.Time would format differently and never match.
func (db *DB) requestRescanSQLite(ctx context.Context, sha256 string, cooldownCutoff time.Time) error {
	n := now()
	cutoff := cooldownCutoff.UTC().Format(time.RFC3339Nano)
	res, err := db.lite.ExecContext(ctx, `
		UPDATE samples
		SET rescan_priority = 2,
		    rescan_requested_at = COALESCE(rescan_requested_at, ?),
		    updated_at = ?
		WHERE sha256 = ? AND parent = '' AND skip = ''
		  AND (rescan_priority > 0
		       OR analyzed_at IS NULL
		       OR analyzed_at < ?)`,
		n, n, sha256, cutoff)
	if err != nil {
		return fmt.Errorf("hopper: request rescan: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("hopper: request rescan: rows affected: %w", err)
	}
	if rows == 0 {
		return ErrRescanNotEligible
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

func (db *DB) updateLLMResultSQLite(ctx context.Context, sha256 string, result []byte) error {
	// Store NULL rather than an empty string when no interpretation ran, so the
	// column is absent exactly when the pass was.
	var val any
	if len(result) > 0 {
		val = string(result)
	}
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET llm_result = ?, updated_at = ?
		WHERE sha256 = ?`, val, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: update llm result: %w", err)
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

func (db *DB) cascadeLabelSQLite(ctx context.Context, sha256, label, source string) (int, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin cascade: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback

	if _, err := tx.ExecContext(ctx,
		`UPDATE samples SET label = ?, label_source = ?, updated_at = ? WHERE sha256 = ?`,
		label, source, now(), sha256); err != nil {
		return 0, fmt.Errorf("hopper: cascade parent: %w", err)
	}
	children, err := cascadeMembersForParentSQLite(ctx, tx, sha256, label, source, false)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hopper: commit cascade: %w", err)
	}
	return children, nil
}

// cascadeMembersForParentSQLite is the SQLite counterpart of
// cascadeMembersForParentPG: it applies the member cascade for an archive
// already labeled `label`, without touching the parent row. dryRun counts
// without writing.
func cascadeMembersForParentSQLite(ctx context.Context, tx *sql.Tx, parent, label, source string, dryRun bool) (int, error) {
	// Member-selection queries mirror cascadeMembersForParentPG. The trailing ?
	// binds the parent SHA256; earlier ? bind the extra args passed alongside.
	const promoteMembers = `SELECT sha256, label FROM samples
		WHERE label IN ('unknown', 'sighted')
		  AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = ?)`
	const revertMembers = `SELECT sha256, label FROM samples
		WHERE label = 'bad' AND label_source = ?
		  AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = ?)`
	const demoteMembers = `SELECT sha256, label FROM samples
		WHERE label IN ('unknown', 'sighted') AND score >= ?
		  AND sha256 IN (SELECT sha256 FROM sample_locations WHERE parent_sha256 = ?)`

	children := 0
	switch label {
	case labelGood:
		n, err := cascadeMembersSQLite(ctx, tx, promoteMembers, []any{parent}, labelGood, source, "cascade-promote", dryRun)
		if err != nil {
			return 0, err
		}
		children += n
		n, err = cascadeMembersSQLite(ctx, tx, revertMembers, []any{cascadeSource(parent), parent}, labelGood, source, "cascade-revert", dryRun)
		if err != nil {
			return 0, err
		}
		children += n
	case labelBad:
		n, err := cascadeMembersSQLite(ctx, tx, demoteMembers, []any{CascadeDemoteScore, parent},
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

// cascadeMembersSQLite is the SQLite counterpart of cascadeMembersPG: query
// selects sha256, label and binds args; matched members are relabeled to
// toLabel/toSource with each transition recorded in label_events under reason.
// dryRun returns the eligible count without writing.
func cascadeMembersSQLite(ctx context.Context, tx *sql.Tx, query string, args []any, toLabel, toSource, reason string, dryRun bool) (int, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("hopper: cascade scan members: %w", err)
	}
	type change struct{ sha, from string }
	var changes []change
	for rows.Next() {
		var c change
		if err := rows.Scan(&c.sha, &c.from); err != nil {
			rows.Close() //nolint:errcheck,sqlclosecheck,gosec // best-effort cleanup before error return
			return 0, fmt.Errorf("hopper: cascade scan member: %w", err)
		}
		changes = append(changes, c)
	}
	rows.Close() //nolint:errcheck,gosec // best-effort cleanup
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if dryRun {
		return len(changes), nil
	}
	ts := now()
	applied := 0
	for _, c := range changes {
		// Compare-and-set on the scanned label (see cascadeMembersPG).
		res, err := tx.ExecContext(ctx, `
			UPDATE samples SET label = ?, label_source = ?, updated_at = ? WHERE sha256 = ? AND label = ?`,
			toLabel, toSource, ts, c.sha, c.from)
		if err != nil {
			return 0, fmt.Errorf("hopper: cascade member: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("hopper: cascade member rows: %w", err)
		}
		if n == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
			VALUES (?, ?, ?, '', '', ?, ?)`,
			c.sha, c.from, toLabel, reason, ts); err != nil {
			return 0, fmt.Errorf("hopper: cascade audit: %w", err)
		}
		applied++
	}
	return applied, nil
}

// cascadeBackfillPendingSQLite is the SQLite counterpart of
// cascadeBackfillPendingPG.
func (db *DB) cascadeBackfillPendingSQLite(ctx context.Context) (bool, error) {
	var pending bool
	err := db.lite.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM samples p
			JOIN sample_locations l ON l.parent_sha256 = p.sha256
			JOIN samples m ON m.sha256 = l.sha256
			WHERE p.parent = '' AND m.label IN ('unknown', 'sighted')
			  AND (p.label = 'good' OR (p.label = 'bad' AND m.score >= ?))
		)`, CascadeDemoteScore).Scan(&pending)
	if err != nil {
		return false, fmt.Errorf("hopper: cascade backfill pending: %w", err)
	}
	return pending, nil
}

// cascadeBackfillSQLite is the SQLite counterpart of cascadeBackfillPG.
func (db *DB) cascadeBackfillSQLite(ctx context.Context, dryRun bool) (CascadeBackfillStats, error) {
	// See cascadeBackfillPG for why selection is eligibility-aware.
	const badArchives = `
		SELECT sha256, label_source FROM samples s
		WHERE parent = '' AND label = 'bad'
		  AND EXISTS (
			SELECT 1 FROM sample_locations l JOIN samples m ON m.sha256 = l.sha256
			WHERE l.parent_sha256 = s.sha256 AND m.label IN ('unknown', 'sighted') AND m.score >= ?)
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
		rows, err := db.lite.QueryContext(ctx, query, args...)
		if err != nil {
			return st, fmt.Errorf("hopper: backfill scan archives: %w", err)
		}
		type archive struct{ sha, source string }
		var archives []archive
		for rows.Next() {
			var a archive
			if err := rows.Scan(&a.sha, &a.source); err != nil {
				rows.Close() //nolint:errcheck,sqlclosecheck,gosec // best-effort cleanup before error return
				return st, fmt.Errorf("hopper: backfill scan archive: %w", err)
			}
			archives = append(archives, a)
		}
		rows.Close() //nolint:errcheck,gosec // best-effort cleanup
		if err := rows.Err(); err != nil {
			return st, err
		}

		slog.Info("cascade backfill pass starting", "label", label, "archives", len(archives), "dry_run", dryRun)
		passMembers := 0
		for i, a := range archives {
			tx, err := db.lite.BeginTx(ctx, nil)
			if err != nil {
				return st, fmt.Errorf("hopper: backfill begin: %w", err)
			}
			n, err := cascadeMembersForParentSQLite(ctx, tx, a.sha, label, a.source, dryRun)
			if err != nil {
				tx.Rollback() //nolint:errcheck,gosec // returning the prior error
				return st, err
			}
			if dryRun {
				tx.Rollback() //nolint:errcheck,gosec // dry-run: discard
			} else if err := tx.Commit(); err != nil {
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

func (db *DB) relocateSampleSQLite(ctx context.Context, sha256, oldRel, newRel, label, source string) error {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("hopper: relocate begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback
	ts := now()
	// Audit the label transition before applying it (see relocateSamplePG).
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, label, ?, skip, '', 'triage', ?
		FROM samples WHERE sha256 = ? AND label <> ?`, label, ts, sha256, label); err != nil {
		return fmt.Errorf("hopper: relocate audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE samples
		   SET label = ?, label_source = ?, path = ?,
		       skip = '', skipped_at = ?, updated_at = ?
		 WHERE sha256 = ?`, label, source, newRel, ts, ts, sha256); err != nil {
		return fmt.Errorf("hopper: relocate sample: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE sample_locations SET path = ?
		 WHERE sha256 = ? AND path = ? AND parent_sha256 = ''`, newRel, sha256, oldRel); err != nil {
		return fmt.Errorf("hopper: relocate location: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hopper: relocate commit: %w", err)
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

func (db *DB) candidatesByLabelSQLite(
	ctx context.Context, label, pathPrefix string, olderThan time.Time, afterSHA string, limit int,
) ([]*Sample, error) {
	// Timestamps are stored as RFC3339Nano text and compare lexicographically
	// (matching staleSamplesSQLite); mtime is written in the same format. GLOB is
	// case-sensitive and uses the path index for a prefix match.
	threshold := olderThan.UTC().Format(time.RFC3339Nano)
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = ? AND parent = '' AND skip = ''
		   AND path GLOB ? || '*'
		   AND mtime IS NOT NULL AND mtime < ?
		   AND sha256 > ?
		 ORDER BY sha256 LIMIT ?`,
		label, pathPrefix, threshold, afterSHA, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: candidates by label: %w", err)
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
		UPDATE samples SET note = ?, last_error_at = ?, updated_at = ? WHERE sha256 = ?`,
		note, nullableErrorTime(note), now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: set note: %w", err)
	}
	return nil
}

func (db *DB) setStatusSQLite(ctx context.Context, sha256, status string) error {
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET status = ?, note = '', last_error_at = NULL, updated_at = ? WHERE sha256 = ?`,
		status, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: set status: %w", err)
	}
	return nil
}

// SQLite sorts NULLs as smallest, so DESC NULLS LAST needs an explicit guard:
// `litmus_score IS NULL` puts NULLs at the end of a DESC sort.
const (
	liteStageOrder = `ORDER BY litmus_score IS NULL, litmus_score DESC, score DESC, updated_at ASC`
	liteSeedOrder  = `ORDER BY litmus_score IS NULL, litmus_score DESC, score DESC, analyzed_at ASC`
)

func liteSeedFreshnessCutoff() string {
	return seedFreshnessCutoff().Format(time.RFC3339Nano)
}

func (db *DB) samplesInPipelineStageSQLite(ctx context.Context, status string, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE status = ? `+liteStageOrder+` LIMIT ?`,
		status, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples in pipeline stage: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) samplesInPipelineStageLightSQLite(ctx context.Context, status string, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleColsLight+` FROM samples WHERE status = ? `+liteStageOrder+` LIMIT ?`,
		status, limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples in pipeline stage (light): %w", err)
	}
	return scanLiteSamplesLight(rows)
}

func (db *DB) falsePositivesSQLite(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2)
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < ?)
		 `+liteSeedOrder+` LIMIT ?`,
		liteSeedFreshnessCutoff(), limit)
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
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND max_crit < 5 AND suspicious_count < 2
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < ?)
		 `+liteSeedOrder+` LIMIT ?`,
		liteSeedFreshnessCutoff(), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) falsePositivesLightSQLite(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleColsLight+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2)
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < ?)
		 `+liteSeedOrder+` LIMIT ?`,
		liteSeedFreshnessCutoff(), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false positives (light): %w", err)
	}
	return scanLiteSamplesLight(rows)
}

func (db *DB) falseNegativesLightSQLite(ctx context.Context, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleColsLight+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND status = '' AND skip = '' AND parent = ''
		   AND max_crit < 5 AND suspicious_count < 2
		   AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < ?)
		 `+liteSeedOrder+` LIMIT ?`,
		liteSeedFreshnessCutoff(), limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: false negatives (light): %w", err)
	}
	return scanLiteSamplesLight(rows)
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

func triageFilterClauseSQLite(f TriageFilter) (clause string, args []any) {
	if f.Ecosystem != "" {
		clause += " AND ecosystem = ?"
		args = append(args, f.Ecosystem)
	}
	if f.FileType != "" {
		clause += " AND file_type = ?"
		args = append(args, f.FileType)
	}
	if !f.MinAnalyzedAt.IsZero() {
		clause += " AND analyzed_at >= ?"
		args = append(args, f.MinAnalyzedAt.UTC().Format(time.RFC3339Nano))
	}
	if f.ExcludeReportType != "" {
		clause += ` AND NOT EXISTS (SELECT 1 FROM reports r` +
			` WHERE r.sha256 = samples.sha256 AND r.report_type = ?` +
			` AND r.created_at > samples.analyzed_at)`
		args = append(args, f.ExcludeReportType)
	}
	return clause, args
}

func (db *DB) triageBadSQLite(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClauseSQLite(f)
	args = append(args, limit)
	//nolint:gosec // G202: label/crit predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''
		   AND (max_crit < 5 OR suspicious_count < 2)`+extra+`
		 `+triageOrderSQL(f)+` LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage bad: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) triageGoodSQLite(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClauseSQLite(f)
	// litmusClassSQLite's two `?` (cutoff, then ceiling) come first in the SQL.
	args := append([]any{CriticalLevel, SuspiciousCeiling}, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: label/crit predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''
		   AND (max_crit >= 5 OR suspicious_count >= 2 OR `+litmusClassSQLite+` >= 1)`+extra+`
		 `+triageOrderSQL(f)+` LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage good: %w", err)
	}
	return scanLiteSamples(rows)
}

// triageHighestSQLite: see TriageHighest. Mirrors triageHighestPG's per-route
// windows — SQLite has no LATERAL, so the per-file_type top-K comes from a
// ROW_NUMBER() PARTITION BY file_type window over the eligible set (dev-scale
// tables; no index gymnastics needed), and the collapse is GROUP BY root with
// MAX(best)/MIN(rank) instead of DISTINCT ON.
func (db *DB) triageHighestSQLite(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClauseSQLite(f)
	args := append([]any{
		createdBefore.UTC().Format(time.RFC3339Nano),
		missingBefore.UTC().Format(time.RFC3339Nano),
	}, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: label predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM (
		   SELECT root, MAX(best) AS best, MIN(rank) AS rank FROM (
		     SELECT CASE WHEN parent = '' THEN sha256 ELSE parent END AS root,
		            litmus_score AS best,
		            ROW_NUMBER() OVER (PARTITION BY file_type ORDER BY litmus_score DESC) AS rank
		     FROM samples s0
		     WHERE label = 'good' AND cleave_result IS NOT NULL AND skip = ''
		       AND litmus_score IS NOT NULL
		       AND (parent = '' OR path LIKE '%!!%')
		       AND (parent = '' OR EXISTS (SELECT 1 FROM samples pp WHERE pp.sha256 = s0.parent))
		       AND created_at < ?
		       AND NOT EXISTS (SELECT 1 FROM reports r
		                       WHERE r.sha256 = CASE WHEN s0.parent = '' THEN s0.sha256 ELSE s0.parent END
		                         AND (r.report_type = 'highest'
		                              OR (r.report_type = '`+ReportTypeMissing+`' AND r.created_at > ?)))`+extra+`
		   ) hot WHERE rank <= `+strconv.Itoa(triagePerRouteK)+`
		   GROUP BY root
		 ) roots
		 JOIN samples ON samples.sha256 = roots.root AND samples.label IN ('good', 'unknown')
		 ORDER BY roots.rank ASC, roots.best DESC, samples.id DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage highest: %w", err)
	}
	return scanLiteSamples(rows)
}

// triageLowestSQLite: see TriageLowest. Mirrors triageLowestPG (per-route
// bottom-K via a PARTITION BY file_type window), including the per-member
// drain key (a bad archive's members each need their own verdict).
func (db *DB) triageLowestSQLite(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClauseSQLite(f)
	args := append([]any{
		createdBefore.UTC().Format(time.RFC3339Nano),
		missingBefore.UTC().Format(time.RFC3339Nano),
	}, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: label predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM (
		   SELECT samples.*,
		          ROW_NUMBER() OVER (PARTITION BY file_type ORDER BY litmus_score ASC) AS rank
		   FROM samples
		   WHERE label = 'bad' AND cleave_result IS NOT NULL AND skip = ''
		     AND litmus_score IS NOT NULL
		     AND label_source != 'conflict'
		     AND (parent = '' OR path LIKE '%!!%')
		     AND (parent = '' OR EXISTS (SELECT 1 FROM samples p WHERE p.sha256 = samples.parent))
		     AND created_at < ?
		     AND NOT EXISTS (SELECT 1 FROM reports r
		                     WHERE r.sha256 = samples.sha256 AND r.report_type = 'lowest')
		     AND NOT EXISTS (SELECT 1 FROM reports r
		                     WHERE r.sha256 = CASE WHEN samples.parent = '' THEN samples.sha256 ELSE samples.parent END
		                       AND r.report_type = '`+ReportTypeMissing+`' AND r.created_at > ?)`+extra+`
		 ) samples
		 WHERE rank <= `+strconv.Itoa(triagePerRouteK)+`
		 ORDER BY rank ASC, litmus_score ASC, id DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage lowest: %w", err)
	}
	return scanLiteSamples(rows)
}

// triageStrandedSQLite: see TriageStranded. Mirrors triageStrandedPG —
// GROUP BY root with MAX(best) stands in for DISTINCT ON.
func (db *DB) triageStrandedSQLite(ctx context.Context, limit int, createdBefore, missingBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClauseSQLite(f)
	args := append([]any{
		createdBefore.UTC().Format(time.RFC3339Nano),
		missingBefore.UTC().Format(time.RFC3339Nano),
	}, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: label/crit predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM (
		   SELECT root, MAX(best) AS best FROM (
		     SELECT m.parent AS root, m.score AS best
		     FROM samples m
		     WHERE m.label = 'good' AND m.cleave_result IS NOT NULL AND m.skip = ''
		       AND m.parent != '' AND m.path LIKE '%!!%'
		       AND m.score > 0 AND m.max_crit >= `+strconv.Itoa(notableCrit)+`
		       AND m.label_source NOT LIKE 'cyclotron:%'
		       AND m.created_at < ?
		       AND EXISTS (SELECT 1 FROM samples p WHERE p.sha256 = m.parent AND p.label = 'bad')
		       AND NOT EXISTS (SELECT 1 FROM reports r
		                       WHERE r.sha256 = m.sha256 AND r.report_type = 'stranded')
		       AND NOT EXISTS (SELECT 1 FROM reports r
		                       WHERE r.sha256 = m.parent
		                         AND r.report_type = '`+ReportTypeMissing+`' AND r.created_at > ?)`+extra+`
		     ORDER BY m.score DESC
		     LIMIT `+strconv.Itoa(strandedInnerScan)+`
		   ) hot GROUP BY root
		 ) roots
		 JOIN samples ON samples.sha256 = roots.root AND samples.label = 'bad'
		 ORDER BY roots.best DESC, samples.id DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage stranded: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) triageNewSQLite(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClauseSQLite(f)
	args = append(args, limit)
	//nolint:gosec // G202: label/crit predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''
		   AND suspicious_count >= 1`+extra+`
		 `+triageOrderSQL(f)+` LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage new: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) triageSightedSQLite(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, args := triageFilterClauseSQLite(f)
	args = append(args, limit)
	//nolint:gosec // G202: label predicate and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'sighted' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''`+extra+`
		 ORDER BY created_at DESC, id DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage sighted: %w", err)
	}
	return scanLiteSamples(rows)
}

// triageSecondOpinionSQLite: see TriageSecondOpinion. Mirrors
// triageSecondOpinionPG; the trusted list expands to IN placeholders, with an
// always-false arm when the list is empty (SQLite rejects `IN ()`).
func (db *DB) triageSecondOpinionSQLite(
	ctx context.Context, limit int, trusted []string, analyzedBefore time.Time, f TriageFilter,
) ([]*Sample, error) {
	trustedClause := "1 = 0"
	// With no trusted sources there can be no trusted-sighting timestamps, so
	// any 'second' report drains permanently.
	refreshClause := `NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'second')`
	// litmusClassSQLite's two `?` (cutoff, then ceiling) come first in the SQL.
	args := []any{CriticalLevel, SuspiciousCeiling, analyzedBefore.UTC().Format(time.RFC3339Nano)}
	if len(trusted) > 0 {
		in := "(?" + strings.Repeat(",?", len(trusted)-1) + ")"
		trustedClause = `EXISTS (SELECT 1 FROM sightings s
		                WHERE (s.subject = samples.sha256
		                       OR (samples.purl_base != '' AND s.subject = samples.purl_base))
		                  AND s.source IN ` + in + `)`
		for _, src := range trusted {
			args = append(args, src)
		}
		// A report only drains while it is newer than the newest trusted
		// sighting; a trusted source citing the sample after its review is new
		// evidence that re-admits it. Timestamps are ISO-8601 text in SQLite,
		// so string comparison orders correctly and '' is older than any.
		refreshClause = `NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'second'
		                     AND r.created_at > COALESCE(
		                       (SELECT max(s2.first_seen) FROM sightings s2
		                        WHERE (s2.subject = samples.sha256
		                               OR (samples.purl_base != '' AND s2.subject = samples.purl_base))
		                          AND s2.source IN ` + in + `), ''))`
		for _, src := range trusted {
			args = append(args, src)
		}
	}
	extra, fargs := triageFilterClauseSQLite(f)
	args = append(args, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: predicates and column list are constant; trusted expands to `?` placeholders, values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'good' AND cleave_result IS NOT NULL AND parent = ''
		   AND corroborated = 1
		   AND NOT (max_crit >= 5 OR suspicious_count >= 2 OR `+litmusClassSQLite+` >= 1)
		   AND analyzed_at < ?
		   AND (`+trustedClause+`
		        OR (SELECT count(DISTINCT s.source) FROM sightings s
		            WHERE s.subject = samples.sha256
		               OR (samples.purl_base != '' AND s.subject = samples.purl_base)) >= 2)
		   AND `+refreshClause+extra+`
		 ORDER BY created_at DESC, id DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage second opinion: %w", err)
	}
	return scanLiteSamples(rows)
}

// triageAcquitSQLite: see TriageAcquit. Mirrors triageAcquitPG; the provenance
// tests use the JSON1 functions over the TEXT sidecar column.
func (db *DB) triageAcquitSQLite(ctx context.Context, limit int, createdBefore time.Time, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClauseSQLite(f)
	args := append([]any{createdBefore.UTC().Format(time.RFC3339Nano)}, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND cleave_result IS NOT NULL AND parent = ''
		   AND skip != 'conflict' AND label_source != 'conflict'
		   AND max_crit >= 5 AND suspicious_count >= 2
		   AND created_at < ?
		   AND provenance IS NOT NULL AND json_valid(provenance)
		   AND json_type(provenance) = 'object'
		   AND json_extract(provenance, '$.feed') IS NULL
		   AND NOT EXISTS (SELECT 1 FROM sightings s
		                   WHERE s.subject = samples.sha256
		                      OR (samples.purl_base != '' AND s.subject = samples.purl_base))
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'acquit')`+extra+`
		 ORDER BY created_at DESC, id DESC LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage acquit: %w", err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) conflictReviewSQLite(ctx context.Context, _, limit int) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE label = 'bad' AND skip = 'conflict' AND status = ''
		 ORDER BY updated_at DESC LIMIT ?`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("hopper: conflict review: %w", err)
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

func (db *DB) relativizePathsSQLite(ctx context.Context, prefix string) (int64, error) {
	if prefix == "" {
		return 0, nil
	}
	ts := now()
	res, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET path = substr(path, length(?) + 1), updated_at = ?
		WHERE instr(path, ?) = 1`,
		prefix, ts, prefix)
	if err != nil {
		return 0, fmt.Errorf("hopper: relativize paths: %w", err)
	}
	total, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("hopper: relativize paths rows affected: %w", err)
	}

	// Three-step rewrite so the UNIQUE (sha256, path) constraint is
	// never violated; see relativizePathsPG for the rationale.
	if _, err := db.lite.ExecContext(ctx, `
		DELETE FROM sample_locations
		 WHERE id IN (
		     SELECT sl.id FROM sample_locations sl
		      WHERE instr(sl.path, ?) = 1
		        AND EXISTS (
		            SELECT 1 FROM sample_locations x
		             WHERE x.sha256 = sl.sha256
		               AND x.path   = substr(sl.path, length(?) + 1)
		               AND x.id    <> sl.id
		        )
		 )`, prefix, prefix); err != nil {
		return 0, fmt.Errorf("hopper: relativize locations dedup-vs-existing: %w", err)
	}
	if _, err := db.lite.ExecContext(ctx, `
		DELETE FROM sample_locations
		 WHERE id IN (
		     SELECT id FROM (
		         SELECT sl.id,
		                row_number() OVER (
		                    PARTITION BY sl.sha256, substr(sl.path, length(?) + 1)
		                    ORDER BY sl.last_seen_at DESC, sl.id ASC
		                ) AS rn
		           FROM sample_locations sl
		          WHERE instr(sl.path, ?) = 1
		     ) t
		     WHERE rn > 1
		 )`, prefix, prefix); err != nil {
		return 0, fmt.Errorf("hopper: relativize locations dedup-peers: %w", err)
	}
	if _, err := db.lite.ExecContext(ctx, `
		UPDATE sample_locations SET
			path = substr(path, length(?) + 1),
			last_seen_at = ?
		 WHERE instr(path, ?) = 1`, prefix, ts, prefix); err != nil {
		return 0, fmt.Errorf("hopper: relativize locations update: %w", err)
	}
	return total, nil
}

func (db *DB) updateSampleSQLite(ctx context.Context, sha256, status string, result []byte, canonical string, fi cleaveFileInfo) error {
	// file_type, score, formula, litmus_score are GENERATED; litmus_score
	// auto-resets to 0 when litmus_result goes NULL.
	n := now()
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET status = ?, cleave_result = ?,
			canonical_sha256 = ?, elements = ?,
			max_crit = ?, suspicious_count = ?, top_traits = ?,
			litmus_result = NULL,
			note = '', last_error_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, ?),
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`,
		status, string(result), canonical,
		fi.Elements, fi.MaxCrit, fi.SuspiciousCount, fi.TopTraits, n, n, n, sha256)
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

func (db *DB) seedCandidatesInPathsSQLite(ctx context.Context, prefixes []string, label string, limit int, light bool) ([]*Sample, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	var clauses []string
	args := []any{label}
	for _, p := range prefixes {
		clauses = append(clauses, "path GLOB ?")
		args = append(args, p+"/*")
	}
	args = append(args, liteSeedFreshnessCutoff(), limit)
	// Apply detection-equivalent filter so the DB only returns samples that
	// will pass the Go-side Detected() / !Detected() post-filter.
	var detectionFilter string
	if label == "good" {
		detectionFilter = " AND (max_crit >= 5 OR suspicious_count >= 2)"
	} else {
		detectionFilter = " AND max_crit < 5 AND suspicious_count < 2"
	}

	cols := liteSampleCols
	if light {
		cols = liteSampleColsLight
	}

	//nolint:gosec // query structure is built from constants, values are parameterized
	query := `SELECT ` + cols + ` FROM samples` +
		` WHERE status = '' AND label = ? AND skip = ''` +
		` AND cleave_result IS NOT NULL` +
		` AND (` + strings.Join(clauses, " OR ") + `)` +
		` AND (cyclotron_attempted_at IS NULL OR cyclotron_attempted_at < ?)` +
		detectionFilter +
		` ` + liteSeedOrder + ` LIMIT ?`
	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: seed candidates in paths: %w", err)
	}
	if light {
		return scanLiteSamplesLight(rows)
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

func (db *DB) addSightingsSQLite(ctx context.Context, s []Sighting) (int, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: add sightings: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rolled back unless Commit succeeds

	// SQLite has no array unnest, so upsert row by row. RETURNING (SQLite 3.35+,
	// bundled by mattn) yields the changed subjects for the flag update, matching
	// the PG delta guard: the WHERE skips rows whose url+note are unchanged.
	changed := make(map[string]struct{})
	for i := range s {
		var subj string
		err := tx.QueryRowContext(ctx, `
			INSERT INTO sightings (source, subject, url, note)
			VALUES (?, ?, ?, ?)
			ON CONFLICT (source, subject) DO UPDATE
				SET url = excluded.url, note = excluded.note
				WHERE sightings.url IS NOT excluded.url
				   OR sightings.note IS NOT excluded.note
			RETURNING subject`, s[i].Source, s[i].Subject, s[i].URL, s[i].Note).Scan(&subj)
		if errors.Is(err, sql.ErrNoRows) {
			continue // unchanged row: DO UPDATE guard tripped, nothing returned
		}
		if err != nil {
			return 0, fmt.Errorf("hopper: upsert sighting: %w", err)
		}
		changed[subj] = struct{}{}
	}

	if len(changed) > 0 {
		subs := make([]string, 0, len(changed))
		for subj := range changed {
			subs = append(subs, subj)
		}
		// Flip the flag for changed subjects, guarded by corroborated = 0.
		// Chunked IN lists keep any single statement bounded.
		const chunk = 500
		for start := 0; start < len(subs); start += chunk {
			end := min(start+chunk, len(subs))
			batch := subs[start:end]
			ph := make([]string, len(batch))
			args := make([]any, 0, len(batch)*2)
			for i := range batch {
				ph[i] = "?"
			}
			for i := range batch {
				args = append(args, batch[i])
			}
			for i := range batch {
				args = append(args, batch[i])
			}
			list := strings.Join(ph, ", ")
			//nolint:gosec // G202: list is fixed "?" placeholders; subjects are bound args.
			if _, err := tx.ExecContext(ctx,
				`UPDATE samples SET corroborated = 1 WHERE corroborated = 0 AND `+
					`(sha256 IN (`+list+`) OR purl_base IN (`+list+`))`, args...); err != nil {
				return 0, fmt.Errorf("hopper: mark corroborated: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hopper: commit sightings: %w", err)
	}
	return len(changed), nil
}

func (db *DB) sightingsForSQLite(ctx context.Context, subjects []string) (map[string][]Sighting, error) {
	out := make(map[string][]Sighting, len(subjects))
	const chunk = 500
	// One chunk per closure so defer rows.Close() runs at chunk boundary, not
	// function exit — SQLite has no array binding, so subjects go in an IN list.
	readChunk := func(batch []string) error {
		ph := make([]string, len(batch))
		args := make([]any, len(batch))
		for i := range batch {
			ph[i] = "?"
			args[i] = batch[i]
		}
		//nolint:gosec // G202: ph is a slice of fixed "?" placeholders; subjects are bound args.
		rows, err := db.lite.QueryContext(ctx,
			`SELECT source, subject, url, note, first_seen FROM sightings `+
				`WHERE subject IN (`+strings.Join(ph, ", ")+`) ORDER BY source`, args...)
		if err != nil {
			return fmt.Errorf("hopper: sightings for subjects: %w", err)
		}
		defer rows.Close() //nolint:errcheck // best-effort cleanup
		for rows.Next() {
			var x Sighting
			if err := rows.Scan(&x.Source, &x.Subject, &x.URL, &x.Note, &x.FirstSeen); err != nil {
				return fmt.Errorf("hopper: scan sighting: %w", err)
			}
			out[x.Subject] = append(out[x.Subject], x)
		}
		return rows.Err()
	}
	for start := 0; start < len(subjects); start += chunk {
		end := min(start+chunk, len(subjects))
		if err := readChunk(subjects[start:end]); err != nil {
			return nil, err
		}
	}
	return out, nil
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
		FROM reports WHERE sha256 = ? ORDER BY created_at DESC, id DESC`, sha256)
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
	// id DESC tiebreaks when two rows share a created_at — strftime('%f') is
	// millisecond-resolution, and rapid InsertReport calls collide on the
	// same value. Without id DESC, "latest" is non-deterministic.
	err := db.lite.QueryRowContext(ctx, `
		SELECT id, sha256, report_type, content, provider, duration_ms, created_at
		FROM reports WHERE sha256 = ? AND report_type = ?
		ORDER BY created_at DESC, id DESC LIMIT 1`, sha256, reportType).Scan(
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
			FROM samples s, json_each(COALESCE(json_extract(s.cleave_result, '$.files'), json_extract(s.cleave_result, '$.fs'))) je
			WHERE COALESCE(json_extract(je.value, '$.sha256'), json_extract(je.value, '$.sha')) = ?
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
					FROM json_each(COALESCE(json_extract(samples.cleave_result, '$.files'), json_extract(samples.cleave_result, '$.fs')))
					WHERE length(v) = 64
					UNION ALL
					SELECT json_extract(value, '$.sha') AS v
					FROM json_each(COALESCE(json_extract(samples.cleave_result, '$.files'), json_extract(samples.cleave_result, '$.fs')))
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

const sqliteCleaveBackfillWhere = `cleave_result IS NOT NULL
	AND elements = ''
	AND EXISTS (
		SELECT 1 FROM json_each(COALESCE(json_extract(cleave_result, '$.files'), json_extract(cleave_result, '$.fs'))) je
		WHERE json_extract(je.value, '$.dp') = 0
			AND COALESCE(json_extract(je.value, '$.mol'), json_extract(je.value, '$.f'), '') != ''
	)`

func (db *DB) backfillPendingSQLite(ctx context.Context) (BackfillPending, error) {
	var pending BackfillPending
	if err := db.lite.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) FROM samples WHERE `+sqliteCleaveBackfillWhere+`),
			(SELECT count(*)
			 FROM samples c
			 JOIN samples p ON p.sha256 = c.parent
			 WHERE c.parent <> ''
				AND c.litmus_result IS NOT NULL
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
		// No FileTypeEmpties count: SQLite derives file_type/score/formula with
		// dual-key GENERATED columns (schema_sqlite.sql), so they never went
		// stale the way the Postgres expression did. It stays 0.
		&pending.CleaveColumns,
		&pending.ArchiveMemberLitmus,
		&pending.ArchiveMemberAnalyzed,
		&pending.StaleGoodMarkers,
		&pending.StaleBadMarkers,
	); err != nil {
		return pending, fmt.Errorf("hopper: backfill pending count: %w", err)
	}
	return pending, nil
}

// backfillSQLite mirrors backfillPG: re-derive the remaining non-generated
// analysis columns (elements, max_crit, suspicious_count) for legacy rows,
// then clear stale misclassified markers. file_type / score / formula /
// litmus_score are GENERATED STORED columns since the recent schema change,
// so they can't drift and don't need a backfill pass.
func (db *DB) backfillSQLite(ctx context.Context) (BackfillStats, error) {
	var stats BackfillStats
	ts := now()

	// Candidate rows: have cleave_result, elements still empty, AND the JSON
	// would actually produce a non-empty elements value. Without the EXISTS
	// clause, rows whose cleave_result has no files entry with dp=0 (or whose
	// dp=0 entry has empty 'mol') match the gate, get UPDATEd to elements='' as
	// a no-op, and re-match next batch — inflating RowsAffected and risking
	// an infinite loop on databases with >= backfillBatch such rows.
	if err := db.lite.QueryRowContext(ctx, `
		SELECT count(*) FROM samples WHERE `+sqliteCleaveBackfillWhere).Scan(&stats.Scanned); err != nil {
		return stats, fmt.Errorf("hopper: backfill count: %w", err)
	}
	// Surface the total to any progress observer before the first batch runs.
	db.reportBackfill(0, stats.Scanned)

	// Pass 1: elements / max_crit / suspicious_count from cleave_result.
	elementsExpr := fmt.Sprintf(stripSubscriptsSQL, "COALESCE(j.f, '')")
	const backfillBatch = 50000
	for {
		//nolint:gosec // constant SQL fragments, no tainted input.
		cleaveSQL := `
			WITH batch AS (
				SELECT sha256 FROM samples WHERE ` + sqliteCleaveBackfillWhere + `
				LIMIT ?
			),
			cleave_extract AS (
				SELECT s.sha256,
					COALESCE(json_extract(je.value, '$.mol'), json_extract(je.value, '$.f')) AS f,
					(SELECT COALESCE(MAX(CAST(COALESCE(json_extract(te.value, '$.crit'), json_extract(te.value, '$.l')) AS INTEGER)), 0)
					 FROM json_each(COALESCE(json_extract(je.value, '$.find'), json_extract(je.value, '$.ts'), '[]')) te) AS mc,
					(SELECT COUNT(*)
					 FROM json_each(COALESCE(json_extract(je.value, '$.find'), json_extract(je.value, '$.ts'), '[]')) te
					 WHERE CAST(COALESCE(json_extract(te.value, '$.crit'), json_extract(te.value, '$.l')) AS INTEGER) >= 4) AS sc
				FROM samples s
				JOIN batch b ON b.sha256 = s.sha256,
					json_each(COALESCE(json_extract(s.cleave_result, '$.files'), json_extract(s.cleave_result, '$.fs'))) je
				WHERE json_extract(je.value, '$.dp') = 0
			)
			UPDATE samples SET
				elements = ` + elementsExpr + `,
				max_crit = COALESCE(j.mc, 0),
				suspicious_count = COALESCE(j.sc, 0),
				updated_at = ?
			FROM cleave_extract j
			WHERE samples.sha256 = j.sha256
				AND samples.elements = ''`
		cleaveRes, err := db.lite.ExecContext(ctx, cleaveSQL, backfillBatch, ts)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill cleave columns: %w", err)
		}
		n, err := cleaveRes.RowsAffected()
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill rows affected: %w", err)
		}
		stats.Updated += n
		db.reportBackfill(stats.Updated, stats.Scanned)
		if n < backfillBatch {
			break
		}
		slog.Info("backfill cleave batch", "batch", n, "total", stats.Updated)
	}

	n, err := db.backfillArchiveMemberLitmusSQLite(ctx)
	if err != nil {
		return stats, err
	}
	stats.Updated += n
	db.reportBackfill(stats.Updated, stats.Scanned)

	// Pass 2: archive members written before analyzed_at was persisted by
	// InsertSampleBatch should inherit the parent's analysis timestamp.
	for {
		childRes, err := db.lite.ExecContext(ctx, `
			UPDATE samples SET
				analyzed_at = (
					SELECT p.analyzed_at FROM samples p
					WHERE p.sha256 = samples.parent
				),
				updated_at = ?
			WHERE sha256 IN (
				SELECT c.sha256
				FROM samples c
				JOIN samples p ON p.sha256 = c.parent
				WHERE c.parent <> ''
					AND c.analyzed_at IS NULL
					AND c.cleave_result IS NOT NULL
					AND c.litmus_result IS NOT NULL
					AND p.analyzed_at IS NOT NULL
				LIMIT ?
			)`, now(), backfillBatch)
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill archive member analyzed_at: %w", err)
		}
		n, err := childRes.RowsAffected()
		if err != nil {
			return stats, fmt.Errorf("hopper: backfill archive member analyzed_at rows affected: %w", err)
		}
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

func (db *DB) backfillArchiveMemberLitmusSQLite(ctx context.Context) (int64, error) {
	type candidate struct {
		sha256       string
		childLitmus  []byte
		parentCleave []byte
		parentLitmus []byte
	}
	loadBatch := func() ([]candidate, error) {
		rows, err := db.lite.QueryContext(ctx, `
			SELECT c.sha256, c.litmus_result, p.cleave_result, p.litmus_result
			FROM samples c
			JOIN samples p ON p.sha256 = c.parent
			WHERE c.parent <> ''
				AND c.litmus_result IS NOT NULL
				AND c.litmus_result = p.litmus_result
				AND p.cleave_result IS NOT NULL
				AND p.litmus_result IS NOT NULL
			LIMIT ?`, archiveMemberLitmusBackfillBatch)
		if err != nil {
			return nil, fmt.Errorf("hopper: backfill archive member litmus query: %w", err)
		}
		defer rows.Close() //nolint:errcheck // best-effort cleanup
		var candidates []candidate
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.sha256, &c.childLitmus, &c.parentCleave, &c.parentLitmus); err != nil {
				return nil, fmt.Errorf("hopper: backfill archive member litmus scan: %w", err)
			}
			candidates = append(candidates, c)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("hopper: backfill archive member litmus rows: %w", err)
		}
		return candidates, nil
	}

	var total int64
	for {
		candidates, err := loadBatch()
		if err != nil {
			return total, err
		}
		if len(candidates) == 0 {
			return total, nil
		}

		var fixed int64
		for _, c := range candidates {
			id, ok := cleaveFileIndexForSHA(c.parentCleave, c.sha256)
			if !ok {
				continue
			}
			memberLitmus := litmusResultForMember(c.parentLitmus, id)
			if len(memberLitmus) == 0 {
				continue
			}
			res, err := db.lite.ExecContext(ctx, `
				UPDATE samples
				SET litmus_result = ?, updated_at = ?
				WHERE sha256 = ? AND litmus_result = ?`,
				jsonTextOrNil(memberLitmus), now(), c.sha256, string(c.childLitmus))
			if err != nil {
				return total, fmt.Errorf("hopper: backfill archive member litmus update %s: %w", c.sha256, err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return total, fmt.Errorf("hopper: backfill archive member litmus rows affected: %w", err)
			}
			fixed += n
		}
		total += fixed
		if fixed > 0 {
			slog.Info("backfill archive member litmus batch", "batch", fixed, "total", total)
		}
		if len(candidates) < archiveMemberLitmusBackfillBatch || fixed == 0 {
			return total, nil
		}
	}
}

func (db *DB) setSkipSQLite(ctx context.Context, sha256, skip string) error {
	ts := now()
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = ?, skipped_at = ?, updated_at = ? WHERE sha256 = ?`,
		skip, ts, ts, sha256)
	if err != nil {
		return fmt.Errorf("hopper: set skip: %w", err)
	}
	return nil
}

// incrementAttemptsSQLite mirrors incrementAttemptsPG. updated_at is left
// untouched so a claim does not register as progress.
func (db *DB) incrementAttemptsSQLite(ctx context.Context, shas []string) error {
	if len(shas) == 0 {
		return nil
	}
	args := make([]any, len(shas))
	for i, s := range shas {
		args[i] = s
	}
	//nolint:gosec // placeholders are '?' bind markers; sha values are parameterized via args.
	q := `UPDATE samples SET attempts = attempts + 1 WHERE sha256 IN (` +
		strings.Repeat("?,", len(shas)-1) + `?)`
	if _, err := db.lite.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("hopper: increment attempts: %w", err)
	}
	return nil
}

func (db *DB) provenanceBySHA256SQLite(ctx context.Context, sha256 string) ([]byte, error) {
	var prov []byte
	err := db.lite.QueryRowContext(ctx,
		`SELECT provenance FROM samples WHERE sha256 = ?`, sha256).Scan(&prov)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("hopper: provenance %s: %w", sha256, err)
	}
	// SQLite stores JSONB as NUL-escaped text (jsonTextOrNil); undo it so the
	// bytes match what was written, exactly as the full sample read does.
	return restoreNULs(prov), nil
}

func (db *DB) setProvenanceSQLite(ctx context.Context, s *Sample) (bool, error) {
	res, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET
			provenance = ?,
			ecosystem  = COALESCE(NULLIF(ecosystem, ''), ?),
			package    = COALESCE(NULLIF(package, ''), ?),
			version    = COALESCE(NULLIF(version, ''), ?),
			purl_base  = COALESCE(NULLIF(purl_base, ''), ?),
			url        = COALESCE(NULLIF(url, ''), ?),
			fetched_at = COALESCE(fetched_at, ?)
		WHERE sha256 = ?`,
		jsonTextOrNil(s.Provenance), s.Ecosystem, s.Package, s.Version, s.PURLBase, s.URL, s.FetchedAt, s.SHA256)
	if err != nil {
		return false, fmt.Errorf("hopper: set provenance %s: %w", s.SHA256, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("hopper: set provenance rows %s: %w", s.SHA256, err)
	}
	return n > 0, nil
}

func (db *DB) shasWithProvenanceSQLite(ctx context.Context, shas []string) (map[string]bool, error) {
	args := make([]any, len(shas))
	for i, s := range shas {
		args[i] = s
	}
	//nolint:gosec // placeholders are '?' bind markers; sha values are parameterized via args.
	q := `SELECT sha256 FROM samples WHERE provenance IS NOT NULL AND sha256 IN (` +
		strings.Repeat("?,", len(shas)-1) + `?)`
	rows, err := db.lite.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: shas with provenance: %w", err)
	}
	defer func() { _ = rows.Close() }() //nolint:errcheck // best-effort
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

// reapStuckSQLite mirrors reapStuckPG.
func (db *DB) reapStuckSQLite(ctx context.Context, maxAttempts int) (int64, error) {
	ts := now()
	res, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = 'stuck', skipped_at = ?, updated_at = ?
		WHERE cleave_result IS NULL AND skip = '' AND attempts >= ?`, ts, ts, maxAttempts)
	if err != nil {
		return 0, fmt.Errorf("hopper: reap stuck: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("hopper: reap stuck rows: %w", err)
	}
	return n, nil
}

// reapOversizedSQLite mirrors reapOversizedPG.
func (db *DB) reapOversizedSQLite(ctx context.Context, maxBytes int64) (int64, error) {
	ts := now()
	res, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = 'oversized', skipped_at = ?, updated_at = ?
		WHERE cleave_result IS NULL AND skip = '' AND size_bytes > ?`, ts, ts, maxBytes)
	if err != nil {
		return 0, fmt.Errorf("hopper: reap oversized: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("hopper: reap oversized rows: %w", err)
	}
	return n, nil
}

func (db *DB) startWalkStagingSQLite(ctx context.Context) error {
	if _, err := db.lite.ExecContext(ctx, `DELETE FROM walk_staging`); err != nil {
		return fmt.Errorf("hopper: clear walk staging: %w", err)
	}
	return nil
}

func (db *DB) stageLocationsSQLite(ctx context.Context, keys []SampleLocationKey) error {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("hopper: begin stage: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO walk_staging (sha256, path) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("hopper: prepare stage: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // best-effort cleanup
	for _, k := range keys {
		if _, err := stmt.ExecContext(ctx, k.SHA256, k.Path); err != nil {
			return fmt.Errorf("hopper: stage location %s: %w", k.SHA256, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hopper: commit stage: %w", err)
	}
	return nil
}

func (db *DB) relabelFromPoolsSQLite(ctx context.Context) (int64, error) {
	ts := now()
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin relabel: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback

	// Materialize the rows whose label/skip should change: top-level, non-marker
	// samples joined to the pools their standalone copies were seen in this walk.
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS _relabel (
		sha256 TEXT PRIMARY KEY, old_label TEXT, old_skip TEXT,
		new_label TEXT, new_skip TEXT, new_source TEXT)`); err != nil {
		return 0, fmt.Errorf("hopper: relabel temp: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM _relabel`); err != nil {
		return 0, fmt.Errorf("hopper: relabel clear: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO _relabel
		WITH pools AS (
			SELECT sha256,
				MAX(path LIKE 'bad/%')     AS in_bad,
				MAX(path LIKE 'good/%')    AS in_good,
				MAX(path LIKE 'sighted/%') AS in_sighted
			FROM walk_staging
			GROUP BY sha256
		)
		SELECT s.sha256, s.label, s.skip,
			CASE WHEN p.in_bad = 1 THEN 'bad'
			     WHEN p.in_good = 1 THEN 'good'
			     -- sighted/ only lifts unknown rows; it never demotes good/bad.
			     WHEN p.in_sighted = 1 AND s.label = 'unknown' THEN 'sighted'
			     ELSE s.label END,
			CASE WHEN p.in_bad = 1 AND p.in_good = 1 THEN 'conflict'
			     WHEN s.skip IN ('conflict', 'missing', 'unsupported') THEN ''
			     ELSE s.skip END,
			CASE WHEN p.in_bad = 1 AND p.in_good = 1 THEN 'conflict'
			     WHEN s.label_source = 'conflict' THEN ''
			     ELSE s.label_source END
		FROM samples s JOIN pools p ON p.sha256 = s.sha256
		WHERE s.parent = '' AND s.label_source <> 'marker'`); err != nil {
		return 0, fmt.Errorf("hopper: relabel stage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM _relabel WHERE new_label = old_label AND new_skip = old_skip`); err != nil {
		return 0, fmt.Errorf("hopper: relabel prune: %w", err)
	}

	// Surface the operationally interesting relabels — a missing/unsupported file
	// revived by reappearing in a pool, or a new conflict — one line each. Drain
	// and close before the writes below: SQLite forbids an Exec on a tx that still
	// has open rows. Ordinary bad<->good moves are covered by the returned count.
	logRows, err := tx.QueryContext(ctx, `
		SELECT sha256, old_label, new_label, old_skip, new_skip
		FROM _relabel WHERE old_skip <> new_skip`)
	if err != nil {
		return 0, fmt.Errorf("hopper: relabel log scan: %w", err)
	}
	for logRows.Next() {
		var sha, oldLabel, newLabel, oldSkip, newSkip string
		if err := logRows.Scan(&sha, &oldLabel, &newLabel, &oldSkip, &newSkip); err != nil {
			logRows.Close() //nolint:errcheck,sqlclosecheck,gosec // best-effort cleanup before error return
			return 0, fmt.Errorf("hopper: relabel log row: %w", err)
		}
		logRelabelSkipChange(sha, oldLabel, newLabel, oldSkip, newSkip)
	}
	logRows.Close() //nolint:errcheck,gosec // best-effort cleanup
	if err := logRows.Err(); err != nil {
		return 0, fmt.Errorf("hopper: relabel log rows: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, old_label, new_label, old_skip, new_skip,
			CASE WHEN new_skip = 'conflict' THEN 'conflict' ELSE 'relabel' END, ?
		FROM _relabel`, ts); err != nil {
		return 0, fmt.Errorf("hopper: relabel audit: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE samples SET
			label = (SELECT new_label FROM _relabel r WHERE r.sha256 = samples.sha256),
			skip = (SELECT new_skip FROM _relabel r WHERE r.sha256 = samples.sha256),
			label_source = (SELECT new_source FROM _relabel r WHERE r.sha256 = samples.sha256),
			updated_at = ?
		WHERE sha256 IN (SELECT sha256 FROM _relabel)`, ts)
	if err != nil {
		return 0, fmt.Errorf("hopper: relabel apply: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("hopper: relabel rows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hopper: commit relabel: %w", err)
	}
	return n, nil
}

func (db *DB) staleStandaloneSamplesSQLite(ctx context.Context) ([]SampleLocationKey, int64, error) {
	var eligible int64
	if err := db.lite.QueryRowContext(ctx,
		`SELECT count(*) FROM samples WHERE parent = '' AND skip IN ('', 'conflict')`).Scan(&eligible); err != nil {
		return nil, 0, fmt.Errorf("hopper: stale count: %w", err)
	}
	rows, err := db.lite.QueryContext(ctx, `
		SELECT s.sha256, s.path FROM samples s
		WHERE s.parent = '' AND s.skip IN ('', 'conflict')
		  AND s.sha256 NOT IN (SELECT sha256 FROM walk_staging)`)
	if err != nil {
		return nil, 0, fmt.Errorf("hopper: stale scan: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
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

func (db *DB) setSkipWithEventSQLite(ctx context.Context, sha256, skip, reason string) (bool, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("hopper: begin set skip event: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback
	var label, curSkip string
	err = tx.QueryRowContext(ctx,
		`SELECT label, skip FROM samples WHERE sha256 = ?`, sha256).Scan(&label, &curSkip)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("hopper: set skip event read: %w", err)
	}
	if curSkip == skip {
		return false, nil
	}
	ts := now()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, sha256, label, label, curSkip, skip, reason, ts); err != nil {
		return false, fmt.Errorf("hopper: set skip event audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE samples SET skip = ?, updated_at = ? WHERE sha256 = ?`, skip, ts, sha256); err != nil {
		return false, fmt.Errorf("hopper: set skip event apply: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("hopper: commit set skip event: %w", err)
	}
	return true, nil
}

func (db *DB) cascadeMembersSQLite(ctx context.Context) (cascaded, revived int64, err error) {
	ts := now()
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("hopper: begin cascade: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback

	// Reachability closure: a sha is alive if a standalone copy was seen this
	// walk (in walk_staging), or it is a member of an alive archive (transitively).
	// A member with an edge to any alive archive therefore survives — the
	// supply-chain veto.
	if _, err := tx.ExecContext(ctx,
		`CREATE TEMP TABLE IF NOT EXISTS _alive (sha256 TEXT PRIMARY KEY)`); err != nil {
		return 0, 0, fmt.Errorf("hopper: cascade temp: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM _alive`); err != nil {
		return 0, 0, fmt.Errorf("hopper: cascade clear: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		WITH RECURSIVE alive(sha256) AS (
			SELECT DISTINCT sha256 FROM walk_staging
			UNION
			SELECT sl.sha256 FROM sample_locations sl
			  JOIN alive a ON sl.parent_sha256 = a.sha256
		)
		INSERT INTO _alive SELECT sha256 FROM alive`); err != nil {
		return 0, 0, fmt.Errorf("hopper: cascade closure: %w", err)
	}

	// Cascade missing to orphaned members (skip='' only — hard and benign-item
	// skips stick, markers are manual).
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, label, label, skip, 'missing', 'cascade-missing', ?
		FROM samples
		WHERE parent <> '' AND skip = '' AND sha256 NOT IN (SELECT sha256 FROM _alive)`, ts); err != nil {
		return 0, 0, fmt.Errorf("hopper: cascade audit: %w", err)
	}
	cascRes, err := tx.ExecContext(ctx, `
		UPDATE samples SET skip = 'missing', updated_at = ?
		WHERE parent <> '' AND skip = '' AND sha256 NOT IN (SELECT sha256 FROM _alive)`, ts)
	if err != nil {
		return 0, 0, fmt.Errorf("hopper: cascade apply: %w", err)
	}
	if cascaded, err = cascRes.RowsAffected(); err != nil {
		return 0, 0, fmt.Errorf("hopper: cascade rows: %w", err)
	}

	// Revive members whose archive reappeared.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, label, label, skip, '', 'revive', ?
		FROM samples
		WHERE parent <> '' AND skip = 'missing' AND sha256 IN (SELECT sha256 FROM _alive)`, ts); err != nil {
		return 0, 0, fmt.Errorf("hopper: revive audit: %w", err)
	}
	revRes, err := tx.ExecContext(ctx, `
		UPDATE samples SET skip = '', updated_at = ?
		WHERE parent <> '' AND skip = 'missing' AND sha256 IN (SELECT sha256 FROM _alive)`, ts)
	if err != nil {
		return 0, 0, fmt.Errorf("hopper: revive apply: %w", err)
	}
	if revived, err = revRes.RowsAffected(); err != nil {
		return 0, 0, fmt.Errorf("hopper: revive rows: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("hopper: commit cascade: %w", err)
	}
	return cascaded, revived, nil
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
	// Delete FK-dependent tables first; SQLite's ON DELETE CASCADE only
	// fires with PRAGMA foreign_keys = ON, which we don't set globally,
	// so we can't rely on it here.
	for _, q := range []string{
		`DELETE FROM sample_locations`,
		`DELETE FROM reports`,
		`DELETE FROM samples`,
		// Reset AUTOINCREMENT counters so next insert starts at 1.
		`DELETE FROM sqlite_sequence WHERE name IN ('samples','reports','sample_locations')`,
	} {
		if _, err := db.lite.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("hopper: delete all (%s): %w", q, err)
		}
	}
	return nil
}

func (db *DB) countCleanupSQLite(ctx context.Context, stage CleanupStage) (int64, error) {
	var n int64
	err := db.lite.QueryRowContext(ctx,
		"SELECT count(*) FROM samples WHERE "+stage.predicate).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("hopper: count cleanup %s: %w", stage.Name, err)
	}
	return n, nil
}

func (db *DB) applyCleanupSQLite(ctx context.Context, stage CleanupStage) (int64, error) {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("hopper: begin cleanup %s: %w", stage.Name, err)
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback
	if _, err := tx.ExecContext(ctx,
		//nolint:gosec // stage.predicate is an internal constant from CleanupStages, not user input.
		"DELETE FROM reports WHERE sha256 IN (SELECT sha256 FROM samples WHERE "+stage.predicate+")"); err != nil {
		return 0, fmt.Errorf("hopper: cleanup %s reports: %w", stage.Name, err)
	}
	//nolint:gosec // stage.predicate is an internal constant from CleanupStages, not user input.
	res, err := tx.ExecContext(ctx, "DELETE FROM samples WHERE "+stage.predicate)
	if err != nil {
		return 0, fmt.Errorf("hopper: cleanup %s samples: %w", stage.Name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("hopper: cleanup %s rows affected: %w", stage.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("hopper: commit cleanup %s: %w", stage.Name, err)
	}
	return n, nil
}

func (db *DB) feedSamplesSQLite(ctx context.Context, q *FeedQuery) ([]*Sample, error) {
	where, args := q.whereSQLite()
	query := `SELECT ` + liteSampleColsFeed + liteSampleColsRegistryExtra + //nolint:gosec // built from fixed query fragments and validated sort key.
		` FROM samples ` + where + ` ORDER BY ` + q.sortBy() + ` LIMIT ? OFFSET ?`
	args = append(args, q.Limit, q.Offset)

	rows, err := db.lite.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed samples: %w", err)
	}
	return scanLiteSamplesFeed(rows)
}

func (db *DB) feedSamplesCountSQLite(ctx context.Context, q *FeedQuery) (int, error) {
	where, args := q.whereSQLite()
	var n int
	err := db.lite.QueryRowContext(ctx, `SELECT count(*) FROM samples `+where, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("hopper: feed samples count: %w", err)
	}
	return n, nil
}

// litmusClassSQLite is the SQL expression yielding a sample's criticality
// class (0=benign, 1=suspicious, 2=hostile) — SQLite has no trigger-maintained
// litmus_class column, so every query derives it inline. Match either schema:
// legacy `class` field, or v6 `l`/`lvl`-derived (null is manual-mode
// hostile/2; -1 benign/0; 0..=cutoff hostile/2; cutoff < l <= ceiling
// suspicious/1; looser is benign/0). Consumes two `?` args, cutoff then
// ceiling — bind them before any placeholders that appear later in the query.
// Mirrors prism's envelopeClass, PG's feedClassExpr, and [LitmusClass]; keep
// the group in sync.
const litmusClassSQLite = `COALESCE(CAST(json_extract(litmus_result, '$.class') AS INTEGER), ` +
	`CASE WHEN litmus_result IS NULL THEN 0 ` +
	`WHEN COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) IS NULL THEN 2 ` +
	`WHEN CAST(COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) AS INTEGER) < 0 THEN 0 ` +
	`WHEN CAST(COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) AS INTEGER) <= ? THEN 2 ` +
	`WHEN CAST(COALESCE(json_extract(litmus_result, '$.lvl'), json_extract(litmus_result, '$.l')) AS INTEGER) <= ? THEN 1 ` +
	`ELSE 0 END)`

func (q *FeedQuery) whereSQLite() (where string, args []any) {
	// file_type <> 'registry' drops provenance sidecars — the `*.registry.json`
	// snapshots cleave types "registry", stored top-level beside a package.
	// They describe an artifact rather than being one, so the feed never lists
	// them (mirrors the PG feed/count queries).
	clauses := []string{"source = ?", "cleave_result IS NOT NULL", "file_type <> 'registry'"}
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

	if len(q.Domains) > 0 {
		placeholders := make([]string, len(q.Domains))
		for i := range q.Domains {
			placeholders[i] = "?"
			args = append(args, q.Domains[i])
		}
		clauses = append(clauses, "domain IN ("+strings.Join(placeholders, ", ")+")")
	}

	if len(q.LitmusClasses) > 0 {
		placeholders := make([]string, len(q.LitmusClasses))
		for i := range q.LitmusClasses {
			placeholders[i] = "?"
		}
		// litmusClassSQLite's two `?` (cutoff, then ceiling) precede the
		// IN(...) placeholders in the SQL, so their args are appended first.
		args = append(args, q.criticalLevel(), SuspiciousCeiling)
		for i := range q.LitmusClasses {
			args = append(args, q.LitmusClasses[i])
		}
		clauses = append(clauses, litmusClassSQLite+" IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.RequireLitmus {
		clauses = append(clauses, "litmus_result IS NOT NULL")
	}

	if q.TopLevelOnly {
		clauses = append(clauses, uncontainedSQL)
	}

	if q.Corroborated {
		clauses = append(clauses, "corroborated = 1")
	}

	if q.Formula != "" {
		clauses = append(clauses, "formula = ?")
		args = append(args, q.Formula)
	}

	// SQLite LIKE is case-insensitive for ASCII, matching the filename intent;
	// sha256 is matched by equality (the term is lowercased in searchTerm to
	// meet the lowercase-stored column).
	if term := q.searchTerm(); term != "" {
		clauses = append(clauses,
			`(filename LIKE '%' || ? || '%' ESCAPE '\' OR sha256 = ? OR package = ?)`)
		args = append(args, term, term, q.packageTerm())
	}

	// Exact package-identity filter: purl_base is the version-less canonical
	// PURL, version pins the release. Both are equality against stored columns.
	if q.PURLBase != "" {
		clauses = append(clauses, "purl_base = ?")
		args = append(args, q.PURLBase)
	}
	if q.PURLVersion != "" {
		clauses = append(clauses, "version = ?")
		args = append(args, q.PURLVersion)
	}

	return "WHERE " + strings.Join(clauses, " AND "), args
}

func (db *DB) feedSourcesSQLite(ctx context.Context, source, label string) ([]string, error) {
	query := `SELECT DISTINCT feed FROM samples WHERE (? = '' OR source = ?) AND (? = '' OR label = ?) AND feed != '' ORDER BY feed`
	rows, err := db.lite.QueryContext(ctx, query, source, source, label, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed sources: %w", err)
	}
	return scanLiteStrings(rows)
}

func (db *DB) feedEcosystemsSQLite(ctx context.Context, source, label string, since time.Time) ([]string, error) {
	// created_at is stored as RFC3339Nano UTC text (see now()), so a
	// same-format cutoff compares lexicographically. Empty cutoff disables
	// the time filter, mirroring the source/label empty-string sentinels.
	cutoff := ""
	if !since.IsZero() {
		cutoff = since.UTC().Format(time.RFC3339Nano)
	}
	query := `SELECT DISTINCT ecosystem FROM samples
		WHERE (? = '' OR source = ?) AND (? = '' OR label = ?) AND ecosystem != ''
		AND (? = '' OR created_at >= ?)
		ORDER BY ecosystem`
	rows, err := db.lite.QueryContext(ctx, query, source, source, label, label, cutoff, cutoff)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed ecosystems: %w", err)
	}
	return scanLiteStrings(rows)
}

func (db *DB) distinctEcosystemsSQLite(ctx context.Context) ([]string, error) {
	rows, err := db.lite.QueryContext(ctx, `
		SELECT ecosystem FROM samples WHERE ecosystem != ''
		UNION
		SELECT ecosystem FROM sample_locations WHERE ecosystem != ''
		ORDER BY ecosystem`)
	if err != nil {
		return nil, fmt.Errorf("hopper: distinct ecosystems: %w", err)
	}
	return scanLiteStrings(rows)
}

func (db *DB) updateEcosystemsSQLite(ctx context.Context, mapping map[string]string) (int64, error) {
	// One CASE statement per table (single pass), filtered to the remapped
	// values. Bind order matches placeholder order: the CASE's (when,then)
	// pairs first, then the IN-list keys.
	keys := sortedKeys(mapping)
	var caseExpr strings.Builder
	caseExpr.WriteString("CASE ecosystem")
	args := make([]any, 0, len(keys)*3)
	for _, k := range keys {
		caseExpr.WriteString(" WHEN ? THEN ?")
		args = append(args, k, mapping[k])
	}
	caseExpr.WriteString(" END")
	in := make([]string, len(keys))
	for i, k := range keys {
		in[i] = "?"
		args = append(args, k)
	}
	filter := strings.Join(in, ",")

	var total int64
	for _, table := range []string{"samples", "sample_locations"} {
		// #nosec G201 -- table is a fixed local literal; all values are bound params.
		q := fmt.Sprintf("UPDATE %s SET ecosystem = %s WHERE ecosystem IN (%s)", table, caseExpr.String(), filter)
		res, err := db.lite.ExecContext(ctx, q, args...)
		if err != nil {
			return total, fmt.Errorf("hopper: update %s ecosystem: %w", table, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
		}
	}
	return total, nil
}

func (db *DB) feedDomainsSQLite(ctx context.Context, source, label string) ([]string, error) {
	query := `SELECT DISTINCT domain FROM samples WHERE (? = '' OR source = ?) AND (? = '' OR label = ?) AND domain != '' ORDER BY domain`
	rows, err := db.lite.QueryContext(ctx, query, source, source, label, label)
	if err != nil {
		return nil, fmt.Errorf("hopper: feed domains: %w", err)
	}
	return scanLiteStrings(rows)
}

// Pull-based work scheduling (SQLite).

// Pull-based work scheduling (SQLite). See pg.go for design rationale —
// claim ownership lives in workerTracker, not the database.

// bigArchiveCandidatesSQLite mirrors bigArchiveCandidatesPG: the largest
// unanalyzed samples above minBytes, largest first.
func (db *DB) bigArchiveCandidatesSQLite(ctx context.Context, minBytes int64, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	startCutoff := hopperStart.UTC().Format(time.RFC3339Nano)
	return queryLiteCandidates(ctx, db.lite,
		`SELECT sha256, path, size_bytes, file_type FROM samples
		 WHERE size_bytes > ?
		   AND cleave_result IS NULL AND skip = '' AND parent = ''
		   AND (note = '' OR last_error_at IS NULL OR last_error_at < ?)
		   AND attempts < ?
		 ORDER BY size_bytes DESC
		 LIMIT ?`, minBytes, startCutoff, maxClaimAttempts, limit)
}

func (db *DB) unanalyzedCandidatesSQLite(ctx context.Context, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	startCutoff := hopperStart.UTC().Format(time.RFC3339Nano)
	pivot := randomSHA256Pivot()
	return queryLiteCandidates(ctx, db.lite,
		`WITH picked AS (
			SELECT sha256, path, size_bytes, file_type, 0 AS pass
			FROM samples
			WHERE sha256 >= ?
			  AND cleave_result IS NULL AND skip = '' AND parent = ''
			  AND (note = '' OR last_error_at IS NULL OR last_error_at < ?)
			  AND attempts < ?
			ORDER BY sha256
			LIMIT ?
		),
		wrapped AS (
			SELECT sha256, path, size_bytes, file_type, 1 AS pass
			FROM samples
			WHERE sha256 < ?
			  AND cleave_result IS NULL AND skip = '' AND parent = ''
			  AND (note = '' OR last_error_at IS NULL OR last_error_at < ?)
			  AND attempts < ?
			ORDER BY sha256
			LIMIT ?
		)
		SELECT sha256, path, size_bytes, file_type
		FROM (
			SELECT sha256, path, size_bytes, file_type, pass FROM picked
			UNION ALL
			SELECT sha256, path, size_bytes, file_type, pass FROM wrapped
		)
		ORDER BY pass, sha256
		LIMIT ?`, pivot, startCutoff, maxClaimAttempts, limit, pivot, startCutoff, maxClaimAttempts, limit, limit)
}

// forcedRescanCandidatesSQLite mirrors forcedRescanCandidatesPG: Tier 0
// operator-requested rescans, oldest first, skipping rows that errored since
// this hopper started.
func (db *DB) forcedRescanCandidatesSQLite(ctx context.Context, hopperStart time.Time, limit int) ([]ClaimJob, error) {
	startCutoff := hopperStart.UTC().Format(time.RFC3339Nano)
	return queryLiteCandidates(ctx, db.lite, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE rescan_priority = 2
		  AND skip = '' AND parent = ''
		  AND (note = '' OR last_error_at IS NULL OR last_error_at < ?)
		ORDER BY rescan_requested_at ASC
		LIMIT ?`, startCutoff, limit)
}

// repairCandidatesSQLite mirrors repairCandidatesPG.
func (db *DB) repairCandidatesSQLite(ctx context.Context, limit int) ([]ClaimJob, error) {
	return queryLiteCandidates(ctx, db.lite, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE rescan_priority = 1 AND skip = '' AND parent = ''
		ORDER BY rescan_requested_at ASC, score DESC
		LIMIT ?`, limit)
}

// queueRescanSQLite mirrors queueRescanPG. SQLite has no array binding, so the
// SHA list is expanded into placeholders.
func (db *DB) queueRescanSQLite(ctx context.Context, shas []string) (int64, error) {
	placeholders := make([]string, len(shas))
	args := make([]any, len(shas))
	for i, s := range shas {
		placeholders[i] = "?"
		args[i] = s
	}
	//nolint:gosec // placeholders are literal "?" tokens, never user input
	res, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET rescan_priority = 1,
		     rescan_requested_at = COALESCE(rescan_requested_at, strftime('%Y-%m-%dT%H:%M:%f','now')),
		     updated_at = strftime('%Y-%m-%dT%H:%M:%f','now')
		 WHERE sha256 IN (`+strings.Join(placeholders, ",")+`) AND parent = '' AND skip = '' AND rescan_priority = 0`,
		args...)
	if err != nil {
		return 0, fmt.Errorf("hopper: queue rescan: %w", err)
	}
	return res.RowsAffected()
}

// queueMissingMembersForRepairSQLite mirrors queueMissingMembersForRepairPG.
func (db *DB) queueMissingMembersForRepairSQLite(ctx context.Context) (int64, error) {
	res, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET rescan_priority = 1,
		    rescan_requested_at = strftime('%Y-%m-%dT%H:%M:%f','now'),
		    updated_at = strftime('%Y-%m-%dT%H:%M:%f','now')
		WHERE parent = '' AND skip = '' AND rescan_priority = 0
		  AND cleave_result IS NOT NULL
		  AND json_extract(cleave_result, '$.truncated') IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM samples m WHERE m.parent = samples.sha256)`)
	if err != nil {
		return 0, fmt.Errorf("hopper: queue missing-member archives: %w", err)
	}
	return res.RowsAffected()
}

// sampleAnalyzedSQLite mirrors sampleAnalyzedPG: cheap status query that
// avoids pulling the cleave_result blob during tight poll loops.
func (db *DB) sampleAnalyzedSQLite(ctx context.Context, sha256 string) (exists, analyzed bool, err error) {
	var analyzedInt int
	err = db.lite.QueryRowContext(ctx,
		`SELECT cleave_result IS NOT NULL FROM samples WHERE sha256 = ?`, sha256,
	).Scan(&analyzedInt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("hopper: sample analyzed lookup: %w", err)
	}
	return true, analyzedInt != 0, nil
}

// uploadCandidatesSQLite mirrors uploadCandidatesPG: interactive uploads
// not yet analyzed, oldest first.
func (db *DB) uploadCandidatesSQLite(ctx context.Context, limit int) ([]ClaimJob, error) {
	return queryLiteCandidates(ctx, db.lite, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE source = 'upload' AND cleave_result IS NULL
		  AND skip = '' AND parent = ''
		ORDER BY id ASC
		LIMIT ?`, limit)
}

func (db *DB) forceRescanCandidatesSQLite(ctx context.Context, hopperStart time.Time, prefixes []string, limit int) ([]ClaimJob, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	startCutoff := hopperStart.UTC().Format(time.RFC3339Nano)
	clauses := make([]string, 0, len(prefixes))
	args := []any{startCutoff}
	for _, p := range prefixes {
		clauses = append(clauses, "(path = ? OR path LIKE ?)")
		args = append(args, p, p+"/%")
	}
	args = append(args, startCutoff, limit)
	query := `SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''
		  AND analyzed_at < ?
		  AND (` + strings.Join(clauses, " OR ") + `)
		  AND (note = '' OR last_error_at IS NULL OR last_error_at < ?)
		ORDER BY updated_at ASC, id
		LIMIT ?`
	return queryLiteCandidates(ctx, db.lite, query, args...)
}

func (db *DB) staleTraitsCandidatesSQLite(
	ctx context.Context, currentTraits string, rescanAge time.Duration,
	hopperStart time.Time, limit int,
) ([]ClaimJob, error) {
	if currentTraits == "" {
		return nil, nil
	}
	staleAge := time.Now().Add(-rescanAge).UTC().Format(time.RFC3339Nano)
	startCutoff := hopperStart.UTC().Format(time.RFC3339Nano)
	return queryLiteCandidates(ctx, db.lite,
		`SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE cleave_result IS NOT NULL AND skip = '' AND parent = ''
		  AND traits_version != ?
		  AND analyzed_at < ?
		  AND (note = '' OR last_error_at IS NULL OR last_error_at < ?)
		ORDER BY
		  CASE
		    WHEN label = 'good' AND (max_crit >= 5 OR suspicious_count >= 2) THEN 0
		    WHEN label = 'bad' AND max_crit < 5 AND suspicious_count < 2 THEN 0
		    ELSE 1
		  END,
		  ABS(litmus_score - 0.5),
		  analyzed_at ASC
		LIMIT ?`, currentTraits, staleAge, startCutoff, limit)
}

func queryLiteCandidates(ctx context.Context, db *sql.DB, query string, args ...any) ([]ClaimJob, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: candidates: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []ClaimJob
	for rows.Next() {
		var j ClaimJob
		if err := rows.Scan(&j.SHA256, &j.Path, &j.SizeBytes, &j.FileType); err != nil {
			return nil, fmt.Errorf("hopper: candidate scan: %w", err)
		}
		out = append(out, j)
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
