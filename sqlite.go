package hopper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
			`CREATE INDEX IF NOT EXISTS idx_samples_elements ON samples(elements) WHERE elements != ''`,
			// Drains itself as backfill completes: rows leave the index when elements
			// is populated. Without it, each batch's gating SELECT seq-scans the heap.
			`CREATE INDEX IF NOT EXISTS idx_samples_backfill_pending ON samples(sha256) WHERE cleave_result IS NOT NULL AND elements = ''`,
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
			`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_created ON samples(source, label, created_at DESC) WHERE cleave_result IS NOT NULL`,
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
		`CREATE INDEX IF NOT EXISTS idx_samples_feed_source_created ` +
			`ON samples(source, label, created_at DESC) WHERE cleave_result IS NOT NULL`,
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

	// forced_rescan_at: operator-initiated re-queue marker (Tier 0). See the
	// matching PG migration for rationale. Workers drain Tier 0 before Tier 1
	// so user-requested rescans jump the queue.
	if pragmaHasColumn(ctx, db.lite, "forced_rescan_at") == 0 {
		if _, err := db.lite.ExecContext(ctx,
			`ALTER TABLE samples ADD COLUMN forced_rescan_at DATETIME`); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
		}
	}
	// Re-create the partial index without `cleave_result IS NULL` in the
	// predicate. The prior version forced RequestRescan to null the cached
	// envelope to make rows eligible — see pg.go for the full rationale.
	// DROP+CREATE is idempotent: fresh installs see no prior index to drop.
	for _, ddl := range []string{
		`DROP INDEX IF EXISTS idx_samples_forced_rescan`,
		`CREATE INDEX IF NOT EXISTS idx_samples_forced_rescan ` +
			`ON samples(forced_rescan_at) ` +
			`WHERE forced_rescan_at IS NOT NULL`,
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
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite samples index: %w", err)
		}
	}

	// Covers FP/FN seed queries ordered by impact. SQLite needs the explicit
	// `litmus_score IS NULL` prefix to match the `NULLS LAST` semantics our
	// queries use (see liteSeedOrder).
	for _, ddl := range []string{
		`CREATE INDEX IF NOT EXISTS idx_samples_seed_pool ` +
			`ON samples(label, litmus_score IS NULL, litmus_score DESC, score DESC, analyzed_at ASC) ` +
			`WHERE cleave_result IS NOT NULL AND status = '' AND skip = ''`,
		`CREATE INDEX IF NOT EXISTS idx_samples_pipeline_stage ` +
			`ON samples(status, litmus_score IS NULL, litmus_score DESC, score DESC, updated_at ASC) ` +
			`WHERE status != ''`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite: %w", err)
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
		// conflictReview
		`CREATE INDEX IF NOT EXISTS idx_samples_conflict_review ` +
			`ON samples(updated_at) ` +
			`WHERE skip = 'conflict' AND status = ''`,
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
		`CREATE INDEX IF NOT EXISTS idx_samples_top_ready_first_analyzed ` +
			`ON samples(first_analyzed_at DESC, id) ` +
			`WHERE parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL AND first_analyzed_at IS NOT NULL`,
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
		`CREATE INDEX IF NOT EXISTS idx_sl_source ON sample_locations(source, feed) WHERE feed <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_sl_parent ON sample_locations(parent_sha256) WHERE parent_sha256 <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_sl_last_seen ON sample_locations(last_seen_at)`,
	} {
		if _, err := db.lite.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("hopper: migrate sqlite sample_locations: %w", err)
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

	return nil
}

const liteSampleCols = `id, sha256, source, feed, ecosystem,
	filename, file_type, size_bytes, label, label_source,
	cleave_result, litmus_result, litmus_score,
	path, status, note, canonical_sha256, parent, skip,
	formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime,
	traits_version,
	url, domain, package, version`

// liteSampleColsLight excludes cleave_result and litmus_result to avoid
// loading large JSON blobs when only metadata is needed.
const liteSampleColsLight = `id, sha256, source, feed, ecosystem,
	filename, file_type, size_bytes, label, label_source,
	litmus_score,
	path, status, note, canonical_sha256, parent, skip,
	formula, elements, score, max_crit, suspicious_count,
	created_at, updated_at, analyzed_at, first_analyzed_at, last_error_at, mtime, marker_mtime,
	traits_version,
	url, domain, package, version`

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
			&s.URL, &s.Domain, &s.Package, &s.Version,
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
			-- carried 'class' directly; v2 dropped it for 'l' (the strictest
			-- grid level at which the file fires, or -1 for never-fires).
			-- Try class first; otherwise derive from l using CriticalLevel %d
			-- as the hostile/suspicious cutoff (l == null means manual-mode
			-- hostile and is treated as hostile fail-safe).
			COALESCE(
				CAST(json_extract(litmus_result, '$.class') AS INTEGER),
				CASE
					WHEN litmus_result IS NULL THEN 0
					WHEN json_extract(litmus_result, '$.l') IS NULL THEN 2
					WHEN CAST(json_extract(litmus_result, '$.l') AS INTEGER) < 0 THEN 0
					WHEN CAST(json_extract(litmus_result, '$.l') AS INTEGER) <= %d THEN 2
					ELSE 1
				END
			)
		FROM samples `+where, CriticalLevel, CriticalLevel), limit)
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

func scanLiteSample(row *sql.Row) (*Sample, error) {
	s := &Sample{}
	var cleaveResult, litmusResult, status sql.NullString
	var analyzedAt, firstAnalyzedAt, lastErrorAt, mtime, markerMtime sql.NullTime
	err := row.Scan(
		&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
		&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult, &s.LitmusScore,
		&s.Path, &status, &s.Note, &s.CanonicalSHA256, &s.Parent, &s.Skip, &s.Formula,
		&s.Elements, &s.Score, &s.MaxCrit, &s.SuspiciousCount,
		&s.CreatedAt, &s.UpdatedAt, &analyzedAt, &firstAnalyzedAt, &lastErrorAt, &mtime, &markerMtime,
		&s.TraitsVersion,
		&s.URL, &s.Domain, &s.Package, &s.Version,
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
	return s, nil
}

func scanLiteSamples(rows *sql.Rows) ([]*Sample, error) {
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []*Sample
	for rows.Next() {
		s := &Sample{}
		var cleaveResult, litmusResult, status sql.NullString
		var analyzedAt, firstAnalyzedAt, lastErrorAt, mtime, markerMtime sql.NullTime
		if err := rows.Scan(
			&s.ID, &s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.Filename,
			&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &cleaveResult, &litmusResult, &s.LitmusScore,
			&s.Path, &status, &s.Note, &s.CanonicalSHA256,
			&s.Parent, &s.Skip, &s.Formula, &s.Elements,
			&s.Score, &s.MaxCrit, &s.SuspiciousCount,
			&s.CreatedAt, &s.UpdatedAt, &analyzedAt, &firstAnalyzedAt, &lastErrorAt, &mtime, &markerMtime,
			&s.TraitsVersion,
			&s.URL, &s.Domain, &s.Package, &s.Version,
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
const sampleConflictUpdateSQLite = `ON CONFLICT (sha256) DO UPDATE SET
	label = CASE
		WHEN excluded.label_source = 'marker' THEN excluded.label
		WHEN samples.label_source = 'marker' THEN excluded.label
		WHEN (samples.label = 'good' AND excluded.label = 'bad')
		  OR (samples.label = 'bad' AND excluded.label = 'good') THEN 'bad'
		WHEN (CASE excluded.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		   > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END) THEN excluded.label
		ELSE samples.label
	END,
	label_source = CASE
		WHEN excluded.label_source = 'marker' THEN 'marker'
		WHEN samples.label_source = 'marker' THEN excluded.label_source
		WHEN (samples.label = 'good' AND excluded.label = 'bad')
		  OR (samples.label = 'bad' AND excluded.label = 'good') THEN 'conflict'
		WHEN (CASE excluded.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		   > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END) THEN excluded.label_source
		ELSE samples.label_source
	END,
	feed  = CASE WHEN excluded.feed  != '' THEN excluded.feed  ELSE samples.feed  END,
	ecosystem = CASE WHEN excluded.ecosystem != '' THEN excluded.ecosystem ELSE samples.ecosystem END,
	path  = CASE WHEN excluded.path  != ''   THEN excluded.path  ELSE samples.path  END,
	mtime = CASE WHEN excluded.mtime IS NOT NULL THEN excluded.mtime ELSE samples.mtime END,
	url     = CASE WHEN samples.url     = '' THEN excluded.url     ELSE samples.url     END,
	domain  = CASE WHEN samples.domain  = '' THEN excluded.domain  ELSE samples.domain  END,
	package    = CASE WHEN samples.package    = '' THEN excluded.package    ELSE samples.package    END,
	version = CASE WHEN samples.version = '' THEN excluded.version ELSE samples.version END,
	-- Label-related skips ('misclassified'/'conflict') track the resolution;
	-- the walker also clears 'missing'/'unsupported'. Hard skips stick.
	skip  = CASE
		WHEN excluded.label_source = 'marker' THEN 'misclassified'
		WHEN samples.label_source = 'marker' AND samples.skip = 'misclassified' THEN ''
		WHEN ((samples.label = 'good' AND excluded.label = 'bad')
		   OR (samples.label = 'bad' AND excluded.label = 'good'))
		  AND samples.skip IN ('', 'misclassified', 'conflict', 'missing', 'unsupported') THEN 'conflict'
		WHEN (CASE excluded.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
		   > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
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
    OR samples.skip IN ('missing','unsupported')
    -- Pool-precedence transitions must fire even when path/mtime are unchanged.
    OR ((CASE excluded.label WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END)
      > (CASE samples.label  WHEN 'bad' THEN 2 WHEN 'good' THEN 1 ELSE 0 END))
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
	// file_type, score, formula, litmus_score are GENERATED STORED columns
	// (SQLite 3.31+). They auto-derive from cleave_result / litmus_result
	// so writing to them is neither necessary nor legal.
	res, err := tx.ExecContext(ctx, `
		INSERT INTO samples (sha256, source, feed, ecosystem, filename,
			size_bytes, label, label_source, path, status,
			canonical_sha256, parent, skip, elements,
			max_crit, suspicious_count, mtime, marker_mtime,
			cleave_result, litmus_result,
			url, domain, package, version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`+sampleConflictUpdateSQLite,
		s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
		s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
		s.SHA256, s.Parent, s.Skip, s.Elements,
		s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
		jsonTextOrNil(s.CleaveResult), jsonTextOrNil(s.LitmusResult),
		s.URL, s.Domain, s.Package, s.Version)
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
				(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256, path) DO UPDATE SET
				last_seen_at = strftime('%Y-%m-%dT%H:%M:%f', 'now'),
				source = CASE WHEN excluded.source != '' THEN excluded.source ELSE sample_locations.source END,
				feed = CASE WHEN excluded.feed != '' THEN excluded.feed ELSE sample_locations.feed END,
				ecosystem = CASE WHEN excluded.ecosystem != '' THEN excluded.ecosystem ELSE sample_locations.ecosystem END,
				mtime = COALESCE(excluded.mtime, sample_locations.mtime)`,
			s.SHA256, s.Path, s.Parent, s.Filename, s.Source, s.Feed, s.Ecosystem, s.Mtime); err != nil {
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
		"url", "domain", "package", "version",
	}
	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = "?"
	}

	query := fmt.Sprintf( //nolint:gosec // column list and placeholders are derived from fixed local constants.
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
			(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256, path) DO UPDATE SET
			last_seen_at = strftime('%Y-%m-%dT%H:%M:%f', 'now'),
			source = CASE WHEN excluded.source != '' THEN excluded.source ELSE sample_locations.source END,
			feed = CASE WHEN excluded.feed != '' THEN excluded.feed ELSE sample_locations.feed END,
			ecosystem = CASE WHEN excluded.ecosystem != '' THEN excluded.ecosystem ELSE sample_locations.ecosystem END,
			mtime = COALESCE(excluded.mtime, sample_locations.mtime)`)
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
		res, err := stmt.ExecContext(ctx,
			s.SHA256, s.Source, s.Feed, s.Ecosystem, s.Filename,
			s.SizeBytes, s.Label, s.LabelSource, s.Path, s.Status,
			s.SHA256, s.Parent, s.Skip, s.Elements,
			s.MaxCrit, s.SuspiciousCount, s.Mtime, s.MarkerMtime,
			jsonTextOrNil(s.CleaveResult), jsonTextOrNil(s.LitmusResult), s.AnalyzedAt, firstAnalyzedAt,
			s.URL, s.Domain, s.Package, s.Version)
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
				s.SHA256, s.Path, s.Parent, s.Filename, s.Source, s.Feed, s.Ecosystem, s.Mtime); err != nil {
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

func (db *DB) sampleBySHA256SQLite(ctx context.Context, sha256 string) (*Sample, error) {
	s, err := scanLiteSample(db.lite.QueryRowContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE sha256 = ?`, sha256))
	if err != nil {
		return nil, fmt.Errorf("hopper: sample %s: %w", sha256, err)
	}
	return s, nil
}

func (db *DB) samplesByParentSQLite(ctx context.Context, parentSHA string) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE parent = ? ORDER BY path`, parentSHA)
	if err != nil {
		return nil, fmt.Errorf("hopper: samples by parent %s: %w", parentSHA, err)
	}
	return scanLiteSamples(rows)
}

func (db *DB) badMembersByParentSQLite(ctx context.Context, parentSHA string) ([]*Sample, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples WHERE parent = ? AND label = 'bad' ORDER BY path`, parentSHA)
	if err != nil {
		return nil, fmt.Errorf("hopper: bad members by parent %s: %w", parentSHA, err)
	}
	return scanLiteSamples(rows)
}

const liteLocationCols = `id, sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at`

func scanLiteLocation(row interface{ Scan(...any) error }) (*SampleLocation, error) {
	var loc SampleLocation
	if err := row.Scan(&loc.ID, &loc.SHA256, &loc.Path, &loc.ParentSHA256,
		&loc.Filename, &loc.Source, &loc.Feed, &loc.Ecosystem,
		&loc.Mtime, &loc.FirstSeenAt, &loc.LastSeenAt); err != nil {
		return nil, err
	}
	return &loc, nil
}

func (db *DB) upsertLocationSQLite(ctx context.Context, loc *SampleLocation) error {
	_, err := db.lite.ExecContext(ctx, `
		INSERT INTO sample_locations
			(sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sha256, path) DO UPDATE SET
			last_seen_at = strftime('%Y-%m-%dT%H:%M:%f', 'now'),
			mtime = COALESCE(excluded.mtime, sample_locations.mtime)`,
		loc.SHA256, loc.Path, loc.ParentSHA256, loc.Filename,
		loc.Source, loc.Feed, loc.Ecosystem, loc.Mtime)
	if err != nil {
		return fmt.Errorf("hopper: upsert location %s: %w", loc.SHA256, err)
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
	path string
	id   int64
}

// pruneMissingLocationsSQLite walks every sample_locations row whose
// path lives under absRoot, stats the file, and deletes the row if
// stat returns ENOENT. Refuses to delete more than maxFraction of the
// rows it scanned, returning *PruneSafetyExceeded instead.
// Returns the count of rows deleted.
func (db *DB) pruneMissingLocationsSQLite(ctx context.Context, absRoot string, maxFraction float64) (int, error) {
	rows, err := db.lite.QueryContext(ctx,
		`SELECT id, path FROM sample_locations WHERE path LIKE ?`, absRoot+"/%")
	if err != nil {
		return 0, fmt.Errorf("hopper: scan locations for prune: %w", err)
	}
	var victims []pruneVictim
	total := 0
	for rows.Next() {
		var v pruneVictim
		if err := rows.Scan(&v.id, &v.path); err != nil {
			rows.Close() //nolint:errcheck,sqlclosecheck,gosec // best-effort cleanup before error return
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
	rows.Close() //nolint:errcheck,gosec // best-effort cleanup
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if total > 0 && float64(len(victims))/float64(total) > maxFraction {
		return 0, &PruneSafetyExceeded{Total: total, Victims: len(victims), MaxFraction: maxFraction}
	}

	for _, v := range victims {
		if _, err := db.lite.ExecContext(ctx, `DELETE FROM sample_locations WHERE id = ?`, v.id); err != nil {
			return 0, fmt.Errorf("hopper: delete location %d: %w", v.id, err)
		}
	}
	return len(victims), nil
}

func (db *DB) updateCleaveResultSQLite(
	ctx context.Context, sha256 string, result []byte, canonical string,
	fi cleaveFileInfo, traitsVersion string,
) error {
	// file_type, score, formula, litmus_score are GENERATED columns;
	// setting litmus_result = NULL auto-resets litmus_score to 0.
	n := now()
	// forced_rescan_at clears here so the row drops out of the Tier 0
	// queue once fresh analysis lands.
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET cleave_result = ?,
			canonical_sha256 = ?, elements = ?,
			max_crit = ?, suspicious_count = ?,
			litmus_result = NULL,
			note = '', last_error_at = NULL,
			traits_version = ?,
			forced_rescan_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, ?),
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`,
		string(result), canonical, fi.Elements,
		fi.MaxCrit, fi.SuspiciousCount,
		traitsVersion, n, n, n, sha256)
	if err != nil {
		return fmt.Errorf("hopper: update cleave result: %w", err)
	}
	return nil
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
		SET forced_rescan_at = COALESCE(forced_rescan_at, ?),
		    updated_at = ?
		WHERE sha256 = ? AND parent = '' AND skip = ''
		  AND (forced_rescan_at IS NOT NULL
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
			max_crit = ?, suspicious_count = ?,
			litmus_result = NULL,
			note = '', last_error_at = NULL,
			first_analyzed_at = COALESCE(first_analyzed_at, ?),
			analyzed_at = ?, updated_at = ?
		WHERE sha256 = ?`,
		status, string(result), canonical,
		fi.Elements, fi.MaxCrit, fi.SuspiciousCount, n, n, n, sha256)
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

const sqliteCleaveBackfillWhere = `cleave_result IS NOT NULL
	AND elements = ''
	AND EXISTS (
		SELECT 1 FROM json_each(cleave_result, '$.fs') je
		WHERE json_extract(je.value, '$.dp') = 0
			AND COALESCE(json_extract(je.value, '$.f'), '') != ''
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
	// clause, rows whose cleave_result has no fs entry with dp=0 (or whose
	// dp=0 entry has empty 'f') match the gate, get UPDATEd to elements='' as
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
					json_extract(je.value, '$.f') AS f,
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
	_, err := db.lite.ExecContext(ctx, `
		UPDATE samples SET skip = ?, updated_at = ? WHERE sha256 = ?`,
		skip, now(), sha256)
	if err != nil {
		return fmt.Errorf("hopper: set skip: %w", err)
	}
	return nil
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
				MAX(path LIKE 'bad/%')  AS in_bad,
				MAX(path LIKE 'good/%') AS in_good
			FROM walk_staging
			GROUP BY sha256
		)
		SELECT s.sha256, s.label, s.skip,
			CASE WHEN p.in_bad = 1 THEN 'bad'
			     WHEN p.in_good = 1 THEN 'good'
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

func (db *DB) feedSamplesSQLite(ctx context.Context, q FeedQuery) ([]*Sample, error) {
	where, args := q.whereSQLite()
	query := `SELECT ` + liteSampleCols + ` FROM samples ` + where + //nolint:gosec // built from fixed query fragments and validated sort key.
		` ORDER BY ` + q.sortBy() + ` LIMIT ? OFFSET ?`
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
		// Match either schema: legacy `class` field, or v6 `l`-derived. Mirror
		// prism's envelopeClass / the scan query above: class first; else derive
		// from l using the cutoff `?` (null is manual-mode hostile/2; -1 benign/0;
		// 0..=cutoff hostile/2; above cutoff suspicious/1). The cutoff `?` precedes
		// the IN(...) placeholders in the SQL, so its arg is appended first.
		args = append(args, q.criticalLevel())
		for i := range q.LitmusClasses {
			args = append(args, q.LitmusClasses[i])
		}
		clauses = append(clauses,
			"COALESCE(CAST(json_extract(litmus_result, '$.class') AS INTEGER), "+
				"CASE WHEN litmus_result IS NULL THEN 0 "+
				"WHEN json_extract(litmus_result, '$.l') IS NULL THEN 2 "+
				"WHEN CAST(json_extract(litmus_result, '$.l') AS INTEGER) < 0 THEN 0 "+
				"WHEN CAST(json_extract(litmus_result, '$.l') AS INTEGER) <= ? THEN 2 "+
				"ELSE 1 END) "+
				"IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.RequireLitmus {
		clauses = append(clauses, "litmus_result IS NOT NULL")
	}

	if q.TopLevelOnly {
		clauses = append(clauses, "parent = ''")
	}

	if q.Formula != "" {
		clauses = append(clauses, "formula = ?")
		args = append(args, q.Formula)
	}

	// SQLite LIKE is case-insensitive for ASCII, matching the filename intent;
	// sha256 is stored lowercase and the term is lowercased in searchTerm.
	if term := q.searchTerm(); term != "" {
		clauses = append(clauses,
			`(filename LIKE '%' || ? || '%' ESCAPE '\' OR sha256 LIKE ? || '%' ESCAPE '\')`)
		args = append(args, term, term)
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
			ORDER BY sha256
			LIMIT ?
		),
		wrapped AS (
			SELECT sha256, path, size_bytes, file_type, 1 AS pass
			FROM samples
			WHERE sha256 < ?
			  AND cleave_result IS NULL AND skip = '' AND parent = ''
			  AND (note = '' OR last_error_at IS NULL OR last_error_at < ?)
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
		LIMIT ?`, pivot, startCutoff, limit, pivot, startCutoff, limit, limit)
}

// forcedRescanCandidatesSQLite mirrors forcedRescanCandidatesPG: Tier 0
// operator-requested rescans, oldest first.
func (db *DB) forcedRescanCandidatesSQLite(ctx context.Context, limit int) ([]ClaimJob, error) {
	return queryLiteCandidates(ctx, db.lite, `
		SELECT sha256, path, size_bytes, file_type FROM samples
		WHERE forced_rescan_at IS NOT NULL
		  AND skip = '' AND parent = ''
		ORDER BY forced_rescan_at ASC
		LIMIT ?`, limit)
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
