package hopper

import (
	_ "embed"
	"strings"
)

// SetReplicaIndexPolicy selects the index set of a database that is a logical
// replica's: migrations then build the training indexes only a replica
// carries (pgReplicaTrainingMigrations) instead of the primary-only ones
// (pgPrimaryIndexMigrations). Off by default: a primary must build its own.
//
// It concerns the legacy tables alone. Since 2026-11-15 a replica copies the
// verdict schema (scripts/replica/replicated-tables.sh) and carries every
// index store/schema.sql defines; nothing here builds or declines those.
func (db *DB) SetReplicaIndexPolicy(on bool) { db.replicaIndexPolicy = on }

// replicaTrainingIndexDDL holds the indexes only collimator reads, and
// collimator reads only the replica. Keep them out of the primary's migration
// list: only a replica trains models.
//
// idx_samples_training_hash serves the deterministic hash-sampled runs; its
// projection is covered so repeated 1-2% iterations need not scan the heap.
// idx_samples_labeled_route serves the per-route training-set export
//
//	SELECT id, sha256, label, canonical_sha256, score, file_type FROM samples
//	 WHERE label IN ('bad','good') AND cleave_result IS NOT NULL AND skip = ''
//	   AND id <= <snapshot> AND file_type = ANY(<route>) ORDER BY id
//
// (collimator data.py, stream_partitioned_metadata_grouped; its LABELED_WHERE
// is the predicate verbatim). Without it each route was a Parallel Seq Scan of
// ~93M rows, ~100 seconds, measured 2026-08-24. It moved here from the shared
// list on 2026-10-23: no primary scan since 2026-09-16.
//
// One statement per semicolon, and no SQL comments. Spell each as
// CREATE INDEX IF NOT EXISTS, never CONCURRENTLY: hopper defers that spelling
// and rewrites it to a concurrent build outside a transaction, while an
// explicit CONCURRENTLY runs inside one and fails (SQLSTATE 25001).
//
//go:embed scripts/replica/training-index.sql
var replicaTrainingIndexDDL string

// Partial-index expression statistics do not give these route queries a usable
// selectivity estimate. Table-level expression statistics prevent the planner
// from treating a 1% sample as one third of the corpus.
//
//go:embed scripts/replica/training-statistics.sql
var replicaTrainingStatisticsDDL string

func pgReplicaTrainingMigrations() []string {
	var out []string
	for stmt := range strings.SplitSeq(replicaTrainingIndexDDL, ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, stmt+";")
		}
	}
	return append(out, strings.TrimSpace(replicaTrainingStatisticsDDL), "ANALYZE public.samples")
}

// pgPrimaryIndexMigrations holds index DDL that only the primary runs. The
// migration ledger is not replicated, so this must not run on the replica.
//
// idx_sl_location_key enforces sample_locations' (sha256, path) uniqueness
// and is the arbiter every location upsert names. It replaced the constraint
// sample_locations_sha256_path_key, which keyed on the raw path (181 bytes
// on average): 509 GB freshly built against 1,651 GB, at 4.1B rows on
// 2026-11-02. It is primary-only because a logical replica replays rows the
// primary has already made unique and reads nothing through it: galadriel
// had dropped the old constraint and recorded no sample_locations query from
// 2026-10-28 through 2026-11-02.
//
// It is core DDL, not deferred (see isDeferrableIndexDDL): the upserts name
// it, so a fresh database must have it before serving. The previous release
// built it in the background on the established primary, where the ledger
// now skips it. The old constraint is dropped after it, in the deferred
// phase, so uniqueness is never left unenforced.
//
// Any other binary that writes locations through this package (forager)
// must run a version with the path_key arbiters before this drop lands:
// ON CONFLICT (sha256, path) fails once the old constraint is gone.
func pgPrimaryIndexMigrations() []string {
	return []string{
		`DROP INDEX IF EXISTS idx_samples_labeled_route`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sl_location_key ON sample_locations (sha256, path_key(path))`,
		`ALTER TABLE sample_locations DROP CONSTRAINT IF EXISTS sample_locations_sha256_path_key`,
	}
}

func (db *DB) pgMigrationsForRole() []string {
	migrations := pgRuntimeMigrations()
	if db.replicaIndexPolicy {
		return append(migrations, pgReplicaTrainingMigrations()...)
	}
	return append(migrations, pgPrimaryIndexMigrations()...)
}
