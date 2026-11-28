package hopper

// SetReplicaIndexPolicy marks a database as a logical replica's: migrations
// then leave out the primary-only index DDL (pgPrimaryIndexMigrations). Off by
// default: a primary must build its own.
//
// It concerns the legacy tables alone. Since 2026-11-15 a replica copies the
// verdict schema (scripts/replica/replicated-tables.sh) and carries every
// index store/schema.sql defines; nothing here builds or declines those.
//
// Until 2026-11-28 it also built the replica-only training indexes
// idx_samples_training_hash and idx_samples_labeled_route on public.samples,
// for collimator. Collimator has read the verdict schema since the
// migration, where store/schema.sql's samples_labeled_route serves its
// per-route pass on every database, and the legacy tables no longer
// replicate, so a fresh replica no longer builds them.
func (db *DB) SetReplicaIndexPolicy(on bool) { db.replicaIndexPolicy = on }

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
		return migrations
	}
	return append(migrations, pgPrimaryIndexMigrations()...)
}
