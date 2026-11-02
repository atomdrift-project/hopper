package hopper

import (
	"strings"
	"testing"
)

func TestConcurrentIndexDDL(t *testing.T) {
	for _, tt := range []struct {
		name string
		ddl  string
		want string
	}{
		{"plain", "CREATE INDEX IF NOT EXISTS idx_test ON samples(id)", "idx_test"},
		{"explicit concurrent", "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_test ON samples(id)", "idx_test"},
		{"unique", "CREATE UNIQUE INDEX IF NOT EXISTS idx_test ON samples(id)", "idx_test"},
		{"explicit concurrent unique", "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_test ON samples(id)", "idx_test"},
		{"embedded training index", strings.TrimSpace(replicaTrainingIndexDDL), "idx_samples_training_hash"},
		{"missing name", "CREATE INDEX IF NOT EXISTS ", ""},
		{"other migration", "ANALYZE samples", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := concurrentIndexDDL(tt.ddl)
			if got != tt.want || ok != (tt.want != "") {
				t.Fatalf("concurrentIndexDDL = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.want != "")
			}
		})
	}
}

// TestPGMigrationConcurrentIndexes builds indexes through the migration path
// twice each, checking the result is valid and recorded in the ledger. It
// runs the replica training indexes one statement at a time, exactly as
// pgReplicaTrainingMigrations splits them, plus an explicit CONCURRENTLY
// spelling, which concurrentIndexDDL must route outside a transaction too.
func TestPGMigrationConcurrentIndexes(t *testing.T) {
	db := openDisposablePG(t)
	ctx := t.Context()

	var stmts []string
	for _, ddl := range pgReplicaTrainingMigrations() {
		if _, ok := concurrentIndexDDL(ddl); ok {
			// Target this test's isolated schema.
			stmts = append(stmts, strings.ReplaceAll(ddl, "public.samples", "samples"))
		}
	}
	if len(stmts) == 0 {
		t.Fatal("pgReplicaTrainingMigrations yielded no index DDL")
	}
	stmts = append(stmts, `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_samples_explicit_concurrent ON samples (id)`)

	for _, ddl := range stmts {
		name, _ := concurrentIndexDDL(ddl)
		for range 2 {
			if err := db.execPGMigrationDDL(ctx, ddl, false); err != nil {
				t.Fatalf("migrate %s: %v", name, err)
			}
		}
		if _, exists, err := db.pgIndexDef(ctx, name); err != nil || !exists {
			t.Fatalf("%s missing: exists=%v err=%v", name, exists, err)
		}
		if invalid, err := db.invalidPGIndexPool(ctx, name); err != nil || invalid {
			t.Fatalf("%s invalid: invalid=%v err=%v", name, invalid, err)
		}
		if applied, err := db.pgMigrationApplied(ctx, migrationID(ddl)); err != nil || !applied {
			t.Fatalf("%s missing from ledger: applied=%v err=%v", name, applied, err)
		}
	}
}

// TestLocationKeyMigrationPhases pins the first half of the (sha256, path)
// uniqueness swap (see pgPrimaryIndexMigrations). The new index builds in
// the background, concurrently, on the primary only, and nothing drops the
// old constraint yet: forager's upserts still name it.
func TestLocationKeyMigrationPhases(t *testing.T) {
	var create string
	for _, ddl := range pgPrimaryIndexMigrations() {
		if strings.Contains(ddl, "idx_sl_location_key") {
			create = ddl
		}
	}
	if create == "" {
		t.Fatal("primary migrations do not build idx_sl_location_key")
	}
	if !isDeferrableIndexDDL(create) {
		t.Errorf("%q must build in the background; in the core phase it blocks startup for hours", create)
	}
	if _, ok := concurrentIndexDDL(create); !ok {
		t.Errorf("%q must build CONCURRENTLY; a plain build blocks every location write for hours", create)
	}
	for _, ddl := range append(pgRuntimeMigrations(), pgPrimaryIndexMigrations()...) {
		if strings.Contains(ddl, "DROP CONSTRAINT") && strings.Contains(ddl, "sample_locations_sha256_path_key") {
			t.Errorf("the old constraint must outlive every writer that names it as an arbiter: %q", ddl)
		}
	}
	for _, ddl := range pgRuntimeMigrations() {
		if strings.Contains(ddl, "idx_sl_location_key ON") {
			t.Errorf("idx_sl_location_key is in the shared list, so replicas would build it: %q", ddl)
		}
	}
}

// TestPGLocationKeyIndex checks the migrated sample_locations index set, and
// that upserts and exact-path probes work with both unique indexes present.
func TestPGLocationKeyIndex(t *testing.T) {
	db := openDisposablePG(t)
	ctx := t.Context()

	for _, name := range []string{"idx_sl_location_key", "sample_locations_sha256_path_key", "idx_sl_members"} {
		def, exists, err := db.pgIndexDef(ctx, name)
		if err != nil || !exists {
			t.Fatalf("%s missing after migrate: exists=%v err=%v", name, exists, err)
		}
		if name != "idx_sl_members" && !strings.Contains(def, "UNIQUE") {
			t.Errorf("%s is not unique: %s", name, def)
		}
	}
	if _, exists, err := db.pgIndexDef(ctx, "idx_sl_parent_child"); err != nil || exists {
		t.Errorf("idx_sl_parent_child should be gone after migrate: exists=%v err=%v", exists, err)
	}

	sha := strings.Repeat("ab", 32)
	if _, err := db.pool.Exec(ctx, `INSERT INTO samples (sha256, source, path) VALUES ($1, 'test', 'a/b')`, sha); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"", "fetched"} {
		if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, Path: "a/b", Rel: rel}); err != nil {
			t.Fatalf("upsert rel=%q: %v", rel, err)
		}
	}
	var n int
	var rel string
	if err := db.pool.QueryRow(ctx,
		`SELECT count(*), max(rel) FROM sample_locations WHERE sha256 = $1`, sha).Scan(&n, &rel); err != nil {
		t.Fatal(err)
	}
	if n != 1 || rel != "fetched" {
		t.Errorf("re-upserting one (sha256, path) gave %d rows, rel=%q; want 1 row, rel=%q", n, rel, "fetched")
	}

	first, second, err := db.TopLevelLocationsRecorded(ctx, sha, "a/b", "a/c")
	if err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Errorf("TopLevelLocationsRecorded = (%v, %v), want (true, false)", first, second)
	}
}
