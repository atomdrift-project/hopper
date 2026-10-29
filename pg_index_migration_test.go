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

func TestPGMigrationExplicitConcurrentIndex(t *testing.T) {
	db := openDisposablePG(t)
	ctx := t.Context()
	// Use the real replica DDL, targeting this test's isolated schema.
	ddl := strings.ReplaceAll(strings.TrimSpace(replicaTrainingIndexDDL), "public.samples", "samples")
	for range 2 {
		if err := db.execPGMigrationDDL(ctx, ddl, false); err != nil {
			t.Fatalf("migrate explicit concurrent index: %v", err)
		}
	}
	_, exists, err := db.pgIndexDef(ctx, "idx_samples_training_hash")
	if err != nil || !exists {
		t.Fatalf("training index missing: exists=%v err=%v", exists, err)
	}
	invalid, err := db.invalidPGIndexPool(ctx, "idx_samples_training_hash")
	if err != nil || invalid {
		t.Fatalf("training index invalid: invalid=%v err=%v", invalid, err)
	}
	applied, err := db.pgMigrationApplied(ctx, migrationID(ddl))
	if err != nil || !applied {
		t.Fatalf("migration missing from ledger: applied=%v err=%v", applied, err)
	}
}
