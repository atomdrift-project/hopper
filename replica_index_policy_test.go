package hopper

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestReplicatedTablesAreTheVerdictSchema fails when store/schema.sql gains a
// table that scripts/replica/replicated-tables.sh neither publishes nor
// names as unreplicated, or a list names one schema.sql no longer creates. A
// replica carries every verdict table except the unlogged ones, which a
// publication cannot carry, and those UNREPLICATED_TABLES names; a table left
// off both lists would be silently absent on the replica, and setup.sh
// reconciles the publication to exactly REPLICATED_TABLES.
func TestReplicatedTablesAreTheVerdictSchema(t *testing.T) {
	src, err := os.ReadFile("scripts/replica/replicated-tables.sh")
	if err != nil {
		t.Fatal(err)
	}
	tables := func(variable string) map[string]bool {
		t.Helper()
		_, rest, found := strings.Cut(string(src), "\n"+variable+"='")
		if !found {
			t.Fatalf("%s='...' not found in replicated-tables.sh", variable)
		}
		list, _, found := strings.Cut(rest, "'")
		if !found {
			t.Fatalf("%s is not closed by a single quote", variable)
		}
		names := map[string]bool{}
		for name := range strings.FieldsSeq(list) {
			if names[name] {
				t.Errorf("%s names %s twice", variable, name)
			}
			names[name] = true
		}
		return names
	}
	published, unpublished := tables("REPLICATED_TABLES"), tables("UNREPLICATED_TABLES")
	for name := range unpublished {
		if published[name] {
			t.Errorf("%s is both replicated and unreplicated", name)
		}
	}

	schema, err := os.ReadFile("store/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	logged := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^CREATE (UNLOGGED )?TABLE ([a-z0-9_]+)`).FindAllStringSubmatch(string(schema), -1) {
		if m[1] == "" {
			logged[m[2]] = true
		} else if published[m[2]] {
			t.Errorf("REPLICATED_TABLES names %s, which is UNLOGGED: a publication cannot carry it", m[2])
		}
	}
	if len(logged) == 0 {
		t.Fatal("parsed no CREATE TABLE from store/schema.sql — its shape changed")
	}
	for name := range logged {
		if !published[name] && !unpublished[name] {
			t.Errorf("store/schema.sql creates %s but REPLICATED_TABLES does not publish it, nor UNREPLICATED_TABLES leave it out", name)
		}
	}
	for name := range published {
		if !logged[name] {
			t.Errorf("REPLICATED_TABLES names %s, which store/schema.sql does not create", name)
		}
	}
	for name := range unpublished {
		if !logged[name] {
			t.Errorf("UNREPLICATED_TABLES names %s, which store/schema.sql does not create as a logged table", name)
		}
	}
}

// TestReplicaRoleOmitsPrimaryIndexes pins what the policy still decides: the
// primary-only DDL runs on a primary and never on a replica, and neither role
// builds the retired training indexes on the legacy public.samples.
func TestReplicaRoleOmitsPrimaryIndexes(t *testing.T) {
	for _, replica := range []bool{false, true} {
		db := &DB{}
		db.SetReplicaIndexPolicy(replica)
		joined := strings.Join(db.pgMigrationsForRole(), "\n")
		for _, ddl := range pgPrimaryIndexMigrations() {
			if strings.Contains(joined, ddl) == replica {
				t.Errorf("replica=%v: incorrect inclusion of %q", replica, ddl)
			}
		}
		for _, retired := range []string{"idx_samples_training_hash", "samples_training_hash_stats", "ANALYZE public.samples"} {
			if strings.Contains(joined, retired) {
				t.Errorf("replica=%v: migrations still name %s", replica, retired)
			}
		}
	}
}
