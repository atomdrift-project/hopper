package hopper

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestReplicatedTablesAreTheVerdictSchema fails when store/schema.sql gains a
// table that scripts/replica/replicated-tables.sh does not publish, or the list
// names one schema.sql no longer creates. A replica carries every verdict
// table except the unlogged ones, which a publication cannot carry; a table
// left off the list would be silently absent on the replica, and setup.sh
// reconciles the publication to exactly this list.
func TestReplicatedTablesAreTheVerdictSchema(t *testing.T) {
	src, err := os.ReadFile("scripts/replica/replicated-tables.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(src), "\nREPLICATED_TABLES='")
	if !found {
		t.Fatal("REPLICATED_TABLES='...' not found in replicated-tables.sh")
	}
	list, _, found := strings.Cut(rest, "'")
	if !found {
		t.Fatal("REPLICATED_TABLES is not closed by a single quote")
	}
	published := map[string]bool{}
	for name := range strings.FieldsSeq(list) {
		if published[name] {
			t.Errorf("REPLICATED_TABLES names %s twice", name)
		}
		published[name] = true
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
		if !published[name] {
			t.Errorf("store/schema.sql creates %s but REPLICATED_TABLES does not publish it", name)
		}
	}
	for name := range published {
		if !logged[name] {
			t.Errorf("REPLICATED_TABLES names %s, which store/schema.sql does not create", name)
		}
	}
}

func TestTrainingHashIndexIsReplicaOnly(t *testing.T) {
	for _, name := range []string{"idx_samples_training_hash", "idx_samples_labeled_route"} {
		for _, replica := range []bool{false, true} {
			db := &DB{}
			db.SetReplicaIndexPolicy(replica)
			created := false
			for _, ddl := range db.pgMigrationsForRole() {
				if !strings.Contains(ddl, name) {
					continue
				}
				if strings.HasPrefix(ddl, "DROP ") {
					if replica {
						t.Errorf("replica role drops %s, which its readers need", name)
					}
					continue
				}
				created = true
				if _, ok := concurrentIndexDDL(ddl); !ok || !isDeferrableIndexDDL(ddl) {
					t.Errorf("%s is not a deferred concurrent build: %q", name, ddl)
				}
			}
			if created != replica {
				t.Errorf("replica=%v: %s created=%v", replica, name, created)
			}
		}
	}
}

func TestTrainingHashStatisticsAreReplicaOnly(t *testing.T) {
	for _, replica := range []bool{false, true} {
		db := &DB{}
		db.SetReplicaIndexPolicy(replica)
		joined := strings.Join(db.pgMigrationsForRole(), "\n")
		for _, marker := range []string{"samples_training_hash_stats", "ANALYZE public.samples"} {
			if strings.Contains(joined, marker) != replica {
				t.Errorf("replica=%v: incorrect inclusion of %s", replica, marker)
			}
		}
	}
}
