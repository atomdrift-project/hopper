package hopper

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// replicaPublishedTables are the tables in the 'hopper_replica' publication.
// An index on any other table never costs a subscriber anything — apply only
// maintains indexes on tables it actually receives rows for — so the replica
// index policy deliberately says nothing about them.
//
// Keep in sync with the publication (scripts/replica/setup.sh); a table added
// there needs its indexes classified here too.
var replicaPublishedTables = map[string]bool{
	"samples":          true,
	"sample_locations": true,
	"reports":          true,
	"sightings":        true,
}

// createIndexRE matches the CREATE INDEX forms hopper's migration list uses,
// capturing the index name and the table it targets.
var createIndexRE = regexp.MustCompile(
	`(?is)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([a-z0-9_]+)\s+ON\s+(?:public\.)?([a-z0-9_]+)`)

// TestReplicaIndexPolicyIsComplete fails when hopper gains an index on a
// published table that scripts/replica/slim-indexes.sh does not classify.
//
// The replica keeps an intentionally minimal index set: on a logical replica
// every applied row change maintains every index, so a master-only index is
// pure apply-throughput tax. slim-indexes.sh enforces that with an allowlist —
// anything not in REPLICA_KEEP_INDEXES is dropped — which means a new index is
// SAFE by default but also silently absent from the replica, and nobody is
// forced to think about whether prism needed it.
//
// This test is where that thought is forced. Every index on a published table
// must appear in exactly one of the two lists: REPLICA_KEEP_INDEXES (a prism
// read path needs it) or REPLICA_DROP_INDEXES (it is master-only). The second
// list drives no behaviour; it exists so the decision is recorded at the moment
// the index is written, by the person who knows the answer, instead of being
// rediscovered months later by diffing two catalogs.
//
// This is the same guard shape as TestCleaveTriggerKnowsAllTraitKeys.
func TestReplicaIndexPolicyIsComplete(t *testing.T) {
	keep, drop := parseReplicaIndexPolicy(t)

	stmts := append(pgRuntimeMigrations(), trgmIndexDDL)
	seen := map[string]bool{}
	var unclassified []string

	for _, stmt := range stmts {
		for _, m := range createIndexRE.FindAllStringSubmatch(stmt, -1) {
			name, table := m[1], m[2]
			if !replicaPublishedTables[table] || seen[name] {
				continue
			}
			seen[name] = true
			if !keep[name] && !drop[name] {
				unclassified = append(unclassified, name+" (on "+table+")")
			}
		}
	}

	if len(seen) == 0 {
		t.Fatal("parsed no CREATE INDEX statements on published tables — the regex or the migration list changed shape")
	}

	sort.Strings(unclassified)
	for _, name := range unclassified {
		t.Errorf("index %s is not classified in scripts/replica/slim-indexes.sh — "+
			"add it to REPLICA_KEEP_INDEXES if a prism read path needs it on the replica, "+
			"otherwise to REPLICA_DROP_INDEXES", name)
	}

	// A name in both lists is ambiguous: the keep list wins at runtime, so the
	// drop entry is a stale leftover that misrepresents the policy.
	for name := range keep {
		if drop[name] {
			t.Errorf("index %q is in BOTH REPLICA_KEEP_INDEXES and REPLICA_DROP_INDEXES — "+
				"remove the REPLICA_DROP_INDEXES entry; the keep list is what runs", name)
		}
	}

	// Entries naming an index hopper no longer creates are dead weight that
	// makes the policy look more considered than it is.
	for _, list := range []struct {
		name  string
		items map[string]bool
	}{{"REPLICA_KEEP_INDEXES", keep}, {"REPLICA_DROP_INDEXES", drop}} {
		for name := range list.items {
			if !seen[name] {
				t.Errorf("%s names %q, which hopper no longer creates on a published table — remove it", list.name, name)
			}
		}
	}
}

// parseReplicaIndexPolicy reads the two shell lists out of slim-indexes.sh.
// Parsing the script rather than duplicating the names in Go keeps one source
// of truth: the file the operator actually edits is the file under test.
func parseReplicaIndexPolicy(t *testing.T) (keep, drop map[string]bool) {
	t.Helper()
	const path = "scripts/replica/slim-indexes.sh"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	keep = parseShellIndexList(t, string(src), "REPLICA_KEEP_INDEXES")
	drop = parseShellIndexList(t, string(src), "REPLICA_DROP_INDEXES")
	return keep, drop
}

// parseShellIndexList extracts NAME='\n a \n b \n' single-quoted list bodies.
func parseShellIndexList(t *testing.T, src, name string) map[string]bool {
	t.Helper()
	open := name + "='"
	_, rest, found := strings.Cut(src, open)
	if !found {
		t.Fatalf("%s not found in slim-indexes.sh", name)
	}
	body, _, found := strings.Cut(rest, "'")
	if !found {
		t.Fatalf("%s is not closed by a single quote", name)
	}
	out := map[string]bool{}
	for line := range strings.FieldsSeq(body) {
		out[line] = true
	}
	if len(out) == 0 {
		t.Fatalf("%s parsed as empty", name)
	}
	return out
}
