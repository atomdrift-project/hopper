package hopper

import (
	"sort"
	"strings"
	"testing"
)

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
	keep, drop, published := mustReplicaPolicy(t)

	stmts := append(pgRuntimeMigrations(), trgmIndexDDL)
	seen := map[string]bool{}
	var unclassified []string

	for _, stmt := range stmts {
		for _, m := range createIndexRE.FindAllStringSubmatch(stmt, -1) {
			name, table := m[1], m[2]
			if !published[table] || seen[name] {
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

// TestReplicaIndexPolicyMatchesSlimIndexes is the behavioural half of the guard
// above. The completeness test proves every index is *classified*; this proves
// migrateServingPG's replica mode actually acts on that classification, so a
// replica declines exactly the set slim-indexes.sh would have dropped. If these
// two ever disagree, `make replica` is back to building indexes only to drop
// them — the round trip that filled galadriel's disk on 2026-08-21.
func TestReplicaIndexPolicyMatchesSlimIndexes(t *testing.T) {
	keep, drop, published := mustReplicaPolicy(t)

	checked := map[string]bool{}
	for _, stmt := range append(pgRuntimeMigrations(), trgmIndexDDL) {
		m := createIndexRE.FindStringSubmatch(strings.TrimSpace(stmt))
		if m == nil {
			continue
		}
		name, table := m[1], m[2]
		if !published[table] || checked[name] {
			continue
		}
		checked[name] = true

		skip, err := replicaSkipsIndexDDL(stmt)
		if err != nil {
			t.Fatalf("replicaSkipsIndexDDL(%q): %v", name, err)
		}
		switch {
		case keep[name] && skip:
			t.Errorf("index %q is in REPLICA_KEEP_INDEXES but replica mode declines to build it — "+
				"prism would read the replica without it", name)
		case drop[name] && !skip:
			t.Errorf("index %q is in REPLICA_DROP_INDEXES but replica mode still builds it — "+
				"slim-indexes.sh will drop it right after, which is the round trip this policy exists to avoid", name)
		}
	}
	if len(checked) == 0 {
		t.Fatal("checked no indexes — the migration list or regex changed shape")
	}
}

func TestReplicaSkipsIndexDDL(t *testing.T) {
	tests := []struct {
		name string
		ddl  string
		want bool
		why  string
	}{{
		name: "published table, not in keep list",
		ddl:  `CREATE INDEX IF NOT EXISTS idx_sl_standalone ON sample_locations(id) INCLUDE (sha256) WHERE parent_sha256 = ''`,
		want: true,
		why:  "master-only repair index; slim-indexes.sh drops it on the replica",
	}, {
		name: "published table, in keep list",
		ddl:  `CREATE INDEX IF NOT EXISTS idx_samples_purl_lookup ON samples(purl_base)`,
		want: false,
		why:  "prism's feed lookup reads this on the replica",
	}, {
		name: "unpublished table is none of the policy's business",
		ddl:  `CREATE INDEX IF NOT EXISTS idx_workers_seen ON workers(last_seen)`,
		want: false,
		why:  "apply never touches an unreplicated table, so its indexes cost the replica nothing",
	}, {
		name: "DROP INDEX is never declined",
		ddl:  `DROP INDEX IF EXISTS idx_samples_status`,
		want: false,
		why:  "a migration that retires an index must retire it on the replica too",
	}, {
		name: "non-index DDL is never declined",
		ddl:  `ALTER TABLE samples ADD COLUMN IF NOT EXISTS parent TEXT NOT NULL DEFAULT ''`,
		want: false,
	}, {
		name: "unique index is never declined",
		ddl:  `CREATE UNIQUE INDEX IF NOT EXISTS idx_samples_made_up ON samples(sha256)`,
		want: false,
		why:  "uniqueness is a correctness guarantee, not a lookup path",
	}, {
		name: "schema-qualified table still resolves",
		ddl:  `CREATE INDEX IF NOT EXISTS idx_samples_score ON public.samples(score) WHERE score != 0`,
		want: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := replicaSkipsIndexDDL(tt.ddl)
			if err != nil {
				t.Fatalf("replicaSkipsIndexDDL: %v", err)
			}
			if got != tt.want {
				t.Errorf("replicaSkipsIndexDDL = %v, want %v (%s)", got, tt.want, tt.why)
			}
		})
	}
}

// TestReplicaIndexPolicyOffByDefault pins the default: a DB that was never told
// it is a replica builds everything. Getting this backwards would quietly strip
// the master's write-path indexes on the next `hopper init`.
func TestReplicaIndexPolicyOffByDefault(t *testing.T) {
	db := &DB{}
	skip, err := db.skipReplicaIndex(
		`CREATE INDEX IF NOT EXISTS idx_sl_standalone ON sample_locations(id) WHERE parent_sha256 = ''`)
	if err != nil {
		t.Fatalf("skipReplicaIndex: %v", err)
	}
	if skip {
		t.Fatal("a DB with no replica policy set declined an index; the master would lose it")
	}

	db.SetReplicaIndexPolicy(true)
	skip, err = db.skipReplicaIndex(
		`CREATE INDEX IF NOT EXISTS idx_sl_standalone ON sample_locations(id) WHERE parent_sha256 = ''`)
	if err != nil {
		t.Fatalf("skipReplicaIndex: %v", err)
	}
	if !skip {
		t.Fatal("replica policy is on but the index was still built")
	}
}

// mustReplicaPolicy loads the three embedded lists or fails the test.
func mustReplicaPolicy(t *testing.T) (keep, drop, published map[string]bool) {
	t.Helper()
	var err error
	if keep, err = replicaKeepIndexes(); err != nil {
		t.Fatalf("REPLICA_KEEP_INDEXES: %v", err)
	}
	if drop, err = replicaDropIndexes(); err != nil {
		t.Fatalf("REPLICA_DROP_INDEXES: %v", err)
	}
	if published, err = replicaPublishedTables(); err != nil {
		t.Fatalf("REPLICATED_TABLES: %v", err)
	}
	return keep, drop, published
}
