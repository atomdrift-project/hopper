package hopper

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// replicaPolicyFS embeds the operator-facing shell files that define a logical
// replica's index policy. They are embedded rather than mirrored in Go so there
// is exactly one source of truth: the file the operator edits is the file that
// slim-indexes.sh executes, that TestReplicaIndexPolicyIsComplete guards, and
// that migrateServingPG consults before building an index.
//
// Mirroring the lists in Go instead would reintroduce the drift the allowlist
// was created to kill — a name added to one copy and not the other is exactly
// the silent divergence that left 16 never-scanned indexes queued for a replica
// on 2026-08-20.
//
//go:embed scripts/replica/slim-indexes.sh scripts/replica/replicated-tables.sh
var replicaPolicyFS embed.FS

// createIndexRE matches the CREATE INDEX forms hopper's migration list uses,
// capturing the index name and the table it targets.
var createIndexRE = regexp.MustCompile(
	`(?is)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([a-z0-9_]+)\s+ON\s+(?:public\.)?([a-z0-9_]+)`)

// parseShellWordList extracts the whitespace-separated words from a single
// NAME='...' shell assignment. Both policy files use that one shape — the
// index lists one name per line, REPLICATED_TABLES all on one line — and
// strings.FieldsSeq flattens either. Matching on NAME=' (with the quote) is what
// keeps a prose mention of the variable in a comment from being parsed as the
// assignment itself.
func parseShellWordList(src, name string) (map[string]bool, error) {
	open := name + "='"
	_, rest, found := strings.Cut(src, open)
	if !found {
		return nil, fmt.Errorf("hopper: %s not found in replica policy", name)
	}
	body, _, found := strings.Cut(rest, "'")
	if !found {
		return nil, fmt.Errorf("hopper: %s is not closed by a single quote", name)
	}
	out := map[string]bool{}
	for word := range strings.FieldsSeq(body) {
		out[word] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hopper: %s parsed as empty", name)
	}
	return out, nil
}

// parseReplicaPolicyFile reads one embedded policy file and pulls a list from it.
func parseReplicaPolicyFile(path, name string) (map[string]bool, error) {
	src, err := replicaPolicyFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hopper: read %s: %w", path, err)
	}
	return parseShellWordList(string(src), name)
}

const (
	slimIndexesPath      = "scripts/replica/slim-indexes.sh"
	replicatedTablesPath = "scripts/replica/replicated-tables.sh"
)

// replicaKeepIndexes is the allowlist: indexes a prism read path needs on the
// replica. Anything else on a published table is dead weight there, because a
// logical replica maintains every index on every applied row change.
var replicaKeepIndexes = sync.OnceValues(func() (map[string]bool, error) {
	return parseReplicaPolicyFile(slimIndexesPath, "REPLICA_KEEP_INDEXES")
})

// replicaDropIndexes drives no behaviour — it exists so the completeness guard
// can prove every index was classified deliberately rather than by omission.
var replicaDropIndexes = sync.OnceValues(func() (map[string]bool, error) {
	return parseReplicaPolicyFile(slimIndexesPath, "REPLICA_DROP_INDEXES")
})

// replicaPublishedTables is the table set in the hopper_replica publication.
// An index on any other table costs a subscriber nothing — apply only maintains
// indexes on tables it actually receives rows for — so the policy deliberately
// says nothing about them, and a replica still builds them normally.
var replicaPublishedTables = sync.OnceValues(func() (map[string]bool, error) {
	return parseReplicaPolicyFile(replicatedTablesPath, "REPLICATED_TABLES")
})

// replicaSkipsIndexDDL reports whether ddl builds a secondary index that a
// logical replica does not need, so a replica-mode migration can decline to
// build it in the first place.
//
// Before this existed the same index was built and then dropped on every
// `make replica`: setup.sh runs `hopper init` (which applies the full canonical
// index set, because init has no notion of a replica) and only later runs
// slim-indexes.sh to drop everything outside the allowlist. On a replica whose
// sample_locations is hundreds of GB that round trip is not free — on
// 2026-08-21 it was actively consuming a filesystem with 631 MB left, and the
// resulting ENOSPC broke apply and disabled the subscription.
//
// Only non-unique CREATE INDEX is filtered. Primary keys and unique
// constraints arrive as table DDL, never as a bare CREATE INDEX, so the replica
// identity an apply worker needs can never be skipped by this path. DROP INDEX
// statements are likewise untouched: a migration that retires an index must
// still retire it here.
//
// CREATE UNIQUE INDEX is refused explicitly even though no migration uses one
// today. A unique index carries a correctness guarantee, not just a lookup
// path, so declining it would silently let a replica accept rows the master
// would reject — a different and much worse failure than a slow query. If one
// is ever added, this policy must not be what decides to drop it.
func replicaSkipsIndexDDL(ddl string) (bool, error) {
	trimmed := strings.TrimSpace(ddl)
	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "CREATE ") || strings.HasPrefix(upper, "CREATE UNIQUE ") {
		return false, nil
	}
	match := createIndexRE.FindStringSubmatch(trimmed)
	if match == nil {
		return false, nil
	}
	name, table := match[1], match[2]

	published, err := replicaPublishedTables()
	if err != nil {
		return false, err
	}
	if !published[table] {
		return false, nil
	}

	keep, err := replicaKeepIndexes()
	if err != nil {
		return false, err
	}
	return !keep[name], nil
}

// SetReplicaIndexPolicy makes subsequent migrations skip secondary indexes that
// a logical replica does not need — the allowlist in
// scripts/replica/slim-indexes.sh decides. Off by default: a primary must build
// its full index set.
//
// A skipped statement is deliberately NOT recorded in the migration ledger. It
// was declined, not applied, so promote.sh (or any later run without this set)
// still builds it. Recording it would leave a promoted replica permanently
// missing the master's write-path indexes with nothing to indicate why.
func (db *DB) SetReplicaIndexPolicy(on bool) { db.replicaIndexPolicy = on }

// skipReplicaIndex applies replicaSkipsIndexDDL only when replica mode is on.
func (db *DB) skipReplicaIndex(ddl string) (bool, error) {
	if !db.replicaIndexPolicy {
		return false, nil
	}
	return replicaSkipsIndexDDL(ddl)
}
