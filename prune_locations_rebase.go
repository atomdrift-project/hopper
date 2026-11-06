package hopper

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
)

// An archive moved outside the move lifecycle (or before member rebasing
// existed) leaves its members recorded under the old outer path. Their bytes
// are still reachable through the archive's live location, so the obsolete pass
// rewrites those rows onto it instead of discarding the only member edge and
// marking the sample missing.

// pruneParentLimit bounds the per-archive path lists read while planning.
const pruneParentLimit = 10000

type pruneRebase struct {
	loc     pruneLocation
	newPath string
}

type pruneParent struct {
	known map[string]bool // every recorded or retired path of the archive
	names map[string]bool // archive file names of those paths
	live  string          // a recorded path whose outer file exists; "" when none
}

// pruneArchiveName is the file name of the innermost archive in a path:
// "a/b.zip!!c/d.tgz" names "d.tgz".
func pruneArchiveName(path string) string {
	if i := strings.LastIndex(path, "!!"); i >= 0 {
		path = path[i+2:]
	}
	return filepath.Base(path)
}

func (p *pruneParent) remember(path string) {
	p.known[path] = true
	p.names[pruneArchiveName(path)] = true
}

// pruneParentInfo loads an archive's known paths and picks a live one,
// preferring physical copies, then the oldest observation. Results are cached
// per run; fresh re-verifies a cached live path before an apply relies on it.
func (db *DB) pruneParentInfo(ctx context.Context, sha string, c *pruneChecker, fresh bool) (*pruneParent, error) {
	if p, ok := c.parents[sha]; ok {
		if !fresh || p.live == "" || c.check(p.live, true) == prunePresent {
			return p, nil
		}
	}
	p := &pruneParent{known: map[string]bool{}, names: map[string]bool{}}
	var candidates []string
	err := db.queryLocations(ctx, `SELECT path FROM sample_locations
 WHERE sha256=$1 AND rel IN `+containmentRelsSQL+` AND path NOT LIKE '%://%'
 ORDER BY CASE WHEN parent_sha256='' THEN 0 ELSE 1 END, first_seen_at, id LIMIT $2`, []any{sha, pruneParentLimit},
		func(rows locationRows) error {
			for rows.Next() {
				var path string
				if err := rows.Scan(&path); err != nil {
					return err
				}
				p.remember(path)
				candidates = append(candidates, path)
			}
			return rows.Err()
		})
	if err != nil {
		return nil, err
	}
	err = db.queryLocations(ctx, `SELECT path FROM sample_location_history WHERE sha256=$1 LIMIT $2`, []any{sha, pruneParentLimit},
		func(rows locationRows) error {
			for rows.Next() {
				var path string
				if err := rows.Scan(&path); err != nil {
					return err
				}
				p.remember(path)
			}
			return rows.Err()
		})
	if err != nil {
		return nil, err
	}
	for _, path := range candidates {
		if c.check(path, fresh) == prunePresent {
			p.live = path
			break
		}
	}
	if c.parents == nil || len(c.parents) >= 4096 {
		c.parents = map[string]*pruneParent{}
	}
	c.parents[sha] = p
	return p, nil
}

// rebaseTarget maps a member path onto the archive's live path. The longest
// "!!" prefix that is a known path of the archive is the part to replace, which
// handles both immediate and outermost parent edges of nested members. Members
// recorded under a staging path the archive itself never had fall back to the
// longest prefix whose archive file name matches one of the archive's known
// names: the parent edge already identifies the archive by hash, so the name
// only selects which "!!" boundary is the archive's.
func (p *pruneParent) rebaseTarget(path string) (string, bool) {
	if p.live == "" {
		return "", false
	}
	for _, match := range []func(string) bool{
		func(prefix string) bool { return p.known[prefix] },
		func(prefix string) bool { return p.names[pruneArchiveName(prefix)] },
	} {
		for i := strings.LastIndex(path, "!!"); i > 0; i = strings.LastIndex(path[:i], "!!") {
			if match(path[:i]) {
				target := p.live + path[i:]
				return target, target != path
			}
		}
	}
	return "", false
}

// planObsoleteRebases splits absent rows into rebases (the archive still exists
// elsewhere), deletions (no live copy of the archive), and rows preserved
// because the archive is live but the old prefix cannot be mapped onto it.
func (db *DB) planObsoleteRebases(
	ctx context.Context, victims []pruneLocation, c *pruneChecker, fresh bool,
) (rebases []pruneRebase, deletes []pruneLocation, unmapped int64, err error) {
	for _, l := range victims {
		if l.Parent == "" || !Rel(l.Rel).IsContainment() || !strings.Contains(l.Path, "!!") {
			deletes = append(deletes, l)
			continue
		}
		parent, err := db.pruneParentInfo(ctx, l.Parent, c, fresh)
		if err != nil {
			return nil, nil, 0, err
		}
		if parent.live == "" {
			deletes = append(deletes, l)
			continue
		}
		target, ok := parent.rebaseTarget(l.Path)
		if !ok {
			unmapped++
			continue
		}
		rebases = append(rebases, pruneRebase{loc: l, newPath: target})
	}
	return rebases, deletes, unmapped, nil
}

// rebasePruneLocations moves member rows onto their archive's live path in one
// transaction. Each statement is a CAS on (id, sha256, path): a row changed by
// a concurrent move or ingest is left alone. An existing row at the target
// absorbs the rebase; the stale row is removed either way.
func (db *DB) rebasePruneLocations(ctx context.Context, rebases []pruneRebase) (int64, error) {
	if len(rebases) == 0 {
		return 0, nil
	}
	ids := make([]int64, len(rebases))
	shas := make([]string, len(rebases))
	olds := make([]string, len(rebases))
	news := make([]string, len(rebases))
	for i, r := range rebases {
		ids[i], shas[i], olds[i], news[i] = r.loc.ID, r.loc.SHA, r.loc.Path, r.newPath
	}
	locked := slices.Clone(shas)
	slices.Sort(locked)
	locked = slices.Compact(locked)
	var moved int64
	stamp := db.locationTimestamp()
	err := db.locationTransaction(ctx, func(tx locationSQLTx) error {
		count := func(rows locationRows) error {
			for rows.Next() {
				moved++
			}
			return rows.Err()
		}
		if err := retirePruneArchivePaths(tx, db.pool != nil, ids, news, stamp); err != nil {
			return err
		}
		if db.pool != nil {
			// Same lock order as deletePruneLocations: content rows by SHA. SQLite
			// write transactions are already serialized.
			if err := tx.query(`SELECT sha256 FROM samples WHERE sha256=ANY($1) ORDER BY sha256 FOR UPDATE`,
				[]any{locked}, func(rows locationRows) error {
					for rows.Next() {
					}
					return rows.Err()
				}); err != nil {
				return err
			}
			const victims = `unnest($1::bigint[],$2::text[],$3::text[],$4::text[]) AS v(id,sha256,path,new_path)`
			if err := tx.exec(`INSERT INTO sample_locations
  (sha256,path,parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at)
  SELECT l.sha256,v.new_path,l.parent_sha256,l.rel,l.filename,l.source,l.feed,l.ecosystem,l.mtime,l.first_seen_at,l.last_seen_at
  FROM `+victims+` JOIN sample_locations l ON l.id=v.id AND l.sha256=v.sha256 AND l.path=v.path
  ON CONFLICT DO NOTHING`, ids, shas, olds, news); err != nil {
				return err
			}
			if err := tx.exec(`UPDATE samples s SET path=v.new_path, updated_at=$5
  FROM `+victims+` WHERE s.sha256=v.sha256 AND s.path=v.path`, ids, shas, olds, news, stamp); err != nil {
				return err
			}
			return tx.query(`DELETE FROM sample_locations l USING `+victims+`
  WHERE l.id=v.id AND l.sha256=v.sha256 AND l.path=v.path RETURNING l.id`, []any{ids, shas, olds, news}, count)
		}
		for i := range rebases {
			if err := tx.exec(`INSERT INTO sample_locations
  (sha256,path,parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at)
  SELECT sha256,$4,parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at
  FROM sample_locations WHERE id=$1 AND sha256=$2 AND path=$3
  ON CONFLICT (sha256, path) DO NOTHING`, ids[i], shas[i], olds[i], news[i]); err != nil {
				return err
			}
			if err := tx.exec(`UPDATE samples SET path=$3, updated_at=$4 WHERE sha256=$1 AND path=$2`,
				shas[i], olds[i], news[i], stamp); err != nil {
				return err
			}
			if err := tx.query(`DELETE FROM sample_locations WHERE id=$1 AND sha256=$2 AND path=$3 RETURNING id`,
				[]any{ids[i], shas[i], olds[i]}, count); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, sha := range locked {
		db.forgetSHA(sha)
	}
	return moved, nil
}

// retirePruneArchivePaths records the obsolete pass's removed rows for SHAs that
// contain members, with the path they were rebased to (if any). Member prefixes
// stay mappable after the archive's own stale row is gone, including across
// resumed passes, and the archive path change can be audited. Reason 'prune' is
// never followed by ingest-time move reconciliation, which reads only 'move'.
// Leaf rows, the overwhelming majority, are not copied.
func retirePruneArchivePaths(tx locationSQLTx, postgres bool, ids []int64, successors []string, stamp any) error {
	if len(ids) == 0 {
		return nil
	}
	const columns = `(sha256,path,parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at,retired_at,reason,successor_path)`
	const container = `EXISTS(SELECT 1 FROM sample_locations m WHERE m.parent_sha256=l.sha256)`
	if postgres {
		return tx.exec(`INSERT INTO sample_location_history `+columns+`
  SELECT l.sha256,l.path,l.parent_sha256,l.rel,l.filename,l.source,l.feed,l.ecosystem,l.mtime,l.first_seen_at,l.last_seen_at,$3,'prune',v.successor
  FROM unnest($1::bigint[],$2::text[]) AS v(id,successor) JOIN sample_locations l ON l.id=v.id WHERE `+container,
			ids, successors, stamp)
	}
	for i, id := range ids {
		if err := tx.exec(`INSERT INTO sample_location_history `+columns+`
  SELECT l.sha256,l.path,l.parent_sha256,l.rel,l.filename,l.source,l.feed,l.ecosystem,l.mtime,l.first_seen_at,l.last_seen_at,$3,'prune',$2
  FROM sample_locations l WHERE l.id=$1 AND `+container, id, successors[i], stamp); err != nil {
			return err
		}
	}
	return nil
}
