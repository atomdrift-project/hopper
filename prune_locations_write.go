package hopper

import (
	"context"
	"slices"
	"strconv"
	"strings"
)

type pruneSample struct{ SHA, Path, Parent, Skip, Label, Source string }

func (db *DB) deletePruneLocations(
	ctx context.Context, observed []pruneLocation, capMode bool, keepers []pruneLocation, c *pruneChecker, opts LocationPruneOptions,
) (deleted, protected int64, err error) {
	if len(observed) == 0 {
		return 0, 0, nil
	}
	err = db.locationTransaction(ctx, func(tx locationSQLTx) error {
		samples := map[string]pruneSample{}
		// Lock content rows before deleting locations. Every primary-path repair is
		// conditional on the exact row actually removed, never an old client snapshot.
		query := `SELECT sha256,path,parent,skip,label,label_source FROM samples
   WHERE sha256 IN (SELECT sha256 FROM sample_locations WHERE id IN (` + pruneIDList(observed) + `))
   ORDER BY sha256 FOR UPDATE`
		if err := tx.query(query, nil, func(rows locationRows) error {
			for rows.Next() {
				var s pruneSample
				if err := rows.Scan(&s.SHA, &s.Path, &s.Parent, &s.Skip, &s.Label, &s.Source); err != nil {
					return err
				}
				samples[s.SHA] = s
			}
			return rows.Err()
		}); err != nil {
			return err
		}
		eligible := make([]pruneLocation, 0, len(observed))
		for _, l := range observed {
			sample := samples[l.SHA]
			limit := locationLabelCap(sample.Label, sample.Skip, sample.Source, opts)
			if capMode && !capLabelSelected(sample.Label, opts) {
				limit = 0
			}
			if capMode && (limit == 0 || limit > opts.MaxPaths || sample.Path == l.Path) {
				protected++
				continue
			}
			eligible = append(eligible, l)
		}
		if !capMode {
			ids := make([]int64, len(eligible))
			for i, l := range eligible {
				ids[i] = l.ID
			}
			if err := retirePruneArchivePaths(tx, db.pool != nil, ids, make([]string, len(eligible)), db.locationTimestamp()); err != nil {
				return err
			}
		}
		removed, err := db.deletePruneRows(tx, eligible, capMode)
		if err != nil {
			return err
		}
		deleted = int64(len(removed))
		affected := map[string]pruneArchiveGroup{}
		for _, l := range removed {
			if l.Parent != "" && strings.Contains(l.Path, "!!") && Rel(l.Rel).IsContainment() {
				outer, _, _ := strings.Cut(l.Path, "!!")
				g := pruneArchiveGroup{SHA: l.SHA, Parent: l.Parent, Outer: outer}
				affected[g.key()] = g
			}
			s, ok := samples[l.SHA]
			if !ok || s.Path != l.Path {
				continue
			}
			replacement, err := pruneReplacement(tx, s.SHA, keepers, c)
			if err != nil {
				return err
			}
			if err := db.repairPrunedPrimary(tx, s, replacement); err != nil {
				return err
			}
		}
		if !capMode {
			// Ordinary missing rows pay one batched lookup; only existing per-file
			// markers need a bounded occupancy check after a slot is freed.
			marked, err := db.pruneMarkedGroups(tx, affected)
			if err != nil {
				return err
			}
			for _, group := range marked {
				if err := refreshLocationCapMarker(tx, group, opts); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	for _, l := range observed {
		db.forgetSHA(l.SHA)
	}
	return deleted, protected, nil
}

func (db *DB) deletePruneRows(tx locationSQLTx, rows []pruneLocation, capMode bool) ([]pruneLocation, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	byID := map[int64]pruneLocation{}
	ids := make([]int64, len(rows))
	shas := make([]string, len(rows))
	paths := make([]string, len(rows))
	for i, l := range rows {
		byID[l.ID] = l
		ids[i] = l.ID
		shas[i] = l.SHA
		paths[i] = l.Path
	}
	var deleted []pruneLocation
	scan := func(result locationRows) error {
		for result.Next() {
			var id int64
			if err := result.Scan(&id); err != nil {
				return err
			}
			deleted = append(deleted, byID[id])
		}
		return result.Err()
	}
	if db.pool != nil {
		// One network round trip, driven by primary keys. SHA and path are a CAS
		// against concurrent in-place path repairs; a changed row is left alone.
		err := tx.query(`WITH victims AS (
   SELECT v.id,v.sha256,v.path FROM unnest($1::bigint[],$2::text[],$3::text[]) AS v(id,sha256,path))
   DELETE FROM sample_locations l USING victims v
   WHERE l.id=v.id AND l.sha256=v.sha256 AND l.path=v.path
 AND (NOT $4 OR (l.parent_sha256<>'' AND l.rel IN `+containmentRelsSQL+` AND l.path LIKE '%!!%'))
 RETURNING l.id`, []any{ids, shas, paths, capMode}, scan)
		return deleted, err
	}
	for _, l := range rows {
		if err := tx.query(`DELETE FROM sample_locations
 WHERE id=$1 AND sha256=$2 AND path=$3
 AND (NOT $4 OR (`+pruneInFileSQL+`)) RETURNING id`, []any{l.ID, l.SHA, l.Path, capMode}, scan); err != nil {
			return nil, err
		}
	}
	return deleted, nil
}

func pruneReplacement(tx locationSQLTx, sha string, keepers []pruneLocation, c *pruneChecker) (pruneLocation, error) {
	for _, l := range keepers {
		if l.SHA != sha || !Rel(l.Rel).IsContainment() || c.check(l.Path, true) != prunePresent {
			continue
		}
		var exists bool
		err := tx.query(`SELECT EXISTS(
 SELECT 1 FROM sample_locations WHERE id=$1 AND sha256=$2 AND path=$3)`, []any{l.ID, sha, l.Path}, func(rows locationRows) error {
			if rows.Next() {
				return rows.Scan(&exists)
			}
			return rows.Err()
		})
		if err != nil {
			return pruneLocation{}, err
		}
		if exists {
			return l, nil
		}
	}
	var chosen pruneLocation
	for _, predicate := range []string{`parent_sha256 = ''`, `parent_sha256 <> '' AND rel IN ` + containmentRelsSQL} {
		err := tx.query(`SELECT `+pruneLocationColumns+` FROM sample_locations
 WHERE sha256=$1 AND `+predicate, []any{sha}, func(rows locationRows) error {
			for rows.Next() {
				l, err := scanPruneLocation(rows)
				if err != nil {
					return err
				}
				if !Rel(l.Rel).IsContainment() || c.check(l.Path, false) != prunePresent {
					continue
				}
				if c.check(l.Path, true) == prunePresent {
					chosen = l
					break
				}
			}
			return rows.Err()
		})
		if err != nil {
			return chosen, err
		}
		if chosen.Path != "" {
			return chosen, nil
		}
	}
	return chosen, nil
}

func (db *DB) repairPrunedPrimary(tx locationSQLTx, s pruneSample, replacement pruneLocation) error {
	stamp := db.locationTimestamp()
	if replacement.Path == "" && s.Skip == "" {
		if err := tx.exec(`INSERT INTO label_events(sha256,from_label,to_label,from_skip,to_skip,reason,observed_at)
   SELECT sha256,label,label,skip,'missing','prune-missing',$2 FROM samples WHERE sha256=$1`, s.SHA, stamp); err != nil {
			return err
		}
	}
	return tx.exec(`UPDATE samples SET path=$2,parent=$3,
  skip=CASE WHEN $2='' AND skip='' THEN 'missing' ELSE skip END,
  skipped_at=CASE WHEN $2='' AND skip='' THEN $4 ELSE skipped_at END,
  updated_at=$4 WHERE sha256=$1`, s.SHA, replacement.Path, replacement.Parent, stamp)
}

func (db *DB) pruneMarkedGroups(tx locationSQLTx, affected map[string]pruneArchiveGroup) ([]pruneArchiveGroup, error) {
	keys := make([]string, 0, len(affected))
	for key := range affected {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(keys) == 0 {
		return nil, nil
	}
	predicate := "key=ANY($1::text[])"
	args := []any{keys}
	if db.pool == nil {
		predicate = "key IN (" + strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",") + ")"
		args = make([]any, len(keys))
		for i, key := range keys {
			args[i] = key
		}
	}
	var out []pruneArchiveGroup
	err := tx.query(`SELECT key FROM hopper_kv WHERE `+predicate, args, func(rows locationRows) error {
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				return err
			}
			out = append(out, affected[key])
		}
		return rows.Err()
	})
	return out, err
}

// locationAdmissionSQL suppresses new contained observations for a capped SHA.
// Physical paths, reference edges and existing rows remain eligible. SQLite
// binds the marker key as parameter 10.
func locationAdmissionSQL(sha, path, parent, rel string, postgres bool) string {
	exact := `sl.sha256=` + sha + ` AND sl.path=` + path
	key := "?10"
	hasBoundary := "instr(" + path + ",'!!')"
	if postgres {
		exact += ` AND path_key(sl.path)=path_key(` + path + `)`
		key = "'" + locationCapPrefix + "'||" + sha
		hasBoundary = "strpos(" + path + ",'!!')"
	}
	return `(` + parent + `='' OR ` + rel + ` NOT IN ` + containmentRelsSQL + ` OR ` + hasBoundary + `=0
 OR NOT EXISTS(SELECT 1 FROM hopper_kv k JOIN samples s ON s.sha256=` + sha + ` AND k.value=CAST(s.id AS TEXT)||'/'||s.label
 AND s.label IN ('good','unknown') AND s.skip<>'conflict' AND s.label_source<>'conflict'
 WHERE k.key=` + key + `)
 OR EXISTS(SELECT 1 FROM sample_locations sl WHERE ` + exact + `)
 OR EXISTS(SELECT 1 FROM samples p WHERE p.sha256=` + sha + ` AND p.path=` + path + `))`
}

// prepareLocationCapPolicy changes the configured retention limit atomically.
// Raising a cap releases old admission markers so new observations can fill it.
func (db *DB) prepareLocationCapPolicy(ctx context.Context, opts LocationPruneOptions) error {
	policy := strconv.Itoa(opts.GoodMaxPaths) + "/" + strconv.Itoa(opts.UnknownMaxPaths) + "/v4"
	return db.locationTransaction(ctx, func(tx locationSQLTx) error {
		const key = "location-member-cap-policy"
		if err := tx.exec(`INSERT INTO hopper_kv(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING`, key, policy); err != nil {
			return err
		}
		var previous string
		if err := tx.query(`SELECT value FROM hopper_kv WHERE key=$1 FOR UPDATE`, []any{key}, func(rows locationRows) error {
			if rows.Next() {
				return rows.Scan(&previous)
			}
			return rows.Err()
		}); err != nil {
			return err
		}
		if previous == policy {
			return nil
		}
		if err := tx.exec(`DELETE FROM hopper_kv WHERE key LIKE 'location-member-cap/%'`); err != nil {
			return err
		}
		return tx.exec(`UPDATE hopper_kv SET value=$2 WHERE key=$1`, key, policy)
	})
}
