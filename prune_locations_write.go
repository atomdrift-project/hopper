package hopper

import (
	"context"
)

type pruneSample struct{ SHA, Path, Parent, Skip, Label, Source string }

func (db *DB) deletePruneLocations(
	ctx context.Context, observed []pruneLocation, c *pruneChecker,
) (deleted, protected int64, err error) {
	if len(observed) == 0 {
		return 0, 0, nil
	}
	err = db.locationTransaction(ctx, func(tx locationSQLTx) error {
		samples, err := pruneLockSamples(tx, observed)
		if err != nil {
			return err
		}
		var changed int64
		observed, changed, err = lockPruneObservations(tx, observed)
		if err != nil {
			return err
		}
		protected += changed
		eligible := observed
		// Recheck under the sample locks. Batches may span all remaining rows
		// of a relationship, so an EXISTS test must exclude the entire batch.
		var guarded int64
		eligible, guarded, err = protectPruneRelationships(tx, eligible, db.pool != nil)
		if err != nil {
			return err
		}
		protected += guarded
		ids := make([]int64, len(eligible))
		for i, l := range eligible {
			ids[i] = l.ID
		}
		if err := retirePruneArchivePaths(tx, db.pool != nil, ids, make([]string, len(eligible)), db.locationTimestamp()); err != nil {
			return err
		}
		removed, err := db.deletePruneRows(tx, eligible)
		if err != nil {
			return err
		}
		deleted = int64(len(removed))
		for _, l := range removed {
			s, ok := samples[l.SHA]
			if !ok || s.Path != l.Path {
				continue
			}
			replacement, err := pruneReplacement(tx, s.SHA, c)
			if err != nil {
				return err
			}
			if err := db.repairPrunedPrimary(tx, s, replacement); err != nil {
				return err
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

func pruneLockSamples(tx locationSQLTx, observed []pruneLocation) (map[string]pruneSample, error) {
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
		return nil, err
	}
	return samples, nil
}

func (db *DB) deletePruneRows(tx locationSQLTx, rows []pruneLocation) ([]pruneLocation, error) {
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
 RETURNING l.id`, []any{ids, shas, paths}, scan)
		return deleted, err
	}
	for _, l := range rows {
		if err := tx.query(`DELETE FROM sample_locations
 WHERE id=$1 AND sha256=$2 AND path=$3 RETURNING id`, []any{l.ID, l.SHA, l.Path}, scan); err != nil {
			return nil, err
		}
	}
	return deleted, nil
}

func pruneReplacement(tx locationSQLTx, sha string, c *pruneChecker) (pruneLocation, error) {
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
	missing := replacement.Path == ""
	if missing {
		// The last retained relationship can be obsolete too. Preserve its
		// denormalized parent pointer while marking the lack of usable bytes.
		for _, predicate := range []string{` AND parent_sha256<>''`, ``} {
			query := `SELECT ` + pruneLocationColumns + ` FROM sample_locations WHERE sha256=$1` + predicate + ` LIMIT 1`
			if err := tx.query(query, []any{s.SHA}, func(rows locationRows) error {
				if rows.Next() {
					var err error
					replacement, err = scanPruneLocation(rows)
					return err
				}
				return rows.Err()
			}); err != nil {
				return err
			}
			if replacement.Path != "" {
				break
			}
		}
	}
	if missing && s.Skip == "" {
		if err := tx.exec(`INSERT INTO label_events(sha256,from_label,to_label,from_skip,to_skip,reason,observed_at)
   SELECT sha256,label,label,skip,'missing','prune-missing',$2 FROM samples WHERE sha256=$1`, s.SHA, stamp); err != nil {
			return err
		}
	}
	return tx.exec(`UPDATE samples SET path=$2,parent=$3,
  skip=CASE WHEN $5 AND skip='' THEN 'missing' ELSE skip END,
  skipped_at=CASE WHEN $5 AND skip='' THEN $4 ELSE skipped_at END,
  updated_at=$4 WHERE sha256=$1`, s.SHA, replacement.Path, replacement.Parent, stamp, missing)
}
