package hopper

// lockPruneObservations compares the full observed edge under row locks.
// Ingest upserts need not acquire a sample lock before changing a relation.
func lockPruneObservations(tx locationSQLTx, observed []pruneLocation) ([]pruneLocation, int64, error) {
	if len(observed) == 0 {
		return observed, 0, nil
	}
	wanted := make(map[int64]pruneLocation, len(observed))
	for _, l := range observed {
		wanted[l.ID] = l
	}
	var valid []pruneLocation
	err := tx.query(`SELECT `+pruneLocationColumns+` FROM sample_locations
 WHERE id IN (`+pruneIDList(observed)+`) ORDER BY id FOR UPDATE`, nil, func(rows sqlRows) error {
		for rows.Next() {
			current, err := scanPruneLocation(rows)
			if err != nil {
				return err
			}
			old := wanted[current.ID]
			if current.SHA == old.SHA && current.Path == old.Path && current.Parent == old.Parent && current.Rel == old.Rel {
				valid = append(valid, current)
			}
		}
		return rows.Err()
	})
	return valid, int64(len(observed) - len(valid)), err
}

// protectPruneRelationships retains a canonical occurrence whenever a batch
// would remove the last relevant edge. Obsolete pruning may remove a vanished
// parent, but never the child's last parent edge (or a standalone sample's last
// observation).
//
// All probes use the existing SHA/parent indexes, stop at the first survivor,
// and exclude every proposed victim, including victims in other archive groups.
// Apply calls this with the sample rows locked; preview uses the same query
// without locks and remains an estimate in the presence of concurrent changes.
func protectPruneRelationships(tx locationSQLTx, victims []pruneLocation, lockSurvivors bool) ([]pruneLocation, int64, error) {
	if len(victims) == 0 {
		return victims, 0, nil
	}
	ids := pruneIDList(victims)
	scope := `(l.parent_sha256='' OR survivor.parent_sha256<>'')`
	group := `l.sha256,(l.parent_sha256<>'')`
	keep := map[int64]bool{}
	survivorLock := ""
	if lockSurvivors {
		// FOR SHARE also blocks non-key relation updates. KEY SHARE would
		// permit those updates and could invalidate the final-edge proof.
		survivorLock = " LIMIT 1 FOR SHARE"
	}
	err := tx.query(`SELECT COALESCE(min(CASE WHEN l.path=s.path THEN l.id END),min(l.id))
 FROM sample_locations l JOIN samples s ON s.sha256=l.sha256
 WHERE l.id IN (`+ids+`) AND NOT EXISTS (
 SELECT 1 FROM sample_locations survivor WHERE survivor.sha256=l.sha256
 AND `+scope+` AND survivor.id NOT IN (`+ids+`)`+survivorLock+`)
 GROUP BY `+group, nil, func(rows sqlRows) error {
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			keep[id] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	eligible := make([]pruneLocation, 0, len(victims))
	for _, l := range victims {
		if !keep[l.ID] {
			eligible = append(eligible, l)
		}
	}
	return eligible, int64(len(victims) - len(eligible)), nil
}
