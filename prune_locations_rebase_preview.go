package hopper

import "context"

// previewPruneRebaseTargets distinguishes a row merge from a path repair: only
// a compatible destination that already exists can save a location row.
func (db *DB) previewPruneRebaseTargets(ctx context.Context, rebases []pruneRebase) (duplicates, conflicts int64, err error) {
	if len(rebases) == 0 {
		return 0, 0, nil
	}
	if db.pool != nil {
		shas, paths := make([]string, len(rebases)), make([]string, len(rebases))
		parents, rels := make([]string, len(rebases)), make([]string, len(rebases))
		for i, r := range rebases {
			shas[i], paths[i], parents[i], rels[i] = r.loc.SHA, r.newPath, r.loc.Parent, r.loc.Rel
		}
		err = db.queryLocations(ctx, `SELECT
 count(*) FILTER(WHERE d.id IS NOT NULL AND d.parent_sha256=v.parent AND d.rel=v.rel),
 count(*) FILTER(WHERE d.id IS NOT NULL AND (d.parent_sha256<>v.parent OR d.rel<>v.rel))
 FROM unnest($1::text[],$2::text[],$3::text[],$4::text[]) AS v(sha,path,parent,rel)
 LEFT JOIN sample_locations d ON d.sha256=v.sha AND path_key(d.path)=path_key(v.path) AND d.path=v.path`,
			[]any{shas, paths, parents, rels}, func(rows locationRows) error {
				if rows.Next() {
					return rows.Scan(&duplicates, &conflicts)
				}
				return rows.Err()
			})
		return duplicates, conflicts, err
	}
	for _, r := range rebases {
		err = db.queryLocations(ctx, `SELECT parent_sha256,rel FROM sample_locations WHERE sha256=$1 AND path=$2`,
			[]any{r.loc.SHA, r.newPath}, func(rows locationRows) error {
				if rows.Next() {
					var parent, rel string
					if err := rows.Scan(&parent, &rel); err != nil {
						return err
					}
					if parent == r.loc.Parent && rel == r.loc.Rel {
						duplicates++
					} else {
						conflicts++
					}
				}
				return rows.Err()
			})
		if err != nil {
			return 0, 0, err
		}
	}
	return duplicates, conflicts, nil
}
