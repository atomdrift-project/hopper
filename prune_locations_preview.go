package hopper

import "context"

// previewLocationWindow applies the retention order to a bounded catalog window.
// Counts are scoped to that window, not extrapolated to the whole corpus.
// This is a single SELECT, so labels and locations share one database snapshot.
func (db *DB) previewLocationWindow(ctx context.Context, opts LocationPruneOptions, stats *LocationPruneStats) error {
	query := `WITH scope AS MATERIALIZED (
 SELECT id,sha256,path,parent_sha256,first_seen_at,(` + pruneInFileSQL + `) AS contained
 FROM sample_locations WHERE id>$1 AND id<=$2 ORDER BY id LIMIT $3
 ), classified AS MATERIALIZED (
 SELECT l.*,COALESCE(s.label,'orphan') AS label,
 CASE WHEN s.skip='conflict' OR s.label_source='conflict' THEN 0
      WHEN s.label='good' THEN $4 WHEN s.label='unknown' THEN $5 ELSE 0 END AS cap,
 CASE WHEN l.path=s.path THEN 0 ELSE 1 END AS primary_rank
 FROM scope l LEFT JOIN samples s ON s.sha256=l.sha256
 ), parent_ranked AS (
 SELECT c.*,row_number() OVER(PARTITION BY sha256,parent_sha256
 ORDER BY primary_rank,first_seen_at,id) AS parent_rank
 FROM classified c WHERE contained AND cap>0
 ), ranked AS MATERIALIZED (
 SELECT p.*,row_number() OVER(PARTITION BY sha256
 ORDER BY primary_rank,CASE WHEN parent_rank=1 THEN 0 ELSE 1 END,first_seen_at,id) AS keep_rank
 FROM parent_ranked p
 ), dropped AS (
 SELECT id FROM ranked WHERE keep_rank>cap
 ), lost_edges AS (
 SELECT label,sha256,parent_sha256 FROM ranked GROUP BY label,sha256,parent_sha256
 HAVING min(CASE WHEN keep_rank>cap THEN 1 ELSE 0 END)=1
 ), lost_by_label AS (
 SELECT label,count(*) AS lost FROM lost_edges GROUP BY label
 )
 SELECT c.label,count(*),
 SUM(CASE WHEN c.contained THEN 1 ELSE 0 END),
 SUM(CASE WHEN c.contained AND c.cap>0 THEN 1 ELSE 0 END),
 SUM(CASE WHEN c.parent_sha256='' THEN 1 ELSE 0 END),
 count(d.id),
 count(DISTINCT CASE WHEN d.id IS NOT NULL THEN c.sha256 END),
 count(DISTINCT CASE WHEN c.contained AND c.cap>0 THEN c.sha256||c.parent_sha256 END),
 COALESCE(max(e.lost),0),
 (SELECT COALESCE(max(id),$1) FROM scope)
 FROM classified c LEFT JOIN dropped d ON d.id=c.id LEFT JOIN lost_by_label e ON e.label=c.label
 GROUP BY c.label ORDER BY c.label`
	goodCap, unknownCap := opts.GoodMaxPaths, opts.UnknownMaxPaths
	if !capLabelSelected(labelGood, opts) {
		goodCap = 0
	}
	if !capLabelSelected(labelUnknown, opts) {
		unknownCap = 0
	}
	err := db.queryLocations(ctx, query, []any{opts.AfterID, stats.ThroughID, opts.PreviewRows, goodCap, unknownCap},
		func(rows locationRows) error {
			for rows.Next() {
				var label string
				var detail LocationPruneLabelStats
				if err := rows.Scan(&label, &detail.Rows, &detail.MemberLocations, &detail.EligibleLocations,
					&detail.PhysicalLocations, &detail.Excess,
					&detail.AffectedSHAs, &detail.ArchivesSeen, &detail.ArchiveEdgesRemoved, &stats.AfterID); err != nil {
					return err
				}
				target := locationLabelStats(stats.Labels, label)
				target.Rows += detail.Rows
				target.MemberLocations += detail.MemberLocations
				target.EligibleLocations += detail.EligibleLocations
				target.PhysicalLocations += detail.PhysicalLocations
				target.Excess += detail.Excess
				target.AffectedSHAs += detail.AffectedSHAs
				target.ArchivesSeen += detail.ArchivesSeen
				target.ArchiveEdgesRemoved += detail.ArchiveEdgesRemoved
				stats.Scanned += detail.Rows
				stats.Excess += detail.Excess
				stats.CappedSHAs += int(detail.AffectedSHAs)
				stats.PhysicalRetained += detail.PhysicalLocations
				stats.ArchivesSeen += detail.ArchivesSeen
				stats.ArchiveEdgesRemoved += detail.ArchiveEdgesRemoved
				// Physical paths, references and exempt labels are outside the cap.
				stats.Protected += detail.Rows - detail.EligibleLocations
			}
			return rows.Err()
		})
	if err != nil {
		return err
	}
	stats.Complete = true
	return reportLocationPrune(opts, *stats)
}
