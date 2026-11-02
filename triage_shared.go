package hopper

import (
	"context"
	"fmt"
	"strconv"
)

// Six distinct recorded paths qualify, including archive-member locations.
// sample_locations is unique on (sha256, path). An indexed existence probe
// stops at the sixth row even for ubiquitous files with millions of locations.
// Do not gate on parent, detection strength, provenance, or analysis freshness:
// common inert members can inherit a bad label regardless of those properties.
const triageBadSharedCandidates = `label = 'bad' AND path <> ''
 AND skip != 'conflict' AND label_source != 'conflict'`

const triageBadSharedPop = triageBadSharedCandidates + `
 AND EXISTS (SELECT 1 FROM sample_locations sl
             WHERE sl.sha256 = samples.sha256 LIMIT 1 OFFSET 5)`

// Keep the candidate walk covered: the location and report probes need only
// sha256 and analyzed_at. Full sample metadata is fetched after the limit,
// rather than reading a samples heap tuple for every rejected candidate.
const triageBadSharedIndexDDL = `CREATE INDEX IF NOT EXISTS idx_samples_bad_shared_newest ` +
	`ON samples(created_at DESC, id DESC) INCLUDE (sha256, analyzed_at) WHERE ` + triageBadSharedCandidates

func triageBadSharedSQL(extra, limit string) string {
	return `WITH picked AS MATERIALIZED (
 SELECT id FROM samples WHERE ` + triageBadSharedPop + extra + `
 ORDER BY created_at DESC, id DESC LIMIT ` + limit + `)
 SELECT ` + pgSampleColsLight + ` FROM samples WHERE id IN (SELECT id FROM picked)
 ORDER BY created_at DESC, id DESC`
}

// TriageBadShared returns bad-labeled content recorded at six or more distinct
// paths. Completed reviews drain through the queue's ordinary report filter.
func (db *DB) TriageBadShared(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		extra, args := triageFilterClausePG(f, 1, "samples")
		args = append(args, limit)
		rows, err := db.pool.Query(ctx,
			triageBadSharedSQL(extra, "$"+strconv.Itoa(len(args))), args...)
		if err != nil {
			return nil, fmt.Errorf("hopper: triage bad-shared: %w", err)
		}
		return scanPGSamplesLight(rows)
	}
	extra, args := triageFilterClauseSQLite(f, "samples")
	args = append(args, limit)
	//nolint:gosec // G202: constant SQL fragments; filter values are parameterized
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleColsLight+` FROM samples WHERE `+triageBadSharedPop+extra+
			` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage bad-shared: %w", err)
	}
	return scanLiteSamplesLight(rows)
}
