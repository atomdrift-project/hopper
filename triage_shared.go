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
const triageBadSharedPop = `label = 'bad' AND path <> ''
 AND skip != 'conflict' AND label_source != 'conflict'
 AND EXISTS (SELECT 1 FROM sample_locations sl
             WHERE sl.sha256 = samples.sha256 LIMIT 1 OFFSET 5)`

// TriageBadShared returns bad-labeled content recorded at six or more distinct
// paths. Completed reviews drain through the queue's ordinary report filter.
func (db *DB) TriageBadShared(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		extra, args := triageFilterClausePG(f, 1, "samples")
		args = append(args, limit)
		rows, err := db.pool.Query(ctx,
			`SELECT `+pgSampleColsLight+` FROM samples WHERE `+triageBadSharedPop+extra+
				` ORDER BY created_at DESC, id DESC LIMIT $`+strconv.Itoa(len(args)), args...)
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
