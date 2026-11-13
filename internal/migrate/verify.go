package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Check is one of Verify's tests: the rows that break the rule it names.
type Check struct {
	Name  string
	Count int64
}

// excerpt is true of a legacy row (l) whose result is an excerpt of another
// file's scan (convert).
const excerpt = `(l.parent = '' AND coalesce(coalesce(l.cleave_result->'files', l.cleave_result->'fs')->0 ? 'pid', false))`

// Verify checks a finished migration against the legacy rows it came from
// (MIGRATION_PLAN.md, part 2, stage 7) and writes nothing. Each check counts
// the rows that break its rule; a sound migration answers zero everywhere.
// The pool's search_path must be opt.To, as for Run.
func Verify(ctx context.Context, pool *pgxpool.Pool, opt Options) ([]Check, error) {
	if opt.From == "" || opt.To == "" || opt.From == opt.To {
		return nil, errors.New("migrate: From and To must name two schemas")
	}
	from := pgx.Identifier{opt.From}.Sanitize()
	checks := []struct{ name, query string }{
		{"legacy samples without their row, id and digest", `SELECT count(*) FROM ` + from + `.samples l
			LEFT JOIN samples s ON s.id = l.id AND s.sha256 = decode(l.sha256, 'hex')
			WHERE l.sha256 ~ '^[0-9a-f]{64}$' AND s.id IS NULL AND NOT ` + excerpt},
		{"excerpts dropped though something accounts for them", `SELECT count(*) FROM ` + from + `.samples l
			WHERE ` + excerpt + ` AND NOT EXISTS (SELECT 1 FROM samples s WHERE s.id = l.id)
			  AND (l.label <> 'unknown' OR l.purl_base <> '' OR (l.path <> '' AND l.skip NOT IN ('missing', 'replaced'))
			    OR EXISTS (SELECT 1 FROM ` + from + `.sample_locations x WHERE x.sha256 = l.sha256 AND x.parent_sha256 = '' AND x.path <> '')
			    OR EXISTS (SELECT 1 FROM ` + from + `.sightings g WHERE g.subject = l.sha256)
			    OR EXISTS (SELECT 1 FROM ` + from + `.label_events e WHERE e.sha256 = l.sha256)
			    OR EXISTS (SELECT 1 FROM ` + from + `.reports r WHERE r.sha256 = l.sha256))`},
		{"excerpts stored as a scan of their file", `SELECT count(*) FROM ` + from + `.samples l
			JOIN scans sc ON sc.sample_id = l.id WHERE ` + excerpt},
		{"labels not carried", `SELECT count(*) FROM ` + from + `.samples l JOIN samples s ON s.id = l.id
			WHERE s.label::text <> CASE WHEN l.label = 'purgatory' THEN 'inconclusive' ELSE l.label END
			  AND l.label IN ('unknown', 'sighted', 'good', 'bad', 'inconclusive', 'dual-use', 'purgatory')`},
		{"analyzed top-level files without atomscan's verdict and a scan", `SELECT count(*) FROM ` + from + `.samples l
			JOIN samples s ON s.id = l.id
			WHERE l.parent = '' AND l.cleave_result IS NOT NULL AND NOT ` + excerpt + `
			  AND (NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = s.id AND v.scanner_id = 1)
			    OR NOT EXISTS (SELECT 1 FROM scans sc WHERE sc.sample_id = s.id))`},
		{"scans not at the legacy analysis time", `SELECT count(*) FROM ` + from + `.samples l
			JOIN scans sc ON sc.sample_id = l.id
			WHERE l.parent = '' AND l.cleave_result IS NOT NULL AND l.analyzed_at IS NOT NULL
			  AND sc.scanned_at < date_trunc('second', l.analyzed_at) - interval '1 second'`},
		{"top-level placements without a location", `SELECT count(*) FROM ` + from + `.sample_locations l
			WHERE l.parent_sha256 = '' AND l.path <> '' AND octet_length(l.path) <= 1024
			  AND NOT EXISTS (SELECT 1 FROM locations x WHERE x.path = l.path)`},
		{"cited unlike the ledger", `SELECT count(*) FROM samples WHERE cited <> named(sha256, name_id, version)`},
		{"queue unlike the unscanned files on disk", `SELECT count(*) FROM samples s
			WHERE (EXISTS (SELECT 1 FROM queue q WHERE q.sample_id = s.id))
			   <> (EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
			       AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = s.id AND v.scanner_id = 1))`},
		{"legacy reports not carried", `SELECT count(*) FROM ` + from + `.reports r
			WHERE EXISTS (SELECT 1 FROM samples s WHERE s.sha256 = decode(r.sha256, 'hex'))
			  AND NOT EXISTS (SELECT 1 FROM reports n WHERE n.id = r.id)`},
	}
	for _, table := range []string{"names", "samples", "reports", "label_events"} {
		checks = append(checks, struct{ name, query string }{table + " sequence behind its ids", `SELECT count(*) FROM pg_sequences
			WHERE schemaname = current_schema() AND sequencename = pg_get_serial_sequence('` + table + `', 'id')::regclass::text
			  AND last_value < (SELECT coalesce(max(id), 0) FROM ` + table + `)`})
	}
	out := make([]Check, 0, len(checks))
	for _, c := range checks {
		var n int64
		if err := pool.QueryRow(ctx, c.query).Scan(&n); err != nil {
			return out, fmt.Errorf("verify %s: %w", c.name, err)
		}
		out = append(out, Check{Name: c.name, Count: n})
	}
	return out, nil
}
