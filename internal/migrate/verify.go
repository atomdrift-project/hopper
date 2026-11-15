package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"
)

// Check is one of Verify's tests: the rows that break the rule it names.
type Check struct {
	Name  string
	Count int64
}

// excerpt is true of a legacy row (l) whose result is an excerpt of another
// file's scan (convert). Testing it reads the row's whole result, so Verify
// lists the excerpts once (verify_excerpts) and the checks ask the list.
// EXISTS, not IN: a NOT IN list too large to hash in work_mem (galadriel's
// 46 million) is searched again for every legacy row, while NOT EXISTS is an
// anti-join.
const excerpt = `EXISTS (SELECT 1 FROM verify_excerpts e WHERE e.id = l.id)`

// Verify checks a finished migration against the legacy rows it came from
// (MIGRATION_PLAN.md, part 2, stage 7) and writes nothing but a temporary
// table, its list of the legacy excerpts. Each check counts
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
		// Each account is its own semi-join: OR'd, they are subplans run once
		// per dropped excerpt, a scan of 4.86 billion placements each where
		// sample_locations has no index on sha256 (galadriel).
		{"excerpts dropped though something accounts for them", `WITH gone AS MATERIALIZED (
				SELECT l.id, l.sha256, l.label, l.purl_base, l.path, l.skip FROM ` + from + `.samples l
				WHERE ` + excerpt + ` AND NOT EXISTS (SELECT 1 FROM samples s WHERE s.id = l.id))
			SELECT count(DISTINCT id) FROM (
				SELECT id FROM gone WHERE label <> 'unknown' OR purl_base <> '' OR (path <> '' AND skip NOT IN ('missing', 'replaced'))
				UNION ALL SELECT id FROM gone l WHERE EXISTS (SELECT 1 FROM ` + from + `.sample_locations x
					WHERE x.sha256 = l.sha256 AND x.parent_sha256 = '' AND x.path <> '')
				UNION ALL SELECT id FROM gone l WHERE EXISTS (SELECT 1 FROM ` + from + `.sightings g WHERE g.subject = l.sha256)
				UNION ALL SELECT id FROM gone l WHERE EXISTS (SELECT 1 FROM ` + from + `.label_events e WHERE e.sha256 = l.sha256)
				UNION ALL SELECT id FROM gone l WHERE EXISTS (SELECT 1 FROM ` + from + `.reports r WHERE r.sha256 = l.sha256)) accounted`},
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
	excerpts, err := legacyExcerpts(ctx, pool, from, opt.Workers)
	if err != nil {
		return nil, fmt.Errorf("verify: excerpts: %w", err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `CREATE TEMP TABLE verify_excerpts (id bigint PRIMARY KEY) ON COMMIT PRESERVE ROWS`); err != nil {
		return nil, fmt.Errorf("verify: excerpts: %w", err)
	}
	if _, err := conn.CopyFrom(ctx, pgx.Identifier{"verify_excerpts"}, []string{"id"}, pgx.CopyFromSlice(len(excerpts),
		func(i int) ([]any, error) { return []any{excerpts[i]}, nil })); err != nil {
		return nil, fmt.Errorf("verify: excerpts: %w", err)
	}
	if _, err := conn.Exec(ctx, `ANALYZE verify_excerpts`); err != nil {
		return nil, fmt.Errorf("verify: excerpts: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS verify_excerpts`); err != nil {
			slog.WarnContext(ctx, "verify: dropping the excerpt list failed", "error", err)
		}
	}()
	slog.InfoContext(ctx, "verify: excerpts listed", "count", len(excerpts))
	out := make([]Check, 0, len(checks))
	for _, c := range checks {
		var n int64
		if err := conn.QueryRow(ctx, c.query).Scan(&n); err != nil {
			return out, fmt.Errorf("verify %s: %w", c.name, err)
		}
		out = append(out, Check{Name: c.name, Count: n})
	}
	return out, nil
}

// legacyExcerpts lists the legacy excerpts (convert). Telling one apart reads
// its whole result, 2.5 TB of them in production and four hours on one core,
// so the legacy rows are read in id ranges on workers connections.
func legacyExcerpts(ctx context.Context, pool *pgxpool.Pool, from string, workers int) ([]int64, error) {
	var lo, hi int64
	if err := pool.QueryRow(ctx, `SELECT coalesce(min(id), 0) - 1, coalesce(max(id), 0) FROM `+from+`.samples`).Scan(&lo, &hi); err != nil {
		return nil, err
	}
	workers = max(workers, 1)
	width := (hi-lo)/int64(64*workers) + 1 // 64 spans a worker, so none is left holding the last long one
	var (
		mu  sync.Mutex
		ids []int64
	)
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	for start := lo; start < hi; start += width {
		g.Go(func() error {
			rows, err := pool.Query(ctx, `SELECT l.id FROM `+from+`.samples l
				WHERE l.id > $1 AND l.id <= $2 AND l.parent = ''
				  AND coalesce(coalesce(l.cleave_result->'files', l.cleave_result->'fs')->0 ? 'pid', false)`, start, min(start+width, hi))
			if err != nil {
				return err
			}
			span, err := pgx.CollectRows(rows, pgx.RowTo[int64])
			if err != nil {
				return err
			}
			mu.Lock()
			ids = append(ids, span...)
			mu.Unlock()
			return nil
		})
	}
	return ids, g.Wait()
}
