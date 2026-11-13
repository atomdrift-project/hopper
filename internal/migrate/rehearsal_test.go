package migrate

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrationRehearsal migrates a selection of the replica, copied by
// scripts/rehearsal-select.sh into a local database's public schema, into a
// fresh verdict schema there, and checks the result against the legacy rows
// (MIGRATION_PLAN.md, part 3). It drops and rebuilds the verdict schema.
//
//	HOPPER_REHEARSAL_DSN='postgres://proto@/rehearsal?host=/tmp/hopper-schema-prototype/v2&port=5499' \
//	  go test -run MigrationRehearsal -v ./internal/migrate
func TestMigrationRehearsal(t *testing.T) {
	dsn := os.Getenv("HOPPER_REHEARSAL_DSN")
	if dsn == "" || strings.Contains(dsn, "hopper-db") {
		t.Skip("HOPPER_REHEARSAL_DSN (a disposable local database holding a selection) is needed")
	}
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "verdict"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS verdict CASCADE`); err != nil {
		t.Fatal(err)
	}
	workers := 8
	if w, err := strconv.Atoi(os.Getenv("HOPPER_REHEARSAL_WORKERS")); err == nil && w > 0 {
		workers = w
	}
	opt := Options{From: "public", To: "verdict", Workers: workers, Batch: 50_000}
	start := time.Now()
	r, err := Run(ctx, pool, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("migrated in %s: %+v", time.Since(start).Round(time.Millisecond), *r)
	for reason, n := range r.Failures {
		t.Errorf("refused %d: %s", n, reason)
	}

	checks, err := Verify(ctx, pool, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Count != 0 {
			t.Errorf("%s: %d", c.Name, c.Count)
		}
	}

	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, queue := range store.TriageQueueNames() {
		got, err := st.Triage(ctx, queue, 10, nil)
		if err != nil {
			t.Errorf("triage %s: %v", queue, err)
			continue
		}
		t.Logf("triage %-28s %d", queue, len(got))
	}

	// Converting again in order, by one worker, corrects only what the
	// parallel run stored out of order: a member two workers stored at once
	// from archives a little apart in time. Converting a third time writes
	// nothing: every verdict keeps its row version (a frozen row reports
	// xmin 2, which is not a write).
	var verdicts int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM verdicts`).Scan(&verdicts); err != nil {
		t.Fatal(err)
	}
	for pass := 2; pass <= 3; pass++ {
		changed := reconvert(ctx, t, pool, Options{From: "public", To: "verdict", Workers: 1, Batch: opt.Batch}, r.Converted)
		t.Logf("pass %d, one worker: %d of %d verdicts changed", pass, changed, verdicts)
		switch {
		case pass == 2 && changed*1000 > verdicts:
			t.Errorf("pass 2 changed %d of %d verdicts: more than out-of-order storage explains", changed, verdicts)
		case pass == 3 && changed != 0:
			t.Errorf("pass 3 changed %d verdicts: converting is not idempotent", changed)
		default:
		}
	}
	report(ctx, t, pool, r)
}

// report logs what each new table costs per sample, the figures part 2's
// sizing extrapolates from.
func report(ctx context.Context, t *testing.T, pool *pgxpool.Pool, r *Report) {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT c.relname, pg_total_relation_size(c.oid), c.reltuples::bigint
		FROM pg_class c WHERE c.relnamespace = 'verdict'::regnamespace AND c.relkind = 'r'
		ORDER BY pg_total_relation_size(c.oid) DESC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var (
		name        string
		size, count int64
		total       int64
	)
	for rows.Next() {
		if err := rows.Scan(&name, &size, &count); err != nil {
			t.Fatal(err)
		}
		total += size
		t.Logf("%-22s %10d bytes %10d rows %8.0f bytes/result", name, size, count, float64(size)/float64(max(r.Converted, 1)))
	}
	t.Logf("%-22s %10d bytes %10s      %8.0f bytes/result", "total", total, "", float64(total)/float64(max(r.Converted, 1)))
	for stage, took := range r.Took {
		t.Logf("stage %-10s %s", stage, took.Round(time.Millisecond))
	}
}

// reconvert runs the conversion stage again and returns how many verdict
// rows it rewrote, removed or added.
func reconvert(ctx context.Context, t *testing.T, pool *pgxpool.Pool, opt Options, want int64) int64 {
	t.Helper()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS rehearsal_versions;
		CREATE TABLE rehearsal_versions AS SELECT sample_id, scanner_id, xmin::text AS x,
			formed_at, class, fires_at, ruleset, digest, summary FROM verdicts`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS rehearsal_versions`); err != nil {
			t.Error(err)
		}
	}()
	if _, err := pool.Exec(ctx, `DELETE FROM hopper_kv WHERE key IN ('migrate:convert', 'migrate:convert:through')`); err != nil {
		t.Fatal(err)
	}
	again, err := Run(ctx, pool, opt)
	if err != nil {
		t.Fatal(err)
	}
	if again.Converted != want {
		t.Errorf("converted %d results again, %d the first time", again.Converted, want)
	}
	// What changed, by kind and scanner, and whether the file was scanned on
	// its own and sits in an archive: what tells one cause from another.
	rows, err := pool.Query(ctx, `SELECT c.kind, sc.name,
			EXISTS (SELECT 1 FROM scans s WHERE s.sample_id = c.sample_id),
			EXISTS (SELECT 1 FROM contents p WHERE p.child_ids @> ARRAY[c.sample_id]), count(*)
		FROM (SELECT 'rewritten' AS kind, v.sample_id, v.scanner_id FROM rehearsal_versions o JOIN verdicts v USING (sample_id, scanner_id)
		      WHERE o.x <> v.xmin::text AND v.xmin::text <> '2'
		      UNION ALL
		      SELECT 'removed', o.sample_id, o.scanner_id FROM rehearsal_versions o WHERE NOT EXISTS
		        (SELECT 1 FROM verdicts v WHERE v.sample_id = o.sample_id AND v.scanner_id = o.scanner_id)
		      UNION ALL
		      SELECT 'added', v.sample_id, v.scanner_id FROM verdicts v WHERE NOT EXISTS
		        (SELECT 1 FROM rehearsal_versions o WHERE o.sample_id = v.sample_id AND o.scanner_id = v.scanner_id)) c
		JOIN scanners sc ON sc.id = c.scanner_id
		GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var changed int64
	for rows.Next() {
		var (
			kind, scanner   string
			scanned, member bool
			n               int64
		)
		if err := rows.Scan(&kind, &scanner, &scanned, &member, &n); err != nil {
			t.Fatal(err)
		}
		t.Logf("  %d %s %s row(s): scanned on its own %v, in an archive %v", n, kind, scanner, scanned, member)
		changed += n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	logRewrites(ctx, t, pool)
	return changed
}

// logRewrites logs which columns the rewritten rows changed, with one
// example of each combination.
func logRewrites(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT d.cols, count(*), min(d.example)
		FROM (SELECT concat_ws(',',
				CASE WHEN o.formed_at <> v.formed_at THEN 'formed_at' END,
				CASE WHEN o.class IS DISTINCT FROM v.class THEN 'class' END,
				CASE WHEN o.fires_at IS DISTINCT FROM v.fires_at THEN 'fires_at' END,
				CASE WHEN o.ruleset <> v.ruleset THEN 'ruleset' END,
				CASE WHEN o.digest IS DISTINCT FROM v.digest THEN 'digest' END,
				CASE WHEN o.summary IS DISTINCT FROM v.summary THEN 'summary' END) AS cols,
			left(encode(s.sha256, 'hex'), 12) || ' ' || o.formed_at || ' -> ' || v.formed_at || ', ' ||
				coalesce(o.class::text, '-') || '/' || coalesce(o.fires_at::text, '-') || ' -> ' ||
				coalesce(v.class::text, '-') || '/' || coalesce(v.fires_at::text, '-') || ', ' ||
				left(coalesce(o.summary::text, '-'), 80) || ' -> ' || left(coalesce(v.summary::text, '-'), 80) AS example
			FROM rehearsal_versions o JOIN verdicts v USING (sample_id, scanner_id) JOIN samples s ON s.id = v.sample_id
			WHERE o.x <> v.xmin::text AND v.xmin::text <> '2') d
		GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cols, example string
			n             int64
		)
		if err := rows.Scan(&cols, &n, &example); err != nil {
			t.Fatal(err)
		}
		t.Logf("    %d rewrote [%s], e.g. %s", n, cols, example)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
