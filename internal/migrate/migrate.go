// Package migrate builds hopper's verdict schema from the legacy tables, in
// the same database, while hopper is stopped (MIGRATION_PLAN.md, part 2).
//
// The legacy tables are only read. The new tables are filled stage by stage;
// each stage records in hopper_kv how far it got, so a run that stops is
// started again and continues, and a stage already done is skipped. A range
// done twice writes nothing the second time.
package migrate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/atomdrift-project/hopper/store"
	"github.com/atomdrift-project/hopper/v7result"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options says where the legacy tables are, where the new ones go, and how
// hard to work.
type Options struct {
	From    string // schema holding the legacy tables
	To      string // schema the verdict tables are built in; the pool's search_path
	Workers int    // parallel converters
	Batch   int64  // legacy ids per range
}

// Report counts what a run did. Counts are of this run: a stage skipped as
// already done counts nothing.
type Report struct {
	Took      map[string]time.Duration
	Failures  map[string]int // results the converter or the writer refused, by reason
	Names     int64          // names interned
	Samples   int64          // sample rows copied
	Converted int64          // legacy results stored through the writer
	Files     int64          // file lines those results held
	Failed    int64          // results refused (Failures)
	Excerpts  int64          // legacy results that were excerpts of another file's scan, not converted
	Dropped   int64          // excerpts' sample rows that nothing else accounted for
	Locations int64          // paths copied
	Sightings int64          // ledger rows copied
	Respelled int64          // package subjects whose spelling changed
	Reports   int64          // triage reports copied
	Carried   int64          // rows of the tables carried as they are
	Marked    int64          // files cited
	Queued    int64          // files queued for a first scan
}

// migration carries one run.
type migration struct {
	pool   *pgxpool.Pool
	st     *store.Store
	report *Report
	from   string // quoted
	opt    Options
	mu     sync.Mutex // guards report.Failures, Failed, Converted, Files
}

// Run migrates. The pool's search_path must be opt.To alone, so that the
// store, and the schema's functions, find the new tables.
func Run(ctx context.Context, pool *pgxpool.Pool, opt Options) (*Report, error) {
	if opt.From == "" || opt.To == "" || opt.From == opt.To {
		return nil, errors.New("migrate: From and To must name two schemas")
	}
	opt.Workers, opt.Batch = max(opt.Workers, 1), max(opt.Batch, 1)
	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+pgx.Identifier{opt.To}.Sanitize()); err != nil {
		return nil, fmt.Errorf("migrate: schema: %w", err)
	}
	var current *string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&current); err != nil {
		return nil, fmt.Errorf("migrate: schema: %w", err)
	}
	if current == nil || *current != opt.To {
		return nil, fmt.Errorf("migrate: the pool's search_path must be %q, not %v", opt.To, current)
	}
	st, err := store.New(pool)
	if err != nil {
		return nil, err
	}
	st.KeepOrphans = true
	m := &migration{
		pool: pool, st: st, from: pgx.Identifier{opt.From}.Sanitize(), opt: opt,
		report: &Report{Took: map[string]time.Duration{}, Failures: map[string]int{}},
	}
	if err := m.tables(ctx); err != nil {
		return m.report, err
	}
	for _, s := range []struct {
		run  func(context.Context) error
		name string
	}{
		{m.names, "names"},
		{m.samples, "samples"},
		{m.convert, "convert"},
		{m.locations, "locations"},
		{m.paths, "paths"},
		{m.carried, "carried"},
		{m.post, "post"},
	} {
		done, err := m.kv(ctx, "migrate:"+s.name)
		if err != nil {
			return m.report, err
		}
		if done == "done" {
			slog.InfoContext(ctx, "migrate: stage already done", "stage", s.name)
			continue
		}
		start := time.Now()
		slog.InfoContext(ctx, "migrate: stage", "stage", s.name)
		if err := s.run(ctx); err != nil {
			return m.report, fmt.Errorf("migrate: %s: %w", s.name, err)
		}
		if err := m.setKV(ctx, "migrate:"+s.name, "done"); err != nil {
			return m.report, err
		}
		m.report.Took[s.name] = time.Since(start)
		slog.InfoContext(ctx, "migrate: stage done", "stage", s.name, "took", time.Since(start).Round(time.Second))
	}
	return m.report, nil
}

// deferred is what the load leaves for the end: the secondary indexes, which
// are built once over the loaded rows instead of maintained row by row. The
// writer needs only the keys, and the GIN index on contents, which it uses
// to find what holds a file; that one is built at the start with a pending
// list, and made to skip it once the load is done.
func split(ddl string) (pre string, post []string) {
	var b strings.Builder
	var stmt []string
	for line := range strings.Lines(ddl) {
		if stmt == nil && strings.HasPrefix(line, "CREATE INDEX ") && !strings.HasPrefix(line, "CREATE INDEX contents_parents ") {
			stmt = []string{}
		}
		if stmt == nil {
			b.WriteString(strings.Replace(line, "WITH (fastupdate = off)", "WITH (fastupdate = on)", 1))
			continue
		}
		stmt = append(stmt, line)
		if strings.HasSuffix(strings.TrimSpace(line), ";") {
			post = append(post, strings.Replace(strings.Join(stmt, ""), "CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1))
			stmt = nil
		}
	}
	return b.String(), post
}

// tables creates the new tables, unless an earlier run did.
func (m *migration) tables(ctx context.Context) error {
	var exists bool
	if err := m.pool.QueryRow(ctx, `SELECT to_regclass('hopper_kv') IS NOT NULL`).Scan(&exists); err != nil {
		return fmt.Errorf("migrate: tables: %w", err)
	}
	if exists {
		return nil
	}
	pre, _ := split(store.Schema)
	if _, err := m.pool.Exec(ctx, pre); err != nil {
		return fmt.Errorf("migrate: tables: %w", err)
	}
	return nil
}

func (m *migration) kv(ctx context.Context, key string) (string, error) {
	var v string
	err := m.pool.QueryRow(ctx, `SELECT value FROM hopper_kv WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("migrate: progress: %w", err)
	}
	return v, nil
}

func (m *migration) setKV(ctx context.Context, key, value string) error {
	if _, err := m.pool.Exec(ctx, `INSERT INTO hopper_kv (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, value); err != nil {
		return fmt.Errorf("migrate: progress: %w", err)
	}
	return nil
}

// ranges calls step on each range of a legacy table's ids not yet done, in
// order, recording each as done. step gets the range (lo, hi]; a range
// starts at the next id there is, so gaps in the ids cost nothing.
func (m *migration) ranges(ctx context.Context, name, table string, step func(ctx context.Context, lo, hi int64) error) error {
	from, last, err := m.span(ctx, name, table)
	if err != nil {
		return err
	}
	for lo := from; lo < last; {
		if lo, err = m.nextID(ctx, table, lo); err != nil || lo >= last {
			return err
		}
		hi := min(lo+m.opt.Batch, last)
		if err := step(ctx, lo, hi); err != nil {
			return err
		}
		lo = hi
		if err := m.setKV(ctx, "migrate:"+name+":through", strconv.FormatInt(hi, 10)); err != nil {
			return err
		}
	}
	return nil
}

// nextID is the id just before the first row of a legacy table after lo, or
// the largest id when there is none, so that (result, …] starts at a row.
func (m *migration) nextID(ctx context.Context, table string, lo int64) (int64, error) {
	var next *int64
	if err := m.pool.QueryRow(ctx, `SELECT min(id) FROM `+m.from+`.`+pgx.Identifier{table}.Sanitize()+` WHERE id > $1`, lo).Scan(&next); err != nil {
		return 0, fmt.Errorf("next id: %w", err)
	}
	if next == nil {
		return math.MaxInt64, nil
	}
	return *next - 1, nil
}

// span is where a ranged stage starts (after what an earlier run finished)
// and the largest id of the legacy table it walks.
func (m *migration) span(ctx context.Context, name, table string) (from, last int64, err error) {
	if err := m.pool.QueryRow(ctx, `SELECT coalesce(min(id) - 1, 0), coalesce(max(id), 0) FROM `+m.from+`.`+pgx.Identifier{table}.Sanitize()).
		Scan(&from, &last); err != nil {
		return 0, 0, fmt.Errorf("span: %w", err)
	}
	through, err := m.kv(ctx, "migrate:"+name+":through")
	if err != nil {
		return 0, 0, err
	}
	if through != "" {
		if from, err = strconv.ParseInt(through, 10, 64); err != nil {
			return 0, 0, fmt.Errorf("span: progress %q: %w", through, err)
		}
	}
	return from, last, nil
}

// names interns every legacy release name, spelled as the store spells one,
// and keeps a map from the legacy spelling for the samples stage.
func (m *migration) names(ctx context.Context) error {
	if _, err := m.pool.Exec(ctx, `CREATE UNLOGGED TABLE IF NOT EXISTS migrate_names (
		purl_base text PRIMARY KEY, name_id bigint NOT NULL)`); err != nil {
		return err
	}
	rows, err := m.pool.Query(ctx, `SELECT DISTINCT purl_base FROM `+m.from+`.samples WHERE purl_base <> ''`)
	if err != nil {
		return err
	}
	legacy, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	const batch = 10_000
	for chunk := range slices.Chunk(legacy, batch) {
		var olds, news []string
		for _, old := range chunk {
			if name := store.NameOf(old); name != "" && len(name) <= scanresult.MaxName {
				olds, news = append(olds, old), append(news, name)
			}
		}
		tag, err := m.pool.Exec(ctx, `WITH n AS (
				INSERT INTO names (name)
				SELECT DISTINCT x FROM unnest($2::text[]) AS x
				WHERE NOT EXISTS (SELECT 1 FROM names WHERE name = x)
				ORDER BY x
				ON CONFLICT (name) DO NOTHING
				RETURNING id, name)
			INSERT INTO migrate_names (purl_base, name_id)
			SELECT u.old, coalesce(n.id, k.id)
			FROM unnest($1::text[], $2::text[]) AS u(old, name)
			LEFT JOIN n ON n.name = u.name
			LEFT JOIN names k ON k.name = u.name
			ON CONFLICT (purl_base) DO NOTHING`, olds, news)
		if err != nil {
			return err
		}
		m.report.Names += tag.RowsAffected()
	}
	return nil
}

// samples copies every legacy sample row, members too, keeping its id. A
// legacy skip state that is a label decision (a good/bad conflict, a marker)
// becomes the label source; the others are what other stages derive
// (missing: no location; stuck: queued again).
func (m *migration) samples(ctx context.Context) error {
	err := m.ranges(ctx, "samples", "samples", func(ctx context.Context, lo, hi int64) error {
		tag, err := m.pool.Exec(ctx, `INSERT INTO samples (id, sha256, size_bytes, file_type, label, label_source,
				created_at, name_id, version, url, fetched_at, provenance)
			SELECT l.id, decode(l.sha256, 'hex'), nullif(l.size_bytes, 0), nullif(l.file_type, ''),
			       CASE WHEN l.label = 'purgatory' THEN 'inconclusive'
			            WHEN l.label IN ('unknown', 'sighted', 'good', 'bad', 'inconclusive', 'dual-use') THEN l.label
			            ELSE 'unknown' END::label,
			       CASE WHEN l.skip IN ('conflict', 'marker') THEN l.skip ELSE nullif(l.label_source, '') END,
			       l.created_at, n.name_id, CASE WHEN n.name_id IS NULL THEN '' ELSE coalesce(l.version, '') END,
			       nullif(l.url, ''), l.fetched_at, l.provenance
			FROM `+m.from+`.samples l
			LEFT JOIN migrate_names n ON n.purl_base = l.purl_base
			WHERE l.id > $1 AND l.id <= $2 AND l.sha256 ~ '^[0-9a-f]{64}$'
			ON CONFLICT DO NOTHING`, lo, hi)
		if err != nil {
			return err
		}
		m.report.Samples += tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	// The writer creates the rows of members legacy never held: their ids
	// come after every legacy id.
	_, err = m.pool.Exec(ctx, `SELECT setval(pg_get_serial_sequence('samples', 'id'), greatest((SELECT max(id) FROM samples), 1))`)
	return err
}

// legacyResult is one analyzed top-level row as the converter takes it.
type legacyResult struct {
	raw, mlSection, interp *string
	at                     time.Time
	sha256, ruleset, skip  string
	// topTraits is the legacy row's top_traits: the strongest findings of its
	// own entry, which legacy kept for reports the converter cannot read.
	topTraits string
}

// scanTime is when a legacy result was formed: the later of the row's
// analysis time and its ML result's. The ML result completes an analysis
// when it comes last; a rescan that reused an older one leaves the row's
// time the newer. Whichever exists when only one does, else the last error,
// else the row's creation. An ML time that is not a timestamp is ignored,
// not fatal: the expression runs over every row in one statement. The ML
// result is flat, or nested under "ml" beside an "llm" section, as legacy's
// litmusSections reads it.
const scanTime = `coalesce(greatest(l.analyzed_at,
	CASE WHEN pg_input_is_valid(coalesce(l.litmus_result->'ml', l.litmus_result)->>'analyzed_at', 'timestamptz')
	     THEN (coalesce(l.litmus_result->'ml', l.litmus_result)->>'analyzed_at')::timestamptz END),
	l.last_error_at, l.created_at)`

// convertBatch is how many results one converter takes at a time: small, so
// that the results being stored at once are close together in time.
const convertBatch = 1_000

// convert stores every analyzed top-level row's result through the writer,
// as a version 7 upload of it would be stored, oldest analysis first. Order
// matters: a member's stored opinion says when it last changed, not when a
// scan last confirmed it, so a member shared by archives ends up with the
// newest archive's opinion only if the newest comes last, as live uploads
// do. The order is listed once (migrate_order); workers take consecutive
// batches of it. Progress is recorded only through the last batch below
// which every batch is done, so a restart redoes at most a worker's worth,
// which writes nothing.
//
// A legacy excerpt is not converted. Legacy hopper cut each member's line
// out of an archive's report and stored it on the member's own row, as if it
// were that file's scan: a dependency, a registry sidecar, a file inside an
// archive, overwriting what an earlier scan of the file itself had stored.
// Its first line has a parent (pid), where a scan's first line is the
// scanned artifact. Its file keeps its row and labels, and is queued for a
// scan of its own if it is on disk; one that nothing accounts for is dropped
// at the end (post). The excerpts are listed in migrate_excerpts.
func (m *migration) convert(ctx context.Context) error {
	if _, err := m.pool.Exec(ctx, `CREATE UNLOGGED TABLE IF NOT EXISTS migrate_order (
			seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, id bigint NOT NULL);
		CREATE UNLOGGED TABLE IF NOT EXISTS migrate_excerpts (id bigint PRIMARY KEY)`); err != nil {
		return err
	}
	var last int64
	if err := m.pool.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM migrate_order`).Scan(&last); err != nil {
		return err
	}
	if last == 0 {
		// Both lists are made by one statement, so a restart finds both or
		// neither.
		if err := m.pool.QueryRow(ctx, `WITH legacy AS (
				SELECT l.id, `+scanTime+` AS at,
				       coalesce(coalesce(l.cleave_result->'files', l.cleave_result->'fs')->0 ? 'pid', false) AS excerpt
				FROM `+m.from+`.samples l
				WHERE l.parent = '' AND l.sha256 ~ '^[0-9a-f]{64}$' AND (l.cleave_result IS NOT NULL OR l.skip = 'timeout')
			), excerpts AS (
				INSERT INTO migrate_excerpts (id) SELECT id FROM legacy WHERE excerpt RETURNING id
			), ordered AS (
				INSERT INTO migrate_order (id) SELECT id FROM legacy WHERE NOT excerpt ORDER BY at, id RETURNING seq
			)
			SELECT (SELECT count(*) FROM ordered), (SELECT count(*) FROM excerpts)`).Scan(&last, &m.report.Excerpts); err != nil {
			return err
		}
	}
	from := int64(0)
	through, err := m.kv(ctx, "migrate:convert:through")
	if err != nil {
		return err
	}
	if through != "" {
		if from, err = strconv.ParseInt(through, 10, 64); err != nil {
			return fmt.Errorf("progress %q: %w", through, err)
		}
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	type span struct{ lo, hi int64 }
	work := make(chan span)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		pending = map[int64]int64{} // finished batches not yet contiguous: lo → hi
		done    = from
	)
	finish := func(s span) error {
		mu.Lock()
		defer mu.Unlock()
		pending[s.lo] = s.hi
		moved := false
		for hi, ok := pending[done]; ok; hi, ok = pending[done] {
			delete(pending, done)
			done, moved = hi, true
		}
		if !moved {
			return nil
		}
		return m.setKV(ctx, "migrate:convert:through", strconv.FormatInt(done, 10))
	}
	for range m.opt.Workers {
		wg.Go(func() {
			for s := range work {
				err := m.convertRange(ctx, s.lo, s.hi)
				if err == nil {
					err = finish(s)
				}
				if err != nil {
					cancel(err)
					return
				}
			}
		})
	}
	started := time.Now()
	for lo := from; lo < last && ctx.Err() == nil; lo += convertBatch {
		select {
		case work <- span{lo, min(lo+convertBatch, last)}:
		case <-ctx.Done():
		}
		if n := (lo - from) / convertBatch; n > 0 && n%100 == 0 {
			slog.InfoContext(ctx, "migrate: converting", "done", lo, "of", last,
				"converted", m.converted(), "elapsed", time.Since(started).Round(time.Second))
		}
	}
	close(work)
	wg.Wait()
	return context.Cause(ctx)
}

func (m *migration) converted() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.report.Converted
}

// convertRange converts and stores the results at positions (lo, hi] of
// migrate_order, in that order.
// A row whose scan legacy gave up on as timed out has no result, and is
// stored as that failed verdict, so the age sweep retries it rather than the
// queue at once.
func (m *migration) convertRange(ctx context.Context, lo, hi int64) error {
	rows, err := m.pool.Query(ctx, `SELECT l.sha256, l.cleave_result::text, l.litmus_result::text, l.llm_result::text,
			coalesce(l.traits_version, ''), `+scanTime+`, l.skip, coalesce(l.top_traits, '')
		FROM migrate_order o JOIN `+m.from+`.samples l ON l.id = o.id
		WHERE o.seq > $1 AND o.seq <= $2
		ORDER BY o.seq`, lo, hi)
	if err != nil {
		return err
	}
	results, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (legacyResult, error) {
		var r legacyResult
		err := row.Scan(&r.sha256, &r.raw, &r.mlSection, &r.interp, &r.ruleset, &r.at, &r.skip, &r.topTraits)
		return r, err
	})
	if err != nil {
		return err
	}
	for _, r := range results {
		files, err := r.files()
		if err != nil {
			m.refuse(ctx, r.sha256, err)
			continue
		}
		if _, err := m.st.Write(ctx, files); err != nil {
			if !errors.Is(err, scanresult.ErrMalformed) {
				return fmt.Errorf("%s: %w", r.sha256, err)
			}
			m.refuse(ctx, r.sha256, err)
			continue
		}
		m.mu.Lock()
		m.report.Converted++
		m.report.Files += int64(len(files))
		m.mu.Unlock()
	}
	return nil
}

// files is the result as the writer takes it.
func (r *legacyResult) files() ([]scanresult.File, error) {
	if r.raw == nil {
		sha, err := hex.DecodeString(r.sha256)
		return []scanresult.File{{
			SHA256: sha, Verdict: json.RawMessage(`{"outcome":"timeout"}`),
			Scan: scanresult.Stamp{At: r.at.UTC(), Ruleset: r.ruleset, Worker: "migrate"},
		}}, err
	}
	c, err := v7result.Convert(&v7result.Result{
		At: r.at.UTC(), SHA256: r.sha256, Worker: "migrate", Ruleset: r.ruleset,
		ML: raw(r.mlSection), LLM: raw(r.interp), Raw: raw(r.raw),
	}, hopper.CriticalLevel)
	if err != nil {
		return nil, err
	}
	// The result was formed at scanTime; the converter would take the ML
	// section's own, which an analysis that reused it leaves older.
	for i := range c.Files {
		c.Files[i].Scan.At = r.at.UTC()
	}
	if err := r.keepTopTraits(c.Files); err != nil {
		return nil, err
	}
	return c.Files, nil
}

// keepTopTraits gives the scanned file's verdict the findings legacy kept
// in top_traits when the converter read none: a report older than version 6,
// whose traits it does not parse, still carried them, and lookup showed them.
func (r *legacyResult) keepTopTraits(files []scanresult.File) error {
	if len(files) == 0 || files[0].Verdict == nil || r.topTraits == "" {
		return nil
	}
	var verdict map[string]json.RawMessage
	if err := json.Unmarshal(files[0].Verdict, &verdict); err != nil {
		return fmt.Errorf("verdict: %w", err)
	}
	if _, has := verdict["top"]; has {
		return nil
	}
	var top []scanresult.Finding
	if err := json.Unmarshal([]byte(r.topTraits), &top); err != nil {
		return nil //nolint:nilerr // a top_traits legacy could not write cleanly is left behind, not fatal
	}
	top = slices.DeleteFunc(top, func(f scanresult.Finding) bool { return f.ID == "" || f.Crit < 4 })
	if len(top) == 0 {
		return nil
	}
	encoded, err := json.Marshal(top[:min(len(top), 3)])
	if err != nil {
		return err
	}
	verdict["top"] = encoded
	if files[0].Verdict, err = json.Marshal(verdict); err != nil {
		return err
	}
	return nil
}

func raw(s *string) []byte {
	if s == nil {
		return nil
	}
	return []byte(*s)
}

// refuse counts a result the converter or the writer would not take, by
// the reason with the digest left out, and logs the first of each reason.
func (m *migration) refuse(ctx context.Context, sha256 string, err error) {
	reason := strings.ReplaceAll(err.Error(), sha256, "<sha256>")
	if len(reason) > 120 {
		reason = reason[:120]
	}
	m.mu.Lock()
	m.report.Failed++
	m.report.Failures[reason]++
	first := m.report.Failures[reason] == 1
	m.mu.Unlock()
	if first {
		slog.WarnContext(ctx, "migrate: result refused", "sha256", sha256, "error", err)
	}
}

// A path names one file. Where legacy recorded a path for two files (bytes
// that replaced others there), the most recently seen wins.
const locationConflict = `ON CONFLICT (path) DO UPDATE SET sample_id = EXCLUDED.sample_id, source = EXCLUDED.source,
	feed = EXCLUDED.feed, mtime = EXCLUDED.mtime, seen_at = EXCLUDED.seen_at
	WHERE locations.seen_at < EXCLUDED.seen_at`

// locations records every top-level placement legacy knew: the rows of
// sample_locations with no parent (most top-level files keep their path
// only there), in id ranges, which reads that table once in its order. Its
// member placements, nearly all of its 4.9 billion rows, are not wanted:
// a member's path is in its container's contents. A path legacy knew gone
// is retired by the first reconcile walk, which also learns any copy legacy
// missed.
func (m *migration) locations(ctx context.Context) error {
	return m.ranges(ctx, "locations", "sample_locations", func(ctx context.Context, lo, hi int64) error {
		tag, err := m.pool.Exec(ctx, `INSERT INTO locations (path, sample_id, source, feed, mtime, seen_at)
			SELECT DISTINCT ON (l.path) l.path, s.id, nullif(l.source, ''), nullif(l.feed, ''), l.mtime,
			       coalesce(l.last_seen_at, l.first_seen_at, now())
			FROM `+m.from+`.sample_locations l
			JOIN samples s ON s.sha256 = decode(l.sha256, 'hex')
			WHERE l.id > $1 AND l.id <= $2 AND l.parent_sha256 = '' AND l.path <> ''
			  AND octet_length(l.path) <= 1024 AND l.sha256 ~ '^[0-9a-f]{64}$'
			ORDER BY l.path, l.last_seen_at DESC NULLS LAST
			`+locationConflict, lo, hi)
		if err != nil {
			return err
		}
		m.report.Locations += tag.RowsAffected()
		return nil
	})
}

// paths adds the path legacy kept on a top-level sample row, where
// sample_locations did not have it, unless legacy knew it gone (missing) or
// held by newer bytes (replaced).
func (m *migration) paths(ctx context.Context) error {
	return m.ranges(ctx, "paths", "samples", func(ctx context.Context, lo, hi int64) error {
		tag, err := m.pool.Exec(ctx, `INSERT INTO locations (path, sample_id, source, feed, mtime, seen_at)
			SELECT DISTINCT ON (l.path) l.path, l.id, nullif(l.source, ''), nullif(l.feed, ''), l.mtime,
			       coalesce(l.updated_at, l.created_at)
			FROM `+m.from+`.samples l
			WHERE l.id > $1 AND l.id <= $2 AND l.parent = '' AND l.path <> '' AND octet_length(l.path) <= 1024
			  AND l.skip NOT IN ('missing', 'replaced') AND EXISTS (SELECT 1 FROM samples s WHERE s.id = l.id)
			ORDER BY l.path, l.updated_at DESC NULLS LAST
			`+locationConflict, lo, hi)
		if err != nil {
			return err
		}
		m.report.Locations += tag.RowsAffected()
		return nil
	})
}

// carried copies the tables that keep their shape, the triage reports with
// their sample ids, and the ledger with its package subjects spelled as the
// store spells names.
func (m *migration) carried(ctx context.Context) error {
	for _, table := range []string{
		"sightings", "label_events", "popular_packages", "sighting_acquisitions",
		"gauntlet_runs", "gauntlet_samples", "gauntlet_results", "gauntlet_withdrawals",
	} {
		n, err := m.copyTable(ctx, table)
		if err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
		if table == "sightings" {
			m.report.Sightings = n
		} else {
			m.report.Carried += n
		}
	}
	tag, err := m.pool.Exec(ctx, `INSERT INTO reports (id, sample_id, report_type, content, provider, duration_ms, evidence_key, created_at)
		SELECT r.id, s.id, r.report_type, r.content, coalesce(r.provider, ''), coalesce(r.duration_ms, 0),
		       coalesce(r.evidence_key, ''), r.created_at
		FROM `+m.from+`.reports r JOIN samples s ON s.sha256 = decode(r.sha256, 'hex')
		WHERE r.sha256 ~ '^[0-9a-f]{64}$'
		ON CONFLICT DO NOTHING`)
	if err != nil {
		return fmt.Errorf("reports: %w", err)
	}
	m.report.Reports = tag.RowsAffected()
	return m.respell(ctx)
}

// copyTable copies a table the migration does not reshape: the columns both
// sides have, rows already copied left alone. A table the legacy schema
// lacks (the replica carries no gauntlet tables) copies nothing.
func (m *migration) copyTable(ctx context.Context, table string) (int64, error) {
	rows, err := m.pool.Query(ctx, `SELECT t.column_name FROM information_schema.columns t
		JOIN information_schema.columns f ON f.table_schema = $2 AND f.table_name = t.table_name AND f.column_name = t.column_name
		WHERE t.table_schema = $1 AND t.table_name = $3 ORDER BY t.ordinal_position`, m.opt.To, m.opt.From, table)
	if err != nil {
		return 0, err
	}
	cols, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(cols) == 0 {
		return 0, err
	}
	list := make([]string, len(cols))
	for i, c := range cols {
		list[i] = pgx.Identifier{c}.Sanitize()
	}
	names := strings.Join(list, ", ")
	t := pgx.Identifier{table}.Sanitize()
	tag, err := m.pool.Exec(ctx, `INSERT INTO `+t+` (`+names+`) SELECT `+names+` FROM `+m.from+`.`+t+` ON CONFLICT DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// respell rewrites each package subject not spelled as the store spells a
// name. Where the respelled row would repeat one already there, the old
// spelling's row goes.
func (m *migration) respell(ctx context.Context) error {
	rows, err := m.pool.Query(ctx, `SELECT DISTINCT subject FROM sightings WHERE subject LIKE 'pkg:%'`)
	if err != nil {
		return err
	}
	subjects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, old := range subjects {
		name := store.NameOf(old)
		if name == old || name == "" {
			continue
		}
		err := pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE sightings g SET subject = $2 WHERE g.subject = $1
				AND NOT EXISTS (SELECT 1 FROM sightings d WHERE d.source = g.source AND d.subject = $2 AND d.affected = g.affected)`,
				old, name); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM sightings WHERE subject = $1`, old)
			return err
		})
		if err != nil {
			return fmt.Errorf("respell %q: %w", old, err)
		}
		m.report.Respelled++
	}
	return nil
}

// exec runs one statement of the post stage and logs how long it took, so a
// step that grows faster than the data shows in the log.
func (m *migration) exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	start := time.Now()
	tag, err := m.pool.Exec(ctx, sql, args...)
	step, _, _ := strings.Cut(strings.Join(strings.Fields(sql), " "), " WHERE ")
	if len(step) > 80 {
		step = step[:80]
	}
	slog.InfoContext(ctx, "migrate: post step", "step", step, "rows", tag.RowsAffected(),
		"took", time.Since(start).Round(time.Millisecond), "error", err)
	return tag, err
}

// post builds what the load left for the end and derives what depends on
// everything being there.
func (m *migration) post(ctx context.Context) error {
	_, indexes := split(store.Schema)
	for _, ddl := range indexes {
		if _, err := m.exec(ctx, ddl); err != nil {
			return fmt.Errorf("index: %w", err)
		}
	}
	for _, sql := range []string{
		`ALTER INDEX contents_parents SET (fastupdate = off)`,
		`SELECT gin_clean_pending_list('contents_parents'::regclass)`,
		// A file labelled bad is triage's business from its last scan on.
		`UPDATE scans sc SET flagged = true FROM samples s WHERE s.id = sc.sample_id AND s.label = 'bad' AND NOT sc.flagged`,
	} {
		if _, err := m.exec(ctx, sql); err != nil {
			return fmt.Errorf("%.40s: %w", sql, err)
		}
	}
	// An excerpt's file is dropped where nothing accounts for it: no label,
	// name, URL, provenance, location, opinion, list it is in or holds, report,
	// label event, sighting by digest, or reference that fetched it. Most are
	// the registry sidecars legacy filed as files. Each test is a NOT EXISTS
	// of one equality, which the planner runs as a hash anti-join: written as
	// one test with OR, the refs test was a nested loop over every ref for
	// every excerpt, 6 minutes at 50,000 results and growing with the square.
	tag, err := m.exec(ctx, `DELETE FROM samples s USING migrate_excerpts e
		WHERE s.id = e.id AND s.label = 'unknown' AND s.name_id IS NULL AND s.url IS NULL AND s.provenance IS NULL
		  AND NOT EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM scans sc WHERE sc.sample_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM claims c WHERE c.sample_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM contents c WHERE c.parent_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM contents c WHERE c.child_ids @> ARRAY[s.id])
		  AND NOT EXISTS (SELECT 1 FROM refs r WHERE r.sample_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM refs r WHERE r.fetched = s.sha256)
		  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.sample_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM label_events le WHERE le.sha256 = encode(s.sha256, 'hex'))
		  AND NOT EXISTS (SELECT 1 FROM sightings g WHERE g.subject = encode(s.sha256, 'hex'))`)
	if err != nil {
		return fmt.Errorf("excerpts: %w", err)
	}
	m.report.Dropped = tag.RowsAffected()
	start := time.Now()
	if m.report.Marked, _, err = m.st.Recite(ctx); err != nil {
		return err
	}
	slog.InfoContext(ctx, "migrate: post step", "step", "recite", "rows", m.report.Marked, "took", time.Since(start).Round(time.Millisecond))
	start = time.Now()
	if m.report.Queued, err = m.st.QueueUnscanned(ctx); err != nil {
		return err
	}
	slog.InfoContext(ctx, "migrate: post step", "step", "queue unscanned", "rows", m.report.Queued, "took", time.Since(start).Round(time.Millisecond))
	for _, table := range []string{"names", "samples", "reports", "label_events"} {
		t := pgx.Identifier{table}.Sanitize()
		if _, err := m.exec(ctx, `SELECT setval(pg_get_serial_sequence($1, 'id'), greatest((SELECT max(id) FROM `+t+`), 1))`,
			table); err != nil {
			return fmt.Errorf("sequence %s: %w", table, err)
		}
	}
	// The keys the writer needed through the load were filled out of order
	// (sha256 is random, and the converters interleave member ids), leaving
	// their pages about two-thirds full; rebuilt, verdicts_pkey and
	// samples_sha256_key measured a quarter smaller. Built once more over the
	// finished tables, they start packed, and verdicts' stays so: new ids
	// only grow.
	for _, sql := range []string{
		`DROP TABLE IF EXISTS migrate_names`, `DROP TABLE IF EXISTS migrate_order`, `DROP TABLE IF EXISTS migrate_excerpts`,
		`REINDEX INDEX verdicts_pkey`, `REINDEX INDEX samples_sha256_key`, `REINDEX INDEX samples_pkey`,
		`REINDEX INDEX refs_pkey`, `REINDEX INDEX claims_pkey`, `REINDEX INDEX locations_pkey`,
		`VACUUM (ANALYZE) samples`, `ANALYZE`,
	} {
		if _, err := m.exec(ctx, sql); err != nil {
			return fmt.Errorf("%s: %w", sql, err)
		}
	}
	return nil
}
