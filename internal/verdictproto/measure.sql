-- Measurements over the loaded prototype. Run with psql against the local
-- database after `go run ./internal/verdictproto`. Every number it prints is
-- for the exported sample only; scale by row counts, not by totals.
\pset footer off
VACUUM (ANALYZE) names, samples, scanners, verdicts, verdict_details, contents, refs, locations, legacy_samples;

\echo '== bytes per table (heap, toast, indexes)'
SELECT c.relname AS table, c.reltuples::bigint AS rows,
       pg_size_pretty(pg_relation_size(c.oid)) AS heap,
       pg_size_pretty(coalesce(pg_total_relation_size(c.reltoastrelid), 0)) AS toast,
       pg_size_pretty(pg_indexes_size(c.oid)) AS indexes,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total,
       round(pg_total_relation_size(c.oid) / greatest(c.reltuples, 1)) AS bytes_per_row
FROM pg_class c
WHERE c.relkind = 'r' AND c.relnamespace = 'public'::regnamespace AND c.relname <> 'stage'
ORDER BY pg_total_relation_size(c.oid) DESC;

SELECT pg_size_pretty(sum(pg_total_relation_size(oid))) AS new_layout_total
FROM pg_class WHERE relkind = 'r' AND relnamespace = 'public'::regnamespace
  AND relname NOT IN ('legacy_samples', 'stage');

\echo '== verdicts and reports per scanner'
SELECT sc.name AS scanner, count(*) AS verdicts,
       count(*) FILTER (WHERE v.class = 'benign') AS benign,
       count(*) FILTER (WHERE v.class = 'suspicious') AS suspicious,
       count(*) FILTER (WHERE v.class = 'hostile') AS hostile,
       count(*) FILTER (WHERE v.class IS NULL) AS no_class,
       round(avg(pg_column_size(v.*))) AS avg_row_bytes,
       count(d.sample_id) AS reports, round(avg(octet_length(d.detail))) AS avg_report_bytes
FROM verdicts v JOIN scanners sc ON sc.id = v.scanner_id
LEFT JOIN verdict_details d USING (sample_id, scanner_id)
GROUP BY sc.id, sc.name ORDER BY sc.id;
SELECT pg_size_pretty(pg_relation_size('verdicts_flagged')) AS flagged_index,
       (SELECT count(*) FROM verdicts WHERE class <> 'benign') AS flagged_rows;

\echo '== contents: edges, bytes per edge by part'
SELECT count(DISTINCT c.parent_id) AS containers, count(*) AS edges,
       count(DISTINCT m.child_id) AS distinct_children, count(DISTINCT m.path) AS distinct_paths,
       max(cardinality(c.child_ids)) AS largest
FROM contents c, unnest(c.child_ids, c.paths) AS m(child_id, path);
SELECT round(sum(pg_column_size(child_ids)) / e, 1) AS ids, round(sum(pg_column_size(paths)) / e, 1) AS paths,
       round(pg_relation_size('contents_parents') / e, 1) AS gin,
       round(pg_total_relation_size('contents') / e, 1) AS total
FROM contents, (SELECT sum(cardinality(child_ids))::numeric AS e FROM contents) n GROUP BY e;
-- The loader unions every stored scan of an archive, so a path with two
-- children here is an embedded extraction whose bytes differed between scans.
SELECT count(*) AS multi_child_paths, count(DISTINCT parent_id) AS in_archives FROM (
	SELECT c.parent_id FROM contents c, unnest(c.paths) AS path GROUP BY c.parent_id, path HAVING count(*) > 1) x;

\echo '== refs'
SELECT kind, count(*), count(DISTINCT name_id) AS names, count(*) FILTER (WHERE version = '') AS unversioned FROM refs GROUP BY 1;
SELECT count(*) AS refs_resolving_to_a_sample FROM refs r
WHERE EXISTS (SELECT 1 FROM samples s WHERE s.name_id = r.name_id AND (r.version = '' OR s.version = r.version));
