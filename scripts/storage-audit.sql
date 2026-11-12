-- Read-only storage inventory. Run separately on the primary and each replica:
--   psql -X -d hopper -f scripts/storage-audit.sql
-- Catalog sizes are exact; reltuples and dead-tuple counts are estimates.
-- Crash recovery can reset usage counters without restoring their old values.
-- A zero scan count never establishes that an index is safe to drop.
\set ON_ERROR_STOP on
\pset pager off
BEGIN READ ONLY;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '1s';

SELECT now(), pg_postmaster_start_time(), pg_size_pretty(pg_database_size(current_database())) AS database_size;
SELECT stats_reset FROM pg_stat_database WHERE datname = current_database();

SELECT c.relname, c.reltuples::bigint AS estimated_rows,
       pg_size_pretty(pg_relation_size(c.oid)) AS heap,
       pg_size_pretty(pg_total_relation_size(c.reltoastrelid)) AS toast,
       pg_size_pretty(pg_indexes_size(c.oid)) AS indexes,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total,
       s.n_dead_tup, s.last_autovacuum, s.last_autoanalyze, c.reloptions
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY pg_total_relation_size(c.oid) DESC;

SELECT s.relname, s.indexrelname,
       pg_size_pretty(pg_relation_size(s.indexrelid)) AS size,
       s.idx_scan, s.last_idx_scan, i.indisunique, i.indisprimary,
       i.indisreplident, i.indisvalid,
       EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conindid = i.indexrelid) AS backs_constraint,
       regexp_replace(pg_get_indexdef(s.indexrelid), '[[:space:]]+', ' ', 'g') AS definition
FROM pg_stat_user_indexes s JOIN pg_index i ON i.indexrelid = s.indexrelid
WHERE s.schemaname = 'public'
ORDER BY pg_relation_size(s.indexrelid) DESC;

-- Exact duplicate keys, operator classes, collations, ordering and predicates.
-- These are review candidates; integrity dependencies must still be preserved.
SELECT i.indrelid::regclass AS tablename, array_agg(i.indexrelid::regclass) AS duplicates
FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
GROUP BY i.indrelid, i.indkey, i.indclass, i.indcollation, i.indoption,
         i.indexprs::text, i.indpred::text
HAVING count(*) > 1;

SELECT tablename, attname, avg_width, null_frac, n_distinct
FROM pg_stats
WHERE schemaname = 'public' AND tablename IN ('samples', 'sample_locations')
ORDER BY tablename, avg_width DESC;

SELECT name, setting, unit FROM pg_settings
WHERE name IN ('autovacuum', 'autovacuum_max_workers', 'autovacuum_vacuum_threshold',
               'autovacuum_vacuum_max_threshold', 'autovacuum_vacuum_scale_factor',
               'autovacuum_analyze_scale_factor', 'autovacuum_work_mem',
               'default_toast_compression');
COMMIT;

-- Optional bounded page samples; SYSTEM samples can be biased by clustering.
-- They estimate representation costs, not bloat or total prune savings.
-- SELECT count(*), avg(pg_column_size(l)), avg(length(path))
-- FROM sample_locations l TABLESAMPLE SYSTEM(0.001) REPEATABLE(1111);
-- SELECT count(*), avg(pg_column_size(cleave_result)), avg(pg_column_size(trait_graph))
-- FROM samples s TABLESAMPLE SYSTEM(0.002) REPEATABLE(1111);
