-- Scale test for the packed member list: does a GIN index on child_ids hold
-- up when a few files sit in a large share of all archives?
--
-- Synthetic, ids only (paths do not touch the index). 1.3M archives, about
-- 100M edges. Member counts are log-normal (median 27, mean about 72, cap
-- 100,000). 60% of an archive's members are unique to it; 40% are drawn from
-- a pool of 1M shared files with a steep skew, so child 1 lands in most
-- archives, as an empty file or a common licence does in production.
--
-- Run with psql against the local prototype database. Takes minutes and
-- several GB; drops its tables at the end unless -v keep=1 is given.
\timing on
\pset footer off
SET maintenance_work_mem = '2GB';
SET max_parallel_maintenance_workers = 4;
SELECT setseed(0.42);

DROP TABLE IF EXISTS scale_contents, scale_edges;
CREATE UNLOGGED TABLE scale_contents (
	parent_id bigint PRIMARY KEY,
	child_ids bigint[] COMPRESSION lz4 NOT NULL
);

-- synthetic returns archives lo..hi. The member count is drawn per archive in
-- the inner query; drawing it inside generate_series' bound would evaluate
-- it once for the whole statement.
CREATE OR REPLACE FUNCTION synthetic(lo int, hi int) RETURNS TABLE (parent_id bigint, child_ids bigint[])
LANGUAGE sql VOLATILE AS $$
	SELECT a.p::bigint, ARRAY(
		SELECT CASE WHEN random() < 0.6
			THEN 1000000000 + a.p::bigint * 100000 + i
			ELSE 1 + floor(1000000 * power(random(), 4))::bigint END
		FROM generate_series(1, a.n) AS i)
	FROM (SELECT p, greatest(1, least(100000, exp(random_normal(3.3, 1.4)))::int) AS n
	      FROM generate_series(lo, hi) AS p OFFSET 0) AS a
$$;

\echo '== load 1.3M archives'
INSERT INTO scale_contents SELECT * FROM synthetic(1, 1300000);

SELECT count(*) AS archives, sum(cardinality(child_ids)) AS edges,
       max(cardinality(child_ids)) AS largest,
       pg_size_pretty(pg_total_relation_size('scale_contents')) AS heap_toast_pkey
FROM scale_contents;

\echo '== build GIN'
CREATE INDEX scale_contents_parents ON scale_contents USING gin (child_ids);
SELECT pg_size_pretty(pg_relation_size('scale_contents_parents')) AS gin,
       round(pg_relation_size('scale_contents_parents')::numeric
             / (SELECT sum(cardinality(child_ids)) FROM scale_contents), 1) AS gin_bytes_per_edge;
VACUUM (ANALYZE) scale_contents;

\echo '== how shared are the shared children'
CREATE TEMP TABLE popular AS
SELECT c AS child_id, count(*) AS parents
FROM scale_contents, unnest(child_ids) AS c WHERE c < 1000000000
GROUP BY 1 ORDER BY 2 DESC LIMIT 2000;
SELECT child_id, parents FROM popular WHERE child_id IN (1, 2, 10, 100, 1000) ORDER BY 1;

\echo '== GIN: parents of the most shared child (count, then first 50)'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT count(*) FROM scale_contents WHERE child_ids @> ARRAY[1::bigint];
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT parent_id FROM scale_contents WHERE child_ids @> ARRAY[1::bigint] LIMIT 50;
\echo '== GIN: child 100, child 1000, a unique child'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT parent_id FROM scale_contents WHERE child_ids @> ARRAY[100::bigint] LIMIT 50;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT parent_id FROM scale_contents WHERE child_ids @> ARRAY[1000::bigint] LIMIT 50;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT parent_id FROM scale_contents
WHERE child_ids @> ARRAY[(SELECT child_ids[1] FROM scale_contents WHERE parent_id = 777777)];

\echo '== GIN: fuzzy limit on the most shared child'
SET gin_fuzzy_search_limit = 1000;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT parent_id FROM scale_contents WHERE child_ids @> ARRAY[1::bigint] LIMIT 50;
RESET gin_fuzzy_search_limit;

\echo '== insert 20,000 more archives with the index in place (fastupdate on)'
INSERT INTO scale_contents SELECT * FROM synthetic(1300001, 1320000);
\echo '== same, fastupdate off'
ALTER INDEX scale_contents_parents SET (fastupdate = off);
VACUUM scale_contents;
INSERT INTO scale_contents SELECT * FROM synthetic(1320001, 1340000);

\echo '== alternative: a narrow reverse table with a btree'
CREATE UNLOGGED TABLE scale_edges AS
SELECT DISTINCT c AS child_id, parent_id FROM scale_contents, unnest(child_ids) AS c;
ALTER TABLE scale_edges ADD PRIMARY KEY (child_id, parent_id);
VACUUM (ANALYZE) scale_edges;
SELECT pg_size_pretty(pg_relation_size('scale_edges')) AS heap,
       pg_size_pretty(pg_indexes_size('scale_edges')) AS btree,
       round(pg_total_relation_size('scale_edges')::numeric / count(*), 1) AS bytes_per_edge
FROM scale_edges;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT parent_id FROM scale_edges WHERE child_id = 1 LIMIT 50;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF)
SELECT count(*) FROM scale_edges WHERE child_id = 1;

\if :{?keep}
\else
DROP TABLE scale_contents, scale_edges;
DROP FUNCTION synthetic;
\endif
