-- Read paths and rescan WAL for the prototype. Run after measure.sql.
\pset footer off
\timing off

-- inside reports what an archive would install beyond its own verdict: the
-- worst atomscan class among everything it contains, contained files labelled
-- bad, and declared references whose resolved releases are bad or hostile. It
-- walks one level at a time with arrays, as hopper's Go loop would: a recursive
-- CTE gets estimated at thousands of rows and plans hash joins over whole
-- tables. Content addressing makes a cycle a quine; the depth bound ends it.
CREATE OR REPLACE FUNCTION inside(root bigint, OUT files bigint, OUT worst class,
	OUT bad_files bigint, OUT refs bigint, OUT bad_refs bigint, OUT truncated boolean)
LANGUAGE plpgsql STABLE AS $$
DECLARE
	atomscan constant smallint := 1;
	frontier bigint[] := ARRAY[root];
	reach    bigint[] := '{}';
	depth    int := 0;
BEGIN
	LOOP
		frontier := ARRAY(SELECT DISTINCT u FROM contents c, unnest(c.child_ids) u WHERE c.parent_id = ANY (frontier));
		EXIT WHEN cardinality(frontier) = 0;
		depth := depth + 1;
		truncated := depth > 16 OR cardinality(reach) > 100000;
		EXIT WHEN truncated;
		reach := reach || frontier;
	END LOOP;
	SELECT count(DISTINCT x) INTO files FROM unnest(reach) x;
	SELECT max(v.class) INTO worst FROM verdicts v WHERE v.sample_id = ANY (reach) AND v.scanner_id = atomscan;
	SELECT count(*) INTO bad_files FROM samples s WHERE s.id = ANY (reach) AND s.label = 'bad';
	SELECT count(*), count(*) FILTER (WHERE EXISTS (
			SELECT 1 FROM samples s LEFT JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = atomscan
			WHERE s.name_id = f.name_id AND (f.version = '' OR s.version = f.version)
			  AND (s.label = 'bad' OR v.class = 'hostile')))
	INTO refs, bad_refs
	FROM refs f WHERE f.sample_id = ANY (reach || root);
	truncated := coalesce(truncated, false);
END
$$;

-- referrers lists the outermost files that contain, at any depth, a file
-- declaring the given name: who is exposed when that name turns hostile.
CREATE OR REPLACE FUNCTION referrers(name text) RETURNS TABLE (sample_id bigint)
LANGUAGE sql STABLE AS $$
	WITH RECURSIVE up(id) AS (
		SELECT r.sample_id FROM names n JOIN refs r ON r.name_id = n.id
		WHERE text_key(n.name) = text_key(referrers.name) AND n.name = referrers.name
		UNION
		SELECT c.parent_id FROM up JOIN contents c ON c.child_ids @> ARRAY[up.id]
	)
	SELECT id FROM up WHERE NOT EXISTS (SELECT 1 FROM contents c WHERE c.child_ids @> ARRAY[up.id])
$$;

\echo '== archive sizes in the sample (direct members)'
SELECT width_bucket(n, ARRAY[10, 100, 1000, 10000]) AS bucket, count(*), min(n), max(n)
FROM (SELECT parent_id, cardinality(child_ids) n FROM contents) x GROUP BY 1 ORDER BY 1;

\echo '== inside(): one archive per size, warm'
SELECT t.n AS direct_members, (inside(t.parent_id)).*
FROM (SELECT DISTINCT ON (width_bucket(n, ARRAY[10, 160, 1000, 10000])) parent_id, n
      FROM (SELECT parent_id, cardinality(child_ids) n FROM contents) x
      ORDER BY width_bucket(n, ARRAY[10, 160, 1000, 10000]), n DESC) t ORDER BY 1;

\echo '== referrers(): most-declared names'
SELECT n.name, count(*) AS declarations, (SELECT count(*) FROM referrers(n.name)) AS outermost
FROM refs r JOIN names n ON n.id = r.name_id GROUP BY n.name ORDER BY 2 DESC LIMIT 5;

\echo '== declared versions that are ranges, not releases'
SELECT count(*) FILTER (WHERE version ~ '^[~^<>=*]|\s|\|\||x$') AS ranges, count(*) FILTER (WHERE version = '') AS any, count(*) AS total
FROM refs WHERE kind = 'dependency';

-- Triage: every queue starts from a small indexed set and probes by primary
-- key. Scanner ids: 1 atomscan, 2 cleave, 3 ml. Top-level means it has a location.
\echo '== queue: discord (rules hostile, ML benign)'
EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF)
SELECT c.sample_id FROM verdicts c JOIN verdicts m ON m.sample_id = c.sample_id AND m.scanner_id = 3
WHERE c.scanner_id = 2 AND c.class = 'hostile' AND m.class = 'benign'
  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = c.sample_id)
ORDER BY c.scanned_at DESC LIMIT 50;

\echo '== queue: unconvicted hostile (label good or unknown, rules hostile)'
EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF)
SELECT c.sample_id FROM verdicts c JOIN samples s ON s.id = c.sample_id
WHERE c.scanner_id = 2 AND c.class = 'hostile' AND s.label IN ('good', 'unknown')
  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = c.sample_id)
ORDER BY c.scanned_at DESC LIMIT 50;

\echo '== queue: bad (labelled bad, rules do not convict)'
EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, BUFFERS OFF)
SELECT s.id FROM samples s JOIN verdicts c ON c.sample_id = s.id AND c.scanner_id = 2
WHERE s.label = 'bad' AND c.class <> 'hostile'
  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
ORDER BY c.scanned_at DESC LIMIT 50;

-- Rescan WAL: rescan the members of the 40 largest archives under a new
-- ruleset and measure WAL per member for each thing that can happen.
CREATE TEMP TABLE rescan AS
SELECT DISTINCT m.id FROM (SELECT child_ids FROM contents ORDER BY cardinality(child_ids) DESC LIMIT 40) c,
	unnest(c.child_ids) AS m(id)
WHERE EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = m.id AND v.scanner_id = 2);
CREATE TEMP TABLE rescan_legacy AS
SELECT l.sha256 FROM rescan r JOIN samples s ON s.id = r.id JOIN legacy_samples l ON l.sha256 = encode(s.sha256, 'hex');
SELECT (SELECT count(*) FROM rescan) AS members, (SELECT count(*) FROM rescan_legacy) AS legacy_members;
CHECKPOINT;

SELECT pg_current_wal_insert_lsn() AS lsn \gset
UPDATE legacy_samples l SET cleave_result = jsonb_set(l.cleave_result, '{rev}', '"bench1"'),
	traits_version = 'bench1', analyzed_at = now()
FROM rescan_legacy r WHERE l.sha256 = r.sha256;
SELECT 'legacy: rewrite report' AS case,
	round(pg_wal_lsn_diff(pg_current_wal_insert_lsn(), :'lsn') / (SELECT count(*) FROM rescan_legacy)) AS wal_bytes_per_member;

-- Nothing changed: stamp atomscan's row; the jurors are untouched.
SELECT pg_current_wal_insert_lsn() AS lsn \gset
UPDATE verdicts v SET ruleset = 'bench1', scanned_at = now()
FROM rescan r WHERE v.sample_id = r.id AND v.scanner_id = 1;
SELECT 'new: nothing changed' AS case,
	round(pg_wal_lsn_diff(pg_current_wal_insert_lsn(), :'lsn') / (SELECT count(*) FROM rescan)) AS wal_bytes_per_member;
VACUUM verdicts;

-- A new ML model: the ml juror's score moves, class unchanged; atomscan's
-- served level moves with it.
SELECT pg_current_wal_insert_lsn() AS lsn \gset
UPDATE verdicts v SET ruleset = 'bench2', scanned_at = now(), digest = sha256(v.digest),
	summary = v.summary || '{"prob": 0.5}'
FROM rescan r WHERE v.sample_id = r.id AND v.scanner_id = 3;
UPDATE verdicts v SET ruleset = 'bench2', scanned_at = now(), summary = v.summary || '{"fires_at": -1}'
FROM rescan r WHERE v.sample_id = r.id AND v.scanner_id = 1;
SELECT 'new: ML score changed' AS case,
	round(pg_wal_lsn_diff(pg_current_wal_insert_lsn(), :'lsn') / (SELECT count(*) FROM rescan)) AS wal_bytes_per_member;
VACUUM verdicts;

-- New rules changed cleave's report: its row and report are rewritten.
SELECT pg_current_wal_insert_lsn() AS lsn \gset
BEGIN;
UPDATE verdicts v SET ruleset = 'bench3', scanned_at = now(), digest = sha256(v.digest)
FROM rescan r WHERE v.sample_id = r.id AND v.scanner_id = 2;
UPDATE verdict_details d SET detail = d.detail || '\x00'::bytea
FROM rescan r WHERE d.sample_id = r.id AND d.scanner_id = 2;
UPDATE verdicts v SET ruleset = 'bench3', scanned_at = now()
FROM rescan r WHERE v.sample_id = r.id AND v.scanner_id = 1;
COMMIT;
SELECT 'new: cleave report changed' AS case,
	round(pg_wal_lsn_diff(pg_current_wal_insert_lsn(), :'lsn') / (SELECT count(*) FROM rescan)) AS wal_bytes_per_member;

SELECT pg_stat_force_next_flush();
SELECT relname, n_tup_upd, n_tup_hot_upd FROM pg_stat_user_tables
WHERE relname IN ('verdicts', 'verdict_details', 'legacy_samples') ORDER BY 1;
