package storageproto

const unchangedBatchSQL = `SELECT NOT EXISTS(
 SELECT 1 FROM _staging st LEFT JOIN identities s ON s.sha256=st.sha
 LEFT JOIN locations l ON l.sample_id=s.id AND l.full_path_key=path_key(st.path)
 LEFT JOIN parent_locations p ON p.id=l.parent_location_id
 LEFT JOIN relative_paths r ON r.id=l.relative_path_id
 WHERE l.id IS NULL OR (` + changedSQL + `)
 OR coalesce(p.path||'!!'||r.path,l.path) IS DISTINCT FROM st.path)`

const resolveSamplesSQL = `INSERT INTO identities(sha256)
 SELECT sha FROM (SELECT sha FROM _staging UNION SELECT parent_sha FROM _staging WHERE parent_sha IS NOT NULL) d
 WHERE NOT EXISTS(SELECT 1 FROM identities s WHERE s.sha256=d.sha)
 ORDER BY sha ON CONFLICT DO NOTHING`

// Scalar lookups express the dictionary's unique-key contract. Hash joins here
// scanned and rehashed the entire dictionary for each small incoming batch.
const resolvePathsSQL = `INSERT INTO relative_paths(path)
 SELECT path FROM (SELECT DISTINCT relative_path AS path FROM _staging WHERE relative_path IS NOT NULL) d
 WHERE (SELECT id FROM relative_paths p WHERE path_key(p.path)=path_key(d.path)) IS NULL
 ORDER BY path_key(path),path ON CONFLICT DO NOTHING`

const resolveParentsSQL = `INSERT INTO parent_locations(sample_id,path)
 SELECT s.id,d.path FROM (SELECT DISTINCT parent_sha,parent_path AS path FROM _staging WHERE parent_path IS NOT NULL) d
 JOIN identities s ON s.sha256=d.parent_sha
 WHERE NOT EXISTS(SELECT 1 FROM parent_locations p WHERE p.sample_id=s.id AND path_key(p.path)=path_key(d.path))
 ORDER BY s.id,path_key(d.path),d.path ON CONFLICT DO NOTHING`

const resolveLocationsSQL = `CREATE TEMP TABLE _resolved ON COMMIT DROP AS
 WITH samples AS MATERIALIZED (
 SELECT st.path,st.filename,st.rel,st.source,st.feed,st.ecosystem,st.mtime,st.parent_path,st.relative_path,
 (SELECT id FROM identities WHERE sha256=st.sha) AS sample_id,
 (SELECT id FROM identities WHERE sha256=st.parent_sha) AS parent_sample_id FROM _staging st)
 SELECT
 st.sample_id,st.parent_sample_id,
 (SELECT id FROM parent_locations p WHERE p.sample_id=st.parent_sample_id
 AND path_key(p.path)=path_key(st.parent_path) AND p.path=st.parent_path) AS parent_location_id,
 (SELECT id FROM relative_paths r
 WHERE path_key(r.path)=path_key(st.relative_path) AND r.path=st.relative_path) AS relative_path_id,
 st.path AS full_path,path_key(st.path) AS full_path_key,
 CASE WHEN st.relative_path IS NULL THEN st.path END AS path,
 CASE WHEN st.filename=coalesce(st.relative_path,st.path) THEN NULL ELSE st.filename END AS filename_override,
 st.rel,st.source,st.feed,st.ecosystem,st.mtime
 FROM samples st`

const checkLocationsSQL = `SELECT EXISTS(
 SELECT 1 FROM _resolved WHERE path IS NULL AND (parent_location_id IS NULL OR relative_path_id IS NULL))
 OR EXISTS(SELECT 1 FROM _resolved GROUP BY sample_id,full_path_key HAVING min(full_path)<>max(full_path))
 OR EXISTS(
 SELECT 1 FROM _resolved st JOIN locations l ON l.sample_id=st.sample_id AND l.full_path_key=st.full_path_key
 LEFT JOIN parent_locations p ON p.id=l.parent_location_id LEFT JOIN relative_paths r ON r.id=l.relative_path_id
 WHERE coalesce(p.path||'!!'||r.path,l.path) IS DISTINCT FROM st.full_path)`

const changedSQL = `(st.rel<>'' AND st.rel IS DISTINCT FROM l.rel)
 OR (l.source='' AND st.source<>'')
 OR (st.feed<>'' AND st.feed IS DISTINCT FROM l.feed)
 OR (st.ecosystem<>'' AND st.ecosystem IS DISTINCT FROM l.ecosystem)
 OR (st.mtime IS NOT NULL AND st.mtime IS DISTINCT FROM l.mtime)`

const writeLocationsSQL = `INSERT INTO locations AS l
 (sample_id,parent_sample_id,parent_location_id,relative_path_id,path,full_path_key,filename_override,rel,source,feed,ecosystem,mtime)
 SELECT DISTINCT ON(st.sample_id,st.full_path_key)
 st.sample_id,st.parent_sample_id,st.parent_location_id,st.relative_path_id,st.path,st.full_path_key,
 st.filename_override,st.rel,st.source,st.feed,st.ecosystem,st.mtime
 FROM _resolved st
 LEFT JOIN locations l ON l.sample_id=st.sample_id AND l.full_path_key=st.full_path_key
 WHERE l.id IS NULL OR (` + changedSQL + `)
 ORDER BY st.sample_id,st.full_path_key
 ON CONFLICT(sample_id,full_path_key) DO UPDATE SET
 rel=CASE WHEN EXCLUDED.rel<>'' THEN EXCLUDED.rel ELSE l.rel END,
 source=CASE WHEN l.source='' THEN EXCLUDED.source ELSE l.source END,
 feed=CASE WHEN EXCLUDED.feed<>'' THEN EXCLUDED.feed ELSE l.feed END,
 ecosystem=CASE WHEN EXCLUDED.ecosystem<>'' THEN EXCLUDED.ecosystem ELSE l.ecosystem END,
 mtime=coalesce(EXCLUDED.mtime,l.mtime)
 WHERE (EXCLUDED.rel<>'' AND EXCLUDED.rel IS DISTINCT FROM l.rel)
 OR (l.source='' AND EXCLUDED.source<>'')
 OR (EXCLUDED.feed<>'' AND EXCLUDED.feed IS DISTINCT FROM l.feed)
 OR (EXCLUDED.ecosystem<>'' AND EXCLUDED.ecosystem IS DISTINCT FROM l.ecosystem)
 OR (EXCLUDED.mtime IS NOT NULL AND EXCLUDED.mtime IS DISTINCT FROM l.mtime)`
