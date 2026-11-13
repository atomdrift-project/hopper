-- LOCAL DISPOSABLE DATABASE ONLY. This is a storage experiment, not a migration.
-- Run via a local Unix socket against database hopper_schema_prototype:
-- psql -X -qAt -d hopper_schema_prototype -v cohort=lodash
--   -v input_csv=/tmp/lodash.csv -f this-file.sql > lodash-result.json
-- Input: successful output of storage-prototype-fetch.sql. A separate schema
-- is created for each cohort; existing schemas cause an error, not deletion.
-- Every layout retains all observed metadata and is loaded in location-ID order.
-- Indexes are built after loading, so results measure compact fresh storage,
-- not production bloat, online-build peaks, or ingestion throughput.
\set ON_ERROR_STOP on
DO $$ BEGIN
 IF current_database()<>'hopper_schema_prototype' OR inet_server_addr() IS NOT NULL THEN
  RAISE EXCEPTION 'use a local Unix socket and disposable database hopper_schema_prototype';
 END IF;
END $$;
CREATE SCHEMA :"cohort";
SET search_path TO :"cohort";
SET statement_timeout = '10min';
CREATE FUNCTION path_key(path text) RETURNS bytea
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
 RETURN sha256(convert_to(path, 'UTF8'));
CREATE TABLE raw (
 purl_base text, version text, parent_catalog_id bigint,
 id bigint, sha256 text, path text, parent_sha256 text, rel text,
 filename text, source text, feed text, ecosystem text, mtime timestamptz,
 first_seen_at timestamptz, last_seen_at timestamptz
);
-- SQL COPY (not \copy) expands the psql filename variable. The CSV must be
-- readable by this local server, which should run as the invoking OS user.
COPY raw FROM :'input_csv' WITH (FORMAT csv, HEADER true);

CREATE TABLE identity_text (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, sha256 text NOT NULL UNIQUE);
INSERT INTO identity_text(sha256)
 SELECT sha FROM (SELECT sha256 AS sha FROM raw UNION SELECT parent_sha256 FROM raw WHERE parent_sha256<>'') x ORDER BY sha;
CREATE TABLE identity_bytes AS SELECT id,decode(sha256,'hex') AS sha256 FROM identity_text;
ALTER TABLE identity_bytes ADD PRIMARY KEY(id), ADD UNIQUE(sha256), ADD CHECK(octet_length(sha256)=32);

CREATE TABLE legacy AS SELECT id,sha256,path,parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at FROM raw ORDER BY id;
CREATE TABLE binary_hashes AS SELECT id,decode(sha256,'hex') AS sha256,path,decode(nullif(parent_sha256,''),'hex') AS parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at FROM raw ORDER BY id;
CREATE TABLE integer_ids AS
 SELECT r.id,s.id AS sample_id,r.path,p.id AS parent_sample_id,r.rel,r.filename,r.source,r.feed,r.ecosystem,r.mtime,r.first_seen_at,r.last_seen_at
 FROM raw r JOIN identity_text s ON s.sha256=r.sha256 LEFT JOIN identity_text p ON p.sha256=r.parent_sha256 ORDER BY r.id;

-- Synthetic parent placements let this experiment measure the cost of storing
-- prefixes once. A real migration must resolve existing parent location IDs,
-- retain unresolved rows, and preserve nested extraction semantics.
CREATE TABLE parent_locations (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, sample_id bigint NOT NULL, path text NOT NULL);
INSERT INTO parent_locations(sample_id,path)
 SELECT DISTINCT parent_sample_id,left(path,length(path)-length(split_part(path,'!!',-1))-2)
 FROM integer_ids WHERE strpos(path,'!!')>0 AND parent_sample_id IS NOT NULL ORDER BY 1,2;
CREATE UNIQUE INDEX parent_locations_key ON parent_locations(sample_id,path_key(path));
CREATE TABLE relative_inline AS
 SELECT r.id,r.sample_id,r.parent_sample_id,p.id AS parent_location_id,
        CASE WHEN p.id IS NULL THEN r.path ELSE split_part(r.path,'!!',-1) END AS locator,
        CASE WHEN r.filename=CASE WHEN p.id IS NULL THEN r.path ELSE split_part(r.path,'!!',-1) END THEN NULL ELSE r.filename END AS filename_override,
        r.rel,r.source,r.feed,r.ecosystem,r.mtime,r.first_seen_at,r.last_seen_at
 FROM integer_ids r LEFT JOIN parent_locations p
 ON strpos(r.path,'!!')>0 AND p.sample_id=r.parent_sample_id
 AND path_key(p.path)=path_key(left(r.path,length(r.path)-length(split_part(r.path,'!!',-1))-2))
 AND p.path=left(r.path,length(r.path)-length(split_part(r.path,'!!',-1))-2)
 ORDER BY r.id;
CREATE TABLE relative_paths (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,path text NOT NULL UNIQUE);
INSERT INTO relative_paths(path) SELECT DISTINCT locator FROM relative_inline WHERE parent_location_id IS NOT NULL ORDER BY locator;
-- Alternative: the heap owns the string and the lookup index stores only a
-- digest, avoiding a second indexed string and B-tree limits on long names.
-- Production lookup must compare the exact string too; a digest collision
-- must raise an error, never silently alias two different paths.
CREATE TABLE relative_paths_digest AS SELECT * FROM relative_paths ORDER BY id;
ALTER TABLE relative_paths_digest ADD PRIMARY KEY(id);
CREATE UNIQUE INDEX ON relative_paths_digest(path_key(path));
CREATE TABLE relative_interned AS
 SELECT r.id,r.sample_id,r.parent_sample_id,r.parent_location_id,p.id AS relative_path_id,
        CASE WHEN r.parent_location_id IS NULL THEN r.locator END AS path,
        r.filename_override,r.rel,r.source,r.feed,r.ecosystem,r.mtime,r.first_seen_at,r.last_seen_at
 FROM relative_inline r LEFT JOIN relative_paths p ON r.parent_location_id IS NOT NULL AND p.path=r.locator ORDER BY r.id;

-- Preserve the existing seven access paths. Empty partial indexes are included.
DO $$
DECLARE t text; child text; parent text; parented text; root text;
BEGIN
 FOREACH t IN ARRAY ARRAY['legacy','binary_hashes','integer_ids','relative_inline','relative_interned'] LOOP
  EXECUTE format('ALTER TABLE %I ADD PRIMARY KEY(id)',t);
  IF t IN ('legacy','binary_hashes') THEN child:='sha256'; parent:='parent_sha256';
  ELSE child:='sample_id'; parent:='parent_sample_id'; END IF;
  IF t='legacy' THEN parented:=parent||'<>'''''; root:=parent||'=''''';
  ELSE parented:=parent||' IS NOT NULL'; root:=parent||' IS NULL'; END IF;
  EXECUTE format('CREATE INDEX ON %I (%I,%I,id DESC) WHERE %s',t,child,parent,parented);
  EXECUTE format('CREATE INDEX ON %I (%I) WHERE %s',t,parent,parented);
  EXECUTE format('CREATE INDEX ON %I (%I) WHERE %s AND rel IN ('''',''unpacked'')',t,child,parented);
  IF t='relative_inline' THEN
   EXECUTE 'CREATE UNIQUE INDEX ON relative_inline(sample_id,parent_location_id,path_key(locator)) NULLS NOT DISTINCT';
   EXECUTE format('CREATE INDEX ON %I (%I,locator COLLATE "C") WHERE %s',t,child,root);
   EXECUTE format('CREATE INDEX ON %I (first_seen_at,%I,locator) WHERE %s AND locator LIKE ''incoming/%%''',t,child,root);
  ELSIF t='relative_interned' THEN
   EXECUTE 'CREATE UNIQUE INDEX ON relative_interned(sample_id,parent_location_id,relative_path_id) WHERE parent_location_id IS NOT NULL';
   EXECUTE 'CREATE UNIQUE INDEX ON relative_interned(sample_id,path_key(path)) WHERE parent_location_id IS NULL';
   EXECUTE format('CREATE INDEX ON %I (%I,path COLLATE "C") WHERE %s',t,child,root);
   EXECUTE format('CREATE INDEX ON %I (first_seen_at,%I,path) WHERE %s AND path LIKE ''incoming/%%''',t,child,root);
  ELSE
   EXECUTE format('CREATE UNIQUE INDEX ON %I (%I,path_key(path))',t,child);
   EXECUTE format('CREATE INDEX ON %I (%I,path COLLATE "C") WHERE %s',t,child,root);
   EXECUTE format('CREATE INDEX ON %I (first_seen_at,%I,path) WHERE %s AND path LIKE ''incoming/%%''',t,child,root);
  END IF;
 END LOOP;
END $$;

-- Reconstruct full paths and filenames, then compare every original column.
-- This checks byte-for-byte strings, including synthetic embedded locators.
DO $$
BEGIN
 IF EXISTS (
  SELECT id,sha256,path,parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at FROM legacy
  EXCEPT ALL
  SELECT r.id,s.sha256,CASE WHEN p.id IS NULL THEN r.path ELSE p.path||'!!'||d.path END,
         coalesce(parent.sha256,''),r.rel,coalesce(r.filename_override,d.path,r.path),r.source,r.feed,r.ecosystem,r.mtime,r.first_seen_at,r.last_seen_at
  FROM relative_interned r JOIN identity_text s ON s.id=r.sample_id
  LEFT JOIN identity_text parent ON parent.id=r.parent_sample_id
  LEFT JOIN parent_locations p ON p.id=r.parent_location_id LEFT JOIN relative_paths d ON d.id=r.relative_path_id
 ) OR (SELECT count(*) FROM legacy)<>(SELECT count(*) FROM relative_interned) THEN
  RAISE EXCEPTION 'reconstruction failed';
 END IF;
END $$;
VACUUM ANALYZE legacy;
VACUUM ANALYZE binary_hashes;
VACUUM ANALYZE integer_ids;
VACUUM ANALYZE relative_inline;
VACUUM ANALYZE relative_interned;
VACUUM ANALYZE parent_locations;
VACUUM ANALYZE relative_paths;
VACUUM ANALYZE relative_paths_digest;
VACUUM ANALYZE identity_text;
VACUUM ANALYZE identity_bytes;

SELECT jsonb_pretty(jsonb_build_object(
 'cohort',current_schema(), 'postgres',version(),
 'rows',(SELECT count(*) FROM raw),
 'versions_with_locations',(SELECT count(DISTINCT nullif(version,'')) FROM raw),
 'parent_contents',(SELECT count(DISTINCT nullif(parent_sha256,'')) FROM raw),
 'parent_placements',(SELECT count(*) FROM parent_locations),
 'sample_identities',(SELECT count(*) FROM identity_text),
 'distinct_relative_paths',(SELECT count(*) FROM relative_paths),
 'average_full_path_bytes',(SELECT round(avg(octet_length(path)),2) FROM raw),
 'average_relative_path_bytes',(SELECT round(avg(octet_length(locator)),2) FROM relative_inline WHERE parent_location_id IS NOT NULL),
 'filename_overrides',(SELECT count(*) FROM relative_inline WHERE filename_override IS NOT NULL),
 'reconstruction_verified',true,
 'relations',(SELECT jsonb_object_agg(relname,jsonb_build_object('heap_bytes',pg_relation_size(oid),'index_bytes',pg_indexes_size(oid),'total_bytes',pg_total_relation_size(oid))) FROM pg_class
  WHERE relnamespace=current_schema()::regnamespace AND relname IN ('legacy','binary_hashes','integer_ids','relative_inline','relative_interned','parent_locations','relative_paths','relative_paths_digest','identity_text','identity_bytes'))
));
