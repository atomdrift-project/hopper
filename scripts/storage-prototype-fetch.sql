-- Read-only export of every existing direct-child location for all catalogued
-- versions of one package. Some versions may have no catalogued members.
-- Usage: psql -X -q -v purl='pkg:npm/lodash' -f this-file.sql > lodash.csv
-- A timeout leaves an incomplete CSV: discard it, never count it as a cohort.
\set ON_ERROR_STOP on
SET default_transaction_read_only = on;
SET statement_timeout = '30s';
SET lock_timeout = '1s';
COPY (
 SELECT p.purl_base, p.version, p.id AS parent_catalog_id,
        l.id, l.sha256, l.path, l.parent_sha256, l.rel, l.filename,
        l.source, l.feed, l.ecosystem, l.mtime, l.first_seen_at, l.last_seen_at
 FROM samples p
 JOIN LATERAL (
   SELECT * FROM sample_locations
   WHERE parent_sha256 = p.sha256 AND parent_sha256 <> '' OFFSET 0
 ) l ON true
 WHERE p.purl_base <> '' AND p.purl_base = :'purl'
) TO STDOUT WITH (FORMAT csv, HEADER true);
