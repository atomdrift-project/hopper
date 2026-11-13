-- Broad page sample to contrast with complete package-version cohorts.
-- SYSTEM samples are clustered and miss reuse elsewhere in the corpus.
-- Do not extrapolate the sampled distinct-path fraction to all locations.
\set ON_ERROR_STOP on
SET default_transaction_read_only = on;
SET statement_timeout = '30s';
SET lock_timeout = '1s';
COPY (
 SELECT '' AS purl_base,'' AS version,0::bigint AS parent_catalog_id,
        id,sha256,path,parent_sha256,rel,filename,source,feed,ecosystem,
        mtime,first_seen_at,last_seen_at
 FROM sample_locations TABLESAMPLE SYSTEM(0.001) REPEATABLE(905)
) TO STDOUT WITH (FORMAT csv,HEADER true);
