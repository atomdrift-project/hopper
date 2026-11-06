-- Candidate for a production-like test, not an automatic service migration.
-- Build outside a transaction: CREATE INDEX CONCURRENTLY avoids blocking writes,
-- but still scans the entire samples table and can impose substantial load.
-- Benchmark popular and popular-tail with EXPLAIN (ANALYZE, BUFFERS), compare
-- with the existing index, and measure size and ingestion overhead before rollout.
-- Check pg_index.indisvalid after an interrupted build before attempting a retry.
CREATE INDEX CONCURRENTLY idx_samples_popular_recent_candidate
    ON samples (analyzed_at DESC)
    WHERE cleave_result IS NOT NULL AND parent = '' AND path <> ''
      AND skip <> 'conflict' AND max_crit >= 5 AND purl_base <> '';
