-- Run with psql -X -q -w -At -v ON_ERROR_STOP=1; save stdout as seeds.jsonl.
-- The standalone predicate uses idx_sl_donor rather than scanning the entire
-- multi-billion-row location heap. Archive members with reviewed labels are
-- included below; descendant locations are a separate inventory step.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '300s';
SELECT json_build_object('sha256', sha256, 'path', path, 'kind', 'standalone')
FROM sample_locations
WHERE parent_sha256 = ''
  AND (path LIKE 'purgatory/%' OR path LIKE 'inconclusive/%' OR path LIKE 'dual-use/%');
SELECT json_build_object('sha256', sha256, 'path', path, 'kind', 'label')
FROM samples WHERE label IN ('purgatory', 'inconclusive', 'dual-use');
ROLLBACK;
