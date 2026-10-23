CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_samples_training_hash
ON public.samples (substr(md5(lower(COALESCE(NULLIF(canonical_sha256, ''), sha256))), 1, 8), id)
INCLUDE (sha256, canonical_sha256, label, score, file_type)
WHERE label IN ('bad', 'good') AND cleave_result IS NOT NULL AND skip = '';
