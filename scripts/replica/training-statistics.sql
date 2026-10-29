CREATE STATISTICS IF NOT EXISTS samples_training_hash_stats
ON (substr(md5(lower(COALESCE(NULLIF(canonical_sha256, ''), sha256))), 1, 8))
FROM public.samples;
