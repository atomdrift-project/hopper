-- The prototype's baseline, loaded beside the verdict schema
-- (internal/store/schema.sql) in a local disposable database.
--
-- Baseline: today's samples layout for the same rows, so both sides of a size
-- or WAL comparison hold identical data.
CREATE TABLE legacy_samples (
	id bigint PRIMARY KEY, sha256 text UNIQUE NOT NULL,
	source text, feed text, ecosystem text, url text, package text, version text, purl_base text,
	filename text, file_type text, size_bytes bigint, label text, label_source text, path text,
	parent text, skip text, status text, score int, max_crit int, suspicious_count int,
	traits_version text, created_at timestamptz, analyzed_at timestamptz, first_analyzed_at timestamptz,
	fetched_at timestamptz, corroborated boolean, lvl int, litmus_class smallint, top_traits text,
	cleave_result jsonb, litmus_result jsonb, llm_result jsonb, provenance jsonb
);
CREATE INDEX legacy_analyzed ON legacy_samples (analyzed_at DESC) WHERE analyzed_at IS NOT NULL;
CREATE INDEX legacy_parent   ON legacy_samples (parent) WHERE parent <> '';
CREATE INDEX legacy_purl     ON legacy_samples (purl_base, version) WHERE purl_base <> '';
