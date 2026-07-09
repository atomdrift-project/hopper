CREATE TABLE IF NOT EXISTS samples (
	id            BIGSERIAL PRIMARY KEY,
	sha256        TEXT UNIQUE NOT NULL,
	source        TEXT NOT NULL DEFAULT '',
	feed          TEXT NOT NULL DEFAULT '',
	ecosystem     TEXT NOT NULL DEFAULT '',
	url           TEXT NOT NULL DEFAULT '',
	-- domain is the registered domain (eTLD+1) of the url, e.g.
	-- "registry.npmjs.org" → "npmjs.org". Computed by the writer via
	-- golang.org/x/net/publicsuffix so it handles multi-level public
	-- suffixes ("example.co.uk" → "example.co.uk") correctly.
	domain        TEXT NOT NULL DEFAULT '',
	-- package is the software package this file belongs to (e.g. "zfs"
	-- for zfs-2.4.1-r0.apk). Parsed from the download filename using
	-- the format-specific patterns in pkgparse.ParseFilename.
	package       TEXT NOT NULL DEFAULT '',
	version       TEXT NOT NULL DEFAULT '',
	-- purl_base is the version-less canonical Package URL (e.g. "pkg:npm/lodash"),
	-- computed by the collector at ingestion. It is the package's stable identity
	-- across versions: GROUP BY purl_base collapses every version of a package.
	-- Empty for files that aren't a known package ecosystem. The full versioned
	-- PURL is purl_base || '@' || version.
	purl_base     TEXT NOT NULL DEFAULT '',
	filename      TEXT NOT NULL DEFAULT '',
	file_type     TEXT NOT NULL DEFAULT '',
	size_bytes    BIGINT NOT NULL DEFAULT 0,
	label         TEXT NOT NULL DEFAULT 'unknown',
	label_source  TEXT NOT NULL DEFAULT '',
	cleave_result JSONB,
	litmus_result JSONB,
	litmus_score  DOUBLE PRECISION NOT NULL DEFAULT 0,
	-- provenance is the collector's per-artifact sidecar (forager's Sidecar:
	-- artifact bytes, fetch act, feed event, and authoritative registry
	-- snapshot). Mirrors the on-disk <artifact>.forage.json so the catalog is
	-- queryable without reading files. fetched_at is the artifact fetch time
	-- (UTC), distinct from created_at (row-insert time, which diverges when the
	-- hopper-load walk backfills a row long after capture).
	provenance    JSONB,
	fetched_at    TIMESTAMPTZ,
	path  TEXT NOT NULL DEFAULT '',
	status        TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL DEFAULT '',
	canonical_sha256 TEXT NOT NULL DEFAULT '',
	parent        TEXT NOT NULL DEFAULT '',
	skip          TEXT NOT NULL DEFAULT '',
	formula       TEXT NOT NULL DEFAULT '',
	elements      TEXT NOT NULL DEFAULT '',
	score         INTEGER NOT NULL DEFAULT 0,
	max_crit      INTEGER NOT NULL DEFAULT 0,
	suspicious_count INTEGER NOT NULL DEFAULT 0,
	-- corroborated is true when at least one external threat feed has cited this
	-- sample's sha256 or purl_base (see the sightings table). A denormalized flag,
	-- maintained by AddSightings and sample ingest, so the feed's "?feeds=1" filter
	-- stays a single-column predicate that composes with the tuned feed indexes
	-- instead of joining the sightings ledger on the hot read path.
	corroborated  BOOLEAN NOT NULL DEFAULT false,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	analyzed_at   TIMESTAMPTZ,
	first_analyzed_at TIMESTAMPTZ,
	last_error_at TIMESTAMPTZ,
	mtime         TIMESTAMPTZ,
	marker_mtime  TIMESTAMPTZ,
	claimed_by    TEXT NOT NULL DEFAULT '',
	claimed_at    TIMESTAMPTZ,
	traits_version TEXT NOT NULL DEFAULT '',
	-- Set by cyclotron when it first commits to working on a sample (initial
	-- status seed). Used to gate seed queries with a per-sample cooldown so
	-- cyclotron never re-attacks the same unfixable sample in a tight loop.
	cyclotron_attempted_at TIMESTAMPTZ,
	-- attempts counts how many times this sample has been handed to a worker
	-- without producing a result. Poison samples that repeatedly wedge or
	-- crash a worker never report an error, so this is the only signal that
	-- catches them; the reaper skips a row once it crosses MaxClaimAttempts.
	attempts      INTEGER NOT NULL DEFAULT 0,
	-- skipped_at records when skip was last set, for audit and so the queue
	-- can be reasoned about over time.
	skipped_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_samples_label ON samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type);
CREATE INDEX IF NOT EXISTS idx_samples_unanalyzed ON samples(sha256) WHERE cleave_result IS NULL;
CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_samples_path ON samples(path);
CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != '';
-- Indexes on url/domain/package/version live in the runtime migration
-- list (pg.go) so they fire AFTER the ALTER TABLE ADD COLUMN. Putting
-- them here would fail on existing databases that haven't yet acquired
-- the new columns: CREATE TABLE IF NOT EXISTS is a no-op, but CREATE
-- INDEX still tries to read the column.

CREATE TABLE IF NOT EXISTS reports (
	id          BIGSERIAL PRIMARY KEY,
	sha256      TEXT NOT NULL REFERENCES samples(sha256),
	report_type TEXT NOT NULL,
	content     TEXT NOT NULL,
	provider    TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_reports_sha256_type ON reports(sha256, report_type);

-- sightings is the external-corroboration ledger: one row per (source, subject)
-- recording that an outside threat feed, scanner, blog, or advisory cited a
-- sample. subject is either a sha256 (64 hex) or a PURL (pkg:npm/lodash@1.2.3 or
-- the version-less pkg:npm/lodash) — the two namespaces never collide, so one
-- column carries both. The primary key makes writes idempotent: re-recording the
-- same sighting is a no-op unless url/note changed. Producers (gauntlet, forager,
-- cyclotron, promoter) upsert here; prism reads it for the "also detected by"
-- badge. url points at the advisory/blog/report; note is the source's own tag
-- ("malware", "MAL-2024-1234").
CREATE TABLE IF NOT EXISTS sightings (
	source     TEXT NOT NULL,
	subject    TEXT NOT NULL,
	url        TEXT NOT NULL DEFAULT '',
	note       TEXT NOT NULL DEFAULT '',
	first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (source, subject)
);

-- Lookup by subject is the read path (SightingsFor): "who cited this sha/purl?".
CREATE INDEX IF NOT EXISTS idx_sightings_subject ON sightings(subject);

CREATE TABLE IF NOT EXISTS workers (
	name      TEXT PRIMARY KEY,
	last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
	slots     INTEGER NOT NULL DEFAULT 1,
	version   TEXT NOT NULL DEFAULT '',
	traits    TEXT NOT NULL DEFAULT '',
	analyzed  BIGINT NOT NULL DEFAULT 0,
	errors    BIGINT NOT NULL DEFAULT 0
);

-- hopper_kv stores internal key/value state that needs to survive process
-- restart but doesn't belong in a domain table. Used today for the
-- upload-token bootstrap (shared with prism via this row).
CREATE TABLE IF NOT EXISTS hopper_kv (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
