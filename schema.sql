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
	-- PURL splices '@' || version in *before* any '?qualifiers' tail (purl-spec
	-- order; a purl_base can carry one, e.g. the AUR's repository_url) — a plain
	-- purl_base || '@' || version misplaces the version for those. See scan's
	-- scripts/bloom_pool.sql for the splice.
	purl_base     TEXT NOT NULL DEFAULT '',
	filename      TEXT NOT NULL DEFAULT '',
	file_type     TEXT NOT NULL DEFAULT '',
	size_bytes    BIGINT NOT NULL DEFAULT 0,
	-- label: 'bad' > 'good' > 'sighted' > 'unknown' (see labelRank in
	-- hopper.go). 'sighted' = a threat feed claimed it, pending verification;
	-- invisible to the training triage queues.
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
	-- sample's sha256 or purl_base (see the sightings table). Any claim counts --
	-- 'suspicious' sets it exactly as 'malicious' does; the graded notion is the
	-- DISTINCT-operator corroboration COUNT, which is a different question asked
	-- of the ledger directly. A denormalized flag, so the feed's "?feeds=1" filter
	-- and the sighted claim tier stay single-column predicates that compose with
	-- the tuned indexes instead of joining the sightings ledger on a hot path.
	-- (Measured 2026-08-24: the join costs 780ms per claim poll at the planner's
	-- best; the flag makes it an ordered seek over a 3,423-row partial index.)
	--
	-- Maintained from two sides, because one side cannot see the other:
	--   * the sightings_corroborate trigger, for a citation that arrives after
	--     the sample -- in the database, so no writer can forget it;
	--   * corroborateStagedBySHAPG / insertSampleNewPG at ingest, for a citation
	--     that was already on file when the sample arrived, which the trigger has
	--     no event to fire on.
	-- Between them those cover every ongoing path, so the flag is correct the
	-- instant a transaction commits and no scheduled sweep maintains it.
	-- reconcile-corroborated re-derives it from the whole ledger in both
	-- directions; that is a repair tool for history and restores, not a
	-- dependency of normal operation.
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
CREATE INDEX IF NOT EXISTS idx_reports_sha256_type_created ON reports(sha256, report_type, created_at DESC);

-- sightings is the external-corroboration ledger: one row per claim an outside
-- threat feed, scanner, blog, or advisory made about a sample. subject is either
-- a sha256 (64 hex) or a PURL (pkg:npm/lodash@1.2.3 or the version-less
-- pkg:npm/lodash) — the two namespaces never collide, so one column carries
-- both. Producers (gauntlet, forager, cyclotron, promoter) upsert here; prism
-- reads it for the "also detected by" badge.
--
-- The key includes affected because one source can make two SEPARATE claims
-- about one package: ossf carries a report for @whalent/agent 0.3.230-0.3.302
-- and another for 0.3.358. Keyed on (source, subject) alone, the second silently
-- replaced the first. Writes stay idempotent: re-recording an unchanged claim is
-- a no-op.
--
-- operator is the body of evidence the source speaks for, and two sources
-- sharing one are ONE voice — osv.dev and the OSSF malicious-packages project
-- publish the same corpus, so counting them separately is how a single opinion
-- becomes "independently corroborated". Corroboration counts DISTINCT operator.
--
-- The two timestamps answer different questions and must never be conflated.
-- published_at is the SOURCE's date and is NULL for the many feeds that publish
-- none (an undated blocklist knows nothing about when an entry appeared).
-- first_seen is when the claim entered OUR world, which for those feeds is the
-- only date there is, and is what "reported in the last 48 hours" means. A
-- source's FIRST import is backdated (see AddSightings) so that adopting a feed
-- does not present its whole backlog as today's news.
CREATE TABLE IF NOT EXISTS sightings (
	source       TEXT NOT NULL,
	subject      TEXT NOT NULL,
	url          TEXT NOT NULL DEFAULT '',
	note         TEXT NOT NULL DEFAULT '',
	operator     TEXT NOT NULL DEFAULT '',
	affected     TEXT NOT NULL DEFAULT '',
	claim        TEXT NOT NULL DEFAULT 'malicious',
	filename     TEXT NOT NULL DEFAULT '',
	-- Opaque provider retrieval identifier. A hint, never artifact identity.
	handle       TEXT NOT NULL DEFAULT '',
	-- basis is how the source arrived at the claim: 'predicted' (a detector
	-- or model fired and nobody adjudicated it), 'hosted' (the source holds
	-- the artifact as malware) or 'reviewed' (a person adjudicated the report
	-- before publication). Stamped by the producer from its parallax source
	-- definition, for the same reason operator is: the judgement belongs
	-- beside the definition it is about, and that lives in a module hopper
	-- must not depend on. A copy of the list here would be a second opinion
	-- that drifts, which is exactly what TrustedBadSources was.
	--
	-- It names a FACT, not a policy: "enough on its own" is enough for what,
	-- and gauntlet, promoter and /v1/lookup each mean a different bar. Each
	-- consumer applies its own threshold to this; see hopper.Assess.
	--
	-- 'predicted' is the fail-safe default, so rows written before the column
	-- existed under-count confidence until their feed re-pushes.
	basis        TEXT NOT NULL DEFAULT 'predicted',
	published_at TIMESTAMPTZ,
	first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (source, subject, affected)
);

-- Lookup by subject is the read path (SightingsFor): "who cited this sha/purl?".
CREATE INDEX IF NOT EXISTS idx_sightings_subject ON sightings(subject);

-- Keeps samples.corroborated in step with the ledger on every write, so the flag
-- can be trusted the instant a transaction commits and nothing has to sweep up
-- afterwards. FOR EACH ROW (not a statement trigger over a transition table): a
-- transition table has no statistics, so the planner can pick a hash join that
-- sequentially scans samples, while constant equality is an index probe by
-- construction -- the same rule the mark statements follow.
--
-- The DELETE arm clears only once the LAST citation is gone: two sources naming
-- one package is the normal case, and dropping one of them must not
-- uncorroborate the sample.
--
-- What no trigger here can see is a sighting already on file when the sample
-- arrives; that is the ingest side's job (corroborateStagedBySHAPG,
-- insertSampleNewPG).
CREATE OR REPLACE FUNCTION sightings_corroborate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
	-- Nested, not one AND-ed condition: SQL does not promise to short-circuit,
	-- and OLD is unassigned on INSERT.
	IF TG_OP IN ('DELETE', 'UPDATE') THEN
		IF NOT EXISTS (SELECT 1 FROM sightings WHERE subject = OLD.subject) THEN
			UPDATE samples SET corroborated = false
			 WHERE corroborated AND sha256 = OLD.subject;
			UPDATE samples SET corroborated = false
			 WHERE purl_base = OLD.subject AND purl_base <> '' AND corroborated;
		END IF;
	END IF;
	IF TG_OP <> 'DELETE' THEN
		UPDATE samples SET corroborated = true
		 WHERE NOT corroborated AND sha256 = NEW.subject;
		UPDATE samples SET corroborated = true
		 WHERE purl_base = NEW.subject AND purl_base <> '' AND NOT corroborated;
	END IF;
	RETURN NULL;
END;
$$;

CREATE OR REPLACE TRIGGER sightings_corroborate_trg
	AFTER INSERT ON sightings
	FOR EACH ROW EXECUTE FUNCTION sightings_corroborate();

CREATE OR REPLACE TRIGGER sightings_uncorroborate_trg
	AFTER DELETE ON sightings
	FOR EACH ROW EXECUTE FUNCTION sightings_corroborate();

-- UPDATE OF subject, so a delta-guarded snapshot re-push -- which only ever
-- rewrites url/note/operator/claim/filename/published_at -- fires nothing at
-- all. This exists for the writer that does not exist yet.
CREATE OR REPLACE TRIGGER sightings_resubject_trg
	AFTER UPDATE OF subject ON sightings
	FOR EACH ROW WHEN (OLD.subject IS DISTINCT FROM NEW.subject)
	EXECUTE FUNCTION sightings_corroborate();

-- The cohort read path: what entered our world recently. Partial, because a
-- benchmark drawing a fresh cohort is asking about malware, and the suspicious
-- rows (capability scanners, unreviewed reports) outnumber it.
CREATE INDEX IF NOT EXISTS idx_sightings_recent
	ON sightings(first_seen DESC) WHERE claim = 'malicious';

CREATE INDEX IF NOT EXISTS idx_sightings_acquisition_recent
	ON sightings(first_seen DESC) WHERE claim IN ('malicious', 'suspicious');

-- Durable suppression and retry state for consumers foraging artifacts named
-- by sightings. target is intentionally opaque to Hopper: callers may key a
-- digest, an exact PURL release, or another immutable coordinate.
CREATE TABLE IF NOT EXISTS sighting_acquisitions (
	target       TEXT PRIMARY KEY,
	attempts     INTEGER NOT NULL DEFAULT 0,
	acquired     BOOLEAN NOT NULL DEFAULT false,
	last_attempt TIMESTAMPTZ,
	next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_error   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sighting_acquisitions_due
	ON sighting_acquisitions(next_attempt) WHERE NOT acquired;

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
-- restart but doesn't belong in a domain table.
CREATE TABLE IF NOT EXISTS hopper_kv (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
