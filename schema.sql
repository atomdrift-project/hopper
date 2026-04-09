CREATE TABLE IF NOT EXISTS samples (
	id            BIGSERIAL PRIMARY KEY,
	sha256        TEXT UNIQUE NOT NULL,
	source        TEXT NOT NULL DEFAULT '',
	feed          TEXT NOT NULL DEFAULT '',
	ecosystem     TEXT NOT NULL DEFAULT '',
	filename      TEXT NOT NULL DEFAULT '',
	file_type     TEXT NOT NULL DEFAULT '',
	size_bytes    BIGINT NOT NULL DEFAULT 0,
	label         TEXT NOT NULL DEFAULT 'unknown',
	label_source  TEXT NOT NULL DEFAULT '',
	cleave_result JSONB,
	litmus_result JSONB,
	litmus_score  DOUBLE PRECISION NOT NULL DEFAULT 0,
	path  TEXT NOT NULL DEFAULT '',
	status        TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL DEFAULT '',
	canonical_sha256 TEXT NOT NULL DEFAULT '',
	parent        TEXT NOT NULL DEFAULT '',
	skip          TEXT NOT NULL DEFAULT '',
	formula       TEXT NOT NULL DEFAULT '',
	elements      TEXT NOT NULL DEFAULT '',
	score         INTEGER NOT NULL DEFAULT 0,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	analyzed_at   TIMESTAMPTZ,
	mtime         TIMESTAMPTZ,
	marker_mtime  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_samples_label ON samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_unanalyzed ON samples(sha256) WHERE cleave_result IS NULL;
CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_samples_path ON samples(path);
CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != '';

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
