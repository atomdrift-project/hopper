CREATE TABLE IF NOT EXISTS samples (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	sha256        TEXT UNIQUE NOT NULL,
	source        TEXT NOT NULL DEFAULT '',
	feed          TEXT NOT NULL DEFAULT '',
	ecosystem     TEXT NOT NULL DEFAULT '',
	url           TEXT NOT NULL DEFAULT '',
	-- domain is the registered domain (eTLD+1), populated by the Go writer
	-- via golang.org/x/net/publicsuffix.
	domain        TEXT NOT NULL DEFAULT '',
	-- package is the software package this file belongs to (parsed from
	-- the download filename via pkgparse.ParseFilename).
	package       TEXT NOT NULL DEFAULT '',
	version       TEXT NOT NULL DEFAULT '',
	filename      TEXT NOT NULL DEFAULT '',
	-- file_type, score, formula, litmus_score are GENERATED from the JSONB
	-- source columns. Writing to them is an error; readers see the same
	-- derived values they always did.
	file_type     TEXT GENERATED ALWAYS AS
	                   (COALESCE(json_extract(cleave_result, '$.files[0].type'), json_extract(cleave_result, '$.fs[0].type'), ''))
	                   STORED,
	size_bytes    INTEGER NOT NULL DEFAULT 0,
	label         TEXT NOT NULL DEFAULT 'unknown',
	label_source  TEXT NOT NULL DEFAULT '',
	cleave_result TEXT,
	litmus_result TEXT,
	litmus_score  REAL GENERATED ALWAYS AS
	                   (COALESCE(json_extract(litmus_result, '$.prob'), 0))
	                   STORED,
	path  TEXT NOT NULL DEFAULT '',
	status        TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL DEFAULT '',
	canonical_sha256 TEXT NOT NULL DEFAULT '',
	parent        TEXT NOT NULL DEFAULT '',
	skip          TEXT NOT NULL DEFAULT '',
	formula       TEXT GENERATED ALWAYS AS
	                   (COALESCE(json_extract(cleave_result, '$.files[0].mol'), json_extract(cleave_result, '$.fs[0].f'), ''))
	                   STORED,
	elements      TEXT NOT NULL DEFAULT '',
	score         INTEGER GENERATED ALWAYS AS
	                   (COALESCE(json_extract(cleave_result, '$.files[0].risk'), json_extract(cleave_result, '$.fs[0].x'), 0))
	                   STORED,
	max_crit      INTEGER NOT NULL DEFAULT 0,
	suspicious_count INTEGER NOT NULL DEFAULT 0,
	created_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
	updated_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),

	analyzed_at   DATETIME,
	first_analyzed_at DATETIME,
	last_error_at DATETIME,
	mtime         DATETIME,
	marker_mtime  DATETIME,
	claimed_by    TEXT NOT NULL DEFAULT '',
	claimed_at    DATETIME,
	traits_version TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_samples_label ON samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type);
CREATE INDEX IF NOT EXISTS idx_samples_unanalyzed ON samples(sha256) WHERE cleave_result IS NULL;
CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_samples_path ON samples(path);
CREATE INDEX IF NOT EXISTS idx_samples_parent ON samples(parent) WHERE parent != '';

CREATE TABLE IF NOT EXISTS reports (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	sha256      TEXT NOT NULL REFERENCES samples(sha256),
	report_type TEXT NOT NULL,
	content     TEXT NOT NULL,
	provider    TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0,
	created_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_reports_sha256_type ON reports(sha256, report_type);

CREATE TABLE IF NOT EXISTS workers (
	name      TEXT PRIMARY KEY,
	last_seen DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
	slots     INTEGER NOT NULL DEFAULT 1,
	version   TEXT NOT NULL DEFAULT '',
	traits    TEXT NOT NULL DEFAULT '',
	analyzed  INTEGER NOT NULL DEFAULT 0,
	errors    INTEGER NOT NULL DEFAULT 0
);

-- hopper_kv stores internal key/value state that needs to survive process
-- restart but doesn't belong in a domain table. Used today for the
-- upload-token bootstrap (shared with prism via this row).
CREATE TABLE IF NOT EXISTS hopper_kv (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
