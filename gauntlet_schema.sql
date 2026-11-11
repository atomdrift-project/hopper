-- History is independent of the live corpus: pruning samples must not erase it.
-- UTC timestamps use a fixed-width RFC3339 representation in both backends.
CREATE TABLE IF NOT EXISTS gauntlet_runs (
 id TEXT PRIMARY KEY,
 producer TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 source TEXT NOT NULL,
 digest TEXT NOT NULL,
 metadata TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gauntlet_samples (
 run_id TEXT NOT NULL REFERENCES gauntlet_runs(id),
 sha256 TEXT NOT NULL,
 label TEXT NOT NULL,
 eligible BOOLEAN NOT NULL,
 metadata TEXT NOT NULL,
 PRIMARY KEY (run_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_gauntlet_samples_sha ON gauntlet_samples(sha256, run_id);
CREATE TABLE IF NOT EXISTS gauntlet_results (
 run_id TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 scanner TEXT NOT NULL,
 status TEXT NOT NULL,
 evidence_key TEXT NOT NULL,
 payload TEXT NOT NULL,
 PRIMARY KEY (run_id, sha256, scanner),
 FOREIGN KEY (run_id, sha256) REFERENCES gauntlet_samples(run_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_gauntlet_ascan ON gauntlet_results(sha256, run_id)
 WHERE scanner = 'ascan' AND status IN ('benign', 'detected');

-- Withdrawals are later publications, not edits to the original scan. Keeping
-- them as facts also makes arrival order irrelevant during a backfill.
CREATE TABLE IF NOT EXISTS gauntlet_withdrawals (
 run_id TEXT NOT NULL REFERENCES gauntlet_runs(id),
 sha256 TEXT NOT NULL,
 PRIMARY KEY(run_id,sha256)
);
CREATE INDEX IF NOT EXISTS idx_gauntlet_withdrawals_sha ON gauntlet_withdrawals(sha256);
