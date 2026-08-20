-- repair_identity_20260808.sql
--
-- One-off repair for two historical identity-corruption classes found while
-- auditing the asset-identity columns (see scan/ASSET_IDENTITY_PLAN.md):
--
--   A. Go-module collapse: rows walked before the parseForagedDirs dirs[3:]
--      rejoin fix (05c94da, 2026-08-01) recorded only the first module path
--      segment: package="github.com", purl_base="pkg:golang/github.com"
--      (12,062 rows; also buf.build, ghproxy-*.pages.dev, ...). The full
--      module path is still present in samples.path between the
--      "/pkg.go.dev/" feed segment and the filename.
--
--   B. Disclosure-date misparse: Datadog dataset zips named
--      "YYYY-MM-DD-<name>-v<version>.zip" parsed as package="2026"
--      (purl_base='pkg:npm/2026', 645 rows). pkgparse now strips the date
--      prefix (datePrefix in pkgparse/filename.go); this repairs the rows
--      ingested before that fix.
--
-- Read-only dry-run SELECTs first; each UPDATE is wrapped in its own
-- transaction. Run psql with no statement_timeout (single seq-scan passes).
-- Case is preserved for Go module paths (matches SourcePURL behavior and
-- existing rows, e.g. pkg:golang/github.com/GoogleCloudPlatform/...).

------------------------------------------------------------------------------
-- Pass A: Go-module collapse
------------------------------------------------------------------------------

-- Dry run: what would change, and to what.
SELECT purl_base AS old_purl_base,
       'pkg:golang/' || substring(path FROM '/pkg\.go\.dev/(.+)/[^/]*$') AS new_purl_base,
       count(*)
  FROM samples
 WHERE purl_base LIKE 'pkg:golang/%'
   AND strpos(substr(purl_base, 12), '/') = 0            -- single-segment name
   AND substring(path FROM '/pkg\.go\.dev/(.+)/[^/]*$') LIKE '%/%'
 GROUP BY 1, 2
 ORDER BY 3 DESC
 LIMIT 50;

BEGIN;
UPDATE samples
   SET package   = substring(path FROM '/pkg\.go\.dev/(.+)/[^/]*$'),
       purl_base = 'pkg:golang/' || substring(path FROM '/pkg\.go\.dev/(.+)/[^/]*$')
 WHERE purl_base LIKE 'pkg:golang/%'
   AND strpos(substr(purl_base, 12), '/') = 0
   AND substring(path FROM '/pkg\.go\.dev/(.+)/[^/]*$') LIKE '%/%';
-- Expect ~14k rows (github.com 12,062 + buf.build 1,106 + ghproxy 1,022 + tail).
COMMIT;

-- Audit: single-segment golang purls that remain (no /pkg.go.dev/ path to
-- recover from — inspect by hand; clear identity if unrecoverable).
SELECT purl_base, count(*), min(path) example_path
  FROM samples
 WHERE purl_base LIKE 'pkg:golang/%'
   AND strpos(substr(purl_base, 12), '/') = 0
 GROUP BY 1 ORDER BY 2 DESC LIMIT 20;

------------------------------------------------------------------------------
-- Pass B: date-prefixed dataset names (pkg:npm/2026)
------------------------------------------------------------------------------

-- Dry run: recovered identities. All observed filenames use the
-- "-v<digits>" version marker; the greedy (.+) name capture splits at the
-- LAST "-v<digit>" so platform-suffixed names ("archgate-win32-x64") survive.
SELECT filename,
       substring(filename FROM '^[0-9]{4}-[0-9]{2}-[0-9]{2}-(.+)-v[0-9][0-9A-Za-z._+~-]*\.zip$') AS new_package,
       substring(filename FROM '-v([0-9][0-9A-Za-z._+~-]*)\.zip$')                               AS new_version
  FROM samples
 WHERE purl_base = 'pkg:npm/2026'
 LIMIT 30;

BEGIN;
-- Recoverable rows: real npm typosquat names (npm versions carry no "v").
UPDATE samples
   SET package   = substring(filename FROM '^[0-9]{4}-[0-9]{2}-[0-9]{2}-(.+)-v[0-9][0-9A-Za-z._+~-]*\.zip$'),
       version   = substring(filename FROM '-v([0-9][0-9A-Za-z._+~-]*)\.zip$'),
       purl_base = 'pkg:npm/' || substring(filename FROM '^[0-9]{4}-[0-9]{2}-[0-9]{2}-(.+)-v[0-9][0-9A-Za-z._+~-]*\.zip$')
 WHERE purl_base = 'pkg:npm/2026'
   AND filename ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}-.+-v[0-9][0-9A-Za-z._+~-]*\.zip$';

-- Unrecoverable stragglers: clear the corrupt identity rather than guess.
UPDATE samples
   SET package = '', version = '', purl_base = ''
 WHERE purl_base = 'pkg:npm/2026';
COMMIT;

-- Audit: nothing should remain under the bogus identity.
SELECT count(*) FROM samples WHERE purl_base IN ('pkg:npm/2026', 'pkg:golang/github.com');
