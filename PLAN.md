# Efficient sample observations

Updated: 2026-11-12. Progress and remaining work: [PLAN_TODO.md](PLAN_TODO.md).

## Verdict schema (supersedes the location-only design below)

Goal: a sample records bytes, a label and where it came from; a rescan writes
only what changed. Scanners (atomscan, ClamAV, later malcontent) are independent
opinions; atomscan's components (the trait floor, ml, llm, and isomer's
drift_heuristic and drift_llm) are its jurors.
`/v1/lookup` (not `?full`) is the hot read. PostgreSQL 18.6 only; SQLite support
is dropped.

Schema: [store/schema.sql](store/schema.sql). A second
reviewer's notes (`PLAN_ADDENDUM.md`) are folded into the table and rules
below; the detail and what is still to build are under "Review integrated".

| Table | Holds | Written when |
| --- | --- | --- |
| `samples` | sha256 (bytea), size, type, label, package name/version, provenance | first seen; label change |
| `scanners` | who can hold an opinion; `part_of` marks a juror; `operator` is whose evidence it is (NULL: ours) | when a scanner is added |
| `verdicts` | one row per (sample, scanner or juror): outcome, class, fires_at, ruleset, ≤1 KB summary, and the scanner's report (zstd, placement-free, opaque to SQL) with its digest. A member's benign floor or ml juror that fires at no level has no row unless the member was scanned on its own | a scanned artifact's own row on every scan of it (HOT); a member's row and a juror's row only when the opinion changes; the report only when its digest does |
| `contents` | one row per archive: the immediate members scan kept (at most 256 per scan), as parallel arrays of child ids and relative paths, GIN on the ids | first scan of the parent; again when the kept set changes |
| `refs` | scanned artifact → name (PURL without version, or URL) + resolved version + the constraint as written + kind | replaced on each scan of the artifact |
| `claims` | one row per file that says what it is: cleave's identity block whole, with the name, version and signer lifted out and indexed | when a scan reads the block differently; removed when a scan reads the file and finds none |
| `names`, `locations`, `queue` | interned names; outer paths of top-level files; pending work | rarely |

Rules the prototype relies on:

1. A stored report is a function of the bytes and the findings. Placement keys
   (`id pid path depth dp rel via role`) and the ruleset stamp (`rev tv fp`) are
   removed; trait and reference sources are rewritten from scan-local file ids
   to content digests. `verdicts.digest` is sha256 of that canonical report, so
   an unchanged rescan updates only `ruleset` and `scanned_at`.
2. Members are attributed to their immediate container using `pid`. Fetched
   dependencies are `refs` from the scanned artifact, whichever file inside it
   declared them, and their contents hang off the dependency's own sample, not
   the top-level archive. Registry sidecars are provenance of a release, not
   members.
3. A stored verdict covers the file and what it contains, never what it
   depends on. Lookup of an archive walks `contents` level by level (bounded,
   reports truncation) to surface strong verdicts inside it, and resolves
   `refs` to releases at read time, so a dependency judged hostile later is
   found from every archive that declared it. A hostile dependency, URL or
   member raises the class the lookup answers with; the raise is computed per
   request and never stored. A recursive CTE is not used: the planner
   estimates thousands of rows and hash-joins whole tables (224 ms vs 3.4 ms).
4. `class` (`benign`, `suspicious`, `hostile`) is the one scale every scanner
   shares, matching scan's `Classification`. A scanner's own scale (`fires_at`,
   criticality, probability, signature) stays in `summary`. atomscan's verdict
   is written by scan, not recomputed by hopper. Its stored class is the one
   at level 25, the deploy default; the level is recorded in `summary` beside
   `fires_at`, so a reader can recompute for another level and a later change
   of default is visible per row. `/v1/lookup` keeps returning `fires_at`.
5. Jurors are rows, so a disagreement between them is a join, and one partial
   index — `verdicts (scanner_id, class, sample_id) WHERE class <> 'benign'` —
   is where every triage queue starts. Jurors are never counted as sources.
6. A file is called hostile when atomscan says so or independent sources
   do (other scanners, sightings). This is derived at read time from the
   verdict rows and the sightings ledger, with attribution, and is not stored.
   How many sources it takes is the ladder `corroboration.go` already applies
   (`Floor`), which is looser than the "three sources" this rule first said;
   see "Review integrated", where that is listed for confirmation.
   Independence already exists in hopper: every sighting row carries the
   `operator` and `basis` its writer took from parallax's source definitions,
   and `corroboration.go` folds claims by operator (`Conclusive` is three or
   more). The new part is that a scanner's hostile verdict joins that fold
   under `scanners.operator` (clamav is `talos`), so a ClamAV verdict and a
   relayed ClamAV sighting are one voice. Scanners with no operator are ours
   and never count. hopper cannot import parallax, so the fact keeps arriving
   with the data.
7. `skip` is not carried forward: `unsupported`, `timeout` and `stuck` are
   verdict outcomes; `conflict` and `misclassified` are already
   `label_source` (`conflict`, `marker`); `missing` is a
   top-level sample with no `locations` row; `skip-benign-archive-item` goes
   away with the member label rule below.
8. Labels: a good archive makes its contained members good. A bad archive marks
   a member bad only if it is among the top 3 by score and a suspicious or
   hostile finding cites it as a source. Neither propagates across a `refs` edge.

Prototype evidence (local, 1,943 archives and 137,932 member rows exported from
galadriel; 161,712 samples after stubs for unexported members):

| Measure | Today's layout | Prototype |
| --- | ---: | ---: |
| Sample rows + reports | 1,108 MB (`samples` only) | 875 MB including members, refs, locations |
| Stored cleave report, average | 6,180 B (pglz TOAST) | 3,674 B (zstd) |
| Verdict rows per file | 1 wide row | 3 (atomscan, cleave, ml), 650 B together with indexes |
| Containment, per edge with indexes | ~890 B (`sample_locations`, prod) | 159 B (`members`) |
| WAL per member rescan, nothing changed | 5,811 B (prod: 6.9 KB) | 153 B |
| WAL per member rescan, ML score changed | 5,811 B | 415 B |
| WAL per member rescan, cleave report changed | 5,811 B | 3,526 B |
| Lookup by sha256, warm | 0.057 ms | 0.081 ms (all verdict rows) |
| Lookup by name + version, warm | 3.0 ms (prod mean) | 0.23 ms |
| Archive walk, 100–1,000 members | none | 2.8 ms mean (263 ms at 22,242 members) |
| Triage queue fetch (discord, unconvicted hostile, bad) | one partial index each | 0.2–0.4 ms from two indexes |

Caveats: warm cache and a small corpus; the local baseline has 5 indexes where
production has 59, so its WAL is understated. With fillfactor 80, 81% of verdict
updates were HOT. Unchanged-report frequency is not yet measured directly: 34%
of member files seen under two or more rulesets keep the same risk and formula,
a lower bound because rulesets compared may be months apart. Non-benign verdict
rows are 554 of 416,483; the queue index is 40 kB. Classes in the prototype are
stand-ins: cleave's from hopper's conviction bar, atomscan's from the served ML
class.

Findings from the load that change the plan:

- Flattening is the cause of multiple children at one path: 1,815 such
  (parent, path) groups under today's attribution, 1 after `pid` attribution
  within a single scan. Across every stored scan of an archive there are 16,
  in 7 archives: an embedded extraction (15 are a workflow `run` step) whose
  bytes differed between scans. An archive's row is replaced when its member
  set differs, which keeps the latest.
- 19,808 registry sidecars in older reports lack `rel=registry`; detect them by
  type until those reports are rescanned.
- `truncated` only marks members factored out of the parent (cap 100,000).
  But 5,243 stored archive reports (npm, crate, tar.gz, whl, ...) keep only the
  container entry, so 854K of their trait sources cite file ids the stored
  report no longer lists (949,193 unresolved in 23,337 reports overall).
  Attribution must happen at ingest, while hopper holds the full report.
- The same flattening also files members of nested containers under the
  top-level archive with the container dropped from the path (1,531 rows in the
  sample); those are contained, so only their path and parent are wrong.
- Nothing deletes a parent's stale member rows on rescan, so fixing
  `buildRange` alone leaves existing misfiled rows in place.
- 30 reports contain a rule-timeout finding whose text includes a duration;
  that makes the digest change on every scan. Scan should drop the duration.
- Scan already resolves dependency versions (1 range among 52,030 dependency
  refs); 5,894 are unversioned.
- `provenance` is 15 KB average on package rows and is most of `samples`' size.
- `samples.status` (cyclotron pipeline stage) has no remaining callers in hopper
  besides the `false-positives` CLI; it is not carried forward.

### Revisions after the prototype

1. **Triage queues start from two small indexes.** Today each queue is one
   conjunction over label, top-level, `skip`, cleave severity, litmus class and
   an `analyzed_at` floor, served by its own partial index on `samples` (88
   `idx_samples_*` names in the code). In the new layout a queue starts from
   `verdicts_flagged` (a juror that is not benign) or `samples_bad` (a convicted
   file) and probes the rest by primary key; "top-level" is "has a `locations`
   row". Three representative queues run in 0.2–0.4 ms locally.
   - The freshness floor cannot be indexed: any index naming `scanned_at`
     disables HOT for every verdict update. Queues filter and sort freshness
     after the indexed fetch.
   - Production sizes are now known (see "Production measurements"): the
     starting sets hold millions of rows, so a queue must not fetch its set
     and sort it. `verdicts_flagged` ends in `sample_id`, and sample ids rise
     with `created_at`, so a newest-first queue reads the index backwards and
     stops after one page. Cost per page is about page size ÷ the fraction of
     the set the queue keeps; estimated, not yet measured, for the sparse ones.
   - Queues ordered by verdict age ("stale") cannot be served this way without
     indexing `scanned_at`. They are rescan work and belong in `queue`.
   - Still to do: the remaining 18 queues, with plans.
   - Scan should emit cleave's class (the trait floor) so hopper stops
     re-deriving it from `max_crit` and `suspicious_count`.
2. **Report compression is a readers decision, not only a size one.** Same
   137,269 single-file reports, average bytes: raw 12,600; jsonb pglz 5,817;
   jsonb lz4 5,809; zstd 3,602; zstd with a trained 110 KB dictionary 2,745
   (level 3) or 2,373 (level 9). Decided: zstd. SQL never selects inside a
   report; tools that want one for local analysis (collimator, prism,
   cyclotron select `cleave_result` today) fetch and decompress it. A
   dictionary can be added later because the frame names its dictionary.
3. **Litmus needs no detail row.** Without the per-file list (which is the
   members' own verdicts) a litmus result averages 146 B; keep a detail row only
   for the rare result over 1 KB.
4. **Member rows:** fix `buildRange`, make an archive's member store replace its
   rows, then run a bounded cleanup driven by stored reports. Multi-child
   paths are under 1% of the misfiled rows and must not be the deletion test.
5. **Migration order.** Containment replaces `sample_locations` (4.3 TB) and
   can be built from stored reports before anything else moves; that step
   frees the most disk and should go first, reports follow. Whether it fits
   in free space depends on the member layout (see below). The migration
   sequence further down predates this and still needs rewriting.

### Production measurements (2026-11-12, read-only)

Catalog estimates from hopper-db (`reltuples`, `pg_stats`), a 0.03% page sample
of `sample_locations` on galadriel (1,466,965 rows), and 3,000 exact placement
counts on hopper-db.

| Measure | Value |
| --- | ---: |
| `samples` | 309.9M rows, 3,193 GB |
| `sample_locations` | 4.875B rows, 4,343 GB (890 B per row) |
| Location rows that are members / registry sidecars / fetched / roots | 91.7% / 6.1% / 1.5% / 0.6% |
| Distinct (parent, path, child) among member rows | 98.2%, so about 4.4B edges |
| Distinct relative paths, extrapolated | 0.4–1.2B (4–11 edges per path) |
| Labels: unknown / good / bad / sighted | 90.6% / 6.3% / 2.96% (9.2M) / 0.12% |
| Bad labels that are `skip-benign-archive-item` | about 6.6M of the 9.2M |
| Cleave severity ≥ 4 | about 4.2M rows (1.4%) |
| Litmus class not benign | about 4.1M rows (1.3%) |
| Top-level samples | about 57.6M |

Queue populations today (partial-index `reltuples`): bad_shared 9.1M,
bad_route_fresh 2.8M, bad_miss 1.15M, popular_ranked 847K, unknown_newest 806K,
version_drift 770K, unconvicted_susp 692K, discord 170K, unconvicted_hostile
134K, review 98K, stranded 72K, fp_trait 36K, good_repair 21K, second 10K,
acquit 5K.

What this changes:

- **Paths do not share as hoped.** Distinct paths grow as n^0.88 in the
  sample; go, crate and sdist archives put the version in the top directory.
  Interning buys 4–11 edges per path, not the hundreds the npm cohorts showed.
- **Row-per-edge `members` is tight.** 4.4B edges at 159 B is about 700 GB,
  plus 86–260 GB for `member_paths`: 0.8–0.95 TB against 1.36 TB free that
  swings by about 350 GB. The edge count is an upper bound: dependency contents
  now filed under the top-level archive (38% of contained rows in the prototype
  sample) move to the dependency's own sample and are stored once.
- **A packed layout was measured locally and adopted** (`schema.sql`, the
  loader, `measure.sql` and `bench.sql` now use it):

  ```sql
  CREATE TABLE contents (
      parent_id bigint PRIMARY KEY REFERENCES samples,
      child_ids bigint[] COMPRESSION lz4 NOT NULL,
      paths     text[]   COMPRESSION lz4 NOT NULL);
  CREATE INDEX contents_parents ON contents USING gin (child_ids);
  ```

  | Measure (same 240,766 edges) | `members` + `member_paths` | `contents` |
  | --- | ---: | ---: |
  | Bytes per edge, with indexes | 296 | 57 (ids 5, paths 15, GIN 33.5) |
  | Archive walk, 100–1,000 members | 2.85 ms | 2.72 ms, same results |
  | Child → parents | 0.042 ms | 0.043 ms |
  | Projected at 4.4B edges | 0.8–0.95 TB | about 250 GB |

  One archive is one row, which is what rule 2 says containment is.
  Replacing a member set is a single-row upsert. The row is not written
  once: an upload names a member only while it has something to say, so
  archives holding the same nested archive list it differently. The row
  carries the time of its list (`listed_at`), and only a newer scan's list
  replaces it (the migration rehearsal found a newer verdict without a list
  shutting out the only list stated). Costs: no foreign key on
  array elements, and SQL that wants rows must `unnest(child_ids, paths)`.
  After the reload the whole prototype is 820 MB and `contents` is 52 B per
  edge (ids 5.0, paths 15.1, GIN 28.6).

  Scale test ([scale.sql](internal/verdictproto/scale.sql)): 1.3M synthetic
  archives, 93.7M edges, log-normal member counts, 40% of members drawn from a
  skewed shared pool so one file sits in 91% of archives.

  | Measure | GIN on `child_ids` | Reverse table + btree |
  | --- | ---: | ---: |
  | Bytes per edge | 36.6 | 75.8 |
  | Build | 49 s | 33 s |
  | Parents of a file in 1 archive | 0.03 ms | — |
  | First 50 parents, file in 9K archives | 1.1 ms cold | — |
  | First 50 parents, file in 55K / 224K / 1.19M archives | 0.5 / 0.2 / 0.07 ms | 0.06 ms |
  | Same, with the planner forced onto the index | 5 / 9 / 18 ms | — |
  | Insert 20,000 archives (1.4M edges) with the index in place | 1.5 s | — |

  For a widely shared file the planner reads the table instead of the index
  and finds 50 parents at once. The bad case is a file shared enough to have a
  long posting list but too rare for that: the index read is linear, about
  15 ns per parent, so 2M parents is roughly 30 ms. `gin_fuzzy_search_limit`
  caps it (2.3 ms for the 1.19M-parent file) at the cost of returning a
  sample of parents rather than the first ones. Walking up is informational,
  labels flow down, so a sample is acceptable; the walk-up query sets the
  limit. At 4.4B edges the index projects to about 160 GB and `contents` in
  all to about 260 GB.
- **The bad set shrinks.** 6.6M of 9.2M bad labels exist only because members
  of bad archives were marked bad and then skipped; rule 8 does not create them.
- **Replica state at measurement time:** subscription
  `hopper_replica_galadriel` is disabled with no apply worker; the slot on the
  master is inactive and 313 MB behind. Replica `sample_locations` has only its
  primary key and `idx_sl_containment`.

### Decisions (2026-11-12)

- **hopper is stopped and nothing writes to production** until the migration.
  The migration can therefore be offline: no change capture, no dual writes,
  no catch-up. The sections below that plan for concurrent writers are
  superseded; `MIGRATION_PLAN.md` will be written once the local port is
  trusted.
- **atomscan's stored class** is the class at level 25, with the level in
  `summary`.
- **`provenance` stays a `jsonb` column on `samples`** (lz4, written once, so
  it adds no churn). `/v1/lookup` does not read it. The acquit queue's "no
  feed" test moves to `locations.feed`; the registry title, description and
  download count are read for one page of rows at a time by the feed view.
- **Member layout is `contents`.**
- **Stored reports move.** The migration moves each `cleave_result` blob, as
  it is, into atomscan's verdict row (`verdicts.detail`, zstd), its final
  location. Report contents
  are not converted; a report is replaced by the version 8 form when the file
  is next scanned.
- **Sources:** operators as described in rule 6; `sightings` keeps its text
  `subject` key (981K rows, one index probe per lookup), so it needs no
  `sample_id` or `name_id`.
- **Next:** port hopper's ingest, `/v1/lookup` and triage queues to the new
  schema against local PostgreSQL, with a parity test of lookup answers on
  the exported sample.

### Result writer, current against new (2026-11-12, local)

`TestResultWriters` (`store_writer_test.go`) stores the same 3,999 uploads
(30,714 files) through `DB.StoreResult` into the current schema and through
`v7result.Convert` then `store.Write` into the verdict schema. Each upload is an
exported archive with its members' stored reports joined back in, which is
what the worker posted. One writer at a time, checkpoint before each pass,
`fsync` on, WAL measured cluster-wide.

| Pass | Current | New | New / current |
| --- | ---: | ---: | ---: |
| First scan, time per upload | 10.0 ms | 4.3 ms | 0.43 |
| First scan, WAL per upload | 107.8 KB | 30.1 KB | 0.28 |
| Rescan under a new ruleset, same reports, time | 9.7 ms | 1.8 ms | 0.19 |
| Rescan under a new ruleset, same reports, WAL | 95.5 KB | 2.5 KB | 0.03 |
| Rescan, every report differs, time | 9.5 ms | 2.4 ms | 0.25 |
| Rescan, every report differs, WAL | 95.1 KB | 29.5 KB | 0.31 |
| On disk after the three passes, before vacuum | 397 MB | 179 MB | 0.45 |

Rerun after `scans` took the stamp and the converter began rebuilding
reports in the version 8 shape (same 3,999 uploads, same machine, PostgreSQL
18.7):

| Pass | Current | New |
| --- | ---: | ---: |
| First scan, time / WAL per upload | 6.5 ms / 109.4 KB | 5.3 ms / 29.7 KB |
| Rescan, same reports, time / WAL | 6.9 ms / 97.0 KB | 1.8 ms / 2.1 KB |
| Rescan, every report differs, time / WAL | 7.0 ms / 102.5 KB | 2.2 ms / 25.0 KB |
| On disk after the three passes, before vacuum | 495 MB | 179 MB |

The unchanged rescan now writes 5,418 verdict rows where it wrote 10,028:
the 3,999 artifact stamps went to `scans`. The new writer's first scan is
slower because `Convert` now rebuilds every report (about 1.3 ms of the
5.3). The "every report differs" pass needed a fix to the harness: it made
reports differ by changing the report's own ruleset, which a version 8
report no longer carries, so it had silently become a second "same reports"
pass; it now adds a crit 1 finding to every entry.

The first table is the run made after the review's writer changes (a member's row is
written only when its verdict differs). Before them the "same reports" row
was 1.6 ms and 4.5 KB for the new writer: the rule took 45% off the WAL of
an unchanged rescan and cut the verdict rows it writes from 32,697 to
10,028. Three runs of the same test spread by about this much: the current
writer's first scan 8.6–11.1 ms, the new writer's "every report differs" WAL
25.4–29.5 KB, the current writer's disk 351–463 MB. Read the ratios as
indicative.

What the numbers do and do not say:

- The current writer rewrites every member row on every rescan; that is the
  98–106 KB. The new one stamps one narrow row per file and writes a report
  only when its hash differs.
- A version 7 report names its ruleset, so in production every version 7
  rescan is the "every report differs" row. The "same reports" row needs
  version 8, where the ruleset lives in the header.
- About 1.1 ms of the new writer's time per upload is `v7result.Convert` taking the
  report apart, work that version 8 removes (its decode costs about 1.3 µs per
  file).
- In the "same reports" pass of the first run 10,028 verdict rows and 1,300
  reports were still written. 3,999 of the rows were the artifacts' own
  stamps, which now go to `scans`. The rest are there because the export holds scans made
  under 35 rulesets, and a file shared by two archives carries each
  archive's reading of it. A scan wave under one ruleset would not do that.
- The new writer's time includes creating the archive's `samples` row; the
  current writer was handed an existing row, as it is in production. Both
  exclude ingest (locations, provenance, queueing).
- One connection, a warm cache, 31K files. This says nothing about lock
  behavior under concurrent workers or about tables at production size.

### Review integrated (2026-11-12)

`PLAN_ADDENDUM.md` and `../scan/JSON_PLAN_ADDENDUM.md` are a second reviewer's
notes on this plan and on the upload format. This section is what was taken
from them. Where it differs from the addenda, this is the plan. The upload
format is specified in `../scan/JSON_PLAN.md`, which another agent implements
in scan while this side is built. Built and tested locally so far: the
schema changes, the references rules, and the verdict-row rules below.
Also built: a member's line is ignored for a file that holds an `llm` or
drift row; a member that leaves every list loses its verdicts. Not built:
everything under
"Raising a class at lookup", and the two requeues. `PLAN_TODO.md` has the
list.

**Schema changes**

```sql
-- samples: '' is "no version" here as it is in refs, so the two join by
-- plain equality; the index ends in id so "newest under a name" reads it.
version text NOT NULL DEFAULT '',
CREATE INDEX samples_release ON samples (name_id, version, id) WHERE name_id IS NOT NULL;

-- The scanned artifact points at that name.
CREATE TABLE refs (
    sample_id bigint   NOT NULL REFERENCES samples,
    name_id   bigint   NOT NULL REFERENCES names,
    version   text     NOT NULL DEFAULT '',  -- exact: declared, or resolved by scan
    kind      ref_kind NOT NULL,
    requested text     NOT NULL DEFAULT '',  -- the constraint as written; '' if it was exact
    fetched   bytea    CHECK (octet_length(fetched) = 32),  -- url_fetch: sha256 of what was served
    PRIMARY KEY (sample_id, name_id, version, kind)
);
CREATE INDEX refs_referrers ON refs (name_id, version, sample_id);
```

**References**

- **Resolved version, and the request.** Scan sent the declared version, and
  a declared range has none: the converter's `splitLocator` drops the
  `?vers=` qualifier and stores `''`, which can never equal a release. Most
  of an npm manifest is ranges, so "depends on something hostile" would have
  seen almost nothing. `version` is now the exact one scan resolved;
  `requested` keeps the constraint and marks the ref as floating. It is not
  part of the key: two declarations that resolve to one version are one row.
- **Held by the scanned artifact,** not by the manifest inside it. A lookup
  reads a package's refs in one range scan of the primary key, and "who
  declares this release" returns packages with no walk up. The cost: a
  nested archive looked up by its own hash shows no dependencies unless it
  was scanned as an artifact itself.
- **The reverse index includes the version.** "Who declares this hostile
  release" searches by name and version; `(name_id, sample_id)` made it read
  every referrer of every version.
- **One canonicalizer.** Ref names arrive spelled by fletch; sample names are
  spelled by `pkgparse`; names are interned by exact bytes. Every ref name
  goes through `pkgparse.CanonicalizePURL` at ingest, and the sightings
  ledger's `subject` has to be spelled the same way, or corroboration of a
  ref misses silently.
- **Every declared ref,** development-only ones included. No scope column.
- **A URL ref carries what it served.** A sample row has one name, so bytes
  first seen at URL A stay filed under A, and a ref to URL B that served the
  same bytes finds no sample by name. `fetched` is the fallback. Both links
  are kept: the digest says what the URL served when scanned, and "newest
  sample under that URL" catches a later change.
- Refs are replaced on every scan of the artifact, because a floating ref's
  resolved version can change. The writer already does this.

**Verdict rows**

- **What a row covers.** atomscan's verdict and the `ml` and `floor` jurors
  cover the file and everything it contains; scan folds members in at every
  nesting level, so a nested archive's row says the same thing whether it
  arrived as a member or was scanned directly. `llm` and `drift` exist only
  on a scanned artifact. Dependencies are in no stored row.
- **A verdict row is written only when its opinion differs.** That a scan
  happened is the artifact's `scans` row (see "Scans: when, apart from
  what"), so on every verdict row `ruleset` and `scanned_at` say when the
  opinion was formed. Restamping members would have been 153 B of WAL per
  member per rescan: 3.4 MB for the 22,242-file archive, and up to 670 GB for
  one ruleset wave over 4.4 billion edges. A file that is both a member and a
  top-level file has a `scans` row from its own scans.
- **Juror rows absent from an upload are removed,** scoped to what the line
  can carry: the artifact's line removes any of the four, a member's line
  only `ml` and `floor`.
- **`worker` leaves atomscan's summary.** It is logged with the result. The
  upsert no longer needs to ignore it when comparing. `level` stays: the
  default may change, and the level is what makes a stored class readable
  afterwards.
- **A verdict or juror object is at most 900 bytes,** and scan holds `reason`
  and `error` to 400 bytes each so that it is. The two numbers are stated in
  `../scan/JSON_PLAN.md`.
- **Drift** carries its baseline's sha256 in its summary. The key allows one
  baseline per head.

**Contents**

Decided 2026-11-12, and applied by scan, the uploading client; hopper stores
what it is sent and enforces no member cap of its own beyond the decoder's
safety limits. Scan uploads the members its retention keeps today (the
three riskiest, any with a trait of its own at crit 3 or above, any cited by
such a finding), capped at the 256 riskiest, plus the containers on the path
to them. A member that is not kept gets no line, no `samples` row and no
place in `contents`. The addendum's "a line for every member" is not taken:
a row for every unremarkable file is mostly noise, and member rows do not
feed the known-good filter, which reads top-level files only.

- The cap cannot hide a member from the archive's verdict; scan folds every
  member in before retention cuts. In the local export it keeps 68% of
  100,770 member rows and touches 58 of 5,600 archives.
- **A member that leaves every list loses its verdicts.** The addendum's
  defect is real: a member convicted under one ruleset and quiet under the
  next drops out of the upload, and hopper holds no bytes to rescan it. The
  fix is not more rows. When a result replaces an archive's member list, the
  writer takes the members that left it and, for each that no other archive
  lists and that is not a file in its own right (no location, name, URL or
  provenance), deletes its verdict rows and reports in the same transaction.
  An orphaned container gives up its own list, so its members are considered
  in turn. Built (`orphans` in `write.go`, `Stats.Orphaned`).
  - This is done in the writer and not as a background prune because a
    prune cannot tell an orphaned member from a top-level file whose bytes
    went missing: both are "no location, listed nowhere". The writer knows
    the file was a member, because it just left a list.
  - The `samples` row stays. Deleting it would need every writer to lock
    the sample rows it names, or a list being committed elsewhere could be
    left holding a dead id; a row lock per file per upload is the churn this
    schema exists to avoid. What remains is a row with no verdict, and a
    lookup by that hash answers "known, not analyzed".
  - A member still listed by an archive that has not been rescanned keeps
    its old verdict until that archive is; rescan by age bounds that, at `--rescan-age`.
- `contents` is therefore not a function of the parent's bytes. It is
  rewritten when a ruleset changes which members are kept: one row and its
  GIN entries per affected archive.
- Known gap, as today: a file that was quiet when its archive was scanned
  has no edge, so if its hash is convicted later (three operators report
  it), that archive is not found until it is rescanned.

**Raising a class at lookup**

Decided in the review. A stored verdict is the sample's own. When
`/v1/lookup` answers, it raises the class if the sample points at or contains
something hostile:

| Thing | Raises when |
| --- | --- |
| A dependency, by name and version | a file of that release is detected hostile, or the release is corroborated |
| A URL reference | the newest sample held under that URL (or the bytes it served, by `fetched`) is detected hostile, or the URL is corroborated |
| A member, at any depth within the caps | the member is detected hostile, or corroborated |

- Detected means atomscan's current class for that sample is `hostile`.
  Corroborated means the sightings ledger says so by the existing ladder
  (`Floor` in `corroboration.go`): three or more operators L1, two L10, one
  human-reviewed claim L25. The two lower rungs reach only suspicious.
- Only hostile raises. Suspicious does not, so a ref never uses the lower
  rungs; that is a consequence, not a second rule.
- The raise is never stored. Cyclotron's queues keep comparing real juror
  opinions, and an acquittal needs no fan-out.
- The answer's `fires_at` is the tightest of the sample's own level and the
  levels of what raised it (`tighten`), and the class is graded from that.
  Each thing that raised it is listed with its kind, name, version, sha256
  where there is one, and why. Field names are not settled.
- One hop: the sample's own refs, not its dependencies' refs.
- A failed fetch of a URL (404, 403) produces no sample, so the previous
  sample stays the newest and the old finding is kept with no extra rule.
- The raise is computed per request on top of the cached record.
  `lookup_cache.go` holds a sample for up to 48 hours and forgets only the
  sample that was written, so a cached raise would be missed when it appears
  and kept after it clears.
- `fired`, which decides "backed by our own analysis", tests a flat L3000.
  With the class stored, it reads the class.

What has to be true before this is built, none of it in the addendum:

- **Measured first** (2026-11-12, local export loaded into the current
  schema; warm, median of 30, statement time without the round trip). Both
  were run as exported (39 hostile files) and with half the members made
  hostile and every release benign, so that nothing a lockfile names is
  found and every probe runs.

  | Case | Cost |
  | --- | --- |
  | Refs, largest real lockfiles (1,003 to 1,294 refs) | 0.5 to 0.7 ms |
  | Refs, synthetic lockfile of 10,000 refs | 10 ms |
  | Members, 22,242 direct (14,260 distinct reached in 2 levels) | 5.3 to 6.5 ms |
  | Members, same archive, reach capped at 4,096 | 2.9 to 3.2 ms |
  | Members, same archive, reach capped at 1,024 | 2.6 ms |
  | Members, a median package (8 direct, 30 reached) | 0.03 ms |

  The refs query must be driven from the lookup's own refs: for each ref, a
  `LATERAL` probe of `samples_release` then `verdicts_flagged`, `LIMIT 1`.
  That costs one probe per ref whatever the table sizes. Written as a plain
  join, the planner either starts from the hostile set (fast while it is
  small) or, with many hostile files, scans every release in
  `samples_release`; 2.3 ms on 6,568 local releases and ruinous on
  production's. The member walk is a statement per level (`contents` by
  `parent_id = ANY`), then one probe of `verdicts_flagged` with
  `sample_id = ANY (reach)`. The 263 ms figure above came from a walk
  (`inside()` in `internal/verdictproto/bench.sql`) that also counted labels
  and resolved the refs of every file reached; this one does neither.

  So: examine at most 4,096 refs and 4,096 members, at most 16 levels, stop
  at 32 things raised, and say in the answer when a cap was hit. That bounds
  the raise near 4 ms plus 3 ms in the worst case and leaves an ordinary
  package under 0.1 ms. Corroboration is not measured: sightings are not on
  the new tables yet, and it adds a probe per ref and per hostile-candidate
  member in the same shape.

  **Built (2026-11-12, local).** `Store.Raise(ctx, id)` in
  `store/raise.go` returns the raisers (kind, name, version, sha256,
  level) and whether a bound cut the search short; `Record.RaiseBy` applies
  them: hostile, at the tightest level among the record's and theirs, never
  lower. The refs half is one batch (a truncation count and the `LATERAL`
  query); names are joined only for the refs that matched. On the
  hostile-heavy export it took 4 ms at the 4,096-ref bound and 1 ms for the
  largest real lockfile, round trip included. Choices made while building it:

  - `command` refs raise like `dependency` refs: both name a release, and a
    command that installs a hostile release installs it.
  - The `good`-label brake applies to every raiser, not only releases: a URL's
    newest file or a member labelled good does not raise either. The label
    says the bytes are known good; where they were found does not change that.
  - A URL raises when the newest file held under its name is hostile, or the
    bytes it served when scanned (`fetched`) are. An older hostile file under
    the URL does not.
  - A member is listed by sha256, and by name and version when it has them;
    not by path, which would need its container's `paths` array.
  - Not yet: corroboration (sightings are not on the new tables), and the
    `/v1/lookup` handler, which moves to the new tables with the other readers.
- **Members must not go stale in opposite directions.** Scan folds members
  into an archive's stored verdict, and lookup also raises for members. A
  member convicted later is covered twice over (the lookup raise, and the
  repair requeue the writer already does). A member acquitted later is not:
  the archive's stored verdict stays hostile until something rescans it. The
  writer's queue step should requeue holders when a member's class falls
  from hostile, as it does when one rises, with the same cap. Wanted and
  deferred (2026-11-12): rescan by age reaches the archive eventually, and
  the error is on the safe side. See `DEFERRED.md`.
- **A false positive on a popular package** makes every package that declares
  it hostile at lookup until the conviction is fixed. A `good` label on the
  dependency's release blocks the raise from our own detection of it
  (confirmed 2026-11-12). The release's own lookup still says hostile, and
  corroboration by outside sources still raises its declarers. The addendum
  deferred labels entirely; this one is cheap and is the only brake.
- **A floating ref is matched at the version scan resolved.** A hostile
  release published after the declarer's last scan is not seen until the
  declarer is rescanned. Requeueing the declarers of a name when one of its
  releases turns hostile is needed, and a popular name has declarers by the
  million, so it is capped and queued below repair. Wanted and deferred
  (2026-11-12); until then a floating declarer learns of a new hostile
  release at its next scan. See `DEFERRED.md`.

Known gaps, accepted:

- One hop misses the transitive dependencies of a package that ships no
  lockfile, which is most npm tarballs.
- A ranged ref that scan never resolved has no version and matches nothing.
- A takedown or parking page served with status 200 becomes the newest
  sample under a URL and clears the finding.

**Not taken**

- Dropping `level` from the summary, for the reason above.
- Storing the reason once. It is the same sentence in atomscan's summary and
  the `llm` row when the LLM decided; one copy saves a few hundred bytes on
  few rows and costs every reader a rule.
- "A member line does not replace a row that carries more jurors than it
  does." Replaced by the question below.

**For Thomas to confirm**

1. **The ladder against "three sources".** Confirmed 2026-11-12: use the
   existing ladder for now. It will change when external scanners (ClamAV,
   malcontent) are added; their verdicts count as automated sources, not
   human-reviewed ones, so one of them alone never reaches the L25 rung.
2. **A file scanned on its own with the LLM that also sits inside an
   archive.** Confirmed 2026-11-12, the path of least churn: a member line
   leaves a file alone when the file holds an `llm` or `drift` row. Those
   rows come only from the file's own scan, which read everything the member
   line did and more, so replacing the verdict would only be undone by the
   file's next scan. The file's own queue keeps it current while it has a
   location. Built (`Stats.Deferred` counts them).
3. Quiet members: decided, see "Contents". The identity-only members scan's
   retention keeps today are dropped with them; the cost is in the claims
   item of `PLAN_TODO.md`.
4. **The `good`-label brake and the two requeues** above. Confirmed
   2026-11-12: the brake is part of the lookup raise; both requeues are
   wanted and deferred (`DEFERRED.md`).

### Other scanners, isomer's jurors, and who uploads (2026-11-12, local)

Decided in the scan thread and relayed: postdoc becomes the main uploader. It
builds the body through scan's upload document, adds isomer's jurors and the
third-party scanners, and sets the final verdict. ClamAV is the first
scanner, as the worked example. The wire format is in
`../scan/JSON_PLAN.md`, "Jurors" and "Other scanners".

What changed here:

- **`drift` is two jurors,** `drift_heuristic` and `drift_llm`, both part of
  atomscan (`scanners` ids 5 and 8). A member's line cannot carry either, and
  a file holding either is one "scanned in its own right", as with `llm`.
- **A `scanners` object on the artifact's line** becomes one `verdicts` row
  per scanner. The schema already had the rows (`clamav`, `malcontent`, each
  with the operator its evidence counts under); `guarddog` (row 9, operator
  `guarddog`, the name gauntlet's sightings already relay it under) was added
  when postdoc began running it (2026-11-12).
- **A scanner's row holds its finding, and its stamp beside it.** `engine`
  goes to the summary as `eng`, `ruleset` or `db` to `verdicts.ruleset`, and
  neither is part of what the row is compared by. ClamAV's database changes
  daily, as the ruleset does, so a row written per database would be the
  per-rescan churn the member rule was built to avoid.
- **Absent is no statement, for a scanner** (Thomas, 2026-11-12, replacing
  "absent means removed"). Only a scanner's own report replaces its row; a
  body that leaves a scanner out, or has no `scanners` at all, leaves its
  finding standing. Whether a scanner runs depends on the uploading host
  (`atomscan --hopper`, a worker without clamd), not on the file, so absence
  says nothing about the file. A scanner that finds nothing reports benign,
  which replaces a hostile row. Jurors keep the old rule: a version 7 rescan
  of a file removes isomer's rows, because a version 7 body cannot carry
  them. That is wrong for as long as old scan workers and postdoc both
  upload, and stops mattering when the converter goes.
- **A scanner that fails keeps its last good row,** as atomscan does.
- **No scanner feeds atomscan's verdict.** Hopper stores what each said;
  what they add up to is the lookup rule (atomscan, or enough outside
  sources by the ladder, with a scanner's verdict counted as one automated
  source under its operator). That rule is unchanged and still unbuilt.

Not built: a scanner's report. `verdicts.detail` is on every scanner's row
and could hold one, but a body's report lines are matched to file lines one each.
The decoder rejects a scanner's `report` rather than drop it. ClamAV has no
report; malcontent will, and needs this first.

**Old results and their readers.** Also relayed: old results stay in hopper
and are converted when read, and prism and cyclotron (both Go, both already
requiring this module) need a version 7 converter they can import.

Both hold exactly what the converter takes. Prism builds `{ml, llm, raw}`
from a sample's envelope (`parentSampleFromEnvelope`); cyclotron reads the
same three blobs and writes `cleave_result` back. So the converter moved to
public packages of this module (2026-11-12, local), both standard library
only:

- `scanresult`: the version 8 body. Its types (`File`, `Stamp`, `Ref`,
  `Upload`, `Claim`, `Finding`), `Decode`, the limits (`MaxMembers`,
  `MaxSummary`, `MaxIdent`, …), the juror and scanner names, `ClaimOf`,
  `SplitScanner` and `CheckJSONB`. It stores nothing. `store` keeps
  only the name-to-id maps for the `scanners` table, with a test that every
  name `scanresult` admits has an id.
- `v7result`: `Convert(*Result, level)` turns `{raw, ml, llm}` into
  `[]scanresult.File` plus the reports, so a reader sees an old result as
  the same verdict, jurors, contents, refs and identity a version 8 body
  carries.

`v7result` now lives as long as old results do, not until the last worker
uploads version 8. What goes with the last version 7 worker is hopper's
`fromV7` path in `cmd/hopper/results.go`.

**Readers read version 8 only** (Thomas, 2026-11-12). Old representations
are converted to version 8 when read; no reader handles two shapes. So
`Convert` also rebuilds each report the way scan's `report_line`
(`src/engine/v8.rs`) does: the file's own entry, without the placement keys
(`PLACEMENT_KEYS`: id, pid, depth, dp, path, rel, via, role, sha, size, type,
ident), without dependency verdicts pinned onto it (`dep`), each trait or
reference source in another file cited by that file's sha256 and one in the
file itself by nothing, a source naming no file dropped, keys sorted at every
level, numbers and text as they came. The pinned dependency verdicts also no
longer count toward a converted file's `top` or floor juror, as in scan:
a verdict covers the file and its contents, never its dependencies.

Reports older than version 6 (single-letter keys, `fs`; 97 of the 138,767
exported results) use another schema. Their verdict and jurors are converted
and the report is left out, which version 8 allows; rescan by age replaces
them.

Over the whole local export: 138,767 results, no errors, 390,021 reports
(87% of the raw bytes), none over the line limit or refused as jsonb, about
0.26 ms a result including the read. The same file under the same ruleset
gives the same report in 97.4% of cases. The rest differ only in cleave's
`risk` or `mol` values on a member entry, never in placement or citation;
whether that is the engine version or context was not checked. Where a file
scanned alone keeps its `facts` but a quiet member's entry is trimmed to
`{mol, risk}`, the reports differ by design; scan's version 8 reports come
from the same trimmed report.

Version 8 bodies from scan may still differ from converted ones in escaping:
Go writes U+2028 and U+2029 escaped and serde does not. That costs one report
rewrite on a file's first version 8 scan, nothing more.

To use it, prism and cyclotron bump their `github.com/atomdrift-project/hopper`
requirement once this is pushed (prism is at a 2026-10-21 pseudo-version).

### Rescan by age (2026-11-12, local)

Hopper has always rescanned old samples: the last tier of the claim ladder
(`rescan_age`) hands out files last analysed more than `--rescan-age` ago
(90 days by default), oldest first, when workers have nothing newer to do.
That stays. In the new schema it is the `QueueStale` priority, fed by a loop.

- **Age is the only test,** as it is today, and for the reasons recorded
  beside the legacy query (`rescanAgeCandidatesPG`): the ruleset is bumped at
  least daily, so "judged under another ruleset" is true of nearly every file
  and filters nothing; and a test that needs to be told the current ruleset
  stops working the day nobody tells it, which is how the old tier spent
  months disabled. `SweepStale` had a ruleset test as well; it is gone.
- **The loop** (`sweepStale` in `cmd/hopper/queue.go`, started from `main`
  when a results store is set). Once a minute, if fewer than 5,000 rescans by
  age are queued, it walks `scans` oldest first from where it left off
  (`scans_age`, a keyset cursor), 5,000 a statement and at most 200
  statements a tick, queueing files on disk last scanned before the cutoff,
  until 10,000 are queued or no overdue scan is left. It reads only overdue
  files; the 200 statements bound a run of files no longer on disk, which
  it passes over rather than deletes (a lookup still reports their last
  scan).
- **The cursor is not persisted.** After a restart the walk begins at the
  oldest again. A file rescanned since is no longer old, so starting over
  costs reads and queues nothing twice.
- **Every scan of a file is recorded, a failed one included,** in its
  `scans` row: a later scan with the same result writes that row and no
  verdict, and the same upload sent twice writes nothing. A failed scan
  never replaces a good verdict; it moves only the time, so a file that
  scanned once and now times out does not look overdue forever.

The dashboard's count of how many files are past the age
(`RescanDepths.Age`) is now a range count on `scans_age`; it is not ported
yet.

### Scans: when, apart from what (2026-11-12, local)

Decided with Thomas: "verdicts will change seldomly; but rescans will be a
constant". Triage wants files by when they were last scanned, and an index
on `verdicts.scanned_at` is not possible cheaply: PostgreSQL decides HOT
eligibility from every column any index uses, partial predicates included,
so even a partial index would turn every scan's stamp into a non-HOT update
of a verdict row and index all 310M atomscan rows, members included.

So when a file was last scanned moved to its own narrow table,
`scans (sample_id, scanned_at, ruleset, engine)` with `scans_age` on
`(scanned_at, sample_id)`, one row per scanned artifact (about 57.6M in
production, members never). The writer's `stamp` step rewrites it on every
scan: the ruleset and engine only for a scan that reached a verdict, the
time for any; an earlier upload than the one recorded, or the same one
again, writes nothing; a different ruleset or engine at the same instant is
recorded. A verdict row now changes only when its opinion does, so:

- `verdicts` is packed full (`fillfactor` 100, was 80). At production scale
  that is roughly a fifth of the table back, possibly tens of GB; an
  extrapolation from about 1B rows at 110 B, not a measurement.
- The writer lost its special case for the artifact's own row and the
  separate statement that moved a failed scan's time forward.
- Lookup reads the last confirmation (time, ruleset, engine) from `scans`
  for a top-level file and from the verdict row for a member.
- The rescan-by-age sweep reads only overdue files, oldest first.
- `scans` sets `autovacuum_vacuum_scale_factor = 0.02`: each scan leaves a
  dead row, a little over 1% of the table a day at a 90-day rescan age.

Measured, per scan, on the 138,767 atomscan rows of the local export
(20,000 rows stamped each time):

| Layout | WAL per scan |
| --- | ---: |
| Stamp on the verdict row, HOT (before) | 154–171 B |
| `scans` row (sample_id, scanned_at, ruleset, engine), not HOT | 301–337 B |
| `scans` row with only sample_id and scanned_at | 293–330 B |
| Append-only log, plus the verdict stamp it cannot replace | 137 B + 154–171 B |

The stamp roughly doubles, about 100 MB of WAL a day more at an estimated
640,000 scans a day. In the whole writer (`TestResultWriters`, 3,999
uploads, below) an unchanged rescan fell from 2.5 KB to 2.1 KB per upload,
because the verdict rows the old rule restamped are no longer written.

Migration: `scans` is filled from atomscan's verdict row of every file with
a location (`scanned_at`, `ruleset`, `summary->>'eng'`). The local export
was given it that way (21,851 rows).

### Triage queues on the new tables (2026-11-12, design)

Thomas: keep all of them, port them as they are unless something is an
obvious improvement. The time windows exist to keep a queue reachable
(under about a thousand entries) where nothing tighter was found; for some,
recent scans being accurate is the point.

Production, read-only, measured back from the last scan (writes stopped):

| Queue | In its window | Whole population |
| --- | ---: | ---: |
| bad (24h) | 1,886 | 1,196,110 |
| unconvicted-hostile (12h) | 1,421 | 179,653 |
| unconvicted-suspicious (12h) | 3,014 | 273,861 |
| discord (24h) | 2,624 | 181,627 |
| fp-trait (24h) | 517 | 43,130 |
| popular / popular-tail (24h / 1-21d) | 39 / 20 | 3,054 |
| highest (analyzed 3d, created over 48h ago) | 26,934 | |
| version-drift candidates (created 7d) | 20,912 | |
| fallout (created 7d) | 7,677 | |
| stranded | | 427 |
| acquit | | 3,651 |
| second, before its sightings test | | 5,563 |
| review | | 113,239 |
| Top-level files scanned, 12h / 24h | 903,610 / 1,257,859 | |
| Of those, flagged (crit 4+, ML above benign, or labelled bad), 12h / 72h | 17,041 / 42,506 | |

So a queue cannot start from "scanned in the window" (900K rows to find
1,400) nor from its population and test each row's scan time (up to 1.2M).
It starts from the flagged scans in its window:

- **`scans.flagged`**, set by the writer's stamp step when the artifact's
  atomscan, floor or ml row is not benign or the file is labelled bad, with
  `scans_flagged (scanned_at, sample_id) WHERE flagged`. Only flagged scans,
  about 2%, add an index entry. A file relabelled bad after its scan is not
  flagged until its next scan or until the relabel sets it (labels port).
- **"Created in the window" reads the same index.** A scan follows its
  file's creation, so a file created in the last 7 days was last scanned in
  them; version-drift and fallout filter `created_at` after it.
- **Folded jurors replace member collapsing.** Scan folds members into the
  container's floor and ml rows, so highest, which collapsed members onto
  their archive, reads the archive's own rows.
- **Predicates on `samples` alone get partial indexes on `samples`**, which
  no longer churns with scans (acquit: bad, with a feedless provenance).
- **`samples.cited` comes back, for second alone**, as a mark that some
  sighting has named the file: second needs good, cited files as its
  starting set (partial index), and answering that from the ledger instead
  measured 19.5 s on production. Unconvicted's order and fallout's test ask
  `named()` per candidate instead. The mark is only ever set, by the Go
  writers after they commit, and recomputed whole by `Store.Recite`; see
  "Review for simplicity and efficiency".
- **`reports`** moves with `sample_id` in place of the text sha256; the
  cooldown and the permanent exclusions are unchanged.

Legacy columns map as: `cleave_result IS NOT NULL` is an ok atomscan
verdict; `parent = ''` and `path <> ''` are a `locations` row; `skip = ''` is
`label_source` not `conflict` or `marker` (and `skip <> 'conflict'` is not
`conflict`); `analyzed_at` is `scans.scanned_at`; `max_crit >= 5` is the floor
row's `hostile >= 1`, `max_crit = 4 AND suspicious_count >= 2` is `hostile =
0 AND suspicious >= 2`, `max_crit >= 4` is a floor row that is not benign;
`litmus_class` is the ml row's class, `lvl` its `fires_at`, `litmus_score`
its `prob`; `top_traits` is atomscan's `top`; `llm_result->>'interpretation'`
is the llm row's `reason`; `score` (cleave's risk) is not stored and
orders by the floor's counts instead.

Narrowed on purpose, each noted where it is built: lowest considers
top-level files (rule 8 leaves few bad members).

**Dropped (Thomas, 2026-11-12): bad-shared and stranded.** bad-shared had no
constraint tighter than reading every bad file on disk. stranded handed out
a good member with a finding inside a bad archive; in the new schema the
member's finding is folded into every archive that holds it, so the good
archive its label came from has a floor that is not benign and reaches
unconvicted-hostile or -suspicious on its next scan. What is lost is being
handed the member itself, with the bad archive as context. cyclotron's
policy entries for both go when it moves to the new tables.

**Built (2026-11-12, local): the other 19**, in
`store/triage.go` (`Store.Triage`, `Store.TriageDepth`,
`Store.FileReport`, `TriageQueueNames`), with `TestTriage*`, `TestFileReport`
and `TestCitedAndFlagged`. `cmd/hopper` serves `/api/triage/*` and
`/api/report` from them when a results store is set
(`cmd/hopper/triagestore.go`, `TestTriageFromStore`), in the legacy
`hopper.Sample` shape cyclotron decodes; bad-shared and stranded answer
404 there. Also changed for it: `locations.path` is `COLLATE "C"` (production
is `en_US.UTF-8`, where a byte-prefix range of paths is not safe, and review
reads `review/` as a range of the key); the ledger's DDL gained `basis`,
`relayer` and `sightings_review_queue`, as production has them; ingest marks
arriving files cited and flags the last scan of a file it relabels bad.

Timed with `TestTriageScale` (set `HOPPER_TRIAGE_SCALE`): one month of
flagged scans at production's rate, 1,000,000 rows, selecting 64 and
counting depth to the 10,000 cap, warm, local:

| Queue | Select 64 | Depth |
| --- | ---: | ---: |
| unconvicted-* (four), popular, fp-trait, bad, discord | 2-41 ms | 10-54 ms |
| popular-tail (21 days), highest (3 days) | 47-64 ms | 42-64 ms |
| version-drift, fallout (7 days) | 96-141 ms | 95-140 ms |
| lowest (30 days) | 424 ms | 411 ms |
| bad-shared (no window; since dropped) | 389 ms, nothing found | 390 ms |

The generated data has no sightings, reports, contents or gauntlet runs, so
the queues built on those (sighted, second, review, acquit, gauntlet) were
not exercised at scale. One needs more than a port:

- **lowest** sorts every bad file scanned in 30 days by the model's
  probability. Legacy had an index on `(file_type, litmus_score,
  analyzed_at)`; the new schema has no column to index without indexing a
  juror's summary, which an ML release rewrites.

### Labels and moves (2026-11-12, local)

A triage ruling (`POST /api/triage`) moves a file between pool trees and
usually relabels it. The filesystem half of a move (content and source
locks, publishing by hard link or copy, the provenance sidecar, removing the
source) is unchanged; its four catalog calls are now `hopper.MoveCatalog`,
which `hopper.DB` implements for the legacy tables and `storeCatalog`
(`cmd/hopper/triagestore.go`) for the verdict schema. `relocateTriaged`
records in whichever is set.

- **The catalog half** (`store/locations.go`): `PrepareMove`
  records the destination beside the source and any relabel, in one
  transaction, before the source is removed; `FinishMove` retires the source
  once the destination is recorded; `LocationsRecorded` and `Donors` answer
  the two questions the filesystem half asks. A move retried after it
  finished is a no-op that succeeds. A destination path recorded for other
  bytes is refused.
- **Nothing else moves.** Legacy rewrote every member placement under a
  moved archive; here a member's path is relative to its container, so a
  move touches one locations row.
- **A relabel** appends to `label_events` (carried over: gauntlet reads it
  for disputed ground truth, collimator writes it) and, to bad, flags the
  file's last scan for triage. A conviction then queues up to 64 of the
  package's other files for repair, newest first, those still unknown and
  judged under an older ruleset (`QueueSiblings`, legacy's
  `QueueSiblingRescans`), best effort after the conviction commits.
- **Not carried over: `sample_location_history`.** Legacy kept retired
  paths for file serving to recover from; a move here retires its source
  only after the destination is recorded in the same catalog. Revisit when
  file serving is ported.
- **Rule 8 is not service behaviour.** Legacy cascades labels to members
  only in the `cascade-backfill` CLI, never in the service, so the cascade
  is a migration-time step, not part of this port.

`TestMove`, `TestQueueSiblings`, `TestRulingFromStore` (a ruling moves a real
file and records it).

**Pool reconciliation** (`store/reconcile.go`, `Store.Reconcile`),
after a complete walk, as legacy's `ReconcilePools`:

- A reconcile walk stages every path it sees into `walk_staging`
  (UNLOGGED, `COLLATE "C"`, emptied by `StartWalk`), through the same
  `walkStager` the legacy walk uses, now given a stage function.
- **Learn:** staged paths the catalog lacks, or holds for other bytes (a
  rename or hard link the hash cache recognised, so ingest never saw it).
- **Relabel from pools,** legacy's rules unchanged: inconclusive/ (or
  purgatory/) and dual-use/ win, then bad/, then good/; sighted/ only lifts
  an unknown file; both bad/ and good/ is bad held as `conflict` until a copy
  goes; markers and reviewed labels are never overridden. Each change goes to
  `label_events`; a relabel to bad flags the last scan.
- **Retire** paths the walk did not see and that are gone from disk. A path
  still on disk but not listed is kept (legacy's `unsupported`). Retiring
  is per path, not per file: a file that lost one of two copies keeps the
  other. A file left with no path leaves the queue.
- **Breakers,** as legacy: more than 15% of the paths on disk relabelled, or
  retired overall or in one pool, refuses the step with nothing changed
  (populations under 100 are unguarded). With `--dataset-incomplete` nothing
  is retired.
- Steps 4 and 5 of legacy (cascading "missing" to members of a missing
  archive, reviving them) have no counterpart: members have no paths.

`TestReconcile`, `TestWalkReconcilesStore` (a real walk: a file moved from
good/ to bad/ follows its pool, a deleted file loses its path). The walk's
`walkPass` now takes the results store from the API, so setting it in `main`
turns this on too.

Still on the legacy tables: file serving's recovery and "missing" marker,
the hash cache's "already inserted" mark and the upload handler's lookup of
a known file, and the CLIs that change labels (`demote-sighted`,
`migrate-purgatory`, marker resolution, `cascade-backfill`).

### Identity claims (2026-11-12, local)

Scan now sends each file's `ident` block on its file line and leaves it out
of the report (`../scan/JSON_PLAN.md`, "File lines"). Hopper's decoder is
strict, so it had to learn the field; and with the block gone from the
report, hopper has to keep it or it is lost.

```sql
CREATE TABLE claims (
	sample_id bigint PRIMARY KEY REFERENCES samples,
	name      text   NOT NULL DEFAULT '',
	version   text   NOT NULL DEFAULT '',
	signer    text   NOT NULL DEFAULT '',
	ident     jsonb  COMPRESSION lz4 NOT NULL
);
CREATE INDEX claims_name   ON claims (name, version) WHERE name <> '';
CREATE INDEX claims_signer ON claims (signer) WHERE signer <> '';
```

- **One row per file,** where the legacy table had one per file and source.
  A block has one name claim; the legacy key only ever held a second row
  when a later scan named a different source for it. `source`, `verified`
  and `trust` are read from `ident` when wanted. The two legacy filters
  (`asset_claims` by name, by signer) are the two indexes.
- **Written only when the block differs,** compared as jsonb, with the same
  leave-unchanged-rows-out-first shape as every other statement. A scan that
  read the file and found no block removes the row; a failed scan, or a line
  with no verdict, leaves it. A member's line is ignored for a file with a
  scan of its own, as its verdict is.
- **An orphaned member gives up its claim** with its verdicts.
- **The legacy converter sets claims and never removes them.** A version 7
  report older than the identity block says nothing by leaving it out.
  Version 7 reports keep the block inside them as well.
- **Limits:** 8,192 bytes a block (the local export's largest is 1,893 of
  6,588; median 640). A lifted name or signer over 2,048 bytes, or version
  over 256, is left out of the columns and stays in the block.

Found on the way, and fixed for verdicts and jurors too: a verdict, juror or
identity object holding an escaped NUL or text that is not UTF-8 passed the
decoder and then failed at the database, the same way on every retry. The
decoder now rejects the body with a 422 that says which file and why.

The member limit in the decoder went from 100,000 to 256, scan's cap. That
was not needed to accept scan's bodies; it is worth having because the limit
bounds what one upload can make a `contents` row hold (256 paths of up to
4,096 bytes, where it was 100,000). The cost is an ordering rule: raise it
here before raising scan's cap. The converter for version 7 bodies has its
own limit and is untouched.

### Ingest on the new tables (2026-11-12, local)

`Store.Ingest` (`store/ingest.go`) is the walker's, the fetchers'
and the upload path's way in: a batch of arrivals, each a digest at a path
with whatever its producer claims. One transaction writes the file's row,
its path and its place in the queue. In `cmd/hopper` the walker's batches
(`QueueNew`) and the upload handler (`QueueUpload`) call it when a results
store is set, which `main` still does not do; `/api/rescan` goes to
`Store.Rescan` under the same switch.

Where the legacy sample columns went:

| Legacy column | Now |
|---|---|
| `path`, `source`, `feed`, `mtime` | `locations` |
| `purl_base` | `names`, by `samples.name_id`, spelled by `pkgparse.CanonicalizePURL` |
| `package` | not stored: with a PURL it is part of the name, and without one it was a guess from the filename, which the path still holds |
| `version`, `url`, `fetched_at`, `provenance`, `label`, `label_source` | `samples` |
| `status`, `skip` | dropped: a `queue` row is "not scanned yet", a verdict's outcome is why not |
| `ecosystem`, `domain`, `filename` | derived from the name, the URL and the path when read |
| `corroborated` | read from the sightings ledger at lookup |
| `canonical_sha256`, `elements` | never ingest's: analysis derives them |
| `marker_mtime` | not carried; one review CLI's age column read it |

The rules for a file shown again are the legacy ones
(`sampleObservationSQLPG`), restated once as a list of column expressions
that renders both the update and the test for whether it would change
anything:

- A reviewed label (inconclusive, dual-use, purgatory) is never replaced.
- A marker beside the file overrides its pool; the pool's label returns when
  the marker is gone.
- Good and bad pools disagreeing is `bad` with the source `conflict`.
- Otherwise the label that claims more wins: bad, good, sighted, unknown.
- The first sidecar supersedes an identity guessed from a filename; after
  that an arrival only fills what is missing. URL, fetch time and provenance
  are written once.

What ingest does that the legacy path did not:

- **Queues in the same transaction.** A file with no atomscan verdict is
  queued at the caller's priority (`QueueNew` for a walk, `QueueUpload` when
  someone is waiting), as `QueueBigArchive` when a first scan is over 1 GB,
  and as `QueueSighted` when a feed has cited it. A file queued lower is
  raised; one queued higher is left.
- **A path names one file.** An arrival at a path another file held takes
  the path over, and a file that has lost its only path leaves the queue:
  there is nothing to hand a worker.
- **Shown again unchanged, it writes and locks nothing**, in `samples`,
  `locations` and `queue` alike: each statement leaves unchanged rows out
  before the insert, because a conflict clause whose `WHERE` is false still
  locks the row.
- **Nothing an arrival carries fails the batch at the database.** Names,
  versions and URLs come from registries, so from whoever published the
  package; a NUL or a byte that is not UTF-8 is dropped from them, and a
  sidecar jsonb would refuse (`\u0000`, or not JSON) is left out for a later
  one to fill. The legacy path scrubbed NULs only. An arrival at a path that
  cannot be one is refused and counted, as are empty files and files under
  six bytes.

Three things to know before trusting it with production's rows:

- **Quarantine no longer keeps a file from being scanned.** The legacy
  claim index required `skip = ''`, so a file under a marker
  (`misclassified`) or in both pools (`conflict`) was not handed out for
  a first scan until someone settled it. Both facts survive as `label_source`, and the
  queue does not read labels: such a file is scanned like any other. A
  verdict is not a label, so nothing is lost, but the triage queues that
  excluded `skip <> ''` must test `label_source` when they are ported.
- **Nothing supplies `published_at`.** The column and `samples_newest` exist
  for the newest release under a name (floating references at lookup), and
  `Arrival` carries it, but no sidecar hopper parses has a publication
  time. It has to come from forager's sidecar or the registry before the
  lookup raise can use it.
- **`purgatory` arrives as `inconclusive`.** `cmd/hopper` spells the legacy
  alias the way `hopper.CanonicalLabel` does; the enum keeps `purgatory`
  only so the migration can load rows as they are.

A rescan request (`Store.Rescan`) is granted when the file has somewhere to
be read from and either a scan of it is still owed or atomscan has not
judged it within the cooldown (15 minutes). The legacy rule also refused
archive members and skipped files; "has a location" covers the first and the
second no longer exists.

Kept from the legacy path, and worth knowing: when one batch shows the same
bytes twice, the first arrival speaks for the file and the rest add only
their paths. Good and bad pools holding the same file in one batch resolve to
`conflict` the next time the bad pool is shown, not the first.

### Sightings on the new tables (2026-11-12, local)

The ledger itself does not change. It is keyed by text (a lowercase sha256,
or a package URL without its version), so it has no `sample_id` to rewrite,
and the migration leaves the table, its rows and its acquisition indexes
where they are. `schema.sql` declares its columns, key and subject index so
the new schema is complete on its own and tests have a ledger. What changes
is where the ledger met `samples`:

- **`samples.corroborated` goes.** It was a copy of "some sighting names
  this file or its package", kept by triggers in both directions, and its
  main use was the claim ladder's sighted tier. In the new schema that tier
  is the `QueueSighted` priority, which drains itself when the file is
  scanned, so nothing has to be cleared when a sighting is dropped.
- **A sighting moves a waiting file to the front** (`Store.Cite`, which the
  sighting writer calls once its claims commit). A digest subject raises
  that file; a package subject raises the files of that name, narrowed by
  `covers()`: to the listed versions when `affected` is a list or one
  version written with `=`, package-wide when it is empty, `*` or a range,
  the legacy `unnarrowableScope` rule. Only files with no atomscan verdict
  move. This was a trigger; see "Review for simplicity and efficiency".
- **A file that arrives already named goes first.** Ingest's queue step
  probes the ledger by digest and by name (two index probes per file not yet
  scanned) beside the existing `sighted` label test.
- **One spelling.** `nameOf` in `store` spells every package name
  (ingest's, the writer's refs) as the ledger spells a subject:
  `VersionlessPURL(CanonicalizePURL(s))`, the body of `normalizeSubject`.
  On the 7,711 package names in the local export it changes nothing; it
  guarantees the join for the rest.

`TestSighted`, `TestNameOf`. Corroboration at lookup reads the ledger by
subject as it does today, so it needs no port of its own; the raise from
corroboration and the readers that filtered on `samples.corroborated` move
with the readers:

- the feed's `Corroborated` filter and its two partial indexes
  (`idx_samples_corroborated_created`, `idx_samples_sighted_created`):
  without the flag, a newest-first feed of cited files is read from the
  ledger's side (`idx_sightings_recent`) and probed into `samples`;
- the good-but-cited triage queue (`AND corroborated` in `pg.go`), which
  already re-checks the ledger with `EXISTS` and can drop the flag;
- the dashboard's pending-sighted count, which becomes the queue's count at
  `QueueSighted`;
- the acquisition queue's "do we hold it" probes (`knownRetrievableSQL`):
  `samples.sha256` is bytea now, and retrievable means it has a location.

### Review for simplicity and efficiency (2026-11-12, local)

Two independent reviews (Go, and schema/SQL) read the verdict schema and
hopper's changes against the project's standard. What was confirmed was
fixed; `go test ./...` passes against the local cluster, `make lint` has no
finding in the changed code, and the 37,997 exported version 7 results
convert and store in 64 s (288,692 files).

**Bugs fixed.**

- *Rescans locked unchanged rows.* The verdict, contents and refs upserts
  had only a conflict-clause WHERE, which still locks the row: every rescan
  locked (WAL, a dirtied page, an 8 KB image after a checkpoint) every row
  it did not change, and a member shared by many archives became a lock
  every upload queued behind. Each now leaves unchanged rows out before the
  insert, as ingest and claims did. `TestWriteUnchangedTouchesNothing`
  checks that no row version moves.
- *A late upload could overwrite a newer verdict.* Every Write of an
  artifact takes its advisory lock, then, in a statement of its own, checks
  `scans`: a result older than the recorded scan changes nothing
  (`Stats.Late`). A verdict row is also never replaced by a scan older than
  its `formed_at` (another archive's newer reading of a shared member).
  `TestWriteLate`, `TestWriteKeepsNewerOpinion`.
- *Bad input became a 500 and endless retries.* One validator,
  `scanresult.Check`, runs in `Store.Write` for both paths: limits, format
  rules, duplicate digests, report digests, stamp lengths (`MaxStamp`), and
  everything PostgreSQL would refuse, now including half a UTF-16 surrogate
  pair. `Decode` only parses: it no longer allocates from the header's file
  count, and refuses trailing bytes. Version 7 conversion clips the
  interpreter's text; it also gave a member with no ML level an ok verdict
  with no class, which the validator caught on real data. The summary
  `CHECK` (jsonb's stored size, not the checked text's) is gone. Members
  keep their two limits: 256 a container in a version 8 body
  (`MaxMembers`, enforced by `Decode`), 100,000 in anything stored
  (`MaxStored`, the schema's check), which version 7 conversion needs.
- *Ingest failed a batch on one long path, name or version*; it refuses them.
- *`Unlocate` left queue rows* for files with no path; it drops them.
- *Orphan cleanup could delete a verdict another writer was relying on*; it
  locks the candidates' rows, then re-checks in a fresh statement.
- *Juror and queue deletes took rows in no order*; they take them in key
  order. `TestWriteConcurrent` stores 16 results sharing members at once.
- *Reconcile* wrote before checking its breaker (now one statement that
  writes only when the count is within it), could overwrite a concurrent
  ruling (now updates only rows still as read), and trusted an hours-old
  walk (it takes the walk's start; a label event, a path, or a move recorded
  since stands).
- *Repair requeue* missed archives holding the member through a nested
  container (now a bounded walk up `contents`), and its comment disagreed
  with its SQL.
- *Concurrent results for one file were merged* by a singleflight keyed by
  sha256; it is gone, and the artifact lock orders them.
- *A raised record could read hostile and "never fires"*; *a lookup by name
  alone sorted every file of the name* (now newest by id, `samples_name`);
  *an unknown size was stored as 0*, so a huge file could reach a small
  worker (now NULL, never offered to a worker with a limit, filled by the
  scan).

**`samples.cited`, simplified.** It was kept by a trigger in both
directions and by ingest, and was brittle: a claim and its file committing
at once were never marked (neither transaction sees the other), removing a
claim re-checked every other one, the trigger could deadlock with ingest,
and each flip was a non-HOT update on `samples`. Now the mark is only set,
by the Go writers after they commit (`Store.Cite`, ingest's post-commit
step): whichever of a claim and its file commits second marks it. A
withdrawn claim leaves its mark, which costs second a row (it re-checks the
ledger). `Store.Recite` recomputes every mark; the migration runs it, and it
repairs claims written by hand. The trigger is gone; `named()` answers the
exact question for the readers that look at a few rows. The sighting writer
(legacy `AddSightings`, forager's) must call `Cite` when it moves to the new
tables, spelling subjects with `nameOf`.

**One version rule.** `exact_versions()` decides which releases a claim
names; `covers()` and every queue use it. A single version written `= 1.0.0`
was read as a range and covered every release (about 2–3K production
claims, 252 good files). Acquit and second ignored versions; the sighted
queues matched only `affected = version`. On production, package claims
name about 5,000 good files with the rule applied.

**Simplified.** Reports travel on each file (`File.ReportLine`) instead of
through an iterator, so `Converted.Next` and its re-sorting went;
`Stats.Changed`; `rose` is computed in SQL (classes are an ordered enum);
the triage registry is a map of functions; `Finding` is defined once;
`Enqueue` (no caller) went; `bigFile`, `minSize` and `trustedSources` are
unexported; the unqueue statement is one constant. Schema: `text_key` went
(names have a plain `UNIQUE`); `queue.job` went (the queue is scans);
`verdicts.created_at` went and `scanned_at` became `formed_at`, columns
ordered so a row has no padding; unused indexes went (`samples_bad`,
`samples_newest`, `reports_created`, `claims_name`, `claims_signer`); the
move takes `FOR NO KEY UPDATE`.

**Kept, on purpose.** Ingest's `against()`: the resolution rules are written
once and rendered for the pre-filter and the conflict clause; writing them
out twice would duplicate thirty lines of CASE that must agree.
`api.go` and `main.go` were over 2,000 lines before this work.

**For the migration plan.** Split the DDL (tables, then indexes, keys and
the functions that read other tables); load into a separate schema and swap
by rename; add foreign keys `NOT VALID`, then validate; reset identity
sequences after loading explicit ids; map `purgatory` to `inconclusive`;
set `cited` with `Recite`; project the size of `refs`; measure the contents
index's `fastupdate` at scale; batch reconcile's joins; turn on
`wal_compression = zstd`.

**Foreign keys on hot paths (Thomas, 2026-11-12: for efficiency).** A row
inserted with a key takes a key lock on the row it references, and many
writers locking one row share it through a MultiXact, whose churn forces
anti-wraparound vacuums of billion-row tables. `verdicts.scanner_id` is held
by `CHECK (scanner_id BETWEEN 1 AND 9)` instead of a key on nine rows every
new verdict would lock (`TestScannerCheck` keeps the two in step); `refs →
names`, `samples → names` (every ingest of a common package's files) and
`queue → samples` (every enqueue) have no key, since names and samples are
never deleted. The other keys stay; `verdicts → samples` is load-bearing,
as the orphan cleanup waits on it.

## Objective and current scope

Make repeated observations cheap enough to support billions of observations:
reuse sample identities, avoid rewriting unchanged rows, and avoid repeating
hashes and locator strings in every child location.

Work is currently **local prototyping only**. The user has deferred production
deployment until more disk is available on minas-tirith. No production schema,
index, or backfill changes have been made by this prototype work. Deployment
status of the earlier ingestion fixes has not been verified here.

Prefer a small relational design and measured improvements. Do not add a cache,
service, partitioning scheme, or additional normalization layer without evidence
that it earns its complexity. This is deduplicated observation tracking, not an
append-only event history: repeated sightings do not each require a new row.

## Design to carry forward

1. **Use the existing `samples.id BIGINT` for internal references.** Child and
   parent references should not repeat 64-character SHA256 strings. Preserve
   existing sample IDs during migration.
2. **Store SHA256 as 32-byte `bytea` at the sample identity boundary.** Keep hex
   strings at API, CLI, and import/export boundaries where compatibility requires
   them. Enforce exactly 32 bytes and uniqueness in the database.
3. **Intern exact relative locator strings.** A relative-path table owns the
   string; locations reference its ID. Use a unique 32-byte digest expression
   index, avoiding a second full string in a text index. Compare the original
   strings before accepting a match and reject a digest collision atomically.
4. **Separate a parent placement's prefix from a child's relative locator.**
   Reconstruct the full path by joining them. Keep roots and locators that cannot
   be safely split inline. Derive the filename when it equals the locator and
   store an override when it differs.
5. **Skip unchanged observations before an upsert can lock them.** Batch identity
   and path resolution. Preserve conflict guards for races and update only fields
   whose effective values change. Do not add a `last_seen` heartbeat write to
   every repeat.

The local implementation is in [internal/storageproto](internal/storageproto).
Its `identities` table stands in for production sample identities; it is not a
decision to create a second permanent copy of `samples` and its hashes.

The prototype retains location uniqueness on **sample plus full path**, using
`(sample_id, full_path_key)`. Changing the claimed parent of an existing location
must not silently create a duplicate or replace its original association. The
full-path digest costs space in both the row and its index; the writer benchmark
includes that cost.

Relative strings are shared, but this does not yet eliminate every repeated
string in Hopper. Parent placements still contain full prefixes, including
nested prefixes. Production `samples.path` and other copies need a reader and
schema audit before any claim that all locator duplication is removed.

## Behavior that must survive

- Preserve every locator byte, including `!!embedded:pe@0x12000`, nested child
  locators, and `##base64+gzip@1234`. A parent reference does not replace an
  anonymous embedded file's offset or decoding information.
- Preserve distinct child samples at the same relative path. A relative-path ID
  identifies a string, not a file or a unique child of an archive.
- Preserve source/feed/ecosystem, relationship type, mtime, filename overrides,
  and historical timestamps. Match the existing field-update rules.
- Validate every observation before deduplicating a batch, so a duplicate cannot
  hide a conflicting locator. Filter unchanged duplicates before selecting the
  row to upsert, so a metadata enrichment is not discarded.
- Retain separate statements where needed to see dictionary rows committed by
  competing writers at READ COMMITTED. Check full-path collisions after the
  upsert as well, and roll back the whole batch on a collision.
- Preserve existing move, retirement, containment, donor, incoming, and parent
  lookup behavior before switching production readers.
- Audit parent hashes with no corresponding sample row. Resolve that migration
  case explicitly; do not discard the association or invent a different parent.

## Evidence so far

The earlier storage experiment reconstructed every original field for six npm
cohorts totaling 2,850,431 location rows, plus a broad page sample and synthetic
locator fixtures. It compared text hashes, binary hashes, integer references,
inline relative paths, and dictionary paths. A dictionary can cost more when
reuse is low: its rows and indexes are not free. A unique text index also repeats
the string; the digest-index variant avoids that particular duplication.

The writer experiment executes Hopper's actual current location SQL as its
baseline. Both layouts include identity resolution and seven location access
paths. Neither includes sample analysis JSON, labels, queues, or their indexes.

Latest small local benchmark: median mean elapsed time per 1,000-observation
batch across three trials of 20 batches, on PostgreSQL 18.6 / Apple M4 Max.

| Workload | Current writer | Compact writer |
| --- | ---: | ---: |
| Entirely new samples and paths | 25.8 ms | 29.8 ms |
| New samples sharing relative paths | 26.1 ms | 26.9 ms |
| Exact repeats | 7.0 ms | 6.1 ms |
| Same archive at new prefixes | 23.6 ms | 25.4 ms |

For shared paths, compact storage uses about **59% less space and 45% less WAL**
in this experiment. Entirely new paths use about 49% less space and 32% less WAL.
Repeats leave persistent row versions unchanged, but temporary-table/catalog
work still produces WAL.

Profiling found full dictionary scans and repeated digest computation. Scalar
unique-key lookups and combined resolution/validation removed those scans. The
new-insert latency penalty relative to the same-run baseline fell from 83% to
16%; the shared-path penalty fell from 23% to 3%. Absolute timings also changed
between sessions, including the baseline, so do not attribute all wall-clock
improvement to the code.

A separate single-trial check with 100,000 preloaded observations and refreshed
statistics favored compact by roughly 2x. Its sensitivity to query plans and
checkpoint effects makes it a diagnostic, not a production throughput forecast.
These are small warm-cache experiments, not billion-row capacity validation.

Measurement details, raw trials, plans, caveats, and reproduction instructions:

- [Storage layouts](scripts/storage-prototype-results.json)
- [Writer measurements and containment audit](scripts/storage-writer-results.json)
- [Benchmark implementation](storage_writer_bench_test.go)

## Share archive contents across placements (decided: see verdict schema)

The verdict schema adopts this: `members` records containment once per parent
content, and only top-level files have `locations`. The analysis below is kept
for its reasoning.

A placement is a physical location of a particular sample. If identical archive
bytes exist at `/downloads/a.zip` and `/mirror/a.zip`, their contents are the same.
The current layout can store a child location under each prefix:

```text
/downloads/a.zip!!src/main.js
/mirror/a.zip!!src/main.js
```

A content-sharing design would record the archive's child relationships once and
record its physical placements separately. Conceptually:

```text
content relationship: parent sample ID, relative locator ID, child sample ID
placement:            archive sample ID, physical locator, observation metadata
```

For 1,000 children and two copies, that could mean 1,000 content relationships
plus two placements instead of 2,000 child-location records. This count excludes
any records needed for metadata differences. The current compact writer still
stores children per placement; it does not implement this optimization.

Anonymous offsets remain in the relative locator. Different npm versions with
different archive bytes still need separate content relationships; they can
share path strings, but are not interchangeable archives.

The exported TypeScript cohort has 74,803 eligible child rows but 54,893 distinct
parent/relative-locator/child triples. Lodash has 67,999 rows and 32,300 triples.
However, repeated relationships have different source/feed/ecosystem and
timestamps. Some parent/relative-locator pairs also have multiple child hashes.
These are candidate relationship counts, not measured net storage savings.

Before adopting this design:

1. Distinguish content facts from placement-specific observations. Measure whether
   metadata can usually live on the placement, with exceptions, without inventing
   values or losing per-child history.
2. Preserve multiple children at one locator and investigate their causes. Do
   not impose uniqueness on parent plus relative path alone.
3. Define when contents are known to be complete, including extractor version,
   partial/failed extraction, and later enrichment. Knowing a parent SHA alone
   does not justify skipping unfinished child ingestion.
4. Prototype reconstruction, nested archives, embedded offsets, moves, retirement,
   and metadata differences. Compare end-to-end writes and reads with the compact
   writer, including all supporting tables and indexes.

Adopt content sharing only if those measurements justify the additional model.
Do not describe either design as the globally most efficient option yet.

## Migration sequence

Superseded by `MIGRATION_PLAN.md` (2026-11-12): with writes stopped, the
migration is an offline rebuild into a `verdict` schema beside the legacy
tables, not the additive, dual-write sequence below, which planned a design
that no longer exists. Kept for its reasoning about disk and rollback.

### 1. Finish the local design

Keep the existing no-op ingestion fixes. Complete the reader/move/metadata audit,
larger mixed-workload tests, and the content-sharing decision. Select the smallest
schema that preserves required behavior and has measured benefits.

### 2. Rehearse identity and location conversion locally

Use stable existing `samples.id` values. Build a resumable migration prototype
against representative fixtures. Convert child and parent references to IDs
before retiring their text hashes. Keep path normalization a separate migration
step so it does not block the basic identity savings.

For SHA256, explicitly choose a bounded migration route rather than issuing an
unplanned whole-table type conversion:

- Validate existing hex values and dependent constraints/readers.
- In an additive route, populate a temporary `sha256_bytes bytea` alongside the
  text field in bounded batches using `decode(sha256, 'hex')`. Account for the
  temporary duplicate storage, updates, indexes, and WAL. Keep new writes in sync
  during the compatibility period.
- Validate length, uniqueness, and text/binary equivalence before reader cutover.
- If a shadow-table rebuild is selected instead, decode on copy and preserve
  IDs. Avoid copying the large analysis payload merely to change identity fields
  unless a separately measured rebuild requires it.
- Retire text SHA storage only after all dependent foreign keys, SQL callers,
  and compatibility requirements have been addressed. Encode hex at boundaries.

The exact additive-versus-rebuild choice remains open. Both need a local disk/WAL
measurement and rollback rehearsal; the prototype is not a migration script.

### 3. Rehearse path normalization and reader cutover

Populate the path dictionary and parent placements, preserving old location IDs
where references require them. Reconstruct and compare every original field.
Implement bounded progress checkpoints and a defined concurrent-write capture
strategy. Test catch-up, pause/resume, retry, cutover, and rollback. Do not leave
concurrent moves or metadata corrections outside the capture strategy.

Port all relevant readers and movers before retiring the old representation.
Delay removal of old data until the cutover checks and rollback window are done.

### 4. Production deployment, deferred until disk permits

Refresh the production inventory when deployment is actually scheduled. Budget
the old and new representations together, indexes and sort files, WAL and replica
retention, ongoing growth, snapshots, and reserve. Existing cohort projections
are sensitivity scenarios, not a sufficient headroom guarantee.

Review indexes against current query plans and dependencies. Do not drop an index
merely because it is large or has a low usage counter. The measured prototype
retains the existing access paths; no production index drop is selected here.

Once headroom and the rehearsal support it: deploy compatibility code, backfill
in bounded batches, catch up concurrent changes, validate, switch readers and
writers, and retain a tested rollback route. Stop at defined disk, WAL, lock, or
replication thresholds rather than consuming the reserve.

### 5. Reclaim space after validation

Remove obsolete indexes, fields, or old tables only after dependency checks and
the rollback window. Dropping a column does not by itself return the old heap
space to the filesystem. Plan any rewrite/compaction as a separate disk-budgeted
operation. Refresh measurements after reclamation.

## Acceptance criteria

- Exact reconstruction and API compatibility, including anonymous offsets,
  nested/decoded locators, metadata, and move/retirement behavior.
- Repeats do not rewrite stored rows or wait on their row locks. Mixed batches
  update only effective changes; duplicate enrichment is preserved.
- Concurrent ingestion and collision handling cannot silently lose or misattach
  data. Retrying a rejected batch is well defined.
- Storage accounting includes every supporting heap and index; WAL and migration
  peak disk usage are measured separately.
- Throughput, latency, read cost, and contention are tested on representative data
  with realistic statistics and working-set sizes. No unsupported billion-row
  throughput claim.
- Migration is resumable, observable, and rollback-tested before production use.
