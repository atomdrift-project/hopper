# Sample storage progress

Updated: 2026-11-12. Design and migration rationale: [PLAN.md](PLAN.md).

**Current phase: local prototype and measurements. hopper is stopped and nothing
writes to production until the migration (2026-11-12). The schema is settled in
the prototype; hopper itself is not yet ported to it.**

## Completed

- [x] Inspect production schema and storage read-only; save the inventory and
  local storage measurements in `scripts/storage-prototype-results.json`.
- [x] Fix the three repeat-ingestion issues in the current code: guard unchanged
  marker mtimes, prefilter unchanged location upserts, and derive sample update
  assignments/change detection together with the matching staging prefilter.
- [x] Add regression coverage for those fixes in `pg_ingest_test.go`.
  Production deployment of those fixes has not been verified here.
- [x] Export six successful npm cohorts; exclude failed/partial exports from
  measurements. Include a broad page sample and synthetic locator fixtures.
- [x] Compare text hashes, binary hashes, integer references, inline relative
  paths, and shared relative-path storage. Verify exact reconstruction.
- [x] Measure dictionary overhead, including the full text index, and compare a
  digest index that avoids storing the complete string twice.
- [x] Build the isolated local writer in `internal/storageproto`, using binary
  identities, integer references, parent placements, and shared relative paths.
- [x] Preserve current sample/full-path uniqueness, filename overrides, embedded
  offsets, decoded locators, and existing metadata update rules.
- [x] Add an exact-repeat fast path that leaves persistent rows unchanged.
- [x] Test mixed batches, held row locks, long locators, metadata enrichment,
  concurrent inserts, and whole-transaction collision rollback.
- [x] Test collisions within a batch and in duplicate observations. Ensure an
  unchanged duplicate cannot suppress a metadata enrichment in either order.
- [x] Benchmark against Hopper's actual location writer, with equivalent access
  paths, and record latency, throughput, storage, WAL, and sampled lock waits.
- [x] Profile dictionary resolution. Replace full dictionary scans with indexed
  unique-key lookups and combine resolution with exact-string validation.
- [x] Re-run all five benchmark scenarios for three trials and add a 100,000-row
  preload check, including a run with explicit ANALYZE on both layouts.
- [x] Audit candidate shared-content relationships and metadata differences in
  existing local exports; record why parent/path alone cannot identify a child.
- [x] Run the full Go test suite with local PostgreSQL enabled. Pass prototype
  tests under the race detector for three repetitions after final query changes.
- [x] Lint the prototype and benchmark. No findings in these files; repository-wide
  lint still reports 40 issues in unrelated existing code.
- [x] Save results, query-plan evidence, caveats, and reproduction instructions in
  `scripts/storage-writer-results.json`.
- [x] Stop the disposable local PostgreSQL cluster after measurements.
- [x] Record the overall plan and progress in `PLAN.md` and `PLAN_TODO.md`.

## Verdict schema prototype

Code: [internal/verdictproto](internal/verdictproto) (`go run ./internal/verdictproto`,
then `psql -f measure.sql` and `psql -f bench.sql`). Data: CSV export under
`/tmp/hopper-schema-prototype/v2/`; cluster on socket port 5499, database `proto`.

- [x] Export 1,943 archives and 137,932 member rows from galadriel.
- [x] Load the legacy layout and the verdict schema from the same rows.
- [x] Strip placement and ruleset stamps; rewrite trait sources to digests.
- [x] Attribute members by `pid`; verify multi-child paths disappear (1,815 → 1).
- [x] Record fetched dependencies as `refs` from the declaring file.
- [x] Measure table sizes, rescan WAL (unchanged and changed), lookups, walk,
  and reverse name → outermost-container query.
- [x] Compare report compression: pglz 5,817 B, lz4 5,809 B, zstd 3,602 B,
  zstd + dictionary 2,373–2,745 B per report.
- [x] Litmus: no detail row; 146 B average once the per-file list is dropped.
- [x] Classify misfiled member rows: 65,891 dependency-content rows in the
  sample, 217 of them visible as multi-child paths.

- [x] Replace `level` with `class`; add `scanners` with jurors; atomscan gets
  its own verdict row; one flagged-verdict index for queues. Reloaded and
  remeasured (3 verdict rows per file; 153 B WAL for an unchanged rescan).
- [x] Decide `skip`: not carried forward (outcomes, `label_source`, no location).
- [x] Decide report compression: zstd, fetched whole, never queried inside.
- [x] Plan three representative queues (discord, unconvicted hostile, bad)
  against the new tables: 0.2–0.4 ms.

Research that can change the schema, in order:

- [x] Triage: production sizes of the starting sets read from `reltuples` and
  `pg_stats` (flagged about 4M per juror, bad 9.2M, queues 5K–9.1M rows).
  Too large to fetch and sort; queues read `verdicts_flagged` backwards by
  sample id and stop after a page.
- [x] Production edge count: about 4.4B distinct edges, 0.4–1.2B distinct
  relative paths. Row-per-edge `members` projects to 0.8–0.95 TB.
- [x] Measure a packed member list (`contents`: one row per archive, id and
  path arrays, GIN on ids): 57 B per edge against 296 B, same walk and reverse
  lookup times. Projects to about 250 GB.
- [x] Member layout decided: `contents`. `schema.sql`, the loader,
  `measure.sql` and `bench.sql` moved to it; reloaded (820 MB, 52 B per edge).
- [x] GIN at scale (`scale.sql`, 93.7M synthetic edges): 36.6 B per edge,
  built in 49 s, 1.5 s to insert 20,000 archives, first 50 parents of a file
  in 91% of archives in 0.07 ms. Walk-up sets `gin_fuzzy_search_limit`.
- [x] Decide atomscan's stored class: level 25, level recorded in `summary`.
- [x] Decide where `provenance` lives: `jsonb` on `samples`.
- [x] Source independence: already in hopper (`sightings.operator`, `basis`,
  `corroboration.go`); add `scanners.operator` so scanner verdicts fold in.
- [ ] Triage: rewrite the remaining 18 queues with plans as backward index
  reads; measure the sparse ones (acquit, second, good_repair). Move the
  verdict-age ("stale") queues to `queue`.
- [ ] Scan: emit atomscan's class at a fixed reference level and cleave's class
  (the trait floor); the prototype uses stand-ins for both.
- [ ] Unchanged-report frequency: log, in the member refresh path, whether the
  incoming canonical report digest equals the stored one. One day of
  production logs decides whether rescan WAL falls by about 60% or about 95%.
- [ ] External readers: port collimator, prism and cyclotron to fetch and
  decompress reports instead of selecting `cleave_result`.

Decisions still open:

- [ ] Scan: drop the duration from rule-timeout findings; keep emitting `pid`,
  `rel` and `via` for fetched dependencies and their contents.
- [ ] Hopper ingest: rewrite trait sources to digests and apply the member label
  rule (top 3 by score and cited by a suspicious or hostile finding).
- [ ] Bounded Go walk for `/v1/lookup` with truncation reporting.
- [x] `/v1/lookup` reads on the new tables (`store`), held to the
  legacy projection by `store_parity_test.go`: 138,767 digests and 6,537
  releases agree, apart from four counted legacy defects (PURL recomposed
  instead of read from `purl_base`, level under the v6 key, unfilled
  `top_traits`, same-level tie order).
- [x] Design scan's version 8 upload: JSON lines (header, one line per file,
  one line per report), one verdict and one object per juror, placement-free
  reports hopper never parses. Recorded in `../scan/JSON_PLAN.md`.
- [x] Result storage: `store` holds the schema (`schema.sql`,
  embedded), the version 8 decoder (`v8.go`) and one transactional writer
  (`write.go`): a fixed handful of statements and one `COPY` per result,
  atomscan's row stamped, jurors and reports rewritten only when they differ.
- [x] Version 7 converter in its own package, `internal/v7result` (renamed
  from `internal/v7`, which Go tooling reads as a major-version suffix), to
  delete once scan uploads version 8. Keeps today's report JSON as it is; takes members
  (by `pid`) and references out of it; grades classes with scan's rule at the
  deploy level. Over all 37,997 exported top-level rows: 288,692 files
  written through the store, member lists match the prototype loader's apart
  from 3,269 fetched dependencies now filed as references and 1,549 edges
  (0.65%) of containers named by several results, where the last write wins.
- [x] Benchmark the new result writer against `DB.StoreResult` on the same
  3,999 reassembled uploads (`store_writer_test.go`): first scan 4.3 ms and
  30.5 KB of WAL per upload against 8.6 ms and 106.4 KB; rescan with unchanged
  reports 1.6 ms and 4.5 KB against 9.3 ms and 98.1 KB. Table in `PLAN.md`.
  It exposed that the converter left placement keys in member reports, so a
  shared file got a different report from each archive; fixed.
- [ ] hopper's `SuspiciousCeiling` is a flat L3000; scan and gauntlet use
  `min(25000, max(500, 100n))` (L2500 at L25) since 2026-11-06, and treat the
  old trait-floor markers L25001/L25002 as suspicious. Today's
  `litmus_class` therefore grades L2501–L3000 suspicious where scan says
  benign. Version 8 makes this moot (scan sends the class); decide whether to
  fix the live constant before then.
- [x] `/api/result` stores in the verdict schema when `apiServer.results` is
  set (`cmd/hopper/results.go`): `Content-Type: application/x-ndjson` bodies
  go to `store.Decode`, anything else to `v7result.Convert` (`fromV7`, deleted
  with the package). One transaction per result, retried on transient errors,
  concurrent stores of one artifact collapsed. A malformed body, including a
  new report whose hash does not match, is a 422 and is not retried. A
  version 7 worker error becomes a verdict with outcome `timeout`,
  `unsupported` or `error`; "missing bytes" records nothing. `main` does not
  set `results` yet, so production behavior is unchanged.
- [x] Writer rules: a failed scan never replaces an `ok` verdict, its jurors or
  its report; a repeat of the same verdict under the same ruleset writes
  nothing, whichever worker sent it; atomscan's row is rewritten when its
  verdict or ruleset changes. The upsert returns the replaced report digest
  (`RETURNING old.digest`), so the stored digest is read under the row lock.
  Rows are written in key order to avoid deadlocks between workers.
- [x] Work queue (`store/queue.go`, `cmd/hopper/queue.go`): the
  `queue` table replaces `cleave_result IS NULL` and the `rescan_priority`,
  `attempts`, `note` and `claimed_first_at` writes to `samples`. Seven
  priorities in the old ladder's order (sighted, capped at half a batch and
  newest first; upload; requested; big archive, for 16-slot workers; new,
  size-interleaved; repair; stale). A hand-out is a lease on the queue row
  (`FOR UPDATE SKIP LOCKED`, per-size lease), so two hoppers cannot hand out
  the same file and leases outlive a restart. Eight hand-outs without a
  result and the row is stuck: out of the index, counted by `Depths`, and
  cleared by a requested rescan. A result deletes the rows of the files it
  judged in the same transaction; an `error` outcome backs off six hours. A
  file whose class rose queues up to 256 other archives holding it for
  repair, in the same transaction, unless they were already judged as bad or
  under this ruleset. A missing file forgets its location instead of
  skipping the sample. `SweepStale` feeds the stale priority by walking
  verdicts in id order (`scanned_at` stays unindexed).
- [x] Review addenda (`PLAN_ADDENDUM.md`, `../scan/JSON_PLAN_ADDENDUM.md`)
  folded into `PLAN.md` ("Review integrated") and into
  `../scan/JSON_PLAN.md`, which is now the specification scan's version 8
  emitter is built from. The addenda themselves are unchanged.
- [x] Hopper side of the revised upload (`store`,
  `internal/v7result`); the decoder now accepts what `../scan/JSON_PLAN.md`
  specifies:
  - `schema.sql`: `refs.requested`, `refs.fetched`,
    `refs_referrers (name_id, version, sample_id)`, `samples.version NOT NULL
    DEFAULT ''`, `samples_release (name_id, version, id)`.
  - `v8.go`: `Ref` gains `Requested` and `SHA256` (URL refs only); a member's
    line carrying `llm`, a drift juror, `scanners` or `refs` is malformed.
  - `write.go`: a member's atomscan row is written only when its verdict
    differs, the artifact's also when the ruleset or engine does; juror
    removal is scoped by line; `worker` is out of the summary; ref names go
    through `pkgparse.CanonicalizePURL`; a ref whose constraint or fetched
    digest changed is updated in place.
  - `internal/v7result`: refs collected onto the root line; the `vers` or
    `version_requirement` qualifier kept as `requested`; `content_sha256`
    kept on URL refs.
  - `TestResultWriters` rerun: an unchanged rescan is 2.5 KB of WAL per
    upload, down from 4.5 KB, and writes 10,028 verdict rows where it wrote
    32,697.
- [ ] Ref versions are not canonicalized, only names. If fletch and
  `pkgparse` spell a version differently (a `v` prefix, PEP 440
  normalization), the join on version misses. Check on real data once scan
  sends resolved versions.
- [x] Decided 2026-11-12: the existing corroboration ladder stays for now;
  scan uploads today's retained members capped at 256 (`PLAN.md`,
  "Contents").
- [x] Relayed 2026-11-12: postdoc is the main uploader and the decider;
  `drift` is two jurors, `drift_heuristic` and `drift_llm`; third-party scanners
  (ClamAV first) arrive in a `scanners` object on the artifact's line and
  are stored as their own `verdicts` rows (`scanresult.SplitScanner`, the verdicts
  step in `write.go`, `TestWriteScanners`; `PLAN.md`, "Other scanners").
- [ ] A scanner's report: define the order of report lines when a file has
  more than one, extend the writer's report reader, then accept `report` in
  a scanner's object. Needed before malcontent.
- [x] The version 8 body and the version 7 converter are public packages,
  `scanresult` and `v7result`, standard library only, for prism and
  cyclotron (`PLAN.md`, "Old results and their readers"). `store/v8.go`
  became `scanresult`; its decode tests moved with it.
- [x] Readers read version 8 only; old results are converted when read
  (decided 2026-11-12). `v7result` rebuilds each report as scan's
  `report_line` does, drops pinned dependency verdicts from `top` and the
  floor, and leaves out reports older than version 6. Checked over the whole
  local export (`PLAN.md`, "Old results and their readers").
- [ ] prism and cyclotron: bump the hopper requirement and convert old
  results with `v7result.Convert` (after this is pushed).
- [ ] Lookup: count a third-party scanner's hostile verdict as one automated
  source under `scanners.operator`, alongside sightings, in the ladder.
- [x] A member line leaves alone a file that holds an `llm` or `drift` row
  (confirmed 2026-11-12; `write.go`, `Stats.Deferred`,
  `TestWriteMemberWithOwnScan`).
- [x] The writer sets a known file's `file_type` from its scan (`Retyped`).
  It used to set the type only on rows it created, so a file ingest had
  already created was never typed; today a trigger derives it from the
  report.
- [x] Claims under version 8: `ident` rides on the file line (scan) and is
  stored in `claims`, one row per file, written only when the block differs
  (`claims` in `write.go`, `scanresult.ClaimOf`, `TestWriteClaims`;
  `PLAN.md`, "Identity claims"). The decoder's member limit is 256.
- [ ] Scan does not yet hold an `ident` to 8,192 bytes or strip NULs from its
  strings; hopper rejects a body that breaks either.
- [ ] Readers of the legacy `asset_claims` view (the two sample-list filters,
  by name and by signer) move to `claims` plus `samples.name_id` when the
  readers are ported. Migration: fill `claims` from the stored reports'
  `ident` blocks, not from the legacy `claims` table, which lacks the block.
- [x] A member that leaves every archive's list loses its verdicts, in the
  writer and in the same transaction (`orphans` in `write.go`,
  `TestWriteOrphans`). Not a background prune: that cannot tell an orphaned
  member from a top-level file whose bytes went missing. The `samples` row
  stays; see `PLAN.md`, "Contents".
- [x] Lookup raise from our own detection (`PLAN.md`, "Raising a class at
  lookup"): measured, then built as `Store.Raise` and `Record.RaiseBy`
  (`store/raise.go`, `TestRaise`, `TestRaiseBounds`,
  `TestRecordRaiseBy`). Bounds of 4,096 refs, 4,096 members, 16 levels, 32
  raised, with a truncation flag; a `good` label blocks the raise.
- [ ] Lookup raise from corroboration, once sightings are on the new tables:
  a corroborated release, URL or member raises even when labelled good.
- [ ] `/v1/lookup` on the new tables: cached record, then `Raise` per
  request; the answer lists what raised it and says when a bound was hit;
  `fired` reads the stored class.
- [x] Decided 2026-11-12: requeueing holders when a member's class falls,
  and floating declarers when a release turns hostile, are both wanted and
  deferred. `DEFERRED.md` has what covers each gap and where the work goes.
  Both lean on rescan by age, so each gap lasts up to `--rescan-age`.
- [x] Sightings: names, refs and subjects share one spelling (`nameOf` in
  `store`, the body of `normalizeSubject`; `TestNameOf`).
- [x] Ingest on the new tables: `Store.Ingest` (`store/ingest.go`,
  `ingest_test.go`) writes the file, its path and its queue entry in one
  transaction, with the legacy re-observation rules for labels and identity
  (`PLAN.md`, "Ingest on the new tables").
- [x] `cmd/hopper` calls it when a results store is set: the walker's
  batches at `QueueNew` (`walkPass.results`, `runDir`), the upload handler at
  `QueueUpload`, both through `ingest` in `queue.go`. `/api/rescan` goes to
  `Store.Rescan` (`QueueRequested`, same 15 minute cooldown).
  `TestIngestAndRescan`, `TestQueueRescan`.
- [ ] The rest of the walk still reads and writes the legacy tables with a
  results store set: the hash cache's "already inserted" mark, the
  "replaced" marking, and the upload handler's lookup of an existing row
  (`SampleBySHA256`, to keep known bytes where they are). Walk staging and
  pool reconciliation are ported.
- [ ] `published_at` has no supplier: no sidecar hopper parses carries a
  publication time. Needed before floating references can pick the newest
  release at lookup.
- [ ] Triage queues that excluded `skip <> ''` must exclude
  `label_source IN ('marker', 'conflict')` when ported; the queue now scans
  such files.
- [x] Sightings on the new tables (`PLAN.md`, "Sightings on the new
  tables"): the ledger carries over as it is; the `sighted` trigger moves a
  waiting file it names to `QueueSighted`, and ingest does the same for a
  file that arrives already named (`TestSighted`). `samples.corroborated`
  and its triggers go.
- [ ] Readers of `samples.corroborated`, with the readers: the feed's
  `Corroborated` filter, the good-but-cited triage queue, the dashboard's
  pending-sighted count, the acquisition queue's availability probes.
- [x] Rescan by age, kept from the legacy ladder (decided 2026-11-12):
  `sweepStale` in `cmd/hopper/queue.go` feeds `QueueStale` from
  `Store.SweepStale`, by age alone, started from `main` when a results store
  is set. Every scan of a file is recorded in its `scans` row, a failed one
  included (`PLAN.md`, "Rescan by age"; `TestRefillStale`,
  `TestQueueSweepStale`).
- [x] `scans` holds when each artifact was last scanned, apart from its
  verdicts (decided 2026-11-12): the writer's `stamp` step, lookup's last
  confirmation, the sweep oldest first on `scans_age`, `verdicts` at
  fillfactor 100 (`PLAN.md`, "Scans: when, apart from what").
- [ ] The dashboard's past-the-age count (`RescanDepths.Age`): a range count
  on `scans_age`, not ported yet.
- [ ] `MIGRATION_PLAN.md`: fill `scans` from atomscan's verdict row of every
  file with a location.
- [ ] Not ported yet: the missing-LLM tier (one interpret attempt per file;
  version 8's `llm` juror can say it declined); path-prefix rescans
  (`--force-rescan`); lookup cache
  invalidation (`forgetSHA`).
- [x] Triage queues on the new tables, 19 of 21; bad-shared and stranded
  dropped (Thomas, 2026-11-12) (`PLAN.md`, "Triage queues on the new tables"): `scans.flagged` and `scans_flagged`, `samples.cited`
  back, `reports` by `sample_id`, served by `cmd/hopper` when a results store
  is set. Timed at a month of flagged scans (`TestTriageScale`).
- [ ] cyclotron: drop the bad-shared and stranded policy entries (and its
  use of `/api/stranded/{sha}`) when it moves to the new tables; the legacy
  registry keeps them until then.
- [ ] lowest: 424 ms at a month of flagged scans; measure against production
  volume after the migration rehearsal.
- [x] The labels port flags a file's last scan when triage relabels it bad
  (`PrepareMove`), as ingest does for pool moves. A relabel that changes a
  file's name or version marks `cited` through ingest's post-commit step.
- [ ] `hopper.TrustedBadSources` and `store.trustedSources` are one list;
  the legacy one goes with the legacy queues.
- [x] `MIGRATION_PLAN.md` written: integration, the offline migration, the
  replica rehearsal, the pipeline rehearsal, and six decisions.
- [ ] Build `hopper migrate` and the replica selection; run the rehearsal
  (`MIGRATION_PLAN.md`, part 3).
- [ ] Port the endpoints and forager (`MIGRATION_PLAN.md`, part 1); run the
  pipeline rehearsal (part 4).
- [x] Review for simplicity and efficiency (`PLAN.md`): the bugs and
  simplifications both reviews confirmed, `cited` set only after commit
  (`Store.Cite`, `Store.Recite`, no trigger), one version rule
  (`exact_versions`), one validator (`scanresult.Check`).
- [ ] The sighting writer on the new tables (forager's `AddSightings`):
  spell subjects with `nameOf`, call `Store.Cite` after the claims commit.
- [x] Foreign keys on hot paths: `scanners` by a `CHECK`; no `refs → names`,
  `samples → names` or `queue → samples` key (`PLAN.md`).
- [x] Triage rulings on the new tables: `hopper.MoveCatalog` (legacy `DB`
  and `storeCatalog`), `Store.PrepareMove`/`FinishMove`/`LocationsRecorded`/
  `Donors`/`LabelOf`/`QueueSiblings`, `label_events` carried over (`PLAN.md`,
  "Labels and moves").
- [x] Pool reconciliation on the new tables: `walk_staging`,
  `Store.StartWalk`/`StageWalk`/`Reconcile` (learn, relabel from pools,
  retire unseen, legacy's breakers), wired into the walk (`PLAN.md`, "Labels
  and moves"). `TestReconcile`, `TestWalkReconcilesStore`.
- [ ] `MIGRATION_PLAN.md`: rule 8 as a one-time step.
- [ ] Port hopper locally, in order (sightings with their enqueue, the
  triage queues and triage rulings are done): labels and moves, then the remaining
  methods, then set `results` in `main`. 188 exported DB methods;
  `sqlite.go` goes.
- [ ] External readers with their own SQL: gauntlet, promoter, prism, forager,
  pulsar, and collimator (about 36 files, keyed on `samples.id` and `xmin`).
  Decide: port each before cutover, or serve them a read-only legacy view.
- [ ] `MIGRATION_PLAN.md`: offline (hopper is stopped), under 1.36 TB free.

## Superseded: decide whether content sharing is worthwhile

Decided by the verdict schema above; kept for reference.

- [ ] Classify child fields as content facts, placement facts, or per-child
  observation exceptions. Measure exception frequency and storage cost.
- [ ] Investigate multiple child hashes at an identical parent/relative locator.
  Preserve them; do not silently choose a single child.
- [ ] Define completeness and extractor-version rules for reusing known archive
  contents, including partial extraction and later enrichment.
- [ ] Build a separate local content-sharing experiment. Store child relationships
  once per parent content identity and reconstruct them under each placement.
- [ ] Prove round-trip behavior for nested archives, anonymous offsets, decoded
  locators, metadata differences, moves, and retirement.
- [ ] Compare end-to-end reads, writes, WAL, and total storage with the existing
  compact prototype. Include the metadata exceptions and all indexes.
- [ ] Decide whether the gain justifies this model. Keep the basic ID/binary-SHA
  migration independent of that decision.

## Local work before any production migration

- [ ] Audit every production reader/writer and all SHA-based references; identify
  compatibility requirements and parent hashes without sample rows.
- [ ] Audit duplicate locator strings outside `sample_locations`, especially
  `samples.path`, parent prefixes, and filename overrides.
- [ ] Test larger working sets, representative batches, mixed concurrent metadata
  changes, read workloads, and contention with realistic planner statistics.
- [ ] Define deadlock/retry behavior and confirm idempotent retries.
- [ ] Select the additive or shadow-table route for text-to-bytea SHA conversion.
  Measure temporary storage and WAL; preserve existing sample IDs.
- [ ] Implement a local, resumable identity-reference migration and validate every
  text SHA against its binary representation.
- [ ] Implement path backfill separately, preserving required location IDs and
  exact reconstruction of original fields and timestamps.
- [ ] Define and implement concurrent-write capture, including moves and metadata
  corrections, rather than relying on a one-time snapshot.
- [ ] Port readers/movers and test lookup parity, cutover, catch-up, pause/resume,
  interruption recovery, and rollback.
- [ ] Decide whether any index can be removed using workload and dependency
  evidence. No index drop is currently selected.
- [ ] Measure peak migration disk/WAL requirements and establish stop thresholds.
- [ ] Review the chosen production schema and migration together. The current
  prototype schema is not a deployable migration.

## Production work: deferred

- [ ] Confirm sufficient disk and refresh production size, growth, WAL, replica,
  snapshot, index-usage, and query-plan measurements.
- [ ] Schedule rollout after the local rehearsal and user-directed deployment
  decision. Do not deploy as part of local prototyping.
- [ ] Deploy compatibility code and bounded backfill; monitor defined thresholds.
- [ ] Catch up concurrent writes, validate reconstruction and constraints, and
  switch readers/writers with the tested rollback route available.
- [ ] After the rollback window, remove obsolete representations and dependencies.
- [ ] Reclaim heap space through a separately budgeted operation where necessary;
  do not assume dropping text columns releases filesystem space immediately.
- [ ] Measure production storage, WAL, latency, contention, and read behavior.

## Latest evidence and limits

For 1,000-observation batches in the latest small local benchmark, compact inserts
with shared paths take 26.9 ms versus 26.1 ms for the current writer, using about 59%
less storage and 45% less WAL. Exact repeats take 6.1 ms versus 7.0 ms. Entirely
new paths remain about 16% slower on this small test. The separate preloaded test
favored compact but was sensitive to plans and checkpoint effects.

The benchmark excludes analysis JSON, labels, queues, and their indexes. It does
not validate billion-row production performance. Repeats still incur staging and
catalog work. Shared archive contents, production readers, migrations, change
capture, and dictionary garbage collection have not been implemented.

Local reproduction commands and environment requirements are in
[`scripts/storage-writer-results.json`](scripts/storage-writer-results.json).
The disposable database is named `hopper_schema_prototype`; tests require a
local Unix socket. Cohort CSVs and raw run logs remain under
`/tmp/hopper-schema-prototype/` and are not durable committed fixtures.
