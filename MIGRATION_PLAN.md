# Migration plan: legacy tables to the verdict schema

Written 2026-11-12. Hopper and all writes have been stopped since
2026-11-12 so the migration can be done offline. PLAN.md holds the design
and its evidence; this file says how hopper gets there. It replaces
PLAN.md's older "Migration sequence", which planned an additive, dual-write
migration to a design that no longer exists.

Five parts, in the order they can start:

1. Finish the integration, so hopper and its consumers run on the verdict
   schema alone.
2. The migration itself: one tool, run offline.
3. A local rehearsal of that tool on a selection of real data read from the
   replica.
4. A local forager → hopper → postdoc → cyclotron run on the migrated data.
5. Production.

Parts 1 and 3 can proceed in parallel. Part 4 needs both. Part 5 needs part 4
and the added disk.

## Shape: an offline rebuild beside the legacy tables

The new tables are built in a new schema, `verdict`, in the same database,
from the legacy tables in `public`, while hopper is stopped. Nothing writes
to `public` during or after the build, so:

- **No dual writes, no change capture, no catch-up.** The writes are already
  stopped.
- **Rollback is starting the old binary.** `public` is untouched until the
  rollback window ends. Anything written to `verdict` after the switch is
  lost on rollback; the window is kept short for that reason.
- **The copy is `INSERT … SELECT` within one database,** with no export or
  network hop. The legacy report blobs are read once, by the converter.

Disk, measured 2026-11-12:

| | Size |
|---|---|
| Database today | 7.58 TB |
| Free | 1.36 TB (±350 GB from snapshots) |
| New tables, estimated | 1.3–1.5 TB, about 0.8–1.0 TB of it reports (`verdicts.detail`); the efficiency changes below cut the rehearsal's verdict tables by 34% (473 to 312 MB at 10,000 results) |
| Index builds | sort space on `pgtemp` (the `scratch` pool), not `tank` |
| WAL during the load | bounded by checkpoints, with `wal_compression = zstd`; the inactive replication slot below would otherwise hold it all |

The added disk has to cover the new tables, their indexes and the WAL on top
of today's data, until the legacy tables are dropped. Part 3 measures the
bytes per sample of each new table, which turns the estimate into a number
before any production step.

## 1. Finish the integration

**Done when:** hopper serves every endpoint postdoc, cyclotron and forager
use from a database that holds no legacy tables. Part 4 checks this by
deleting them from its local copy.

### hopper (`cmd/hopper`)

`hopper load --store <schema>` opens the verdict tables (creating them when
the schema is empty) and hands them to the API and the walk. The acceptance
test is `TestLoadIngestsAndServesWorker` (cmd/hopper), part of `make test`:
`hopper load` on `cmd/hopper/testdata/load` with a local postdoc worker must
file every sample, have each scanned, store the results and member lists,
serve them through `/v1/lookup` and `/v1/files`, take a dependency uploaded as
a worker that fetched it would (scan refuses loopback, so the test plays that
worker), link it to the package that pins it, raise that package when the
ledger convicts the release, stop cleanly on SIGTERM with no process left,
and after a restart with a new file scan that file and no other. It runs the
worker with `--no-cleave-validate`, `POSTDOC_SCANNERS=none` and
`SCAN_FOLLOW=none`, so it needs no network and takes about a minute. Part 4
runs the same with the legacy tables gone. The work:

- **Open the store.** Done for the API, the walk and the sweep. With it set,
  hopper still opens the legacy `DB` for what is not yet ported below; when
  nothing is left, it stops.
- **Port, by consumer.**

  | Endpoint | Used by | State |
  |---|---|---|
  | `/v1/work/result` | postdoc, scan | done (`results.go`) |
  | `/v1/triage/*` | cyclotron | done (`triagestore.go`) |
  | `/v1/work/next` | postdoc | done: `claimJobs` is on the store, and `validateClaimJobs` opens a claimed file at its path or any other the store records (`openClaimedFromStore`), forgetting those it is not at |
  | `/v1/work/heartbeat` | postdoc | a heartbeat extends the lease through `Store.Lease` (release is gone) |
  | `/v1/files/{sha256}` | postdoc, cyclotron, gauntlet, prism | done (`filestore.go`, `Store.Source`): a file's own paths, newest first, forgetting each it is no longer at; a member out of a located archive that lists it |
  | `/v1/files/{sha256}/provenance` | postdoc, cyclotron | done: `Store.Provenance`; a sidecar sent alone refreshes it through `Store.SetProvenance` |
  | `/v1/lookup` | postdoc, poppy, scan | done (`lookupstore.go`): the record (`BySHA256`/`ByRelease`), the ledger's word on it (`hopper.Corroborate`), raised by what it points at or holds that atomscan holds hostile or the ledger convicts at a hostile rung (`Raise`, `hopper.Convicts`), listed in `raised_by` with `why` |
  | `/v1/intake/upload` (from postdoc's `/v1/analyze`) | postdoc, scan, forager | done: `Store.Ingest` with source `upload` at `QueueUpload`, the sidecar with it; a held digest is found in the store (`heldInStore`). `/v1/analyze` itself is postdoc's route, behind beamline; hopper's part of it is this upload, `/v1/intake/held` and the renewal through `/v1/work/result` |
  | `/v1/intake/held` | scan, forager | done: `Store.Held`, a file at a path, or one an archive at a path lists |
  | `/v1/intake/popular` | poppy | done: `Store.SetPopular` |
  | `/v1/storage/incoming` | draino | done: `Store.Incoming`, keyset on (seen_at, path) |
  | `/v1/sightings` | cyclotron, gauntlet, promoter, forager | done: writes through `hopper.PrepareSightings` (the legacy rules, shared) and `Store.AddSightings`, which marks the files named (`Cite`); reads from the store's ledger. `?backfill=1` dates a source's history (`BackfillSightingsToStore`), and a source's first bulk arrival is backdated as legacy's `seedTimes` did |
  | `/v1/sightings/attempted`, `/v1/sightings/retract`, `/v1/acquisitions/claim`, `/v1/acquisitions/finish` | forager | done (`ledgerapi.go`): the acquirers' writes, which forager made with SQL; it reads its queues with read-only SQL |
  | `/v1/sightings/ancestry` | cyclotron | done: `Store.Ancestry` up `contents`, then `hopper.SightingsInAncestryFromStore` |
  | `/api/cleave-result` | cyclotron | with the store, queues a whole scan (`Store.Rescan`) rather than writing a cleave-only result over the jurors; becomes a version 8 result through `/v1/work/result` once a juror a body does not name is no statement |

- **Claim tiers with no store equivalent.** `tierPathRescan` becomes a
  rescan of a path prefix (`locations.path` is `COLLATE "C"`, so a prefix
  is a range of the key). `tierMissingLLM` is a triage question, not a scan
  tier, and goes.
- **Dashboard and metrics (17 methods), maintenance (6), diagnostics (3).**
  Each is ported to store counts (`Depths`, `TriageDepth`, catalog
  estimates) or removed with the legacy schema. A list goes to Thomas
  before any removal.
- **`serve-replica`** is all legacy: rebuilt on the replica's new
  subscription, or retired (see "Replica" below).

### API: one `/v1/` surface (decided 2026-11-13)

Every route moves under `/v1/`, named for what it is and grouped by how it
is used; a route with no caller in the sibling repositories goes; routes
that answer the same question merge, and where a `/v1/` route already
answers it, its shape wins. The `/_/` probes (`health`, `ready`, `metrik`,
`replica`) stay: every service in the stack answers on them. The dashboard
has its own listener and is not part of this. Authentication is unchanged:
one bearer token.

```
/v1/lookup                        what is known about an artifact (the contract postdoc also serves)

/v1/work/next                     POST  the scan queue: claim,
/v1/work/heartbeat                POST    keep the lease,
/v1/work/result                   POST    report what was found,
/v1/work/rescan/{sha256}          POST    and ask for a scan again (prism)

/v1/files/{sha256}                GET   the bytes
/v1/files/{sha256}/provenance     GET   how they arrived

/v1/intake/held                   POST  which of these bytes does hopper hold?
/v1/intake/upload                 POST  bytes and their sidecar
/v1/intake/popular                POST  which packages deserve scrutiny (poppy)

/v1/sightings                     GET by subject, POST to append (?backfill=1 for a source's history)
/v1/sightings/ancestry            GET   sightings on a file or any archive holding it
/v1/sightings/attempted           POST  claims an acquirer has tried, by key
/v1/sightings/retract             POST  claims a source withdrew, by key

/v1/acquisitions/claim            POST  claim a fetch target, once ever
/v1/acquisitions/finish           POST  how it ended

/v1/triage/{queue}                GET   select (the stranded queue's items carry their members)
/v1/triage/{queue}/depth          GET   a capped count
/v1/triage/rulings                POST  label and move files
/v1/triage/reports                POST  mark a file worked (a queue's drain)

/v1/storage/incoming              GET   the hot pool's backlog (draino)
```

| Today | Becomes | Callers |
|---|---|---|
| `GET /api/sample?purl=` | `/v1/lookup?purl=`: the digest, and `state` for analyzed or held | poppy |
| `GET /api/sample/{sha256}` | goes; the probes call `/v1/lookup?sha256=` (the route served the legacy envelope) | promoter, beamline stress |
| `GET /healthz` | goes; `/_/health` | beamline stress |
| `GET /data/{path}` | goes; `/v1/files/{sha256}` (a ruling already checks the catalogued path) | collimator script |
| `GET /api/stranded/{sha256}` | goes into `/v1/triage/stranded` | cyclotron |
| `POST /api/cleave-result` | `/v1/work/result`, once a juror a body does not name is no statement, as a scanner is; the writer drops it today, which is why this route exists | cyclotron |
| `POST /api/gauntlet/runs` | `/v1/gauntlet/runs` (`Store.AddGauntletRun`) | gauntlet |
| `POST /api/release`, `GET /api/triage/queues`, `GET /api/gauntlet/runs/{id}`, `GET /_/corroboration` | go: no caller | — |
| every other `/api/…` | its place in the tree | as found by `rg` |

**Wire rules** (from a review against Google's AIPs):

- No GET changes state: `next` and `heartbeat` are POST.
- Every response is its own type with `lower_snake_case` fields; no
  internal struct goes on the wire (the triage selection sends
  `hopper.Sample` with Go field names today).
- One error object, `application/json`:
  `{"error": {"code": "…", "message": "…"}}`, with details such as `use`.
- A route that pages takes `page_size` and an opaque `page_token`, and
  answers `next_page_token`; one that takes up to N items takes `limit`.
- Each batch route states its maximum and refuses more with that error.
- Status codes say what happened. `/v1/lookup` answers 200 with a `state`
  (`analyzed`, or `pending` for bytes held that nothing has analyzed) where
  it answered 202, and 404 for nothing known; postdoc's and scan's corpus
  readers, which took 202 as "nothing stored", read `pending` the same way.
  `files/{sha256}/provenance` answers 404 with code `no_provenance` where it
  answered 204. `work/next` answers 200 with an empty `jobs` list where it
  answered 204. `work/heartbeat` keeps 204: a POST with nothing to say.

**Go clients of hopper's library** (decided 2026-11-13). A Go service that
uses hopper as a client library may read the database directly, through
hopper's `store` package against the verdict schema: the SQL lives in
hopper, so the schema stays hopper's to change. It never writes that way:
every write goes through the API, so it is ordered, validated and logged in
one place. prism, promoter and gauntlet read the legacy tables directly
today (`hopper.Open`), and prism's feed, stats and fallout are SQL of its
own. They move to `store` reads, their writes to `/v1/` routes, before the
switch; until then the switch would leave them reading frozen legacy
tables, and dropping those tables would break them.

**Retired paths.** There is one path per route, never two. An old path
answers **410 Gone** with the error object, `use` naming its new path (none
for a route that went), logs a warning with the route, user agent and remote
address, and counts in `hopper_api_retired_requests_total{route}`. 410 is
final: a client does not retry it.

**Order.** Each route moves when it is ported to the store, so nothing is
ported twice. The clients change in their own repositories, one diff each,
and deploy at the switch (part 2, stage 8); the 410 log names any client
left behind.

The largest overlap left is `serve-replica` itself: a second read API with
a relay, `?fresh=1`, read-only branches and `/_/replica`, there to keep
heavy reads off a primary whose legacy tables made them heavy. Retiring it
is the open replica decision below.

### prism, promoter, gauntlet (readers of hopper's database)

They read the legacy tables through hopper's library (`hopper.Open`) and SQL
of their own; their writes already go through the API (rulings, sightings,
rescans, reports). Each read becomes a `store` function against the verdict
schema, and each service moves to the hopper version that has it
("Go clients of hopper's library" above). Inventory of 2026-11-13:

| Service | Legacy library reads | Its own SQL |
|---|---|---|
| promoter | `CandidatesByLabel`, `BadMembersByParent` | `pkg/promoter/promote.go`: samples, sightings, popular packages |
| gauntlet | `SightingsFor` | `hopper.go`, `adjudicate.go`, `prime.go`: samples, placements, sightings, label events |
| prism | `FeedSamples`, `FeedEcosystems`, `FeedDomains`, `SightingsFor`, `SamplesBySHAs`, `ParentArchivesForChild`, `LatestReport` | `feed_query.go`: samples, placements, `asset_claims`; `stats.go`: counts |

prism is the largest: its file page renders legacy's stored analysis, the
envelope reassembled with its members (`hopper.Reassemble`), where the store
keeps a report per file and member lists, so the page needs a data model as
well as queries. promoter and gauntlet go first.

### forager

Forager links `hopper.DB` and writes the database directly:

- samples and locations: `InsertSample`, `InsertSampleNew`,
  `InsertSampleBatch`, `UpsertLocationBatch`;
- sightings: `AddSightings`, `AddSightingsBackfill`, `SightingsFor`,
  `SightingSources`;
- acquisitions: `TryClaimSightingAcquisition`,
  `FinishSightingAcquisition`, `UnattemptedSightings`,
  `UnattemptedForProvider`, `OldestUnattemptedForProvider`,
  `MarkSightingsAttempted`, `AcquisitionProviders`;
- `PackageVersionPresent`, and `Migrate`.

The store is now the public `store` package (decision 1; it was
`internal/store`, which another module cannot import), and forager calls it
as it calls `hopper.DB` today: behaviour does not change, and forager's
batches stay bulk statements. The methods map to:

- the sample and location writes → `Store.Ingest`;
- the sighting writes → a new `Store.AddSightings`, which spells package
  subjects with `nameOf` and calls `Store.Cite` after its claims commit;
- the sighting reads → the ledger, unchanged;
- the acquisition methods → `sighting_acquisitions`, carried over as it is,
  with its "do we hold it" probes reading a sample with a location;
- `PackageVersionPresent` → `names` and `samples`;
- `Migrate` → nothing at run time: the migration tool owns the schema.

### postdoc and cyclotron

- **postdoc:** no change while the endpoints keep their shape. ClamAV's
  object already rides in version 8's `scanners`.
- **cyclotron:** drop the bad-shared and stranded policy entries and its use
  of `/api/stranded`; settle `/api/cleave-result`.

### Schema

`schema.sql` gains `sighting_acquisitions` and `hopper_kv` (the reconcile
stamps) as they are in production.

## 2. The migration

One tool, `hopper migrate`, runs every stage against a DSN. It is the same
code for the rehearsal and for production:

- **Resumable:** each stage records its last id range in `hopper_kv` and
  continues from there.
- **Idempotent:** rerunning a finished stage writes nothing.
- **Guarded:** it refuses a host named `hopper-db` without
  `--production`, as the tests already refuse it.

### Where each table comes from

| New | From | How |
|---|---|---|
| `names` | `samples.purl_base` | distinct `nameOf(purl_base)`; ref names arrive through the writer |
| `samples` | `samples` | ids kept; a legacy scan given up as timed out is stored as a `timeout` verdict, so the age sweep retries it rather than the queue at once; `decode(sha256)`; `purgatory` → `inconclusive`; `skip` is not a column: `conflict` and `marker` become `label_source`, `missing` means no location, `stuck` means requeued, `skip-benign-archive-item` is a member judged through its archive (the rehearsal checks each against its count); size NULL when unknown |
| `verdicts`, `contents`, `refs`, `claims`, `scans` | each top-level row's `cleave_result`, `litmus_result`, `llm_result` | `v7result.Convert`, then `Store.Write`: the path live version 7 uploads take, so the migration is not a second writer to get right. Ruleset from `traits_version`; time from `analyzed_at`. A legacy *excerpt* is not converted (below) |
| `locations` | the top-level rows of `sample_locations`, then `samples.path` | most top-level files keep their path only in `sample_locations` (70% in the rehearsal's selection have an empty `samples.path`). Its top-level rows are about 0.7% of 4.86 billion, with no index for them, so the stage reads the table once in id ranges; the newest sighting wins a contested path. The first reconcile walk learns any copy legacy missed and retires paths gone from disk |
| `queue` | — | files on disk with no atomscan verdict, at `QueueNew`, excerpts' files among them; the sweep queues the stale |
| `reports` | `reports` | `sample_id` by `decode(sha256)` |
| `sightings` | `sightings` | as is; package subjects re-spelled with `nameOf` (the rehearsal counts how many change) |
| `label_events`, `popular_packages`, `sighting_acquisitions`, `gauntlet_*` | the same tables | as is; `hopper_kv` is not carried: legacy's keys mark repairs of the legacy tables done |
| `samples.cited` | — | `Store.Recite` |
| `scans.flagged` | — | the writer sets it; files labelled bad are flagged after the load |

**Legacy excerpts.** From 2026-06-18 legacy hopper cut each member's line
out of an archive's report and stored it on the member's own row as its
`cleave_result` (`RefreshStaleMemberAnalysis` and the member batch insert):
fetched dependencies, registry sidecars, files inside archives. A slice
overwrote the result of an earlier scan of the file itself, and a file whose
row got one was never queued for its own scan. A scan's first line is the
scanned artifact; an excerpt's has a parent (`pid`), which is how the
migration knows one. In the rehearsal's selection 12,196 of 16,039 analyzed
top-level results are excerpts, 11,335 of them registry sidecars. Decided
2026-11-13: excerpts are dropped.

- An excerpt is not converted: no verdict, no scans row. Its file keeps its
  row, label and placements.
- An excerpt's file on disk is queued for a scan of its own.
- An excerpt's row that nothing accounts for (no label, name, URL,
  provenance, location, opinion, member list, report, label event, sighting
  by digest, or reference that fetched it) is dropped at stage 6. That is
  every registry sidecar.

A verdict that existed only as an excerpt is gone until the file's own scan
(7 hostile in the selection, all on disk and queued).

Not carried:

- `sample_location_history` (PLAN.md, "Labels and moves");
- the legacy `claims`, one row per file and source, superseded by the
  analyzer's identity block, which the converter reads from the reports;
- `workers`, `walk_staging`, `hopper_migrations`.

### Stages

1. **Preflight.** Measure free space against part 3's per-sample sizes.
   Check `temp_tablespaces = 'pgtemp'`, `maintenance_work_mem` and
   checkpoint spacing; with `full_page_writes = off` (ZFS) WAL compression
   does nothing. No replication slot may be holding WAL (production's was
   dropped 2026-11-13). Pause zrepl's snapshots of the database datasets.
2. **Tables.** Create `verdict` with its tables, keys, functions and the GIN
   index on `contents` (with a pending list for the load); the writer needs
   the keys for its conflict clauses and the GIN index to find what holds a
   file. The other secondary indexes come at stage 5. The foreign keys are
   dropped for the load and their definitions kept in `migrate_fkeys`.
3. **Copy.** `names`, then `samples` in id ranges on every worker (members
   too, ids kept), then moving the samples sequence past the largest legacy
   id: the writer creates the rows of members legacy never held.
4. **Convert.** Parallel workers take consecutive batches of the analyzed
   top-level rows in analysis-time order, oldest first, as live uploads
   arrive, excerpts left out, and convert and write. A freshly loaded verdict has no old class, so nothing
   rises, nothing is requeued for repair, nothing is orphaned, and the
   writer needs neither the GIN index nor `verdicts_flagged` yet. Locally a
   writer stores about 5,800 files a second (288,692 in 49.5 s). Production
   has about 57.6 million top-level samples and roughly 7.6 files each, so
   one writer would take about 21 hours; part 3 measures how far parallel
   writers cut that on this disk.
5. **Locations and the rest.** Top-level placements, then `samples.path`;
   the tables carried as they are, the reports, and the ledger respelled.
   Then the secondary indexes (parallel maintenance workers), and the GIN
   index told to skip its pending list.
6. **Derive.** Drop the excerpts' rows nothing accounts for; `Recite`; flag
   the scans of files labelled bad; fill the queue; set each identity
   sequence past its largest id (`names`, `samples`, `reports`,
   `label_events`); add the foreign keys back, each validated; rebuild the
   keys the load filled out of order; `VACUUM` samples; `ANALYZE`. Each step
   logs its time.
7. **Validate.**
   - Every legacy sample has a row with its id and digest, but for
     dropped excerpts, and no dropped excerpt had anything accounting for it.
   - The lookup parity tests (`store_parity_test.go`), run against
     `public` and `verdict` over a random sample.
   - Each triage queue's depth beside its legacy count.
   - A rerun of stage 4 over a sample writes nothing.
8. **Switch.** Start the new hopper on `verdict`. Its first pass is a
   reconcile walk, which learns any copy legacy did not record and retires
   paths gone from disk.
9. **Rollback window.** Until the legacy tables are dropped, stopping the new
   hopper and starting the old binary on `public` is the way back.
10. **Reclaim.** Drop the legacy tables, about 7.5 TB. A dropped table frees
    its files at once, though zrepl snapshots on `tank` hold the space until
    nazgul replicates past them.

### Runbook (galadriel, then minas-tirith)

On galadriel, from a commit, with the pre-migration snapshot taken:

1. Pause zrepl's snapshots of `tank/pgdata` (and `tank/pgwal` where it is
   separate).
2. Build and copy: `GOOS=linux GOARCH=amd64 go build -o out/hopper-linux ./cmd/hopper`.
3. Migrate, logging to a file:
   `hopper migrate --db 'postgres:///hopper?host=/var/run/postgresql' --workers 16 --maintenance-mem 8GB --maintenance-workers 8`.
   Sixteen workers on galadriel's 128 cores mirror what minas-tirith's 32
   can run, so the duration predicts production's outage; more workers
   would make the dress rehearsal faster and the prediction worse. The run
   is resumable: rerun the same command after an interruption.
4. `hopper migrate --verify` with the same `--db`: every check must be 0.
5. Lookup parity against the result: `TestRehearsalLookupParity` with
   `HOPPER_REHEARSAL_DSN` at galadriel's database and `HOPPER_PARITY_SAMPLE=0.1`
   (a tenth of a percent of legacy's pages, tens of thousands of files); it
   only reads. Then each triage queue's depth.
6. Record the sizes and each stage's time here; resume zrepl and take one
   snapshot.

On minas-tirith the same, after stopping hopper, with `--production`; then
start the new binary with `--store`.

### Replica

`galadriel` subscribes to the publication `hopper_replica`, which covers the
legacy tables. Its subscription is disabled. Production's slot
`hopper_replica_galadriel` was dropped on 2026-11-13: inactive, it had come
to hold 644 GB of WAL and would have held every byte the load writes.
galadriel's legacy subscription cannot resume; its tables are a snapshot as
of when it was disabled, which the dress rehearsal migrates.

The plan:

- migrate galadriel's own snapshot first, as a full-size dress rehearsal,
  then production;
- on both hosts, pause zrepl's snapshots of the database datasets for the
  run and take one afterwards: a snapshot taken mid-run pins the WAL,
  sort files and replaced indexes the load writes and frees (the dropped
  slot's 644 GB stayed on disk under `tank/pgwal`'s snapshots);
- create a publication of the verdict tables after stage 7;
- give galadriel a new subscription into its own `verdict` schema (an
  initial copy of about 1.5 TB);
- drop its old subscription with the legacy tables.

Nothing on galadriel changes before then.

## 3. Rehearsal: migrate a selection of the replica, locally

**Goal:** run part 2's tool, unchanged, on real data of every shape, and
measure it. A test gated by `HOPPER_REHEARSAL_DSN` (a local, disposable
database), `TestMigrationRehearsal`, drives it.

### The selection

`scripts/rehearsal-select.sh DSN MAX` reads a selection from galadriel once,
in read-only transactions over `ssh galadriel psql`, into the `replica`
schema of the local rehearsal database. It is never committed.

- **Results:** the first MAX analyzed top-level rows in sha256 order.
  sha256 is uniform, so the order is an unbiased sample, and each size holds
  every row of the smaller ones.
- **Topped up with the rare shapes:** the newest bad, corroborated and
  good-and-cited files, at every size.
- **What names them:** their top-level placements (one sequential pass over
  `sample_locations`, about half an hour), the sightings naming them by
  digest or package, their `label_events` and `reports`, and every
  `popular_packages` and acquisition row.

`scripts/rehearsal.sh N` then builds `public` from the first N of them and
runs the migration and the parity check, writing `out/rehearsal/N/`: the
logs and a summary of times and sizes. The sizes run 1,000, 5,000, 10,000,
25,000, 50,000, 100,000 and 250,000, each fixed before the next.

Galadriel's copy stopped when its subscription was disabled. For a
rehearsal that is fine.

### What the test checks

- **Identity:** every selected legacy sample has its row, id and digest in
  `verdict`.
- **Lookups:** legacy and store agree on every selected file and release
  (the parity tests, pointed at the rehearsal database).
- **Shape:** verdict, contents and refs counts match what the converter
  produced; `cited` matches the ledger; the queue is exactly the unscanned
  files on disk; each identity sequence is past its largest id.
- **The queues:** every triage queue runs.
- **Idempotence:** a second run of every stage writes nothing.
- **Measurement:** rows a second and bytes per sample for each stage and
  table, extrapolated to production in the rehearsal's report. That report
  replaces this plan's estimates.

### Findings (2026-11-13)

The selection: 82,777 legacy rows; 16,039 analyzed top-level results, of
which 12,196 are excerpts. Every check above passes.

- **Converted:** 3,843 results, 1,003,203 file lines, none refused, in about
  a minute with 8 workers. 11,486 excerpt rows dropped, 1,051 files queued.
- **Repeat conversion:** a one-worker second pass changes no verdict, and a
  third writes nothing. (Before excerpts were dropped, the second pass
  changed 0.08%.)
- **Size:** the verdict tables take 681 MB, about 42.5 KB per legacy
  analyzed result, members included. At 57.6 million results that is about
  2.4 TB, an upper bound: archives that share members share rows, and a
  1/4096 selection cannot show how often. Galadriel's full run measures it.
- **Lookup parity** (`TestRehearsalLookupParity`): every converted file's
  `/v1/lookup` record matches legacy's, or differs for a listed reason. The
  ones decided 2026-11-13:
  - A scan's time is the later of the row's analysis time and the ML
    result's (flat or under `ml`). They agree to a second at the median and
    32 s at p90, but 11 of 3,815 differ by over an hour (a rescan that reused
    an older ML result leaves the row's newer).
  - A slash in a qualifier value is `%2F`, as ECMA-427 5.4 requires
    (`?repository_url=https:%2F%2Fopen-vsx.org`); legacy left it bare.
  - A report older than version 6, whose traits the converter cannot read,
    keeps the findings legacy held in `top_traits`.
  - A trait about a fetched dependency is left to `refs`: the dependency
    raises its declarer once it is held hostile. Where its only verdict was
    the parent's excerpt, that waits for its own scan (1 hostile in 3,825).
- **Writer changes the rehearsal forced:** conversion in time order (a
  member's opinion records when it last changed, so the newest archive must
  come last); retention of unlisted members during the migration; a member's opinion
  changed only by a strictly newer scan; and a member list with its own
  time (`contents.listed_at`), replaced only by a newer list, not by a newer
  verdict of its archive; and a member's line that replaces a stored
  verdict only when it says as much (a reason and findings where the stored
  one has them) or is tighter (decided 2026-11-13, after a stealer's own
  L12 verdict with its interpretation was replaced by an archive's bare L25
  line; `TestWriteMemberLineKeepsRicherVerdict`).
- **Efficiency (decided 2026-11-13).** Members are 99% of the rows, so the
  cost per member decides the size: about 920 bytes at 25,000 results
  (verdicts 390 for two rows, samples 250, `verdict_details` 196, contents
  57 an edge). Changed:
  - The report moved onto atomscan's verdict row (`verdicts.detail`,
    `STORAGE EXTERNAL`). 96.5% of reports are under 64 bytes (a member's is
    its trait molecule, `{"mol":"K(Li)","risk":2}`), each paying a whole
    row and key in a table of its own; inline they cost their bytes, and a
    large one still moves to TOAST. One row change per member per scan
    fewer, for WAL and logical replication alike.
  - A member's floor or ml juror that is benign and fires at no level is not
    stored unless the member was scanned on its own (98.7% of ml rows said
    only that). A file scanned alone keeps it: the triage queues read its
    score. `TestWriteQuietMemberJurors`.
  - `fires_at` is a `smallint` column, read by the writer's comparisons, the
    raise and the queues without parsing jsonb; the upload check refuses a
    level it cannot hold. atomscan's `level` is stored only when it is not
    25.
  - The migration rebuilds the keys its load filled out of order
    (`verdicts_pkey` 66% full, `samples_sha256_key` 68%, `refs_pkey` 52%);
    rebuilt, the first two measured a quarter smaller.
  - The sightings key leads with `subject`, the only way the store reads
    the ledger, so legacy's second index on it is gone.
  - Kept after measuring: `verdicts_flagged`, which looked unused (no
    triage queue reads it any more) but serves Raise's member check: 0.33 ms
    for a 4,096-member archive with it, 0.98 ms without, at 2% of the key's
    size.
  - A newer scan that agrees with a stored reading refreshes it (its time,
    ruleset and engine) when the reading came from another ruleset or is
    more than 30 days old: scan's rule for trusting a stored dependency
    verdict (`corpus_precheck.rs`: the same analyzer, or benign within
    `DEFAULT_MAX_AGE_DAYS`). Before, an agreeing scan wrote nothing and left
    no trace, so an older scan's different reading arriving after it won.
    Version 8 sends identical member lines from any archive under one engine,
    so this took two engine versions: the migration's replay of months of
    them in parallel, or a rollout. Traced at 10,000: a member read alike on
    Sep 29 and Nov 7 kept Oct 18's reading from `3.0.0-beta.0`. The second
    pass's rewrites fell from 12 to 0 at 10,000, for 1.5% more verdict space
    and 15% more conversion time. `TestWriteAgreeingNewerScanRefreshes`.
  - Speed (2026-11-13), measured at 25,000 results: 1 m 46 s became about
    30 s.
    - The excerpt cleanup tested `refs` with one `OR`, a nested loop over
      every ref for every excerpt: 6 minutes at 50,000 results, growing with
      the square, and at full size it would not have finished. Split into
      two tests it is a hash anti-join (1.7 s). Each post step now logs its
      time.
    - The ranged stages (samples, locations, paths) run on the workers, as
      the conversion does; at full size they read 308M legacy samples and
      4.86B placements. The conversion's spans shrink so that every worker
      has work at any size.
    - The foreign keys are dropped for the load and added back, validated,
      at the end (`migrate_fkeys`): each insert had probed and locked the
      sample it names. Conversion at 8 workers: 40 s to 24 s.
    - A member's juror is listed as gone only when it has a row.
    - `--verify` lists the excerpts once instead of reading every legacy
      report three times.
  - A writer race the 16-worker rehearsal found (2026-11-13): a file's own
    scan and an archive's thinner line for it, stored at once, could lose the
    richer verdict, since held back, settled and reclaim were decided from a
    read made before another writer committed. Seen on a UPX payload
    (`bc2613fe…`) whose own scan said L12 with findings and an LLM reason,
    and whose packed executable's line said L25: the parallel pass kept L25.
    The writer now locks the sample rows of the files it will change, in
    digest order, and decides again (`writer.lock`); a file whose line is
    the stored opinion is not locked (`sameAs`), so files every archive
    reads alike do not serialize writers. A lost deadlock is retried.
    `TestWriteRaceKeepsRicherVerdict` reproduces both orders.
  - The rehearsal's second pass may move a member's time, engine and report
    (an agreeing newer scan within 30 days leaves no trace), bounded at 1%
    of rows; what a lookup serves (class, level, outcome, rows present) must
    not change at all. Decided 2026-11-13.
  - Not changed: the `contents_parents` GIN index, 42 bytes an edge, is no
    smaller rebuilt (almost every member sits in one archive) and serves four
    readers; WAL compression, which does nothing with
    `full_page_writes = off` (ZFS) as on galadriel; probabilities left
    unrounded, since after the drop few ml rows remain.

### Galadriel (2026-11-13 to 2026-11-14)

The full-size dress rehearsal, migrated with the build of 2731a34 and its
working tree as of 2026-11-13, 16 workers until the last 700,000 results,
then 32.

- **Interrupted twice, resumed both times.** At 08:24 the GPU fell off the bus
  (Xid 79) and the watchdog rebooted the host; at 14:27 it rebooted again on
  a false alarm, `nvidia-smi` failing after a driver upgrade had replaced the
  userspace tools under the loaded module. Crash recovery emptied that
  build's unlogged working tables, so each resume rebuilt the conversion
  order (4 h 10 m, one statement reading every legacy report). The working
  tables are logged now, and the order is built in parallel without reading
  the reports; conversion refuses to resume into an order that is gone.
- **Stage times:** names 10 m, samples 31 m, conversion about 11 h in all
  (11.8M results in 9 h 19 m at 16 workers, the last 1M in 2 h 17 m;
  the newest results convert slowest), locations 28 m, paths 19 m, carried
  1 m, post 1 h 47 m (the excerpt cleanup 28 m, the queue 22 m, the foreign
  keys 37 m, `verdicts_sample_id_fkey` 16 m of it).
- **Counts:** 12,851,387 results, 15 refused (each row's report describes
  another file); 46,157,256 excerpts not converted, 42,770,845 of their rows
  dropped; 268,932,653 samples (legacy's 311,130,883, less the dropped
  excerpts, plus 572,615 members legacy never held a row for); 981,578
  sightings (18 respelled), 291,015 reports, 5,966,206 label events, 57,010
  popular packages, all equal to legacy; every bad and good label carried
  (9,373,573 and 19,364,451); 1,144,595 files queued; 208,172 cited.
- **Conversion rate, measured on the newest results:** 138 results/s at 16
  workers, 171 at 32. At 32, 41% of the backends' time is spent waiting for
  another writer's row lock, so more workers buy little. Each result costs
  about 44 ms of the migration's CPU and 52 ms of PostgreSQL's.
- **Audit, a 0.1% sample of legacy rows (310,804):** no row is gone but
  excerpts, and no dropped excerpt had a label, name or path; labels equal
  legacy's (purgatory as inconclusive); every analyzed top-level file has
  atomscan's verdict and a scan. Legacy's `max_crit` is the worst trait
  anywhere in a scan and atomscan's class is the ML level of one file, so
  the two disagree by design; the trait reading is the floor juror's.
- **Lookup parity at 0.1% (12,863 records):** the listed differences, plus 19
  records whose `fires_at` legacy showed empty where the store serves -1 and
  14 with an engine version legacy did not show: in the one traced, the file
  was read again, by a newer engine, as a member of a later archive, and the
  store serves that newer reading.
- **Found and fixed for production:** version 7 reports written before
  cleave's v8 format (2026-06-16) spell the findings `find` and the identity
  `idn`, and the converter read neither: those files lost their floor juror,
  the findings their verdict cites, and their identity claims (the report
  itself was kept). About 240,000 results; in a sample of 592, 100 gain a
  floor (52 hostile, 48 suspicious) and 45 an identity, and none fails to
  convert. Galadriel's own copy keeps the gap. `TestConvertVersion7Find`.
  The same build also reads version 4 to 6 reports' file lists (`fs`),
  which galadriel's build did not: about 22% of results, whose members
  had no verdicts.
- **Reports the first full run left out (found 2026-11-16 by collimator's
  training read, fixed in the `reports` stage).** Two gaps, together about a
  third of the labeled samples collimator trained on before the migration
  (2.6M samples have a verdict and no report; many more members hold a stub):
  - Version 4 to 6 results converted their files, verdicts and placements but
    passed on no report, so a scanned file, and every member taking its line
    from the same result, had a verdict with no `detail`. Those reports are now
    passed on as written, minus placement (`id`, `dp`, `sz`, `sha`, `path`,
    `type`), in their short keys. Scanned between 2026-04 and 2026-06-09 for
    the most part. collimator's `features.py` reads the short keys.
  - The member backfill took an excerpt for a member's only when its first entry
    named a parent (`pid`). Legacy also cut member lines with a depth of 1 to 3,
    a path through the archive (`a.tgz!!b/c`) and no `pid`: 22% of the
    training rows of a frozen 2026-10-23 corpus, 32% of its ELF. They kept the
    molecule-only stub their archive's line left. `ExcerptReport` now also
    takes a first entry nested below the root (`depth`/`dp` above 0); a scan,
    at depth 0, is still not one. `Convert` is unchanged: only the backfill
    reads this wider test, and only for rows never scanned on their own.
  The `reports` stage covers both (`reportRange`), reading the legacy rows
  again; it only fills a `detail` that is missing or a molecule alone, so it is
  safe to re-run: delete `migrate:reports` and `migrate:reports:through` from
  `hopper_kv` and run the migration again against the legacy schema.
  `TestReportRange`, `TestLegacyReports*`, `TestExcerptReportWithoutPid`.
  - **Optional, `--excerpt-verdicts`:** files that only a legacy excerpt
    judged have no verdict at all (about 10% of the legacy ELF training rows,
    11% of a 20,000-row sample of the frozen corpus), so nothing is there to
    fill. The plan decided on 2026-11-13 to leave them to a scan of their own;
    this stage keeps the one analysis there is until that scan. It stores
    atomscan's verdict and report for each (`Store.FillVerdicts`): judged on the
    excerpt's findings alone, as `Convert` judges a member the model did not
    cover (the trait floor's class; `fires_at` unset), formed at the excerpt's
    own analysis time under the ruleset it names, with no scans row. It never
    replaces a verdict, and a scan of the file replaces it. Off by default; run
    it with `migrate --excerpt-verdicts` (kv keys `migrate:excerptverdicts` and
    `:through`). `ExcerptFile`, `TestFillVerdicts`, `TestReportRange`.
- **`--verify` at full size:** two checks would not have finished. The
  excerpt test was `IN (SELECT id FROM verify_excerpts)`: 46 million ids do
  not hash in `work_mem`, so the list was searched again for each of 311
  million legacy rows; it is `EXISTS` now, an anti-join. The check that no
  dropped excerpt was accounted for OR'd its accounts, each a subplan run
  per excerpt, and galadriel's `sample_locations` has no index on `sha256`;
  each account is its own semi-join now, one scan of the placements.

## 4. Pipeline: forager → hopper → postdoc → cyclotron on the migrated data

**Goal:** the whole pipeline running locally on the rehearsal's migrated
database, with no legacy table left to fall back on. A script
(`scripts/pipeline-rehearsal.sh`) and a test gated by the same variable run
it.

Topology, all local:

- PostgreSQL holding only `verdict`: the legacy tables are dropped from the
  rehearsal copy after migration, so any call left on them fails the run;
- hopper built from this tree, on a local data root;
- forager, postdoc (with atomscan, and ClamAV if `clamd` is present) and
  cyclotron, each pointed at that hopper.

Steps and checks:

1. **Forager acquires** a handful of small packages the migrated ledger
   names. They land through `Store.Ingest`; their claims through
   `AddSightings`, marked cited; queued at `QueueSighted`.
2. **The walker** ingests what forager wrote, and the reconcile walk learns
   it.
3. **postdoc** takes work from `/api/next`, sighted first. It fetches
   `/api/file` and `/api/provenance`, uploads a version 8 result (with
   `scanners.clamav` when ClamAV ran), and hopper stores it.
4. **A migrated file rescanned** under a new ruleset writes only its scan
   when nothing changed, and replaces the converted verdict when something
   did. This needs bytes for a few migrated files (a decision below).
5. **`/v1/lookup`** answers for a new file, a migrated file and a release,
   with the raise and the attribution.
6. **cyclotron** previews the queues (`preview-queues`), works a few files
   (`--max-samples`) and files reports. A ruling moves a file: the move,
   `label_events`, the flagged scan and the sibling rescan are all checked.
7. **Nothing touched a legacy table:** none exists, and hopper's log shows
   no fallback.

Cyclotron's providers are the `claude` and `codex` CLIs, so step 6 makes a
few real model calls (a decision below).

## 5. Order of work

1. Add `sighting_acquisitions` and `hopper_kv` to `schema.sql`, and settle
   how forager reaches the store. Then build `hopper migrate` and the
   selection export, and run part 3 until it passes and has measured.
2. In parallel, part 1's ports, driven by part 4's "no legacy tables" check.
3. The forager port.
4. Part 4.
5. The full migration of galadriel into `verdict` (decision 5): part 2's
   tool at production size, validated as in stage 7, measured.
6. Production, once production is reachable again and the disk is added,
   or galadriel's promotion:
   - refresh the measurements (sizes, growth, WAL, the slot, query plans
     on the new tables);
   - run part 2 with part 3's numbers;
   - keep the rollback window;
   - reclaim.

## Decisions

Settled by Thomas, 2026-11-12:

1. **forager** uses the store as the public `store` package (moved from
   `internal/store`).
2. **Bytes for the pipeline test:** a small set of migrated files (under
   2 GB) is copied read-only from smaug, so postdoc rescans migrated files.
3. **The inactive slot `hopper_replica_galadriel`** is dropped at preflight;
   galadriel gets a new subscription to the verdict tables after
   validation.
4. **Model calls in the pipeline test:** a few real `claude` calls
   (cyclotron with `--max-samples`).
5. **Order:** the integration tests (parts 3 and 4) all run locally until
   they satisfy; then the replica, galadriel, is migrated in full into its
   own `verdict` schema as the production-size rehearsal (128 cores, 251 GB,
   3.25 TB free; the legacy tables untouched). Its numbers decide between
   promoting galadriel to primary for the new schema and migrating the
   master.

Open:

6. **`serve-replica`:** rebuilt on the new subscription, or retired.
7. **Dashboard, maintenance and diagnostics:** which to port and which to
   remove; a list follows part 1's first pass.
