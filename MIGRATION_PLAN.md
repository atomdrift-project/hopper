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
  | `/v1/files/{sha256}/provenance` | postdoc, cyclotron | port: `samples.provenance` |
  | `/v1/lookup` | postdoc, poppy, scan | done (`lookupstore.go`): the record (`BySHA256`/`ByRelease`), the ledger's word on it (`hopper.Corroborate`), raised by what it points at or holds that atomscan holds hostile or the ledger convicts at a hostile rung (`Raise`, `hopper.Convicts`), listed in `raised_by` with `why` |
  | `/v1/intake/upload` (from postdoc's `/v1/analyze`) | postdoc, scan, forager | done: `Store.Ingest` with source `upload` at `QueueUpload`, the sidecar with it; a held digest is found in the store (`heldInStore`). `/v1/analyze` itself is postdoc's route, behind beamline; hopper's part of it is this upload, `/v1/intake/held` and the renewal through `/v1/work/result` |
  | `/v1/intake/held` | scan, forager | port: a sample with a location |
  | `/v1/sightings` | cyclotron, gauntlet, promoter | done: writes through `hopper.PrepareSightings` (the legacy rules, shared) and `Store.AddSightings`, which marks the files named (`Cite`); reads from the store's ledger |
  | `/v1/sightings/ancestry` | cyclotron | port: the joins to `samples` change |
  | `/api/cleave-result` | cyclotron | becomes a version 8 result through `/v1/work/result`, once a juror a body does not name is no statement |

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

/v1/sightings                     GET by subject, POST to append
/v1/sightings/ancestry            GET   sightings on a file or any archive holding it

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
| `POST /api/release`, `GET /api/triage/queues`, `GET`/`POST /api/gauntlet/runs`, `GET /_/corroboration` | go: no caller | — |
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
| `label_events`, `popular_packages`, `sighting_acquisitions`, `hopper_kv`, `gauntlet_*` | the same tables | as is |
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
   Check `temp_tablespaces = 'pgtemp'`, `wal_compression = zstd`,
   `maintenance_work_mem` and checkpoint spacing. Settle the inactive
   replication slot (below).
2. **Tables.** Create `verdict` with its tables, keys, functions and the GIN
   index on `contents` (with a pending list for the load); the writer needs
   the keys for its conflict clauses and the GIN index to find what holds a
   file. The other secondary indexes come at stage 5. The foreign keys left
   (PLAN.md: the hot-path ones are gone) are checked as rows load; the
   rehearsal measures whether that is worth deferring.
3. **Copy.** `names`, then `samples` in id ranges (members too, ids kept),
   then moving the samples sequence past the largest legacy id: the writer
   creates the rows of members legacy never held.
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
6. **Derive.** Drop the excerpts' rows nothing accounts for, then
   `VACUUM` samples; `Recite`; flag the scans of files labelled bad; fill the
   queue; set each identity sequence past its largest id (`names`,
   `samples`, `reports`, `label_events`); `ANALYZE`.
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

### Replica

`galadriel` subscribes to the publication `hopper_replica`, which covers the
legacy tables. Its subscription is disabled, and production's slot
`hopper_replica_galadriel` is inactive and holding WAL (461 MB behind when
last measured). It would hold every byte the load writes.

The plan:

- drop or advance that slot before stage 3 (a decision below);
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
  come last); `Store.KeepOrphans` during the migration; a member's opinion
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
  - Not changed: the `contents_parents` GIN index, 42 bytes an edge, is no
    smaller rebuilt (almost every member sits in one archive) and serves four
    readers; WAL compression, which does nothing with
    `full_page_writes = off` (ZFS) as on galadriel; probabilities left
    unrounded, since after the drop few ml rows remain.

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
