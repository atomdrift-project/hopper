# hopper

hopper is the sample registry, job queue, and result store for the Atomdrift
malware-analysis pipeline. It catalogs files and provenance, serves bytes to
authorized workers, accepts Atomdrift Scan results, and exposes the labeled
data used to train Azoth.

This is infrastructure for running a scan fleet or research corpus. To scan a
file on one machine, install
[Atomdrift Scan](https://github.com/atomdrift-project/scan) instead.

```text
collectors ──► hopper ──► postdoc workers
                 │              │
                 └◄── results ──┘
                 │
                 └──► collimator / cyclotron / prism
```

## What it provides

- PostgreSQL and SQLite storage for samples, labels, provenance, and reports
- Pull-based jobs for horizontally scaled `postdoc worker` processes
- A file and result API with worker liveness and retry handling
- Local filesystem ingestion from `bad/`, `good/`, `sighted/`, `inconclusive/`, `dual-use/`, `pending/`, `review/`, and hot `incoming/` pools (legacy `purgatory/` remains readable)
- A dashboard for queue depth, workers, and analysis rates
- Review, rescan, reconciliation, import, and backfill commands

## Requirements

- Go 1.25.4 or newer and CGO to build hopper
- `cleave` to enumerate recognized files during ingestion
- `postdoc` for the default local analysis worker
- PostgreSQL 17 or newer for production; several corpus operations use
  `JSON_TABLE`

SQLite is useful for development and small datasets. Production deployments
should use PostgreSQL and normal database authentication, backup, and network
controls.

## Build and test

```bash
make build
make test
./hopper
```

## Local quick start

Create a small labeled pool:

```text
samples/
├── bad/
├── good/
├── dual-use/
├── inconclusive/
├── incoming/
├── pending/
├── review/
└── sighted/
```

`bad/`, `good/`, `sighted/`, `inconclusive/`, and `dual-use/` carry classification labels;
`pending/`, `review/` and `incoming/` are workflow roots holding label
`unknown`. `inconclusive/` holds samples carefully reviewed without enough
evidence for a confident benign or malicious verdict. `dual-use/` holds reviewed
tooling with legitimate and malicious applications that make a binary training
label inappropriate. Capability alone does not make every general-purpose tool
dual-use, and does not override evidence that a particular artifact is malicious.
Both reviewed labels are excluded from binary training and routine triage,
including queues that otherwise compare detectors regardless of label.
They have equal precedence above `bad`, so re-ingestion and pool reconciliation
cannot undo a reviewed ruling or switch between them. An explicit ruling can.

`purgatory` remains an input alias for `inconclusive`; new rulings write only the
canonical label and pool. Ingestion still discovers legacy `purgatory/` as
`inconclusive` until its catalogued locations have been migrated.

`incoming/`, `pending/`, and `review/` are physical workflow roots. Samples in
all three retain the catalog label `unknown`, and moves between them preserve
the complete suffix below the root. New API uploads land in `incoming/`.

Then initialize SQLite and ingest it:

```bash
./hopper init --db samples.db
./hopper load \
  --db samples.db \
  --data ./samples \
  --local \
  --workers 1
```

`load` remains running: it watches the corpus, runs the local worker, and
serves two listeners — the work API (`--api-addr`) and the HTML dashboard
(`--dashboard-addr`, every interface by default). They are separate so each
carries one access policy: the API requires a bearer token, the dashboard has
none — it is read-only, so keep it on a trusted network and never route the
tunnel to it. `--local`, or `--dashboard-addr 127.0.0.1:8082`, binds it back to
loopback for an SSH forward.

To run a disposable local PostgreSQL instance instead, install PostgreSQL's
`initdb`, `postgres`, `createdb`, and `pg_isready` tools, then run:

```bash
./hopper serve --dir ~/.hopper --port 5433
./hopper init --db postgres://localhost:5433/hopper
```

`hopper serve` uses trust authentication and is intended only for local
development. Do not expose that database to a network.

## Production outline

```bash
./hopper init --db "$DATABASE_URL"
./hopper load \
  --db "$DATABASE_URL" \
  --data /srv/samples \
  --api-addr 0.0.0.0:8081 \
  --token-file ~/.tok/hopper \
  --dashboard-addr 0.0.0.0:8082
```

`--token-file` requires `Authorization: Bearer <token>` on every API route
except the liveness, readiness, and metrics probes — loopback callers included,
because a Cloudflare tunnel terminates on loopback and a loopback exemption
would be an internet exemption. Clients (scan's workers and uploader, hopper's
own `triage` and `post-triage`) read the same token from `~/.tok/hopper`. The
deploy scripts generate one on first run and install it for the service user;
rotation is an edit plus a restart, since it is read once at startup.

Run `./hopper <command> -h` for command-specific flags. Review the deployment
scripts before using them: they encode Atomdrift's own topology, database
roles, replication, and service assumptions.

Protect the worker/file API, database, and dashboard as sensitive
infrastructure. Hopper can accept and serve malware bytes and store
authoritative labels. Only the API listener is designed to be published — and
only with `--token-file` set. The dashboard has no authentication of its own,
so it must stay on loopback and be reached over an SSH forward; never give it a
tunnel hostname.

## Native FreeBSD deployment

On FreeBSD, `make deploy` installs Hopper and the postdoc worker as separate
`rc.d` services. Hopper runs the ingestion/API process with its local worker
disabled; `postdoc_worker` pulls jobs from Hopper.

```bash
make deploy \
  DATA_DIR=/data/samples \
  DB='postgres://hopper@hopper-db/hopper?sslmode=disable' \
  POSTDOC_DIR=../postdoc
```

The deploy also builds and installs `cleave` and postdoc, runs Hopper migrations,
and configures `hopper` to listen on port 8081. The worker is supervised
independently, so a worker crash or memory failure does not stop the Hopper API.

## Operations

- [Production readiness packet](docs/production-readiness.md) — architecture,
  dependencies, failure modes, resource limits, and the open risk register
- [Alert runbook](docs/runbook.md) — one procedure per alert rule
- [SLI/SLO proposal](docs/slo.md) — proposed objectives (targets not yet adopted)
- [Replica runbook](scripts/replica/RUNBOOK.md) · [monitoring setup](scripts/monitoring/RUNBOOK.md)

Metrics are exported for Prometheus at `GET /_/metrik` on the **API** address
(`--api-addr`, default `0.0.0.0:8081`), not the dashboard one. Like the
liveness and readiness probes it is exempt from the bearer token so a scraper
needs no credential — keep the scrape path reachable only from your monitoring
network, and scope the tunnel's ingress to the routes you mean to publish.
Alert rules live in `scripts/prometheus-hopper-alerts.yml` and a Grafana
dashboard in `scripts/grafana-hopper-dashboard.json`.

Lookup cache metrics carry `cache="sample"` or `cache="record"`:
`hopper_cache_entries`, `hopper_cache_capacity`,
`hopper_cache_requests_total{source="cache"|"database"}`,
`hopper_cache_memory_estimated_bytes`, and
`hopper_cache_memory_sampled_at_seconds`.
The five-minute fraction served without a database load (including coalesced
misses) is:

```promql
sum by (instance, cache) (rate(hopper_cache_requests_total{source="cache"}[5m]))
/
sum by (instance, cache) (rate(hopper_cache_requests_total[5m]))
```

Memory is sampled asynchronously at most once a minute; scrapes use the last
successful sample. `time() - hopper_cache_memory_sampled_at_seconds` exposes
stale estimates. Estimated bytes include referenced payloads and Fido entry,
FIFO, and bloom storage, including expired and pending-eviction entries. They
exclude allocator rounding, xsync map/lock internals and in-flight requests;
shared storage may be counted more than once. Use heap profiles for independent
measurement. Existing `hopper_lookup_*` sample-cache metrics remain available.

### Dataset registry metadata

Curated corpora that do not pass through forager can still carry registry
provenance. When a tree under a `datasets/` directory is laid out as
`samples/<registry>/<name>/<version>/`, the walk treats `meta.json.zst`,
`metadata.json` (an npm packument or a single-version manifest) and
`maintainers.json` in that directory as provenance for the artifact beside
them, not as samples: enumeration skips them, and the artifact's row gets a
synthesized sidecar whose registry record holds the document (a packument is
trimmed to the one release) and whose feed record names the dataset. The
document's package name, version, PURL and tarball URL replace the walk's
filename guesses. Only npm documents are understood today.

Rows a walk wrote before this existed are repaired with
`hopper backfill-dataset-metadata --data <root> [--path-prefix bad/datasets/]`:
it pairs each provenance-less artifact with the document beside it and, with
`--apply`, stores the sidecar and adopts its identity. `--purge` also runs the
`dataset_metadata` cleanup stage, deleting the documents (and their exploded
members) that were ingested as samples. Dry-run by default.

## Useful commands

```bash
./hopper stats --db "$DATABASE_URL"
./hopper false-positives --db "$DATABASE_URL"
./hopper false-negatives --db "$DATABASE_URL"
./hopper rescan --db "$DATABASE_URL" <sha256>
./hopper import --from old.db --db "$DATABASE_URL"

# Relabel by SHA-256. The master moves the bytes into the corrected pool
# bucket and flips the label in one operation; nothing is uploaded.
./hopper mv -url "$HOPPER_URL" -target=bad <sha256> <sha256>
./hopper mv -url "$HOPPER_URL" -target=good -dry-run < shas.txt

# Record a careful but inconclusive review, outside binary training.
./hopper mv -url "$HOPPER_URL" -target=inconclusive < shas.txt
# Separately classify reviewed dual-use tooling.
./hopper mv -url "$HOPPER_URL" -target=dual-use < dual-use-shas.txt

# Audit hot samples queries for seq-scan regressions (needs production-like stats):
HOPPER_PLAN_DSN="$DATABASE_URL" go test ./... -run TestPlanAudit -count=1
```

The bare `./hopper` command prints the maintained command list, including
triage, cleanup, backfill, and corpus-reconciliation operations.

To migrate the old pool, deploy the new binary first, then pause corpus ingestion
and other movers on the full corpus host. Run the preview and apply against the
database paired with that host's complete data root:

```bash
./hopper migrate-purgatory --db "$DATABASE_URL" --data /data/samples --dry-run
./hopper migrate-purgatory --db "$DATABASE_URL" --data /data/samples --apply
```

The migration moves every catalogued standalone `purgatory/` observation to
`inconclusive/`, preserving its suffix and provenance sidecar. It repairs contained
member paths, then renames remaining `purgatory` labels, including archive members
and samples stored outside the old pool. Attribution, skip state, and historical
audit records are preserved; the rename adds an audit event. Each file move and
catalog update is resumable: re-run after an interruption. Missing bytes,
destination collisions, or samples with a newer classification are reported as
failures and left for repair; label renaming waits until location moves succeed.
Inspect the migration logs for affected paths. Index any uncatalogued artifacts
with the new binary before migrating. Once migration completes, resume ingestion
and other movers. Run separately for independent corpus hosts/catalogs; database
replication does not move files on a replica's filesystem.

Existing samples default to `inconclusive`. Move confirmed dual-use samples into
`dual-use` with an explicit ruling after reviewing their rationale; the migration
does not infer which ones belong there.

Collimator performance iterations use the replica-only `idx_samples_training_hash`
covering index defined in `scripts/replica/training-index.sql`. `hopper init -replica`
builds it concurrently; ordinary primary migrations never create it.
The replica keep policy retains it. It covers a rehashed canonical group key, row ID,
labels, scores and file types used by sampled training, allowing the planner to
avoid repeated full-table metadata scans. The one-time index build is separate
from a fresh training benchmark; replication continues during the build.
The companion `training-statistics.sql` migration adds table-level expression
statistics, followed by a one-time `ANALYZE public.samples`. Without those
statistics PostgreSQL can overestimate the sampled fraction and choose the old
route index even though the covering index exists.
