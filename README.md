# hopper

hopper is the sample registry, job queue, and result store for the Atomdrift
malware-analysis pipeline. It catalogs files and provenance, serves bytes to
authorized workers, accepts Atomdrift Scan results, and exposes the labeled
data used to train Azoth.

This is infrastructure for running a scan fleet or research corpus. To scan a
file on one machine, install
[Atomdrift Scan](https://github.com/atomdrift-project/scan) instead.

```text
collectors ──► hopper ──► atomscan workers
                 │              │
                 └◄── results ──┘
                 │
                 └──► collimator / cyclotron / prism
```

## What it provides

- PostgreSQL and SQLite storage for samples, labels, provenance, and reports
- Pull-based jobs for horizontally scaled `atomscan worker` processes
- A file and result API with worker liveness and retry handling
- Local filesystem ingestion from `bad/`, `good/`, `pending/`, `review/`, and hot `incoming/` pools
- A dashboard for queue depth, workers, and analysis rates
- Review, rescan, reconciliation, import, and backfill commands

## Requirements

- Go 1.25.4 or newer and CGO to build hopper
- `cleave` to enumerate recognized files during ingestion
- `atomscan` for the default local analysis worker
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
├── incoming/
├── pending/
└── review/
```

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
(`--dashboard-addr`, loopback by default). They are separate so each carries one
access policy: the API requires a bearer token, the dashboard has none and is
not meant to leave the host. `--local` binds both to loopback.

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
  --dashboard-addr 127.0.0.1:8082
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

On FreeBSD, `make deploy` installs Hopper and the Scan worker as separate
`rc.d` services. Hopper runs the ingestion/API process with its local worker
disabled; `scan-worker` pulls jobs from Hopper and can read the same sample tree
directly.

```bash
make deploy \
  DATA_DIR=/data/samples \
  DB='postgres://hopper@hopper-db/hopper?sslmode=disable' \
  SCAN_DIR=../scan \
  FREEBSD_WORKERS=96 \
  FREEBSD_MAX_MEMORY_GB=0
```

`FREEBSD_MAX_MEMORY_GB=0` leaves Scan's RSS admission threshold automatic.

The deploy also builds and installs `cleave`, runs Hopper migrations, refreshes
the tool rules, and configures `hopper` to listen on port 8081. The worker is
supervised independently, so a worker crash or memory failure does not stop the
Hopper API. The `scan` account must be able to read `DATA_DIR`; the installer
adds both service accounts to the `samples` group by default.

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

## Useful commands

```bash
./hopper stats --db "$DATABASE_URL"
./hopper false-positives --db "$DATABASE_URL"
./hopper false-negatives --db "$DATABASE_URL"
./hopper rescan --db "$DATABASE_URL" <sha256>
./hopper import --from old.db --db "$DATABASE_URL"

# Audit hot samples queries for seq-scan regressions (needs production-like stats):
HOPPER_PLAN_DSN="$DATABASE_URL" go test ./... -run TestPlanAudit -count=1
```

The bare `./hopper` command prints the maintained command list, including
triage, cleanup, backfill, and corpus-reconciliation operations.
