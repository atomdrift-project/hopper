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
- Local filesystem ingestion from `bad/`, `good/`, and `unknown/` pools
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
└── unknown/
```

Then initialize SQLite and ingest it:

```bash
./hopper init --db samples.db
./hopper load \
  --db samples.db \
  --data ./samples \
  --local \
  --workers 1
```

`load` remains running: it watches the corpus, runs the local worker, and serves
the dashboard/API. `--local` binds the dashboard to loopback; use it for a
workstation unless remote access is explicitly required.

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
  --dashboard-addr 127.0.0.1:8081
```

Run `./hopper <command> -h` for command-specific flags. Review the deployment
scripts before using them: they encode Atomdrift's own topology, database
roles, replication, and service assumptions.

Protect the worker/file API, database, dashboard, and bearer tokens as
sensitive infrastructure. Hopper can serve malware bytes and store authoritative
labels; it should not be exposed directly to the public internet.

## Useful commands

```bash
./hopper stats --db "$DATABASE_URL"
./hopper false-positives --db "$DATABASE_URL"
./hopper false-negatives --db "$DATABASE_URL"
./hopper rescan --db "$DATABASE_URL" <sha256>
./hopper import --from old.db --db "$DATABASE_URL"
```

The bare `./hopper` command prints the maintained command list, including
triage, cleanup, backfill, and corpus-reconciliation operations.
