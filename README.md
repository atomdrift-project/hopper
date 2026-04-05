# hopper

Sample registry for the [atomdrift](https://codeberg.org/atomdrift) malware analysis pipeline. Catalogs binaries, runs static analysis via [cleave](https://codeberg.org/atomdrift/cleave), and stores results for [cyclotron](https://github.com/atomdrift/cyclotron) (LLM-powered RE) and [collimator](https://codeberg.org/atomdrift/collimator) (ML training).

```
samples on disk ──→ hopper load ──→ hopper DB ←── cyclotron (RE + traits)
                        │                │
                     cleave              └──→ collimator (ML training)
                   (auto-managed)
```

## Quick start

```bash
# SQLite for small runs:
hopper init --db samples.db
hopper load --db samples.db --bad ./malware --good ./benign

# Local postgres for larger work:
hopper serve                          # starts postgres on :5433
hopper load --bad ./malware --good ./benign   # uses DATABASE_URL
```

Hopper auto-starts a cleave server, manages its memory, restarts it on crash, and parallelizes analysis. Pass `--rescan` to re-analyze samples that already have results.

## Production PostgreSQL

`hopper serve` runs a local single-user instance under `~/.hopper/pgdata`. For production, create a database on an existing PostgreSQL 17+ server:

```bash
sudo -u postgres createuser --no-superuser --no-createdb --no-createrole hopper
sudo -u postgres createdb --owner=hopper hopper
sudo -u postgres psql -c "ALTER USER hopper WITH PASSWORD 'changeme';"
```

Set up `~/.pgpass` so credentials stay out of your environment and shell history:

```bash
# ~/.pgpass — chmod 600
localhost:5432:hopper:hopper:changeme
```

The default `DATABASE_URL` is `postgres://hopper@localhost:5432/hopper`, so for a local database no environment variable is needed:

```bash
hopper load --bad ./malware --good ./benign        # load samples
hopper import-legacy --from /path/to/cyclotron.db  # legacy cyclotron DB
hopper import --from ./local.db                    # transfer between hopper DBs
```

All commands apply schema migrations automatically before writing.

Override with `DATABASE_URL` or `--db` to point at a remote host.

All import commands run migrations automatically and log progress with row IDs. If interrupted, pass `--after <id>` to resume. Imports use `COPY`-based bulk inserts with staging tables, so throughput is bounded by disk I/O rather than round-trips.

PostgreSQL 17+ is required for `JSON_TABLE` support, which enables SQL-side queries against embedded file hashes in cleave results (used by collimator for train/test split dedup).

## As a Go library

```go
db, _ := hopper.Open(ctx, "postgres://localhost:5433/hopper")
defer db.Close()

db.InsertSample(ctx, &hopper.Sample{SHA256: sha, Label: "bad", StoragePath: path})
db.UpdateCleaveResult(ctx, sha, cleaveJSON, "hostile", 5)

samples, _ := db.SamplesByStatus(ctx, "bad-review", 100)
```

PostgreSQL or SQLite — detected automatically from the DSN.

## Building

Requires Go 1.25+ with CGO enabled (for SQLite). PostgreSQL 17+.

```bash
make build    # produces ./hopper
make test
make lint
```
