# hopper <img src="media/logo-small.png" align="right" alt="hopper logo">

Distributed malware analysis engine for the [atomdrift](https://codeberg.org/atomdrift) pipeline. Hopper catalogs samples, hands work out to a small army of [litmus](https://codeberg.org/atomdrift/litmus) workers, and keeps the database honest so downstream tools ([cyclotron](https://github.com/atomdrift/cyclotron), [collimator](https://codeberg.org/atomdrift/collimator)) have something solid to chew on.

```
  samples ──► hopper ◄──► litmus workers (pull jobs, return verdicts)
                 │
                 └──► cyclotron (RE) · collimator (ML training)
```

Workers poll `/api/next`, fetch bytes from `/api/file/{sha256}`, and POST results to `/api/result`. Hopper tracks liveness, retries stuck jobs, and serves a dashboard so you can watch the swarm. Point as many `litmus` workers as you like at the hopper URL — they'll pull until the queue drains.

## Quick start

```bash
hopper init --db samples.db                       # SQLite, for a laptop
hopper load --db samples.db --data ./samples      # expects bad/ good/ unknown/

hopper serve                                      # embedded postgres on :5433
hopper load --data ./samples                      # uses DATABASE_URL
```

## Production deployment

PostgreSQL 17+ is required (for `JSON_TABLE`, which collimator uses to dedupe embedded hashes). On the DB host:

```bash
sudo -u postgres psql -c "CREATE ROLE hopper LOGIN PASSWORD 'changeme'; \
  CREATE DATABASE hopper OWNER hopper; ALTER ROLE hopper WITH REPLICATION;"
echo 'localhost:5432:hopper:hopper:changeme' >> ~/.pgpass && chmod 600 ~/.pgpass
hopper init                                       # applies migrations
hopper load --data /srv/samples --dashboard-addr 0.0.0.0:8081   # HTTP API + dashboard
```

Run the `hopper load` process under rc.d, systemd, or s6 — it stays up serving the worker API and dashboard. `hacks/rollout-bastille.sh` is a working FreeBSD/bastille rollout with tuned postgres, hourly `pg_dump` backups, and a `hopper_training` logical-replication publication for collimator subscribers. Imports use `COPY`-based bulk loads and resume with `--after <id>`.

## Commands & building

`serve`, `init`, `load`, `import`, `reset`, `stats`, `backfill`, `purge-unsupported`, `false-positives`, `false-negatives`, `bad-review`, `benign-review`. Run `hopper` for the full list. Build with Go 1.25+ and CGO: `make build && make test && make lint`.
