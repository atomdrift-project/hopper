<p align="center">
  <img src="media/logo.svg" alt="hopper" width="240">
</p>

# hopper

Job broker and sample store for the [atomdrift](https://github.com/atomdrift-project) malware analysis pipeline. Hopper catalogs samples, distributes analysis work to [litmus](https://github.com/atomdrift-project/litmus) workers, and publishes labeled results to [collimator](https://github.com/atomdrift-project/collimator) for ML training.

```
  samples ──► hopper ◄──► litmus workers (pull jobs, return verdicts)
                 │
                 └──► collimator (ML training)
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

PostgreSQL 18 is recommended; PostgreSQL 17+ is required for `JSON_TABLE`, which collimator uses to dedupe embedded hashes. On the DB host:

```bash
sudo -u postgres psql -c "CREATE ROLE hopper LOGIN PASSWORD 'changeme'; \
  CREATE DATABASE hopper OWNER hopper; ALTER ROLE hopper WITH REPLICATION;"
echo 'localhost:5432:hopper:hopper:changeme' >> ~/.pgpass && chmod 600 ~/.pgpass
hopper init                                       # applies migrations
hopper load --data /srv/samples --dashboard-addr 0.0.0.0:8081   # HTTP API + dashboard
```

Run the `hopper load` process under rc.d, systemd, or s6 — it stays up serving the worker API and dashboard. `scripts/master/freebsd-bastille.sh` is a working FreeBSD/bastille rollout with tuned postgres, hourly `pg_dump` backups, and a `hopper_replica` logical-replication publication for replica subscribers. Imports use `COPY`-based bulk loads and resume with `--after <id>`.

## Commands & building

`serve`, `init`, `load`, `import`, `reset`, `stats`, `backfill`, `purge-unsupported`, `false-positives`, `false-negatives`, `bad-review`, `benign-review`. Run `hopper` for the full list. Build with Go 1.25+ and CGO: `make build && make test && make lint`.
