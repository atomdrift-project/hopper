# Replica lag monitoring — self-hosted Grafana

Ships Postgres **replication** metrics (the gap the app's OTel pipeline doesn't
cover) to the self-hosted Grafana fleet and pages when a replica falls behind, a
slot is invalidated, or a replica goes away. Alerts evaluate **in Grafana**, so
a dead replica still pages — the failure mode of the 2026-06-27 galadriel
outage.

## Topology

```
 publisher hopper-db (illumos)        uruk-hai (FreeBSD, 10.9.8.5)
   postgres :5432  ◄───── tailnet ───  Alloy: prometheus.exporter.postgres
   pg_replication_slots                 (hopper_exporter, pg_monitor)
   (sees every replica's lag)                    │ OTLP/HTTP
                                                 ▼
                                          otel (self-hosted Grafana/Mimir)
                                          + replication-alerts.yml
```

One Alloy, one connection to the publisher: `pg_replication_slots` on the
publisher shows galadriel, `.62`, and any tablesync at once. uruk-hai is a
non-replica box (a monitor shouldn't share a failure domain with what it
watches), and FreeBSD/amd64 is an official Alloy build target. App/runtime
metrics already reach the fleet via each Go service's OTel exporter — not
Alloy's job.

Files in this dir: `config.alloy`, `queries.yaml`, `exporter-role.sql`,
`hopper_alloy` (rc.d script), `alloy.env.example`, `replication-alerts.yml`.

## 1. Monitoring role on the publisher

Run as a superuser on hopper-db (least-priv; does **not** touch the app role):

```sh
EXPORTER_PASSWORD='<generate>' psql -h hopper-db -U postgres -d hopper \
  -v pw="$EXPORTER_PASSWORD" -f exporter-role.sql
```

Then allow it from uruk-hai in the publisher's `pg_hba.conf`
(`/var/pgsql/data/pg_hba.conf`) and reload:

```
host  hopper  hopper_exporter  10.9.8.5/32  scram-sha-256
```
```sh
psql -h hopper-db -U postgres -c 'SELECT pg_reload_conf();'
```

## 2. Install Alloy on uruk-hai (FreeBSD)

FreeBSD/amd64 is an official Alloy release. If it's not in `pkg`, fetch the
release binary:

```sh
# on uruk-hai, as root
fetch -o /tmp/alloy.zip \
  https://github.com/grafana/alloy/releases/latest/download/alloy-freebsd-amd64.zip
unzip -o /tmp/alloy.zip -d /tmp
install -m 0755 /tmp/alloy-freebsd-amd64 /usr/local/bin/alloy
alloy --version

pw useradd alloy -d /nonexistent -s /usr/sbin/nologin -c "Grafana Alloy" || true
install -d -m 0750 /usr/local/etc/hopper-alloy
install -d -o alloy -g alloy -m 0750 /var/db/hopper-alloy
```

## 3. Drop config + secrets

Copy from this repo dir onto uruk-hai (scp/rsync from a checkout):

```sh
install -m 0644 config.alloy queries.yaml /usr/local/etc/hopper-alloy/
install -m 0600 -o alloy -g alloy alloy.env.example \
  /usr/local/etc/hopper-alloy/alloy.env
vi /usr/local/etc/hopper-alloy/alloy.env      # EXPORTER_DSN (+ OTLP_ENDPOINT if needed)
```

`config.alloy` already points `custom_queries_config_path` at
`/usr/local/etc/hopper-alloy/queries.yaml`. Default `OTLP_ENDPOINT` is
`http://otel:9090/api/v1/otlp` (no auth). Ensure uruk-hai resolves `otel`
(e.g. via `/etc/hosts` or DNS) to the collector host.

## 4. Service (rc.d)

```sh
install -m 0755 hopper_alloy /usr/local/etc/rc.d/hopper_alloy
sysrc hopper_alloy_enable=YES
service hopper_alloy start
service hopper_alloy status
```

Logs go to syslog under the tag `hopper_alloy` (`tail -f /var/log/messages`).
The rc.d script sources `alloy.env`, supervises under `daemon(8)` with restart,
and drops to the `alloy` user.

## 5. Verify metrics are flowing

- Alloy's own UI/health: `http://10.9.8.5:12345` (component graph — the
  `prometheus.exporter.postgres.publisher` and OTLP exporter should be healthy).
- In Grafana → Explore (Prometheus), query
  `hopper_replication_slot_retained_wal_bytes` — expect one series per slot with
  a `kind` label, plus `up{job="postgres-publisher"} == 1`.

## 6. Load the alerts

Load `replication-alerts.yml` into the self-hosted Prometheus/Mimir that
backs Grafana on `otel` (same rule-load path you use for other hopper alerts).
Wire a notification policy/contact point for `severity=page`.

## 7. (Optional) statement-level attribution

Everything above measures *that* Postgres is busy or blocked. None of it says
*which statement*. On 2026-08-21 the walk-path staging upsert and the
`/api/result` member upsert were each running 10-13s and timing out on each
other's tuple locks in `samples`; that was visible only because
`log_min_duration_statement` caught it in the server log. Nothing in the fleet
trended it, so it could not be watched starting or shown to have stopped.

`hopper_pg_statements` in `queries.yaml` fixes that, and ships **commented
out** because it needs the extension to exist first — a custom query naming a
missing relation fails to plan on every scrape.

```sh
# on the DB host, as the postgres superuser
sh scripts/pg-stat-statements.sh     # step 1: stage shared_preload_libraries
# ... restart Postgres ...
sh scripts/pg-stat-statements.sh     # step 2: CREATE EXTENSION + verify
```

Then uncomment the `hopper_pg_statements` block in `queries.yaml`, reinstall it
(section 3), and restart Alloy. Verify in Explore:

```promql
topk(10, rate(hopper_pg_statements_total_exec_time_ms{job="postgres-publisher"}[15m]))
```

The label is `queryid`, not the query text — text is unbounded and would be a
cardinality disaster. Resolve one by hand:

```sql
SELECT query FROM pg_stat_statements WHERE queryid = <id>;
```

## 8. (Optional) subscriber-side detail

Publisher-side covers every paging case. For earlier signal on schema-drift
disables / apply errors, add a second target in `config.alloy` pointed at a
replica with a subscriber query file:

```alloy
prometheus.exporter.postgres "replica_62" {
  data_source_names = [sys.env("REPLICA_62_DSN")]   // hopper_exporter@10.9.8.62
  custom_queries_config_path = "/usr/local/etc/hopper-alloy/queries-subscriber.yaml"
}
prometheus.scrape "replica_62" {
  targets = prometheus.exporter.postgres.replica_62.targets
  forward_to = [prometheus.relabel.labels.receiver]
  job_name = "postgres-replica"
  scrape_interval = "30s"
}
```

`.62` is reachable from uruk-hai. galadriel's PG is socket-only, so its
subscriber stats need its `listen_addresses`/`pg_hba` opened to the tailnet (a
`10.9.8.5/32` host line) to scrape from uruk-hai. Then uncomment the subscriber
rules at the bottom of `replication-alerts.yml`.

## What pages you, and why

| Alert | Fires when | Real incident it covers |
|-------|-----------|-------------------------|
| `PostgresPublisherExporterDown` | exporter unscrapeable 5m | publisher PG down, or uruk-hai/Alloy down |
| `ReplicaSlotInvalidated` | `wal_status=lost` | 2026-06-21 slot self-invalidation (needs rebuild) |
| `ReplicaSlotInactive` | streaming slot no consumer 10m | 2026-06-27 galadriel down; sub disabled |
| `ReplicaSlotLagWarning` / `…Critical` | >300GB / >1.2TB pinned | replica falling behind toward the 1500GB backstop |
| `TablesyncSlotLagWarning` | tablesync >400GB | a slow initial copy (e.g. `.62` sample_locations) |
