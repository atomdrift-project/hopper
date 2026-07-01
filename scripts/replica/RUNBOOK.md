# Runbook: derived-column schema changes & logical-replica health

This is the operational checklist for changing a **derived column** on `samples`
(`litmus_score`, `file_type`, `score`, `formula`, …) and for keeping the logical
replicas healthy across such a change. It exists because one such change — done
the naive way — froze the primary for 44 minutes and silently disabled a replica.

## The two rules that make this safe

1. **Never run a table-rewriting statement on `samples`.** Adding/recreating a
   `GENERATED ALWAYS AS … STORED` column, or `ALTER COLUMN … TYPE`, rewrites every
   row (~350 GB) under `ACCESS EXCLUSIVE` — it locks out *all* readers and writers
   (even plain `SELECT`s hit `lock_timeout`/`55P03`) for the whole rewrite. The
   migration code refuses these on a populated table (`isTableRewriteDDL` →
   `execPGMigrationDDL`); serving always, `init`/`import` unless
   `HOPPER_FORCE_REWRITE=1`. Derive instead with a **plain column + a BEFORE
   INSERT/UPDATE trigger** (see `samples_derive_litmus_score` /
   `samples_derive_cleave_cols`) plus a batched online backfill in `backfillPG`.

2. **A plain derived column must be plain on every replica too.** Logical apply
   runs with `session_replication_role=replica`, so **BEFORE triggers do not fire
   on subscribers** — the replica can't compute the value during apply. So a
   plain+trigger derived column on the primary is **published** and the subscriber
   **stores the replicated value**, which means its column must be **plain**, not
   generated. A generated column on the subscriber makes apply fail (`cannot
   write a replicated value into a generated column`) → the subscription disables
   itself → WAL piles up on the primary. This is why a generated↔plain change is a
   **coordinated primary + all-replicas migration**, not a primary-only one.

## Procedure: convert a derived column generated → plain

Order matters — get the new code everywhere *before* the primary publishes the
now-plain column.

1. **Deploy the new `hopper` binary to every host that can run
   `init`/`import`** — primary and all replicas — *before* converting. (Old
   binaries re-trigger the rewrite once the column is plain.) `make deploy` on the
   primary; on replicas, `git pull` then `make replica` (or copy the binary).
2. **Quiesce the primary** (`systemctl stop hopper.service`) so the `DROP
   EXPRESSION` takes its brief `ACCESS EXCLUSIVE` instantly instead of stalling
   behind live writers. Cancel any long reconcile holding IO.
3. **Apply on the primary:** `hopper init -db "…&lock_timeout=15s"`. The
   conversion is `ALTER COLUMN … DROP EXPRESSION` (metadata-only, retains values,
   no rewrite) + the derive trigger. Then `hopper backfill` if historical rows
   need filling (no-op if values were already populated).
4. **Restart the primary** on the new binary; confirm ingestion resumes and the
   startup migration is a clean no-op.
5. **Heal the replicas** — they will break the moment the primary publishes the
   now-plain column. Either let `replica-heal.sh` do it (see below) or, per
   replica: `ALTER TABLE samples ALTER COLUMN <col> DROP EXPRESSION;` then
   `ALTER SUBSCRIPTION <sub> ENABLE;`.

## Auto-heal: `replica-heal.sh`

The healer (systemd timer / cron, runs as `postgres`) reconciles two **bounded,
lossless** cases against the publisher's live catalog and re-enables the
subscription:
- a published column missing locally → `ADD COLUMN`;
- a column the publisher publishes plain but that is **STORED-generated locally**
  → `ALTER COLUMN … DROP EXPRESSION`.

It never guesses at drops/renames/true type changes (alerts + leaves disabled for
a human). So the generated→plain conversion in the procedure above **self-heals**
on the next timer tick — once the updated healer is installed.

**Distributing the healer:** `install-heal.sh` *copies* `replica-heal.sh` to
`/usr/local/bin/hopper-replica-heal.sh` and points the timer at the copy. So after
updating the script in the repo you must re-install: `git pull` on the replica,
then `scripts/replica/install-heal.sh` (light — no rebuild, no `hopper init`, no
subscription disable), or a full `make replica`.

## Fast (re)build: deferred-index bulk copy

The initial tablesync COPYs every row into a table that **already has all its
indexes**, so the subscriber maintains each secondary B-tree per row. On a big,
heavily-indexed table this — not the network — is the wall: `sample_locations`
(200M+ rows, 8 indexes / ~130 GB of index) took **72 h+** and *decelerated* as
the indexes grew, pinning the publisher's WAL the whole time. `samples` (540 GB
but only ~51 GB of index) streamed in well under a day by comparison.

So `setup.sh` (and therefore `rebuild.sh` and a fresh `make replica`) now, by
default, runs an **index-deferred bulk copy** (`scripts/replica/bulkload.sh`):

1. before the copy, it saves each to-be-copied table's non-PK index/constraint
   DDL and **drops** those indexes (keeping the PK — that's the replica identity
   streamed UPDATE/DELETE need during catch-up);
2. relaxes reload-only bulk GUCs for the load (`maintenance_work_mem`,
   `max_parallel_maintenance_workers`, `max_wal_size`, `autovacuum=off`,
   `synchronous_commit=off`, `wal_compression=off`);
3. lets the copy run index-light, then **rebuilds each table's indexes in
   parallel the moment that table finishes** (so `sample_locations`' indexes
   build while the bigger `samples` is still copying), `ANALYZE`s, and restores
   the GUCs.

Because it rebuilds after the copy, `setup.sh` now **blocks until the copy
completes** when it deferred anything (a steady-state reconcile defers nothing
and still returns immediately). Saved DDL lives under the healer state dir
(`~postgres/.hopper-replica-heal/bulkload/`); if a copy is interrupted the
indexes are recorded there — re-run `make rebuild-replica` or apply the files by
hand. The healer is paused (maintenance flag) for the whole window.

Knobs (env): `FAST_SYNC=false` disables it (plain indexed copy, async return);
`BULK_MAINT_MEM` (default `1GB` — raise on a big box, e.g. `8GB`),
`BULK_MAX_PARALLEL_MAINT` (`4`), `BULK_MAX_WAL` (`32GB`), `BULK_POLL_SECS` (`15`).

### Disposable read-replica: durability-for-speed tuning

Replicas serve **reads only** and can be rebuilt from the publisher at will, so
they run with crash durability traded away for throughput. This is safe *only*
because a crash just means "rebuild"; a primary must never run this way.

**ZFS — now a default.** `setup.sh` runs `zfs-tune.sh apply` (sync=disabled,
logbias=throughput on the pgdata/pg_wal datasets); `promote.sh` runs
`zfs-tune.sh revert` (sync=standard, logbias=latency) so a promoted primary is
durable. Set `ZFS_TUNE=false` to skip. It's best-effort and **a no-op inside a
Bastille jail** (a jail can't set the host pool's props) — for a jail replica,
run it on the host by hand:

```sh
# on the ZFS host, targeting the jail's dataset:
scripts/replica/zfs-tune.sh apply  zroot/bastille/jails/<jail>/pgdata
# promote.sh prints the matching revert (sync=standard) for the host to run.
```

**PostgreSQL restart-only knobs — still manual.** These need a restart (and
`shared_buffers`/`fsync` would be wrong to force on every replica), so apply by
hand on a disposable replica before a big rebuild and restart postgres:

```sh
ALTER SYSTEM SET fsync = off;              -- rebuild-on-crash; ZFS sync=disabled also covers this
ALTER SYSTEM SET full_page_writes = off;   -- SAFE to keep off permanently on ZFS (CoW, no torn pages)
ALTER SYSTEM SET shared_buffers = '8GB';   -- vs a tiny default
sysctl vfs.zfs.arc.max=<~half RAM>         -- (FreeBSD) leave room for shared_buffers + index builds
```

Wire compression is **not** available (PostgreSQL 18's libpq has no
`compression=` option), and it wouldn't help anyway — the copy is CPU/IO-bound
on the publisher detoasting blobs, not saturating the gigabit link.

## Guard: `setup.sh` refuses the primary

`setup.sh` aborts if the local cluster hosts the publication (i.e. it *is* the
primary) — you can't accidentally point replica setup at the publisher.

## Diagnostics

```sql
-- lock storm: who holds a strong lock on samples (run on the primary DB)
SELECT a.pid, now()-a.xact_start AS age, l.mode, a.wait_event_type, left(a.query,80)
FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid
JOIN pg_class c ON c.oid=l.relation WHERE c.relname='samples' ORDER BY a.xact_start;

-- replication health / WAL pinned by a stalled subscriber (on the primary)
SELECT slot_name, active,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)) AS lag
FROM pg_replication_slots;

-- on a replica: is its derived column plain, and is the subscription enabled?
SELECT attname, attgenerated FROM pg_attribute
 WHERE attrelid='samples'::regclass AND attname='litmus_score';   -- '' = plain
SELECT subname, subenabled FROM pg_subscription;
```

A bare `SELECT` on `samples` returning `55P03` means a **table-level** lock (DDL /
rewrite), not row contention — row locks never block plain reads.
