# Runbook: derived-column schema changes & logical-replica health

This is the operational checklist for changing a **derived column** on `samples`
(`litmus_score`, `file_type`, `score`, `formula`, …) and for keeping the logical
replicas healthy across such a change. It exists because one such change — done
the naive way — froze the primary for 44 minutes and silently disabled a replica.

## The four rules that make this safe

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

3. **Never add an *unconditional* index to `samples`.** Prefer a partial one.
   `samples` takes ~29 updates per insert (206M vs 7.1M, measured 2026-09-05)
   and its HOT ratio is **0.04%** — `analyzed_at`, `updated_at`, `cleave_result`
   and `litmus_result` are each either indexed outright or named in some partial
   index's predicate, and HOT is disabled the moment *any* index-referenced
   column changes. So nearly every update writes a new heap tuple plus an index
   entry in every index the new row matches. A partial index pays that only for
   rows matching its predicate; an unconditional one pays it on all ~130M
   row-writes.

   Two unconditional indexes accounted for 37 GB of the ~69 GB always-written
   set, and were retired on 2026-09-05:
   - `idx_samples_path` (28 GB) — **never once scanned** (`idx_scan` 0,
     `last_idx_scan` NULL); its only equality consumer carries
     `skip = '' AND cleave_result IS NULL` and plans via
     `idx_samples_pending_path`. Retired.
   - `idx_samples_status` (8955 MB over 106M rows) — served `countByStatusPG`,
     which only ever asks `WHERE status != ''`: 674,957 rows, 0.63%. Rewritten
     as a partial, ~160x smaller.

   Before adding one, check the cost with:
   `SELECT indexrelname, idx_scan, last_idx_scan, pg_size_pretty(pg_relation_size(indexrelid)) FROM pg_stat_user_indexes WHERE relname='samples' ORDER BY idx_scan;`
   and remember that **`idx_scan = 0` is not proof an index is dead** — indexes
   in `REPLICA_KEEP_INDEXES` read zero on the master because prism reads them on
   the *replica*, and a tier that is merely switched off reads zero too. `EXPLAIN`
   the application's real SQL text before dropping anything.

   Measured outcome, so nobody repeats it expecting more: that diet cut samples'
   index footprint **129 GB → 93 GB** and left WAL per row **unchanged at
   ~7.6 KB**. Index writes are real, but on this table they are second-order.
   Rule 4 is where the bytes actually were.

4. **Never assign a large TOASTed column unconditionally in an upsert.** This is
   the big one. On 2026-09-05 a single statement — the member upsert in
   `insertMembersFromStagingPG` — was **73.7% of all WAL on the master** (990 GB,
   130M rows, ~7.6 KB each), and galadriel sat **~7.5 h behind** because
   single-threaded logical decode must read every byte of that WAL before it can
   apply anything.

   Almost none of those bytes were new information. `samples.cleave_result` is
   JSONB averaging **6.6 KB** (p50 2.8 KB, p95 16 KB, max 2.2 MB) with 62% of
   rows over the TOAST threshold, and samples' TOAST table is **933 GB** taking
   ~394M chunk inserts. The row is keyed by `sha256`, so identical content yields
   an identical cleave analysis — while a popular dependency is a member of
   thousands of archives, each of which re-upserts it with a fresh `analyzed_at`.
   So the statement was re-TOASTing an unchanged 6.6 KB payload, over and over,
   to refresh a timestamp.

   The mechanism to know: assigning `EXCLUDED.<col>` hands `heap_update` a fresh
   datum, which always re-TOASTs — even when the bytes are identical. Assigning
   `samples.<col>` back hands it the **original external TOAST pointer**, which it
   preserves instead of writing new chunks and deleting the old ones. So guard
   the write:

   ```sql
   cleave_result = CASE
       WHEN samples.cleave_result IS DISTINCT FROM EXCLUDED.cleave_result
       THEN EXCLUDED.cleave_result
       ELSE samples.cleave_result   -- preserves the TOAST pointer
   END
   ```

   Keep the cheap scalar refreshes (`analyzed_at`) unconditional — skipping those
   would strand rescan scheduling on a stale timestamp, which is a correctness
   change rather than an optimization. `sampleConflictUpdatePG` already applies
   this discipline via its `IS DISTINCT FROM` WHERE guard; `locationChangedPG` is
   the same lesson learned earlier on `sample_locations`.

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
indexes are recorded there — re-run `make replica` (resumes: post-COPY catch-up
for `f`/`s`, truncates + retries mid-COPY `i`/`d` with leftover rows, finishes
pending index rebuilds) or apply the files by hand. Use `make rebuild-replica`
only for lost slots / hard apply wedges. The healer is paused (maintenance flag)
for the whole window.

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

**PostgreSQL server tuning — applied by `setup.sh` on every replica.** These
used to live only in `freebsd-bastille.sh`, so a Linux replica (galadriel) never
got them; `setup.sh` now applies them itself, on every platform.
`REPLICA_TUNE=false` skips the durability/parallelism trades —
`wal_receiver_timeout` is still applied, since that one is apply-worker
resilience rather than something traded away:

| setting | value | why |
|---|---|---|
| `wal_receiver_timeout` | `10min` | the 1-minute default turns a slow catch-up into a restart loop |
| `checkpoint_timeout` | `30min` | FPIs regenerate on first touch after each checkpoint; the stock 5min does that 12×/hour. Matches the publisher |
| `full_page_writes` | `off` **if CoW** | 64.7% of publisher WAL *bytes* were FPIs; off cut WAL 15.06 → 6.14 MB/s |
| `max_parallel_workers_per_gather` | `0` on the reader role | one runaway feed query must not fork more bulkread scanners into the queue the apply worker is stuck behind |

`full_page_writes=off` is **gated on the filesystem**, not on the replica being
rebuildable. Copy-on-write (ZFS, btrfs) never overwrites a live block, so a torn
8 KB page is unreachable; on ext4/xfs/ufs it is a corruption risk on power loss
and `setup.sh` leaves the setting alone and says so. The probe reads the mount
table rather than `df -T "$PGDATA"` — pgdata is mode 0700 and the script runs as
the operator, so `df` would fail and silently take the safe branch forever.

The parallelism cap is set with `ALTER ROLE`, not `ALTER SYSTEM`, so it applies
to prism/beamline/cyclotron logins and deliberately *overrides* the cluster-wide
`max_parallel_workers_per_gather=4` that `freebsd-bastille.sh` sets below;
`hopper init`'s index builds read `max_parallel_maintenance_workers` and are
untouched. Override with `REPLICA_MAX_PARALLEL_PER_GATHER=<n>`. `promote.sh`
RESETs it — a primary has no apply worker to protect and does run the reporting
queries parallelism exists for.

Why this block exists at all: on 2026-08-24 the publisher generated 11.9 MB/s of
WAL while the replica burned it down at 13.1 MB/s — a 1.2 MB/s net against a
151 GB backlog. The publisher was *not* the constraint (its walsender sat 75% in
`Client:WalSenderWriteData`, waiting on the subscriber); the apply worker was,
60% in `IO:DataFileRead` behind a device carrying 3.6 GB/s at queue depth 65.
Apply is single-threaded, so its ceiling is 1/latency — ~850 reads/s at the
1.17 ms that queue was actually returning.

**PostgreSQL read/apply tuning — now deploy defaults.** `freebsd-bastille.sh`
sets these in its tuning block (they take effect on the restart it already
does), sized from host RAM: `shared_buffers` (~RAM/8, capped 16 GB),
`effective_cache_size` (~60% RAM — the stock 4 GB default badly biases the
planner toward seq scans), `work_mem=64MB`, `max_parallel_workers_per_gather=4`,
`checkpoint_timeout=30min`, `default_statistics_target=200`,
`full_page_writes=off` (ZFS CoW → no torn pages, safe), and
`synchronous_commit=off` (`promote.sh` restores it to `on`). `autotrim=on` and a
deeper `vfs.zfs.vdev.async_read_max_active` are applied host-side too.

**Still manual (most aggressive):** `fsync=off` trades a crash into a full
rebuild — only worth it during a big rebuild, and `sync=disabled` at the ZFS
layer already covers most of the win, so it's left off by default:

```sh
ALTER SYSTEM SET fsync = off;       -- then restart; revert to on for anything you must keep
sysctl vfs.zfs.arc.max=<~half RAM>  -- (FreeBSD) cap ARC to leave room for index builds during a rebuild
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
