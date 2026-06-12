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
