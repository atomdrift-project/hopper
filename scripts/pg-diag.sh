#!/bin/sh
# pg-diag.sh — point-in-time diagnostics for the hopper Postgres + ZFS host.
#
# Captures the *ephemeral* state that vanishes on restart (lock pileups,
# long-running queries, temp spills, the live reconcile plan) plus a tuning
# baseline (settings, bloat, ZFS/ARC). Strictly read-only: it cancels nothing
# and writes nothing to the database.
#
# Run on the DB host as a superuser for full visibility (some stats views and
# other backends' query text require it). The Postgres section also works
# remotely (set PGHOST/PGPORT or DB_HOST); the ZFS/OS section auto-skips when
# the ZFS tools are absent (e.g. invoked from a Linux box).
#
# Overridable via env:
#   DB           database name                 (default: hopper)
#   DB_HOST      psql -h target, "" = local     (default: "")
#   OUTDIR       directory for the report       (default: /tmp)
#   POOL         zpool to sample, "" = autodetect
#   RECONCILE_RE regex of the long query to EXPLAIN (default: reconcile CTE)
#   SKIP_OS      set to 1 to skip the ZFS/OS section
#
# Each invocation writes a single timestamped report and prints its path.

set -u

# illumos/OmniOS keep zpool/zfs in /usr/sbin and prstat/kstat/iostat in
# /usr/bin; make sure they resolve even under a trimmed PATH (e.g. when this
# runs as the postgres user). Existing PATH entries keep priority.
PATH="$PATH:/usr/sbin:/sbin:/usr/bin"
export PATH

DB="${DB:-hopper}"
DB_HOST="${DB_HOST:-}"
OUTDIR="${OUTDIR:-/tmp}"
POOL="${POOL:-}"
RECONCILE_RE="${RECONCILE_RE:-RECURSIVE}"
SKIP_OS="${SKIP_OS:-0}"

ts=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown)
host=$(hostname 2>/dev/null || echo host)
REPORT="$OUTDIR/pg-diag-$host-$ts.txt"

# host flag for psql when targeting a remote server.
HOSTARG=""
[ -n "$DB_HOST" ] && HOSTARG="-h $DB_HOST"

# Pick a superuser escalation path (mirrors scripts/replica/diagnose.sh).
# shellcheck disable=SC2086
if psql -U postgres $HOSTARG -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres $HOSTARG "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -n -u postgres psql "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -u postgres psql "$@"; }
elif command -v pfexec >/dev/null 2>&1 && pfexec -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { pfexec -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -n -u postgres psql "$@"; }
elif psql $HOSTARG -tAc 'SELECT 1' >/dev/null 2>&1; then
    # Fall back to the default role (e.g. hopper). Other backends' query text
    # and some stats may be hidden, but the lock/wait picture still comes through.
    echo "warn: no superuser access; running as default role (output may be redacted)" >&2
    admin() { psql $HOSTARG "$@"; }
else
    echo "error: cannot connect to postgres (db=$DB host=${DB_HOST:-local})" >&2
    echo "       in a connection-slot exhaustion, only a superuser can get in." >&2
    exit 1
fi

# All admin() calls bound by short timeouts so a diagnostic query can never
# join the pileup it is trying to observe. Catalog/stats reads take no heavy
# locks, but fail fast if one ever does.
PREAMBLE="SET statement_timeout='15s'; SET lock_timeout='2s'; SET idle_in_transaction_session_timeout='15s';"

# sql RUNS a heredoc (read on stdin) under the preamble, appending to the report.
# -q suppresses the command-status tags ("SET") the preamble would otherwise emit.
sql() { admin -d "$DB" -q -P pager=off -v ON_ERROR_STOP=0 -c "$PREAMBLE" -f - ; }

section() { printf '\n========== %s ==========\n' "$*" >>"$REPORT"; }
note()    { printf '%s\n' "$*" >>"$REPORT"; }
have()    { command -v "$1" >/dev/null 2>&1; }

: >"$REPORT"
note "hopper pg-diag — $(date 2>/dev/null)"
note "report host=$host  db=$DB  target=${DB_HOST:-local}"
echo "collecting → $REPORT" >&2

# ===========================================================================
# POSTGRES — ephemeral forensics (lost on restart)
# ===========================================================================

section "server version + uptime"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT version();
SELECT pg_postmaster_start_time() AS started, now()-pg_postmaster_start_time() AS uptime;
SQL

section "wait-event breakdown (the pileup at a glance)"
sql >>"$REPORT" 2>&1 <<SQL
SELECT wait_event_type, wait_event, count(*)
FROM pg_stat_activity WHERE datname='$DB' GROUP BY 1,2 ORDER BY 3 DESC;
SQL

section "connection count by state + application"
sql >>"$REPORT" 2>&1 <<SQL
SELECT state, application_name, count(*)
FROM pg_stat_activity WHERE datname='$DB' GROUP BY 1,2 ORDER BY 3 DESC;
SQL

section "full activity snapshot (oldest transaction first)"
sql >>"$REPORT" 2>&1 <<SQL
SELECT pid, state, wait_event_type, wait_event,
       now()-xact_start AS xact_age, now()-query_start AS query_age,
       backend_type, application_name,
       left(regexp_replace(query,'\s+',' ','g'),200) AS query
FROM pg_stat_activity WHERE datname='$DB'
ORDER BY xact_start NULLS LAST;
SQL

section "blocking tree (who is blocked, by whom)"
sql >>"$REPORT" 2>&1 <<SQL
SELECT pid, pg_blocking_pids(pid) AS blocked_by, state, wait_event,
       now()-xact_start AS xact_age,
       left(regexp_replace(query,'\s+',' ','g'),90) AS query
FROM pg_stat_activity
WHERE datname='$DB' AND cardinality(pg_blocking_pids(pid))>0
ORDER BY xact_age DESC;
SQL

section "lock modes held/awaited on the hot tables"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT c.relname, l.pid, l.mode, l.granted, a.wait_event,
       now()-a.xact_start AS xact_age
FROM pg_locks l
JOIN pg_class c ON c.oid=l.relation
JOIN pg_stat_activity a USING (pid)
WHERE c.relname IN ('samples','sample_locations','walk_staging','label_events','reports')
ORDER BY c.relname, l.granted DESC, l.pid;
SQL

# ===========================================================================
# POSTGRES — reconcile root cause (why is that query so slow?)
# ===========================================================================

section "hot-table sizes + row estimates (instant, from catalog)"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT relname, reltuples::bigint AS est_rows,
       pg_size_pretty(pg_total_relation_size(oid)) AS total_size,
       pg_size_pretty(pg_relation_size(oid)) AS heap_size
FROM pg_class
WHERE relname IN ('samples','sample_locations','walk_staging','label_events','reports')
  AND relkind='r'
ORDER BY pg_total_relation_size(oid) DESC;
SQL

section "indexes on the recursive-join tables (is walk_staging unindexed?)"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT indrelid::regclass AS tbl, indexrelid::regclass AS idx,
       pg_get_indexdef(indexrelid) AS def
FROM pg_index
WHERE indrelid IN ('walk_staging'::regclass, 'sample_locations'::regclass)
ORDER BY 1, 2;
SQL

# Capture the live long-running statement matching RECONCILE_RE and EXPLAIN it
# (no ANALYZE -> the plan is estimated, the query is NOT executed). Only works
# for statements without bind parameters; worker UPDATEs ($1,$2) are skipped.
section "live reconcile query + estimated plan"
# Capture with -tAq and NO preamble: a single pg_stat_activity read takes no
# heavy locks, and omitting the SET preamble keeps stray "SET" command tags out
# of the captured text (otherwise EXPLAIN <text> becomes EXPLAIN SET...).
recon_sql=$(admin -d "$DB" -tAqc \
  "SELECT query FROM pg_stat_activity
   WHERE datname='$DB' AND query ~ '$RECONCILE_RE' AND pid<>pg_backend_pid()
   ORDER BY xact_start LIMIT 1" 2>/dev/null)
if [ -n "$recon_sql" ]; then
    note "--- captured statement (may be truncated at track_activity_query_size) ---"
    printf '%s\n' "$recon_sql" >>"$REPORT"
    case "$recon_sql" in
        *\$1*|*\$2*)
            note "--- has bind parameters; cannot EXPLAIN without values, skipping ---" ;;
        *)
            note "--- EXPLAIN (VERBOSE, SETTINGS) ---"
            tmp=$(mktemp 2>/dev/null || echo /tmp/pg-diag-explain.$$)
            printf '%s\nEXPLAIN (VERBOSE, SETTINGS) %s;\n' "$PREAMBLE" "$recon_sql" >"$tmp"
            admin -d "$DB" -q -P pager=off -v ON_ERROR_STOP=0 -f "$tmp" >>"$REPORT" 2>&1
            rm -f "$tmp" ;;
    esac
else
    note "no running statement matched /$RECONCILE_RE/"
fi

# ===========================================================================
# POSTGRES — spill, cache, bloat, replication
# ===========================================================================

section "temp-spill + cache-hit, database-wide"
sql >>"$REPORT" 2>&1 <<SQL
SELECT datname, numbackends, xact_commit, xact_rollback,
       temp_files, pg_size_pretty(temp_bytes) AS temp_total,
       blks_hit, blks_read,
       round(100.0*blks_hit/nullif(blks_hit+blks_read,0),2) AS cache_hit_pct,
       deadlocks, stats_reset
FROM pg_stat_database WHERE datname='$DB';
SQL

section "IO by context (pg_stat_io — confirms temp vs normal reads)"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT backend_type, object, context, reads, writes,
       pg_size_pretty(reads*8192) AS read_bytes,
       pg_size_pretty(writes*8192) AS write_bytes
FROM pg_stat_io WHERE reads>0 OR writes>0
ORDER BY reads DESC LIMIT 30;
SQL

section "vacuum / bloat state of the hot tables"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT relname, n_live_tup, n_dead_tup,
       round(100.0*n_dead_tup/nullif(n_live_tup+n_dead_tup,0),1) AS dead_pct,
       last_vacuum, last_autovacuum, last_analyze, last_autoanalyze,
       n_mod_since_analyze, vacuum_count, autovacuum_count
FROM pg_stat_user_tables
WHERE relname IN ('samples','sample_locations','walk_staging','reports')
ORDER BY n_dead_tup DESC;
SQL

section "autovacuum workers currently running"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT pid, now()-xact_start AS age, left(query,90) AS query
FROM pg_stat_activity WHERE backend_type='autovacuum worker' OR query LIKE 'autovacuum:%';
SQL

section "replication slots (inactive logical slot pins WAL on the pool)"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT slot_name, slot_type, active, wal_status,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal
FROM pg_replication_slots ORDER BY retained_wal DESC NULLS LAST;
SQL

# ===========================================================================
# POSTGRES — tuning baseline (not ephemeral, grabbed for sizing)
# ===========================================================================

section "key settings (with source: where each value comes from)"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT name, setting, unit, source FROM pg_settings WHERE name IN (
 'shared_buffers','work_mem','maintenance_work_mem','effective_cache_size',
 'max_connections','superuser_reserved_connections','reserved_connections',
 'max_wal_size','min_wal_size','checkpoint_timeout','checkpoint_completion_target',
 'wal_compression','full_page_writes','random_page_cost','effective_io_concurrency',
 'max_parallel_workers','max_parallel_workers_per_gather','max_worker_processes',
 'autovacuum_max_workers','autovacuum_vacuum_cost_limit','autovacuum_naptime',
 'statement_timeout','lock_timeout','idle_in_transaction_session_timeout',
 'log_min_duration_statement','log_temp_files','temp_file_limit',
 'jit','huge_pages','wal_level','track_activity_query_size')
ORDER BY name;
SQL

section "checkpoint / bgwriter behavior"
sql >>"$REPORT" 2>&1 <<'SQL'
SELECT * FROM pg_stat_checkpointer;
SQL

# ===========================================================================
# OS / ZFS — only on the DB host (auto-skips elsewhere)
# ===========================================================================

if [ "$SKIP_OS" = "1" ]; then
    section "OS/ZFS section skipped (SKIP_OS=1)"
elif ! have zpool; then
    section "OS/ZFS section skipped (no zpool here — run on the DB host)"
else
    # Derive PGDATA and its ZFS dataset so the report names what to tune.
    datadir=$(admin -d "$DB" -tAc 'SHOW data_directory' 2>/dev/null)
    dataset=""
    if [ -n "$datadir" ] && have zfs; then
        dataset=$(zfs list -H -o name,mountpoint 2>/dev/null | awk -v d="$datadir" '
            index(d,$2)==1 && length($2)>maxlen { maxlen=length($2); name=$1 }
            END { print name }')
    fi
    [ -z "$POOL" ] && POOL=$(zpool list -H -o name 2>/dev/null | head -n 1)

    section "PGDATA dataset tuning (recordsize/compression/atime/logbias/cache/sync)"
    note "data_directory=$datadir   dataset=${dataset:-?}   pool=${POOL:-?}"
    if [ -n "$dataset" ]; then
        zfs get -p recordsize,compression,atime,logbias,primarycache,secondarycache,sync,logicalused,used "$dataset" >>"$REPORT" 2>&1
    else
        note "could not map data_directory to a ZFS dataset"
    fi

    section "on-disk temp spill (pgsql_tmp) + WAL size"
    # illumos du lacks -h on some builds; fall back to -sk (1K blocks).
    disk_usage() { du -sh "$1" 2>/dev/null || du -sk "$1" 2>/dev/null; }
    if [ -n "$datadir" ]; then
        disk_usage "$datadir/base/pgsql_tmp" >>"$REPORT"
        disk_usage "$datadir/pg_wal" >>"$REPORT"
    fi

    section "zpool status"
    zpool status ${POOL:+"$POOL"} >>"$REPORT" 2>&1

    section "zpool iostat -v (5x 1s — IO during the spill)"
    zpool iostat -v ${POOL:+"$POOL"} 1 5 >>"$REPORT" 2>&1

    section "ARC size + hit rate"
    if have arcstat; then
        arcstat 1 5 >>"$REPORT" 2>&1
    elif have kstat; then
        kstat -p 'zfs:0:arcstats:size' 'zfs:0:arcstats:c' 'zfs:0:arcstats:hits' 'zfs:0:arcstats:misses' >>"$REPORT" 2>&1
    else
        note "no arcstat/kstat available"
    fi

    section "per-thread microstate (on-CPU vs IO wait)"
    if have prstat; then
        prstat -mLc 1 2 >>"$REPORT" 2>&1
    fi

    section "disk service times"
    if have iostat; then
        iostat -xnz 1 3 >>"$REPORT" 2>&1
    fi

    section "free memory"
    if have vmstat; then
        vmstat 1 3 >>"$REPORT" 2>&1
    fi
fi

note ""
note "=== end of report ==="
echo "done → $REPORT" >&2
printf '%s\n' "$REPORT"
