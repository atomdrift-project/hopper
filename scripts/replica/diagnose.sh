#!/bin/sh
# diagnose-replica.sh — collect status from both sides of the logical
# replication pair so a stuck sync is obvious at a glance. Read-only.
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# SUBSCRIPTION (auto-detected from pg_subscription when unset).
# Remote queries read ~/.pgpass for credentials.

set -u

REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
SUBSCRIPTION="${SUBSCRIPTION:-}"

section() { printf '\n=== %s ===\n' "$*"; }

# Pick a local admin escalation tool (matches setup-replica.sh).
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -n -u postgres psql "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -n -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -u postgres psql "$@"; }
else
    echo "error: no admin access to local postgres" >&2
    exit 1
fi

# Auto-detect the subscription name rather than guessing: a wrong name makes
# every filtered section come back empty, which reads as "not set up at all".
if [ -z "$SUBSCRIPTION" ]; then
    subs=$(admin -d "$LOCAL_DB" -tA <<'SQL'
SELECT subname FROM pg_subscription
 WHERE subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
 ORDER BY subname;
SQL
)
    SUBSCRIPTION=$(printf '%s\n' "$subs" | head -n 1)
    if [ -z "$SUBSCRIPTION" ]; then
        echo "error: no subscription found in database '$LOCAL_DB'; is the replica set up?" >&2
        exit 1
    fi
    n=$(printf '%s\n' "$subs" | grep -c .)
    [ "$n" -gt 1 ] && echo "note: $n subscriptions found; using '$SUBSCRIPTION' (override with SUBSCRIPTION=...)"
fi
echo "subscription: $SUBSCRIPTION"

# ---------------------------------------------------------------------------
# LOCAL SIDE
# ---------------------------------------------------------------------------

section "local: per-table sync state"
# 'i' initializing, 'd' copying data, 'f' finished copy,
# 's' synchronized (catching up), 'r' ready (streaming).
admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" <<'SQL'
SELECT c.relname AS table,
       CASE r.srsubstate
           WHEN 'i' THEN 'initializing'
           WHEN 'd' THEN 'copying data'
           WHEN 'f' THEN 'finished copy'
           WHEN 's' THEN 'synchronized'
           WHEN 'r' THEN 'ready (streaming)'
           ELSE r.srsubstate::text
       END AS state,
       r.srsublsn
  FROM pg_subscription_rel r
  JOIN pg_subscription s ON s.oid = r.srsubid
  JOIN pg_class c ON c.oid = r.srrelid
  WHERE s.subname = :'sub'
  ORDER BY c.relname;
SQL

section "local: replication workers (what are they waiting on?)"
# ClientRead = waiting on publisher; Lock = blocked locally; IO waits =
# disk-bound; nothing unusual = worker is actively working.
admin -d "$LOCAL_DB" <<'SQL'
SELECT pid, backend_type, state,
       wait_event_type, wait_event,
       coalesce((now() - xact_start)::text, '-') AS xact_age,
       left(query, 100) AS query
  FROM pg_stat_activity
 WHERE backend_type LIKE 'logical replication%'
 ORDER BY backend_type, pid;
SQL

section "local: pg_stat_subscription"
admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" <<'SQL'
SELECT subname, worker_type, pid, relid,
       received_lsn, latest_end_lsn,
       last_msg_receipt_time
  FROM pg_stat_subscription
 WHERE subname = :'sub';
SQL

section "local: pg_stat_subscription_stats (PG15+; error counters)"
admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" <<'SQL'
SELECT subname, apply_error_count, sync_error_count,
       confl_insert_exists, confl_update_origin_differs,
       confl_update_exists, confl_update_missing,
       confl_delete_origin_differs, confl_delete_missing
  FROM pg_stat_subscription_stats
 WHERE subname = :'sub';
SQL

section "local: pg_stat_progress_copy (PG14+; live COPY progress)"
admin -d "$LOCAL_DB" <<'SQL'
SELECT pid, relid::regclass AS table, command,
       pg_size_pretty(bytes_processed) AS copied,
       pg_size_pretty(NULLIF(bytes_total, 0)) AS total,
       tuples_processed
  FROM pg_stat_progress_copy;
SQL

section "local: row counts for subscribed tables"
tables=$(admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA <<'SQL'
SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname)
  FROM pg_subscription_rel r
  JOIN pg_subscription s ON s.oid = r.srsubid
  JOIN pg_class c ON c.oid = r.srrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE s.subname = :'sub'
 ORDER BY c.relname;
SQL
)
printf '%s\n' "$tables" | while read -r q; do
    [ -n "$q" ] || continue
    n=$(admin -d "$LOCAL_DB" -tAc "SELECT count(*) FROM $q" 2>/dev/null | tr -d '[:space:]')
    printf '  %s: %s rows\n' "$q" "${n:-?}"
done

# ---------------------------------------------------------------------------
# REMOTE SIDE
# ---------------------------------------------------------------------------

remote() { psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" "$@"; }

section "remote: replication slots (subscription + tablesync)"
# Tablesync workers use their own transient slots named pg_<suboid>_sync_<...>.
remote -v sub="$SUBSCRIPTION" <<'SQL'
SELECT slot_name, active, active_pid,
       restart_lsn, confirmed_flush_lsn,
       pg_size_pretty(pg_current_wal_lsn() - restart_lsn) AS retained_wal
  FROM pg_replication_slots
 WHERE slot_name = :'sub' OR slot_name LIKE 'pg\_%\_sync\_%'
 ORDER BY slot_name;
SQL

section "remote: pg_stat_replication (this subscriber's peer)"
remote <<'SQL'
SELECT application_name, client_addr, state, sync_state,
       pg_size_pretty(pg_current_wal_lsn() - sent_lsn)  AS send_lag,
       pg_size_pretty(sent_lsn  - write_lsn)             AS write_lag,
       pg_size_pretty(write_lsn - flush_lsn)             AS flush_lag,
       pg_size_pretty(flush_lsn - replay_lsn)            AS replay_lag
  FROM pg_stat_replication;
SQL

section "remote: row counts (for comparison)"
remote -tA <<'SQL' | sed 's/^/  /'
SELECT relname || ': ' || n_live_tup || ' rows (est)'
  FROM pg_stat_user_tables
 ORDER BY relname;
SQL

# ---------------------------------------------------------------------------
# LOG TAIL (best-effort; location varies by distro)
# ---------------------------------------------------------------------------

section "postgres log (last 60 lines, filtered)"
if command -v journalctl >/dev/null 2>&1; then
    (doas journalctl -u postgresql -n 60 --no-pager 2>/dev/null \
        || sudo journalctl -u postgresql -n 60 --no-pager 2>/dev/null \
        || journalctl -u postgresql -n 60 --no-pager 2>/dev/null) \
        | grep -iE 'subscrip|replicat|worker|error|fatal' \
        || echo "  (no matching log lines — or journalctl needs sudo/doas)"
else
    echo "  journalctl not available on this system; check /var/log/postgresql/ manually"
fi
