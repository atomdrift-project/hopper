#!/bin/sh
# replica-textfile.sh — emit logical-replica health as Prometheus textfile
# metrics for Alloy's textfile collector. Read-only.
#
# Why textfile and not a postgres_exporter scrape: every replication alert we
# have (hopper/scripts/monitoring/replication-alerts.yml) is PUBLISHER-side,
# scraped from uruk-hai against hopper-db. That view sees a sick replica only
# indirectly — as slot lag or an inactive slot — and cannot see the thing that
# has actually caused the outages: the subscription disabling itself. The
# subscriber-side rules were left commented out in that file because reaching
# galadriel's postgres would mean opening listen_addresses/pg_hba to the
# tailnet. A local emitter needs none of that: it talks over the unix socket as
# postgres, and Alloy ships the result to the same otel endpoint as everything
# else, where the rules already evaluate.
#
# A textfile dies with its host, so these metrics COMPLEMENT the publisher-side
# rules rather than replacing them: keep those as the backstop for "the replica
# is gone", and alert on staleness here via node_textfile_mtime_seconds.
#
# Overridable via env: LOCAL_DB, SUBSCRIPTION (auto-detected), REMOTE_HOST,
# REMOTE_USER, REMOTE_DB, PGPASSFILE, HOST_MON_TEXTFILE_DIR, SLIM_INDEXES_SH.

set -eu

LOCAL_DB="${LOCAL_DB:-hopper}"
SUBSCRIPTION="${SUBSCRIPTION:-}"
REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
OUT_DIR="${HOST_MON_TEXTFILE_DIR:-${NODE_EXPORTER_TEXTFILE_DIR:-/var/lib/host-mon/textfile}}"
TMP="${OUT_DIR}/hopper-replica.prom.$$"
OUT="${OUT_DIR}/hopper-replica.prom"

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
SLIM_INDEXES_SH="${SLIM_INDEXES_SH:-$SCRIPT_DIR/slim-indexes.sh}"

# Same local-admin ladder as replica-heal.sh. Unlike the healer we exit 0 on
# no access: a missing metrics file is a staleness alert, not a crash loop.
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -n -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -n -u postgres psql "$@"; }
else
    echo "replica-textfile: no admin access to local postgres — not writing metrics" >&2
    exit 0
fi

q() { admin -d "$LOCAL_DB" -tAX -c "$1" 2>/dev/null | head -n 1; }

if [ -z "$SUBSCRIPTION" ]; then
    SUBSCRIPTION=$(q "SELECT subname FROM pg_subscription
                       WHERE subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                       ORDER BY subname LIMIT 1")
fi
[ -n "$SUBSCRIPTION" ] || { echo "replica-textfile: no subscription in '$LOCAL_DB'" >&2; exit 0; }

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
SUB=$(esc "$SUBSCRIPTION")

num() { case "${1:-}" in ''|*[!0-9-]*) echo 0 ;; *) echo "$1" ;; esac; }

enabled=$(num "$(q "SELECT subenabled::int FROM pg_subscription WHERE subname = '$SUBSCRIPTION'")")
worker=$(num "$(q "SELECT count(*)::int FROM pg_stat_subscription
                    WHERE subname = '$SUBSCRIPTION' AND pid IS NOT NULL AND relid IS NULL")")
apply_err=$(num "$(q "SELECT apply_error_count::bigint FROM pg_stat_subscription_stats WHERE subname = '$SUBSCRIPTION'")")
sync_err=$(num "$(q "SELECT sync_error_count::bigint FROM pg_stat_subscription_stats WHERE subname = '$SUBSCRIPTION'")")
tbl_total=$(num "$(q "SELECT count(*)::int FROM pg_subscription_rel r
                       JOIN pg_subscription s ON s.oid = r.srsubid WHERE s.subname = '$SUBSCRIPTION'")")
tbl_ready=$(num "$(q "SELECT count(*)::int FROM pg_subscription_rel r
                       JOIN pg_subscription s ON s.oid = r.srsubid
                      WHERE s.subname = '$SUBSCRIPTION' AND r.srsubstate = 'r'")")

# --- Index policy drift -----------------------------------------------------
# The keep list in slim-indexes.sh is the single source of truth for which
# indexes this replica is supposed to carry (see TestReplicaIndexPolicyIsComplete).
# 'missing' is the signal that 'make replica' has not been run since the master
# gained an index; 'extra' means slim-indexes.sh has not been run since one
# appeared. Both are silent today — that is exactly why they drifted.
policy_known=0
policy_missing=0
policy_extra=0
if [ -r "$SLIM_INDEXES_SH" ]; then
    keep=$(sed -n "/^REPLICA_KEEP_INDEXES='/,/^'/p" "$SLIM_INDEXES_SH" \
           | grep -vE "^REPLICA_KEEP_INDEXES='|^'" | grep -v '^$' || true)
    if [ -n "$keep" ]; then
        policy_known=1
        keep_csv=$(printf '%s\n' "$keep" | sed "s/^/'/; s/\$/'/" | paste -sd, -)
        policy_missing=$(num "$(q "SELECT count(*)::int FROM (VALUES ($(printf '%s' "$keep_csv" | sed "s/,/),(/g"))) AS w(name)
             WHERE NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                WHERE c.relkind = 'i' AND n.nspname = 'public' AND c.relname = w.name)")")
        policy_extra=$(num "$(q "SELECT count(*)::int
              FROM pg_index i
              JOIN pg_class c ON c.oid = i.indexrelid
              JOIN pg_class t ON t.oid = i.indrelid
              JOIN pg_namespace n ON n.oid = t.relnamespace
             WHERE n.nspname = 'public'
               AND i.indrelid IN (SELECT srrelid FROM pg_subscription_rel)
               AND NOT i.indisprimary AND NOT i.indisreplident
               AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = i.indexrelid)
               AND c.relname NOT IN ($keep_csv)")")
    fi
fi

# --- Lag vs the publisher ---------------------------------------------------
# Optional: a blank publisher just leaves lag absent (and reachable=0) rather
# than failing the whole emit, so subscription state still reaches the alerts
# when the publisher is the thing that is down.
pub_reachable=0
lag_bytes=""
if [ -n "${PGPASSFILE:-}" ] || [ -r "$HOME/.pgpass" ]; then
    recv=$(q "SELECT latest_end_lsn FROM pg_stat_subscription WHERE subname = '$SUBSCRIPTION' AND relid IS NULL")
    if [ -n "$recv" ]; then
        lag_bytes=$(PGCONNECT_TIMEOUT=5 psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAX \
            -c "SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '$recv')::bigint" 2>/dev/null | head -n 1 || true)
        case "${lag_bytes:-}" in
            ''|*[!0-9-]*) lag_bytes="" ;;
            *) pub_reachable=1 ;;
        esac
    fi
fi

mkdir -p "$OUT_DIR"
{
  printf '# HELP hopper_replica_subscription_enabled 1 if the logical subscription is enabled\n'
  printf '# TYPE hopper_replica_subscription_enabled gauge\n'
  printf 'hopper_replica_subscription_enabled{subscription="%s"} %s\n' "$SUB" "$enabled"

  printf '# HELP hopper_replica_apply_worker_running 1 if an apply worker is attached\n'
  printf '# TYPE hopper_replica_apply_worker_running gauge\n'
  printf 'hopper_replica_apply_worker_running{subscription="%s"} %s\n' "$SUB" "$worker"

  printf '# HELP hopper_replica_apply_error_count Cumulative apply errors (pg_stat_subscription_stats)\n'
  printf '# TYPE hopper_replica_apply_error_count counter\n'
  printf 'hopper_replica_apply_error_count{subscription="%s"} %s\n' "$SUB" "$apply_err"

  printf '# HELP hopper_replica_sync_error_count Cumulative tablesync errors\n'
  printf '# TYPE hopper_replica_sync_error_count counter\n'
  printf 'hopper_replica_sync_error_count{subscription="%s"} %s\n' "$SUB" "$sync_err"

  printf '# HELP hopper_replica_tables_total Tables in the subscription\n'
  printf '# TYPE hopper_replica_tables_total gauge\n'
  printf 'hopper_replica_tables_total{subscription="%s"} %s\n' "$SUB" "$tbl_total"

  printf '# HELP hopper_replica_tables_ready Subscribed tables in srsubstate=r\n'
  printf '# TYPE hopper_replica_tables_ready gauge\n'
  printf 'hopper_replica_tables_ready{subscription="%s"} %s\n' "$SUB" "$tbl_ready"

  printf '# HELP hopper_replica_index_policy_known 1 if the slim-indexes keep list was readable\n'
  printf '# TYPE hopper_replica_index_policy_known gauge\n'
  printf 'hopper_replica_index_policy_known %s\n' "$policy_known"

  printf '# HELP hopper_replica_index_policy_missing Keep-list indexes absent locally (make replica is overdue)\n'
  printf '# TYPE hopper_replica_index_policy_missing gauge\n'
  printf 'hopper_replica_index_policy_missing %s\n' "$policy_missing"

  printf '# HELP hopper_replica_index_policy_extra Indexes on subscribed tables the keep list does not name (slim-indexes is overdue)\n'
  printf '# TYPE hopper_replica_index_policy_extra gauge\n'
  printf 'hopper_replica_index_policy_extra %s\n' "$policy_extra"

  printf '# HELP hopper_replica_publisher_reachable 1 if the publisher answered a lag query\n'
  printf '# TYPE hopper_replica_publisher_reachable gauge\n'
  printf 'hopper_replica_publisher_reachable %s\n' "$pub_reachable"

  if [ -n "$lag_bytes" ]; then
    printf '# HELP hopper_replica_lag_bytes WAL bytes between publisher current LSN and this subscriber\n'
    printf '# TYPE hopper_replica_lag_bytes gauge\n'
    printf 'hopper_replica_lag_bytes{subscription="%s"} %s\n' "$SUB" "$lag_bytes"
  fi
} >"$TMP"

mv -f "$TMP" "$OUT"
