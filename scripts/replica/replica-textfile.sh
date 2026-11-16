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
# Overridable via env: LOCAL_DB, SUBSCRIPTION (auto-detected), PUBLICATION,
# REMOTE_HOST, REMOTE_USER, REMOTE_DB, PGPASSFILE, HOST_MON_TEXTFILE_DIR.

set -eu

LOCAL_DB="${LOCAL_DB:-hopper}"
SUBSCRIPTION="${SUBSCRIPTION:-}"
PUBLICATION="${PUBLICATION:-hopper_replica}"
REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
OUT_DIR="${HOST_MON_TEXTFILE_DIR:-${NODE_EXPORTER_TEXTFILE_DIR:-/var/lib/host-mon/textfile}}"
TMP="${OUT_DIR}/hopper-replica.prom.$$"
OUT="${OUT_DIR}/hopper-replica.prom"

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

# --- Lag and index parity vs the publisher ----------------------------------
# Optional: a blank publisher just leaves lag absent (and reachable=0) rather
# than failing the whole emit, so subscription state still reaches the alerts
# when the publisher is the thing that is down.
#
# Index parity: the replica carries every index the publisher has on a
# published table (readers query it as they would the publisher). DDL does not
# replicate, so an index added upstream never arrives on its own, and one left
# out by an interrupted fast-sync rebuild stays out. Indexes are compared by
# schema.table.name: 'missing' are the publisher's absent here, 'extra' are
# this replica's on subscribed tables that the publisher lacks.
pub_reachable=0
lag_bytes=""
index_known=0
index_missing=0
index_extra=0
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
    remote_idx=$(PGCONNECT_TIMEOUT=5 psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAX \
        -v pub="$PUBLICATION" 2>/dev/null <<'SQL' | LC_ALL=C sort -u || true
SELECT i.schemaname || '.' || i.tablename || '.' || i.indexname
  FROM pg_indexes i
  JOIN pg_publication_tables p ON p.schemaname = i.schemaname AND p.tablename = i.tablename
 WHERE p.pubname = :'pub';
SQL
    )
    # Every published table has a primary key, so an empty local list means
    # the query failed or nothing is subscribed yet: unknown, not all missing.
    local_idx=$(admin -d "$LOCAL_DB" -tAX -v sub="$SUBSCRIPTION" 2>/dev/null <<'SQL' | LC_ALL=C sort -u || true
SELECT n.nspname || '.' || t.relname || '.' || c.relname
  FROM pg_index i
  JOIN pg_class c ON c.oid = i.indexrelid
  JOIN pg_class t ON t.oid = i.indrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
 WHERE i.indrelid IN (SELECT r.srrelid FROM pg_subscription_rel r
                        JOIN pg_subscription s ON s.oid = r.srsubid
                       WHERE s.subname = :'sub');
SQL
    )
    if [ -n "$remote_idx" ] && [ -n "$local_idx" ]; then
        index_known=1
        # grep -c prints the count and exits 1 when it is 0.
        index_missing=$(printf '%s\n' "$remote_idx" | grep -cvxF "$local_idx" || true)
        index_extra=$(printf '%s\n' "$local_idx" | grep -cvxF "$remote_idx" || true)
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

  printf '# HELP hopper_replica_index_policy_known 1 if the publisher and local index lists were readable\n'
  printf '# TYPE hopper_replica_index_policy_known gauge\n'
  printf 'hopper_replica_index_policy_known %s\n' "$index_known"

  printf '# HELP hopper_replica_index_policy_missing Publisher indexes on published tables absent from this replica\n'
  printf '# TYPE hopper_replica_index_policy_missing gauge\n'
  printf 'hopper_replica_index_policy_missing %s\n' "$(num "$index_missing")"

  printf '# HELP hopper_replica_index_policy_extra Indexes on subscribed tables that the publisher does not have\n'
  printf '# TYPE hopper_replica_index_policy_extra gauge\n'
  printf 'hopper_replica_index_policy_extra %s\n' "$(num "$index_extra")"

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
