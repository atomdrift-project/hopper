#!/bin/sh
# pg-tuning.sh — apply hopper's Postgres guardrail + planner settings.
#
# Idempotent: every statement is an ALTER ROLE / ALTER SYSTEM SET, so re-running
# just re-asserts the same values. Run on the DB host as the postgres superuser
# (ALTER SYSTEM requires it). Preview without changing anything via DRY_RUN=1.
#
# The settings here are the reversible, low-risk PG-side knobs. The OS/ZFS knobs
# (recordsize, zfs_arc_max, ...) reboot-affect the host and are illumos-specific,
# so they are printed at the end as a reviewed-by-hand checklist, not applied.
#
# Overridable via env (defaults in brackets):
#   DB [hopper]  DB_HOST ['' = local]  APP_ROLE [hopper]  DRY_RUN [0]
#   LOCK_TIMEOUT [10s]  IDLE_TX_TIMEOUT [300s]
#   LOG_MIN_DURATION [10s]  LOG_TEMP_FILES [64MB]
#   SUPERUSER_RESERVED [5]  TRACK_QUERY_SIZE [4096]

set -u

PATH="$PATH:/usr/sbin:/sbin:/usr/bin"
export PATH

DB="${DB:-hopper}"
DB_HOST="${DB_HOST:-}"
APP_ROLE="${APP_ROLE:-hopper}"
DRY_RUN="${DRY_RUN:-0}"

LOCK_TIMEOUT="${LOCK_TIMEOUT:-10s}"
IDLE_TX_TIMEOUT="${IDLE_TX_TIMEOUT:-300s}"
LOG_MIN_DURATION="${LOG_MIN_DURATION:-10s}"
LOG_TEMP_FILES="${LOG_TEMP_FILES:-64MB}"
SUPERUSER_RESERVED="${SUPERUSER_RESERVED:-5}"
TRACK_QUERY_SIZE="${TRACK_QUERY_SIZE:-4096}"

HOSTARG=""
[ -n "$DB_HOST" ] && HOSTARG="-h $DB_HOST"

# Superuser escalation ladder (mirrors pg-diag.sh / scripts/replica/diagnose.sh).
# shellcheck disable=SC2086
if psql -U postgres $HOSTARG -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres $HOSTARG "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -u postgres psql "$@"; }
elif command -v pfexec >/dev/null 2>&1 && pfexec -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { pfexec -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -u postgres psql "$@"; }
else
    echo "error: need superuser psql access to apply ALTER SYSTEM (db=$DB host=${DB_HOST:-local})" >&2
    exit 1
fi

# ALTER SYSTEM requires superuser; fail loudly rather than half-applying.
if [ "$(admin -d "$DB" -tAc 'SELECT current_setting(''is_superuser'')' 2>/dev/null)" != "on" ]; then
    echo "error: connected role is not a superuser; ALTER SYSTEM would fail" >&2
    exit 1
fi

FAILED=0
run() {
    printf '  %s\n' "$1" >&2
    [ "$DRY_RUN" = "1" ] && return 0
    if ! admin -d "$DB" -v ON_ERROR_STOP=1 -qc "$1"; then
        echo "    ^ FAILED" >&2
        FAILED=1
    fi
}

[ "$DRY_RUN" = "1" ] && echo "== DRY RUN (printing only) ==" >&2

echo "== applied immediately (reload) ==" >&2

# Bound lock waits for the APP role only — admin/superuser keep full latitude.
# A wedged DDL now fails after $LOCK_TIMEOUT instead of head-of-line-blocking
# every writer for hours. Steady-state row UPDATEs never wait on a table lock,
# so only genuine lock contention is affected.
run "ALTER ROLE $APP_ROLE SET lock_timeout = '$LOCK_TIMEOUT'"

# Reap any app transaction that leaks while idle holding locks.
run "ALTER ROLE $APP_ROLE SET idle_in_transaction_session_timeout = '$IDLE_TX_TIMEOUT'"

# Proactive visibility: slow queries and real temp spills land in the PG log so
# the next reconcile-style problem shows up before workers drop results.
run "ALTER SYSTEM SET log_min_duration_statement = '$LOG_MIN_DURATION'"
run "ALTER SYSTEM SET log_temp_files = '$LOG_TEMP_FILES'"

# NOTE: effective_cache_size is intentionally NOT set here. With the PGDATA
# dataset on primarycache=metadata, ARC does not cache data, so it should track
# shared_buffers (~32-40GB), NOT host RAM. Set it deliberately alongside any
# shared_buffers / primarycache change (see the cache-strategy note below).

run "SELECT pg_reload_conf()"

echo "== recorded, ACTIVATE ON NEXT RESTART (postmaster-context) ==" >&2

# Guarantee an operator can always connect when the app pool saturates — the
# exact thing that locked us out mid-incident.
run "ALTER SYSTEM SET superuser_reserved_connections = $SUPERUSER_RESERVED"

# Stop truncating query text at 1KB (diagnostics lost the tail of every query).
run "ALTER SYSTEM SET track_activity_query_size = $TRACK_QUERY_SIZE"

if [ "$DRY_RUN" != "1" ]; then
    echo "== verify ==" >&2
    admin -d "$DB" -c "SELECT rolname, rolconfig FROM pg_roles WHERE rolname = '$APP_ROLE';"
    admin -d "$DB" -c "
        SELECT name, setting, pending_restart FROM pg_settings
        WHERE name IN ('lock_timeout','idle_in_transaction_session_timeout',
                       'log_min_duration_statement','log_temp_files',
                       'superuser_reserved_connections','track_activity_query_size')
        ORDER BY name;"
fi

cat >&2 <<'EOF'

== OS / ZFS notes — the dataset is already well-tuned ==
PGDATA: rpool/zones/postgres/ROOT/zbe (PG runs in an OmniOS zone)
  recordsize=8K  compression=lz4  atime=off  -> already optimal for PG; leave them.
  logbias=latency -> fine for commit latency.

The one lever is the CACHE STRATEGY. primarycache=metadata means ARC caches only
metadata, never data blocks, so shared_buffers (32GB) is the ENTIRE data cache
while ~86GB of 128GB RAM sits idle. The ~99% buffer-cache hit shows this is fine
for OLTP; only the full-scan reconcile suffered, and that is now fixed in code
(work_mem + temp-table restructure). So memory tuning is OPTIONAL. To use the
idle RAM, pick ONE deliberately:

  A) Keep primarycache=metadata; raise shared_buffers 32GB -> 48-64GB (restart).
     Clean, no double-buffering. Then: ALTER SYSTEM SET effective_cache_size =
     '<new shared_buffers>'.
  B) Switch primarycache=all and raise zfs_arc_max (~64GB; illumos /etc/system
     `set zfs:zfs_arc_max=68719476736` + reboot, or live via mdb -kw). ARC then
     caches compressed data dynamically; keep shared_buffers 32GB and set
     effective_cache_size ~= 96GB.

Do NOT raise effective_cache_size on its own — under the current
primarycache=metadata it must track shared_buffers, not host RAM.

Optional, decide deliberately: full_page_writes=off is safe on ZFS copy-on-write
and cuts WAL volume:  ALTER SYSTEM SET full_page_writes = off; SELECT pg_reload_conf();
EOF

[ "$FAILED" = "1" ] && { echo "one or more statements FAILED (see above)" >&2; exit 1; }
echo "done." >&2
