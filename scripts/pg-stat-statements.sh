#!/bin/sh
# pg-stat-statements.sh — enable pg_stat_statements on the hopper primary.
#
# Without it we can only INFER which queries are slow. With it, the top
# offenders rank by total/mean time, rows, and temp/IO — the fastest way to
# turn "the DB feels slow" into a named query to fix.
#
# This requires a postmaster-context change (shared_preload_libraries), so it
# is a TWO-STEP operation with a Postgres RESTART in between. The script does
# the reversible ALTER SYSTEM in step 1, then you restart, then it does the
# CREATE EXTENSION in step 2. Run on the DB host as the postgres superuser.
#
# Overridable via env (defaults in brackets):
#   DB [hopper]   DB_HOST ['' = local]   DRY_RUN [0]
#   MAX [5000]    pg_stat_statements.max — distinct statements tracked
#
# Usage:
#   sh scripts/pg-stat-statements.sh          # step 1: stage the preload lib
#   <restart Postgres>                        # e.g. zone svcadm / pg_ctl restart
#   sh scripts/pg-stat-statements.sh          # step 2: CREATE EXTENSION + verify

set -u

PATH="$PATH:/usr/sbin:/sbin:/usr/bin"
export PATH

DB="${DB:-hopper}"
DB_HOST="${DB_HOST:-}"
DRY_RUN="${DRY_RUN:-0}"
MAX="${MAX:-5000}"

HOSTARG=""
[ -n "$DB_HOST" ] && HOSTARG="-h $DB_HOST"

# Superuser escalation ladder (mirrors pg-diag.sh / pg-tuning.sh).
# shellcheck disable=SC2086
if psql -U postgres $HOSTARG -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres $HOSTARG "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -u postgres psql "$@"; }
elif command -v pfexec >/dev/null 2>&1 && pfexec su postgres -c "psql -tAc 'SELECT 1'" >/dev/null 2>&1; then
    # Not `pfexec -u`: OmniOS pfexec has no -u flag (that is Solaris 11).
    admin() { pfexec su postgres -c "psql $*"; }
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -u postgres psql "$@"; }
else
    echo "error: need superuser psql access (db=$DB host=${DB_HOST:-local})" >&2
    exit 1
fi

# Distinguish "not superuser" from "cannot even reach $DB": the ladder above
# probes the default maintenance DB, and pg_hba may allow that while denying
# $DB — reporting that as a role problem cost real debugging time (2026-08-22).
if ! admin -d "$DB" -tAc 'SELECT 1' >/dev/null 2>&1; then
    echo "error: cannot connect to db=$DB as the selected admin role (pg_hba?)" >&2
    exit 1
fi
if [ "$(admin -d "$DB" -tAc "SELECT current_setting('is_superuser')" 2>/dev/null)" != "on" ]; then
    echo "error: connected role is not a superuser; ALTER SYSTEM would fail" >&2
    exit 1
fi

run() {
    printf '  %s\n' "$1" >&2
    [ "$DRY_RUN" = "1" ] && return 0
    # Hard stop on failure: each statement is its own psql, so without this a
    # failed ALTER is silently followed by the rest and leaves a partial
    # config staged in postgresql.auto.conf (observed 2026-08-22).
    admin -d "$DB" -v ON_ERROR_STOP=1 -qc "$1" || {
        echo "error: statement failed; aborting before staging a partial config" >&2
        exit 1
    }
}

# Already loaded? Then we are on the second pass: just create the extension.
loaded=$(admin -d "$DB" -tAc \
    "SELECT 1 FROM pg_settings WHERE name='shared_preload_libraries' AND setting LIKE '%pg_stat_statements%'" \
    2>/dev/null)

if [ "$loaded" != "1" ]; then
    echo "== step 1: stage pg_stat_statements in shared_preload_libraries ==" >&2
    # Append rather than overwrite — never clobber an existing preload list.
    # Read-modify-write from the shell: ALTER SYSTEM accepts only literal
    # values, never expressions or subqueries, so the merge cannot be done in
    # SQL (a subquery here is a syntax error — found the hard way 2026-08-22).
    cur=$(admin -d "$DB" -tAc "SHOW shared_preload_libraries" | tr -d ' ')
    case ",$cur," in
        *,pg_stat_statements,*) new="$cur" ;;
        ,,)                     new="pg_stat_statements" ;;
        *)                      new="$cur,pg_stat_statements" ;;
    esac
    run "ALTER SYSTEM SET shared_preload_libraries = '$new'"
    run "ALTER SYSTEM SET pg_stat_statements.max = $MAX"
    run "ALTER SYSTEM SET pg_stat_statements.track = 'top'"
    cat >&2 <<'EOF'

== staged. RESTART POSTGRES, then re-run this script. ==
shared_preload_libraries is postmaster-context — pg_reload_conf() is NOT enough.
Restart the postgres zone's service (or `pg_ctl restart`) during a quiet window,
then run this script again to CREATE EXTENSION.
EOF
    exit 0
fi

echo "== step 2: library loaded — creating extension + verifying ==" >&2
run "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"

if [ "$DRY_RUN" != "1" ]; then
    admin -d "$DB" -c "SELECT extversion FROM pg_extension WHERE extname='pg_stat_statements';"
    cat >&2 <<'EOF'

Ready. Let stats accumulate, then rank the offenders, e.g.:

  SELECT round(total_exec_time)        AS total_ms,
         calls,
         round(mean_exec_time, 2)      AS mean_ms,
         round(100*shared_blks_read /
               nullif(shared_blks_hit+shared_blks_read,0), 1) AS miss_pct,
         left(regexp_replace(query,'\s+',' ','g'), 90) AS query
  FROM pg_stat_statements
  ORDER BY total_exec_time DESC
  LIMIT 20;

Reset the baseline anytime with: SELECT pg_stat_statements_reset();
EOF
fi
