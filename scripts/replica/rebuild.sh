#!/bin/sh
# rebuild-replica.sh — tear down a wedged replica and rebuild it from
# scratch. Use when the upstream replication slot has been invalidated
# (e.g. max_slot_wal_keep_size exceeded), or when stale local rows make an
# incremental/initial refresh impossible because of data conflicts.
#
# This is destructive: it TRUNCATEs the locally published tables and
# re-copies every row from the publisher. The table list is read from the
# publisher's publication at runtime, so newly published tables are included.
# setup.sh deliberately never truncates — Postgres' initial tablesync COPY
# appends, so a re-copy on top of stale rows would collide on primary keys.
# Guard with FORCE=true.
#
# Steps:
#   1. Disable + drop the local subscription (slot_name = NONE so DROP
#      doesn't block trying to reach the dead remote slot).
#   2. TRUNCATE every locally-present table in the publisher's publication
#      (RESTART IDENTITY CASCADE). Every one must be in REPLICA_SCHEMA.
#   3. Re-run setup.sh with COPY_DATA=true, which drops any orphan remote
#      slot, recreates the subscription, and triggers a fresh full copy (its
#      fast-sync drops the secondary indexes for the copy and rebuilds them).
#
# Idempotent: safe to re-run if interrupted. Re-running after success just
# re-copies again (the subscription is dropped and recreated each time).
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# SUBSCRIPTION, PUBLICATION, FORCE. setup.sh's own env (PGPASSFILE, …) is
# inherited and passed through.

set -eu

REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
PUBLICATION="${PUBLICATION:-hopper_replica}"
# Mirror setup.sh's per-host default so a bare `make rebuild-replica`
# targets the same subscription a bare `make replica` created. For a
# Bastille jail, pass SUBSCRIPTION explicitly (same as diagnose).
default_sub_suffix=$(hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_' | sed 's/_*$//')
[ -z "$default_sub_suffix" ] && default_sub_suffix="local"
SUBSCRIPTION="${SUBSCRIPTION:-hopper_replica_${default_sub_suffix}}"
FORCE="${FORCE:-false}"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }
validate_ident() {
    case "$2" in
        ""|[!A-Za-z_]*|*[!A-Za-z0-9_]*)
            die "$1 must be a simple PostgreSQL identifier, got '$2'"
            ;;
    esac
}

validate_ident SUBSCRIPTION "$SUBSCRIPTION"
validate_ident PUBLICATION "$PUBLICATION"
case "$FORCE" in
    true) ;;
    *) die "rebuild is destructive (TRUNCATEs + full re-copy). Re-run with FORCE=true to proceed." ;;
esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/replicated-tables.sh"

# --- Admin access probe ----------------------------------------------------
# Same ladder as setup.sh / promote.sh so this works on FreeBSD (doas/sudo),
# Debian/Arch (sudo), or a box with direct admin access.
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE=""
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="doas -n -u postgres"
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="doas -u postgres"
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="sudo -n -u postgres"
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="sudo -u postgres"
else
    die "no admin access to local postgres (tried 'psql -U postgres', doas, sudo)"
fi

if [ -z "$ESCALATE" ]; then
    admin() { psql -U postgres "$@"; }
    pg_sh() { sh -c "$1"; }
else
    # shellcheck disable=SC2086
    admin() { $ESCALATE psql "$@"; }
    # shellcheck disable=SC2086
    pg_sh() { $ESCALATE sh -c "$1"; }
fi

# Read the publisher's current publication before dropping the subscription.
# This keeps the destructive reset in step with the actual publication rather
# than this checkout's list, which setup.sh reconciles the publication to after.
if ! published_tables=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" \
        -tA -F '|' -c \
        "SELECT schemaname, tablename
           FROM pg_publication_tables
          WHERE pubname = '$PUBLICATION'
          ORDER BY schemaname, tablename"); then
    die "could not read publication '$PUBLICATION' from $REMOTE_HOST"
fi
[ -n "$published_tables" ] || die "publication '$PUBLICATION' has no tables on $REMOTE_HOST"

truncate_tables=''
while IFS='|' read -r schema table; do
    [ -n "$schema" ] || continue
    [ "$schema" = "$REPLICA_SCHEMA" ] \
        || die "publication '$PUBLICATION' contains $schema.$table; rebuild expects only $REPLICA_SCHEMA tables (run make replica first to reconcile the publication)"
    case "$table" in
        ""|[!A-Za-z_]*|*[!A-Za-z0-9_]*)
            die "publication '$PUBLICATION' contains unsupported table name '$table'" ;;
    esac

    local_table=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT to_regclass('$schema.$table') IS NOT NULL" | tr -d '[:space:]')
    if [ "$local_table" = "t" ]; then
        truncate_tables="$truncate_tables $schema.$table,"
    else
        log "Published table '$schema.$table' is not local; setup.sh refuses to subscribe until it exists"
    fi
done <<EOF
$published_tables
EOF

[ -n "$truncate_tables" ] || die "none of the publisher's published tables exist locally; refusing an empty rebuild"
truncate_tables=${truncate_tables%,}

# Suppress the schema-drift self-healer for the rebuild — it must not try to
# re-enable the subscription while we deliberately drop, truncate, and re-copy.
# (setup.sh, invoked at step 3, manages the same flag on its own exit.)
# shellcheck disable=SC2016
HEAL_DIR=$(pg_sh 'printf %s "${HEAL_STATE_DIR:-$HOME/.hopper-replica-heal}"' 2>/dev/null || true)
maint_off() { [ -n "${HEAL_DIR:-}" ] && pg_sh "rm -f '$HEAL_DIR/maintenance'" 2>/dev/null || true; }
[ -n "${HEAL_DIR:-}" ] && pg_sh "mkdir -p '$HEAL_DIR' && : > '$HEAL_DIR/maintenance'" 2>/dev/null || true
trap maint_off EXIT

# --- 1. Drop the wedged subscription locally -------------------------------
# slot_name = NONE dissociates from the (likely invalidated) remote slot so
# DROP SUBSCRIPTION doesn't hang or fail trying to remove it. setup.sh's
# orphan-slot cleanup drops the remote slot when it recreates the sub.
if admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" | grep -q 1; then
    log "Dropping wedged subscription '$SUBSCRIPTION'"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -v sub="$SUBSCRIPTION" <<'SQL'
ALTER SUBSCRIPTION :"sub" DISABLE;
ALTER SUBSCRIPTION :"sub" SET (slot_name = NONE);
DROP SUBSCRIPTION :"sub";
SQL
else
    log "Subscription '$SUBSCRIPTION' already absent — skipping drop"
fi

# --- 2. Clear the replicated tables ----------------------------------------
# RESTART IDENTITY resets id sequences. CASCADE also clears any local
# FK-dependent table that is not itself published.
log "Truncating published tables:$truncate_tables (full re-copy follows)"
admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c \
    "TRUNCATE $truncate_tables RESTART IDENTITY CASCADE;"

# --- 3. Recreate the subscription with a fresh full copy -------------------
# setup.sh recreates the role/db/schema (no-ops here), reconciles the
# publication, drops any orphan remote slot, and CREATE SUBSCRIPTION ...
# copy_data=true.
log "Re-running setup.sh for a fresh copy (COPY_DATA=true)"
COPY_DATA=true \
    REMOTE_HOST="$REMOTE_HOST" \
    REMOTE_USER="$REMOTE_USER" \
    REMOTE_DB="$REMOTE_DB" \
    PUBLICATION="$PUBLICATION" \
    LOCAL_DB="$LOCAL_DB" \
SUBSCRIPTION="$SUBSCRIPTION" \
    "$SCRIPT_DIR/setup.sh"

log "Rebuild complete. Monitor with: make diagnose-replica SUBSCRIPTION=$SUBSCRIPTION"
