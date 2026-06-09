#!/bin/sh
# rebuild-replica.sh — tear down a wedged replica and rebuild it from
# scratch. Use when the upstream replication slot has been invalidated
# (e.g. max_slot_wal_keep_size exceeded) and the apply worker can no
# longer resume, so an incremental refresh is impossible.
#
# This is destructive: it TRUNCATEs the locally replicated tables and
# re-copies every row from the publisher. setup.sh deliberately never
# truncates — Postgres' initial tablesync COPY appends, so a re-copy on
# top of stale rows would collide on the primary key. Guard with FORCE=true.
#
# Steps:
#   1. Disable + drop the local subscription (slot_name = NONE so DROP
#      doesn't block trying to reach the dead remote slot).
#   2. TRUNCATE samples, sample_locations, reports (RESTART IDENTITY CASCADE).
#   3. Re-run setup.sh with COPY_DATA=true, which drops any orphan remote
#      slot, recreates the subscription, and triggers a fresh full copy.
#
# Idempotent: safe to re-run if interrupted. Re-running after success just
# re-copies again (the subscription is dropped and recreated each time).
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# SUBSCRIPTION, FORCE. setup.sh's own env (PUBLICATION, PGPASSFILE, …) is
# inherited and passed through.

set -eu

REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
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
case "$FORCE" in
    true) ;;
    *) die "rebuild is destructive (TRUNCATEs + full re-copy). Re-run with FORCE=true to proceed." ;;
esac

SCRIPT_DIR=$(dirname "$0")

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
else
    # shellcheck disable=SC2086
    admin() { $ESCALATE psql "$@"; }
fi

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
# RESTART IDENTITY resets id sequences; CASCADE covers the FKs from
# sample_locations / reports to samples. This matches hopper's own reset.
log "Truncating samples, sample_locations, reports (full re-copy follows)"
admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 <<'SQL'
TRUNCATE samples, sample_locations, reports RESTART IDENTITY CASCADE;
SQL

# --- 3. Recreate the subscription with a fresh full copy -------------------
# setup.sh recreates the role/db (no-ops here), reconciles the publication,
# drops any orphan remote slot, and CREATE SUBSCRIPTION ... copy_data=true.
log "Re-running setup.sh for a fresh copy (COPY_DATA=true)"
COPY_DATA=true \
REMOTE_HOST="$REMOTE_HOST" \
REMOTE_USER="$REMOTE_USER" \
REMOTE_DB="$REMOTE_DB" \
LOCAL_DB="$LOCAL_DB" \
SUBSCRIPTION="$SUBSCRIPTION" \
    "$SCRIPT_DIR/setup.sh"

log "Rebuild complete. Monitor with: make diagnose-replica SUBSCRIPTION=$SUBSCRIPTION"
