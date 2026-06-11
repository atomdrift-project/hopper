#!/bin/sh
# rebuild.sh — tear down a wedged logical replica and rebuild it from
# scratch. Use this when the subscription's replication slot on the
# publisher has been invalidated (e.g. "could not start WAL streaming:
# can no longer access replication slot ... invalidated due to
# 'wal_removed'"). The idempotent `setup.sh` refresh path CANNOT recover
# that: for an existing subscription it only re-points the connection and
# REFRESHes the publication — it never recreates the dead publisher slot,
# so the apply worker just crash-loops on the same error.
#
# This script does the one thing setup.sh won't: drop the subscription
# (detaching the dead slot first so DROP stays local), drop the orphan
# slot on the publisher, TRUNCATE the local copy, then hand off to
# setup.sh which recreates the subscription with a fresh slot and a full
# initial copy (copy_data=true).
#
# DESTRUCTIVE: truncates the local replicated table before the re-copy.
# That's required — copy_data=true into a table that already has rows
# would fail with primary-key conflicts during initial sync. The local
# data is a replica anyway; the authoritative copy is upstream.
#
# Guarded: prompts before truncating unless FORCE=true.
#
# Assumes the same environment as setup.sh (see that script's header):
# local postgres running, ~/.pgpass with the upstream entry, admin access
# via psql -U postgres / doas / sudo.
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# LOCAL_USER, SUBSCRIPTION, REPLICATED_TABLE, FORCE, PGPASSFILE.

set -eu

REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
LOCAL_USER="${LOCAL_USER:-hopper}"
REPLICATED_TABLE="${REPLICATED_TABLE:-public.samples}"
FORCE="${FORCE:-false}"
PGPASS="${PGPASSFILE:-$HOME/.pgpass}"

# Subscription name is derived from the local hostname, identically to
# setup.sh, so the two scripts always agree on the slot/subscription this
# host owns.
default_sub_suffix=$(hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_' | sed 's/_*$//')
[ -z "$default_sub_suffix" ] && default_sub_suffix="local"
SUBSCRIPTION="${SUBSCRIPTION:-hopper_replica_${default_sub_suffix}}"

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
case "$FORCE" in true|false) ;; *) die "FORCE must be true or false, got '$FORCE'" ;; esac
# REPLICATED_TABLE is interpolated into a TRUNCATE, so constrain it to a
# simple schema.table of identifier characters (no quoting games).
case "$REPLICATED_TABLE" in
    *[!A-Za-z0-9_.]*|.*|*.|*..*|*.*.*) die "REPLICATED_TABLE must be schema.table of [A-Za-z0-9_], got '$REPLICATED_TABLE'" ;;
    *.*) ;;
    *) die "REPLICATED_TABLE must be qualified as schema.table, got '$REPLICATED_TABLE'" ;;
esac

# --- Sanity checks ---------------------------------------------------------
command -v pg_isready >/dev/null 2>&1 || die "pg_isready not found; install postgres client tools"
pg_isready -q || die "local postgres is not reachable — start it first"
[ -f "$PGPASS" ] || die "$PGPASS not found; add the upstream entry first"
chmod 600 "$PGPASS"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -x "$SCRIPT_DIR/setup.sh" ] || die "$SCRIPT_DIR/setup.sh not found or not executable"

# --- Admin access probe (matches setup.sh) ---------------------------------
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

# --- Confirmation ----------------------------------------------------------
rows=$(admin -d "$LOCAL_DB" -tAc "SELECT count(*) FROM $REPLICATED_TABLE" 2>/dev/null | tr -d '[:space:]' || true)
# Tables with a FK referencing the replicated table block a bare TRUNCATE, so
# the truncate below uses CASCADE — which also empties these. Surface them in
# the prompt so clearing them is a deliberate choice, not a surprise.
fk_deps=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT string_agg(DISTINCT conrelid::regclass::text, ', ')
       FROM pg_constraint
      WHERE confrelid = '$REPLICATED_TABLE'::regclass AND contype = 'f'" 2>/dev/null | tr -d '\n' || true)
log "About to REBUILD replica subscription '$SUBSCRIPTION':"
echo "    - drop local subscription '$SUBSCRIPTION' (detaching its dead slot)"
echo "    - drop orphan slot '$SUBSCRIPTION' on publisher $REMOTE_HOST"
echo "    - TRUNCATE $REPLICATED_TABLE on local '$LOCAL_DB' (${rows:-?} rows)"
[ -n "$fk_deps" ] && echo "      CASCADE — also empties FK-dependent table(s): $fk_deps"
echo "    - re-run setup.sh → fresh subscription + full initial copy"
if [ "$FORCE" != "true" ]; then
    if [ -r /dev/tty ]; then
        printf 'Proceed? [y/N] ' > /dev/tty
        read -r reply < /dev/tty
        case "$reply" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
    else
        die "refusing to truncate without a TTY; re-run with FORCE=true to confirm"
    fi
fi

# --- Remote credentials from .pgpass (for the publisher-side slot drop) ----
REMOTE_PW=$(awk -F: -v h="$REMOTE_HOST" -v u="$REMOTE_USER" -v d="$REMOTE_DB" '
    /^[[:space:]]*#/ { next }
    ($1==h||$1=="*") && ($3==d||$3=="*") && ($4==u||$4=="*") { print $5; exit }
' "$PGPASS")
[ -n "$REMOTE_PW" ] || die "no matching $REMOTE_HOST:*:$REMOTE_DB:$REMOTE_USER entry in $PGPASS"

# --- Tear down the local subscription --------------------------------------
sub_exists=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT 1 FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" | tr -d '[:space:]')
if [ "$sub_exists" = "1" ]; then
    log "Disabling and dropping subscription '$SUBSCRIPTION'"
    # DISABLE stops the apply worker; SET (slot_name = NONE) detaches the
    # publisher slot so DROP SUBSCRIPTION is purely local and won't try to
    # reach the (invalidated, possibly unreachable) slot — without this,
    # DROP can hang or error.
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -v sub="$SUBSCRIPTION" <<'SQL'
ALTER SUBSCRIPTION :"sub" DISABLE;
ALTER SUBSCRIPTION :"sub" SET (slot_name = NONE);
DROP SUBSCRIPTION :"sub";
SQL

    # Reap any wedged logical-replication workers still holding locks.
    killed=$(admin -d "$LOCAL_DB" -tAc "
        SELECT count(*) FROM (
            SELECT pg_terminate_backend(pid)
              FROM pg_stat_activity
             WHERE backend_type IN (
                 'logical replication apply worker',
                 'logical replication tablesync worker',
                 'logical replication parallel apply worker')
        ) t" | tr -d '[:space:]')
    [ "${killed:-0}" -gt 0 ] && log "Terminated ${killed} logical-replication worker(s)"
    sleep 1
else
    log "No local subscription '$SUBSCRIPTION' — nothing to drop"
fi

# --- Drop the orphan slot on the publisher ---------------------------------
# An invalidated slot still exists as a row until explicitly dropped, and
# setup.sh's CREATE SUBSCRIPTION would fail to recreate a same-named slot.
# It's inactive now (the worker is gone), so the drop will succeed.
PGPASSFILE="$PGPASS" psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" \
    -v ON_ERROR_STOP=1 -v slot="$SUBSCRIPTION" <<'SQL'
SELECT pg_drop_replication_slot(slot_name)
  FROM pg_replication_slots
 WHERE slot_name = :'slot';
SQL
log "Dropped orphan slot '$SUBSCRIPTION' on $REMOTE_HOST (if it existed)"

# --- Truncate the local copy so the full re-copy won't conflict ------------
# CASCADE is required: samples is referenced by FK(s) (e.g. reports), so a
# bare TRUNCATE is rejected. Those dependent rows reference sample ids that
# are about to be replaced by the fresh copy, so clearing them is correct.
log "Truncating $REPLICATED_TABLE (CASCADE) on '$LOCAL_DB'"
admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c "TRUNCATE TABLE $REPLICATED_TABLE CASCADE"

# --- Hand off to setup.sh for the fresh create + initial copy --------------
log "Handing off to setup.sh to recreate the subscription (full copy)"
exec env COPY_DATA=true \
    REMOTE_HOST="$REMOTE_HOST" REMOTE_USER="$REMOTE_USER" REMOTE_DB="$REMOTE_DB" \
    LOCAL_DB="$LOCAL_DB" LOCAL_USER="$LOCAL_USER" SUBSCRIPTION="$SUBSCRIPTION" \
    HOPPER="${HOPPER:-}" \
    PGPASSFILE="$PGPASS" "$SCRIPT_DIR/setup.sh"
