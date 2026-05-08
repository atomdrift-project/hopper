#!/bin/sh
# promote-replica.sh — convert the local subscriber into a standalone
# primary, so the old publisher can be decommissioned. Assumes writes
# to the upstream are already stopped (so there's nothing to race
# against) and ~/.pgpass has upstream credentials.
#
# Steps performed here:
#   1. Verify the local replica is caught up to the publisher.
#   2. Drop the subscription locally (dissociated from the remote slot).
#   3. Drop the now-orphan replication slot on the publisher.
#   4. Verify the schema migrations (sample_locations) are in place.
#   5. Show a manual checklist for /etc/hosts + worker reconfig.
#
# Idempotent: re-running after success is a no-op. Intended to be run
# on the replica box (the one that's becoming the new primary).
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# SUBSCRIPTION, OFFLINE_PROMOTE.

set -eu

REMOTE_HOST="${REMOTE_HOST:-hopper}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
SUBSCRIPTION="${SUBSCRIPTION:-hopper_replica}"
OFFLINE_PROMOTE="${OFFLINE_PROMOTE:-0}"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

# Admin probe — same ladder as setup-replica.sh so this works cleanly on
# CachyOS (doas), FreeBSD (doas or sudo), Debian (sudo), or a box where
# the invoking user already has direct admin access.
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
    die "no admin access to local postgres"
fi
if [ -z "$ESCALATE" ]; then
    admin() { psql -U postgres "$@"; }
else
    # shellcheck disable=SC2086
    admin() { $ESCALATE psql "$@"; }
fi

remote() { psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" "$@"; }

# --- 1. Catch-up check -----------------------------------------------------
# Compare the subscriber's apply position to the publisher's current WAL
# LSN. They should be equal (or within a handful of bytes) since writes
# are stopped. Abort if the gap is large — something's still writing.

if ! admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" | grep -q 1; then
    log "Subscription '$SUBSCRIPTION' already gone — nothing to drop."
    log "(If this is an unexpected second run, the promotion likely already happened.)"
    exit 0
fi

if [ "$OFFLINE_PROMOTE" = "1" ]; then
    log "OFFLINE_PROMOTE=1 — skipping publisher catch-up check"
    log "This is a disaster-recovery promotion; any unapplied publisher WAL is assumed lost."
else
    log "Checking replica catch-up vs $REMOTE_HOST"
    remote_lsn=$(remote -tAc "SELECT pg_current_wal_lsn()" | tr -d '[:space:]')
    local_lsn=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT latest_end_lsn FROM pg_stat_subscription WHERE subname = '$SUBSCRIPTION' AND relid IS NULL" | tr -d '[:space:]')
    gap_bytes=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT pg_wal_lsn_diff('$remote_lsn'::pg_lsn, '$local_lsn'::pg_lsn)" | tr -d '[:space:]')
    log "publisher wal_lsn:   $remote_lsn"
    log "subscriber applied:  $local_lsn"
    log "lag:                 $gap_bytes bytes"

    # Arbitrary threshold: 1 MB. With writes stopped we expect 0; allow a bit of
    # slop for housekeeping activity (autovacuum WAL, etc.).
    case "$gap_bytes" in
        -*) die "subscriber is AHEAD of publisher — something is very wrong" ;;
        *)  if [ "${gap_bytes:-1}" -gt 1048576 ]; then
                die "replica is $gap_bytes bytes behind — writes may still be active on the primary. Stop writers, wait, and re-run."
            fi ;;
    esac
fi

# --- 2. Drop subscription locally -----------------------------------------
# We set slot_name = NONE first so DROP SUBSCRIPTION doesn't try to remove
# the slot on the publisher over a (possibly flaky) network. We clean the
# remote slot explicitly in the next step.

log "Disabling and dropping local subscription '$SUBSCRIPTION'"
admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -v sub="$SUBSCRIPTION" <<'SQL'
ALTER SUBSCRIPTION :"sub" DISABLE;
ALTER SUBSCRIPTION :"sub" SET (slot_name = NONE);
DROP SUBSCRIPTION :"sub";
SQL

# --- 3. Clean up the remote slot ------------------------------------------
# Orphan slots retain WAL forever, which eventually fills the publisher's
# disk. Drop ours so the old primary can be decommissioned cleanly.

if [ "$OFFLINE_PROMOTE" = "1" ]; then
    log "OFFLINE_PROMOTE=1 — skipping remote slot cleanup on unreachable publisher"
else
    log "Dropping replication slot '$SUBSCRIPTION' on $REMOTE_HOST"
    slot_exists=$(remote -tAc \
        "SELECT 1 FROM pg_replication_slots WHERE slot_name = '$SUBSCRIPTION'" 2>/dev/null | tr -d '[:space:]')
    if [ "$slot_exists" = "1" ]; then
        remote -v ON_ERROR_STOP=1 -v slot="$SUBSCRIPTION" <<'SQL'
SELECT pg_drop_replication_slot(:'slot');
SQL
    else
        log "slot already absent — skipping"
    fi
fi

# --- 4. Make this database publishable ------------------------------------

log "Ensuring local publication '$SUBSCRIPTION' publishes public.samples"
pub_exists=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT 1 FROM pg_publication WHERE pubname = '$SUBSCRIPTION'" | tr -d '[:space:]')
if [ "$pub_exists" = "1" ]; then
    pub_has_samples=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM pg_publication_tables WHERE pubname = '$SUBSCRIPTION' AND schemaname = 'public' AND tablename = 'samples'" \
        | tr -d '[:space:]')
    if [ "$pub_has_samples" != "1" ]; then
        admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -v pub="$SUBSCRIPTION" <<'SQL'
ALTER PUBLICATION :"pub" ADD TABLE public.samples;
SQL
    fi
else
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -v pub="$SUBSCRIPTION" <<'SQL'
CREATE PUBLICATION :"pub" FOR TABLE public.samples;
SQL
fi

log "Granting hopper role REPLICATION for future subscribers"
admin -v ON_ERROR_STOP=1 <<'SQL'
ALTER ROLE hopper WITH REPLICATION;
SQL

# --- 5. Verify/backfill the new schema is in place ------------------------
# Bail loudly if sample_locations migration hasn't run yet — we'd be
# promoting an incomplete DB.

log "Verifying sample_locations migration applied"
if ! admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'sample_locations'" | grep -q 1; then
    die "sample_locations table missing. Run 'make replica' or './hopper init' first, then re-run this script."
fi

loc_count=$(admin -d "$LOCAL_DB" -tAc "SELECT count(*) FROM sample_locations" | tr -d '[:space:]')
sample_count=$(admin -d "$LOCAL_DB" -tAc "SELECT count(*) FROM samples WHERE path <> ''" | tr -d '[:space:]')
log "sample_locations rows:     $loc_count"
log "samples with non-empty path: $sample_count"
if [ "$loc_count" -lt "$sample_count" ]; then
    log "Backfilling sample_locations from samples"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO sample_locations
    (sha256, path, parent_sha256, filename, source, feed, ecosystem, mtime, first_seen_at, last_seen_at)
SELECT sha256, path, parent, filename, source, feed, ecosystem, mtime, created_at, updated_at
  FROM samples
 WHERE path <> ''
ON CONFLICT (sha256, path) DO NOTHING;
SQL
    loc_count=$(admin -d "$LOCAL_DB" -tAc "SELECT count(*) FROM sample_locations" | tr -d '[:space:]')
    log "sample_locations rows after backfill: $loc_count"
fi

# --- 6. Manual steps left ------------------------------------------------
cat <<EOF

==> Database side of promotion complete.

What's left (manual):

  1. /etc/hosts on every machine that writes 'hopper':
     point 'hopper' at THIS host's IP (was: $REMOTE_HOST's IP).
     Check current mapping with:  getent hosts hopper

  2. Decommission or read-only the old primary so stray clients can't
     write to it:
       doas bastille service <old-primary-jail> postgresql stop

  3. Resume hopper workers (harvest, analyzers). They should now connect
     to THIS host via the updated 'hopper' hostname.

  4. Smoke-test: run a tiny ingest and confirm it shows up in BOTH tables:
       psql -h hopper -U hopper -d hopper -c 'SELECT count(*) FROM samples'
       psql -h hopper -U hopper -d hopper -c 'SELECT count(*) FROM sample_locations'

  5. Optional: set up reverse replication so the old primary becomes the
     warm replica going forward (publish from here, subscribe there).

If anything looks wrong, the old primary is still intact and unchanged —
flip /etc/hosts back and you're rolled back.
EOF
