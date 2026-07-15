#!/bin/sh
# slim-indexes.sh — drop the master-only indexes on a disposable read replica.
#
# 'hopper init' creates the full canonical index set, most of which exists for
# the MASTER's write pipeline: worker-queue partial indexes (*_pending,
# claimable, rescan_queue, seed_pool, ...) and feed-ingest lookups that no
# prism read path ever touches. On a logical replica every applied row change
# must maintain every index, so that dead weight is pure apply-throughput tax —
# measured 2026-07-13 on bilbo: ~590 GB of zero-scan indexes vs ~60 GB of
# actually-read ones, and the apply worker IO-bound on DataFileRead while a
# ~1 TB WAL backlog sat behind it. Dropping them cut the index working set
# below ARC size and multiplied apply throughput.
#
# Scope / safety:
#   * DROP INDEX CONCURRENTLY — prism readers never block; the one
#     constraint-backed entry uses a bounded-lock retry loop.
#   * The PK / replica identity and every index prism's queries use are NOT in
#     this list. Uniqueness lost with sample_locations_sha256_path_key is
#     enforced by the master; apply replays its already-unique stream.
#   * Restore DDL is captured to $HEAL_STATE_DIR/slim-index-restore.sql before
#     dropping. promote.sh replays it, because a replica promoted to PRIMARY
#     needs the worker-queue indexes back.
#   * Idempotent: IF EXISTS everywhere; re-running is a no-op.
#
# Maintaining the list: when hopper gains a new master-side index, add it here
# if prism doesn't read it. When in doubt, leave it in place and check
# pg_stat_user_indexes.idx_scan on a warm replica.
#
# Env: LOCAL_DB (=hopper), HEAL_STATE_DIR (=$HOME/.hopper-replica-heal),
# SLIM_LOCK_TIMEOUT (=15s), REPLICA_SLIM_INDEXES (=true; 'false' skips).

set -eu

LOCAL_DB="${LOCAL_DB:-hopper}"
HEAL_STATE_DIR="${HEAL_STATE_DIR:-$HOME/.hopper-replica-heal}"
SLIM_LOCK_TIMEOUT="${SLIM_LOCK_TIMEOUT:-15s}"

log()  { printf 'slim-indexes: %s\n' "$*"; }
warn() { printf 'slim-indexes: WARN %s\n' "$*" >&2; }

if [ "${REPLICA_SLIM_INDEXES:-true}" != "true" ]; then
    log "REPLICA_SLIM_INDEXES=$REPLICA_SLIM_INDEXES — skipping"
    exit 0
fi

# Same local-admin ladder as replica-heal.sh.
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -n -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -n -u postgres psql "$@"; }
else
    warn "no admin access to local postgres — skipping"
    exit 0
fi

# Master-only indexes: worker queues, ingest lookups, and covering variants
# prism never scans. One name per line. sample_locations_sha256_path_key is a
# UNIQUE constraint and is handled separately below.
SLIM_INDEXES='
idx_sl_sha256_parents
idx_sl_parent_child
idx_sl_last_seen
idx_sl_source
idx_samples_path
idx_samples_seed_pool
idx_samples_backfill_pending
idx_samples_toptraits_pending
idx_samples_litmus_done
idx_samples_feed_source
idx_samples_feed_source_created
idx_samples_parent
idx_samples_analyzed_at
idx_samples_feed_source_mtime
idx_samples_updated_at
idx_samples_label
idx_samples_review
idx_samples_score
idx_samples_source_feed
idx_samples_feed
idx_samples_stale_traits_pri
'
SLIM_CONSTRAINTS='sample_locations|sample_locations_sha256_path_key'

# Capture restore DDL for everything that still exists, BEFORE dropping, so
# promote.sh can rebuild a promoted primary's full index set.
mkdir -p "$HEAL_STATE_DIR" 2>/dev/null || true
restore="$HEAL_STATE_DIR/slim-index-restore.sql"
names_csv=$(printf '%s\n' "$SLIM_INDEXES" | grep -v '^$' | sed "s/^/'/; s/\$/'/" | paste -sd, -)
admin -d "$LOCAL_DB" -tA >>"$restore" <<SQL || warn "could not capture restore DDL (continuing)"
SELECT pg_get_indexdef(i.indexrelid) || ';'
  FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
 WHERE c.relname IN ($names_csv);
SELECT format('ALTER TABLE public.%I ADD CONSTRAINT %I %s;',
              t.relname, con.conname, pg_get_constraintdef(con.oid))
  FROM pg_constraint con JOIN pg_class t ON t.oid = con.conrelid
 WHERE con.conname = 'sample_locations_sha256_path_key';
SQL

dropped=0
for idx in $SLIM_INDEXES; do
    [ -n "$idx" ] || continue
    if admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM pg_class WHERE relname='$idx' AND relkind='i'" | grep -q 1; then
        log "dropping $idx"
        admin -d "$LOCAL_DB" -c "DROP INDEX CONCURRENTLY IF EXISTS public.\"$idx\";" \
            || warn "drop of $idx failed (continuing)"
        dropped=$((dropped+1))
    fi
done

oldIFS=$IFS; IFS='
'
for pair in $SLIM_CONSTRAINTS; do
    [ -n "$pair" ] || continue
    tbl=${pair%%|*}; con=${pair##*|}
    if admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM pg_constraint WHERE conname='$con'" | grep -q 1; then
        # ACCESS EXCLUSIVE needed briefly; bounded wait + retries so we slot in
        # between apply-worker transactions instead of queueing behind them.
        n=0
        while [ $n -lt 20 ]; do
            n=$((n+1))
            if admin -d "$LOCAL_DB" -c \
                "SET lock_timeout='$SLIM_LOCK_TIMEOUT'; ALTER TABLE public.\"$tbl\" DROP CONSTRAINT IF EXISTS \"$con\";" 2>/dev/null; then
                log "dropped constraint $con (attempt $n)"
                dropped=$((dropped+1))
                break
            fi
            sleep 5
        done
        [ $n -ge 20 ] && warn "could not drop constraint $con after $n attempts — re-run later"
    fi
done
IFS=$oldIFS

if [ "$dropped" -gt 0 ]; then
    log "dropped $dropped master-only index(es); restore DDL appended to $restore"
else
    log "nothing to drop — replica already slim"
fi
