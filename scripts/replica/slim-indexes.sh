#!/bin/sh
# slim-indexes.sh — keep a disposable read replica's index set minimal.
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
# ALLOWLIST, not denylist (changed 2026-08-20). This script used to carry a
# hand-maintained list of indexes to DROP, which meant every index added to
# hopper landed on the replica by default and silently taxed apply until
# someone noticed and extended the list. It drifted exactly that way: by
# 2026-08-20 the master had 77 indexes across the published tables against a
# 21-name drop list, and 16 never-scanned indexes (~19 GB) were queued to be
# built here. The default is now inverted — the replica keeps ONLY what
# REPLICA_KEEP_INDEXES names, and anything else on a subscribed table is
# dropped. A new master-side index therefore costs the replica nothing until
# someone deliberately opts it in.
#
# The two lists below are a partition of every index hopper creates on a
# published table, and TestReplicaIndexPolicyIsComplete (replica_index_policy_test.go)
# fails the build when an index belongs to neither. REPLICA_DROP_INDEXES does
# not drive behaviour — anything absent from the keep list is dropped either
# way — it exists so that "we looked at this and the replica does not need it"
# is recorded rather than inferred from silence.
#
# Scope / safety:
#   * DROP INDEX CONCURRENTLY — prism readers never block; the one
#     constraint-backed entry uses a bounded-lock retry loop.
#   * Never drops a PRIMARY KEY, the configured replica identity, or any
#     constraint-backed index (those are handled via SLIM_CONSTRAINTS).
#     Uniqueness lost with sample_locations_sha256_path_key is enforced by the
#     master; apply replays its already-unique stream.
#   * Only touches tables this replica actually subscribes to (pg_subscription_rel),
#     so local-only tables keep their indexes.
#   * Restore DDL is captured to $HEAL_STATE_DIR/slim-index-restore.sql before
#     dropping. promote.sh replays it, because a replica promoted to PRIMARY
#     needs the worker-queue indexes back.
#   * Idempotent: re-running is a no-op once the replica is slim.
#
# Maintaining the lists: when hopper gains an index on a published table, the
# guard test fails until you put its name in one of the two lists. Put it in
# REPLICA_KEEP_INDEXES only if a replica read path needs it — prism's lookups
# or cyclotron's triage queues; when in doubt leave it out and check
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

# --- The policy -------------------------------------------------------------
# Indexes a replica read path needs. One name per line. Everything else on a
# subscribed table is dropped.
#
# Two consumers now, not one. prism's lookups came first; cyclotron's triage
# queues joined when its selection moved off the master. They want different
# indexes — prism probes single identities (purl_lookup, filename_trgm) while
# cyclotron walks ranked populations (bad_route_fresh, stranded_member) — so
# "prism does not scan it" is no longer sufficient reason to drop one.
REPLICA_KEEP_INDEXES='
idx_claims_name
idx_claims_signer
idx_label_events_sha
idx_reports_sha256_type_created
idx_samples_acquit_newest
idx_samples_bad_miss_newest
idx_samples_bad_miss_stale
idx_samples_bad_route_fresh
idx_samples_class_top_created
idx_samples_clean_release
idx_samples_discord_newest
idx_samples_corroborated_created
idx_samples_sighted_created
idx_samples_domain
idx_samples_eco_class_created
idx_samples_eco_top_created
idx_samples_ecosystem
idx_samples_feed
idx_samples_feed_top_created_done
idx_samples_filename_trgm
idx_samples_formula_top
idx_samples_fp_trait_newest
idx_samples_good_route_score
idx_samples_labeled_route
idx_samples_package_version
idx_samples_popular_ranked
idx_samples_purl_base
idx_samples_purl_lookup
idx_samples_second_newest
idx_samples_sighted_purl
idx_samples_stranded_member
idx_samples_top_ready_created
idx_samples_unconvicted_hostile_repair
idx_samples_unconvicted_hostile_stale
idx_samples_unconvicted_route_fresh
idx_samples_unconvicted_susp_repair
idx_samples_unconvicted_susp_stale
idx_samples_version_drift_newest
idx_sightings_review_queue
idx_sightings_subject
idx_sl_child_parents
idx_sl_containment
idx_sl_parent_child
idx_slh_sha256_retired
'

# Master-only: worker queues, ingest lookups, and covering variants no replica
# read path scans. Listed for the completeness guard only — see the header. If
# prism or cyclotron starts needing one, MOVE it to REPLICA_KEEP_INDEXES rather
# than deleting it from here, so the guard keeps passing.
#
# idx_popular_rank is here despite popular_packages being published, which looks
# wrong until you read the query: TriagePopular probes `EXISTS (SELECT 1 FROM
# popular_packages p WHERE p.purl_base = samples.purl_base)` and pulls `p.rank`
# through that same correlated subquery, so both go through the purl_base
# PRIMARY KEY. Nothing on the replica orders by rank, and the table is a few
# thousand rows anyway.
#
# NOTE: no comments inside the quoted lists — parseShellWordList (Go, embedded)
# splits the body on whitespace, so a '#' line would parse as index names and
# fail the guard.
# shellcheck disable=SC2034
REPLICA_DROP_INDEXES='
idx_samples_good_repair_newest
idx_samples_unknown_newest
idx_samples_candidate_keyset
idx_sightings_acquisition_recent
idx_sightings_recent
idx_popular_rank
idx_reports_created_at
idx_samples_analyzed_at
idx_samples_claimable
idx_samples_claimable_sha
idx_samples_claimed
idx_samples_created_at
idx_samples_feed_source
idx_samples_feed_source_mtime
idx_samples_file_type
idx_samples_formula
idx_samples_litmus_done
idx_samples_mtime
idx_samples_parent
idx_samples_pending_cleave_group
idx_samples_pending_litmus_group
idx_samples_pending_path
idx_samples_pending_sighted
idx_samples_pending_size
idx_samples_reconcile_toplevel
idx_samples_rescan_queue
idx_samples_review_interesting
idx_samples_review_newest
idx_samples_source_ecosystem
idx_samples_source_feed
idx_samples_stale_traits
idx_samples_stale_traits_pri2
idx_samples_top_created
idx_samples_top_ready_first_analyzed_coalesce
idx_samples_unanalyzed_id
idx_samples_updated_at
idx_sl_incoming_seen
idx_sl_reference
idx_sl_sha256
idx_sl_standalone
'

SLIM_CONSTRAINTS='sample_locations|sample_locations_sha256_path_key'

keep_csv=$(printf '%s\n' "$REPLICA_KEEP_INDEXES" | grep -v '^$' | sed "s/^/'/; s/\$/'/" | paste -sd, -)
[ -n "$keep_csv" ] || keep_csv="''"

# --- What to drop -----------------------------------------------------------
# Resolved from the live catalog, not a name list: every non-PK, non-identity,
# non-constraint-backed index on a table this replica subscribes to that the
# keep list does not name. A master-side index added after this script was last
# edited is therefore dropped by default rather than silently retained.
droppable_sql="
SELECT c.relname
  FROM pg_index i
  JOIN pg_class c ON c.oid = i.indexrelid
  JOIN pg_class t ON t.oid = i.indrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
 WHERE n.nspname = 'public'
   AND i.indrelid IN (SELECT srrelid FROM pg_subscription_rel)
   AND NOT i.indisprimary
   AND NOT i.indisreplident
   AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = i.indexrelid)
   AND c.relname NOT IN ($keep_csv)
 ORDER BY pg_relation_size(i.indexrelid) DESC"

targets=$(admin -d "$LOCAL_DB" -tA -c "$droppable_sql" | grep -v '^$' || true)

# Capture restore DDL for everything we are about to drop, BEFORE dropping, so
# promote.sh can rebuild a promoted primary's full index set.
mkdir -p "$HEAL_STATE_DIR" 2>/dev/null || true
restore="$HEAL_STATE_DIR/slim-index-restore.sql"
if [ -n "$targets" ]; then
    names_csv=$(printf '%s\n' "$targets" | sed "s/^/'/; s/\$/'/" | paste -sd, -)
    admin -d "$LOCAL_DB" -tA >>"$restore" <<SQL || warn "could not capture restore DDL (continuing)"
SELECT pg_get_indexdef(i.indexrelid) || ';'
  FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
 WHERE c.relname IN ($names_csv);
SQL
fi
admin -d "$LOCAL_DB" -tA >>"$restore" <<'SQL' || warn "could not capture constraint restore DDL (continuing)"
SELECT format('ALTER TABLE public.%I ADD CONSTRAINT %I %s;',
              t.relname, con.conname, pg_get_constraintdef(con.oid))
  FROM pg_constraint con JOIN pg_class t ON t.oid = con.conrelid
 WHERE con.conname = 'sample_locations_sha256_path_key';
SQL

dropped=0
for idx in $targets; do
    [ -n "$idx" ] || continue
    log "dropping $idx"
    admin -d "$LOCAL_DB" -c "DROP INDEX CONCURRENTLY IF EXISTS public.\"$idx\";" \
        || warn "drop of $idx failed (continuing)"
    dropped=$((dropped+1))
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
