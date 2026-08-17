# bulkload.sh — accelerate a logical-replication initial COPY by deferring
# secondary-index maintenance (sourced by setup.sh; not executed directly).
#
# WHY: initial tablesync COPYs every row into a table that ALREADY has all its
# indexes, so the subscriber maintains each secondary B-tree per row. On a
# large, heavily-indexed table (hopper's sample_locations: 200M+ rows, 8
# indexes / 130GB of index) that per-row random-write maintenance — not the
# network — dominates: the copy runs for *days* and DECELERATES as the indexes
# grow, pinning the publisher's WAL the whole time (risking the
# max_slot_wal_keep_size backstop). Building the same indexes in bulk AFTER the
# copy is far cheaper (one sorted parallel pass per index).
#
# So, when a real copy is about to happen, setup.sh calls us to:
#   1. save each replicated table's non-primary index + unique-constraint DDL,
#   2. DROP those indexes — keeping the PRIMARY KEY, which is the replica
#      identity that streamed UPDATE/DELETE need during post-copy catch-up,
#   3. relax a few bulk-hostile GUCs (bigger checkpoints, parallel index
#      builds, autovacuum paused) — reloadable only, NO restart, and
#   4. after the copy, rebuild each table's indexes as soon as THAT table
#      reaches 'ready' (so sample_locations' indexes build while the bigger
#      samples table is still copying), then restore the GUCs and ANALYZE.
#
# NOT handled here (deliberately): restart-only knobs (fsync,
# full_page_writes, shared_buffers) and host-level ZFS tuning (sync=disabled).
# Those are big wins for a *disposable* replica but wrong as a blanket default
# for every replica, and can't be applied without a restart / from inside a
# jail. See scripts/replica/RUNBOOK.md ("Disposable-replica fast rebuild").
#
# Relies on the caller (setup.sh) having defined: admin() [psql as a local
# superuser], pg_sh() [run a command as the postgres OS user], log(), and the
# vars LOCAL_DB, SUBSCRIPTION, and (optionally) HEAL_DIR. State files live in
# postgres's world, so all reads/writes of them go through admin()'s \copy or
# pg_sh. Enabled by default; FAST_SYNC=false skips everything.

FAST_SYNC="${FAST_SYNC:-true}"
# maintenance_work_mem for the post-copy index builds. Bigger = fewer merge
# passes on the big indexes; sized down by default so it's safe on a small box.
# Raise it on a beefy replica: BULK_MAINT_MEM=8GB make rebuild-replica ...
BULK_MAINT_MEM="${BULK_MAINT_MEM:-1GB}"
BULK_MAX_PARALLEL_MAINT="${BULK_MAX_PARALLEL_MAINT:-4}"
BULK_MAX_WAL="${BULK_MAX_WAL:-32GB}"
# Poll cadence (seconds) while waiting for tablesync to finish.
BULK_POLL_SECS="${BULK_POLL_SECS:-15}"

# Set by bulkload_defer to the space-separated list of tables it deferred, for
# the caller to hand back to bulkload_finish. (Returned via a global rather
# than stdout because log() prints to stdout.)
BULK_DEFERRED=''
BULK_GUCS_ACTIVE=false

# GUCs we override during the load and RESET afterwards. RESET reverts only our
# postgresql.auto.conf override, so a value the operator set in postgresql.conf
# survives untouched.
_BULK_GUCS='maintenance_work_mem max_parallel_maintenance_workers max_wal_size autovacuum synchronous_commit wal_compression'

# State dir for the saved recreate DDL — under the healer's dir (postgres-owned
# and persistent) so an interrupted copy can be finished by re-running setup,
# or by hand from the logged files: a crash never silently leaves the replica
# index-less with no record of what to rebuild.
_bulk_state_dir() {
    if [ -n "${HEAL_DIR:-}" ]; then
        printf '%s/bulkload' "$HEAL_DIR"
    else
        printf '%s' "${TMPDIR:-/tmp}/hopper-bulkload"
    fi
}

# Sanitize a bare table name to a filename-safe token.
_bulk_safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9_' '_'; }

# Validate a bare, unqualified table identifier before we splice it into SQL.
_bulk_valid_table() {
    case "$1" in
        ""|[!A-Za-z_]*|*[!A-Za-z0-9_]*) return 1 ;;
        *) return 0 ;;
    esac
}

# _bulk_dump_reindex TABLE FILE — write the recreate DDL (all CREATE INDEXes
# first for parallel builds, then any UNIQUE-constraint promotions via USING
# INDEX) for TABLE's non-primary indexes to FILE. The \copy query is one
# physical line on purpose: psql meta-commands do not continue across newlines.
_bulk_dump_reindex() {
    _bt="$1"; _bf="$2"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
\copy (SELECT stmt FROM (SELECT regexp_replace(pg_get_indexdef(i.indexrelid), '^CREATE (UNIQUE )?INDEX ', 'CREATE \1INDEX IF NOT EXISTS ')||';' AS stmt, 1 AS ord, pg_relation_size(i.indexrelid) AS sz FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relname='$_bt' AND NOT i.indisprimary UNION ALL SELECT 'DO \$do\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='||quote_literal('public.'||t.relname)||'::regclass AND conname='||quote_literal(c.relname)||') THEN ALTER TABLE public.'||quote_ident(t.relname)||' ADD CONSTRAINT '||quote_ident(c.relname)||' UNIQUE USING INDEX '||quote_ident(c.relname)||'; END IF; END \$do\$;', 2, 0 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_constraint k ON k.conindid=i.indexrelid AND k.contype='u' WHERE n.nspname='public' AND t.relname='$_bt') q ORDER BY ord, sz DESC) TO '$_bf'
SQL
}

# _bulk_drop_indexes TABLE — drop every non-primary index on TABLE, using
# ALTER TABLE ... DROP CONSTRAINT for constraint-backed (UNIQUE) indexes and
# DROP INDEX for plain ones. Done server-side in one DO block.
_bulk_drop_indexes() {
    _bt="$1"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$bulk\$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT c.relname AS idx, k.conname AS con
          FROM pg_index i
          JOIN pg_class c ON c.oid = i.indexrelid
          JOIN pg_class t ON t.oid = i.indrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          LEFT JOIN pg_constraint k ON k.conindid = i.indexrelid AND k.contype IN ('u','x')
         WHERE n.nspname = 'public' AND t.relname = '$_bt' AND NOT i.indisprimary
    LOOP
        -- Drop each index in its own subtransaction so one failure doesn't
        -- roll back the whole batch. Notably a UNIQUE constraint that a foreign
        -- key depends on (e.g. samples_sha256_key, referenced by
        -- sample_locations) can't be dropped — catch it, keep that one index,
        -- and still drop all the others (the bulk of the copy-cost win).
        BEGIN
            IF r.con IS NOT NULL THEN
                EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', '$_bt', r.con);
            ELSE
                EXECUTE format('DROP INDEX IF EXISTS public.%I', r.idx);
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'bulkload: keeping %.% (could not drop: %)', '$_bt', coalesce(r.con, r.idx), SQLERRM;
        END;
    END LOOP;
END
\$bulk\$;
SQL
}

# bulkload_defer TABLE... — save + drop the deferrable indexes on each table,
# then relax the bulk GUCs. Sets BULK_DEFERRED to the tables actually deferred
# (those that had at least one non-primary index).
bulkload_defer() {
    BULK_DEFERRED=''
    [ "$FAST_SYNC" = "true" ] || return 0
    _sd=$(_bulk_state_dir)
    pg_sh "mkdir -p '$_sd'" 2>/dev/null || true
    _deferred=''
    for _t in "$@"; do
        _bulk_valid_table "$_t" || { log "fast-sync: skipping non-simple table name '$_t'"; continue; }
        _f="$_sd/reindex.$(_bulk_safe "$_t").sql"
        _bulk_dump_reindex "$_t" "$_f"
        # Skip tables with nothing to defer (e.g. reports: PK only).
        if ! pg_sh "test -s '$_f'" 2>/dev/null; then
            pg_sh "rm -f '$_f'" 2>/dev/null || true
            continue
        fi
        _n=$(pg_sh "grep -c ';' '$_f'" 2>/dev/null | tr -d '[:space:]')
        log "fast-sync: deferring ${_n:-?} index build(s) on '$_t' during copy"
        _bulk_drop_indexes "$_t"
        _deferred="$_deferred $_t"
    done
    BULK_DEFERRED="${_deferred# }"
    if [ -n "$BULK_DEFERRED" ]; then
        _bulk_apply_gucs
    fi
}

# _bulk_apply_gucs — capture + relax bulk GUCs if not already active. Shared by
# defer (before COPY) and resume_pending (index rebuild after an interrupted run).
# Capture each GUC's CURRENT value first, as a restore script, so finish puts
# back exactly what was there — including values a deploy script set via
# ALTER SYSTEM (e.g. max_wal_size=16GB). A plain ALTER SYSTEM RESET would
# wrongly revert those to the PG defaults.
_bulk_apply_gucs() {
    [ "${BULK_GUCS_ACTIVE:-false}" = true ] && return 0
    _gf="$(_bulk_state_dir)/guc-restore.sql"
    _in=$(printf "'%s'," $_BULK_GUCS | sed 's/,$//')
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
\copy (SELECT 'ALTER SYSTEM SET '||name||' = '''||setting||coalesce(unit,'')||''';' FROM pg_settings WHERE name IN ($_in)) TO '$_gf'
SQL
    log "fast-sync: relaxing bulk GUCs for the copy (maintenance_work_mem=$BULK_MAINT_MEM, autovacuum off)"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
ALTER SYSTEM SET maintenance_work_mem = '$BULK_MAINT_MEM';
ALTER SYSTEM SET max_parallel_maintenance_workers = $BULK_MAX_PARALLEL_MAINT;
ALTER SYSTEM SET max_wal_size = '$BULK_MAX_WAL';
ALTER SYSTEM SET autovacuum = off;
ALTER SYSTEM SET synchronous_commit = off;
ALTER SYSTEM SET wal_compression = off;
SELECT pg_reload_conf();
SQL
    BULK_GUCS_ACTIVE=true
}

# _bulk_srsubstate TABLE — print the tablesync state letter for TABLE under
# this subscription ('r' = ready), or empty if not registered yet.
_bulk_srsubstate() {
    admin -d "$LOCAL_DB" -tAc \
        "SELECT r.srsubstate
           FROM pg_subscription_rel r
           JOIN pg_subscription s ON s.oid = r.srsubid
           JOIN pg_class c ON c.oid = r.srrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE s.subname = '$SUBSCRIPTION' AND n.nspname = 'public' AND c.relname = '$1'" \
        2>/dev/null | tr -d '[:space:]'
}

# _bulk_reindex_one TABLE — rebuild TABLE's indexes from its saved DDL file and
# ANALYZE it, then drop the file. No-op if the file is gone (already rebuilt).
_bulk_reindex_one() {
    _bt="$1"; _bf="$(_bulk_state_dir)/reindex.$(_bulk_safe "$1").sql"
    pg_sh "test -f '$_bf'" 2>/dev/null || return 0
    log "fast-sync: '$_bt' copy done — rebuilding its indexes (parallel, maintenance_work_mem=$BULK_MAINT_MEM)"
    if admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -f "$_bf" >/dev/null; then
        admin -d "$LOCAL_DB" -c "ANALYZE public.$_bt" >/dev/null 2>&1 || true
        pg_sh "rm -f '$_bf'" 2>/dev/null || true
        log "fast-sync: '$_bt' indexes rebuilt"
    else
        log "fast-sync: WARNING — rebuilding '$_bt' indexes failed; DDL kept at $_bf (re-run it by hand)"
    fi
}

# bulkload_restore_gucs — restore the values captured before the bulk copy.
# This is also called from setup.sh's EXIT trap, so an apply error, setup
# failure, or operator interruption does not leave bulk-only GUCs in place.
bulkload_restore_gucs() {
    [ "${BULK_GUCS_ACTIVE:-false}" = true ] || return 0
    _gf="$(_bulk_state_dir)/guc-restore.sql"
    if pg_sh "test -s '$_gf'" 2>/dev/null; then
        if ! admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -f "$_gf" >/dev/null; then
            log "fast-sync: WARNING — could not restore captured bulk GUCs from $_gf"
            return 1
        fi
        admin -d "$LOCAL_DB" -tAc 'SELECT pg_reload_conf()' >/dev/null || return 1
        pg_sh "rm -f '$_gf'" 2>/dev/null || true
    else
        # No capture on hand (older state / interrupted) — RESET our overrides.
        admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<SQL
$(for g in $_BULK_GUCS; do printf 'ALTER SYSTEM RESET %s;\n' "$g"; done)
SELECT pg_reload_conf();
SQL
    fi
    BULK_GUCS_ACTIVE=false
    return 0
}

bulkload_cleanup() {
    bulkload_restore_gucs || true
}

# bulkload_resume_pending — pick up reindex-*.sql left by an interrupted prior
# run and merge those tables into BULK_DEFERRED so finish rebuilds them. Does
# not drop indexes again (COPY may already be done).
bulkload_resume_pending() {
    [ "$FAST_SYNC" = "true" ] || return 0
    _sd=$(_bulk_state_dir)
    _files=$(pg_sh "ls '$_sd'/reindex.*.sql 2>/dev/null" 2>/dev/null || true)
    [ -n "$_files" ] || return 0
    _pending=''
    for _f in $_files; do
        _base=${_f##*/}
        # reindex.<table>.sql — table names are [A-Za-z0-9_]+ from _bulk_safe.
        _t=$(printf '%s' "$_base" | sed -n 's/^reindex\.\(.*\)\.sql$/\1/p')
        _bulk_valid_table "$_t" || continue
        case " $_pending $BULK_DEFERRED " in
            *" $_t "*) ;;
            *) _pending="$_pending $_t" ;;
        esac
    done
    _pending="${_pending# }"
    [ -n "$_pending" ] || return 0
    log "fast-sync: resuming deferred index rebuild(s) from $_sd: $_pending"
    if [ -n "$BULK_DEFERRED" ]; then
        BULK_DEFERRED="$BULK_DEFERRED $_pending"
    else
        BULK_DEFERRED="$_pending"
    fi
    _bulk_apply_gucs
}

# bulkload_finish TABLE... — block until each deferred table finishes its copy,
# rebuilding its indexes as it does, then restore the bulk GUCs. Bails (leaving
# the DDL files) if the subscription disables itself on an apply error.
bulkload_finish() {
    [ "$FAST_SYNC" = "true" ] || return 0
    _remaining=$(printf '%s' "$*" | tr -s ' ')
    _remaining="${_remaining# }"
    [ -n "$_remaining" ] || return 0
    log "fast-sync: waiting for tablesync to finish, rebuilding indexes as each table completes (this blocks until the copy is done)"
    _beats=0
    while [ -n "$_remaining" ]; do
        _en=$(admin -d "$LOCAL_DB" -tAc \
            "SELECT subenabled FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" 2>/dev/null | tr -d '[:space:]')
        if [ "$_en" != "t" ]; then
            log "fast-sync: subscription '$SUBSCRIPTION' is no longer enabled (apply error / disable_on_error?)."
            log "fast-sync: leaving deferred-index DDL in $(_bulk_state_dir) — rebuild it after the subscription recovers."
            bulkload_restore_gucs || true
            return 1
        fi
        _next=''
        for _t in $_remaining; do
            if [ "$(_bulk_srsubstate "$_t")" = "r" ]; then
                _bulk_reindex_one "$_t"
            else
                _next="$_next $_t"
            fi
        done
        _remaining="${_next# }"
        if [ -n "$_remaining" ]; then
            _beats=$((_beats + 1))
            # Heartbeat roughly every ~5 minutes so a long copy shows progress.
            if [ $((_beats % 20)) -eq 0 ]; then
                log "fast-sync: still copying:$_remaining"
            fi
            sleep "$BULK_POLL_SECS"
        fi
    done
    log "fast-sync: all deferred indexes rebuilt — restoring GUCs to their pre-copy values"
    bulkload_restore_gucs
}
