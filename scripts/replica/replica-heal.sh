#!/bin/sh
# replica-heal.sh — keep a logical replica alive across schema drift that breaks
# apply but is safe to fix deterministically from the publisher's catalog.
#
# Logical replication does not replicate DDL, so the subscriber's apply worker
# dies (and, with disable_on_error=true, disables the subscription) when the
# local schema cannot accept what the publisher sends. Three such cases are
# safe and unambiguous to reconcile against the publisher's live catalog:
#   1. a newly ADDed published column the local table lacks; or
#   2. a column the publisher publishes PLAIN while it is still STORED-generated
#      locally — you cannot write a replicated value into a generated column; or
#   3. a whole published table that does not exist locally at all — e.g. a table
#      added to the publication between deploys (the gap that silently broke
#      'sightings': published on the master, never created here, so every reader
#      query hit "relation does not exist" while replication reported itself
#      healthy). It is recreated from the publisher's live catalog — columns plus
#      the primary key, which is the replica identity apply needs for streamed
#      UPDATE/DELETE — then the subscription REFRESHes to add the relation and
#      copy_data backfills it.
# This script restores LIVENESS by reconciling exactly those cases, then
# re-enables (and, for case 3, REFRESHes) the subscription.
#
# Design / scope (read before extending):
#   * LIVENESS, not parity. The job is "every published column exists locally
#     with a compatible type, in a table apply can write" so the worker can run.
#     Full canonical schema (secondary indexes, CHECK/FK constraints, NOT NULL
#     backfills) remains 'hopper init's job at deploy time; this heal is the
#     gap-filler between deploys. What it adds — a column, or a bare table with
#     its PK — gets reconciled to canonical by the next 'make replica'.
#   * BOUNDED, LOSSLESS HEALS ONLY — the three cases above, and nothing else.
#     ADD COLUMN (nullable / non-volatile default), ALTER COLUMN ... DROP
#     EXPRESSION, and CREATE TABLE (empty, from the publisher's catalog) are all
#     metadata-only fast operations that never rewrite or drop existing data.
#     Real migrations — drops, renames, true type changes — are never guessed:
#     it alerts and leaves the subscription disabled for a human + the next
#     deploy.
#   * VERSION-INDEPENDENT. It reads the publisher's live catalog as the source
#     of truth (not a migration list), so it consumes any future column or table
#     add — even ones newer than anything deployed here. No hopper binary needed.
#   * SAFE-BY-DEFAULT. It never disables a subscription merely because the
#     publisher was unreachable; it never re-enables a subscription that was
#     disabled for a non-schema reason; it only ever ADDs (never drops) to close
#     a gap.
#
# Runs as the postgres superuser (local admin) on a schedule (systemd timer on
# Linux, cron inside the FreeBSD jail). Idempotent; cheap when there's no drift.
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# PUBLICATION, SUBSCRIPTION (auto-detected when unset), PGPASSFILE,
# HEAL_STATE_DIR, HEAL_ALERT_CMD, HEAL_LOCK_TIMEOUT.

set -eu

REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
PUBLICATION="${PUBLICATION:-hopper_replica}"
SUBSCRIPTION="${SUBSCRIPTION:-}"
PGPASS="${PGPASSFILE:-$HOME/.pgpass}"
HEAL_STATE_DIR="${HEAL_STATE_DIR:-$HOME/.hopper-replica-heal}"
# Optional notifier: invoked as `$HEAL_ALERT_CMD <severity> <message>` on heal
# (severity=info) and on conditions needing a human (severity=warn). Unset =
# log only (journald/cron capture stdout+stderr regardless).
HEAL_ALERT_CMD="${HEAL_ALERT_CMD:-}"
# DDL lock wait. ADD COLUMN needs a brief ACCESS EXCLUSIVE lock; cap the wait so
# we never hang behind a long reader. Drift is rare, so a miss just retries next run.
HEAL_LOCK_TIMEOUT="${HEAL_LOCK_TIMEOUT:-15s}"

ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log()  { printf '%s replica-heal: %s\n'        "$(ts)" "$*"; }
warn() { printf '%s replica-heal: WARN %s\n'   "$(ts)" "$*" >&2; }
die()  { printf '%s replica-heal: ERROR %s\n'  "$(ts)" "$*" >&2; exit 1; }

validate_ident() {
    case "$2" in
        ""|[!A-Za-z_]*|*[!A-Za-z0-9_]*) die "$1 must be a simple identifier, got '$2'" ;;
    esac
}
validate_ident PUBLICATION "$PUBLICATION"
[ -n "$SUBSCRIPTION" ] && validate_ident SUBSCRIPTION "$SUBSCRIPTION"

mkdir -p "$HEAL_STATE_DIR" 2>/dev/null || die "cannot create state dir $HEAL_STATE_DIR"

# --- Maintenance gate ------------------------------------------------------
# setup.sh / rebuild.sh create this flag while they deliberately disable the
# subscription; healing through a rebuild would fight them. Bail quietly.
if [ -e "$HEAL_STATE_DIR/maintenance" ]; then
    log "maintenance flag present ($HEAL_STATE_DIR/maintenance) — skipping"
    exit 0
fi

# --- Single instance (portable mkdir lock; steals a dead lock) --------------
LOCK="$HEAL_STATE_DIR/lock"
if ! mkdir "$LOCK" 2>/dev/null; then
    oldpid=$(cat "$LOCK/pid" 2>/dev/null || true)
    if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
        log "another instance (pid $oldpid) running — skipping"
        exit 0
    fi
    rm -rf "$LOCK" 2>/dev/null || true
    mkdir "$LOCK" 2>/dev/null || { log "could not acquire lock — skipping"; exit 0; }
fi
echo "$$" > "$LOCK/pid"
trap 'rm -rf "$LOCK"' EXIT INT TERM

# --- Alerting (deduplicated so a stuck condition does not page forever) ------
# A condition's signature is hashed; we only fire HEAL_ALERT_CMD when it changes.
alert() {
    _sev="$1"; shift
    _msg="$*"
    _sig=$(printf '%s|%s' "$_sev" "$_msg" | cksum | cut -d' ' -f1)
    _prev=$(cat "$HEAL_STATE_DIR/alert.sig" 2>/dev/null || true)
    case "$_sev" in
        warn) warn "HEAL-ALERT $_msg" ;;
        *)    log  "HEAL-NOTIFY $_msg" ;;
    esac
    if [ "$_sig" != "$_prev" ]; then
        printf '%s' "$_sig" > "$HEAL_STATE_DIR/alert.sig"
        if [ -n "$HEAL_ALERT_CMD" ]; then
            # shellcheck disable=SC2086
            $HEAL_ALERT_CMD "$_sev" "$_msg" || warn "alert command failed: $HEAL_ALERT_CMD"
        fi
    fi
}
clear_alert() { rm -f "$HEAL_STATE_DIR/alert.sig" 2>/dev/null || true; }

# --- Local admin access (same ladder as setup.sh) --------------------------
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -n -u postgres psql "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -n -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -u postgres psql "$@"; }
else
    die "no admin access to local postgres (tried 'psql -U postgres', doas, sudo)"
fi

# Publisher reads are read-only catalog lookups; credentials come from .pgpass.
[ -f "$PGPASS" ] && export PGPASSFILE="$PGPASS"
remote() { psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" "$@"; }

# --- Resolve the subscription ----------------------------------------------
if [ -z "$SUBSCRIPTION" ]; then
    SUBSCRIPTION=$(admin -d "$LOCAL_DB" -tA <<'SQL' | head -n1
SELECT subname FROM pg_subscription
 WHERE subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
 ORDER BY subname;
SQL
)
    [ -n "$SUBSCRIPTION" ] || { log "no subscription in '$LOCAL_DB' — nothing to heal"; exit 0; }
fi
validate_ident SUBSCRIPTION "$SUBSCRIPTION"

sub_enabled() {
    admin -d "$LOCAL_DB" -tAc \
        "SELECT subenabled FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" | tr -d '[:space:]'
}
enabled=$(sub_enabled)
[ -n "$enabled" ] || die "subscription '$SUBSCRIPTION' not found in '$LOCAL_DB'"

# --- Parity diff: which published columns is the local schema missing? -------
# Publisher emits ready-to-run, fully-quoted ADD COLUMN DDL per published column
# (all quoting/typing done by Postgres' format()/format_type — safe to eval).
# Field 4 flags a column the publisher has NOT NULL but for which we cannot
# reproduce a fill (no usable default): we add it nullable and tell a human.
published=$(remote -tAF '|' -v pub="$PUBLICATION" <<'SQL' 2>/dev/null || true
SELECT format('%I.%I', n.nspname, c.relname),
       a.attname,
       format('ALTER TABLE %I.%I ADD COLUMN %I %s%s%s',
              n.nspname, c.relname, a.attname,
              format_type(a.atttypid, a.atttypmod),
              CASE WHEN ad.adbin IS NOT NULL
                    AND pg_get_expr(ad.adbin, ad.adrelid) NOT ILIKE '%nextval(%'
                   THEN ' DEFAULT ' || pg_get_expr(ad.adbin, ad.adrelid) ELSE '' END,
              CASE WHEN a.attnotnull AND ad.adbin IS NOT NULL
                    AND pg_get_expr(ad.adbin, ad.adrelid) NOT ILIKE '%nextval(%'
                   THEN ' NOT NULL' ELSE '' END),
       CASE WHEN a.attnotnull AND (ad.adbin IS NULL
                    OR pg_get_expr(ad.adbin, ad.adrelid) ILIKE '%nextval(%')
            THEN 'notnull_unenforced' ELSE '' END
  FROM pg_publication_tables pt
  JOIN pg_namespace n  ON n.nspname = pt.schemaname
  JOIN pg_class c      ON c.relname = pt.tablename AND c.relnamespace = n.oid
  JOIN pg_attribute a  ON a.attrelid = c.oid AND a.attname = ANY (pt.attnames)
  LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
 WHERE pt.pubname = :'pub' AND a.attnum > 0 AND NOT a.attisdropped
 ORDER BY 1, 2;
SQL
)
if [ -z "$published" ]; then
    # Could not read the publisher (down/unreachable) OR the publication is
    # empty. Either way: do NOT touch the subscription — just report.
    alert warn "cannot read publisher '$REMOTE_HOST' publication '$PUBLICATION' (down, or no published columns); left subscription '$SUBSCRIPTION' untouched (enabled=$enabled)"
    exit 1
fi

# Per published table: its primary-key DDL, reproduced from the publisher so a
# table this script has to CREATE (case 3) gets the replica identity apply needs
# for streamed UPDATE/DELETE. Emitted as "qt|ALTER TABLE ... ADD CONSTRAINT ...".
# Only tables that have a PK on the publisher appear; a published table without
# one is flagged when created (see pk_missing) rather than silently left
# identity-less. pg_get_constraintdef renders the fully-quoted, ready-to-run def.
published_pk=$(remote -tAF '|' -v pub="$PUBLICATION" <<'SQL' 2>/dev/null || true
SELECT format('%I.%I', n.nspname, c.relname),
       format('ALTER TABLE %I.%I ADD CONSTRAINT %I %s',
              n.nspname, c.relname, con.conname, pg_get_constraintdef(con.oid))
  FROM pg_publication_tables pt
  JOIN pg_namespace n     ON n.nspname = pt.schemaname
  JOIN pg_class c         ON c.relname = pt.tablename AND c.relnamespace = n.oid
  JOIN pg_constraint con  ON con.conrelid = c.oid AND con.contype = 'p'
 WHERE pt.pubname = :'pub'
 ORDER BY 1;
SQL
)

# Local table.column set (and which tables exist locally at all).
local_cols=$(admin -d "$LOCAL_DB" -tAF '|' <<'SQL'
SELECT format('%I.%I', n.nspname, c.relname), a.attname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
   AND n.nspname NOT IN ('pg_catalog', 'information_schema');
SQL
)
local_tables=$(printf '%s\n' "$local_cols" | cut -d'|' -f1 | sort -u)

# Columns that are STORED-generated locally. A published column is always plain
# on the publisher (a publication does not publish generated columns), so a
# column the publisher publishes but that is generated here makes apply fail —
# Postgres cannot write a replicated value into a generated column. The fix is
# ALTER COLUMN ... DROP EXPRESSION: metadata-only, retains values, no rewrite.
local_generated=$(admin -d "$LOCAL_DB" -tAF '|' <<'SQL'
SELECT format('%I.%I', n.nspname, c.relname), a.attname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
   AND a.attgenerated = 's'
   AND n.nspname NOT IN ('pg_catalog', 'information_schema');
SQL
)

# Compute the heals: whole tables to create (case 3), columns to add, and
# generated->plain conversions.
create_ddl=""         # newline-separated CREATE TABLE stubs for absent tables
created_tables=""     # space-separated tables created locally this run
missing_ddl=""        # newline-separated ADD COLUMN statements to run
missing_names=""      # space-separated table.col for logging
notnull_unenforced="" # space-separated table.col added nullable despite NOT NULL
generated_ddl=""      # newline-separated DROP EXPRESSION statements to run
generated_names=""    # space-separated table.col converted generated->plain
oldIFS=$IFS
IFS='
'
for line in $published; do
    qt=${line%%|*}; rest=${line#*|}
    col=${rest%%|*}; rest=${rest#*|}
    ddl=${rest%|*}; flag=${rest##*|}
    if ! printf '%s\n' "$local_tables" | grep -qxF "$qt"; then
        # Whole published table absent locally (case 3). Create it empty from the
        # publisher's catalog — once per table — then fall through so each of its
        # published columns is added below (they read as "missing"); the PK is
        # appended after the columns exist (see "Decide & act"). The per-column
        # ADD COLUMN is not listed as column drift — it is implied by the table.
        case " $created_tables " in
            *" $qt "*) ;;
            *)  create_ddl="${create_ddl}CREATE TABLE IF NOT EXISTS ${qt} ();
"
                created_tables="$created_tables $qt" ;;
        esac
        missing_ddl="${missing_ddl}${ddl};
"
        [ "$flag" = "notnull_unenforced" ] && notnull_unenforced="$notnull_unenforced $qt.$col"
        continue
    fi
    if ! printf '%s\n' "$local_cols" | grep -qxF "$qt|$col"; then
        # Published column absent locally → ADD it (publisher-supplied DDL).
        missing_ddl="${missing_ddl}${ddl};
"
        missing_names="$missing_names $qt.$col"
        [ "$flag" = "notnull_unenforced" ] && notnull_unenforced="$notnull_unenforced $qt.$col"
    elif printf '%s\n' "$local_generated" | grep -qxF "$qt|$col"; then
        # Present locally but STORED-generated while the publisher publishes it
        # plain → DROP EXPRESSION so apply can write the replicated value.
        generated_ddl="${generated_ddl}ALTER TABLE ${qt} ALTER COLUMN \"${col}\" DROP EXPRESSION;
"
        generated_names="$generated_names $qt.$col"
    fi
done
IFS=$oldIFS

# --- Decide & act ----------------------------------------------------------
# For each table we're creating, resolve its primary-key DDL (reproduced from
# the publisher above). It runs AFTER the table's columns exist and gives the
# new table the replica identity apply needs for streamed UPDATE/DELETE. A
# published table with no PK on the publisher yields no line here — record it
# (pk_missing) so a human sets a replica identity rather than us silently
# creating a table that will re-break apply on the first UPDATE.
pk_ddl=""
pk_missing=""
for qt in $created_tables; do
    pkline=$(printf '%s\n' "$published_pk" | grep -F "$qt|" | head -n1)
    if [ -n "$pkline" ]; then
        pk_ddl="${pk_ddl}${pkline#*|};
"
    else
        pk_missing="$pk_missing $qt"
    fi
done

# Order matters: CREATE TABLE -> ADD COLUMN -> ADD PRIMARY KEY -> DROP EXPRESSION.
heal_ddl="${create_ddl}${missing_ddl}${pk_ddl}${generated_ddl}"
heal_names="${missing_names}${generated_names}"
[ -n "$created_tables" ] && heal_names="$heal_names (created tables:$created_tables)"

if [ -z "$heal_ddl" ]; then
    # No healable drift (no missing column, no generated-vs-published mismatch).
    if [ "$enabled" = "t" ]; then
        clear_alert
        log "ok: '$SUBSCRIPTION' enabled, schema in parity with publisher"
        exit 0
    fi
    # Disabled but schema is fine → it tripped on a non-schema apply error
    # (conflict, etc.). Re-enabling blindly could just re-loop; needs a human.
    errcnt=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT coalesce(apply_error_count,0) FROM pg_stat_subscription_stats WHERE subname='$SUBSCRIPTION'" \
        | tr -d '[:space:]')
    alert warn "subscription '$SUBSCRIPTION' is DISABLED but schema is in parity — non-schema apply error (apply_error_count=${errcnt:-?}); not auto-re-enabling. Inspect logs / pg_stat_subscription_stats."
    exit 1
fi

# Healable drift confirmed → heal.
[ -n "$created_tables" ]  && log "new published table(s) on '$SUBSCRIPTION': creating locally from publisher catalog:$created_tables"
[ -n "$missing_names" ]   && log "additive drift on '$SUBSCRIPTION': adding missing column(s):$missing_names"
[ -n "$generated_names" ] && log "generated/plain drift on '$SUBSCRIPTION': converting to plain (DROP EXPRESSION):$generated_names"
[ -n "$pk_missing" ]      && alert warn "created table(s) have NO primary key on the publisher:$pk_missing — apply of UPDATE/DELETE will fail until a REPLICA IDENTITY is set; run 'make replica' to apply canonical schema."

# Disable during DDL so the apply worker's locks don't fight it. (If it was
# disabled by disable_on_error, this is a no-op.)
if [ "$enabled" = "t" ]; then
    log "disabling subscription for DDL"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c "ALTER SUBSCRIPTION $SUBSCRIPTION DISABLE;"
fi

# Apply the heal DDL atomically with a bounded lock wait. CREATE TABLE, ADD
# COLUMN (nullable / non-volatile default), ADD PRIMARY KEY, and ALTER COLUMN
# ... DROP EXPRESSION are all metadata-only fast, transactional ops — wrapping
# them in one transaction means a mid-sequence failure rolls back cleanly rather
# than leaving, say, a new table with columns but no PK for the next run to miss.
printf "BEGIN;\nSET LOCAL lock_timeout = '%s';\n%sCOMMIT;\n" "$HEAL_LOCK_TIMEOUT" "$heal_ddl" \
    | admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
    || { alert warn "failed to apply heal DDL on '$LOCAL_DB' (lock contention or bad type?); subscription left DISABLED. DDL targeted:$heal_names"; exit 1; }

# Re-verify before re-enabling — never re-arm a crash loop. Every published
# column must now exist locally AND be plain (attgenerated empty), so apply can
# write its replicated value.
local_state2=$(admin -d "$LOCAL_DB" -tAF '|' <<'SQL'
SELECT format('%I.%I', n.nspname, c.relname), a.attname, a.attgenerated
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
   AND n.nspname NOT IN ('pg_catalog','information_schema');
SQL
)
unhealed=""
IFS='
'
for line in $published; do
    qt=${line%%|*}; rest=${line#*|}; col=${rest%%|*}
    # A present-and-plain column prints as "qt|col|" (empty attgenerated field).
    printf '%s\n' "$local_state2" | grep -qxF "$qt|$col|" || unhealed="$unhealed $qt.$col"
done
IFS=$oldIFS

if [ -n "$unhealed" ]; then
    alert warn "after heal, these published columns are still missing or generated locally:$unhealed — subscription '$SUBSCRIPTION' left DISABLED. Run 'make replica'."
    exit 1
fi

log "re-enabling subscription '$SUBSCRIPTION'"
admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c "ALTER SUBSCRIPTION $SUBSCRIPTION ENABLE;"

# A table we just created is in the publication but not yet in this
# subscription's relation set — REFRESH adds it and copy_data backfills the
# existing rows, after which it streams. Only needed when a table was created;
# column heals don't change the rel set, and REFRESH is cheap for tables already
# in sync (only newly added rels are copied). Run after ENABLE so tablesync
# starts immediately.
if [ -n "$created_tables" ]; then
    log "refreshing subscription to pick up new table(s):$created_tables"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
        -c "ALTER SUBSCRIPTION $SUBSCRIPTION REFRESH PUBLICATION WITH (copy_data = true);" \
        || { alert warn "created table(s)$created_tables locally but REFRESH PUBLICATION failed on '$SUBSCRIPTION' — run 'ALTER SUBSCRIPTION $SUBSCRIPTION REFRESH PUBLICATION' by hand to start the backfill."; exit 1; }
fi

if [ -n "$notnull_unenforced" ]; then
    alert warn "healed drift, but added these NULLABLE despite publisher NOT NULL (no reproducible default):$notnull_unenforced — run 'make replica' to apply the canonical migration/backfill."
elif [ -z "$pk_missing" ]; then
    clear_alert
fi
alert info "healed drift on '$SUBSCRIPTION' —$heal_names; subscription re-enabled${created_tables:+ & refreshed}"
log "done"
