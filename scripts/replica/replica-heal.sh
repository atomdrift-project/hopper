#!/bin/sh
# replica-heal.sh — keep a logical replica alive across *additive* schema drift.
#
# Logical replication does not replicate DDL. When the publisher gains a column
# (ALTER TABLE ... ADD COLUMN) the subscriber's apply worker dies with
# "missing replicated column" and — with disable_on_error=true — the
# subscription disables itself. This script restores LIVENESS by adding any
# published column the local table lacks, then re-enables the subscription.
#
# Design / scope (read before extending):
#   * LIVENESS, not parity. The job is "every published column exists locally
#     with a compatible type" so the apply worker can run. Canonical schema
#     (indexes, constraints, NOT NULL backfills) remains 'hopper init's job at
#     deploy time; this heal is the gap-filler between deploys. A column this
#     script adds gets reconciled to canonical by the next 'make replica'.
#   * ADDITIVE ONLY. It only ever ADDs missing columns. Drops, renames, and
#     type changes are real migrations: it never guesses at them — it alerts
#     and leaves the subscription disabled for a human + the next deploy.
#   * VERSION-INDEPENDENT. It reads the publisher's live catalog as the source
#     of truth (not a migration list), so it consumes any future column add —
#     even ones newer than anything deployed here. No hopper binary required.
#   * SAFE-BY-DEFAULT. It never disables a subscription merely because the
#     publisher was unreachable; it never re-enables a subscription that was
#     disabled for a non-schema reason.
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

# Compute missing columns (and missing whole tables, which we will NOT create).
missing_ddl=""        # newline-separated ALTER statements to run
missing_names=""      # space-separated table.col for logging
missing_table=""      # space-separated tables published but absent locally
notnull_unenforced="" # space-separated table.col added nullable despite NOT NULL
oldIFS=$IFS
IFS='
'
for line in $published; do
    qt=${line%%|*}; rest=${line#*|}
    col=${rest%%|*}; rest=${rest#*|}
    ddl=${rest%|*}; flag=${rest##*|}
    if ! printf '%s\n' "$local_tables" | grep -qxF "$qt"; then
        case " $missing_table " in *" $qt "*) ;; *) missing_table="$missing_table $qt" ;; esac
        continue
    fi
    if ! printf '%s\n' "$local_cols" | grep -qxF "$qt|$col"; then
        missing_ddl="${missing_ddl}${ddl};
"
        missing_names="$missing_names $qt.$col"
        [ "$flag" = "notnull_unenforced" ] && notnull_unenforced="$notnull_unenforced $qt.$col"
    fi
done
IFS=$oldIFS

# --- Decide & act ----------------------------------------------------------
if [ -n "$missing_table" ]; then
    # A whole published table is absent locally — that's hopper init's job, not
    # an additive column fix. Refuse to guess; page a human.
    alert warn "published table(s) absent locally:$missing_table — run 'make replica' (hopper init creates tables); subscription '$SUBSCRIPTION' left as-is (enabled=$enabled)"
    exit 1
fi

if [ -z "$missing_ddl" ]; then
    # No additive drift.
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

# Additive drift confirmed → heal.
log "additive schema drift on '$SUBSCRIPTION': adding missing column(s):$missing_names"

# Disable during DDL so the apply worker's locks don't fight ADD COLUMN. (If it
# was disabled by disable_on_error, this is a no-op.)
if [ "$enabled" = "t" ]; then
    log "disabling subscription for DDL"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c "ALTER SUBSCRIPTION $SUBSCRIPTION DISABLE;"
fi

# Apply the additive DDL with a bounded lock wait. ADD COLUMN (nullable, or with
# a non-volatile default) is a metadata-only fast operation in PG11+.
printf 'SET lock_timeout = %s;\n%s' "$HEAL_LOCK_TIMEOUT" "$missing_ddl" \
    | admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
    || { alert warn "failed to apply additive DDL on '$LOCAL_DB' (lock contention or bad type?); subscription left DISABLED. DDL was:$missing_names"; exit 1; }

# Re-verify parity before re-enabling — never re-arm a crash loop.
local_cols2=$(admin -d "$LOCAL_DB" -tAF '|' <<'SQL'
SELECT format('%I.%I', n.nspname, c.relname), a.attname
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
   AND n.nspname NOT IN ('pg_catalog','information_schema');
SQL
)
still_missing=""
IFS='
'
for line in $published; do
    qt=${line%%|*}; rest=${line#*|}; col=${rest%%|*}
    printf '%s\n' "$local_cols2" | grep -qxF "$qt|$col" || still_missing="$still_missing $qt.$col"
done
IFS=$oldIFS

if [ -n "$still_missing" ]; then
    alert warn "after heal, still missing:$still_missing — subscription '$SUBSCRIPTION' left DISABLED (could not reproduce these columns). Run 'make replica'."
    exit 1
fi

log "re-enabling subscription '$SUBSCRIPTION'"
admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c "ALTER SUBSCRIPTION $SUBSCRIPTION ENABLE;"

if [ -n "$notnull_unenforced" ]; then
    alert warn "healed drift, but added these NULLABLE despite publisher NOT NULL (no reproducible default):$notnull_unenforced — run 'make replica' to apply the canonical migration/backfill."
else
    clear_alert
fi
alert info "healed additive drift on '$SUBSCRIPTION' — added:$missing_names; subscription re-enabled"
log "done"
