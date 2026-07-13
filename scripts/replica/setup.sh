#!/bin/sh
# setup-replica.sh — configure local PostgreSQL as a logical replica of a
# remote hopper instance. Idempotent: re-running reconciles state.
#
# Assumes:
#   * Local postgres is running (pg_isready ok) but otherwise unconfigured.
#   * ~/.pgpass contains the upstream credentials, e.g.
#         hopper:*:hopper:hopper:<password>
#   * Admin access to the local cluster is reachable via either
#     `psql -U postgres` or `sudo -u postgres psql` (the script probes both).
#   * The hopper binary is built (./hopper) or installed on $PATH.
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# LOCAL_USER, PUBLICATION, SUBSCRIPTION, COPY_DATA, PGPASSFILE.

set -eu

REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
LOCAL_USER="${LOCAL_USER:-hopper}"
PUBLICATION="${PUBLICATION:-hopper_replica}"
# Subscription name is per-replica because Postgres derives the
# replication slot name on the publisher from it: two replicas with the
# same subscription name would fight over a single slot. The local
# hostname is unique per host and stable across restarts; sanitize it to
# the [a-z0-9_] subset Postgres allows for identifiers.
default_sub_suffix=$(hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_' | sed 's/_*$//')
[ -z "$default_sub_suffix" ] && default_sub_suffix="local"
SUBSCRIPTION="${SUBSCRIPTION:-hopper_replica_${default_sub_suffix}}"
COPY_DATA="${COPY_DATA:-true}"
LEGACY_PUBLICATION="${LEGACY_PUBLICATION:-hopper_training}"
PGPASS="${PGPASSFILE:-$HOME/.pgpass}"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }
validate_ident() {
    case "$2" in
        ""|[!A-Za-z_]*|*[!A-Za-z0-9_]*)
            die "$1 must be a simple PostgreSQL identifier, got '$2'"
            ;;
    esac
}

validate_ident PUBLICATION "$PUBLICATION"
validate_ident SUBSCRIPTION "$SUBSCRIPTION"
validate_ident LEGACY_PUBLICATION "$LEGACY_PUBLICATION"
case "$COPY_DATA" in
    true|false) ;;
    *) die "COPY_DATA must be true or false, got '$COPY_DATA'" ;;
esac

# --- Sanity checks ---------------------------------------------------------
command -v pg_isready >/dev/null 2>&1 || die "pg_isready not found; install postgres client tools"
pg_isready -q || die "local postgres is not reachable — start it first"
[ -f "$PGPASS" ] || die "$PGPASS not found; add the upstream entry first"
# libpq ignores .pgpass unless perms are 0600.
chmod 600 "$PGPASS"

# --- Admin access probe ----------------------------------------------------
# Order: direct (trust/peer on stock FreeBSD and some Linux), then doas (BSD
# default), then sudo (Linux default). We pick whichever escalation tool is
# actually installed so this works on FreeBSD/DragonFly (doas or sudo),
# Debian/Ubuntu (sudo), CachyOS/Arch (sudo), etc.
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
    # $ESCALATE is a fixed, script-controlled prefix (never user-supplied), so
    # leaving it unquoted to word-split is intentional and safe here.
    # shellcheck disable=SC2086
    admin() { $ESCALATE psql "$@"; }
fi

# --- Remote credentials from .pgpass --------------------------------------
REMOTE_PW=$(awk -F: -v h="$REMOTE_HOST" -v u="$REMOTE_USER" -v d="$REMOTE_DB" '
    /^[[:space:]]*#/ { next }
    ($1==h||$1=="*") && ($3==d||$3=="*") && ($4==u||$4=="*") { print $5; exit }
' "$PGPASS")
[ -n "$REMOTE_PW" ] || die "no matching $REMOTE_HOST:*:$REMOTE_DB:$REMOTE_USER entry in $PGPASS"

# --- Publisher reachability preflight --------------------------------------
# Fail fast if the publisher is unreachable, instead of doing all the local
# schema work (role/db/hopper init) and only discovering the dead upstream at
# the publication step. DNS misses are common in fresh jails: a jail's
# /etc/hosts does not inherit the host's 'hopper-db' entry.
log "Checking publisher $REMOTE_HOST is reachable"
if probe=$(pg_isready -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" 2>&1); then
    : # rc 0: accepting connections
else
    rc=$?
    # pg_isready rc: 1 = reachable but rejecting (fine — auth/HBA is checked
    # later); 2 = no response; 3 = bad params. Only hard-fail when unreachable.
    if [ "$rc" -ge 2 ]; then
        case "$probe" in
            *"could not translate host name"*|*"not resolve"*|*"nodename nor servname"*|*"No address associated"*)
                die "publisher '$REMOTE_HOST' does not resolve from here ($probe).
       A Bastille jail does not inherit the host's /etc/hosts — add the mapping
       inside the jail, or re-run with REMOTE_HOST set to the publisher's IP:
         doas bastille cmd <jail> sh -c 'echo \"<ip>  $REMOTE_HOST\" >> /etc/hosts'" ;;
            *)
                die "publisher '$REMOTE_HOST' is not accepting connections ($probe).
       Confirm postgres is running there and pg_hba.conf admits this host." ;;
        esac
    fi
fi

# --- Guard: never run replica setup against the primary --------------------
# A replica is a SUBSCRIBER; the publisher (primary) is the only cluster that
# hosts the publication. If this local cluster already has it, we are ON the
# primary — and proceeding would run 'hopper init' (schema migrations) against
# the live database every replica streams from. Refuse before any change. A
# fresh replica has no such database/publication yet, so this is a no-op there.
guard_db=$(admin -tAc "SELECT 1 FROM pg_database WHERE datname = '$LOCAL_DB'" | tr -d '[:space:]')
if [ "$guard_db" = "1" ]; then
    guard_pub=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM pg_publication WHERE pubname = '$PUBLICATION'" | tr -d '[:space:]')
    [ "$guard_pub" = "1" ] && die "local database '$LOCAL_DB' hosts publication '$PUBLICATION' — this cluster is the PRIMARY/publisher, not a replica.
       Refusing replica setup against the primary (it would migrate the live publisher's schema).
       Run this on an actual replica, or correct REMOTE_HOST/LOCAL_DB."
fi

# --- Logical replication must be enabled on the local cluster -------------
wal_level=$(admin -tAc 'SHOW wal_level' | tr -d '[:space:]')
if [ "$wal_level" != "logical" ]; then
    log "Setting wal_level=logical (restart required)"
    admin -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET wal_level = 'logical'"
    die "restart postgres to apply wal_level=logical, then re-run this script"
fi

# --- Local role ------------------------------------------------------------
role_exists=$(admin -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$LOCAL_USER'" | tr -d '[:space:]')

# Existing .pgpass entry for localhost — if present we must reuse its password
# (we can't read the stored hash back out of postgres).
LOCAL_PW=$(awk -F: -v u="$LOCAL_USER" -v d="$LOCAL_DB" '
    /^[[:space:]]*#/ { next }
    $1=="localhost" && ($3==d||$3=="*") && ($4==u||$4=="*") { print $5; exit }
' "$PGPASS")

if [ "$role_exists" = "1" ]; then
    log "Role '$LOCAL_USER' already exists"
    [ -n "$LOCAL_PW" ] || die "role '$LOCAL_USER' exists but no localhost entry in $PGPASS; drop the role or add the entry and re-run"
else
    if [ -z "$LOCAL_PW" ]; then
        LOCAL_PW=$(openssl rand -hex 24 2>/dev/null) \
            || LOCAL_PW=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi
    log "Creating role '$LOCAL_USER'"
    # Substitutions (`:"name"`, `:'pw'`) are only performed by psql when SQL
    # arrives via stdin or -f; the -c path sends the string straight to the
    # server, so we feed this through a heredoc.
    admin -v ON_ERROR_STOP=1 -v role="$LOCAL_USER" -v pw="$LOCAL_PW" <<'SQL'
CREATE ROLE :"role" LOGIN PASSWORD :'pw';
SQL
fi

# Append .pgpass entry if one doesn't already cover localhost for this user/db.
if ! awk -F: -v u="$LOCAL_USER" -v d="$LOCAL_DB" '
    /^[[:space:]]*#/ { next }
    $1=="localhost" && ($3==d||$3=="*") && ($4==u||$4=="*") { found=1; exit }
    END { exit !found }
' "$PGPASS"; then
    log "Appending localhost entry to $PGPASS"
    printf 'localhost:*:%s:%s:%s\n' "$LOCAL_DB" "$LOCAL_USER" "$LOCAL_PW" >> "$PGPASS"
    chmod 600 "$PGPASS"
fi

# --- Local database --------------------------------------------------------
db_exists=$(admin -tAc "SELECT 1 FROM pg_database WHERE datname = '$LOCAL_DB'" | tr -d '[:space:]')
if [ "$db_exists" = "1" ]; then
    log "Database '$LOCAL_DB' already exists"
else
    log "Creating database '$LOCAL_DB' owned by '$LOCAL_USER'"
    admin -v ON_ERROR_STOP=1 -v db="$LOCAL_DB" -v owner="$LOCAL_USER" <<'SQL'
CREATE DATABASE :"db" OWNER :"owner";
SQL
fi

# --- Schema via hopper init (idempotent; uses migration tracking) ---------
# init applies the schema migrations the subscriber needs to match the
# publisher (the schema-parity gate below depends on this being current). A
# STALE binary silently skips migrations added after it was built, leaving the
# replica missing columns the publisher sends — the exact failure that wedges
# the subscription. The Makefile passes HOPPER as the just-built binary so
# `make replica` always inits with current migrations; honor it first, and
# warn loudly if we fall back to a possibly-stale `hopper` on PATH.
if [ -n "${HOPPER:-}" ]; then
    [ -x "$HOPPER" ] || die "HOPPER='$HOPPER' is not an executable — run 'make build'"
elif [ -x ./hopper ]; then
    HOPPER=./hopper
elif command -v hopper >/dev/null 2>&1; then
    HOPPER=hopper
    log "warning: using 'hopper' from PATH ($(command -v hopper)) — if it predates a schema migration, init will silently skip it. Prefer 'make replica' (rebuilds first)."
else
    die "hopper binary not found — run 'make build' first"
fi

# --- Self-heal coordination ------------------------------------------------
# install-heal.sh (called at the end) schedules replica-heal.sh to run as
# postgres and auto-fix additive schema drift. While THIS script disables the
# subscription to run DDL, raise a maintenance flag the healer honors so they
# don't race. pg_sh runs a command as the postgres OS user (same escalation as
# admin()) so files land where the healer — also postgres — reads them.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "$ESCALATE" ]; then
    pg_sh() { sh -c "$1"; }
else
    # shellcheck disable=SC2086
    pg_sh() { $ESCALATE sh -c "$1"; }
fi
HEAL_DIR=$(pg_sh 'printf %s "${HEAL_STATE_DIR:-$HOME/.hopper-replica-heal}"' 2>/dev/null || true)
maint_on()  { [ -n "${HEAL_DIR:-}" ] && pg_sh "mkdir -p '$HEAL_DIR' && : > '$HEAL_DIR/maintenance'" 2>/dev/null || true; }
maint_off() { [ -n "${HEAL_DIR:-}" ] && pg_sh "rm -f '$HEAL_DIR/maintenance'" 2>/dev/null || true; }
trap 'maint_off' EXIT
maint_on

# Fast-sync helpers: defer secondary-index maintenance during the initial COPY
# and rebuild in bulk afterwards (the single biggest lever for large, heavily
# indexed tables). Sourced here so admin()/pg_sh()/log()/HEAL_DIR are defined.
. "$SCRIPT_DIR/bulkload.sh"

# Disposable read-replica ZFS tuning (sync=disabled, logbias=throughput). A
# replica is read-only and rebuildable, so trade crash durability for write
# throughput — a big win for the bulk copy and steady apply. Default on; set
# ZFS_TUNE=false to skip. promote.sh reverts this when a replica becomes a
# durable primary. Best-effort: a no-op inside a Bastille jail (tune the pool
# from the host) and on non-ZFS boxes.
if [ "${ZFS_TUNE:-true}" = "true" ]; then
    PGDATA=$(admin -tAc 'SHOW data_directory' 2>/dev/null | tr -d '[:space:]') \
        "$SCRIPT_DIR/zfs-tune.sh" apply \
        || log "warning: ZFS tuning step failed (continuing)"
fi

# Apply-worker resilience: the 1-minute default wal_receiver_timeout tears down
# (and restarts from the slot's restart_lsn) any stream whose publisher-side
# decode is slow — e.g. while catching up a large backlog. That turns a slow
# catch-up into a restart loop. Give the receiver real slack.
admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER SYSTEM SET wal_receiver_timeout = '10min';
SELECT pg_reload_conf();
SQL

# Refuse to stack on top of a hung hopper init — each new run would just
# queue behind the first one's lock waits and make things worse.
if command -v pgrep >/dev/null 2>&1 && pgrep -f 'hopper init' >/dev/null 2>&1; then
    die "another 'hopper init' is already running (pid $(pgrep -f 'hopper init' | tr '\n' ' ')) — kill it first: pkill -9 -f 'hopper init'"
fi

# If a subscription exists, its apply + tablesync workers hold locks on the
# replicated tables. hopper init's DDL (CREATE INDEX, ALTER TABLE, etc.)
# would block on those locks. Disable the subscription and forcibly
# terminate every logical-replication worker before running DDL. Check by
# existence, not subenabled — a wedged worker from a prior run can outlive
# a DISABLE and still be holding locks even though the sub reads disabled.
# The subscription block below re-ENABLEs it after the migration finishes.
if admin -d "$LOCAL_DB" -tAc \
        "SELECT 1 FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" \
        | grep -q 1; then
    log "Stopping replica subscription during schema migration"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -v sub="$SUBSCRIPTION" <<'SQL'
ALTER SUBSCRIPTION :"sub" DISABLE;
SQL

    # Terminate any lingering logical-replication workers. Filter on
    # backend_type so we catch wedged workers that pg_stat_subscription
    # no longer lists (the launcher is deliberately excluded).
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

    # Give the postmaster a beat to reap them before we take locks.
    sleep 1
fi

# Show any pre-existing backends on this DB so a stuck one is visible before
# we queue behind it.
busy=$(admin -d "$LOCAL_DB" -tAc "
    SELECT count(*) FROM pg_stat_activity
     WHERE datname = '$LOCAL_DB' AND pid <> pg_backend_pid()
       AND backend_type = 'client backend'" | tr -d '[:space:]')
if [ "${busy:-0}" -gt 0 ]; then
    log "$busy existing client backend(s) on '$LOCAL_DB':"
    admin -d "$LOCAL_DB" -tA -F '  ' <<'SQL' | sed 's/^/    /'
SELECT pid, state, coalesce(wait_event, '-'),
       coalesce((now() - xact_start)::text, '-') AS xact_age,
       left(query, 80)
  FROM pg_stat_activity
 WHERE datname = current_database() AND pid <> pg_backend_pid()
   AND backend_type = 'client backend';
SQL
fi

# Set lock_timeout via DSN (pgx honors query-string GUCs reliably); keeps
# hopper init from hanging forever if something else holds a table lock.
log "Running '$HOPPER init' to ensure schema (lock_timeout=30s)"
"$HOPPER" init -db "postgres://$LOCAL_USER@localhost/$LOCAL_DB?sslmode=disable&lock_timeout=30s"

# Drop the master-only worker-queue/ingest indexes a read replica never scans.
# Runs right after init so a fresh replica never bulk-builds them and the
# steady-state apply worker never maintains them (~590 GB of write dead weight,
# see slim-indexes.sh). REPLICA_SLIM_INDEXES=false opts out; promote.sh
# restores them if this replica is ever promoted to primary.
log "Slimming replica indexes (REPLICA_SLIM_INDEXES=${REPLICA_SLIM_INDEXES:-true})"
LOCAL_DB="$LOCAL_DB" "$SCRIPT_DIR/slim-indexes.sh" \
    || log "warning: slim-indexes failed (continuing — replica keeps full index set)"

# --- Remote publication ----------------------------------------------------
# Reconcile the publisher before creating or refreshing the local
# subscription. A subscription can have a healthy apply worker even when its
# publication has no tables, so make the publication/table membership explicit.
log "Ensuring remote publication '$PUBLICATION' publishes public.samples"
psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" \
    -v ON_ERROR_STOP=1 <<SQL
DO \$$
DECLARE
    target_pub text := '$PUBLICATION';
    old_pub    text := '$LEGACY_PUBLICATION';
BEGIN
    IF target_pub <> old_pub
       AND EXISTS (SELECT 1 FROM pg_publication WHERE pubname = old_pub)
       AND NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = target_pub) THEN
        EXECUTE format('ALTER PUBLICATION %I RENAME TO %I', old_pub, target_pub);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = target_pub) THEN
        EXECUTE format('CREATE PUBLICATION %I FOR TABLE public.samples', target_pub);
    ELSIF NOT EXISTS (
        SELECT 1
          FROM pg_publication_tables
         WHERE pubname = target_pub
           AND schemaname = 'public'
           AND tablename = 'samples'
    ) THEN
        EXECUTE format('ALTER PUBLICATION %I ADD TABLE public.samples', target_pub);
    END IF;
END \$$;
SQL

# --- Schema parity gate ----------------------------------------------------
# A logical subscriber must have every column the publisher replicates. If it
# doesn't, the tablesync/apply worker dies on startup with "missing replicated
# column" and the launcher restarts it forever — a crash loop that pins the
# publisher's replication slot and retains WAL on the master without bound
# (it never advances restart_lsn because the initial copy never commits).
# 'hopper init' above is meant to bring the local schema current, but a stale
# hopper binary — one built before a newer column's migration was added —
# silently skips that migration and leaves the gap. Detect it here, before we
# create/refresh the subscription, instead of discovering it later as a wedged
# replica that's quietly eating the master's disk.
#
# Published column set: pg_publication_tables.attnames lists exactly the
# columns the publisher sends (all of them when the publication has no column
# list, as ours doesn't). We require the local table to be a superset.
log "Verifying local public.samples covers every column the publisher replicates"
published_cols=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAc \
    "SELECT unnest(attnames) FROM pg_publication_tables
      WHERE pubname = '$PUBLICATION' AND schemaname = 'public' AND tablename = 'samples'" \
    2>/dev/null | sort -u)
[ -n "$published_cols" ] || die "publisher reports no published columns for public.samples under '$PUBLICATION' — publication missing or unreachable"
local_cols=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT column_name FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'samples'" | sort -u)
[ -n "$local_cols" ] || die "local public.samples has no columns (table missing?) — run 'hopper init' first"
# Set subtraction "published minus local": grep -F reads each line of $local_cols
# as a fixed, whole-line (-x) pattern, and -v prints the published columns that
# match none of them. Done as a single set op rather than a shell for-loop —
# word-splitting $published_cols is IFS-dependent and brittle. (|| true: grep
# exits 1 when nothing is missing, which is the good case and must not trip
# 'set -e'.)
missing=$(printf '%s\n' "$published_cols" | grep -vxF "$local_cols" || true)
if [ -n "$missing" ]; then
    die "local public.samples is missing column(s) the publisher replicates: $(printf '%s' "$missing" | tr '\n' ' ')
       The local schema is behind the publisher — the hopper binary that ran
       'init' is likely stale (built before these columns' migrations existed).
       Rebuild it and re-run:  make build && make replica
       Skipping CREATE/REFRESH SUBSCRIPTION: subscribing now would crash-loop
       the apply worker and retain WAL on the publisher without bound."
fi

# --- Subscription ----------------------------------------------------------
# We keep the password out of argv by passing it through psql's -v mechanism
# (:'name' expands to a properly-quoted SQL literal inside the client).
CONN="host=$REMOTE_HOST dbname=$REMOTE_DB user=$REMOTE_USER password=$REMOTE_PW"

sub_exists=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT 1 FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" | tr -d '[:space:]')

# --- fast-sync: defer secondary-index maintenance during the copy ----------
# Drop each to-be-copied table's non-PK indexes before tablesync so the COPY
# runs index-light; they're rebuilt in bulk after (see bulkload.sh). The set
# that will actually be (re)copied = publication tables not already 'ready'
# locally: a fresh/rebuilt subscription has none ready (all copy); a refresh
# copies only newly-added tables. Best-effort — a hiccup here must not abort
# setup, it just means a slower (indexed) copy.
BULK_DEFERRED=''
if [ "$FAST_SYNC" = "true" ] && [ "$COPY_DATA" = "true" ]; then
    pub_tables=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAc \
        "SELECT tablename FROM pg_publication_tables
          WHERE pubname = '$PUBLICATION' AND schemaname = 'public'" 2>/dev/null)
    to_copy=''
    for t in $pub_tables; do
        ready=''
        if [ "$sub_exists" = "1" ]; then
            ready=$(admin -d "$LOCAL_DB" -tAc \
                "SELECT 1 FROM pg_subscription_rel r
                   JOIN pg_subscription s ON s.oid = r.srsubid
                   JOIN pg_class c ON c.oid = r.srrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE s.subname = '$SUBSCRIPTION' AND n.nspname = 'public'
                    AND c.relname = '$t' AND r.srsubstate = 'r'" | tr -d '[:space:]')
        fi
        [ "$ready" = "1" ] || to_copy="$to_copy $t"
    done
    if [ -n "$to_copy" ]; then
        # shellcheck disable=SC2086 # intentional word-split of the table list
        bulkload_defer $to_copy \
            || log "warning: fast-sync defer incomplete; copy proceeds with remaining indexes"
    fi
fi

if [ "$sub_exists" = "1" ]; then
    current_slot=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT COALESCE(subslotname, '') FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" \
        | tr -d '[:space:]')
    if [ "$current_slot" != "$SUBSCRIPTION" ]; then
        die "subscription '$SUBSCRIPTION' uses replication slot '$current_slot', expected '$SUBSCRIPTION'; rebuild the local replica instead of refreshing across a slot rename"
    fi

    log "Subscription '$SUBSCRIPTION' exists — refreshing connection + tables"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
        -v sub="$SUBSCRIPTION" \
        -v pub="$PUBLICATION" \
        -v conn="$CONN" <<SQL
ALTER SUBSCRIPTION :"sub" CONNECTION :'conn';
ALTER SUBSCRIPTION :"sub" SET PUBLICATION :"pub" WITH (refresh = false);
-- Contain schema drift: on any apply error (e.g. a missing replicated column
-- after the publisher gains one) the subscription disables itself instead of
-- crash-looping and pinning the publisher's WAL. replica-heal.sh re-enables it.
-- streaming=parallel ships large in-progress transactions incrementally
-- instead of buffering+spilling them whole on the publisher — important for
-- this workload's big full-table backfill migrations — and applies them via
-- parallel apply workers instead of spooling to disk and replaying at commit
-- (a single ~300 GB backfill txn stalled apply feedback for hours on
-- 2026-07-13 under plain streaming=on).
ALTER SUBSCRIPTION :"sub" SET (disable_on_error = true, streaming = parallel);
ALTER SUBSCRIPTION :"sub" ENABLE;
ALTER SUBSCRIPTION :"sub" REFRESH PUBLICATION WITH (copy_data = $COPY_DATA);
SQL
else
    # A prior run (or the retired sync-db target) may have left a replication
    # slot on the remote without a matching local subscription. CREATE
    # SUBSCRIPTION would fail to recreate it, so drop the orphan first.
    # libpq reads the password from ~/.pgpass for this connection.
    stale=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAc \
        "SELECT 1 FROM pg_replication_slots WHERE slot_name = '$SUBSCRIPTION'" \
        2>/dev/null | tr -d '[:space:]')
    if [ "$stale" = "1" ]; then
        log "Dropping orphan replication slot '$SUBSCRIPTION' on $REMOTE_HOST"
        psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" \
            -v ON_ERROR_STOP=1 -v slot="$SUBSCRIPTION" <<'SQL'
SELECT pg_drop_replication_slot(:'slot');
SQL
    fi

    log "Creating subscription '$SUBSCRIPTION' → $REMOTE_HOST / $PUBLICATION (copy_data=$COPY_DATA)"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
        -v sub="$SUBSCRIPTION" \
        -v pub="$PUBLICATION" \
        -v conn="$CONN" <<SQL
CREATE SUBSCRIPTION :"sub"
    CONNECTION :'conn'
    PUBLICATION :"pub"
    WITH (copy_data = $COPY_DATA, disable_on_error = true, streaming = parallel);
SQL
fi

# --- Sanity: confirm data is actually flowing ------------------------------
# The apply worker is asynchronous, so give it a beat before reading status.
sleep 2

log "Replication status:"

# Main apply worker status. pg_stat_subscription has one row per worker —
# the apply worker (relid IS NULL) plus one tablesync worker per table during
# initial copy — so we filter to just the apply worker here. pid NULL means
# it hasn't registered yet.
admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA <<'SQL' | sed 's/^/    /'
SELECT 'apply worker: ' ||
    CASE WHEN pid IS NULL THEN 'not connected yet (check logs if this persists)'
         ELSE format('pid=%s received_lsn=%s latest_end_lsn=%s',
                     pid,
                     COALESCE(received_lsn::text,   '0/0'),
                     COALESCE(latest_end_lsn::text, '0/0'))
    END
  FROM pg_stat_subscription
  WHERE subname = :'sub' AND relid IS NULL;
SQL

# Per-table: sync state + exact row count. quote_ident() makes the identifier
# shell/SQL-safe for the follow-up count query.
tables=$(admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA <<'SQL'
SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname) || '|' ||
       CASE r.srsubstate
           WHEN 'i' THEN 'initializing'
           WHEN 'd' THEN 'copying data'
           WHEN 'f' THEN 'finished table copy'
           WHEN 's' THEN 'synchronized'
           WHEN 'r' THEN 'ready (streaming)'
           ELSE 'state=' || r.srsubstate::text
       END
  FROM pg_subscription_rel r
  JOIN pg_subscription s ON s.oid = r.srsubid
  JOIN pg_class c ON c.oid = r.srrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE s.subname = :'sub'
  ORDER BY c.relname;
SQL
)

printf '%s\n' "$tables" | while IFS='|' read -r qualified state; do
    [ -n "$qualified" ] || continue
    rows=$(admin -d "$LOCAL_DB" -tAc "SELECT count(*) FROM $qualified" 2>/dev/null | tr -d '[:space:]')
    printf '    table %s: %s (%s rows)\n' "$qualified" "$state" "${rows:-?}"
done

# --- Schema-drift self-healer ----------------------------------------------
# Give the postgres user (which the healer runs as) the upstream entry in its
# own ~/.pgpass — the healer reads the publisher's catalog as postgres. Append
# only if absent; password goes via stdin, never argv.
PG_PGPASS=$(pg_sh 'printf %s "$HOME/.pgpass"' 2>/dev/null || true)
pat="^$REMOTE_HOST:[*]:$REMOTE_DB:$REMOTE_USER:"
have=$(pg_sh "grep -c '$pat' \"\$HOME/.pgpass\" 2>/dev/null" 2>/dev/null || true)
case "${have:-0}" in
    ''|0)
        printf '%s:*:%s:%s:%s\n' "$REMOTE_HOST" "$REMOTE_DB" "$REMOTE_USER" "$REMOTE_PW" \
          | pg_sh 'umask 077; f="$HOME/.pgpass"; touch "$f"; cat >> "$f"; chmod 600 "$f"' \
          && log "Added upstream entry to postgres ~/.pgpass (for replica-heal.sh)" \
          || log "warning: could not write postgres ~/.pgpass — add the upstream entry manually for the healer" ;;
esac

# Schedule the healer (systemd timer on Linux, postgres cron in a FreeBSD jail).
# Best-effort: a failure here doesn't fail replica setup.
log "Installing schema-drift self-heal schedule"
REMOTE_HOST="$REMOTE_HOST" REMOTE_USER="$REMOTE_USER" REMOTE_DB="$REMOTE_DB" \
LOCAL_DB="$LOCAL_DB" PUBLICATION="$PUBLICATION" SUBSCRIPTION="$SUBSCRIPTION" \
PGPASSFILE="${PG_PGPASS:-$PGPASS}" \
    "$SCRIPT_DIR/install-heal.sh" \
    || log "warning: self-heal schedule not installed — run scripts/replica/install-heal.sh manually"

# --- fast-sync: finish the deferred-index copy -----------------------------
# Block until tablesync completes, rebuilding each table's indexes as it
# finishes (so a smaller table's indexes build while a bigger one still
# copies), then restore the bulk GUCs. No-op when nothing was deferred, which
# preserves this script's fast async return on steady-state reconciles. The
# healer stays paused throughout (the maintenance flag is held until EXIT).
if [ -n "${BULK_DEFERRED:-}" ]; then
    log "Watch from another shell: make diagnose-replica SUBSCRIPTION=$SUBSCRIPTION"
    # shellcheck disable=SC2086 # intentional word-split of the table list
    bulkload_finish $BULK_DEFERRED \
        || log "warning: fast-sync did not finish cleanly — check messages above and $( { [ -n "${HEAL_DIR:-}" ] && printf '%s/bulkload' "$HEAL_DIR"; } || printf 'the bulkload state dir')"
fi

log "Done. Re-run anytime — this script is idempotent."
# psql's built-in \watch works on FreeBSD and Linux alike; GNU watch(1) does
# not exist on FreeBSD (watch(8) there is an unrelated tty-snooping tool).
log "Live monitor: psql -h localhost -U $LOCAL_USER -d $LOCAL_DB -c 'SELECT * FROM pg_stat_subscription \watch 2'"
log "Full status:  make diagnose-replica REMOTE_HOST=$REMOTE_HOST SUBSCRIPTION=$SUBSCRIPTION"
