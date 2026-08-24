#!/bin/sh
# setup-replica.sh — configure local PostgreSQL as a logical replica of a
# remote hopper instance. Idempotent and resumable: re-running reconciles
# schema/publication state, resumes after disable_on_error (init + ENABLE),
# resumes post-COPY catch-up (srsubstate f/s), and safely retries an
# interrupted mid-COPY (truncate those tables, then tablesync again).
# Lost replication slots still need rebuild-replica.
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
# LOCAL_USER, PUBLICATION, SUBSCRIPTION, COPY_DATA, PGPASSFILE,
# ZFS_TUNE, REPLICA_TUNE, REPLICA_MAX_PARALLEL_PER_GATHER,
# REPLICA_SLIM_INDEXES.

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
SETUP_EXACT_COUNTS="${SETUP_EXACT_COUNTS:-false}"
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
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/replicated-tables.sh"
REPLICATED_TABLES_SQL=$(printf "'%s'," $REPLICATED_TABLES | sed 's/,$//')
if [ -z "$ESCALATE" ]; then
    pg_sh() { sh -c "$1"; }
else
    # shellcheck disable=SC2086
    pg_sh() { $ESCALATE sh -c "$1"; }
fi

# A disabled subscription is a resume case, not a hard fail: disable_on_error
# often means schema drift that hopper init below will fix, or a mid-COPY
# conflict that the truncate+tablesync path retries. The subscription block
# re-ENABLEs after migration; if apply fails again the final health check
# exits nonzero. Lost slots still die later with a rebuild-replica pointer.
existing_sub_enabled=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT subenabled FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" \
    | tr -d '[:space:]')
if [ "$existing_sub_enabled" = "f" ]; then
    log "Subscription '$SUBSCRIPTION' is disabled — will reconcile schema, resume tablesync, and re-enable"
fi
HEAL_DIR=$(pg_sh 'printf %s "${HEAL_STATE_DIR:-$HOME/.hopper-replica-heal}"' 2>/dev/null || true)
maint_on()  { [ -n "${HEAL_DIR:-}" ] && pg_sh "mkdir -p '$HEAL_DIR' && : > '$HEAL_DIR/maintenance'" 2>/dev/null || true; }
maint_off() { [ -n "${HEAL_DIR:-}" ] && pg_sh "rm -f '$HEAL_DIR/maintenance'" 2>/dev/null || true; }
maint_on

# Fast-sync helpers: defer secondary-index maintenance during the initial COPY
# and rebuild in bulk afterwards (the single biggest lever for large, heavily
# indexed tables). Sourced here so admin()/pg_sh()/log()/HEAL_DIR are defined.
. "$SCRIPT_DIR/bulkload.sh"
trap 'bulkload_cleanup; maint_off' EXIT

# Readers may remain connected while setup reconciles the replica. Most runs
# have no schema work to do, and rejecting every active query made an
# idempotent repair unnecessarily disruptive. If DDL really conflicts with a
# reader, hopper init's bounded lock_timeout below reports that specific
# conflict instead of this script refusing all client activity up front.

# Classify per-table tablesync state so re-running make replica is safe:
#
#   r           — steady-state streaming; leave alone
#   f / s       — COPY already committed (FINISHEDCOPY / SYNCDONE). Postgres
#                 resumes catch-up without re-COPY; do NOT truncate or refuse
#   i / d       — COPY not finished. Tablesync COPY appends, so leftover rows
#                 collide on PKs when the worker retries. Truncate those tables
#                 after workers are stopped (below), then let tablesync restart
#
# A full rebuild-replica is still required for lost slots (checked later).
RETRY_TRUNCATE=''
catching_up=''
partial_tables=$(admin -d "$LOCAL_DB" -tA -F '|' -c \
    "SELECT c.relname, r.srsubstate
       FROM pg_subscription_rel r
       JOIN pg_subscription s ON s.oid = r.srsubid
       JOIN pg_class c ON c.oid = r.srrelid
      WHERE s.subname = '$SUBSCRIPTION'
      ORDER BY c.relname")
while IFS='|' read -r table state; do
    [ -n "$table" ] || continue
    case "$table" in
        *[!A-Za-z0-9_]*) die "unexpected table name from pg_subscription_rel: '$table'" ;;
    esac
    case "$state" in
        r) continue ;;
        f|s)
            catching_up="$catching_up $table(state=$state)"
            ;;
        i|d)
            has_rows=$(admin -d "$LOCAL_DB" -tAc \
                "SELECT EXISTS (SELECT 1 FROM public.$table LIMIT 1)" | tr -d '[:space:]')
            if [ "$has_rows" = 't' ]; then
                RETRY_TRUNCATE="$RETRY_TRUNCATE $table"
            fi
            ;;
        *)
            die "unexpected srsubstate '$state' for table '$table'; diagnose with make diagnose-replica, or rebuild: SUBSCRIPTION=$SUBSCRIPTION make rebuild-replica FORCE=true"
            ;;
    esac
done <<EOF
$partial_tables
EOF
RETRY_TRUNCATE=${RETRY_TRUNCATE# }
if [ -n "$catching_up" ]; then
    log "Resuming post-copy catch-up (COPY already finished; not truncating):$catching_up"
fi
if [ -n "$RETRY_TRUNCATE" ]; then
    if [ "$COPY_DATA" != "true" ]; then
        die "interrupted mid-COPY with leftover rows:$RETRY_TRUNCATE
       Refusing COPY_DATA=false resume (would leave empty/partial tables). Re-run with COPY_DATA=true, or: SUBSCRIPTION=$SUBSCRIPTION make rebuild-replica FORCE=true"
    fi
    log "Interrupted mid-COPY with leftover rows — will truncate for a clean tablesync retry:$RETRY_TRUNCATE"
fi

# PGDATA backs both the ZFS tuning below and the copy-on-write probe that
# decides whether full_page_writes can safely be turned off. Resolve it once.
PGDATA=$(admin -tAc 'SHOW data_directory' 2>/dev/null | tr -d '[:space:]')

# Disposable read-replica ZFS tuning (sync=disabled, logbias=throughput). A
# replica is read-only and rebuildable, so trade crash durability for write
# throughput — a big win for the bulk copy and steady apply. Default on; set
# ZFS_TUNE=false to skip. promote.sh reverts this when a replica becomes a
# durable primary. Best-effort: a no-op inside a Bastille jail (tune the pool
# from the host) and on non-ZFS boxes.
if [ "${ZFS_TUNE:-true}" = "true" ]; then
    PGDATA="$PGDATA" "$SCRIPT_DIR/zfs-tune.sh" apply \
        || log "warning: ZFS tuning step failed (continuing)"
fi

# --- Disposable read-replica server tuning ---------------------------------
# Everything here exists to keep the single-threaded apply worker fed. The
# 2026-08-24 catch-up stall is the worked example: the publisher was generating
# 11.9 MB/s of WAL and the replica was burning it down at 13.1 MB/s, a 1.2 MB/s
# net against a 151 GB backlog — 35 hours if nothing else moved, and negative
# whenever the master bursted. The walsender was idle 75% of the time blocked on
# Client:WalSenderWriteData (i.e. waiting for THIS box), while the apply worker
# sat 60% in IO:DataFileRead behind a device carrying 3.6 GB/s of reads at queue
# depth 65. Apply is serial, so its ceiling is 1/latency: at the 1.17 ms the
# device was actually returning, ~850 reads/s. Set REPLICA_TUNE=false to skip.
if [ "${REPLICA_TUNE:-true}" = "true" ]; then

    # Reader parallelism. A replica's job is to apply; serving reads is the
    # side job that must not starve it. Every parallel worker a feed query
    # forks scans with the bulkread ring buffer, and N concurrent readers each
    # forking max_parallel_workers_per_gather more of them multiply into the
    # device queue the apply worker is stuck behind — on 2026-08-24, 9.5 TB of
    # the replica's 13.6 TB lifetime reads were bulkread, against a single
    # apply worker doing 8 KB random reads. Capping it at 0 makes a heavy
    # report slower and leaves apply able to make progress; that is the right
    # trade on a box whose reason to exist is being current. Set on the role
    # rather than the cluster so maintenance (hopper init's index builds, which
    # read max_parallel_maintenance_workers instead) is untouched, and so the
    # value applies to prism/beamline/cyclotron connections at login.
    case "${REPLICA_MAX_PARALLEL_PER_GATHER:=0}" in
        ''|*[!0-9]*) die "REPLICA_MAX_PARALLEL_PER_GATHER must be a non-negative integer, got '$REPLICA_MAX_PARALLEL_PER_GATHER'" ;;
    esac
    log "Capping reader parallelism: $LOCAL_USER max_parallel_workers_per_gather=$REPLICA_MAX_PARALLEL_PER_GATHER"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
        -c "ALTER ROLE \"$LOCAL_USER\" SET max_parallel_workers_per_gather = $REPLICA_MAX_PARALLEL_PER_GATHER" \
        >/dev/null || log "warning: could not cap $LOCAL_USER parallelism (continuing)"

    # full_page_writes. After a checkpoint, the first write to each page ships
    # the whole 8 KB page into WAL so replay can repair a torn write. Measured
    # on the publisher 2026-08-21: FPIs are 13.4% of records but 64.7% of WAL
    # BYTES, and turning them off cut WAL 15.06 -> 6.14 MB/s. The replica pays
    # that tax on its own applied writes, and pays it on the same device the
    # apply worker is trying to read from.
    #
    # Only safe where a torn page is unreachable. Copy-on-write filesystems
    # never overwrite a live block — the write lands in a new extent and the
    # metadata flips atomically — so ZFS and btrfs cannot tear an 8 KB page,
    # and the publisher already runs this way. On an overwrite-in-place
    # filesystem (ext4, xfs, ufs) it is a corruption risk on power loss, so
    # probe rather than assume. Note this is a stronger requirement than the
    # replica being rebuildable: a silently corrupt replica serves wrong
    # answers to prism long before anyone thinks to rebuild it.
    #
    # Resolve the filesystem WITHOUT reading pgdata: it is mode 0700 owned by
    # postgres and this script runs as the operator, so `df -T "$PGDATA"` just
    # returns "Permission denied" and an empty type — which would silently and
    # permanently take the safe branch. Match the longest mount point that
    # prefixes the path instead. That is how the kernel resolves it anyway, and
    # the mount table is world-readable on both Linux (/proc/mounts) and
    # FreeBSD (`mount -p`), which share the device/mountpoint/type column
    # order. Falls back to df for anything neither one describes.
    fstype=$({ cat /proc/mounts 2>/dev/null || mount -p 2>/dev/null; } | awk -v path="$PGDATA" '
        { mp = $2; ty = $3 }
        {
            pfx = (mp == "/") ? "/" : mp "/"
            if (substr(path "/", 1, length(pfx)) == pfx && length(mp) >= best) {
                best = length(mp); type = ty
            }
        }
        END { print type }
    ')
    [ -n "$fstype" ] || fstype=$(df -T "$PGDATA" 2>/dev/null | awk 'NR==2 {print $2}')
    case "$fstype" in
        zfs|btrfs)
            log "Disabling full_page_writes (pgdata is $fstype, copy-on-write — torn pages unreachable)"
            admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
                -c "ALTER SYSTEM SET full_page_writes = off" >/dev/null \
                || log "warning: could not disable full_page_writes (continuing)"
            ;;
        *)
            log "Leaving full_page_writes on (pgdata fs '${fstype:-unknown}' is not known copy-on-write)"
            ;;
    esac

    # checkpoint_timeout. FPIs are generated on the first touch of each page
    # after a checkpoint, so checkpoint frequency sets the FPI rate — the stock
    # 5 minutes regenerates them twelve times an hour. 30 minutes matches the
    # publisher and is the milder half of the same lever, which is why it is
    # applied unconditionally: it helps on the filesystems where the probe
    # above declined to turn full_page_writes off, and it costs only a longer
    # crash recovery on a box that is rebuildable anyway.
    #
    # wal_receiver_timeout. The 1-minute default tears down (and restarts from
    # the slot's restart_lsn) any stream whose publisher-side decode is slow —
    # e.g. while catching up a large backlog. That turns a slow catch-up into a
    # restart loop. Give the receiver real slack.
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER SYSTEM SET wal_receiver_timeout = '10min';
ALTER SYSTEM SET checkpoint_timeout = '30min';
SELECT pg_reload_conf();
SQL
else
    log "REPLICA_TUNE=false — leaving server tuning alone"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER SYSTEM SET wal_receiver_timeout = '10min';
SELECT pg_reload_conf();
SQL
fi

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

# Truncate tables left mid-COPY (state i/d with rows). Must run with
# tablesync/apply workers stopped — COPY appends, so a retry without an empty
# table hits duplicate keys. Avoid CASCADE so a ready sibling table is not
# wiped via FK; if truncate fails, fall back to rebuild-replica.
if [ -n "${RETRY_TRUNCATE:-}" ]; then
    trunc_list=''
    for t in $RETRY_TRUNCATE; do
        trunc_list="$trunc_list public.$t,"
    done
    trunc_list=${trunc_list%,}
    log "Truncating interrupted mid-COPY tables: $trunc_list"
    if ! admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c \
            "TRUNCATE $trunc_list RESTART IDENTITY;"; then
        die "could not truncate interrupted mid-COPY tables ($RETRY_TRUNCATE) — FK dependencies may require a full rebuild: SUBSCRIPTION=$SUBSCRIPTION make rebuild-replica FORCE=true"
    fi
fi

# Set lock_timeout via DSN (pgx honors query-string GUCs reliably); keeps
# hopper init from hanging forever if something else holds a table lock.
# -replica makes init consult the same REPLICA_KEEP_INDEXES allowlist that
# slim-indexes.sh applies below, so the master-only indexes are never built here
# in the first place. Without it init builds the full canonical set and
# slim-indexes.sh drops it moments later — a round trip that is not free on a
# multi-hundred-GB sample_locations, and that on 2026-08-21 consumed the last
# of the replica's disk and broke apply with ENOSPC.
#
# Probed rather than passed blindly: an older hopper on PATH would exit(2) on
# the unknown flag, and retrying on failure would be indistinguishable from a
# genuine init error.
if "$HOPPER" init -h 2>&1 | grep -q -- '-replica'; then
    REPLICA_INIT_FLAG=-replica
else
    REPLICA_INIT_FLAG=
    log "warning: $HOPPER predates 'init -replica' — the replica will bulk-build indexes slim-indexes.sh then drops; rebuild with 'make replica'"
fi

log "Running '$HOPPER init${REPLICA_INIT_FLAG:+ $REPLICA_INIT_FLAG}' to ensure schema (lock_timeout=30s)"
# shellcheck disable=SC2086 # REPLICA_INIT_FLAG is a single literal flag or empty
"$HOPPER" init $REPLICA_INIT_FLAG -db "postgres://$LOCAL_USER@localhost/$LOCAL_DB?sslmode=disable&lock_timeout=30s"

# Drop the master-only worker-queue/ingest indexes a read replica never scans.
# With 'init -replica' above this is now a no-op on a fresh replica (they were
# never built); it remains the backstop that reconciles a replica created before
# that flag existed, or one whose policy changed since. REPLICA_SLIM_INDEXES=false
# opts out; promote.sh restores them if this replica is ever promoted to primary.
log "Slimming replica indexes (REPLICA_SLIM_INDEXES=${REPLICA_SLIM_INDEXES:-true})"
LOCAL_DB="$LOCAL_DB" "$SCRIPT_DIR/slim-indexes.sh" \
    || log "warning: slim-indexes failed (continuing — replica keeps full index set)"

# --- Remote publication ----------------------------------------------------
# Reconcile the publisher before creating or refreshing the local
# subscription. A subscription can have a healthy apply worker even when its
# publication has no tables, so make the publication/table membership explicit.
log "Ensuring remote publication '$PUBLICATION' publishes: $REPLICATED_TABLES"
psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" \
    -v ON_ERROR_STOP=1 <<SQL
DO \$$
DECLARE
    target_pub text := '$PUBLICATION';
    old_pub    text := '$LEGACY_PUBLICATION';
    t          text;
    replicated text[] := ARRAY[$REPLICATED_TABLES_SQL];
BEGIN
    IF target_pub <> old_pub
       AND EXISTS (SELECT 1 FROM pg_publication WHERE pubname = old_pub)
       AND NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = target_pub) THEN
        EXECUTE format('ALTER PUBLICATION %I RENAME TO %I', old_pub, target_pub);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = target_pub) THEN
        EXECUTE format('CREATE PUBLICATION %I', target_pub);
    END IF;

    FOREACH t IN ARRAY replicated LOOP
        IF EXISTS (
            SELECT 1
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public'
               AND c.relname = t
               AND c.relkind IN ('r', 'p')
        ) AND NOT EXISTS (
            SELECT 1
              FROM pg_publication_tables
             WHERE pubname = target_pub
               AND schemaname = 'public'
               AND tablename = t
        ) THEN
            EXECUTE format('ALTER PUBLICATION %I ADD TABLE public.%I', target_pub, t);
            RAISE NOTICE 'added table % to publication %', t, target_pub;
        END IF;
    END LOOP;
END \$$;
SQL

# --- Schema parity gate ----------------------------------------------------
# A logical subscriber must have every column on every table the publisher
# replicates. If it
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
# list). Require every local published table to be a superset.
log "Verifying local tables cover every column the publisher replicates"
published_tables=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tA -F '|' -c \
    "SELECT schemaname, tablename
       FROM pg_publication_tables
      WHERE pubname = '$PUBLICATION'
      ORDER BY schemaname, tablename" 2>/dev/null)
[ -n "$published_tables" ] || die "publisher reports no tables under publication '$PUBLICATION' — publication missing or unreachable"

missing=''
while IFS='|' read -r schema table; do
    [ -n "$schema" ] || continue
    published_cols=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAc \
        "SELECT unnest(attnames) FROM pg_publication_tables
          WHERE pubname = '$PUBLICATION'
            AND schemaname = '$schema'
            AND tablename = '$table'" 2>/dev/null | sort -u)
    [ -n "$published_cols" ] || die "publisher reports no columns for $schema.$table under '$PUBLICATION'"
    local_cols=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT column_name FROM information_schema.columns
          WHERE table_schema = '$schema' AND table_name = '$table'" | sort -u)
    if [ -z "$local_cols" ]; then
        table_missing="$published_cols"
    else
        # Set subtraction: grep treats each local column as a fixed,
        # whole-line pattern. (grep exits 1 for the good/no-missing case.)
        table_missing=$(printf '%s\n' "$published_cols" | grep -vxF "$local_cols" || true)
    fi
    if [ -n "$table_missing" ]; then
        missing="$missing $schema.$table:$(printf '%s' "$table_missing" | tr '\n' ',')"
    fi
done <<EOF
$published_tables
EOF

if [ -n "$missing" ]; then
    die "local published table(s) are missing replicated column(s):$missing
       The local schema is behind the publisher — the hopper binary that ran
       'init' is likely stale (built before these columns' migrations existed).
       Rebuild it and re-run:  make build && make replica (or use
       make rebuild-replica FORCE=true if this subscription is disabled)
       Skipping CREATE/REFRESH SUBSCRIPTION: subscribing now would crash-loop
       the apply worker and retain WAL on the publisher without bound."
fi

# Column parity is not sufficient: a subscriber-side key that is narrower than
# the publisher's rejects rows that are distinct upstream. This happened when
# sightings changed from (source, subject) to (source, subject, affected): one
# valid publisher transaction carried multiple affected versions and apply
# stopped with conflict=insert_exists. Logical replication does not copy DDL,
# so mirror each published table's primary-key definition before enabling the
# subscription. Do the drop+add atomically so a failed rebuild preserves the
# old constraint, and bound the lock wait so active readers still cannot hang
# make replica indefinitely.
log "Verifying local primary keys match the publisher"
publisher_pks=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tA -F '|' -c \
    "SELECT pt.schemaname, pt.tablename, con.conname,
            pg_get_constraintdef(con.oid, false)
       FROM pg_publication_tables pt
       JOIN pg_namespace n ON n.nspname = pt.schemaname
       JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = pt.tablename
       JOIN pg_constraint con ON con.conrelid = c.oid AND con.contype = 'p'
      WHERE pt.pubname = '$PUBLICATION'
      ORDER BY pt.schemaname, pt.tablename" 2>/dev/null)
while IFS='|' read -r schema table publisher_pk publisher_def; do
    [ -n "$schema" ] || continue
    validate_ident "publisher primary-key schema" "$schema"
    validate_ident "publisher primary-key table" "$table"
    validate_ident "publisher primary-key name" "$publisher_pk"
    case "$publisher_def" in
        'PRIMARY KEY ('*')') ;;
        *) die "unexpected primary-key definition for $schema.$table from publisher: '$publisher_def'" ;;
    esac

    local_pk=$(admin -d "$LOCAL_DB" -tA -F '|' -c \
        "SELECT con.conname, pg_get_constraintdef(con.oid, false)
           FROM pg_constraint con
           JOIN pg_class c ON c.oid = con.conrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = '$schema' AND c.relname = '$table'
            AND con.contype = 'p'" | head -n 1)
    local_pk_name=${local_pk%%|*}
    if [ "$local_pk" = "$local_pk_name" ]; then
        local_def=''
    else
        local_def=${local_pk#*|}
    fi
    [ "$local_def" = "$publisher_def" ] && continue

    [ -n "$local_pk_name" ] && validate_ident "local primary-key name" "$local_pk_name"
    log "Reconciling primary key on $schema.$table: ${local_def:-none} -> $publisher_def"
    if [ -n "$local_pk_name" ]; then
        drop_local_pk="ALTER TABLE \"$schema\".\"$table\" DROP CONSTRAINT \"$local_pk_name\";"
    else
        drop_local_pk=''
    fi
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 -c \
        "BEGIN; SET LOCAL lock_timeout = '30s'; $drop_local_pk ALTER TABLE \"$schema\".\"$table\" ADD CONSTRAINT \"$publisher_pk\" $publisher_def; COMMIT;"
done <<EOF
$publisher_pks
EOF

# --- Subscription ----------------------------------------------------------
# We keep the password out of argv by passing it through psql's -v mechanism
# (:'name' expands to a properly-quoted SQL literal inside the client).
# options=-c lock_timeout=0: the publisher runs a global lock_timeout (10s),
# but a tablesync worker's CREATE_REPLICATION_SLOT must wait for a consistent
# snapshot behind whatever transactions are in flight there — on 2026-08-22 a
# 15-minute master transaction cancelled slot creation at 10s and
# disable_on_error shut the subscription off. Scoped to the replication
# connections only; nothing else on the publisher is affected.
CONN="host=$REMOTE_HOST dbname=$REMOTE_DB user=$REMOTE_USER password=$REMOTE_PW options='-c lock_timeout=0'"

sub_exists=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT 1 FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" | tr -d '[:space:]')

# --- fast-sync: defer secondary-index maintenance during the copy ----------
# Drop each to-be-copied table's non-PK indexes before tablesync so the COPY
# runs index-light; they're rebuilt in bulk after (see bulkload.sh). The set
# that will actually be (re)copied = publication tables not already past COPY:
#   r / f / s — leave indexes alone (steady-state or post-copy catch-up)
#   i / d / absent — defer for a (re)copy
# Best-effort — a hiccup here must not abort setup, it just means a slower
# (indexed) copy.
BULK_DEFERRED=''
if [ "$FAST_SYNC" = "true" ] && [ "$COPY_DATA" = "true" ]; then
    pub_tables=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAc \
        "SELECT tablename FROM pg_publication_tables
          WHERE pubname = '$PUBLICATION' AND schemaname = 'public'" 2>/dev/null)
    to_copy=''
    for t in $pub_tables; do
        state=''
        if [ "$sub_exists" = "1" ]; then
            state=$(admin -d "$LOCAL_DB" -tAc \
                "SELECT r.srsubstate FROM pg_subscription_rel r
                   JOIN pg_subscription s ON s.oid = r.srsubid
                   JOIN pg_class c ON c.oid = r.srrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE s.subname = '$SUBSCRIPTION' AND n.nspname = 'public'
                    AND c.relname = '$t'" | tr -d '[:space:]')
        fi
        case "$state" in
            r|f|s) ;;
            *) to_copy="$to_copy $t" ;;
        esac
    done
    if [ -n "$to_copy" ]; then
        # shellcheck disable=SC2086 # intentional word-split of the table list
        bulkload_defer $to_copy \
            || log "warning: fast-sync defer incomplete; copy proceeds with remaining indexes"
    fi
    # Pick up reindex DDL left by an interrupted prior run (e.g. COPY reached
    # 'f' but indexes were never rebuilt).
    bulkload_resume_pending
fi

if [ "$sub_exists" = "1" ]; then
    current_slot=$(admin -d "$LOCAL_DB" -tAc \
        "SELECT COALESCE(subslotname, '') FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" \
        | tr -d '[:space:]')
    if [ "$current_slot" != "$SUBSCRIPTION" ]; then
        die "subscription '$SUBSCRIPTION' uses replication slot '$current_slot', expected '$SUBSCRIPTION'; rebuild the local replica instead of refreshing across a slot rename"
    fi

    # The subscription's slot is created exactly once, by CREATE SUBSCRIPTION.
    # If it has since been dropped upstream (manual cleanup, or an invalidated
    # slot reaped during an ENOSPC recovery), NOTHING below can bring it back:
    # ALTER ... CONNECTION / SET PUBLICATION / ENABLE / REFRESH all leave the
    # slot alone, so the apply worker just crash-loops on "replication slot
    # does not exist" and setup.sh reports a misleading partial success. Bail
    # out here pointing at the only real fix. Counterpart of the orphan-slot
    # drop below (slot without subscription); this is subscription without slot.
    remote_slot=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAc \
        "SELECT 'slot:' || count(*) FROM pg_replication_slots WHERE slot_name = '$SUBSCRIPTION'" \
        2>/dev/null | tr -d '[:space:]')
    case "$remote_slot" in
        slot:0)
            die "replication slot '$SUBSCRIPTION' no longer exists on $REMOTE_HOST, so this subscription can never reconnect (refreshing cannot recreate a slot). Recreating it would silently skip every change since the slot was dropped — including deletes — so an incremental resume is unsafe. Rebuild instead: make rebuild-replica FORCE=true" ;;
        slot:*) ;;
        *) log "warning: could not read replication slots on $REMOTE_HOST — proceeding without the missing-slot check" ;;
    esac

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
log "Replication status:"

# Main apply worker status. pg_stat_subscription has one row per worker —
# the apply worker (relid IS NULL) plus one tablesync worker per table during
# initial copy — so we filter to just the apply worker here. pid NULL means
# it hasn't registered yet.
#
# The worker is asynchronous, so poll rather than sleeping once: a worker that
# is crash-looping (each incarnation dying in well under a second) reads as
# "pid IS NULL" on any single sample, which used to be reported as a benign
# startup race. Treat a worker that never appears as the failure it is.
apply_status=''
i=0
while [ "$i" -lt 10 ]; do
    apply_status=$(admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA <<'SQL' | tr -d '\r'
SELECT format('pid=%s received_lsn=%s latest_end_lsn=%s',
              pid,
              COALESCE(received_lsn::text,   '0/0'),
              COALESCE(latest_end_lsn::text, '0/0'))
  FROM pg_stat_subscription
  WHERE subname = :'sub' AND relid IS NULL AND pid IS NOT NULL;
SQL
    )
    [ -n "$apply_status" ] && break
    i=$((i + 1))
    sleep 2
done

if [ -n "$apply_status" ]; then
    printf '    apply worker: %s\n' "$apply_status"
else
    printf '    apply worker: NOT RUNNING after 20s — replication is DOWN, not starting up.\n'
    printf '    Check the subscriber log for the repeating error, e.g.:\n'
    printf '        journalctl -u postgresql -n 50 | grep -i "logical replication"\n'
    SETUP_FAILED=1
fi

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
    if [ "$SETUP_EXACT_COUNTS" = 'true' ]; then
        rows=$(admin -d "$LOCAL_DB" -tAc "SET statement_timeout='15s'; SELECT count(*) FROM $qualified" 2>/dev/null | tr -d '[:space:]')
        printf '    table %s: %s (%s exact rows)\n' "$qualified" "$state" "${rows:-timed out}"
    else
        rows=$(admin -d "$LOCAL_DB" -tAc "SELECT n_live_tup FROM pg_stat_user_tables WHERE relid = '$qualified'::regclass" 2>/dev/null | tr -d '[:space:]')
        printf '    table %s: %s (~%s estimated rows)\n' "$qualified" "$state" "${rows:-?}"
    fi
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
    if ! bulkload_finish $BULK_DEFERRED; then
        log "warning: fast-sync did not finish cleanly — check messages above and $( { [ -n "${HEAL_DIR:-}" ] && printf '%s/bulkload' "$HEAL_DIR"; } || printf 'the bulkload state dir')"
        SETUP_FAILED=1
    fi
fi

# The worker can disable the subscription asynchronously after the initial
# status poll. Make the final result authoritative: a command that leaves a
# disabled subscription must exit nonzero, never print a successful "Done".
final_enabled=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT subenabled FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" \
    | tr -d '[:space:]')
final_apply=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT 1 FROM pg_stat_subscription WHERE subname = '$SUBSCRIPTION' AND relid IS NULL AND pid IS NOT NULL" \
    | tr -d '[:space:]')
if [ "$final_enabled" != 't' ] || [ "$final_apply" != '1' ]; then
    log "FAILED: final replication health check failed (enabled=$final_enabled apply_worker=${final_apply:-absent})"
    SETUP_FAILED=1
fi

if [ -n "${SETUP_FAILED:-}" ]; then
    log "FAILED: the schema/subscription steps ran, but the apply worker is not"
    log "        running, so this replica is NOT replicating. Diagnose first:"
    log "        make diagnose-replica REMOTE_HOST=$REMOTE_HOST SUBSCRIPTION=$SUBSCRIPTION"
    log "        If the root cause is fixed (or was schema drift), re-run make replica;"
    log "        if the slot is gone or apply keeps wedging on data, use:"
    log "        SUBSCRIPTION=$SUBSCRIPTION make rebuild-replica FORCE=true"
    exit 1
fi

log "Done. Re-run anytime — this script is idempotent and resumes interrupted copies."
# GNU watch(1) does not exist on FreeBSD (watch(8) there is an unrelated
# tty-snooping tool); replica-watch.sh loops in portable sh instead.
log "Live monitor: make replica-watch"
log "Full status:  make diagnose-replica REMOTE_HOST=$REMOTE_HOST SUBSCRIPTION=$SUBSCRIPTION"
