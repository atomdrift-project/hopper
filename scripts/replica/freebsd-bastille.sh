#!/bin/sh
# freebsd-bastille.sh - Provision a FreeBSD/Bastille jail as a hopper replica.
# Usage: ./scripts/replica/freebsd-bastille.sh <run-jail>
#
# Idempotent: re-running installs missing packages, keeps the PostgreSQL 18
# data directory selected, refreshes the source copy, and re-runs the normal
# replica setup script inside the jail.
#
# Overridable via env:
#   PGVER          PostgreSQL major version (default: 18)
#   REMOTE_HOST    publisher host (default: hopper-db)
#   REMOTE_USER    publisher role (default: hopper)
#   REMOTE_DB      publisher database (default: hopper)
#   PUBLICATION    publisher publication (default: hopper_replica)
#   SUBSCRIPTION   local subscription / remote slot name
#   COPY_DATA      pass-through to setup.sh (default: true)
#   PGPASSFILE     host-side pgpass to seed into the jail (default: ~/.pgpass)
#   PGPASS_MODE    preserve or replace jail pgpass (default: preserve)

set -eu

RUN="${1:-}"
[ -n "$RUN" ] || { echo "usage: $0 <run-jail>" >&2; exit 1; }

PGVER="${PGVER:-18}"
REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
PUBLICATION="${PUBLICATION:-hopper_replica}"
COPY_DATA="${COPY_DATA:-true}"
PGPASS="${PGPASSFILE:-$HOME/.pgpass}"
PGPASS_MODE="${PGPASS_MODE:-preserve}"
# REBUILD=true drives a destructive full re-copy inside the jail (for a wedged
# replica whose slot was invalidated — setup.sh alone can't resume a lost slot).
# Default is the idempotent setup path.
REBUILD="${REBUILD:-false}"

# Subscription/slot name: do NOT derive it from the jail name — that produced
# cryptic, inconsistent names like 'hopper_replic'. Leave it empty so the
# in-jail setup.sh derives the canonical hopper_replica_<hostname>, identical to
# how every other replica is named. Override by exporting SUBSCRIPTION.
SUBSCRIPTION="${SUBSCRIPTION:-}"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

validate_ident() {
    case "$2" in
        ""|[!A-Za-z_]*|*[!A-Za-z0-9_]*)
            die "$1 must be a simple PostgreSQL identifier, got '$2'"
            ;;
    esac
}

validate_ident PUBLICATION "$PUBLICATION"
[ -n "$SUBSCRIPTION" ] && validate_ident SUBSCRIPTION "$SUBSCRIPTION"
case "$COPY_DATA" in true|false) ;; *) die "COPY_DATA must be true or false" ;; esac
case "$REBUILD" in true|false) ;; *) die "REBUILD must be true or false" ;; esac
case "$PGPASS_MODE" in preserve|replace) ;; *) die "PGPASS_MODE must be preserve or replace" ;; esac
[ -f "$PGPASS" ] || die "$PGPASS not found; add the $REMOTE_HOST credentials first"

doas bastille cmd "$RUN" true >/dev/null || die "jail '$RUN' not accessible"

# Enable DNS before package installation.
log "Ensuring resolver is enabled"
doas bastille sysrc "$RUN" local_unbound_enable=YES >/dev/null
if ! doas bastille cmd "$RUN" service local_unbound status >/dev/null 2>&1; then
    doas bastille service "$RUN" local_unbound start
fi

# PostgreSQL initdb needs SysV IPC in the jail.
need_restart=0
for param in sysvmsg sysvsem sysvshm; do
    current=$(doas bastille config "$RUN" get "$param" 2>/dev/null | tr -d '[:space:]')
    if [ "$current" != "new" ]; then
        log "Setting $param=new (was: ${current:-unset})"
        doas bastille config "$RUN" set "$param" new
        need_restart=1
    fi
done
if [ "$need_restart" -eq 1 ]; then
    log "Restarting jail to apply SysV IPC namespace changes"
    doas bastille restart "$RUN"
fi

log "Installing replica dependencies"
# postgresql${PGVER}-contrib provides pg_trgm; without it hopper init logs
# "extension pg_trgm is not available" and silently skips the trigram index
# the publisher has, leaving the replica's schema subtly behind.
doas bastille pkg "$RUN" install -y \
    git go gmake sqlite3 \
    postgresql${PGVER}-server postgresql${PGVER}-client postgresql${PGVER}-contrib

log "Selecting PostgreSQL ${PGVER} data directory"
doas bastille sysrc "$RUN" postgresql_enable=YES >/dev/null
doas bastille sysrc "$RUN" postgresql_data="/var/db/postgres/data${PGVER}" >/dev/null
doas bastille cmd "$RUN" mkdir -p /var/db/postgres
doas bastille cmd "$RUN" chown postgres:postgres /var/db/postgres
doas bastille cmd "$RUN" chmod 750 /var/db/postgres

wrong_pg=$(doas bastille cmd "$RUN" sh -c \
    "ps axww | grep '[p]ostgres .* -D ' | grep -v '/var/db/postgres/data${PGVER}' || true")
if [ -n "$wrong_pg" ]; then
    echo "$wrong_pg" | sed 's/^/    /'
    die "postgres is running from a different data directory; stop/recreate the jail or stop that cluster first"
fi

log "Initializing PostgreSQL ${PGVER} (if needed)"
doas bastille cmd "$RUN" sh -c "
    if [ -d /var/db/postgres/data${PGVER} ] && [ ! -f /var/db/postgres/data${PGVER}/PG_VERSION ]; then
        echo 'removing incomplete /var/db/postgres/data${PGVER} from interrupted initdb'
        rm -rf /var/db/postgres/data${PGVER}
    fi
    if [ ! -f /var/db/postgres/data${PGVER}/PG_VERSION ]; then
        /usr/local/etc/rc.d/postgresql initdb
    fi
"

log "Writing local PostgreSQL access rules"
doas bastille cmd "$RUN" tee "/var/db/postgres/data${PGVER}/pg_hba.conf" >/dev/null <<'HBAEOF'
# Managed by scripts/replica/freebsd-bastille.sh; edits may be overwritten.
# TYPE  DATABASE     USER    ADDRESS       METHOD
local   all          all                   peer
host    all          all     127.0.0.1/32  scram-sha-256
host    all          all     ::1/128       scram-sha-256
host    all          hopper  10.0.0.0/8    scram-sha-256
HBAEOF
doas bastille cmd "$RUN" chown postgres:postgres "/var/db/postgres/data${PGVER}/pg_hba.conf"
doas bastille cmd "$RUN" chmod 600 "/var/db/postgres/data${PGVER}/pg_hba.conf"

if doas bastille cmd "$RUN" service postgresql status >/dev/null 2>&1; then
    log "Restarting PostgreSQL"
    doas bastille service "$RUN" postgresql restart
else
    log "Starting PostgreSQL"
    doas bastille service "$RUN" postgresql start
fi

log "Configuring PostgreSQL for logical replication"
PG_TUNING_TMP="/tmp/hopper-replica-pg.sql"
doas bastille cmd "$RUN" tee "$PG_TUNING_TMP" >/dev/null <<'SQLEOF'
ALTER SYSTEM SET wal_level = 'logical';
ALTER SYSTEM SET max_replication_slots = '10';
ALTER SYSTEM SET max_wal_senders = '10';
ALTER SYSTEM SET max_wal_size = '16GB';
ALTER SYSTEM SET min_wal_size = '2GB';
ALTER SYSTEM SET wal_compression = 'zstd';
ALTER SYSTEM SET checkpoint_completion_target = '0.9';
ALTER SYSTEM SET autovacuum_vacuum_scale_factor = '0.01';
ALTER SYSTEM SET autovacuum_analyze_scale_factor = '0.005';
ALTER SYSTEM SET random_page_cost = '1.2';
ALTER SYSTEM SET effective_io_concurrency = '200';
SELECT pg_reload_conf();
SQLEOF
doas bastille cmd "$RUN" su -l postgres -c "psql -v ON_ERROR_STOP=1 -f $PG_TUNING_TMP"
doas bastille cmd "$RUN" rm -f "$PG_TUNING_TMP"

# wal_level requires a restart.
log "Restarting PostgreSQL after logical-replication settings"
doas bastille service "$RUN" postgresql restart

log "Installing pgpass for postgres user (mode: $PGPASS_MODE)"
doas bastille cp "$RUN" "$PGPASS" /tmp/hopper-upstream.pgpass
if [ "$PGPASS_MODE" = "replace" ]; then
    doas bastille cmd "$RUN" install -o postgres -g postgres -m 600 \
        /tmp/hopper-upstream.pgpass /var/db/postgres/.pgpass
else
    doas bastille cmd "$RUN" sh -c "
        if [ ! -f /var/db/postgres/.pgpass ]; then
            install -o postgres -g postgres -m 600 /tmp/hopper-upstream.pgpass /var/db/postgres/.pgpass
        else
            chown postgres:postgres /var/db/postgres/.pgpass
            chmod 600 /var/db/postgres/.pgpass
        fi
    "
fi
doas bastille cmd "$RUN" rm -f /tmp/hopper-upstream.pgpass

log "Copying source tree into jail"
doas bastille cmd "$RUN" rm -rf /var/db/postgres/hopper
doas bastille cp "$RUN" . /var/db/postgres/hopper
doas bastille cmd "$RUN" chown -R postgres:postgres /var/db/postgres/hopper

# Ensure cron runs in the jail: setup.sh -> install-heal.sh installs the
# schema-drift self-healer as a postgres crontab (no systemd in a jail), which
# only fires if cron is actually running.
doas bastille sysrc "$RUN" cron_enable=YES >/dev/null
doas bastille cmd "$RUN" service cron status >/dev/null 2>&1 \
    || doas bastille service "$RUN" cron start || true

# Disposable read-replica ZFS tuning — done HERE, on the host, because the jail
# can't set its own dataset's props (the pool lives on the host). setup.sh's
# in-jail ZFS step is a no-op, so we pass ZFS_TUNE=false below and apply it here
# instead. promote.sh reverts it. ZFS_TUNE=false (env) skips both.
if [ "${ZFS_TUNE:-true}" = "true" ]; then
    jail_root=$(doas jls -j "$RUN" path 2>/dev/null || true)
    if [ -n "$jail_root" ]; then
        log "Applying disposable read-replica ZFS tuning on host for jail '$RUN'"
        PGDATA="$jail_root/var/db/postgres/data${PGVER}" \
            "$SCRIPT_DIR/zfs-tune.sh" apply \
            || log "warning: ZFS tuning failed (continuing)"
    else
        log "warning: could not resolve jail path via jls; apply ZFS tuning on the host by hand:"
        log "         scripts/replica/zfs-tune.sh apply <pool>/<jail pgdata dataset>"
    fi
fi

# REBUILD=true → destructive full re-copy (rebuild.sh); else idempotent setup.
jail_target="replica"
force_env=""
if [ "$REBUILD" = "true" ]; then
    jail_target="rebuild-replica"
    force_env="FORCE='true' "
    log "Running replica REBUILD inside jail (destructive full re-copy)"
else
    log "Running replica setup inside jail"
fi
# Pass SUBSCRIPTION only when explicitly set; otherwise let the in-jail scripts
# derive the canonical hopper_replica_<hostname>.
sub_env=""
[ -n "$SUBSCRIPTION" ] && sub_env="SUBSCRIPTION='$SUBSCRIPTION' "
# Forward fast-sync knobs (bulkload.sh) when the operator set them, e.g.
# BULK_MAINT_MEM=8GB on a big-RAM jail. ZFS_TUNE=false: the host handled ZFS.
bulk_env=""
for _v in FAST_SYNC BULK_MAINT_MEM BULK_MAX_PARALLEL_MAINT BULK_MAX_WAL BULK_POLL_SECS; do
    eval "_val=\${$_v:-}"
    [ -n "$_val" ] && bulk_env="$bulk_env $_v='$_val'"
done
doas bastille cmd "$RUN" su -l postgres -c "
    cd /var/db/postgres/hopper &&
    REMOTE_HOST='$REMOTE_HOST' \
    REMOTE_USER='$REMOTE_USER' \
    REMOTE_DB='$REMOTE_DB' \
    PUBLICATION='$PUBLICATION' \
    ${sub_env}${force_env}COPY_DATA='$COPY_DATA' \
    ZFS_TUNE='false'${bulk_env} \
    PGPASSFILE=/var/db/postgres/.pgpass \
    gmake $jail_target
"

log "Replica deployment complete"
log "Monitor with:"
log "  doas bastille cmd $RUN su -l postgres -c 'cd /var/db/postgres/hopper && REMOTE_HOST=$REMOTE_HOST gmake diagnose-replica'"
