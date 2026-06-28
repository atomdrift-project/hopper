#!/bin/sh
# freebsd-bastille.sh - Deploy hopper + PostgreSQL using separate build and run jails
# Usage: ./scripts/master/freebsd-bastille.sh <build-jail> <run-jail>
#        DB_ONLY=1 ./scripts/master/freebsd-bastille.sh "" <run-jail>
#
# Builds the hopper binary in the build jail, installs PostgreSQL and hopper
# in the run jail, and configures both as rc.d services.
#
# When DB_ONLY=1 is set, only PostgreSQL is provisioned in the run jail — the
# build jail is not touched and the hopper binary/service is left alone.

set -e

BUILD="$1"
RUN="$2"

die() {
    echo "error: $*" >&2
    exit 1
}

log() {
    echo "==> $*"
}

if [ -n "$DB_ONLY" ]; then
    [ -n "$RUN" ] || die "usage: DB_ONLY=1 $0 \"\" <run-jail>"
else
    [ -z "$BUILD" ] || [ -z "$RUN" ] && die "usage: $0 <build-jail> <run-jail>"
fi

# PostgreSQL major version.
# Must match the version installed locally if you want pg_dump | pg_restore
# to work without errors across major versions. Override with PGVER=17 if
# the target jail only has PostgreSQL 17 packages.
PGVER="${PGVER:-18}"

# Verify jails are accessible
if [ -z "$DB_ONLY" ]; then
    doas bastille cmd "$BUILD" true || die "build jail '$BUILD' not accessible"
fi
doas bastille cmd "$RUN" true || die "run jail '$RUN' not accessible"

if [ -z "$DB_ONLY" ]; then
    # --- Build jail setup ---

    log "Ensuring build user exists"
    doas bastille cmd "$BUILD" id -u hopper >/dev/null 2>&1 || \
        doas bastille cmd "$BUILD" pw useradd hopper -m -s /bin/sh -c "Hopper Build"

    log "Installing build dependencies"
    doas bastille pkg "$BUILD" install -y go gmake sqlite3

    log "Copying source tree to build jail"
    doas bastille cmd "$BUILD" rm -rf /home/hopper/hopper
    doas bastille cp "$BUILD" . /home/hopper/hopper
    doas bastille cmd "$BUILD" chown -R hopper:hopper /home/hopper/hopper

    log "Building hopper binary"
    doas bastille cmd "$BUILD" su -l hopper -c "cd ~/hopper && gmake build"

    log "Running tests"
    doas bastille cmd "$BUILD" su -l hopper -c "cd ~/hopper && gmake test"

    # --- Transfer binary via jail filesystem ---

    BASTILLE_DIR="/usr/local/bastille/jails"

    log "Transferring binary to run jail"
    doas cp "$BASTILLE_DIR/$BUILD/root/home/hopper/hopper/hopper" \
           "$BASTILLE_DIR/$RUN/root/tmp/hopper"
fi

# --- Run jail setup ---

# Enable DNS before anything else — pkg bootstrap will fail with a resolver
# error if local_unbound isn't up first.
log "Enabling local_unbound resolver"
doas bastille sysrc "$RUN" local_unbound_enable=YES
if ! doas bastille cmd "$RUN" service local_unbound status >/dev/null 2>&1; then
    doas bastille service "$RUN" local_unbound start
fi

# --- Storage tuning note (ZFS — do this on the host before first deploy) ---
#
# If the jail's data lives on ZFS, tune the dataset before initdb:
#   zfs set recordsize=8k    <pool>/jails/<run-jail>   # match PG page size
#   zfs set compression=lz4  <pool>/jails/<run-jail>   # transparent compression
#   zfs set atime=off        <pool>/jails/<run-jail>   # eliminate atime writes
#   zfs set logbias=throughput <pool>/jails/<run-jail> # sequential WAL writes
#   zfs set primarycache=metadata <pool>/jails/<run-jail>  # let PG manage its own cache

log "Installing PostgreSQL"
doas bastille pkg "$RUN" install -y postgresql${PGVER}-server

log "Ensuring hopper user exists"
doas bastille cmd "$RUN" id -u hopper >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd hopper -m -s /bin/sh -c "Hopper Service"

if [ -z "$DB_ONLY" ]; then
    log "Installing hopper binary"
    doas bastille cmd "$RUN" mkdir -p /usr/local/bin
    doas bastille cmd "$RUN" install -o root -g wheel -m 755 /tmp/hopper /usr/local/bin/hopper
    doas bastille cmd "$RUN" rm -f /tmp/hopper
fi

# --- PostgreSQL initialization ---

# PostgreSQL's initdb uses SysV shared memory as a bootstrap interlock, which
# requires a per-jail SysV IPC namespace. These are jail creation params, so
# changes only take effect after a full stop/start — check the running jail's
# kernel state via jls and only restart if something actually needs updating.
need_restart=0
for param in sysvmsg sysvsem sysvshm; do
    # `bastille config get` reads the persisted value from jail.conf; it's
    # more reliable than `jls` for params that aren't enumerated at runtime.
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

log "Initializing PostgreSQL (if needed)"
doas bastille sysrc "$RUN" postgresql_enable=YES

# Initialize the database cluster if it doesn't exist yet.
doas bastille cmd "$RUN" sh -c "
    if [ ! -f /var/db/postgres/data${PGVER}/PG_VERSION ]; then
        /usr/local/etc/rc.d/postgresql initdb
    fi
"

# Restrict network access: listen on all interfaces but only accept
# connections from loopback and the 10.0.0.0/8 private range via pg_hba.
# Overwriting pg_hba.conf is idempotent; postgres is reloaded below if
# it's already running.
log "Writing postgres access rules (loopback + 10.0.0.0/8)"
doas bastille cmd "$RUN" tee /var/db/postgres/data${PGVER}/pg_hba.conf >/dev/null <<'HBAEOF'
# Managed by scripts/master/freebsd-bastille.sh — edits may be overwritten on redeploy.
# TYPE  DATABASE  USER  ADDRESS         METHOD
local   all       all                   peer
host    all       all   127.0.0.1/32    scram-sha-256
host    all       all   ::1/128         scram-sha-256
host    all       all   10.0.0.0/8      scram-sha-256
HBAEOF
doas bastille cmd "$RUN" chown postgres:postgres /var/db/postgres/data${PGVER}/pg_hba.conf
doas bastille cmd "$RUN" chmod 600 /var/db/postgres/data${PGVER}/pg_hba.conf

# Ensure postgres listens on all interfaces so 10.x clients can reach it.
doas bastille cmd "$RUN" sh -c "
    conf=/var/db/postgres/data${PGVER}/postgresql.conf
    if grep -qE \"^[#[:space:]]*listen_addresses\" \$conf; then
        sed -i '' -E \"s|^[#[:space:]]*listen_addresses.*|listen_addresses = '*'|\" \$conf
    else
        echo \"listen_addresses = '*'\" >> \$conf
    fi
"

# Ensure PostgreSQL is running. listen_addresses changes require a full
# restart (a reload won't pick them up), so restart if already running.
if doas bastille cmd "$RUN" service postgresql status >/dev/null 2>&1; then
    log "Restarting PostgreSQL to apply config changes"
    doas bastille service "$RUN" postgresql restart
else
    log "Starting PostgreSQL"
    doas bastille service "$RUN" postgresql start
fi

# --- PostgreSQL performance tuning ---
#
# ALTER SYSTEM writes to postgresql.auto.conf (always included, overrides
# postgresql.conf). shared_buffers requires a restart; the others take effect
# on reload. Adjust shared_buffers/effective_cache_size to your server RAM.
#
# Assumes SSD storage. Set random_page_cost=4 and effective_io_concurrency=2
# for spinning disk.

log "Applying PostgreSQL performance tunings"
PG_TUNING_TMP="/tmp/pg-tuning-hopper.sql"
doas bastille cmd "$RUN" tee "$PG_TUNING_TMP" >/dev/null <<'SQLEOF'
-- Memory: 64GB server — shared_buffers=25% RAM, effective_cache_size=75% RAM.
ALTER SYSTEM SET shared_buffers             = '16GB';
ALTER SYSTEM SET effective_cache_size       = '48GB';
-- work_mem applies per sort/hash node; with ~20 connections doing complex
-- queries this peaks around 10GB — well within budget on 64GB.
ALTER SYSTEM SET work_mem                   = '512MB';
-- Large maintenance_work_mem speeds up VACUUM and index builds on 100M rows.
ALTER SYSTEM SET maintenance_work_mem       = '2GB';
-- Checkpoints: spread I/O and give WAL room for bulk ingestion.
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET max_wal_size               = '4GB';
ALTER SYSTEM SET min_wal_size               = '1GB';
ALTER SYSTEM SET wal_compression            = 'zstd';
-- Planner: tuned for SSD.
ALTER SYSTEM SET random_page_cost           = 1.2;
ALTER SYSTEM SET effective_io_concurrency   = 200;
-- Autovacuum: at 100M rows the default 20% threshold means 20M dead tuples
-- before cleanup; drop to 1% so it stays on top of write-heavy workloads.
ALTER SYSTEM SET autovacuum_vacuum_scale_factor  = 0.01;
ALTER SYSTEM SET autovacuum_analyze_scale_factor = 0.005;
ALTER SYSTEM SET autovacuum_max_workers          = 6;
-- Huge pages: FreeBSD superpages are managed by the VM automatically;
-- 'try' uses them when available without failing if not.
ALTER SYSTEM SET huge_pages                 = 'try';
-- Async commit: safe for this workload — worst case one WAL flush of data
-- loss on a hard crash, acceptable for a file-analysis database.
ALTER SYSTEM SET synchronous_commit         = 'off';
-- Logical replication: required for CREATE PUBLICATION so that replica
-- machines can subscribe for a real-time local replica of the samples table.
ALTER SYSTEM SET wal_level                  = 'logical';
-- Bound per-slot WAL retention so a stuck/slow subscriber can't fill the
-- master's disk. An inactive or far-behind replication slot otherwise retains
-- WAL without limit (the default, -1); a replica that wedges during its
-- initial copy — e.g. blocked behind a long transaction, or crash-looping on
-- a schema mismatch — will then grow the master's pg_wal until the volume
-- fills and the WHOLE primary goes down. With this set, Postgres instead
-- invalidates the offending slot once it exceeds the cap, protecting the
-- master at the cost of forcing that one replica to rebuild.
--
-- TRADE-OFF — tune to this host's disk: the value must exceed the WAL
-- generated on the master during a full initial copy of `samples` under peak
-- write load, or legitimate in-progress rebuilds get their slot invalidated
-- mid-copy and can never finish (the exact 'wal_removed' failure that forces a
-- rebuild). A full ~233 GB copy at ~5 MB/s takes ~13 h, during which the slot
-- retains WAL at the master's write rate (~5 MB/s) — projected peak ~400 GB.
-- 600 GB leaves headroom above that; raise it if rebuilds get invalidated,
-- lower it if pg_wal threatens the disk. Size against free space on the pg_wal
-- volume. (Reload to apply: ALTER SYSTEM only writes postgresql.auto.conf —
-- run SELECT pg_reload_conf(); afterward; no restart needed.)
ALTER SYSTEM SET max_slot_wal_keep_size      = '600GB';
SELECT pg_reload_conf();
SQLEOF

doas bastille cmd "$RUN" su -l postgres -c "psql -f $PG_TUNING_TMP"
doas bastille cmd "$RUN" rm -f "$PG_TUNING_TMP"

# Restart to apply settings that require it (shared_buffers, huge_pages).
log "Restarting PostgreSQL to apply tuning"
doas bastille service "$RUN" postgresql restart


# Create the hopper database and user. Prompt for a password only when the
# role doesn't already exist — re-runs reuse whatever hopper_db is already
# stored in rc.conf.
role_exists=$(doas bastille cmd "$RUN" su -l postgres -c \
    "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='hopper'\"" 2>/dev/null | tr -d '[:space:]')

if [ -z "$role_exists" ]; then
    log "Creating hopper postgres role"
    printf "Enter password for new 'hopper' postgres user: " >&2
    stty -echo 2>/dev/null || true
    IFS= read -r HOPPER_PW
    stty echo 2>/dev/null || true
    printf "\n" >&2
    [ -n "$HOPPER_PW" ] || die "password cannot be empty"

    # Pass the password via psql -v so it never touches a shell-expanded context.
    # :'pw' is psql literal interpolation — the shell only sees the variable name,
    # not its value, so shell metacharacters in the password cannot be executed.
    doas bastille cmd "$RUN" su -l postgres -c \
        "psql -v ON_ERROR_STOP=1 -v pw='$HOPPER_PW' -c \"CREATE ROLE hopper LOGIN PASSWORD :'pw'\""
    doas bastille cmd "$RUN" su -l postgres -c "createdb -O hopper hopper 2>/dev/null || true"

    # Store the password in ~hopper/.pgpass (chmod 600) rather than in rc.conf.
    # rc.conf is world-readable on FreeBSD; .pgpass is only readable by the hopper user.
    # Format: hostname:port:database:username:password
    doas bastille cmd "$RUN" sh -c "
        printf 'localhost:5432:hopper:hopper:%s\n' '$HOPPER_PW' > /home/hopper/.pgpass
        chown hopper:hopper /home/hopper/.pgpass
        chmod 600 /home/hopper/.pgpass
    "
    unset HOPPER_PW

    # DSN has no password — libpq/pgx resolves it from .pgpass at runtime.
    HOPPER_DB="postgres://hopper@localhost/hopper?sslmode=disable"
    doas bastille sysrc "$RUN" hopper_db="$HOPPER_DB" >/dev/null
else
    log "Reusing existing hopper postgres role"
    HOPPER_DB=$(doas bastille cmd "$RUN" sysrc -n hopper_db 2>/dev/null || true)
    [ -n "$HOPPER_DB" ] || HOPPER_DB="postgres://hopper@localhost/hopper?sslmode=disable"
fi

# Run hopper schema migrations if the binary is available. In DB_ONLY mode
# the binary isn't deployed here, so migrations have to be run out-of-band.
if doas bastille cmd "$RUN" test -x /usr/local/bin/hopper; then
    log "Running hopper migrations"
    doas bastille cmd "$RUN" su -l hopper -c \
        "hopper init --db '$HOPPER_DB'"
else
    log "hopper binary not installed in jail — skipping migrations"
fi

# --- Logical replication publication ---
#
# Creates a publication for the samples table so replica machines can
# subscribe for a real-time local replica (CREATE SUBSCRIPTION on the
# subscriber). The publication is idempotent — CREATE IF NOT EXISTS isn't
# supported for publications, so we check first.

log "Ensuring logical replication publication exists"
doas bastille cmd "$RUN" su -l postgres -c "
    psql -d hopper -v ON_ERROR_STOP=1 <<'SQL'
DO \\\$\\\$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'hopper_training')
       AND NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'hopper_replica') THEN
        ALTER PUBLICATION hopper_training RENAME TO hopper_replica;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'hopper_replica') THEN
        CREATE PUBLICATION hopper_replica FOR TABLE samples;
    ELSIF NOT EXISTS (
        SELECT 1
          FROM pg_publication_tables
         WHERE pubname = 'hopper_replica'
           AND schemaname = 'public'
           AND tablename = 'samples'
    ) THEN
        ALTER PUBLICATION hopper_replica ADD TABLE samples;
    END IF;
END \\\$\\\$;
SQL
"

# Grant the hopper role replication privilege so subscribers can connect.
doas bastille cmd "$RUN" su -l postgres -c "
    psql -c \"ALTER ROLE hopper WITH REPLICATION\"
"

if [ -n "$DB_ONLY" ]; then
    log "DB_ONLY set — skipping hopper binary/service setup"
    log "Database deployment complete"
    exit 0
fi

# --- Hourly PostgreSQL backups ---

log "Setting up hourly PostgreSQL backups"
doas bastille cmd "$RUN" mkdir -p /var/db/hopper-backups
doas bastille cmd "$RUN" chown postgres:postgres /var/db/hopper-backups
doas bastille cmd "$RUN" chmod 700 /var/db/hopper-backups

doas bastille cmd "$RUN" tee /usr/local/sbin/hopper-backup.sh >/dev/null <<'BKEOF'
#!/bin/sh
# Dump hopper database and remove dumps older than 48 hours.
BACKUP_DIR="/var/db/hopper-backups"
STAMP=$(date -u +%Y-%m-%dT%H00Z)
DEST="${BACKUP_DIR}/hopper-${STAMP}.dump"

pg_dump -Fc hopper -f "${DEST}.tmp" && mv "${DEST}.tmp" "${DEST}"
find "${BACKUP_DIR}" -name 'hopper-*.dump' -mtime +2 -delete
BKEOF

doas bastille cmd "$RUN" chmod 755 /usr/local/sbin/hopper-backup.sh

# Add cron entry for postgres user (idempotent via grep guard).
doas bastille cmd "$RUN" su -l postgres -c '
    crontab -l 2>/dev/null | grep -q hopper-backup ||
    ( crontab -l 2>/dev/null; echo "0 * * * * /usr/local/sbin/hopper-backup.sh" ) | crontab -
'

# --- Grafana Cloud OTLP token ---
#
# obs reads the base64 OTLP credential from $HOME/.tok/graf (HOME=/home/hopper,
# set in the rc.d command below) and pushes telemetry to Grafana Cloud. Stage
# the deploying host's token into the jail: 0700 dir, 0600 file, owned by hopper.
# Idempotent — re-running re-copies the same bytes and re-asserts ownership.
GRAF_SRC="${GRAF_TOKEN:-$HOME/.tok/graf}"
if [ -r "$GRAF_SRC" ]; then
    log "Installing Grafana Cloud token into run jail"
    doas bastille cmd "$RUN" install -d -o hopper -g hopper -m 0700 /home/hopper/.tok
    doas bastille cp "$RUN" "$GRAF_SRC" /home/hopper/.tok/graf
    doas bastille cmd "$RUN" chown hopper:hopper /home/hopper/.tok/graf
    doas bastille cmd "$RUN" chmod 600 /home/hopper/.tok/graf
else
    log "No $GRAF_SRC on deploy host — OTLP push to Grafana Cloud disabled until provided"
fi

# --- Hopper rc.d service ---

log "Checking rc.d service for hopper"
doas bastille cmd "$RUN" mkdir -p /usr/local/etc/rc.d

RC_TMP="/tmp/hopper-rc.sh"
doas bastille cmd "$RUN" tee "$RC_TMP" >/dev/null <<'RCEOF'
#!/bin/sh

# PROVIDE: hopper
# REQUIRE: LOGIN DAEMON NETWORKING postgresql
# KEYWORD: shutdown

. /etc/rc.subr

name="hopper"
rcvar="hopper_enable"

load_rc_config $name

: ${hopper_enable:="NO"}
: ${hopper_db:="postgres://hopper@localhost/hopper?sslmode=disable"}
: ${hopper_bind:="0.0.0.0:5433"}

pidfile="/var/run/${name}.pid"
hopper_log="/var/log/${name}.log"
command="/usr/sbin/daemon"
# HOME=/home/hopper so obs finds the Grafana Cloud token at $HOME/.tok/graf and
# pushes telemetry there (daemon -u does not set HOME on its own). No OTLP
# endpoint is set: obs falls back to the Grafana Cloud gateway via that token.
command_args="-c -f -P ${pidfile} -S -R 5 -o ${hopper_log} -u hopper /usr/bin/env HOME=/home/hopper DATABASE_URL=${hopper_db} /usr/local/bin/hopper serve --port 5433"

run_rc_command "$1"
RCEOF

RC_CHANGED=0
if ! doas bastille cmd "$RUN" cmp -s "$RC_TMP" /usr/local/etc/rc.d/hopper; then
    log "rc.d script changed — installing update"
    doas bastille cmd "$RUN" install -o root -g wheel -m 755 "$RC_TMP" /usr/local/etc/rc.d/hopper
    RC_CHANGED=1
else
    log "rc.d script unchanged"
    doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/hopper
fi
doas bastille cmd "$RUN" rm -f "$RC_TMP"
doas bastille sysrc "$RUN" hopper_enable=YES

# --- Restart/start services ---

if doas bastille cmd "$RUN" service hopper status >/dev/null 2>&1; then
    log "Restarting hopper service"
    doas bastille service "$RUN" hopper restart
else
    log "Starting hopper service (first deploy)"
    doas bastille service "$RUN" hopper start
fi

log "Deployment complete"
log "Hopper is available at postgres://hopper@<jail-ip>/hopper"
