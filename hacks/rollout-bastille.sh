#!/bin/sh
# rollout-bastille.sh - Deploy hopper + PostgreSQL using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>
#        DB_ONLY=1 ./rollout-bastille.sh "" <run-jail>
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

log "Installing PostgreSQL"
doas bastille pkg "$RUN" install -y postgresql16-server

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
    current=$(doas jls -j "$RUN" "$param" 2>/dev/null || echo "disable")
    if [ "$current" != "new" ]; then
        log "Setting $param=new (was: $current)"
        doas bastille config "$RUN" set "$param" new
        need_restart=1
    fi
done
if [ "$need_restart" -eq 1 ]; then
    log "Restarting jail to apply SysV IPC namespace changes"
    doas bastille restart "$RUN"
fi

log "Enabling local_unbound resolver"
doas bastille sysrc "$RUN" local_unbound_enable=YES
if ! doas bastille cmd "$RUN" service local_unbound status >/dev/null 2>&1; then
    doas bastille service "$RUN" local_unbound start
fi

log "Initializing PostgreSQL (if needed)"
doas bastille sysrc "$RUN" postgresql_enable=YES

# Initialize the database cluster if it doesn't exist yet.
doas bastille cmd "$RUN" sh -c '
    if [ ! -f /var/db/postgres/data16/PG_VERSION ]; then
        /usr/local/etc/rc.d/postgresql initdb
    fi
'

# Restrict network access: listen on all interfaces but only accept
# connections from loopback and the 10.0.0.0/8 private range via pg_hba.
# Overwriting pg_hba.conf is idempotent; postgres is reloaded below if
# it's already running.
log "Writing postgres access rules (loopback + 10.0.0.0/8)"
doas bastille cmd "$RUN" tee /var/db/postgres/data16/pg_hba.conf >/dev/null <<'HBAEOF'
# Managed by rollout-bastille.sh — edits may be overwritten on redeploy.
# TYPE  DATABASE  USER  ADDRESS         METHOD
local   all       all                   peer
host    all       all   127.0.0.1/32    scram-sha-256
host    all       all   ::1/128         scram-sha-256
host    all       all   10.0.0.0/8      scram-sha-256
HBAEOF
doas bastille cmd "$RUN" chown postgres:postgres /var/db/postgres/data16/pg_hba.conf
doas bastille cmd "$RUN" chmod 600 /var/db/postgres/data16/pg_hba.conf

# Ensure postgres listens on all interfaces so 10.x clients can reach it.
doas bastille cmd "$RUN" sh -c "
    conf=/var/db/postgres/data16/postgresql.conf
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

# Percent-encode a string for safe inclusion in a URL userinfo component.
urlencode() {
    LC_ALL=C awk -v s="$1" 'BEGIN {
        for (i = 0; i < 256; i++) ord[sprintf("%c", i)] = i
        n = length(s)
        for (i = 1; i <= n; i++) {
            c = substr(s, i, 1)
            if (c ~ /[A-Za-z0-9._~-]/) printf "%s", c
            else printf "%%%02X", ord[c]
        }
    }'
}

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

    # Escape single quotes for SQL string literal.
    HOPPER_PW_SQL=$(printf '%s' "$HOPPER_PW" | sed "s/'/''/g")
    doas bastille cmd "$RUN" su -l postgres -c "psql -v ON_ERROR_STOP=1" <<SQL
CREATE ROLE hopper LOGIN PASSWORD '$HOPPER_PW_SQL';
SQL
    doas bastille cmd "$RUN" su -l postgres -c "createdb -O hopper hopper 2>/dev/null || true"

    HOPPER_PW_URL=$(urlencode "$HOPPER_PW")
    HOPPER_DB="postgres://hopper:$HOPPER_PW_URL@localhost/hopper?sslmode=disable"
    doas bastille sysrc "$RUN" hopper_db="$HOPPER_DB" >/dev/null
    unset HOPPER_PW HOPPER_PW_SQL HOPPER_PW_URL
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

if [ -n "$DB_ONLY" ]; then
    log "DB_ONLY set — skipping hopper binary/service setup"
    log "Database deployment complete"
    exit 0
fi

# --- Hopper rc.d service ---

log "Creating rc.d service for hopper"
doas bastille cmd "$RUN" mkdir -p /usr/local/etc/rc.d
doas bastille cmd "$RUN" tee /usr/local/etc/rc.d/hopper >/dev/null <<'RCEOF'
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
command_args="-c -f -P ${pidfile} -S -R 5 -o ${hopper_log} -u hopper /usr/bin/env DATABASE_URL=${hopper_db} /usr/local/bin/hopper serve --port 5433"

run_rc_command "$1"
RCEOF

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/hopper
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
