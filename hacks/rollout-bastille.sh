#!/bin/sh
# rollout-bastille.sh - Deploy hopper + PostgreSQL using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>
#
# Builds the hopper binary in the build jail, installs PostgreSQL and hopper
# in the run jail, and configures both as rc.d services.

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

[ -z "$BUILD" ] || [ -z "$RUN" ] && die "usage: $0 <build-jail> <run-jail>"

# Verify jails are accessible
doas bastille cmd "$BUILD" true || die "build jail '$BUILD' not accessible"
doas bastille cmd "$RUN" true || die "run jail '$RUN' not accessible"

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

# --- Run jail setup ---

log "Installing PostgreSQL"
doas bastille pkg "$RUN" install -y postgresql16-server

log "Ensuring hopper user exists"
doas bastille cmd "$RUN" id -u hopper >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd hopper -m -s /bin/sh -c "Hopper Service"

log "Installing hopper binary"
doas bastille cmd "$RUN" mkdir -p /usr/local/bin
doas bastille cmd "$RUN" install -o root -g wheel -m 755 /tmp/hopper /usr/local/bin/hopper
doas bastille cmd "$RUN" rm -f /tmp/hopper

# --- PostgreSQL initialization ---

log "Initializing PostgreSQL (if needed)"
doas bastille sysrc "$RUN" postgresql_enable=YES

# Initialize the database cluster if it doesn't exist yet.
doas bastille cmd "$RUN" sh -c '
    if [ ! -d /var/db/postgres/data16/PG_VERSION ]; then
        /usr/local/etc/rc.d/postgresql initdb
    fi
'

# Ensure PostgreSQL is running.
if ! doas bastille cmd "$RUN" service postgresql status >/dev/null 2>&1; then
    log "Starting PostgreSQL"
    doas bastille service "$RUN" postgresql start
fi

# Create the hopper database and user (ignore "already exists" errors).
log "Creating hopper database"
doas bastille cmd "$RUN" su -l postgres -c "createuser --no-password hopper 2>/dev/null || true"
doas bastille cmd "$RUN" su -l postgres -c "createdb -O hopper hopper 2>/dev/null || true"

# Run hopper schema migrations.
log "Running hopper migrations"
doas bastille cmd "$RUN" su -l hopper -c \
    "hopper init --db 'postgres://hopper@localhost/hopper?sslmode=disable'"

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
