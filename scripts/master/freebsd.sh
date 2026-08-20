#!/bin/sh
# freebsd.sh - Install Hopper and its separately supervised Scan worker on a
# native FreeBSD host.
#
# Hopper owns ingestion and the HTTP API. Atomdrift Scan is installed as the
# independent scan-worker rc.d service from the sibling scan checkout; it is
# deliberately not a child of hopper, so an analysis OOM cannot take the API
# down with it.

set -eu

DATA_DIR="${DATA_DIR:-/data/samples}"
DB="${DB:-postgres://hopper@hopper-db/hopper?sslmode=disable}"
SOURCE="${SOURCE:-harvest}"
API_ADDR="${API_ADDR:-0.0.0.0:8081}"
# The dashboard has no authentication of its own — a browser cannot present a
# bearer token — so it gets its own loopback listener and is never the tunnel
# origin. Reach it over an SSH forward.
DASH_ADDR="${DASH_ADDR:-127.0.0.1:8082}"
TOKEN_SRC="${TOKEN_SRC-${HOME}/.tok/hopper}"
WORKERS="${WORKERS:-96}"
MAX_MEMORY_GB="${MAX_MEMORY_GB:-0}"
LLM="${LLM:-http://10.9.8.149:8000/v1}"
SCAN_DIR="${SCAN_DIR:-../scan}"
CLEAVE_DIR="${CLEAVE_DIR:-../cleave}"
SAMPLES_GROUP="${SAMPLES_GROUP:-samples}"
PULL_DISABLE="${PULL_DISABLE:-0}"
DATASET_INCOMPLETE="${DATASET_INCOMPLETE:-1}"
REQUIRED_MOUNTS="${REQUIRED_MOUNTS:-bad,good,incoming,pending,review}"
# Cloudflare Tunnel exposure. "auto" configures the tunnel only when a token is
# supplied or one was stored by an earlier deploy, so hosts that serve Hopper
# on the LAN alone need no extra flags. Set CLOUDFLARED=1 to require it, or
# CLOUDFLARED=0 to skip it even when a token is present.
CLOUDFLARED="${CLOUDFLARED:-auto}"
CF_TUNNEL_TOKEN_FILE="${CF_TUNNEL_TOKEN_FILE:-/usr/local/etc/hopper/cloudflared-token}"

SERVICE_USER=hopper
HOPPER_BIN=/usr/local/bin/hopper
CLEAVE_BIN=/usr/local/bin/cleave
HOPPER_RCD=/usr/local/etc/rc.d/hopper
HEAL_PERMS_BIN=/usr/local/sbin/hopper-heal-perms
HEAL_PERMS_PERIODIC=/usr/local/etc/periodic/daily/480.hopper-heal-perms
RC_TMP=""
PERIODIC_TMP=""

cleanup() {
	[ -z "$RC_TMP" ] || rm -f "$RC_TMP"
	[ -z "$PERIODIC_TMP" ] || rm -f "$PERIODIC_TMP"
}
trap cleanup EXIT

die() {
	echo "error: $*" >&2
	exit 1
}

log() {
	echo "==> $*"
}

[ "$(uname -s)" = "FreeBSD" ] || die "this script is for FreeBSD"
[ -d "$DATA_DIR" ] || die "DATA_DIR does not exist: $DATA_DIR"
[ -f Makefile ] || die "run from the Hopper repository root"
[ -d "$SCAN_DIR" ] || die "Scan source not found at $SCAN_DIR"
[ -d "$CLEAVE_DIR" ] || die "cleave source not found at $CLEAVE_DIR"

if command -v doas >/dev/null 2>&1; then
	SUDO=doas
elif command -v sudo >/dev/null 2>&1; then
	SUDO=sudo
else
	die "need doas or sudo"
fi

missing=""
for pkg in go gmake git rust pkgconf mold 7-zip upx rizin innoextract; do
	pkg info -e "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
done
if [ -n "$missing" ]; then
	log "Installing packages:$missing"
	# shellcheck disable=SC2086
	$SUDO pkg install -y $missing
fi

update_source() {
	name=$1
	dir=$2
	if [ "$PULL_DISABLE" != 0 ]; then
		log "Skipping $name source pull (PULL_DISABLE=$PULL_DISABLE)"
		return
	fi
	log "Updating $name source"
	git -C "$dir" pull --ff-only
}

log "Updating sibling sources"
update_source scan "$SCAN_DIR"
update_source cleave "$CLEAVE_DIR"

log "Building Hopper"
gmake build

log "Building cleave"
gmake -C "$CLEAVE_DIR" release >/dev/null
[ -x "$CLEAVE_DIR/out/cleave" ] || die "cleave build did not produce $CLEAVE_DIR/out/cleave"

log "Ensuring Hopper service user exists"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
	$SUDO pw useradd "$SERVICE_USER" -m -s /bin/sh -c "Hopper Service"
fi

log "Ensuring shared sample group exists"
if ! pw groupshow "$SAMPLES_GROUP" >/dev/null 2>&1; then
	$SUDO pw groupadd "$SAMPLES_GROUP"
fi
$SUDO pw groupmod "$SAMPLES_GROUP" -m "$SERVICE_USER"

# Refuse to turn absent datasets into ordinary directories. Hopper's reconcile
# treats these roots as authoritative, so a missing mount must stop deployment
# before any mkdir or service restart can hide it.
old_ifs=$IFS
IFS=,
for rel in $REQUIRED_MOUNTS; do
	IFS=$old_ifs
	[ -n "$rel" ] || die "REQUIRED_MOUNTS contains an empty entry"
	case "$rel" in
	/*|.|..|../*|*/../*|*/..) die "invalid required mount: $rel" ;;
	esac
	mountpoint="$DATA_DIR/$rel"
	[ -d "$mountpoint" ] || die "required pool does not exist: $mountpoint"
	mount -p | awk -v target="$mountpoint" '$2 == target { found = 1 } END { exit !found }' \
		|| die "required pool is not mounted: $mountpoint"
	IFS=,
done
IFS=$old_ifs

# pending/ and review/ hold samples whose classification is still "unknown";
# their directory name is workflow state. The roots already exist as mounts.
for dir in "$DATA_DIR/pending" "$DATA_DIR/review"; do
	$SUDO chgrp "$SAMPLES_GROUP" "$dir"
	$SUDO chmod 2775 "$dir"
done

# incoming/ is a separate hot ZFS dataset and the only destination for new
# uploads. Assert the shared writer contract at deploy time so Hopper, Forager,
# and Draino can all create and relocate entries beneath it.
for dir in "$DATA_DIR/incoming/uploads" "$DATA_DIR/incoming/scan" \
	"$DATA_DIR/incoming/prism" "$DATA_DIR/incoming/forager"; do
	if [ ! -d "$dir" ]; then
		$SUDO install -d -m 2775 -o "$SERVICE_USER" -g "$SAMPLES_GROUP" "$dir"
	fi
	$SUDO chgrp "$SAMPLES_GROUP" "$dir"
	$SUDO chmod 2775 "$dir"
done
$SUDO chgrp "$SAMPLES_GROUP" "$DATA_DIR/incoming"
$SUDO chmod 2775 "$DATA_DIR/incoming"

# Create scan before invoking scan's installer so it can be added to the same
# group before the generated rc.d service starts.
if ! id -u scan >/dev/null 2>&1; then
	$SUDO pw useradd scan -m -s /bin/sh -c "Atomdrift Scan Worker"
fi
$SUDO pw groupmod "$SAMPLES_GROUP" -m scan

# Use the deploying user's pgpass when the DSN does not carry credentials.
# Keep it in Hopper's home so both the migration command and rc.d service use
# the same libpq lookup without putting a password in rc.conf.
PGPASS_SRC="${PGPASSFILE:-${HOME:-}/.pgpass}"
if [ -r "$PGPASS_SRC" ]; then
	$SUDO install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
		"$PGPASS_SRC" "/home/$SERVICE_USER/.pgpass"
fi

log "Installing binaries"
$SUDO install -m 0755 -o root -g wheel ./hopper "$HOPPER_BIN"
$SUDO install -m 0755 -o root -g wheel "$CLEAVE_DIR/out/cleave" "$CLEAVE_BIN"

# A full corpus walk must not hold up Hopper readiness. Install the shared-tree
# healer as a daily periodic task instead; it repairs drift from manual moves,
# imports, and files restored with numeric IDs from another host.
log "Installing sample permission healer"
$SUDO install -d -m 0755 -o root -g wheel /usr/local/sbin /usr/local/etc/periodic/daily
$SUDO install -m 0755 -o root -g wheel scripts/master/heal-perms.sh "$HEAL_PERMS_BIN"
PERIODIC_TMP=$(mktemp -t hopper.heal-periodic.XXXXXX)
cat >"$PERIODIC_TMP" <<EOF
#!/bin/sh
exec env DATA_DIR='$DATA_DIR' SAMPLES_GROUP='$SAMPLES_GROUP' '$HEAL_PERMS_BIN'
EOF
if ! $SUDO cmp -s "$PERIODIC_TMP" "$HEAL_PERMS_PERIODIC" 2>/dev/null; then
	$SUDO install -m 0755 -o root -g wheel "$PERIODIC_TMP" "$HEAL_PERMS_PERIODIC"
fi

log "Refreshing cleave rules"
$SUDO su -l "$SERVICE_USER" -c "$CLEAVE_BIN update-rules" \
	|| die "cleave update-rules failed"

# The serving command applies required schema migrations before readiness and
# builds optional indexes in the background. Running the one-shot `init` here
# would put those index builds back on the deployment critical path.

# --- API token ---------------------------------------------------------------
#
# The work API requires `Authorization: Bearer <token>` on every route but the
# probes, loopback callers included: cloudflared terminates the tunnel on
# loopback, so a loopback exemption would be an internet exemption.
#
# The token is a file, never an argument or an environment variable, and is
# never held in a shell variable — so nothing can echo it. Clients read the
# same ~/.tok/hopper path; the Scan worker deployed below runs as this same
# service user and finds it there.
TOKEN_DST="/home/${SERVICE_USER}/.tok/hopper"
token_arg=""
if [ -n "$TOKEN_SRC" ]; then
	token_arg=" --token-file $TOKEN_DST"
	if [ ! -s "$TOKEN_SRC" ] && ! $SUDO test -s "$TOKEN_DST"; then
		(umask 077; mkdir -p "$(dirname "$TOKEN_SRC")")
		(umask 077; { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; } > "$TOKEN_SRC")
		[ -s "$TOKEN_SRC" ] || die "failed to generate a token at $TOKEN_SRC"
		log "Generated an API token at $TOKEN_SRC"
		log "  clients: curl -H \"Authorization: Bearer \$(cat $TOKEN_SRC)\" ..."
	fi
	$SUDO install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" \
		"/home/${SERVICE_USER}/.tok"
	if [ -s "$TOKEN_SRC" ]; then
		$SUDO install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
			"$TOKEN_SRC" "$TOKEN_DST"
	fi
	$SUDO test -s "$TOKEN_DST" || die "no API token at $TOKEN_DST"
	log "API token installed at $TOKEN_DST"
else
	log "TOKEN_SRC is empty — deploying an UNAUTHENTICATED work API"
fi

$SUDO install -d -m 0755 -o root -g wheel /usr/local/etc/rc.d
RC_TMP=$(mktemp -t hopper.rcd.XXXXXX)

dataset_arg=""
[ "$DATASET_INCOMPLETE" != 0 ] && dataset_arg=" --dataset-incomplete"

cat >"$RC_TMP" <<EOF
#!/bin/sh

# PROVIDE: hopper
# REQUIRE: LOGIN DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="hopper"
rcvar="hopper_enable"

load_rc_config \$name

: \${hopper_enable:="NO"}
: \${hopper_data:="$DATA_DIR"}
: \${hopper_db:="$DB"}
: \${hopper_source:="$SOURCE"}
: \${hopper_api_bind:="$API_ADDR"}
: \${hopper_bind:="$DASH_ADDR"}
: \${hopper_logfile:="/var/log/hopper.log"}
: \${hopper_required_mounts:="$REQUIRED_MOUNTS"}

mount_args=""
old_ifs=\$IFS
IFS=,
for required_mount in \${hopper_required_mounts}; do
	IFS=\$old_ifs
	mount_args="\${mount_args} --require-mount \${required_mount}"
	IFS=,
done
IFS=\$old_ifs

pidfile="/var/run/\${name}.pid"
command="/usr/sbin/daemon"
# --litmus '' is intentional: the Scan worker is a separate rc.d service.
command_args="-c -f -r -R 10 -P \${pidfile} -o \${hopper_logfile} -u hopper /usr/bin/env HOME=/home/hopper DATABASE_URL=\${hopper_db} $HOPPER_BIN load --data \${hopper_data} --db \${hopper_db} --source \${hopper_source} --api-addr \${hopper_api_bind} --dashboard-addr \${hopper_bind}$token_arg --litmus '' --cleave $CLEAVE_BIN\${mount_args}$dataset_arg"

run_rc_command "\$1"
EOF

if ! $SUDO cmp -s "$RC_TMP" "$HOPPER_RCD" 2>/dev/null; then
	log "Installing Hopper rc.d service"
	$SUDO install -m 0755 -o root -g wheel "$RC_TMP" "$HOPPER_RCD"
else
	log "Hopper rc.d service unchanged"
fi
$SUDO sysrc hopper_enable=YES >/dev/null

if $SUDO service hopper status >/dev/null 2>&1; then
	log "Restarting Hopper"
	$SUDO service hopper restart
else
	log "Starting Hopper"
	$SUDO service hopper start
fi

log "Waiting for Hopper readiness"
ready=0
ready_port=${DASH_ADDR##*:}
for _ in $(jot 60 1); do
	if fetch -qo - "http://127.0.0.1:$ready_port/_/ready" >/dev/null 2>&1; then
		ready=1
		break
	fi
	sleep 1
done
if [ "$ready" -ne 1 ]; then
	$SUDO tail -n 100 /var/log/hopper.log >&2 || true
	die "Hopper did not become ready within 60 seconds"
fi

case "$CLOUDFLARED" in
0 | no | NO)
	want_tunnel=0
	;;
auto)
	want_tunnel=0
	if [ -n "${CF_TUNNEL_TOKEN:-}" ] || $SUDO test -s "$CF_TUNNEL_TOKEN_FILE"; then
		want_tunnel=1
	fi
	;;
*)
	want_tunnel=1
	;;
esac

if [ "$want_tunnel" = 1 ]; then
	# Started only after readiness: a connector that advertises an origin
	# which is not yet serving hands Cloudflare a 502 window on every deploy.
	log "Deploying Cloudflare Tunnel"
	CF_TUNNEL_TOKEN_FILE="$CF_TUNNEL_TOKEN_FILE" \
		./scripts/master/cloudflared.sh "http://127.0.0.1:$ready_port"
else
	log "Skipping Cloudflare Tunnel (CLOUDFLARED=$CLOUDFLARED)"
fi

log "Deploying separate Scan worker"
(cd "$SCAN_DIR" && \
	DATA_DIR="$DATA_DIR" WORKERS="$WORKERS" MAX_RSS_GB="$MAX_MEMORY_GB" LLM="$LLM" \
		./scripts/worker/worker-freebsd.sh "http://127.0.0.1:8081")

log "Deployment complete"
log "Hopper API: http://127.0.0.1:8081"
log "Hopper database: $DB"
if [ "$want_tunnel" = 1 ]; then
	log "Cloudflare Tunnel: service hopper_tunnel status"
fi
