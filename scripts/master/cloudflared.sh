#!/bin/sh
# cloudflared.sh - Install and supervise a Cloudflare Tunnel on a native
# FreeBSD host (no jails), fronting Hopper's HTTP API.
#
# The tunnel and its ingress rules are configured in the Cloudflare dashboard
# (Zero Trust -> Networks -> Tunnels); this script only installs the connector
# and points it at the token issued there. Ingress should target
# http://127.0.0.1:8081, the address Hopper's work API listens on — and only
# that. The HTML dashboard is a separate listener (--dashboard-addr, loopback
# by default) with no authentication of its own, so it must never be given a
# tunnel hostname; reach it over an SSH forward instead.
#
# The API requires `Authorization: Bearer <token>` on every route but the
# liveness, readiness, and metrics probes, so publishing this hostname does not
# publish the samples behind it.
#
# First deployment:
#   CF_TUNNEL_TOKEN='...' gmake deploy
#
# Later deployments reuse the stored token, so CF_TUNNEL_TOKEN is only needed
# again when the tunnel is rotated.
#
# The token is written to a root-owned, group-readable file and passed with
# --token-file. It is deliberately *not* stored in rc.conf via sysrc: rc.conf
# is world-readable, and an rc.d command line built from it would publish the
# token in ps(1) output to every user on the box.

set -eu

TOKEN_FILE="${CF_TUNNEL_TOKEN_FILE:-/usr/local/etc/hopper/cloudflared-token}"
ORIGIN_URL="${1:-http://127.0.0.1:8081}"

SERVICE_USER=cloudflared
SERVICE_HOME=/var/db/cloudflared
CLOUDFLARED_BIN=/usr/local/bin/cloudflared
# Deliberately not "cloudflared": net/cloudflared installs its own
# rc.d/cloudflared, which runs the connector as root off a config file and is
# rewritten by every pkg upgrade. Hopper's tunnel is a separate service with a
# separate name, so neither one silently overwrites the other.
SERVICE_NAME=hopper_tunnel
CLOUDFLARED_RCD=/usr/local/etc/rc.d/$SERVICE_NAME
CLOUDFLARED_LOG=/var/log/$SERVICE_NAME.log

TOKEN=${CF_TUNNEL_TOKEN:-}
unset CF_TUNNEL_TOKEN

RC_TMP=""
TOKEN_TMP=""

cleanup() {
	[ -z "$RC_TMP" ] || rm -f "$RC_TMP"
	[ -z "$TOKEN_TMP" ] || rm -f "$TOKEN_TMP"
}
trap cleanup EXIT HUP INT TERM

die() {
	echo "error: $*" >&2
	exit 1
}

log() {
	echo "==> $*"
}

[ "$(uname -s)" = "FreeBSD" ] || die "this script is for FreeBSD"

if command -v doas >/dev/null 2>&1; then
	SUDO=doas
elif command -v sudo >/dev/null 2>&1; then
	SUDO=sudo
else
	die "need doas or sudo"
fi

# A token on the command line wins; otherwise an already-installed token keeps
# the tunnel running across deploys. With neither, there is nothing to connect.
if [ -z "$TOKEN" ] && ! $SUDO test -s "$TOKEN_FILE"; then
	die "no Cloudflare Tunnel token; rerun with CF_TUNNEL_TOKEN set"
fi

case "$TOKEN" in
*[[:cntrl:]]*) die "CF_TUNNEL_TOKEN must not contain control characters" ;;
esac

if ! pkg info -e cloudflared >/dev/null 2>&1; then
	log "Installing cloudflared"
	$SUDO pkg install -y cloudflared
fi
[ -x "$CLOUDFLARED_BIN" ] || die "cloudflared installation failed: $CLOUDFLARED_BIN is missing"

# --token-file landed in 2025.4.0. Older connectors only accept --token, which
# would put the secret in the process arguments.
VERSION=$("$CLOUDFLARED_BIN" --version | awk '$1 == "cloudflared" && $2 == "version" {print $3; exit}')
YEAR=${VERSION%%.*}
REST=${VERSION#*.}
MONTH=${REST%%.*}
case "$YEAR:$MONTH" in
*[!0-9:]* | :* | *:) die "could not parse cloudflared version: $VERSION" ;;
esac
if [ "$YEAR" -lt 2025 ] || { [ "$YEAR" -eq 2025 ] && [ "$MONTH" -lt 4 ]; }; then
	die "cloudflared 2025.4.0 or newer is required for --token-file support (have $VERSION)"
fi

log "Ensuring cloudflared service user exists"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
	$SUDO pw useradd "$SERVICE_USER" -d "$SERVICE_HOME" -s /usr/sbin/nologin \
		-c "Cloudflare Tunnel"
fi
$SUDO install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$SERVICE_HOME"

# Restart only on a real change. A connector that is already serving is the
# one thing in this deploy that does not have to blink, and every bounce is a
# window where the edge has no origin at all.
changed=0

if [ -n "$TOKEN" ]; then
	TOKEN_TMP=$(mktemp -t hopper.cftoken.XXXXXX)
	chmod 0600 "$TOKEN_TMP"
	printf '%s\n' "$TOKEN" >"$TOKEN_TMP"
	unset TOKEN
	if $SUDO cmp -s "$TOKEN_TMP" "$TOKEN_FILE" 2>/dev/null; then
		log "Cloudflare Tunnel token unchanged"
	else
		log "Installing the supplied Cloudflare Tunnel token"
		# root:cloudflared 0640 — writable only by root, readable by the
		# connector after daemon(8) drops privileges, opaque to everyone else.
		$SUDO install -d -m 0755 -o root -g wheel "$(dirname "$TOKEN_FILE")"
		$SUDO install -m 0640 -o root -g "$SERVICE_USER" "$TOKEN_TMP" "$TOKEN_FILE"
		changed=1
	fi
	rm -f "$TOKEN_TMP"
	TOKEN_TMP=""
else
	log "Keeping the existing Cloudflare Tunnel token"
fi
$SUDO chown "root:$SERVICE_USER" "$TOKEN_FILE"
$SUDO chmod 0640 "$TOKEN_FILE"

$SUDO install -d -m 0755 -o root -g wheel /usr/local/etc/rc.d
RC_TMP=$(mktemp -t hopper.cfrcd.XXXXXX)

cat >"$RC_TMP" <<EOF
#!/bin/sh

# PROVIDE: $SERVICE_NAME
# REQUIRE: LOGIN DAEMON NETWORKING hopper
# KEYWORD: shutdown

. /etc/rc.subr

name="$SERVICE_NAME"
rcvar="${SERVICE_NAME}_enable"

load_rc_config \$name

: \${${SERVICE_NAME}_enable:="NO"}
# Deliberately not "${SERVICE_NAME}_user": rc.subr reserves \${name}_user and
# would run the whole command line under su(1), leaving daemon(8) itself
# unprivileged and unable to write its pidfile under /var/run.
: \${${SERVICE_NAME}_runas:="$SERVICE_USER"}
: \${${SERVICE_NAME}_token_file:="$TOKEN_FILE"}
: \${${SERVICE_NAME}_logfile:="$CLOUDFLARED_LOG"}

pidfile="/var/run/\${name}.pid"
command="/usr/sbin/daemon"
# The token is read from a file rather than passed as an argument so it never
# appears in ps(1) output.
command_args="-c -f -r -R 5 -P \${pidfile} -o \${${SERVICE_NAME}_logfile} -u \${${SERVICE_NAME}_runas} /usr/bin/env HOME=$SERVICE_HOME $CLOUDFLARED_BIN tunnel --no-autoupdate run --token-file \${${SERVICE_NAME}_token_file}"

run_rc_command "\$1"
EOF

if ! $SUDO cmp -s "$RC_TMP" "$CLOUDFLARED_RCD" 2>/dev/null; then
	log "Installing $SERVICE_NAME rc.d service"
	$SUDO install -m 0755 -o root -g wheel "$RC_TMP" "$CLOUDFLARED_RCD"
	changed=1
else
	log "$SERVICE_NAME rc.d service unchanged"
fi
$SUDO sysrc "${SERVICE_NAME}_enable=YES" >/dev/null
# The port's own connector would otherwise come up alongside ours at boot,
# as root, against a config file nothing here maintains.
$SUDO sysrc cloudflared_enable=NO >/dev/null

if ! $SUDO test -e "$CLOUDFLARED_LOG"; then
	$SUDO install -m 0640 -o "$SERVICE_USER" -g wheel /dev/null "$CLOUDFLARED_LOG"
fi

# daemon(8) appends to the log, so a "Registered" line from an earlier deploy
# is still sitting in it. Remember where this run starts and read only past it.
LOG_OFFSET=$($SUDO stat -f %z "$CLOUDFLARED_LOG" 2>/dev/null || echo 0)

if ! $SUDO service "$SERVICE_NAME" status >/dev/null 2>&1; then
	log "Starting $SERVICE_NAME"
	$SUDO service "$SERVICE_NAME" start
elif [ "$changed" = 1 ]; then
	log "Restarting $SERVICE_NAME"
	$SUDO service "$SERVICE_NAME" restart
else
	log "$SERVICE_NAME already running and unchanged"
	exit 0
fi

# A connector that cannot reach Cloudflare retries forever in the background,
# so a silent start says nothing about whether the tunnel is actually serving.
log "Waiting for the tunnel to register a connection"
registered=0
for _ in $(jot 30 1); do
	if $SUDO tail -c "+$((LOG_OFFSET + 1))" "$CLOUDFLARED_LOG" 2>/dev/null |
		grep -q "Registered tunnel connection"; then
		registered=1
		break
	fi
	sleep 1
done
if [ "$registered" -ne 1 ]; then
	$SUDO tail -n 50 "$CLOUDFLARED_LOG" >&2 || true
	die "cloudflared did not register a tunnel connection within 30 seconds"
fi

log "Cloudflare Tunnel connected (origin: $ORIGIN_URL)"
