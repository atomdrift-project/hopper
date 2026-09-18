#!/bin/sh
# freebsd.sh - Install Hopper and its separately supervised postdoc worker on a
# native FreeBSD host.
#
# Hopper owns ingestion and the HTTP API. postdoc is installed as the
# independent postdoc_worker rc.d service from the sibling postdoc checkout; it is
# deliberately not a child of hopper, so an analysis OOM cannot take the API
# down with it.

set -eu

DATA_DIR="${DATA_DIR:-/data/samples}"
DB="${DB:-postgres://hopper@hopper-db/hopper?sslmode=disable}"
SOURCE="${SOURCE:-fs}"
API_ADDR="${API_ADDR:-0.0.0.0:8081}"
# The dashboard has no authentication of its own — a browser cannot present a
# bearer token — so it gets its own listener and is never the tunnel origin.
# It is read-only; keep it on a trusted network, or set DASH_ADDR=127.0.0.1:8082
# to restrict it to an SSH forward.
DASH_ADDR="${DASH_ADDR:-0.0.0.0:8082}"
TOKEN_SRC="${TOKEN_SRC-${HOME}/.tok/hopper}"
LLM="${LLM:-http://10.9.8.149:8000/v1}"
POSTDOC_DIR="${POSTDOC_DIR:-../postdoc}"
CLEAVE_DIR="${CLEAVE_DIR:-../cleave}"
SAMPLES_GROUP="${SAMPLES_GROUP:-samples}"
PULL_DISABLE="${PULL_DISABLE:-0}"
# The FreeBSD master holds the whole corpus — every pool the Linux host used to
# serve was received here by the ZFS migration — so local absence is
# authoritative and reconcile may mark and relabel. Set DATASET_INCOMPLETE=1 for
# a host that deliberately carries only part of the corpus. ReconcilePools' own
# breakers are what stop a short walk from acting on that authority.
DATASET_INCOMPLETE="${DATASET_INCOMPLETE:-0}"
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
POSTDOC_BIN=/usr/local/bin/postdoc
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
[ -d "$POSTDOC_DIR" ] || die "postdoc source not found at $POSTDOC_DIR"
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
update_source postdoc "$POSTDOC_DIR"
update_source cleave "$CLEAVE_DIR"

log "Building Hopper"
gmake build

log "Building cleave"
gmake -C "$CLEAVE_DIR" release >/dev/null
[ -x "$CLEAVE_DIR/out/cleave" ] || die "cleave build did not produce $CLEAVE_DIR/out/cleave"

log "Building postdoc"
gmake -C "$POSTDOC_DIR" release >/dev/null
[ -x "$POSTDOC_DIR/target/release/postdoc" ] || die "postdoc build did not produce $POSTDOC_DIR/target/release/postdoc"

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

# Use the deploying user's pgpass when the DSN does not carry credentials.
# Keep it in Hopper's home so both the migration command and rc.d service use
# the same libpq lookup without putting a password in rc.conf.
PGPASS_SRC="${PGPASSFILE:-${HOME:-}/.pgpass}"
if [ -r "$PGPASS_SRC" ]; then
	$SUDO install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
		"$PGPASS_SRC" "/home/$SERVICE_USER/.pgpass"
fi

# Installed only when they differ, and what differed is remembered: the
# restart at the bottom of this script is worth an ingestion pause and a
# dropped set of worker connections only when there is something new to run.
# A rollout of a commit this host is already on otherwise bounced the API for
# nothing -- and unlike a worker, hopper going away stalls the whole fleet.
# This is what the systemd path (scripts/master/linux-systemd.sh) has always
# done; FreeBSD reinstalled and restarted unconditionally.
service_changed=0

# install_if_changed <src> <dst> <name> — install as root, and report it.
install_if_changed() {
	if $SUDO cmp -s "$1" "$2" 2>/dev/null; then
		log "$3 unchanged"
		return 0
	fi
	log "Installing $2"
	$SUDO install -m 0755 -o root -g wheel "$1" "$2"
	service_changed=1
}

# cleave is spawned per analysis rather than held open, so a new one is picked
# up without a restart -- but hopper is what decides when to spawn it, and the
# two are built from the same rollout. Counted as a change: the conservative
# answer costs one restart that may not have been needed, and the other way
# round leaves a fleet talking to the wrong analyzer.
install_if_changed ./hopper "$HOPPER_BIN" "Hopper binary"
install_if_changed "$CLEAVE_DIR/out/cleave" "$CLEAVE_BIN" "cleave binary"
install_if_changed "$POSTDOC_DIR/target/release/postdoc" "$POSTDOC_BIN" "postdoc binary"

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
# same ~/.tok/hopper path; the postdoc worker deploy below installs it for its
# service account.
TOKEN_DST="/home/${SERVICE_USER}/.tok/hopper"
TOKEN_FILE_SRC="$TOKEN_SRC"
case "$TOKEN_FILE_SRC" in
	/*) ;;
	*) TOKEN_FILE_SRC="$(pwd)/$TOKEN_FILE_SRC" ;;
esac
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
		# A rotated token needs a restart: hopper reads it once, at startup,
		# so installing a new one without restarting leaves the old one live.
		if $SUDO cmp -s "$TOKEN_SRC" "$TOKEN_DST" 2>/dev/null; then
			log "API token unchanged"
		else
			$SUDO install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
				"$TOKEN_SRC" "$TOKEN_DST"
			log "Installed API token from $TOKEN_SRC"
			service_changed=1
		fi
	fi
	$SUDO test -s "$TOKEN_DST" || die "no API token at $TOKEN_DST"
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
# --postdoc '' is intentional: postdoc runs as a separate rc.d service.
#
# -H makes daemon(8) close and reopen the -o log on SIGHUP, which is what makes
# the newsyslog(8) drop-in below actually reclaim space. Without it newsyslog
# renames the file while daemon keeps writing to the now-unlinked inode: the
# rotated copies look correct, the disk never frees, and the log grows without
# bound (this is how hopper.log reached 4.7G).
command_args="-c -f -r -H -R 10 -P \${pidfile} -o \${hopper_logfile} -u hopper /usr/bin/env HOME=/home/hopper DATABASE_URL=\${hopper_db} $HOPPER_BIN load --data \${hopper_data} --db \${hopper_db} --source \${hopper_source} --api-addr \${hopper_api_bind} --dashboard-addr \${hopper_bind}$token_arg --postdoc '' --cleave $CLEAVE_BIN\${mount_args}$dataset_arg"

run_rc_command "\$1"
EOF

# Log rotation. hopper logs a line per worker result and per non-fatal analysis
# error, so an unrotated log is a steady disk leak on the same pool the samples
# live on. Size-based rather than time-based: the volume tracks ingest activity,
# not the clock. Signal 1 (SIGHUP) goes to the daemon(8) supervisor named by the
# pidfile, which reopens the file because of -H above. zstd (Y) keeps the
# compression cheap on a box whose CPU is already contended.
#
# Pinned to the default /var/log/hopper.log: an operator who overrides
# hopper_logfile in rc.conf must move this drop-in to match.
NEWSYSLOG_TMP=$(mktemp -t hopper.newsyslog.XXXXXX)
cat >"$NEWSYSLOG_TMP" <<EOF
# Installed by hopper scripts/master/freebsd.sh -- do not edit by hand.
# logfilename       [owner:group]  mode count size(KB) when flags [/pid_file]        [sig_num]
/var/log/hopper.log root:wheel     600  10    512000   *    YC   /var/run/hopper.pid 1
EOF
$SUDO install -d -m 0755 -o root -g wheel /usr/local/etc/newsyslog.conf.d
if ! $SUDO cmp -s "$NEWSYSLOG_TMP" /usr/local/etc/newsyslog.conf.d/hopper.conf 2>/dev/null; then
	log "Installing Hopper newsyslog config"
	$SUDO install -m 0644 -o root -g wheel "$NEWSYSLOG_TMP" /usr/local/etc/newsyslog.conf.d/hopper.conf
else
	log "Hopper newsyslog config unchanged"
fi
rm -f "$NEWSYSLOG_TMP"

if ! $SUDO cmp -s "$RC_TMP" "$HOPPER_RCD" 2>/dev/null; then
	log "Installing Hopper rc.d service"
	$SUDO install -m 0755 -o root -g wheel "$RC_TMP" "$HOPPER_RCD"
	# Every argument the service runs with is baked into this file, so a
	# changed flag, address or mount list arrives here and nowhere else.
	service_changed=1
else
	log "Hopper rc.d service unchanged"
fi
$SUDO sysrc hopper_enable=YES >/dev/null

# Walkers left behind by the process we are about to replace.
#
# `cleave iter-files` enumerates the whole sample tree. Hopper starts it, but
# the supervisor does not own it: an abrupt stop leaves it running, reading the
# sample pool for a pass nobody will ever collect, and each restart leaves
# another set behind. Measured 2026-08-24: thirty-six of them from nineteen
# previous incarnations, the oldest eleven hours old, between them holding the
# disks that result ingestion, corpus lookups and logical replication all read
# from. Hopper now asks the kernel to kill them with it, but that only covers
# incarnations started by a build that has it.
#
# Reaped before the restart, deliberately: every walker alive now belongs to the
# outgoing process, and every walker alive afterwards belongs to its
# replacement. Doing this after would kill the walk we just started.
reap_walkers() {
	pattern='cleave.*iter-files'
	# Asked once and counted from that answer: a second pgrep can disagree with
	# the first, and under `set -e` a walker that exits between the two would
	# abort the deploy over its own good news.
	pids=$($SUDO pgrep -u "$SERVICE_USER" -f "$pattern" || true)
	[ -n "$pids" ] || return 0
	n=$(printf '%s\n' "$pids" | wc -l | tr -d ' ')
	log "Stopping $n corpus walker(s) left by the previous run"
	$SUDO pkill -TERM -u "$SERVICE_USER" -f "$pattern" 2>/dev/null || true
	i=0
	while [ "$i" -lt 10 ]; do
		$SUDO pgrep -u "$SERVICE_USER" -f "$pattern" >/dev/null 2>&1 || return 0
		sleep 1
		i=$((i + 1))
	done
	# A walker blocked in a disk read does not act on SIGTERM promptly, and
	# giving those disks back is the entire point of reaping it.
	log "Walkers still present after SIGTERM; sending SIGKILL"
	$SUDO pkill -KILL -u "$SERVICE_USER" -f "$pattern" 2>/dev/null || true
}

if $SUDO service hopper status >/dev/null 2>&1; then
	if [ "$service_changed" -eq 0 ]; then
		log "No changes; leaving service running"
	else
		reap_walkers
		log "Restarting Hopper"
		$SUDO service hopper restart
	fi
else
	# Down is its own reason to act: "nothing new to install" never leaves the
	# queue stopped. Nothing is supervising the walkers either, so anything
	# still walking is orphaned by definition -- a stopped service cannot be
	# the parent of a running walk.
	reap_walkers
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

if [ -n "$TOKEN_SRC" ]; then
	log "Deploying separate postdoc worker"
	(cd "$POSTDOC_DIR" && \
		TOKEN_FILE="$TOKEN_FILE_SRC" LLM="$LLM" \
			gmake deploy-worker URL="http://127.0.0.1:8081")
else
	log "Skipping postdoc worker: postdoc requires a Hopper token; set TOKEN_SRC to enable it"
fi

log "Deployment complete"
log "Hopper API: http://127.0.0.1:8081"
log "Hopper database: $DB"
if [ "$want_tunnel" = 1 ]; then
	log "Cloudflare Tunnel: service hopper_tunnel status"
fi
