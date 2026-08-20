#!/bin/sh
# smf-pg-heal.sh — clear Illumos SMF "restarting too quickly" on pkgsrc/postgresql
# once free space has returned.
#
# Failure mode (2026-08-17 gandalf / hopper-db): rpool hit ENOSPC under heavy
# writes + a zrepl snapshot; Postgres died; SMF retried, entered maintenance,
# and stayed down after zrepl freed space because nothing called svcadm clear.
# Hopper on smaug then crash-looped with 503 "starting".
#
# Safe by default — clears ONLY when all of:
#   1. restarter/state == maintenance
#   2. restarter/auxiliary_state == restarting_too_quickly
#   3. free space on PGDATA_DIR (or DATASET) >= MIN_AVAIL_BYTES
#   4. no $HEAL_STATE_DIR/maintenance flag (operator pause)
#
# Cheap when healthy: one svcprop; exits without touching df/zfs or svcadm.
#
# Run as root inside the postgres zone:
#   ./smf-pg-heal.sh              # one heal pass
#   ./smf-pg-heal.sh install      # root cron every INTERVAL_MIN minutes
#
# Zone notes (exclusive-IP pkgsrc zone on OmniOS):
#   * The delegated pgdata dataset is lofs-mounted at /var/pgsql/data and is
#     NOT visible as rpool/zones/postgres/pgdata inside the zone — space is
#     measured with df on PGDATA_DIR by default.
#   * /usr/local/bin does not exist; the binary lands in /opt/local/bin.
#   * cron PATH is minimal; this script sets its own PATH.
#   * /usr/sbin/install is SVR4 (wrong CLI); copy uses /usr/bin/install.
#
# Env:
#   FMRI              default svc:/pkgsrc/postgresql:default
#   PGDATA_DIR        default /var/pgsql/data (df-based space check)
#   DATASET           optional; if set AND visible, use zfs available instead
#   MIN_AVAIL_BYTES   default 53687091200 (50 GiB)
#   HEAL_STATE_DIR    default /var/lib/hopper-smf-pg-heal
#   HEAL_ALERT_CMD    optional; invoked as: $HEAL_ALERT_CMD <message>
#   INTERVAL_MIN      install cadence (default 2)
#   HEAL_BIN          install target (default /opt/local/bin/hopper-smf-pg-heal.sh)

set -eu

# cron on OmniOS is sparse; keep tools findable.
PATH=/usr/sbin:/sbin:/usr/bin:/bin:/opt/local/sbin:/opt/local/bin
export PATH

FMRI="${FMRI:-svc:/pkgsrc/postgresql:default}"
PGDATA_DIR="${PGDATA_DIR:-/var/pgsql/data}"
DATASET="${DATASET:-}"
MIN_AVAIL_BYTES="${MIN_AVAIL_BYTES:-53687091200}"
HEAL_STATE_DIR="${HEAL_STATE_DIR:-/var/lib/hopper-smf-pg-heal}"
HEAL_ALERT_CMD="${HEAL_ALERT_CMD:-}"
INTERVAL_MIN="${INTERVAL_MIN:-2}"
HEAL_BIN="${HEAL_BIN:-/opt/local/bin/hopper-smf-pg-heal.sh}"

ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log()  { printf '%s smf-pg-heal: %s\n' "$(ts)" "$*"; }
warn() { printf '%s smf-pg-heal: WARN %s\n' "$(ts)" "$*" >&2; }
die()  { printf '%s smf-pg-heal: ERROR %s\n' "$(ts)" "$*" >&2; exit 1; }

alert() {
	_msg="$*"
	warn "ALERT $_msg"
	[ -n "$HEAL_ALERT_CMD" ] && { $HEAL_ALERT_CMD "$_msg" || warn "alert command failed"; } || true
}

# Available bytes on the postgres data volume. Prefer an explicit, visible ZFS
# dataset; otherwise df the PGDATA mount (correct inside the lofs-wrapped zone).
space_avail_bytes() {
	if [ -n "$DATASET" ] && zfs list -H -o name "$DATASET" >/dev/null 2>&1; then
		zfs get -Hp -o value available "$DATASET"
		return 0
	fi
	[ -d "$PGDATA_DIR" ] || die "PGDATA_DIR does not exist: $PGDATA_DIR"
	# Illumos df may wrap long FS names onto two lines; END uses the last line.
	# Field 4 is Available (1K-blocks) for both wrapped and unwrapped forms when
	# the final line carries the numeric columns.
	avail_k=$(df -k "$PGDATA_DIR" | awk 'END { print $4 }')
	case "$avail_k" in *[!0-9]*|'') die "cannot parse df available for $PGDATA_DIR (got '$avail_k')" ;; esac
	# $(( )) is fine for ~tiB on 64-bit OmniOS ksh93-/bin/sh.
	printf '%s\n' $((avail_k * 1024))
}

# --- heal ------------------------------------------------------------------
do_heal() {
	command -v svcprop >/dev/null 2>&1 || die "svcprop not found (Illumos SMF only)"
	command -v svcadm >/dev/null 2>&1 || die "svcadm not found"

	case "$MIN_AVAIL_BYTES" in *[!0-9]*|'') die "MIN_AVAIL_BYTES must be an integer (bytes)" ;; esac

	if [ -e "$HEAL_STATE_DIR/maintenance" ]; then
		log "maintenance flag present ($HEAL_STATE_DIR/maintenance) — skipping"
		return 0
	fi

	# Fast path: healthy / starting / disabled → nothing to do.
	state=$(svcprop -p restarter/state "$FMRI" 2>/dev/null || true)
	[ -n "$state" ] || die "cannot read restarter/state for $FMRI"
	if [ "$state" != maintenance ]; then
		return 0
	fi

	aux=$(svcprop -p restarter/auxiliary_state "$FMRI" 2>/dev/null || true)
	if [ "$aux" != restarting_too_quickly ]; then
		log "maintenance for other reason (auxiliary_state=$aux) — not clearing"
		return 0
	fi

	avail=$(space_avail_bytes)
	case "$avail" in *[!0-9]*|'') die "bad available bytes: '$avail'" ;; esac
	if [ "$avail" -lt "$MIN_AVAIL_BYTES" ]; then
		log "still low on space: available=${avail}B < MIN_AVAIL_BYTES=${MIN_AVAIL_BYTES}B — waiting"
		return 0
	fi

	# Single-flight: avoid overlapping clears if cron stacks during a slow start.
	mkdir -p "$HEAL_STATE_DIR" 2>/dev/null || die "cannot create $HEAL_STATE_DIR"
	LOCK="$HEAL_STATE_DIR/lock"
	if ! mkdir "$LOCK" 2>/dev/null; then
		oldpid=$(cat "$LOCK/pid" 2>/dev/null || true)
		if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
			log "another instance (pid $oldpid) running — skipping"
			return 0
		fi
		rm -rf "$LOCK"
		mkdir "$LOCK" || die "cannot claim lock $LOCK"
	fi
	printf '%s\n' "$$" >"$LOCK/pid"
	# shellcheck disable=SC2064
	trap 'rm -rf "$LOCK"' EXIT

	log "clearing $FMRI (restarting_too_quickly; available=${avail}B)"
	svcadm clear "$FMRI" || die "svcadm clear failed"
	alert "cleared $FMRI after space recovered (available=${avail}B)"
	log "cleared — SMF will restart postgres"
}

# --- install ---------------------------------------------------------------
do_install() {
	case "$INTERVAL_MIN" in *[!0-9]*|'') die "INTERVAL_MIN must be an integer" ;; esac
	[ "$(id -u)" = 0 ] || die "install must run as root inside the postgres zone"

	# Illumos dirname/basename do not accept GNU "--"; never pass it.
	self=$(CDPATH='' cd "$(dirname "$0")" && pwd)/$(basename "$0")
	[ -f "$self" ] || die "cannot locate self at $self"

	bindir=$(dirname "$HEAL_BIN")
	mkdir -p "$bindir" "$HEAL_STATE_DIR"
	# OmniOS PATH prefers /usr/sbin/install (SVR4). Use the GNU-compatible one.
	if [ -x /usr/bin/install ]; then
		/usr/bin/install -m 0755 -o root -g root "$self" "$HEAL_BIN"
	else
		cp -f "$self" "$HEAL_BIN"
		chmod 0755 "$HEAL_BIN"
		chown root:root "$HEAL_BIN"
	fi

	logf="$HEAL_STATE_DIR/heal.log"
	# Bake space-check knobs into the crontab so the installed binary stays dumb.
	envbits="FMRI=$FMRI MIN_AVAIL_BYTES=$MIN_AVAIL_BYTES HEAL_STATE_DIR=$HEAL_STATE_DIR PGDATA_DIR=$PGDATA_DIR"
	[ -n "$DATASET" ] && envbits="$envbits DATASET=$DATASET"
	line="*/${INTERVAL_MIN} * * * * $envbits $HEAL_BIN heal >> $logf 2>&1"

	command -v crontab >/dev/null 2>&1 || die "crontab not found"
	# Illumos: `crontab -` (stdin) fails under zlogin with "can't open your
	# crontab file"; `crontab <file>` works. Always load from a temp file.
	ctmp="$HEAL_STATE_DIR/crontab.tmp.$$"
	{ crontab -l 2>/dev/null | grep -Ev 'hopper-smf-pg-heal|smf-pg-heal' || true; printf '%s\n' "$line"; } >"$ctmp"
	crontab "$ctmp" || { rm -f "$ctmp"; die "crontab install failed"; }
	rm -f "$ctmp"
	log "installed root cron every ${INTERVAL_MIN}min → $HEAL_BIN"
	log "  pause:   touch $HEAL_STATE_DIR/maintenance"
	log "  resume:  rm $HEAL_STATE_DIR/maintenance"
	log "  logfile: $logf"
	log "  run now: $HEAL_BIN heal"
}

cmd="${1:-heal}"
[ $# -gt 0 ] && shift || true
case "$cmd" in
	heal) do_heal ;;
	install) do_install "$@" ;;
	*) die "usage: $0 {heal | install}" ;;
esac
