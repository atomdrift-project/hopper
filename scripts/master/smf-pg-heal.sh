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
#   3. ZFS available on DATASET >= MIN_AVAIL_BYTES
#   4. no $HEAL_STATE_DIR/maintenance flag (operator pause)
#
# Cheap when healthy: one svcprop; exits without touching ZFS or svcadm.
#
# Run as root inside the postgres zone:
#   ./smf-pg-heal.sh              # one heal pass
#   ./smf-pg-heal.sh install      # root cron every INTERVAL_MIN minutes
#
# Env:
#   FMRI              default svc:/pkgsrc/postgresql:default
#   DATASET           default rpool/zones/postgres/pgdata
#   MIN_AVAIL_BYTES   default 53687091200 (50 GiB)
#   HEAL_STATE_DIR    default /var/lib/hopper-smf-pg-heal
#   HEAL_ALERT_CMD    optional; invoked as: $HEAL_ALERT_CMD <message>
#   INTERVAL_MIN      install cadence (default 2)
#   HEAL_BIN          install target path (default /usr/local/bin/hopper-smf-pg-heal.sh)

set -eu

FMRI="${FMRI:-svc:/pkgsrc/postgresql:default}"
DATASET="${DATASET:-rpool/zones/postgres/pgdata}"
MIN_AVAIL_BYTES="${MIN_AVAIL_BYTES:-53687091200}"
HEAL_STATE_DIR="${HEAL_STATE_DIR:-/var/lib/hopper-smf-pg-heal}"
HEAL_ALERT_CMD="${HEAL_ALERT_CMD:-}"
INTERVAL_MIN="${INTERVAL_MIN:-2}"
HEAL_BIN="${HEAL_BIN:-/usr/local/bin/hopper-smf-pg-heal.sh}"

ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log()  { printf '%s smf-pg-heal: %s\n' "$(ts)" "$*"; }
warn() { printf '%s smf-pg-heal: WARN %s\n' "$(ts)" "$*" >&2; }
die()  { printf '%s smf-pg-heal: ERROR %s\n' "$(ts)" "$*" >&2; exit 1; }

alert() {
	_msg="$*"
	warn "ALERT $_msg"
	[ -n "$HEAL_ALERT_CMD" ] && { $HEAL_ALERT_CMD "$_msg" || warn "alert command failed"; } || true
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

	command -v zfs >/dev/null 2>&1 || die "zfs not found"
	avail=$(zfs get -Hp -o value available "$DATASET" 2>/dev/null || true)
	case "$avail" in *[!0-9]*|'') die "cannot read available bytes for $DATASET (got '$avail')" ;; esac
	if [ "$avail" -lt "$MIN_AVAIL_BYTES" ]; then
		log "still low on space: $DATASET available=${avail}B < MIN_AVAIL_BYTES=${MIN_AVAIL_BYTES}B — waiting"
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

	log "clearing $FMRI (restarting_too_quickly; $DATASET available=${avail}B)"
	svcadm clear "$FMRI" || die "svcadm clear failed"
	alert "cleared $FMRI after space recovered ($DATASET available=${avail}B)"
	log "cleared — SMF will restart postgres"
}

# --- install ---------------------------------------------------------------
do_install() {
	case "$INTERVAL_MIN" in *[!0-9]*|'') die "INTERVAL_MIN must be an integer" ;; esac
	[ "$(id -u)" = 0 ] || die "install must run as root inside the postgres zone"

	self=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
	[ -f "$self" ] || die "cannot locate self at $self"
	install -m 0755 -o root -g root "$self" "$HEAL_BIN"
	mkdir -p "$HEAL_STATE_DIR"
	logf="$HEAL_STATE_DIR/heal.log"
	# Keep env overrides inline so the installed binary stays dumb/safe.
	line="*/${INTERVAL_MIN} * * * * FMRI=$FMRI DATASET=$DATASET MIN_AVAIL_BYTES=$MIN_AVAIL_BYTES HEAL_STATE_DIR=$HEAL_STATE_DIR $HEAL_BIN heal >> $logf 2>&1"

	command -v crontab >/dev/null 2>&1 || die "crontab not found"
	{ crontab -l 2>/dev/null | grep -v 'hopper-smf-pg-heal\|smf-pg-heal' || true; printf '%s\n' "$line"; } | crontab -
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
