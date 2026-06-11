#!/bin/sh
# harden-publisher.sh — publisher-side backstops against runaway logical
# replication slots (the failure mode that filled this server's pool and took
# the database down). Run ON the publisher as a postgres superuser.
#
# DRAFT / opt-in: nothing here changes WAL configuration unless you pass
# --keep-size. The monitor it installs is report-only unless REAP=true.
#
# Subcommands:
#   install [--keep-size SIZE]
#       * --keep-size SIZE : ALTER SYSTEM SET max_slot_wal_keep_size = SIZE so a
#         stuck slot self-invalidates BEFORE it fills the pool, instead of
#         pinning WAL without bound. Needs superuser + reload.
#         !! A slot already lagging beyond SIZE is invalidated immediately and
#            that replica must be rebuilt. NEVER set below your largest healthy
#            slot's current retention. Check first:
#              SELECT slot_name,
#                     pg_size_pretty(pg_current_wal_lsn() - restart_lsn) AS retained
#                FROM pg_replication_slots ORDER BY restart_lsn;
#       * installs a cron entry running 'monitor' every $INTERVAL_MIN minutes.
#
#   monitor
#       * WARN when any slot retains > WARN_GB of WAL (the early warning that was
#         missing — you'd be paged at 50 GB, not at disk-full).
#       * optionally REAP (drop) an INACTIVE slot retaining > REAP_GB that has
#         stayed that way for > REAP_GRACE_MIN (a decommissioned/forgotten
#         replica). OFF unless REAP=true (dropping a slot forces a rebuild).
#
# Env: PGDB (hopper), WARN_GB (50), REAP_GB (200), REAP_GRACE_MIN (60),
# REAP (false), ALERT_CMD, INTERVAL_MIN (5), STATE_DIR.

set -eu

PGDB="${PGDB:-hopper}"
WARN_GB="${WARN_GB:-50}"
REAP_GB="${REAP_GB:-200}"
REAP_GRACE_MIN="${REAP_GRACE_MIN:-60}"
REAP="${REAP:-false}"
ALERT_CMD="${ALERT_CMD:-}"
INTERVAL_MIN="${INTERVAL_MIN:-5}"
STATE_DIR="${STATE_DIR:-$HOME/.hopper-slot-monitor}"

ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log()  { printf '%s harden-publisher: %s\n' "$(ts)" "$*"; }
warn() { printf '%s harden-publisher: WARN %s\n' "$(ts)" "$*" >&2; }
die()  { printf '%s harden-publisher: ERROR %s\n' "$(ts)" "$*" >&2; exit 1; }

# Superuser admin to the local publisher (same escalation ladder as the
# replica scripts; here we need a SUPERUSER, not just REPLICATION).
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -u postgres psql "$@"; }
else
    die "no superuser access to local postgres (tried 'psql -U postgres', doas, sudo)"
fi

alert() {
    _msg="$*"
    warn "SLOT-ALERT $_msg"
    [ -n "$ALERT_CMD" ] && { $ALERT_CMD "$_msg" || warn "alert command failed"; } || true
}

# --- monitor: early warning + optional reap --------------------------------
do_monitor() {
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    now=$(date +%s)
    # slot_name | active | retained_bytes
    rows=$(admin -d "$PGDB" -tAF '|' <<'SQL'
SELECT slot_name, active,
       (pg_current_wal_lsn() - restart_lsn)::bigint
  FROM pg_replication_slots
 WHERE restart_lsn IS NOT NULL
 ORDER BY restart_lsn;
SQL
)
    warn_bytes=$((WARN_GB * 1024 * 1024 * 1024))
    reap_bytes=$((REAP_GB * 1024 * 1024 * 1024))
    grace_sec=$((REAP_GRACE_MIN * 60))

    printf '%s\n' "$rows" | while IFS='|' read -r slot active bytes; do
        [ -n "$slot" ] || continue
        gb=$((bytes / 1024 / 1024 / 1024))
        if [ "$bytes" -gt "$warn_bytes" ]; then
            alert "slot '$slot' (active=$active) retains ${gb} GB of WAL on the publisher (warn>${WARN_GB} GB)"
        fi

        # Reap path: only INACTIVE slots over REAP_GB, after a grace period
        # tracked via a per-slot first-seen marker.
        marker="$STATE_DIR/over.$slot"
        if [ "$active" = "f" ] && [ "$bytes" -gt "$reap_bytes" ]; then
            first=$(cat "$marker" 2>/dev/null || echo "$now")
            [ -f "$marker" ] || printf '%s' "$now" > "$marker"
            age=$((now - first))
            if [ "$age" -ge "$grace_sec" ]; then
                if [ "$REAP" = "true" ]; then
                    log "reaping inactive slot '$slot' (${gb} GB, inactive >${REAP_GRACE_MIN}min)"
                    if admin -d "$PGDB" -tAc "SELECT pg_drop_replication_slot('$slot')" >/dev/null 2>&1; then
                        alert "REAPED inactive slot '$slot' (${gb} GB) — that replica must be rebuilt"
                        rm -f "$marker"
                    else
                        warn "failed to drop slot '$slot' (still active?)"
                    fi
                else
                    alert "inactive slot '$slot' has retained ${gb} GB for >${REAP_GRACE_MIN}min — set REAP=true to auto-drop, or drop it manually"
                fi
            fi
        else
            rm -f "$marker" 2>/dev/null || true   # recovered/active → reset grace
        fi
    done
    log "monitor pass complete (WARN_GB=$WARN_GB REAP=$REAP)"
}

# --- install: optional keep-size + schedule the monitor --------------------
do_install() {
    keep_size=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --keep-size) keep_size="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
        esac
    done

    if [ -n "$keep_size" ]; then
        log "current slot retention BEFORE changing max_slot_wal_keep_size:"
        admin -d "$PGDB" -P pager=off -c \
            "SELECT slot_name, active, pg_size_pretty(pg_current_wal_lsn()-restart_lsn) AS retained \
               FROM pg_replication_slots WHERE restart_lsn IS NOT NULL ORDER BY restart_lsn;"
        warn "setting max_slot_wal_keep_size = $keep_size — any slot retaining MORE than this is invalidated NOW (forces that replica to rebuild)."
        admin -d "$PGDB" -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET max_slot_wal_keep_size = '$keep_size';"
        admin -d "$PGDB" -v ON_ERROR_STOP=1 -c "SELECT pg_reload_conf();" >/dev/null
        log "max_slot_wal_keep_size set to $keep_size (reloaded)"
    else
        log "no --keep-size given — leaving max_slot_wal_keep_size unchanged"
    fi

    self=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
    logf="$STATE_DIR/monitor.log"
    line="*/$INTERVAL_MIN * * * * WARN_GB=$WARN_GB REAP_GB=$REAP_GB REAP_GRACE_MIN=$REAP_GRACE_MIN REAP=$REAP PGDB=$PGDB $self monitor >> $logf 2>&1"
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    if command -v crontab >/dev/null 2>&1; then
        { crontab -l 2>/dev/null | grep -v 'harden-publisher.sh monitor' || true; printf '%s\n' "$line"; } | crontab - \
            && log "installed slot-monitor cron (every ${INTERVAL_MIN}min); log: $logf" \
            || warn "could not install crontab — add manually: $line"
    else
        warn "no crontab found — schedule '$self monitor' every ${INTERVAL_MIN}min by hand"
    fi
}

cmd="${1:-}"
[ $# -gt 0 ] && shift || true
case "$cmd" in
    monitor) do_monitor ;;
    install) do_install "$@" ;;
    *) die "usage: $0 {install [--keep-size SIZE] | monitor}" ;;
esac
