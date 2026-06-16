#!/bin/sh
# install-heal.sh — schedule replica-heal.sh to run periodically as postgres.
#
# Picks the right scheduler for the host:
#   * systemd present  -> a oneshot service + timer (User=postgres), logs to
#                         journald, OnFailure-friendly. (Linux, e.g. galadriel.)
#   * otherwise        -> the postgres user's crontab. (FreeBSD jail.)
#
# Called by setup.sh after the subscription exists; also runnable standalone to
# (re)install or change the cadence. Idempotent. Best-effort: a failure here
# warns and prints manual steps but never aborts replica setup — the healer
# script still exists and can be scheduled by hand.
#
# Env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB, PUBLICATION, SUBSCRIPTION,
# PGPASSFILE, HEAL_ALERT_CMD (baked into the schedule), HEAL_INTERVAL_MIN (=5).

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HEAL="$SCRIPT_DIR/replica-heal.sh"
[ -f "$HEAL" ] || { echo "install-heal: $HEAL not found" >&2; exit 1; }
chmod +x "$HEAL" 2>/dev/null || true

INTERVAL_MIN="${HEAL_INTERVAL_MIN:-5}"
case "$INTERVAL_MIN" in *[!0-9]*|'') echo "install-heal: HEAL_INTERVAL_MIN must be an integer" >&2; exit 1 ;; esac

log()  { echo "==> install-heal: $*"; }
warn() { echo "install-heal: WARN $*" >&2; }

# Environment the schedule must carry so the healer targets the right peer.
# Only export what's actually set; keep values simple (no spaces expected).
heal_env() {
    for v in REMOTE_HOST REMOTE_USER REMOTE_DB LOCAL_DB PUBLICATION SUBSCRIPTION PGPASSFILE HEAL_ALERT_CMD; do
        eval "val=\${$v:-}"
        [ -n "${val:-}" ] && printf '%s=%s\n' "$v" "$val"
    done
}

as_root() {
    if [ "$(id -u)" = 0 ]; then "$@";
    elif command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1; then doas "$@";
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then sudo "$@";
    elif command -v doas >/dev/null 2>&1; then doas "$@";
    elif command -v sudo >/dev/null 2>&1; then sudo "$@";
    else return 1; fi
}

# The schedule runs the healer AS postgres, which usually cannot read an
# operator's ~/.pgpass (mode 600 inside a 0700 home dir). Same hazard we handle
# for the healer script itself (copied to a postgres-readable path below) and
# that freebsd-bastille.sh handles by seeding the jail's postgres .pgpass: copy
# the credentials into postgres's own home and repoint PGPASSFILE there, so the
# value baked into the unit/crontab is one postgres can actually read.
ensure_pg_readable_pgpass() {
    src="${PGPASSFILE:-$HOME/.pgpass}"
    [ -f "$src" ] || return 0                       # nothing to relocate
    pg_home=$(getent passwd postgres 2>/dev/null | cut -d: -f6)
    [ -n "$pg_home" ] || { warn "no postgres home found; leaving PGPASSFILE=$src"; return 0; }
    dest="$pg_home/.pgpass"
    [ "$src" = "$dest" ] && { PGPASSFILE="$dest"; return 0; }   # already correct
    if as_root install -o postgres -g postgres -m 600 "$src" "$dest" 2>/dev/null; then
        log "seeded postgres-readable pgpass -> $dest (from $src)"
        PGPASSFILE="$dest"
    else
        warn "could not seed $dest from $src; healer (User=postgres) may be unable to read $src"
    fi
}

# --- systemd path ----------------------------------------------------------
install_systemd() {
    unit_dir=/etc/systemd/system
    svc="$unit_dir/hopper-replica-heal.service"
    tmr="$unit_dir/hopper-replica-heal.timer"

    ensure_pg_readable_pgpass
    envlines=$(heal_env | sed 's/^/Environment=/')

    svc_body=$(cat <<EOF
[Unit]
Description=hopper logical-replica schema-drift self-heal
After=postgresql.service
Wants=network-online.target

[Service]
Type=oneshot
User=postgres
ExecStart=$HEAL
$envlines
EOF
)
    tmr_body=$(cat <<EOF
[Unit]
Description=run hopper replica self-heal every ${INTERVAL_MIN}min

[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL_MIN}min
Persistent=true

[Install]
WantedBy=timers.target
EOF
)
    printf '%s\n' "$svc_body" | as_root tee "$svc" >/dev/null || return 1
    printf '%s\n' "$tmr_body" | as_root tee "$tmr" >/dev/null || return 1
    as_root systemctl daemon-reload || return 1
    as_root systemctl enable --now hopper-replica-heal.timer || return 1
    log "installed systemd timer (every ${INTERVAL_MIN}min): hopper-replica-heal.timer"
    log "  status:  systemctl status hopper-replica-heal.timer"
    log "  run now: systemctl start hopper-replica-heal.service && journalctl -u hopper-replica-heal -n 50"
}

# --- cron path (postgres crontab) ------------------------------------------
install_cron() {
    # The healer must run as postgres (local peer auth + postgres-owned .pgpass).
    ensure_pg_readable_pgpass
    envstr=$(heal_env | tr '\n' ' ')
    logfile="${HEAL_LOG:-/var/db/postgres/.hopper-replica-heal/heal.log}"
    [ -d /var/db/postgres ] || logfile="${HEAL_LOG:-$HOME/.hopper-replica-heal/heal.log}"
    line="*/$INTERVAL_MIN * * * * ${envstr}$HEAL >> $logfile 2>&1"

    # Replace any prior healer entry, keep everything else. Edit postgres's
    # crontab whether we're already postgres or escalating.
    set_crontab() { # reads new crontab on stdin
        if [ "$(id -un 2>/dev/null)" = postgres ]; then
            crontab -
        elif [ "$(id -u)" = 0 ] && crontab -u postgres -l >/dev/null 2>&1; then
            crontab -u postgres -          # Linux & FreeBSD support -u
        else
            as_root crontab -u postgres -
        fi
    }
    get_crontab() {
        if [ "$(id -un 2>/dev/null)" = postgres ]; then crontab -l 2>/dev/null
        elif [ "$(id -u)" = 0 ]; then crontab -u postgres -l 2>/dev/null
        else as_root crontab -u postgres -l 2>/dev/null; fi
    }
    # Ensure the log dir exists for postgres.
    logdir=$(dirname "$logfile")
    ( [ "$(id -un 2>/dev/null)" = postgres ] && mkdir -p "$logdir" ) 2>/dev/null \
        || as_root install -d -o postgres -g postgres "$logdir" 2>/dev/null || true

    { get_crontab | grep -v 'replica-heal.sh' || true; printf '%s\n' "$line"; } | set_crontab || return 1
    log "installed postgres crontab entry (every ${INTERVAL_MIN}min)"
    log "  view:    crontab -u postgres -l   (or as postgres: crontab -l)"
    log "  logfile: $logfile"
}

# Install the healer to a stable, postgres-readable path. The repo often lives
# in a user home the postgres user can't traverse, but the schedule runs the
# healer AS postgres (systemd User=postgres / postgres crontab) — so referencing
# the in-repo path fails with EACCES. Copy it somewhere world-readable.
INSTALL_PATH="${HEAL_INSTALL_PATH:-/usr/local/bin/hopper-replica-heal.sh}"
if [ "$HEAL" != "$INSTALL_PATH" ]; then
    if as_root install -D -m 0755 "$HEAL" "$INSTALL_PATH" 2>/dev/null; then
        log "installed healer -> $INSTALL_PATH"
        HEAL="$INSTALL_PATH"
    else
        warn "could not copy healer to $INSTALL_PATH; using in-place $HEAL (postgres must be able to read it)"
    fi
fi

# --- pick scheduler --------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if install_systemd; then exit 0; fi
    warn "systemd install failed (need root via sudo/doas?) — falling back to cron"
fi
if command -v crontab >/dev/null 2>&1; then
    if install_cron; then exit 0; fi
    warn "cron install failed"
fi

warn "could not auto-install a schedule. Run the healer manually on a timer:"
warn "  $HEAL"
warn "  (env: $(heal_env | tr '\n' ' '))"
exit 1
