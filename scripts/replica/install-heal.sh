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
# Alongside the healer it schedules replica-textfile.sh, which publishes
# subscriber-side health as Prometheus textfile metrics. That runs on its OWN
# timer, not as a second ExecStart of the healer: the healer exits non-zero
# whenever it alerts, and metrics must keep flowing exactly then.
#
# Env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB, PUBLICATION, SUBSCRIPTION,
# PGPASSFILE, HEAL_ALERT_CMD (baked into the schedule), HEAL_INTERVAL_MIN (=5),
# TEXTFILE_INTERVAL_MIN (=1), HOST_MON_TEXTFILE_DIR (=/var/lib/host-mon/textfile),
# REPLICA_TEXTFILE (=true; 'false' skips the metrics timer).

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
HEAL="$SCRIPT_DIR/replica-heal.sh"
[ -f "$HEAL" ] || { echo "install-heal: $HEAL not found" >&2; exit 1; }
chmod +x "$HEAL" 2>/dev/null || true

TEXTFILE_SRC="$SCRIPT_DIR/replica-textfile.sh"
SLIM_SRC="$SCRIPT_DIR/slim-indexes.sh"
TEXTFILE_DIR="${HOST_MON_TEXTFILE_DIR:-/var/lib/host-mon/textfile}"
TEXTFILE_INTERVAL_MIN="${TEXTFILE_INTERVAL_MIN:-1}"
case "$TEXTFILE_INTERVAL_MIN" in *[!0-9]*|'') echo "install-heal: TEXTFILE_INTERVAL_MIN must be an integer" >&2; exit 1 ;; esac

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

# The emitter needs the publisher coordinates (for lag) and the textfile dir.
# It reads the keep list from slim-indexes.sh next to itself, so both are
# installed to the same directory below.
textfile_env() {
    for v in REMOTE_HOST REMOTE_USER REMOTE_DB LOCAL_DB SUBSCRIPTION PGPASSFILE; do
        eval "val=\${$v:-}"
        [ -n "${val:-}" ] && printf '%s=%s\n' "$v" "$val"
    done
    printf 'HOST_MON_TEXTFILE_DIR=%s\n' "$TEXTFILE_DIR"
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

    install_systemd_textfile || warn "metrics timer not installed (healer is still scheduled)"
}

# Separate unit from the healer on purpose: the healer exits 1 whenever it
# alerts, and a second ExecStart in the same oneshot would be skipped exactly
# when the replica is unhealthy — i.e. when the metrics matter most.
install_systemd_textfile() {
    [ "${REPLICA_TEXTFILE:-true}" = true ] || { log "REPLICA_TEXTFILE=false — skipping metrics timer"; return 0; }
    [ -f "$TEXTFILE_EXEC" ] || { warn "replica-textfile.sh not installed — skipping metrics timer"; return 1; }

    unit_dir=/etc/systemd/system
    tf_svc="$unit_dir/hopper-replica-textfile.service"
    tf_tmr="$unit_dir/hopper-replica-textfile.timer"
    tf_envlines=$(textfile_env | sed 's/^/Environment=/')

    as_root install -d -o postgres -g postgres -m 0755 "$TEXTFILE_DIR" 2>/dev/null \
        || warn "could not create $TEXTFILE_DIR as postgres — the emitter will try at run time"

    tf_svc_body=$(cat <<EOF
[Unit]
Description=hopper logical-replica health metrics (Prometheus textfile)
After=postgresql.service

[Service]
Type=oneshot
User=postgres
ExecStart=$TEXTFILE_EXEC
$tf_envlines
EOF
)
    tf_tmr_body=$(cat <<EOF
[Unit]
Description=emit hopper replica health metrics every ${TEXTFILE_INTERVAL_MIN}min

[Timer]
OnBootSec=1min
OnUnitActiveSec=${TEXTFILE_INTERVAL_MIN}min
Persistent=true

[Install]
WantedBy=timers.target
EOF
)
    printf '%s\n' "$tf_svc_body" | as_root tee "$tf_svc" >/dev/null || return 1
    printf '%s\n' "$tf_tmr_body" | as_root tee "$tf_tmr" >/dev/null || return 1
    as_root systemctl daemon-reload || return 1
    as_root systemctl enable --now hopper-replica-textfile.timer || return 1
    log "installed metrics timer (every ${TEXTFILE_INTERVAL_MIN}min) -> $TEXTFILE_DIR/hopper-replica.prom"
    log "  NOTE: Alloy must have the textfile collector enabled for this directory."
    log "        host-mon/alloy/linux.alloy needs \"textfile\" in set_collectors + a textfile block."
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

    tf_line=""
    if [ "${REPLICA_TEXTFILE:-true}" = true ] && [ -f "$TEXTFILE_EXEC" ]; then
        tf_envstr=$(textfile_env | tr '\n' ' ')
        tf_line="*/$TEXTFILE_INTERVAL_MIN * * * * ${tf_envstr}$TEXTFILE_EXEC >/dev/null 2>&1"
        mkdir -p "$TEXTFILE_DIR" 2>/dev/null \
            || as_root install -d -o postgres -g postgres "$TEXTFILE_DIR" 2>/dev/null || true
    fi

    { get_crontab | grep -v -e 'replica-heal.sh' -e 'replica-textfile.sh' || true
      printf '%s\n' "$line"
      [ -n "$tf_line" ] && printf '%s\n' "$tf_line"
    } | set_crontab || return 1
    log "installed postgres crontab entry (every ${INTERVAL_MIN}min)"
    [ -n "$tf_line" ] && log "installed metrics crontab entry (every ${TEXTFILE_INTERVAL_MIN}min) -> $TEXTFILE_DIR/hopper-replica.prom"
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

# The emitter and the slim-indexes policy travel with the healer: the emitter
# reads REPLICA_KEEP_INDEXES from slim-indexes.sh sitting next to it, so both
# must land in the same postgres-readable directory.
TEXTFILE_EXEC="${REPLICA_TEXTFILE_INSTALL_PATH:-/usr/local/bin/hopper-replica-textfile.sh}"
if [ -f "$TEXTFILE_SRC" ]; then
    if as_root install -D -m 0755 "$TEXTFILE_SRC" "$TEXTFILE_EXEC" 2>/dev/null; then
        log "installed metrics emitter -> $TEXTFILE_EXEC"
        if [ -f "$SLIM_SRC" ]; then
            slim_dst="$(dirname "$TEXTFILE_EXEC")/slim-indexes.sh"
            as_root install -D -m 0755 "$SLIM_SRC" "$slim_dst" 2>/dev/null \
                || warn "could not copy slim-indexes.sh to $slim_dst — index-policy metrics will be absent"
        fi
    else
        warn "could not copy replica-textfile.sh to $TEXTFILE_EXEC — metrics will not be scheduled"
        TEXTFILE_EXEC=""
    fi
else
    warn "replica-textfile.sh not found next to the healer — metrics will not be scheduled"
    TEXTFILE_EXEC=""
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
