#!/bin/sh
# zfs-tune.sh — apply (or revert) the ZFS dataset tuning hopper uses for a
# DISPOSABLE read replica.
#
# A replica serves reads only and can be rebuilt from the publisher at any
# time, so it's safe to trade crash durability for write throughput:
#   apply  (read-replica) -> sync=disabled,  logbias=throughput
#   revert (durable prim.) -> sync=standard,  logbias=latency
# sync=disabled lets ZFS ignore fsync/O_SYNC (no ZIL waits) — a big win for the
# initial bulk copy and steady apply — at the cost of losing the last few
# seconds of writes on an unclean shutdown. That's fine for a read replica (you
# rebuild it); it is NOT fine for a primary, so promote.sh reverts it.
#
#   zfs-tune.sh apply  [DATASET ...]
#   zfs-tune.sh revert [DATASET ...]
#
# With no DATASET it auto-detects the dataset(s) backing the local cluster's
# data_directory (and its pg_wal, if on a separate dataset). Needs root for
# `zfs set` (probes direct/doas/sudo). Best-effort and idempotent: where it
# can't manage ZFS — notably INSIDE a Bastille jail, whose pool lives on the
# host — it prints how to run it on the host and exits 0 so callers don't fail.

set -eu

MODE="${1:-}"
[ $# -gt 0 ] && shift || true
case "$MODE" in
    apply)  SYNC=disabled; LOGBIAS=throughput ;;
    revert) SYNC=standard; LOGBIAS=latency ;;
    *) echo "usage: $0 apply|revert [dataset ...]" >&2; exit 2 ;;
esac

log() { echo "==> zfs-tune: $*"; }

# Root escalation for `zfs` (distinct from the postgres escalation callers use).
if [ "$(id -u)" = "0" ]; then
    ZE=""
elif command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1; then
    ZE="doas"
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    ZE="sudo"
elif command -v doas >/dev/null 2>&1; then
    ZE="doas"
elif command -v sudo >/dev/null 2>&1; then
    ZE="sudo"
else
    ZE=""
fi
# shellcheck disable=SC2086 # $ZE is a fixed, script-controlled prefix
zfs_cmd() { if [ -z "$ZE" ]; then zfs "$@"; else $ZE zfs "$@"; fi; }

command -v zfs >/dev/null 2>&1 || {
    log "no 'zfs' command here — skipping (run on the ZFS host if this is a jail)"
    exit 0
}
if ! zfs_cmd list -H -o name >/dev/null 2>&1; then
    log "cannot access ZFS here — a Bastille jail can't tune the host's pool."
    log "Run on the host:  $0 $MODE <pool>/<pgdata-dataset>"
    exit 0
fi

# --- Resolve the dataset(s) to tune ----------------------------------------
# Map a filesystem path to the ZFS dataset whose mountpoint is its longest
# prefix (handles nested datasets, e.g. a separate pg_wal child).
_ds_for_path() {
    _p=$(realpath "$1" 2>/dev/null || printf '%s' "$1")
    zfs_cmd list -H -o mountpoint,name 2>/dev/null | awk -v p="$_p/" '
        $1 != "-" && $1 != "legacy" {
            mp = $1; if (mp !~ /\/$/) mp = mp "/"
            if (index(p, mp) == 1 && length(mp) > bl) { bl = length(mp); ds = $2 }
        }
        END { if (ds) print ds }'
}

# Find the local cluster's data_directory when no dataset was named. Prefer a
# PGDATA passed in the environment by the caller (setup.sh knows it); else ask
# postgres directly via whatever escalation works.
_get_pgdata() {
    if [ -n "${PGDATA:-}" ]; then printf '%s' "$PGDATA"; return 0; fi
    for pfx in "" "doas -u postgres " "sudo -u postgres "; do
        # shellcheck disable=SC2086
        _dd=$(${pfx}psql -U postgres -tAc 'SHOW data_directory' 2>/dev/null | tr -d '[:space:]') || _dd=""
        [ -n "$_dd" ] && { printf '%s' "$_dd"; return 0; }
    done
    return 1
}

DATASETS="$*"
if [ -z "$DATASETS" ]; then
    dd=$(_get_pgdata || true)
    [ -n "$dd" ] || { log "could not determine data_directory and no dataset given — skipping"; exit 0; }
    DATASETS=$(_ds_for_path "$dd")
    wal=$(_ds_for_path "$dd/pg_wal")
    [ -n "$wal" ] && [ "$wal" != "$DATASETS" ] && DATASETS="$DATASETS $wal"
    [ -n "$DATASETS" ] || { log "'$dd' is not on ZFS (or no dataset matched) — skipping"; exit 0; }
fi

# --- Apply -----------------------------------------------------------------
for ds in $DATASETS; do
    log "$MODE $ds -> sync=$SYNC logbias=$LOGBIAS"
    zfs_cmd set "sync=$SYNC" "$ds"       || log "warning: failed to set sync on $ds"
    zfs_cmd set "logbias=$LOGBIAS" "$ds" || log "warning: failed to set logbias on $ds"
done
# shellcheck disable=SC2086 # intentional word-split of the dataset list
zfs_cmd get -o name,property,value sync,logbias $DATASETS 2>/dev/null || true
