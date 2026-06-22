#!/bin/sh
# heal-perms.sh — enforce the shared-tree permission contract on the sample
# store. Run as root, periodically, by the hopper-heal-perms.timer.
#
# /data/samples is shared by forager, hopper, and the promoter — all members of
# the 'samples' group. The contract every writer is expected to honour:
#
#   group   samples              every cooperating service can read/traverse.
#   dirs    2775 setgid|rwxrwxr-x  group-writable so any service can
#                                mkdir/rename/unlink within; setgid so new
#                                children inherit the samples group.
#   files   0444 read-only       samples are immutable: the path *is* the
#                                sha256, so the bytes must never change in
#                                place. Move/replace/delete need only the parent
#                                directory's write bit, which 2775 already
#                                grants — a file's own write bit is never
#                                required to relayout the tree.
#
# forager (pkg/outputperms) and hopper (cmd/hopper/perms.go) already self-heal
# the subtrees they write. This is the safety net for drift introduced by
# writers that bypass that path: a manual `mv`, the relayout, a root-run import.
#
# Each pass only touches entries that are *actually* wrong — the find filters
# select on the bit that is off — so a clean tree costs three cheap walks and
# zero chmod/chgrp calls. GNU chgrp/chmod -c prints one line per entry it
# changes (with the old->new transition); those lines are mirrored to the
# journal as the per-path heal log and tallied for the summary, in one walk.
# A clean tree logs nothing but the summary.
#
# No `find -L`: every walk matches the symlink itself (a symlink is never -type
# d or -type f), so a symlink planted in the tree cannot redirect a chmod onto
# the system directory it points at.
#
# Env:
#   DATA_DIR        sample root      (default /data/samples)
#   SAMPLES_GROUP   owning group     (default samples)
set -eu

DATA_DIR="${DATA_DIR:-/data/samples}"
GROUP="${SAMPLES_GROUP:-samples}"

[ -d "$DATA_DIR" ] || { echo "heal-perms: DATA_DIR does not exist: $DATA_DIR" >&2; exit 1; }
getent group "$GROUP" >/dev/null 2>&1 || { echo "heal-perms: group does not exist: $GROUP" >&2; exit 1; }

log() { echo "heal-perms: $*"; }

# Capture each pass's -c change lines (chgrp/chmod print one "... changed from X
# to Y" line per entry they touch), then print them and tally them. We can't tee
# them to the journal mid-pipeline: under StandardOutput=journal the service's
# fd 1/2 are journal sockets, and /dev/stderr (a /proc/self/fd symlink) can't be
# reopened onto a socket. So we buffer in a variable, print to stdout (which the
# unit routes to the journal), and count for the summary. xargs' own stderr is
# dropped (2>/dev/null) so a file deleted mid-walk is a silent no-op; `|| true`
# keeps a per-entry chmod failure (e.g. EPERM) from aborting the later passes.

# 1. Group ownership: any entry not already in the samples group. -h regroups a
#    stray symlink as the link itself rather than following it to its target.
grp_out=$(find "$DATA_DIR" ! -group "$GROUP" -print0 \
    | xargs -0 -r -n 4096 chgrp -ch "$GROUP" -- 2>/dev/null) || true

# 2. Directories not already exactly 2775 (setgid + group-writable).
dir_out=$(find "$DATA_DIR" -type d ! -perm 2775 -print0 \
    | xargs -0 -r -n 2048 chmod -c 2775 -- 2>/dev/null) || true

# 3. Regular files not already exactly 0444 (read-only). Immutability is
#    deliberate; see the contract above.
file_out=$(find "$DATA_DIR" -type f ! -perm 0444 -print0 \
    | xargs -0 -r -n 4096 chmod -c 0444 -- 2>/dev/null) || true

# Per-path heal log to the journal (nothing on a clean tree).
for o in "$grp_out" "$dir_out" "$file_out"; do
    if [ -n "$o" ]; then printf '%s\n' "$o"; fi
done

count() { [ -z "$1" ] && { printf 0; return; }; printf '%s\n' "$1" | wc -l | tr -d '[:space:]'; }
log "healed under $DATA_DIR (group=$GROUP): regrouped=$(count "$grp_out") dirs=$(count "$dir_out") files=$(count "$file_out")"
