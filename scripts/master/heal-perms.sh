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
# Exception — hopper's upload tree (unknown/uploads): same group + 2775 dirs, but
# its sample files are 0440 (group-private, no world read) since they are
# hopper's own ingest and nothing outside the group reads them off disk. Its
# .tmp staging dir is skipped entirely: those files are mid-write with transient
# modes and hopper re-asserts their final mode on rename.
#
# forager (pkg/outputperms) and hopper (cmd/hopper/perms.go) already self-heal
# the subtrees they write. This is the safety net for drift introduced by
# writers that bypass that path: a manual `mv`, the relayout, a root-run import,
# or upload shards a setgid-blocked hopper left group-private.
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

# hopper's upload trees are healed like the rest (group + 2775 dirs), but their
# sample files are 0440 not 0444 (see header), so the file pass splits on them.
# One tree per producer plus the legacy root, which also holds the .tmp spool.
UPLOAD_DIR="$DATA_DIR/unknown/uploads"
UPLOAD_DIRS="$UPLOAD_DIR $DATA_DIR/unknown/scan $DATA_DIR/unknown/prism $DATA_DIR/unknown/forager"

# Subtree to leave untouched: only hopper's in-flight upload staging dir. Its
# temp files are mid-write with transient modes, and hopper sets their final
# mode on rename, so the heal must never touch them. Empty disables the
# exclusion. (Was the whole upload tree; narrowed to .tmp once uploads joined
# the shared contract.)
EXCLUDE="${HEAL_EXCLUDE:-$UPLOAD_DIR/.tmp}"

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

# Each walk prunes $EXCLUDE first: `-path EXCLUDE -prune -o <test> -print0` reads
# as "(path is EXCLUDE and prune) or (<test> and print)", so the excluded subtree
# is never descended or acted on. An empty EXCLUDE matches no path, disabling it.

# 1. Group ownership: any entry not already in the samples group (whole tree,
#    upload shards included). -h regroups a stray symlink as the link itself
#    rather than following it to its target.
grp_out=$(find "$DATA_DIR" -path "$EXCLUDE" -prune -o ! -group "$GROUP" -print0 \
    | xargs -0 -r -n 4096 chgrp -ch "$GROUP" -- 2>/dev/null) || true

# 2. Directories not already exactly 2775 (setgid + group-writable), whole tree.
dir_out=$(find "$DATA_DIR" -path "$EXCLUDE" -prune -o -type d ! -perm 2775 -print0 \
    | xargs -0 -r -n 2048 chmod -c 2775 -- 2>/dev/null) || true

# 3. Regular files outside the upload trees → 0444 (read-only, world-readable).
#    Every upload tree is pruned here and handled by pass 4. Immutability is
#    deliberate; see the contract above. The prune expression is built in the
#    positional parameters so a path containing spaces survives word splitting.
set -- "("
for tree in $UPLOAD_DIRS; do
    [ "$#" -eq 1 ] || set -- "$@" -o
    set -- "$@" -path "$tree"
done
set -- "$@" ")"
file_out=$(find "$DATA_DIR" "$@" -prune -o -type f ! -perm 0444 -print0 \
    | xargs -0 -r -n 4096 chmod -c 0444 -- 2>/dev/null) || true

# 4. Upload sample files → 0440 (group-private; see header). Walks only the trees
#    that exist, pruning the in-flight .tmp staging dir.
set --
for tree in $UPLOAD_DIRS; do
    # An explicit if, not "[ -d ] && set": under set -e a false AND-OR list
    # exits the script, so the first absent tree would abort the heal.
    if [ -d "$tree" ]; then set -- "$@" "$tree"; fi
done
upload_out=""
if [ "$#" -gt 0 ]; then
    upload_out=$(find "$@" -path "$EXCLUDE" -prune -o -type f ! -perm 0440 -print0 \
        | xargs -0 -r -n 4096 chmod -c 0440 -- 2>/dev/null) || true
fi

# Per-path heal log to the journal (nothing on a clean tree).
for o in "$grp_out" "$dir_out" "$file_out" "$upload_out"; do
    if [ -n "$o" ]; then printf '%s\n' "$o"; fi
done

count() { [ -z "$1" ] && { printf 0; return; }; printf '%s\n' "$1" | wc -l | tr -d '[:space:]'; }
log "healed under $DATA_DIR (group=$GROUP): regrouped=$(count "$grp_out") dirs=$(count "$dir_out") files=$(count "$file_out") upload_files=$(count "$upload_out")"
