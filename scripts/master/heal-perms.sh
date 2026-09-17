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
# Exception — hopper's upload tree (incoming/uploads): same group + 2775 dirs, but
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
# changes (with the old->new transition); those lines are tallied for the
# summary, and printed only under HEAL_VERBOSE.
#
# OUTPUT CONTRACT: silent on success. Nothing reaches stdout unless
# HEAL_VERBOSE=1; the summary goes to syslog, and only real errors go to stderr
# (with a non-zero exit).
#
# This matters because the two deployments consume output very differently. The
# systemd unit routes stdout to the journal, where a per-path line is cheap. The
# FreeBSD periodic(8) wrapper MAILS stdout to root, where it is not: this tree is
# never clean — forager unpacks archive members carrying the source image's modes
# (an /etc/shadow inside a squashfs arrives 0600 root-owned), so every run heals
# one to two million entries and mailed one line for each. On smaug that grew
# /var/mail/root to 16 GB, on the same pool whose filling takes the host down.
#
#   dirs=485685  files=416586  upload_files=1326640   <- one ordinary day
#
# The tally is worth keeping — it is how the daily unpack-permission churn was
# measured at all — so it goes to syslog, which both platforms retain and
# neither mails.
#
# No `find -L`: every walk matches the symlink itself (a symlink is never -type
# d or -type f), so a symlink planted in the tree cannot redirect a chmod onto
# the system directory it points at.
#
# Env:
#   DATA_DIR        sample root      (default /data/samples)
#   SAMPLES_GROUP   owning group     (default samples)
#   HEAL_VERBOSE    1 = print every healed path and the summary to stdout
#                   (default 0: summary to syslog, stdout silent)
set -eu

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

DATA_DIR="${DATA_DIR:-/data/samples}"
GROUP="${SAMPLES_GROUP:-samples}"
VERBOSE="${HEAL_VERBOSE:-0}"

# GNU coreutils reports only changed entries with -c; FreeBSD provides the
# equivalent useful output with -v. The find predicates already select only
# entries that need repair, so -v remains one line per change.
case "$(uname -s)" in
FreeBSD) CHANGE_FLAG=-v ;;
*)       CHANGE_FLAG=-c ;;
esac

# hopper's upload trees are healed like the rest (group + 2775 dirs), but their
# sample files are 0440 not 0444 (see header), so the file pass splits on them.
# One tree per producer plus the fallback root, which also holds the .tmp spool.
# Keep the former unknown/ trees in this permission class while old files drain.
UPLOAD_DIR="$DATA_DIR/incoming/uploads"
UPLOAD_DIRS="$UPLOAD_DIR $DATA_DIR/incoming/scan $DATA_DIR/incoming/prism $DATA_DIR/incoming/forager \
$DATA_DIR/unknown/uploads $DATA_DIR/unknown/scan $DATA_DIR/unknown/prism $DATA_DIR/unknown/forager"

# Subtree to leave untouched: only hopper's in-flight upload staging dir. Its
# temp files are mid-write with transient modes, and hopper sets their final
# mode on rename, so the heal must never touch them. Empty disables the
# exclusion. (Was the whole upload tree; narrowed to .tmp once uploads joined
# the shared contract.)
EXCLUDE="${HEAL_EXCLUDE:-$UPLOAD_DIR/.tmp}"

[ -d "$DATA_DIR" ] || { echo "heal-perms: DATA_DIR does not exist: $DATA_DIR" >&2; exit 1; }
getent group "$GROUP" >/dev/null 2>&1 || { echo "heal-perms: group does not exist: $GROUP" >&2; exit 1; }

log() { echo "heal-perms: $*"; }

# Real failures are collected here and reported at the end. Until now every
# chmod/chgrp ran under `2>/dev/null` with `|| true`, so an EPERM or a read-only
# filesystem was indistinguishable from a clean run — the script could not
# report an error even in principle. Silencing stderr wholesale was doing one
# necessary job (see below) and one harmful one; this separates them.
ERR_SPOOL=$(mktemp -t hopper-heal-perms.err.XXXXXX) || {
    echo "heal-perms: cannot create error spool" >&2; exit 1; }
trap 'rm -f "$ERR_SPOOL"' EXIT HUP INT TERM

# A file that vanishes between the find and the chmod is the normal case here,
# not a fault: draino relocates samples out of this tree continuously while the
# walk runs, and every such race surfaces as ENOENT. Those are dropped; anything
# else is a real error. Matching on the message is the portable option — GNU and
# BSD chmod share the wording and neither offers a machine-readable failure mode.
drop_benign() {
    grep -v -e 'No such file or directory' -e 'no such file or directory' "$1" || true
}

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
grp_out=$(find "$DATA_DIR" 2>>"$ERR_SPOOL" -path "$EXCLUDE" -prune -o ! -group "$GROUP" -print0 \
    | xargs -0 -r -n 4096 chgrp "$CHANGE_FLAG" -h "$GROUP" 2>>"$ERR_SPOOL") || true

# 2. Directories not already exactly 2775 (setgid + group-writable), whole tree.
dir_out=$(find "$DATA_DIR" 2>>"$ERR_SPOOL" -path "$EXCLUDE" -prune -o -type d ! -perm 2775 -print0 \
    | xargs -0 -r -n 2048 chmod "$CHANGE_FLAG" 2775 2>>"$ERR_SPOOL") || true

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
file_out=$(find "$DATA_DIR" 2>>"$ERR_SPOOL" "$@" -prune -o -type f ! -perm 0444 -print0 \
    | xargs -0 -r -n 4096 chmod "$CHANGE_FLAG" 0444 2>>"$ERR_SPOOL") || true

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
    upload_out=$(find "$@" 2>>"$ERR_SPOOL" -path "$EXCLUDE" -prune -o -type f ! -perm 0440 -print0 \
        | xargs -0 -r -n 4096 chmod "$CHANGE_FLAG" 0440 2>>"$ERR_SPOOL") || true
fi

# Per-path heal log, opt-in only. On the FreeBSD host this is one to two million
# lines a day straight into root's mail spool; see the OUTPUT CONTRACT above.
if [ "$VERBOSE" = 1 ]; then
    for o in "$grp_out" "$dir_out" "$file_out" "$upload_out"; do
        if [ -n "$o" ]; then printf '%s\n' "$o"; fi
    done
fi

count() { [ -z "$1" ] && { printf 0; return; }; printf '%s\n' "$1" | wc -l | tr -d '[:space:]'; }
summary="healed under $DATA_DIR (group=$GROUP): regrouped=$(count "$grp_out") dirs=$(count "$dir_out") files=$(count "$file_out") upload_files=$(count "$upload_out")"

# Syslog, not stdout: retained by the journal on systemd and by syslogd on
# FreeBSD, mailed by neither. Under HEAL_VERBOSE it also goes to stdout, which is
# what a hand-run invocation wants.
logger -t hopper-heal-perms -p daemon.info "$summary" 2>/dev/null || true
# An explicit if, not "[ ... ] && log": under set -e a false AND-OR list exits
# the script, so the non-verbose path would return here before reporting errors
# — the same trap the upload-tree loop above documents.
if [ "$VERBOSE" = 1 ]; then
    log "$summary"
fi

# The only thing that reaches stderr, and the only thing that fails the run.
errs=$(drop_benign "$ERR_SPOOL")
if [ -n "$errs" ]; then
    printf '%s\n' "$errs" | sed 's/^/heal-perms: /' >&2
    echo "heal-perms: $summary" >&2
    exit 1
fi
exit 0
