#!/usr/bin/env bash
# linux-systemd.sh - Install hopper as a hardened systemd service on the local host.
#
# hopper runs `hopper load` which forks litmus + rizin children to analyse
# samples under DATA_DIR and push results into postgres. Memory/Tasks caps
# are sized for that workload (litmus-heavy, up to ~32 GiB RSS).
#
# Idempotent: re-running is safe. The service is only daemon-reloaded and
# restarted when the binary or unit file actually changed on disk.
#
# Variables (env):
#   DATA_DIR  sample directory (read-only to hopper except unknown/uploads)
#                                    (default: /data/samples)
#   DB        postgres DSN (password resolved from the installed .pgpass)
#                                    (default: postgres://hopper@hopper-db/hopper?sslmode=disable)
#   SOURCE    --source tag           (default: forager)
#   DASH_ADDR --dashboard-addr       (default: 0.0.0.0:8081)
#   WORKERS   --workers              (default: 40; set 0 for hopper's auto-pick)
#   MAX_MEMORY_GB  --max-memory-gb    litmus RSS cap in GB, forwarded as
#                 --max-rss-gb (default: 48; 0 = litmus self-throttle,
#                 -1 = disable in-process throttling)
#   PULL_DISABLE  set to 1 to skip the git pull of ../scan and ../cleave and
#                 build the current checkouts as-is (e.g. when the remote is down)

set -euo pipefail

DATA_DIR="${DATA_DIR:-/data/samples}"
UPLOAD_DIR="${DATA_DIR}/unknown/uploads"
# Shared group for the sample tree. forager, hopper, and promoter all run in it
# so any of them can read/traverse the others' output; setgid dirs make new
# children inherit it. hopper's upload tree joins this contract.
SAMPLES_GROUP="${SAMPLES_GROUP:-samples}"
DB="${DB:-postgres://hopper@hopper-db/hopper?sslmode=disable}"
SOURCE="${SOURCE:-forager}"
DASH_ADDR="${DASH_ADDR:-0.0.0.0:8081}"
WORKERS="${WORKERS:-40}"
MAX_MEMORY_GB="${MAX_MEMORY_GB:-48}"
PULL_DISABLE="${PULL_DISABLE:-0}"

readonly SERVICE_USER=hopper
readonly SERVICE_NAME=hopper
readonly BINARY=hopper
readonly BIN_PATH=/usr/local/bin/${BINARY}
readonly CONFIG_DIR=/etc/${SERVICE_NAME}
readonly STATE_HOME=/var/lib/${SERVICE_NAME}
readonly TOOLS_DIR=${STATE_HOME}/bin
readonly CACHE_HOME=/var/cache/${SERVICE_NAME}
readonly UNIT_FILE=/etc/systemd/system/${SERVICE_NAME}.service

# Shared memory budget for the whole sample pipeline (hopper + forager +
# promoter). All three live under this slice so their *combined* footprint is
# bounded; without it they share system.slice, which has no ceiling, and an
# unbounded sibling (promoter has peaked at ~95 GiB) drives the host into a
# *global* OOM that kills an arbitrary victim — repeatedly, hopper itself.
# forager/promoter ship from their own repos, so their slice membership and caps
# are layered on as drop-ins here (this is the host's master deploy script); a
# drop-in survives a redeploy of the foreign unit, a live edit would not.
readonly SLICE_NAME=atomdrift
readonly SLICE_FILE=/etc/systemd/system/${SLICE_NAME}.slice
readonly FORAGER_DROPIN=/etc/systemd/system/forager.service.d/10-${SLICE_NAME}-slice.conf
readonly PROMOTER_DROPIN=/etc/systemd/system/promoter.service.d/10-${SLICE_NAME}-slice.conf

# Permission-heal timer: a root oneshot that re-asserts the shared-tree contract
# (samples group + setgid dirs + read-only files) on DATA_DIR, catching drift
# from writers that bypass forager's/hopper's own self-heal. The interval is
# env-overridable; the heal is a no-op when the tree is already clean.
readonly HEAL_PERMS_SRC=scripts/master/heal-perms.sh
readonly HEAL_PERMS_BIN=/usr/local/bin/hopper-heal-perms.sh
readonly HEAL_PERMS_SVC=/etc/systemd/system/hopper-heal-perms.service
readonly HEAL_PERMS_TIMER=/etc/systemd/system/hopper-heal-perms.timer
# Hourly by default: a full /data/samples walk is minutes-long on a large tree
# and runs every tick regardless of drift, so a tight cadence keeps the tree
# under near-constant traversal I/O for little benefit — forager and hopper
# already self-heal the subtrees they write, leaving this as a backstop for
# manual/relayout/root drift. Override for a tighter or looser window.
HEAL_PERMS_INTERVAL_MIN="${HEAL_PERMS_INTERVAL_MIN:-60}"
case "$HEAL_PERMS_INTERVAL_MIN" in *[!0-9]*|'') die "HEAL_PERMS_INTERVAL_MIN must be an integer" ;; esac

# Sibling repos that ship alongside hopper. `make deploy` updates both,
# builds them in release mode, and installs the resulting binaries into
# TOOLS_DIR.
readonly SCAN_SRC=../scan
readonly CLEAVE_SRC=../cleave
# Atomdrift Scan installs as 'ascan' to avoid colliding with the unrelated
# 'litmus' WebDAV tool. ('litmus' remains the internal codename in hopper/db.)
readonly SCAN_BIN=${TOOLS_DIR}/ascan
readonly CLEAVE_BIN=${TOOLS_DIR}/cleave

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

declare -a TMP_FILES=()
trap 'if (( ${#TMP_FILES[@]} > 0 )); then rm -f -- "${TMP_FILES[@]}"; fi' EXIT

# --- Preconditions -----------------------------------------------------------

[[ $(uname -s) == Linux ]]      || die "deploy requires Linux with systemd"
command -v systemctl >/dev/null || die "systemctl not found"
command -v git       >/dev/null || die "git not found"
[[ -f Makefile ]]                || die "run from the repository root"
[[ -d ${DATA_DIR} ]]             || die "DATA_DIR does not exist: ${DATA_DIR}"

# Privilege escalation: prefer doas (BSD default, and passwordless on some Linux
# hosts), fall back to sudo, no-op when already root. Mirrors the ladder the
# replica scripts use so deploy behaves the same everywhere.
if [[ $EUID -eq 0 ]]; then
    priv() { "$@"; }
elif command -v doas >/dev/null 2>&1; then
    priv() { doas "$@"; }
elif command -v sudo >/dev/null 2>&1; then
    priv() { sudo "$@"; }
else
    die "need root: install doas or sudo, or run as root"
fi
priv true || die "privilege escalation failed (doas/sudo)"

# Verify the escalation path can actually run the privileged commands this
# deploy and the perms-heal timer need — not merely `true`. A command-scoped
# doas/sudo policy (vs the common `permit nopass <user>`) can let `priv true`
# succeed yet deny chmod/chgrp, which would otherwise blow up deep in the
# deploy or leave a perms-heal timer that fails every cycle. Probe each with a
# side-effect-free --version. Only when escalation is non-interactive, so a
# password-scoped policy is not turned into a prompt storm.
priv_noninteractive() {
    [[ $EUID -eq 0 ]] && return 0
    command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1 && return 0
    command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 && return 0
    return 1
}
if priv_noninteractive; then
    declare -a priv_missing=()
    for c in install systemctl chgrp chmod find; do
        priv "$c" --version >/dev/null 2>&1 || priv_missing+=("$c")
    done
    if (( ${#priv_missing[@]} > 0 )); then
        die "doas/sudo is configured but not permitted to run: ${priv_missing[*]}
  the deploy installs units (install, systemctl) and the perms-heal timer runs
  chgrp/chmod as root. Grant these to $(id -un) — e.g. /etc/doas.conf:
      permit nopass $(id -un)
  (or a cmd-scoped rule covering the above) — or run 'make deploy' as root."
    fi
    log "doas/sudo capability check passed (install, systemctl, chgrp, chmod, find)"
else
    log "escalation requires a password; skipping non-interactive doas capability probe"
fi

# litmus and cleave are checked out alongside hopper and built in release
# mode during deploy. Their Makefiles drop the binary into ./out/<name>;
# we install those artifacts into TOOLS_DIR so the service has a single,
# hopper-owned location to exec from.
[[ -d ${SCAN_SRC}/.git ]] || die "Atomdrift Scan source not found at ${SCAN_SRC}; check out codeberg.org/atomdrift/scan there"
[[ -d ${CLEAVE_SRC}/.git ]] || die "cleave source not found at ${CLEAVE_SRC}; check out codeberg.org/atomdrift/cleave there"
command -v cargo >/dev/null || die "cargo not found on PATH; install the Rust toolchain to build litmus and cleave"

# --- Build -------------------------------------------------------------------

log "Building ${BINARY}"
make build
[[ -x ./${BINARY} ]] || die "build did not produce ./${BINARY}"

update_tool_source() {
    local name=$1 dir=$2

    if [[ ${PULL_DISABLE} != 0 ]]; then
        log "Skipping ${name} source pull (PULL_DISABLE=${PULL_DISABLE}); building current checkout"
        return
    fi
    log "Updating ${name} source"
    git -C "${dir}" pull --ff-only
}

update_tool_source scan "${SCAN_SRC}"
update_tool_source cleave "${CLEAVE_SRC}"

log "Building Atomdrift Scan (release)"
make -C "${SCAN_SRC}" release >/dev/null
[[ -x ${SCAN_SRC}/out/ascan ]] || die "scan build did not produce ${SCAN_SRC}/out/ascan"

log "Building cleave (release)"
make -C "${CLEAVE_SRC}" release >/dev/null
[[ -x ${CLEAVE_SRC}/out/cleave ]] || die "cleave build did not produce ${CLEAVE_SRC}/out/cleave"

# --- Service user + directories ---------------------------------------------

if ! getent passwd "${SERVICE_USER}" >/dev/null; then
    log "Creating service user '${SERVICE_USER}'"
    priv useradd --system --home-dir "${STATE_HOME}" --no-create-home \
                 --shell /usr/sbin/nologin \
                 --comment "Hopper service" "${SERVICE_USER}"
fi

# hopper must belong to the shared group: it reads the shared sample tree, and
# the setgid bit only sticks on a chmod when the process is in the dir's group
# (otherwise the kernel silently strips it, breaking group inheritance). The
# unit also sets SupplementaryGroups so the running process has it regardless,
# but keep the account's membership in sync too.
getent group "${SAMPLES_GROUP}" >/dev/null \
    || die "shared group '${SAMPLES_GROUP}' does not exist; create it (groupadd --system ${SAMPLES_GROUP}) or set SAMPLES_GROUP"
if ! id -nG "${SERVICE_USER}" | tr ' ' '\n' | grep -qx "${SAMPLES_GROUP}"; then
    log "Adding ${SERVICE_USER} to '${SAMPLES_GROUP}' group"
    priv usermod -aG "${SAMPLES_GROUP}" "${SERVICE_USER}"
fi

priv install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
    "${STATE_HOME}" "${CACHE_HOME}" "${CONFIG_DIR}" "${TOOLS_DIR}"

# Upload tree: part of the shared samples-group contract. Group ${SAMPLES_GROUP},
# setgid 2775 dirs so hopper's runtime sha-shard mkdirs (and .tmp staging)
# inherit the group, and read-only files. hopper writes here at runtime; the
# perms-heal timer deliberately skips this subtree (HEAL_EXCLUDE=${UPLOAD_DIR}),
# so this deploy is the only thing that (re)asserts the contract on it.
priv install -d -m 2775 -o "${SERVICE_USER}" -g "${SAMPLES_GROUP}" "${UPLOAD_DIR}"
priv install -d -m 2775 -o "${SERVICE_USER}" -g "${SAMPLES_GROUP}" "${UPLOAD_DIR}/.tmp"
# Heal a pre-existing tree from before this contract (e.g. hopper:hopper / 0750,
# or shards left group-private by the old setgid-blocked code path): regroup to
# ${SAMPLES_GROUP}, setgid+group-write every dir, mark every file read-only 0440.
log "Asserting shared-group contract on ${UPLOAD_DIR}"
priv chgrp -R "${SAMPLES_GROUP}" "${UPLOAD_DIR}"
priv find "${UPLOAD_DIR}" -type d -exec chmod 2775 {} +
priv find "${UPLOAD_DIR}" -type f -exec chmod 0440 {} +

# --- Binary ------------------------------------------------------------------

binary_changed=0
if priv cmp -s "./${BINARY}" "${BIN_PATH}" 2>/dev/null; then
    log "Binary unchanged"
else
    log "Installing ${BIN_PATH}"
    priv install -m 0755 -o root -g root "./${BINARY}" "${BIN_PATH}"
    binary_changed=1
fi

# Install litmus and cleave into the service user's TOOLS_DIR. A change in
# either counts as a "binary change" so the service is restarted below.
install_tool() {
    local src=$1 dst=$2 name=$3
    if priv cmp -s "${src}" "${dst}" 2>/dev/null; then
        log "${name} unchanged"
        return
    fi
    log "Installing ${dst}"
    priv install -m 0755 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${src}" "${dst}"
    binary_changed=1
}
install_tool "${SCAN_SRC}/out/ascan" "${SCAN_BIN}" ascan
install_tool "${CLEAVE_SRC}/out/cleave" "${CLEAVE_BIN}" cleave

# --- .pgpass (optional, from the invoking user) -----------------------------

pgpass_src=""
for candidate in "${PGPASSFILE:-}" "${HOME}/.pgpass"; do
    if [[ -n $candidate && -f $candidate ]]; then
        pgpass_src=$candidate
        break
    fi
done

pgpass_dst="${CONFIG_DIR}/.pgpass"
if [[ -n $pgpass_src ]]; then
    if priv cmp -s "$pgpass_src" "$pgpass_dst" 2>/dev/null; then
        log ".pgpass unchanged"
    else
        log "Installing .pgpass from ${pgpass_src}"
        priv install -m 0600 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
            "$pgpass_src" "$pgpass_dst"
    fi
elif [[ ! -e $pgpass_dst ]]; then
    log "No ~/.pgpass found; hopper will fail to authenticate until one is provided at ${pgpass_dst}"
fi

# --- Grafana Cloud OTLP token (optional, from the invoking user) ------------

# obs reads the base64 OTLP credential from $HOME/.tok/graf and, when present,
# pushes metrics/traces/logs to Grafana Cloud. HOME is the StateDirectory
# (%S/${SERVICE_NAME}), so stage the token there for the service user. Mirrors
# the .pgpass drop above: sourced from the deploying user, change-detected, 0600.
graf_src=""
for candidate in "${GRAF_TOKEN:-}" "${HOME}/.tok/graf"; do
    if [[ -n $candidate && -f $candidate ]]; then
        graf_src=$candidate
        break
    fi
done

graf_dst="${STATE_HOME}/.tok/graf"
if [[ -n $graf_src ]]; then
    priv install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_HOME}/.tok"
    if priv cmp -s "$graf_src" "$graf_dst" 2>/dev/null; then
        log "Grafana token unchanged"
    else
        log "Installing Grafana Cloud token from ${graf_src}"
        priv install -m 0600 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
            "$graf_src" "$graf_dst"
    fi
elif [[ ! -e $graf_dst ]]; then
    log "No ~/.tok/graf found; OTLP push to Grafana Cloud disabled until one is provided at ${graf_dst}"
fi

# --- Unit --------------------------------------------------------------------

tmp_unit=$(mktemp -t "${SERVICE_NAME}.service.XXXXXX")
TMP_FILES+=("$tmp_unit")

# --workers is only emitted when non-zero; hopper's own default (0 = auto)
# picks a sane per-host value.
workers_arg=""
(( WORKERS > 0 )) && workers_arg=" --workers ${WORKERS}"

# --max-memory-gb caps the litmus worker's RSS (forwarded as --max-rss-gb).
# Emitted for any non-zero value so the -1 "disable throttling" sentinel still
# passes through; 0 leaves it to litmus's own self-throttling.
max_mem_arg=""
(( MAX_MEMORY_GB != 0 )) && max_mem_arg=" --max-memory-gb ${MAX_MEMORY_GB}"

cat >"$tmp_unit" <<EOF
[Unit]
Description=Hopper sample ingester (spawns Atomdrift Scan workers)
Documentation=https://codeberg.org/atomdrift/hopper
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
# Run in the shared sample group so hopper can read the tree the siblings write
# and so the setgid bit sticks on the upload dirs it creates (the kernel strips
# setgid on chmod when the process is not in the target dir's group).
SupplementaryGroups=${SAMPLES_GROUP}

# Share the pipeline-wide memory budget (see ${SLICE_NAME}.slice). hopper is the
# primary service: it keeps the most generous per-service caps and the most
# protective OOMScoreAdjust, so under slice pressure the kernel sheds promoter
# (the runaway) first and leaves the ingester running.
Slice=${SLICE_NAME}.slice

ConfigurationDirectory=${SERVICE_NAME}
ConfigurationDirectoryMode=0750
StateDirectory=${SERVICE_NAME}
StateDirectoryMode=0750
CacheDirectory=${SERVICE_NAME}
CacheDirectoryMode=0750

WorkingDirectory=%S/${SERVICE_NAME}
ExecStart=${BIN_PATH} load --data ${DATA_DIR} --db ${DB} --source ${SOURCE} --dashboard-addr ${DASH_ADDR} --litmus ${SCAN_BIN} --cleave ${CLEAVE_BIN} --prune-missing-paths${workers_arg}${max_mem_arg}
Restart=on-failure
RestartSec=10s
TimeoutStopSec=60s

Environment=HOME=%S/${SERVICE_NAME}
Environment=XDG_CACHE_HOME=%C/${SERVICE_NAME}
Environment=PGPASSFILE=%E/${SERVICE_NAME}/.pgpass
Environment=PATH=${TOOLS_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Open upload endpoint: /api/upload accepts content pushes from scan --upload and
# forager with no bearer token (the browser CSRF guard still blocks form posts).
# This deployment is internal, so frictionless ingest beats shared-secret
# plumbing. To require a token instead, drop this line and set
# Environment=HOPPER_UPLOAD_TOKEN=<token>.
Environment=HOPPER_UPLOAD_OPEN=1

# Bound the Go heap so the runtime applies GC backpressure *before* the cgroup
# MemoryHigh below forces pages into swap. The hopper process RSS is almost
# entirely Go heap; without this the runtime grows to ~2x the live working set
# (GOGC=100) with the cgroup as the only ceiling, which reclaims into swap
# rather than collecting. Soft limit: a transient spike GCs harder instead of
# OOMing. Sits above the observed steady-state working set and below
# MemoryHigh/MemorySwapMax. NB: only bounds hopper itself, not the litmus child.
# 2026-06-21: raised 16->32GiB. 16 sat *below* a (bug-inflated) ~47GB live heap,
# which put GC into a death spiral (continuous GC it can't satisfy → CPU pegged
# → API unresponsive). 32 is an interim backstop pending the result-ingestion
# memory fix; revisit downward once the working set is actually bounded.
Environment=GOMEMLIMIT=32GiB

# OpenTelemetry → Grafana Cloud. No endpoint is set here on purpose: obs falls
# back to the Grafana Cloud OTLP gateway using the credential staged at
# $HOME/.tok/graf (see the token drop above). To target a self-hosted fleet
# instead, set OTEL_EXPORTER_OTLP_ENDPOINT (and _LOGS_ENDPOINT) in the env.

# Resource caps — hopper + litmus children combined.
MemoryHigh=80G
MemoryMax=96G
# Bound cgroup swap. Without this, MemoryMax is toothless: pages spill into
# swap (zram, i.e. compressed RAM) without limit, cannibalizing host memory
# until the box thrashes. Cap it so a runaway litmus worker is OOM-killed and
# retried (see OOMPolicy below) instead of swap-thrashing the whole host.
MemorySwapMax=8G
TasksMax=8192
# Child OOM (e.g. a rogue litmus worker) should be logged and retried, not
# bring down the whole ingester.
OOMPolicy=continue
# Protect the primary service. If the shared slice hits its ceiling the kernel
# kills the highest-scoring task in the slice; a strongly negative bias here
# makes hopper the last to be chosen (promoter, +600, goes first).
OOMScoreAdjust=-800

# Filesystem isolation. hopper is the pool's relocation authority: besides
# interactive uploads it moves samples between the good/bad/unknown trees
# (post-triage and promoter rulings via /api/triage), so the whole sample tree
# must be writable, not just the upload dir. The pools are separate ZFS mounts
# (good, bad, unknown) under the DATA_DIR parent; list each mountpoint so the
# ProtectSystem=strict read-only remount can't leave a submount read-only and
# fault a relocation with EROFS ("mkdir: read-only file system").
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${DATA_DIR}/good ${DATA_DIR}/bad ${DATA_DIR}/unknown
PrivateTmp=true
PrivateDevices=true
PrivateMounts=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
UMask=0077

# Process hardening. MemoryDenyWriteExecute is intentionally omitted because
# litmus/rizin children rely on executable mappings for binary analysis.
NoNewPrivileges=true
# RestrictSUIDSGID is intentionally NOT set. hopper creates setgid (2775) shard
# directories under the upload tree so each sha-shard inherits the shared
# '${SAMPLES_GROUP}' group; RestrictSUIDSGID's seccomp filter denies the setgid
# bit in mkdir/chmod and returns EPERM, which is what broke upload sharding
# ("upload: mkdir shard: operation not permitted"). The tree is hopper-owned and
# group-shared with no setuid binaries, and NoNewPrivileges=true neutralizes any
# setuid/setgid bit at exec time, so dropping this restriction adds no real risk.
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
# Re-allow chown family: upx (invoked transitively via litmus/cleave to unpack
# samples) calls chown when finalizing its output file, and @privileged
# subtracts @chown. Without this the syscall is killed with SIGSYS and upx
# core-dumps instead of returning a clean error.
SystemCallFilter=@chown
# Convert any remaining filter violations to EPERM rather than SIGSYS so a
# stray syscall in a child process degrades to an error instead of a crash.
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Logging.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

unit_changed=0
if priv cmp -s "$tmp_unit" "$UNIT_FILE" 2>/dev/null; then
    log "Unit unchanged"
else
    log "Writing ${UNIT_FILE}"
    priv install -m 0644 -o root -g root "$tmp_unit" "$UNIT_FILE"
    unit_changed=1
fi

# --- Activate ----------------------------------------------------------------

(( unit_changed )) && priv systemctl daemon-reload

priv systemctl enable --now "${SERVICE_NAME}.service" >/dev/null

if (( binary_changed || unit_changed )); then
    log "Restarting ${SERVICE_NAME}"
    if ! priv systemctl restart "${SERVICE_NAME}.service"; then
        priv systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
        die "service failed to start; see: journalctl -u ${SERVICE_NAME} -n 50"
    fi
else
    log "No changes; leaving service running"
fi

# --- Shared memory budget (slice + sibling drop-ins) -------------------------
# Cap the whole pipeline so it can never trigger a host-wide OOM. The host has
# ~125 GiB; the slice ceiling is 120 GiB, leaving ~8 GiB for the kernel,
# journald, dbus, ssh and page cache. When the slice fills, the *cgroup* OOM
# killer fires inside it and picks the member with the highest OOMScoreAdjust
# (promoter) — a contained, recoverable kill, never the global killer that has
# repeatedly taken hopper (and dbus) down.
#
# Per-service MemoryMax values intentionally sum above the slice ceiling
# (96+24+16); the slice is the real backstop and lets any one service burst into
# spare headroom when its siblings are idle (forager/promoter are periodic).

tmp_slice=$(mktemp -t "${SLICE_NAME}.slice.XXXXXX"); TMP_FILES+=("$tmp_slice")
cat >"$tmp_slice" <<EOF
[Unit]
Description=Atomdrift sample pipeline memory budget (hopper + forager + promoter)
Documentation=https://codeberg.org/atomdrift/hopper
Before=slices.target

[Slice]
# Whole-pipeline ceiling. Bounds the sum of every service nested below it, so a
# runaway in one cannot exhaust host RAM and provoke the global OOM killer.
MemoryHigh=112G
MemoryMax=120G
# Swap is zram here — compressed RAM. Uncapped, swap-out cannibalizes the very
# headroom MemoryMax reserves, so bound what the slice can push into it.
MemorySwapMax=8G
EOF

slice_changed=0
if priv cmp -s "$tmp_slice" "$SLICE_FILE" 2>/dev/null; then
    log "slice unit unchanged"
else
    log "Writing ${SLICE_FILE}"
    priv install -m 0644 -o root -g root "$tmp_slice" "$SLICE_FILE"
    slice_changed=1
fi

# Sibling drop-ins. Each adds slice membership + an OOM-victim bias; promoter
# (unbounded in its own unit, peaks ~95 GiB) additionally gets hard caps here.
# Only written when the sibling unit is installed, and a restart is needed for
# a Slice= change to take effect.
install_dropin() {
    local svc=$1 dropin=$2 content=$3
    systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 \
        || { log "${svc}.service not installed; skipping slice drop-in"; return; }
    local tmp; tmp=$(mktemp -t "${svc}.dropin.XXXXXX"); TMP_FILES+=("$tmp")
    printf '%s\n' "$content" >"$tmp"
    if priv cmp -s "$tmp" "$dropin" 2>/dev/null; then
        log "${svc} slice drop-in unchanged"
        return
    fi
    log "Writing ${dropin}"
    priv install -d -m 0755 -o root -g root "$(dirname "$dropin")"
    priv install -m 0644 -o root -g root "$tmp" "$dropin"
    DROPIN_CHANGED_SVCS+=("$svc")
}

declare -a DROPIN_CHANGED_SVCS=()

install_dropin forager "$FORAGER_DROPIN" "[Service]
# Join the pipeline budget; mild OOM bias (above hopper, below promoter). Keeps
# its own MemoryMax from the forager repo's unit.
Slice=${SLICE_NAME}.slice
OOMScoreAdjust=200"

install_dropin promoter "$PROMOTER_DROPIN" "[Service]
# promoter ships with no memory caps and has peaked at ~95 GiB (a batch-scanner
# runaway) — the direct cause of the host-wide OOM. Bound it: steady state is
# ~16 GiB, so a runaway now trips a contained restart (Restart=always) instead
# of taking down the box. Most expendable member: sacrificed first under slice
# pressure.
Slice=${SLICE_NAME}.slice
MemoryHigh=16G
MemoryMax=24G
MemorySwapMax=2G
OOMScoreAdjust=600"

# A new/edited slice or any moved-into-slice membership needs a daemon-reload,
# and a service only enters its new slice on restart.
if (( slice_changed )) || (( ${#DROPIN_CHANGED_SVCS[@]} > 0 )); then
    priv systemctl daemon-reload
fi
for svc in "${DROPIN_CHANGED_SVCS[@]}"; do
    log "Restarting ${svc} to apply slice membership"
    priv systemctl restart "${svc}.service" \
        || log "WARNING: ${svc}.service failed to restart; check: journalctl -u ${svc} -n 50"
done
# hopper's own Slice= lives in its unit; if only the slice file changed (not the
# hopper unit), hopper is still in the old slice until restarted.
if (( slice_changed )) && ! (( unit_changed )); then
    log "Restarting ${SERVICE_NAME} to apply slice membership"
    priv systemctl restart "${SERVICE_NAME}.service" \
        || die "service failed to start; see: journalctl -u ${SERVICE_NAME} -n 50"
fi

# --- Permission-heal timer ---------------------------------------------------
# /data/samples is shared (samples group) by forager, hopper, and the promoter.
# This root oneshot + timer re-asserts the contract — samples group, setgid
# 2775 dirs, read-only files (0444 shared, 0440 in the upload tree) — for drift
# from writers that bypass the services' own self-heal (a manual mv, the
# relayout, a root import, group-private upload shards). It runs
# as root so it can chgrp/chmod paths owned by any of those services; the
# long-running hopper service stays unprivileged and is never granted
# chmod/chgrp rights. The heal is a no-op when the tree is already clean.

[[ -f ${HEAL_PERMS_SRC} ]] || die "perms-heal script not found at ${HEAL_PERMS_SRC} (run from repo root)"
if priv cmp -s "${HEAL_PERMS_SRC}" "${HEAL_PERMS_BIN}" 2>/dev/null; then
    log "perms-heal script unchanged"
else
    log "Installing ${HEAL_PERMS_BIN}"
    priv install -m 0755 -o root -g root "${HEAL_PERMS_SRC}" "${HEAL_PERMS_BIN}"
fi

tmp_heal_svc=$(mktemp -t hopper-heal-perms.service.XXXXXX); TMP_FILES+=("$tmp_heal_svc")
tmp_heal_tmr=$(mktemp -t hopper-heal-perms.timer.XXXXXX); TMP_FILES+=("$tmp_heal_tmr")

cat >"$tmp_heal_svc" <<EOF
[Unit]
Description=Heal shared sample-tree permissions (group/setgid/read-only)
Documentation=https://codeberg.org/atomdrift/hopper

[Service]
Type=oneshot
ExecStart=${HEAL_PERMS_BIN}
Environment=DATA_DIR=${DATA_DIR}
# The upload tree is now part of the shared contract and IS healed (group +
# 2775 dirs; files to 0440). Only the in-flight .tmp staging dir is excluded —
# the script defaults HEAL_EXCLUDE to \${DATA_DIR}/unknown/uploads/.tmp, so no
# override is needed here.
Environment=HEAL_EXCLUDE=${UPLOAD_DIR}/.tmp
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Least privilege for a root oneshot: walk DATA_DIR and chgrp/chmod within it,
# nothing else. ProtectSystem=strict makes the rest of the filesystem
# read-only; ReadWritePaths re-opens just the sample tree. Default root caps
# are retained (CAP_CHOWN/CAP_FOWNER) so it can fix paths owned by forager etc.
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
NoNewPrivileges=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
StandardOutput=journal
StandardError=journal
EOF

cat >"$tmp_heal_tmr" <<EOF
[Unit]
Description=Run hopper-heal-perms every ${HEAL_PERMS_INTERVAL_MIN}min

[Timer]
OnBootSec=3min
OnUnitActiveSec=${HEAL_PERMS_INTERVAL_MIN}min
Persistent=true

[Install]
WantedBy=timers.target
EOF

heal_changed=0
if priv cmp -s "$tmp_heal_svc" "$HEAL_PERMS_SVC" 2>/dev/null; then
    log "perms-heal unit unchanged"
else
    log "Writing ${HEAL_PERMS_SVC}"
    priv install -m 0644 -o root -g root "$tmp_heal_svc" "$HEAL_PERMS_SVC"
    heal_changed=1
fi
if priv cmp -s "$tmp_heal_tmr" "$HEAL_PERMS_TIMER" 2>/dev/null; then
    log "perms-heal timer unchanged"
else
    log "Writing ${HEAL_PERMS_TIMER}"
    priv install -m 0644 -o root -g root "$tmp_heal_tmr" "$HEAL_PERMS_TIMER"
    heal_changed=1
fi
(( heal_changed )) && priv systemctl daemon-reload
# Clear any prior failed run so the timer reschedules cleanly.
priv systemctl reset-failed hopper-heal-perms.service 2>/dev/null || true
priv systemctl enable --now hopper-heal-perms.timer >/dev/null
# Kick one run now, but do NOT block the deploy on it: the first heal walks the
# entire sample tree and can take many minutes (Type=oneshot would otherwise
# make `make deploy` hang until it finishes). --no-block enqueues the start and
# returns; the result lands in the journal. Steady-state runs are cheap (only
# drift), so the timer cadence stays light.
priv systemctl start --no-block hopper-heal-perms.service || true
log "perms-heal run scheduled; watch: journalctl -u hopper-heal-perms.service -f"
log "perms-heal timer active (every ${HEAL_PERMS_INTERVAL_MIN}min): systemctl list-timers hopper-heal-perms.timer"

priv systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
log "Deployment complete"
