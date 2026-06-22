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
#   WORKERS   --workers              (default: 48; set 0 for hopper's auto-pick)
#   PULL_DISABLE  set to 1 to skip the git pull of ../scan and ../cleave and
#                 build the current checkouts as-is (e.g. when the remote is down)

set -euo pipefail

DATA_DIR="${DATA_DIR:-/data/samples}"
UPLOAD_DIR="${DATA_DIR}/unknown/uploads"
DB="${DB:-postgres://hopper@hopper-db/hopper?sslmode=disable}"
SOURCE="${SOURCE:-forager}"
DASH_ADDR="${DASH_ADDR:-0.0.0.0:8081}"
WORKERS="${WORKERS:-48}"
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

# Permission-heal timer: a root oneshot that re-asserts the shared-tree contract
# (samples group + setgid dirs + read-only files) on DATA_DIR, catching drift
# from writers that bypass forager's/hopper's own self-heal. The interval is
# env-overridable; the heal is a no-op when the tree is already clean.
readonly HEAL_PERMS_SRC=scripts/master/heal-perms.sh
readonly HEAL_PERMS_BIN=/usr/local/bin/hopper-heal-perms.sh
readonly HEAL_PERMS_SVC=/etc/systemd/system/hopper-heal-perms.service
readonly HEAL_PERMS_TIMER=/etc/systemd/system/hopper-heal-perms.timer
HEAL_PERMS_INTERVAL_MIN="${HEAL_PERMS_INTERVAL_MIN:-15}"
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

priv install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
    "${STATE_HOME}" "${CACHE_HOME}" "${CONFIG_DIR}" "${TOOLS_DIR}"
priv install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${UPLOAD_DIR}"
priv install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${UPLOAD_DIR}/.tmp"

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

# --- Unit --------------------------------------------------------------------

tmp_unit=$(mktemp -t "${SERVICE_NAME}.service.XXXXXX")
TMP_FILES+=("$tmp_unit")

# --workers is only emitted when non-zero; hopper's own default (0 = auto)
# picks a sane per-host value.
workers_arg=""
(( WORKERS > 0 )) && workers_arg=" --workers ${WORKERS}"

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

ConfigurationDirectory=${SERVICE_NAME}
ConfigurationDirectoryMode=0750
StateDirectory=${SERVICE_NAME}
StateDirectoryMode=0750
CacheDirectory=${SERVICE_NAME}
CacheDirectoryMode=0750

WorkingDirectory=%S/${SERVICE_NAME}
ExecStart=${BIN_PATH} load --data ${DATA_DIR} --db ${DB} --source ${SOURCE} --dashboard-addr ${DASH_ADDR} --litmus ${SCAN_BIN} --cleave ${CLEAVE_BIN} --prune-missing-paths${workers_arg}
Restart=on-failure
RestartSec=10s
TimeoutStopSec=60s

Environment=HOME=%S/${SERVICE_NAME}
Environment=XDG_CACHE_HOME=%C/${SERVICE_NAME}
Environment=PGPASSFILE=%E/${SERVICE_NAME}/.pgpass
Environment=PATH=${TOOLS_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

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

# OpenTelemetry. The base endpoint; the SDK appends /v1/<signal> per the
# OTel spec, so metrics land at /api/v1/otlp/v1/metrics on the Prometheus
# OTLP receiver. Override OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT to send
# a single signal somewhere else (e.g. traces → Tempo).
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://otel:9090/api/v1/otlp
# Logs are handled by Loki; send them to its OTLP endpoint (used verbatim).
Environment=OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://otel:3100/otlp/v1/logs

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

# Filesystem isolation. DATA_DIR is read-only except interactive uploads.
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=${DATA_DIR}
ReadWritePaths=${UPLOAD_DIR}
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
RestrictSUIDSGID=true
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

# --- Permission-heal timer ---------------------------------------------------
# /data/samples is shared (samples group) by forager, hopper, and the promoter.
# This root oneshot + timer re-asserts the contract — samples group, setgid
# 2775 dirs, read-only 0444 files — for drift from writers that bypass the
# services' own self-heal (a manual mv, the relayout, a root import). It runs
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
# Kick one run now (Type=oneshot, so this blocks until it finishes) so each
# deploy heals immediately and surfaces any script error in the journal rather
# than waiting for the first timer tick. A heal failure warns but never fails
# the deploy.
if priv systemctl start hopper-heal-perms.service; then
    log "perms-heal ran: journalctl -u hopper-heal-perms.service -n 20"
else
    log "WARN perms-heal initial run failed; see: journalctl -u hopper-heal-perms.service -n 20"
fi
log "perms-heal timer active (every ${HEAL_PERMS_INTERVAL_MIN}min): systemctl list-timers hopper-heal-perms.timer"

priv systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
log "Deployment complete"
