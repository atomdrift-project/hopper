#!/usr/bin/env bash
# deploy.sh - Install hopper as a hardened systemd service on the local host.
#
# hopper runs `hopper load` which forks litmus + rizin children to analyse
# samples under DATA_DIR and push results into postgres. Memory/Tasks caps
# are sized for that workload (litmus-heavy, up to ~32 GiB RSS).
#
# Idempotent: re-running is safe. The service is only daemon-reloaded and
# restarted when the binary or unit file actually changed on disk.
#
# Variables (env):
#   DATA_DIR  sample directory (read-only to hopper)
#                                    (default: /data/samples)
#   DB        postgres DSN (password resolved from the installed .pgpass)
#                                    (default: postgres://hopper@hopper/hopper?sslmode=disable)
#   SOURCE    --source tag           (default: harvest)
#   DASH_ADDR --dashboard-addr       (default: 0.0.0.0:8081)
#   WORKERS   --workers              (default: 0 = auto)

set -euo pipefail

DATA_DIR="${DATA_DIR:-/data/samples}"
DB="${DB:-postgres://hopper@hopper/hopper?sslmode=disable}"
SOURCE="${SOURCE:-harvest}"
DASH_ADDR="${DASH_ADDR:-0.0.0.0:8081}"
WORKERS="${WORKERS:-0}"

readonly SERVICE_USER=hopper
readonly SERVICE_NAME=hopper
readonly BINARY=hopper
readonly BIN_PATH=/usr/local/bin/${BINARY}
readonly CONFIG_DIR=/etc/${SERVICE_NAME}
readonly STATE_HOME=/var/lib/${SERVICE_NAME}
readonly TOOLS_DIR=${STATE_HOME}/bin
readonly CACHE_HOME=/var/cache/${SERVICE_NAME}
readonly UNIT_FILE=/etc/systemd/system/${SERVICE_NAME}.service

# Sibling repos that ship alongside hopper. `make deploy` updates both,
# builds them in release mode, and installs the resulting binaries into
# TOOLS_DIR.
readonly LITMUS_SRC=../litmus
readonly CLEAVE_SRC=../cleave
readonly LITMUS_BIN=${TOOLS_DIR}/litmus
readonly CLEAVE_BIN=${TOOLS_DIR}/cleave

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

declare -a TMP_FILES=()
trap 'if (( ${#TMP_FILES[@]} > 0 )); then rm -f -- "${TMP_FILES[@]}"; fi' EXIT

# --- Preconditions -----------------------------------------------------------

[[ $(uname -s) == Linux ]]      || die "deploy requires Linux with systemd"
command -v systemctl >/dev/null || die "systemctl not found"
command -v sudo      >/dev/null || die "sudo required"
command -v git       >/dev/null || die "git not found"
[[ -f Makefile ]]                || die "run from the repository root"
[[ -d ${DATA_DIR} ]]             || die "DATA_DIR does not exist: ${DATA_DIR}"
sudo -v                          || die "sudo authentication failed"

# litmus and cleave are checked out alongside hopper and built in release
# mode during deploy. Their Makefiles drop the binary into ./out/<name>;
# we install those artifacts into TOOLS_DIR so the service has a single,
# hopper-owned location to exec from.
[[ -d ${LITMUS_SRC}/.git ]] || die "litmus source not found at ${LITMUS_SRC}; check out codeberg.org/atomdrift/litmus there"
[[ -d ${CLEAVE_SRC}/.git ]] || die "cleave source not found at ${CLEAVE_SRC}; check out codeberg.org/atomdrift/cleave there"
command -v cargo >/dev/null || die "cargo not found on PATH; install the Rust toolchain to build litmus and cleave"

# --- Build -------------------------------------------------------------------

log "Building ${BINARY}"
make build
[[ -x ./${BINARY} ]] || die "build did not produce ./${BINARY}"

update_tool_source() {
    local name=$1 dir=$2

    log "Updating ${name} source"
    git -C "${dir}" pull --ff-only
}

update_tool_source litmus "${LITMUS_SRC}"
update_tool_source cleave "${CLEAVE_SRC}"

log "Building litmus (release)"
make -C "${LITMUS_SRC}" release >/dev/null
[[ -x ${LITMUS_SRC}/out/litmus ]] || die "litmus build did not produce ${LITMUS_SRC}/out/litmus"

log "Building cleave (release)"
make -C "${CLEAVE_SRC}" release >/dev/null
[[ -x ${CLEAVE_SRC}/out/cleave ]] || die "cleave build did not produce ${CLEAVE_SRC}/out/cleave"

# --- Service user + directories ---------------------------------------------

if ! getent passwd "${SERVICE_USER}" >/dev/null; then
    log "Creating service user '${SERVICE_USER}'"
    sudo useradd --system --home-dir "${STATE_HOME}" --no-create-home \
                 --shell /usr/sbin/nologin \
                 --comment "Hopper service" "${SERVICE_USER}"
fi

sudo install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
    "${STATE_HOME}" "${CACHE_HOME}" "${CONFIG_DIR}" "${TOOLS_DIR}"

# --- Binary ------------------------------------------------------------------

binary_changed=0
if sudo cmp -s "./${BINARY}" "${BIN_PATH}" 2>/dev/null; then
    log "Binary unchanged"
else
    log "Installing ${BIN_PATH}"
    sudo install -m 0755 -o root -g root "./${BINARY}" "${BIN_PATH}"
    binary_changed=1
fi

# Install litmus and cleave into the service user's TOOLS_DIR. A change in
# either counts as a "binary change" so the service is restarted below.
install_tool() {
    local src=$1 dst=$2 name=$3
    if sudo cmp -s "${src}" "${dst}" 2>/dev/null; then
        log "${name} unchanged"
        return
    fi
    log "Installing ${dst}"
    sudo install -m 0755 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${src}" "${dst}"
    binary_changed=1
}
install_tool "${LITMUS_SRC}/out/litmus" "${LITMUS_BIN}" litmus
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
    if sudo cmp -s "$pgpass_src" "$pgpass_dst" 2>/dev/null; then
        log ".pgpass unchanged"
    else
        log "Installing .pgpass from ${pgpass_src}"
        sudo install -m 0600 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
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
Description=Hopper sample ingester (spawns litmus workers)
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
ExecStart=${BIN_PATH} load --data ${DATA_DIR} --db ${DB} --source ${SOURCE} --dashboard-addr ${DASH_ADDR} --litmus ${LITMUS_BIN} --cleave ${CLEAVE_BIN}${workers_arg}
Restart=on-failure
RestartSec=10s
TimeoutStopSec=60s

Environment=HOME=%S/${SERVICE_NAME}
Environment=XDG_CACHE_HOME=%C/${SERVICE_NAME}
Environment=PGPASSFILE=%E/${SERVICE_NAME}/.pgpass
Environment=PATH=${TOOLS_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Resource caps — hopper + litmus children combined.
MemoryHigh=64G
MemoryMax=72G
TasksMax=8192
# Child OOM (e.g. a rogue litmus worker) should be logged and retried, not
# bring down the whole ingester.
OOMPolicy=continue

# Filesystem isolation. DATA_DIR is read-only; hopper never mutates samples.
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=${DATA_DIR}
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
if sudo cmp -s "$tmp_unit" "$UNIT_FILE" 2>/dev/null; then
    log "Unit unchanged"
else
    log "Writing ${UNIT_FILE}"
    sudo install -m 0644 -o root -g root "$tmp_unit" "$UNIT_FILE"
    unit_changed=1
fi

# --- Activate ----------------------------------------------------------------

(( unit_changed )) && sudo systemctl daemon-reload

sudo systemctl enable --now "${SERVICE_NAME}.service" >/dev/null

if (( binary_changed || unit_changed )); then
    log "Restarting ${SERVICE_NAME}"
    if ! sudo systemctl restart "${SERVICE_NAME}.service"; then
        sudo systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
        die "service failed to start; see: journalctl -u ${SERVICE_NAME} -n 50"
    fi
else
    log "No changes; leaving service running"
fi

sudo systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
log "Deployment complete"
