#!/usr/bin/env bash
# deploy-replica-api.sh — install `hopper serve-replica` as a systemd service
# on the local host (a replica box: the database at 127.0.0.1 is a logical-
# replication subscriber).
#
# Why this exists: read traffic — beamline's /api/sample?purl= lookups above
# all — must not ride the publisher, where it queues behind ingestion I/O and
# (measured 2026-08-22) a millisecond-indexed lookup showed a ~7s p95, firing
# beamline's scan hedge and reflecting the load back as redundant scans and
# renewals. The replica's disk is idle; lookups served here are immune to the
# publisher's ingestion weather.
#
# The service is READ-ONLY against the LOCAL database by two independent
# guards (no mutating route ever touches it; database sessions forced
# default_transaction_read_only=on, verified at startup, fail-closed). A
# logical replica is an ordinary writable primary — one stray write diverges
# it from the publisher until replication wedges.
#
# Client-facing mutations (upload/known/sightings/popular/triage/rescan) are
# RELAYED verbatim to the primary at RELAY_TO (default hopper-api), so a
# client can point at this one URL for everything; lookups honor ?fresh=1 for
# read-after-write. Worker routes (/api/next, /api/heartbeat, /api/result)
# are refused regardless — never point workers at this listener; result
# envelopes must not double-hop through the replica. See cmd/hopper/relay.go.
#
# Idempotent: re-running installs the current build and restarts only when
# the binary or unit changed.
#
# Variables (env):
#   DB          replica DSN            (default: postgres://hopper@127.0.0.1:5432/hopper?sslmode=disable)
#   API_ADDR    listen address         (default: 0.0.0.0:8091 — LAN clients
#                 like beamline need it; a bearer token is then REQUIRED)
#   TOKEN_SRC   token file to install  (default: ~/.tok/hopper — the same
#                 token the primary uses, so clients need no second secret)
#   SERVICE_USER  unix user            (default: current user)
#   RELAY_TO    primary base URL for the write relay
#                 (default: http://hopper-api:8081; set empty to disable the
#                 relay and refuse client writes with 403 as before). The
#                 client's bearer token passes through to the primary, which
#                 works because TOKEN_SRC defaults to the primary's own token.
#   FORCE       set to 1 to deploy despite applied data exceeding MAX_LAG_S

set -euo pipefail

DB="${DB:-postgres://hopper@127.0.0.1:5432/hopper?sslmode=disable}"
API_ADDR="${API_ADDR:-0.0.0.0:8091}"
TOKEN_SRC="${TOKEN_SRC:-${HOME}/.tok/hopper}"
SERVICE_USER="${SERVICE_USER:-$(id -un)}"
RELAY_TO="${RELAY_TO-http://hopper-api:8081}"

UNIT=/etc/systemd/system/hopper-replica.service
BIN_PATH=/usr/local/bin/hopper
TOKEN_DST=/etc/hopper/replica-token

log() { printf '>> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

priv() {
    # Prefer whichever escalation works WITHOUT a prompt, so unattended runs
    # don't hang at a password prompt; fall back to interactive sudo last.
    if command -v doas >/dev/null 2>&1 && doas -n true 2>/dev/null; then
        doas "$@"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo "$@"
    else
        sudo "$@"
    fi
}

command -v systemctl >/dev/null || die "systemctl not found (this target is for systemd hosts)"
[ -x ./hopper ] || die "./hopper not built — run 'make build' first (make deploy-replica does)"
[ -s "${TOKEN_SRC}" ] || die "token file ${TOKEN_SRC} missing or empty; serving a non-loopback API without one is refused"

# ---------------------------------------------------------------------------
# Replication health gate. A lookup API on a stale replica serves wrong
# answers with a straight face — beamline reads a 404 as "scan it", so every
# hour of lag converts freshly-analyzed packages back into redundant scans.
# Catch-up is fine (the apply worker attached and chewing is the system
# working); what refuses the deploy is applied data more than an hour old,
# or no apply worker at all — that is not catch-up, that is broken, and
# `make replica-watch` is the tool for looking at why.
# ---------------------------------------------------------------------------
MAX_LAG_S="${MAX_LAG_S:-3600}"
FORCE="${FORCE:-0}"
log "replication health gate (max applied-data age: ${MAX_LAG_S}s)"
HEALTH=$(PGCONNECT_TIMEOUT=5 psql -h 127.0.0.1 -U hopper -d hopper -tA <<'SQL'
SELECT
  (SELECT count(*) FROM pg_subscription WHERE subenabled) AS enabled_subs,
  (SELECT count(*) FROM pg_stat_subscription WHERE pid IS NOT NULL) AS apply_workers,
  COALESCE((SELECT round(extract(epoch FROM now() -
      COALESCE(latest_end_time, last_msg_receipt_time)))::bigint
      FROM pg_stat_subscription WHERE pid IS NOT NULL
      ORDER BY 1 DESC LIMIT 1), -1) AS applied_age_s,
  (SELECT count(*) FROM pg_subscription_rel WHERE srsubstate <> 'r') AS tables_syncing
SQL
) || die "health gate: cannot query the local replica database"
IFS='|' read -r ENABLED_SUBS APPLY_WORKERS APPLIED_AGE TABLES_SYNCING <<<"${HEALTH}"

[ "${ENABLED_SUBS}" -ge 1 ] || die "health gate: no ENABLED subscription on this replica (the publisher-restart auto-disable again? re-enable it, then redeploy)"
[ "${APPLY_WORKERS}" -ge 1 ] || die "health gate: subscription enabled but NO apply worker attached — replication is down, not catching up. See 'make replica-watch'."
[ "${APPLIED_AGE}" -ge 0 ] || die "health gate: cannot determine applied-data age (no timestamps in pg_stat_subscription yet); retry in a minute"
if [ "${APPLIED_AGE}" -gt "${MAX_LAG_S}" ]; then
    if [ "${FORCE}" = "1" ]; then
        log "WARNING: FORCE=1: deploying despite applied data being ${APPLIED_AGE}s old (max ${MAX_LAG_S}s); lookups may trigger redundant beamline scans"
    else
        die "health gate: applied data is ${APPLIED_AGE}s old (max ${MAX_LAG_S}s) — a lookup API this stale converts fresh analyses into redundant beamline scans. Let it catch up ('make replica-watch'), override with MAX_LAG_S, or force startup with 'make deploy-replica FORCE=1'."
    fi
fi
if [ "${TABLES_SYNCING}" -gt 0 ]; then
    log "note: ${TABLES_SYNCING} table(s) still in initial sync (srsubstate != 'r') — deploy proceeds; lookups may miss rows from those tables until sync completes"
fi
log "health gate passed: applied data ${APPLIED_AGE}s old, ${APPLY_WORKERS} apply worker(s) attached"

# The service reads the replica DB as the hopper role; the password comes from
# the service user's ~/.pgpass exactly as the primary's deploy does.

log "installing binary -> ${BIN_PATH}"
if ! cmp -s ./hopper "${BIN_PATH}" 2>/dev/null; then
    priv install -m 0755 -o root -g root ./hopper "${BIN_PATH}"
    CHANGED=1
fi

log "installing token -> ${TOKEN_DST}"
priv install -d -m 0755 /etc/hopper
priv install -m 0640 -o root -g "${SERVICE_USER}" "${TOKEN_SRC}" "${TOKEN_DST}"

# The relay flag is appended only when RELAY_TO is set, so RELAY_TO="" yields
# the classic refuse-all-writes unit.
RELAY_ARGS=""
if [ -n "${RELAY_TO}" ]; then
    RELAY_ARGS=" \\
    --relay-writes-to ${RELAY_TO}"
fi

UNIT_TMP=$(mktemp)
cat >"${UNIT_TMP}" <<EOF
# Installed by scripts/replica/deploy-replica-api.sh — edits are overwritten.
[Unit]
Description=hopper read-only replica API (serve-replica)
Documentation=https://github.com/atomdrift-project/hopper
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=${BIN_PATH} serve-replica \\
    --db '${DB}' \\
    --api-addr ${API_ADDR} \\
    --token-file ${TOKEN_DST}${RELAY_ARGS}
Restart=always
RestartSec=2
# Read-only service, hardened accordingly: no filesystem writes at all beyond
# what the runtime itself needs, no privilege escalation, private tmp.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
MemoryMax=4G
TasksMax=256

[Install]
WantedBy=multi-user.target
EOF

if ! priv cmp -s "${UNIT_TMP}" "${UNIT}" 2>/dev/null; then
    log "installing unit -> ${UNIT}"
    priv install -m 0644 -o root -g root "${UNIT_TMP}" "${UNIT}"
    priv systemctl daemon-reload
    CHANGED=1
fi
rm -f "${UNIT_TMP}"

priv systemctl enable hopper-replica.service >/dev/null
if [ "${CHANGED:-0}" = "1" ]; then
    log "restarting hopper-replica"
    priv systemctl restart hopper-replica.service
else
    log "nothing changed; ensuring service is running"
    priv systemctl start hopper-replica.service
fi

sleep 1
priv systemctl --no-pager --lines=5 status hopper-replica.service || true
log "verify: curl -s http://${API_ADDR}/healthz"
