#!/bin/sh
# setup-replica.sh — configure local PostgreSQL as a logical replica of a
# remote hopper instance. Idempotent: re-running reconciles state.
#
# Assumes:
#   * Local postgres is running (pg_isready ok) but otherwise unconfigured.
#   * ~/.pgpass contains the upstream credentials, e.g.
#         hopper:*:hopper:hopper:<password>
#   * Admin access to the local cluster is reachable via either
#     `psql -U postgres` or `sudo -u postgres psql` (the script probes both).
#   * The hopper binary is built (./hopper) or installed on $PATH.
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# LOCAL_USER, PUBLICATION, SUBSCRIPTION, PGPASSFILE.

set -eu

REMOTE_HOST="${REMOTE_HOST:-hopper}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
LOCAL_USER="${LOCAL_USER:-hopper}"
PUBLICATION="${PUBLICATION:-hopper_training}"
SUBSCRIPTION="${SUBSCRIPTION:-hopper_training_sub}"
PGPASS="${PGPASSFILE:-$HOME/.pgpass}"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

# --- Sanity checks ---------------------------------------------------------
command -v pg_isready >/dev/null 2>&1 || die "pg_isready not found; install postgres client tools"
pg_isready -q || die "local postgres is not reachable — start it first"
[ -f "$PGPASS" ] || die "$PGPASS not found; add the upstream entry first"
# libpq ignores .pgpass unless perms are 0600.
chmod 600 "$PGPASS"

# --- Admin access probe ----------------------------------------------------
# Order: direct (trust/peer on stock FreeBSD and some Linux), then doas (BSD
# default), then sudo (Linux default). We pick whichever escalation tool is
# actually installed so this works on FreeBSD/DragonFly (doas or sudo),
# Debian/Ubuntu (sudo), CachyOS/Arch (sudo), etc.
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE=""
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="doas -n -u postgres"
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="doas -u postgres"
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="sudo -n -u postgres"
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    ESCALATE="sudo -u postgres"
else
    die "no admin access to local postgres (tried 'psql -U postgres', doas, sudo)"
fi

if [ -z "$ESCALATE" ]; then
    admin() { psql -U postgres "$@"; }
else
    # $ESCALATE is a fixed, script-controlled prefix (never user-supplied), so
    # leaving it unquoted to word-split is intentional and safe here.
    # shellcheck disable=SC2086
    admin() { $ESCALATE psql "$@"; }
fi

# --- Remote credentials from .pgpass --------------------------------------
REMOTE_PW=$(awk -F: -v h="$REMOTE_HOST" -v u="$REMOTE_USER" -v d="$REMOTE_DB" '
    /^[[:space:]]*#/ { next }
    ($1==h||$1=="*") && ($3==d||$3=="*") && ($4==u||$4=="*") { print $5; exit }
' "$PGPASS")
[ -n "$REMOTE_PW" ] || die "no matching $REMOTE_HOST:*:$REMOTE_DB:$REMOTE_USER entry in $PGPASS"

# --- Logical replication must be enabled on the local cluster -------------
wal_level=$(admin -tAc 'SHOW wal_level' | tr -d '[:space:]')
if [ "$wal_level" != "logical" ]; then
    log "Setting wal_level=logical (restart required)"
    admin -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET wal_level = 'logical'"
    die "restart postgres to apply wal_level=logical, then re-run this script"
fi

# --- Local role ------------------------------------------------------------
role_exists=$(admin -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$LOCAL_USER'" | tr -d '[:space:]')

# Existing .pgpass entry for localhost — if present we must reuse its password
# (we can't read the stored hash back out of postgres).
LOCAL_PW=$(awk -F: -v u="$LOCAL_USER" -v d="$LOCAL_DB" '
    /^[[:space:]]*#/ { next }
    $1=="localhost" && ($3==d||$3=="*") && ($4==u||$4=="*") { print $5; exit }
' "$PGPASS")

if [ "$role_exists" = "1" ]; then
    log "Role '$LOCAL_USER' already exists"
    [ -n "$LOCAL_PW" ] || die "role '$LOCAL_USER' exists but no localhost entry in $PGPASS; drop the role or add the entry and re-run"
else
    if [ -z "$LOCAL_PW" ]; then
        LOCAL_PW=$(openssl rand -hex 24 2>/dev/null) \
            || LOCAL_PW=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi
    log "Creating role '$LOCAL_USER'"
    # Substitutions (`:"name"`, `:'pw'`) are only performed by psql when SQL
    # arrives via stdin or -f; the -c path sends the string straight to the
    # server, so we feed this through a heredoc.
    admin -v ON_ERROR_STOP=1 -v role="$LOCAL_USER" -v pw="$LOCAL_PW" <<'SQL'
CREATE ROLE :"role" LOGIN PASSWORD :'pw';
SQL
fi

# Append .pgpass entry if one doesn't already cover localhost for this user/db.
if ! awk -F: -v u="$LOCAL_USER" -v d="$LOCAL_DB" '
    /^[[:space:]]*#/ { next }
    $1=="localhost" && ($3==d||$3=="*") && ($4==u||$4=="*") { found=1; exit }
    END { exit !found }
' "$PGPASS"; then
    log "Appending localhost entry to $PGPASS"
    printf 'localhost:*:%s:%s:%s\n' "$LOCAL_DB" "$LOCAL_USER" "$LOCAL_PW" >> "$PGPASS"
    chmod 600 "$PGPASS"
fi

# --- Local database --------------------------------------------------------
db_exists=$(admin -tAc "SELECT 1 FROM pg_database WHERE datname = '$LOCAL_DB'" | tr -d '[:space:]')
if [ "$db_exists" = "1" ]; then
    log "Database '$LOCAL_DB' already exists"
else
    log "Creating database '$LOCAL_DB' owned by '$LOCAL_USER'"
    admin -v ON_ERROR_STOP=1 -v db="$LOCAL_DB" -v owner="$LOCAL_USER" <<'SQL'
CREATE DATABASE :"db" OWNER :"owner";
SQL
fi

# --- Schema via hopper init (idempotent; uses migration tracking) ---------
if [ -x ./hopper ]; then
    HOPPER=./hopper
elif command -v hopper >/dev/null 2>&1; then
    HOPPER=hopper
else
    die "hopper binary not found — run 'make build' first"
fi
log "Running '$HOPPER init' to ensure schema"
"$HOPPER" init -db "postgres://$LOCAL_USER@localhost/$LOCAL_DB?sslmode=disable"

# --- Subscription ----------------------------------------------------------
# We keep the password out of argv by passing it through psql's -v mechanism
# (:'name' expands to a properly-quoted SQL literal inside the client).
CONN="host=$REMOTE_HOST dbname=$REMOTE_DB user=$REMOTE_USER password=$REMOTE_PW"

sub_exists=$(admin -d "$LOCAL_DB" -tAc \
    "SELECT 1 FROM pg_subscription WHERE subname = '$SUBSCRIPTION'" | tr -d '[:space:]')

if [ "$sub_exists" = "1" ]; then
    log "Subscription '$SUBSCRIPTION' exists — refreshing connection + tables"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
        -v sub="$SUBSCRIPTION" \
        -v conn="$CONN" <<'SQL'
ALTER SUBSCRIPTION :"sub" CONNECTION :'conn';
ALTER SUBSCRIPTION :"sub" ENABLE;
ALTER SUBSCRIPTION :"sub" REFRESH PUBLICATION;
SQL
else
    # A prior run (or the retired sync-db target) may have left a replication
    # slot on the remote without a matching local subscription. CREATE
    # SUBSCRIPTION would fail to recreate it, so drop the orphan first.
    # libpq reads the password from ~/.pgpass for this connection.
    stale=$(psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" -tAc \
        "SELECT 1 FROM pg_replication_slots WHERE slot_name = '$SUBSCRIPTION'" \
        2>/dev/null | tr -d '[:space:]')
    if [ "$stale" = "1" ]; then
        log "Dropping orphan replication slot '$SUBSCRIPTION' on $REMOTE_HOST"
        psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" \
            -v ON_ERROR_STOP=1 -v slot="$SUBSCRIPTION" <<'SQL'
SELECT pg_drop_replication_slot(:'slot');
SQL
    fi

    log "Creating subscription '$SUBSCRIPTION' → $REMOTE_HOST / $PUBLICATION"
    admin -d "$LOCAL_DB" -v ON_ERROR_STOP=1 \
        -v sub="$SUBSCRIPTION" \
        -v pub="$PUBLICATION" \
        -v conn="$CONN" <<'SQL'
CREATE SUBSCRIPTION :"sub"
    CONNECTION :'conn'
    PUBLICATION :"pub"
    WITH (copy_data = true);
SQL
fi

# --- Sanity: confirm data is actually flowing ------------------------------
# The apply worker is asynchronous, so give it a beat before reading status.
sleep 2

log "Replication status:"

# Main apply worker status. pg_stat_subscription has one row per worker —
# the apply worker (relid IS NULL) plus one tablesync worker per table during
# initial copy — so we filter to just the apply worker here. pid NULL means
# it hasn't registered yet.
admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA <<'SQL' | sed 's/^/    /'
SELECT 'apply worker: ' ||
    CASE WHEN pid IS NULL THEN 'not connected yet (check logs if this persists)'
         ELSE format('pid=%s received_lsn=%s latest_end_lsn=%s',
                     pid,
                     COALESCE(received_lsn::text,   '0/0'),
                     COALESCE(latest_end_lsn::text, '0/0'))
    END
  FROM pg_stat_subscription
  WHERE subname = :'sub' AND relid IS NULL;
SQL

# Per-table: sync state + exact row count. quote_ident() makes the identifier
# shell/SQL-safe for the follow-up count query.
tables=$(admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA <<'SQL'
SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname) || '|' ||
       CASE r.srsubstate
           WHEN 'i' THEN 'initializing'
           WHEN 'd' THEN 'copying data'
           WHEN 'f' THEN 'finished table copy'
           WHEN 's' THEN 'synchronized'
           WHEN 'r' THEN 'ready (streaming)'
           ELSE 'state=' || r.srsubstate::text
       END
  FROM pg_subscription_rel r
  JOIN pg_subscription s ON s.oid = r.srsubid
  JOIN pg_class c ON c.oid = r.srrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE s.subname = :'sub'
  ORDER BY c.relname;
SQL
)

printf '%s\n' "$tables" | while IFS='|' read -r qualified state; do
    [ -n "$qualified" ] || continue
    rows=$(admin -d "$LOCAL_DB" -tAc "SELECT count(*) FROM $qualified" 2>/dev/null | tr -d '[:space:]')
    printf '    table %s: %s (%s rows)\n' "$qualified" "$state" "${rows:-?}"
done

log "Done. Re-run anytime — this script is idempotent."
log "Live monitor: watch -n2 \"psql -h localhost -U $LOCAL_USER -d $LOCAL_DB -c 'SELECT * FROM pg_stat_subscription'\""
