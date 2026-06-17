#!/bin/sh
# index-audit.sh — replica-aware unused-index audit for a hopper table.
#
# Over-indexing on a high-ingest table is pure write amplification: every
# INSERT/UPDATE maintains every index, and the dead ones evict useful pages
# from shared_buffers. This finds indexes that have NEVER been scanned and
# emits the DROP statements — but it NEVER drops anything itself.
#
# Why "replica-aware": hopper's replicas are LOGICAL subscribers, each with its
# own independent pg_stat_user_indexes counters. A read routed to a replica
# bumps that replica's idx_scan, not the primary's, so an index that looks dead
# on the primary may be the workhorse of a replica query. This script sums
# idx_scan across the primary AND every replica before calling an index unused.
# List every host that serves reads, or the audit will be wrong.
#
# Strictly read-only: it cancels nothing and writes nothing to any database.
# pg_stat_user_indexes is world-readable, so the app role (pgpass) is enough —
# no superuser needed. Run from anywhere that can reach the hosts.
#
# Overridable via env (defaults in brackets):
#   DB [hopper]   DB_USER [hopper]   TABLE [samples]
#   HOSTS [hopper-db]   space-separated: primary + EVERY replica serving reads
#   MIN_MB [64]   only flag indexes at least this large (skip noise)
#
# Example — primary plus two logical replicas:
#   HOSTS="hopper-db 10.9.8.21 10.9.8.22" sh scripts/index-audit.sh

set -u

DB="${DB:-hopper}"
DB_USER="${DB_USER:-hopper}"
TABLE="${TABLE:-samples}"
HOSTS="${HOSTS:-hopper-db}"
MIN_MB="${MIN_MB:-64}"

export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-10}"

q() { _h="$1"; shift; psql -h "$_h" -U "$DB_USER" -d "$DB" -tAF '|' -v ON_ERROR_STOP=1 "$@"; }

tmp=$(mktemp)
scans=$(mktemp)
trap 'rm -f "$tmp" "$scans"' EXIT INT TERM

# Metadata + primary scan count, taken once from the first host (the primary).
primary=$(echo "$HOSTS" | awk '{print $1}')
echo "== index audit: table=$TABLE  primary=$primary  min=${MIN_MB}MB ==" >&2
echo "   summing idx_scan across hosts: $HOSTS" >&2

if ! q "$primary" -c "SELECT 1" >/dev/null 2>&1; then
    echo "error: cannot reach primary '$primary' as $DB_USER (check pgpass/connectivity)" >&2
    exit 1
fi

# bytes|pretty|is_constraint|indexname  — constraint indexes (PK/UNIQUE) are
# flagged so we never propose dropping something that enforces integrity.
q "$primary" <<SQL > "$tmp"
SELECT pg_relation_size(s.indexrelid),
       pg_size_pretty(pg_relation_size(s.indexrelid)),
       EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = s.indexrelid),
       s.indexrelname
FROM pg_stat_user_indexes s
WHERE s.relname = '$TABLE'
ORDER BY pg_relation_size(s.indexrelid) DESC;
SQL

# Accumulate idx_scan per index name across every host into $scans.
: > "$scans"
for h in $HOSTS; do
    if ! q "$h" -c "SELECT 1" >/dev/null 2>&1; then
        echo "WARNING: cannot reach '$h' — its reads are NOT counted; results may over-report unused indexes" >&2
        continue
    fi
    q "$h" -c "SELECT indexrelname, idx_scan FROM pg_stat_user_indexes WHERE relname = '$TABLE';" >> "$scans"
done

# total_scans[name] = sum over hosts; print the audit.
awk -F '|' '
    FNR==NR { scan[$1] += $2 + 0; next }              # first file: per-host scans
    {
        bytes=$1; pretty=$2; isc=$3; name=$4
        total = (name in scan) ? scan[name] : 0
        sumbytes += bytes
        printf "%-44s %12s  scans=%-12d %s\n", name, pretty, total, (isc=="t"?"[constraint]":"")
        if (total==0 && isc!="t" && bytes >= MINMB*1024*1024) {
            drop[name]=1; deadbytes += bytes; n++
        }
    }
    END {
        printf "\n-- candidate-unused (0 scans everywhere, non-constraint, >=%dMB): %d index(es), %.1f GB --\n", \
               MINMB, n, deadbytes/1073741824
        for (name in drop)
            printf "DROP INDEX CONCURRENTLY IF EXISTS %s;  -- run on primary AND every replica\n", name
        if (n==0) print "(none — nothing to drop at this threshold)"
    }
' MINMB="$MIN_MB" "$scans" "$tmp"

cat >&2 <<'EOF'

NOTE: review before running any DROP.
  * Re-run after a full ingest+read cycle — a freshly reset counter or a
    just-created index also reads as 0 scans.
  * DROP INDEX CONCURRENTLY does not take an AccessExclusive lock, but it is
    NOT transactional and must be run per host (primary + each replica),
    because the logical replicas are independent physical databases.
  * Keep the DDL out of a transaction block (CONCURRENTLY forbids it).
EOF
