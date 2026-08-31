#!/bin/sh
# drain.sh - quiesce writers on the hopper master before a cutover shutdown.
#
# Committed data is never at risk here: a clean shutdown flushes it regardless.
# What this protects is IN-FLIGHT work -- it stops new connections, frees the
# idle ones, then WAITS for open transactions to finish on their own instead of
# having them rolled back underneath the application.
set -eu
ZONE=${SRC_ZONE:-postgres}
ZROOT=/rpool/zones/$ZONE/root
WAIT=${DRAIN_WAIT:-120}

for f in drain_block drain_idle drain_check; do
  pfexec cp /tmp/$f.sql $ZROOT/tmp/$f.sql
done

# NOTE: CONNECTION LIMIT 0 is written into pg_database, so on a MIGRATION it is
# captured by the final snapshot and arrives on the new master, where it blocks
# every non-superuser client with:
#   FATAL: too many connections for database "hopper"
# That bit us on 2026-08-31. undrain.sh resets it; run it on the NEW master
# after cutover, before repointing clients.
echo "==> blocking new connections"
pfexec zlogin $ZONE "psql -U postgres -d postgres -q -f /tmp/drain_block.sql"

echo "==> terminating idle backends"
pfexec zlogin $ZONE "psql -U postgres -d hopper -tA -f /tmp/drain_idle.sql" | sed 's/^/    freed: /'

echo "==> waiting up to ${WAIT}s for open transactions to finish"
i=0
while [ "$i" -lt "$WAIT" ]; do
  n=$(pfexec zlogin $ZONE "psql -U postgres -d hopper -tA -f /tmp/drain_check.sql" | tr -d ' \r')
  [ "$n" = "0" ] && { echo "    drained: 0 client backends remain"; exit 0; }
  echo "    $n client backend(s) still open (${i}s)"
  sleep 5
  i=$((i + 5))
done

echo "    WARNING: still $n open after ${WAIT}s; the shutdown will roll these back"
exit 0
