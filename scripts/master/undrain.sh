#!/bin/sh
# undrain.sh - reverse drain.sh's connection block.
#
# MUST be run on the NEW master after a migration cutover: drain.sh sets
# `ALTER DATABASE ... CONNECTION LIMIT 0`, which lives in pg_database and is
# therefore carried across by the physical copy. Left set, every non-superuser
# client is refused with `FATAL: too many connections for database`.
# Also usable on the source to abort a cutover before it stops PostgreSQL.
set -eu
DB=${SRC_DB:-hopper}
psql -U postgres -d postgres -c "ALTER DATABASE $DB CONNECTION LIMIT -1"
psql -U postgres -d postgres -tAc \
  "SELECT datname || ' connlimit=' || datconnlimit FROM pg_database WHERE datname = '$DB'"
