#!/usr/bin/env bash
# test-pg.sh starts, or finds running, the throwaway Postgres cluster `make
# test` runs hopper's database tests against, and prints its DSN. The cluster
# lives in out/test-pg and listens only on a Unix socket there; it is left
# running between runs. `scripts/test-pg.sh stop` stops it.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/out/test-pg"
port=${HOPPER_TEST_PG_PORT:-55432}
dsn="postgres://hopper@/hoppertest?host=$dir&port=$port"

if [ "${1:-}" = stop ]; then
	if [ -f "$dir/data/postmaster.pid" ]; then pg_ctl -D "$dir/data" -m fast stop >/dev/null; fi
	exit 0
fi

for bin in initdb pg_ctl createdb psql; do
	command -v "$bin" >/dev/null || { echo "test-pg: $bin not found; install Postgres 18" >&2; exit 1; }
done
version=$(pg_ctl --version | sed -E 's/[^0-9]*([0-9]+).*/\1/')
[ "$version" -ge 18 ] || { echo "test-pg: Postgres $version found; hopper needs 18 or later" >&2; exit 1; }

if [ ! -f "$dir/data/PG_VERSION" ]; then
	mkdir -p "$dir"
	initdb -D "$dir/data" -U hopper --auth=trust --encoding=UTF8 --no-locale >"$dir/initdb.log"
fi
if ! pg_ctl -D "$dir/data" status >/dev/null 2>&1; then
	pg_ctl -D "$dir/data" -l "$dir/postgres.log" -w \
		-o "-k $dir -p $port -c listen_addresses='' -c fsync=off -c synchronous_commit=off -c full_page_writes=off" \
		start >/dev/null
fi
if ! psql -h "$dir" -p "$port" -U hopper -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname = 'hoppertest'" | grep -q 1; then
	createdb -h "$dir" -p "$port" -U hopper hoppertest
fi
echo "$dsn"
