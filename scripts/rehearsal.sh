#!/usr/bin/env bash
# rehearsal.sh builds a migration rehearsal of N legacy results from the
# selection scripts/rehearsal-select.sh pulled into the replica schema, and
# runs it: the migration (TestMigrationRehearsal, with every --verify check
# and two repeat conversions) and the lookup parity check
# (TestRehearsalLookupParity). It writes nothing outside the local database
# and out/rehearsal/N (MIGRATION_PLAN.md, part 3).
#
#   scripts/rehearsal.sh 1000        # then 5000, 10000, … up to what was pulled
#
# N counts analyzed top-level rows, the first N in sha256 order, so each
# rehearsal holds every row of a smaller one; the rare-shape top-ups ride
# along at every size. WORKERS sets the converters (default 8).
set -euo pipefail

n=${1:?usage: rehearsal.sh N}
[[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -gt 0 ] || { echo "N must be a positive number" >&2; exit 1; }
dsn=${REHEARSAL_DSN:-postgres://proto@/rehearsal?host=/tmp/hopper-schema-prototype/v2&port=5499}
workers=${WORKERS:-8}
root=$(cd "$(dirname "$0")/.." && pwd)
hopper=${HOPPER:-$root/out/hopper}
out="$root/out/rehearsal/$n"

case "$dsn" in *hopper-db*) echo "refusing a database naming hopper-db" >&2; exit 1 ;; esac
sql() { psql "$dsn" -X -q -v ON_ERROR_STOP=1 -At "$@"; }

pulled=$(sql -c "SELECT count(*) FROM replica.samples WHERE parent = '' AND (cleave_result IS NOT NULL OR skip = 'timeout')")
if [ "$pulled" -lt "$n" ]; then
	echo "only $pulled results were pulled; run scripts/rehearsal-select.sh with a larger MAX" >&2
	exit 1
fi
mkdir -p "$out"
(cd "$root" && go build -o "$hopper" ./cmd/hopper)

# A fresh legacy schema, filled from the pulled selection.
sql -c 'DROP SCHEMA IF EXISTS verdict CASCADE' -c 'DROP SCHEMA IF EXISTS public CASCADE' -c 'CREATE SCHEMA public'
"$hopper" init --db "$dsn&search_path=public" >/dev/null
cols() { # the columns of TABLE, in order, as both schemas were made by `hopper init`
	sql -c "SELECT string_agg(quote_ident(column_name), ',' ORDER BY ordinal_position)
		FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '$1'"
}
fill() { # fill TABLE WHERE: copy the replica schema's rows into public
	local c
	c=$(cols "$1")
	sql -c "INSERT INTO public.$1 ($c) SELECT $c FROM replica.$1 $2"
}
sql -c "CREATE TABLE replica.rehearsal_ids AS
	SELECT id FROM (SELECT id FROM replica.samples WHERE parent = '' AND (cleave_result IS NOT NULL OR skip = 'timeout')
	                ORDER BY sha256 LIMIT $n) a
	UNION SELECT id FROM replica.rehearsal_topups"
trap 'sql -c "DROP TABLE IF EXISTS replica.rehearsal_ids" >/dev/null 2>&1 || true' EXIT
fill samples "WHERE id IN (SELECT id FROM replica.rehearsal_ids)"
fill sample_locations "WHERE sha256 IN (SELECT sha256 FROM public.samples)"
fill sightings "WHERE subject IN (SELECT sha256 FROM public.samples)
	OR subject IN (SELECT purl_base FROM public.samples WHERE purl_base <> '')"
fill label_events "WHERE sha256 IN (SELECT sha256 FROM public.samples)"
fill reports "WHERE sha256 IN (SELECT sha256 FROM public.samples)"
fill popular_packages ""
fill sighting_acquisitions ""
echo "rehearsal of $n results: $(sql -c "SELECT count(*) FROM public.samples") legacy rows" | tee "$out/summary.txt"

cd "$root"
export HOPPER_REHEARSAL_DSN="$dsn" HOPPER_REHEARSAL_WORKERS="$workers"
status=0
go test -count=1 -timeout 12h -run 'TestMigrationRehearsal$' -v ./internal/migrate > "$out/migrate.log" 2>&1 || status=$?
go test -count=1 -timeout 1h -run 'TestRehearsalLookupParity$' -v . > "$out/parity.log" 2>&1 || status=$?
grep -hE '_test.go:[0-9]+: |^(--- |ok|FAIL)' \
	"$out/migrate.log" "$out/parity.log" | sed -E 's/Took:map\[[^]]*\] //' | tee -a "$out/summary.txt"
exit "$status"
