#!/usr/bin/env bash
# rehearsal-select.sh pulls a selection of the legacy tables from the replica
# (galadriel) into the `replica` schema of a local, disposable database, once.
# scripts/rehearsal.sh then builds rehearsals of any size up to it from there,
# without touching the replica again (MIGRATION_PLAN.md, part 3). Every query
# on the replica runs in a read-only transaction; nothing there is written.
#
#   scripts/rehearsal-select.sh 'postgres://proto@/rehearsal?host=/tmp/hopper-schema-prototype/v2&port=5499' 250000
#
# The selection:
#   - the first MAX analyzed top-level rows in sha256 order. sha256 is
#     uniform, so any prefix of that order is an unbiased sample, and a
#     smaller rehearsal's rows are a subset of a larger one's;
#   - the newest bad, cited and good analyzed files (TOP_UP of each), listed
#     in replica.rehearsal_topups, so the rare shapes are in every rehearsal;
#   - their top-level placements: one sequential pass over sample_locations
#     on the replica (about half an hour; it has no index for them);
#   - the sightings naming them by digest or package, their label events and
#     reports, and every popular package and acquisition row.
#
# The replica schema is made by `hopper init`; the script refuses a target
# naming hopper-db. Run again, it continues: the results, their placements
# and the top-ups are copied only into empty tables, and the small tables
# are copied afresh.
set -euo pipefail

target=${1:?usage: rehearsal-select.sh TARGET_DSN MAX}
max=${2:?usage: rehearsal-select.sh TARGET_DSN MAX}
replica=${REPLICA_SSH:-galadriel}
top_up=${TOP_UP:-300}
root=$(cd "$(dirname "$0")/.." && pwd)
hopper=${HOPPER:-$root/out/hopper}

case "$target" in *hopper-db*) echo "refusing a target naming hopper-db" >&2; exit 1 ;; esac
case "$target" in postgres://*\?*) ;; *) echo "TARGET_DSN must be a postgres:// URL with parameters" >&2; exit 1 ;; esac
[[ "$max" =~ ^[0-9]+$ ]] && [ "$max" -gt 0 ] || { echo "MAX must be a positive number" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# remote runs SQL from stdin on the replica, read-only, printing to stdout.
remote() {
	ssh -o BatchMode=yes "$replica" "PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=3h' psql -U postgres -d hopper -X -q -v ON_ERROR_STOP=1 -At"
}
local_sql() { PGOPTIONS="-c search_path=replica" psql "$target" -X -q -v ON_ERROR_STOP=1 -At "$@"; }

columns() { # columns TABLE: the columns both sides have, in the local order
	local t=$1 theirs ours
	theirs=$(echo "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '$t';" | remote | sort)
	ours=$(local_sql -c "SELECT column_name FROM information_schema.columns WHERE table_schema = 'replica' AND table_name = '$t' ORDER BY ordinal_position")
	local out=()
	for c in $ours; do
		if grep -qx "$c" <<<"$theirs"; then out+=("$c"); fi
	done
	(IFS=,; echo "${out[*]}")
}

# copy TABLE SELECT-TAIL: COPY the replica's rows through to the local table.
# fresh TABLE SELECT-TAIL empties the local table first.
fresh() { local_sql -c "TRUNCATE replica.$1"; copy "$@"; }
empty() { [ "$(local_sql -c "SELECT NOT EXISTS (SELECT 1 FROM replica.$1)")" = t ]; }
copy() {
	local t=$1 tail=$2 cols
	cols=$(columns "$t")
	[ -n "$cols" ] || { echo "  $t: not on both sides, skipped"; return; }
	printf 'COPY (SELECT %s FROM public.%s %s) TO STDOUT;\n' "$cols" "$t" "$tail" > "$work/q.sql"
	remote < "$work/q.sql" | local_sql -c "\\copy replica.$t ($cols) FROM STDIN"
	echo "  $t: $(local_sql -c "SELECT count(*) FROM replica.$t") rows"
}

[ -x "$hopper" ] || (cd "$root" && go build -o "$hopper" ./cmd/hopper)
psql "$target" -X -q -v ON_ERROR_STOP=1 -c 'CREATE SCHEMA IF NOT EXISTS replica'
"$hopper" init --db "$target&search_path=replica" >/dev/null

analyzed="parent = '' AND (cleave_result IS NOT NULL OR skip = 'timeout')"
topups="(SELECT id FROM public.samples WHERE label = 'bad' AND path <> '' AND skip <> 'conflict' AND label_source <> 'conflict'
	       ORDER BY created_at DESC, id DESC LIMIT $top_up)
	UNION (SELECT id FROM public.samples WHERE corroborated AND parent = '' AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL
	       ORDER BY created_at DESC LIMIT $top_up)
	UNION (SELECT id FROM public.samples WHERE label = 'good' AND cleave_result IS NOT NULL AND parent = '' AND path <> ''
	       AND corroborated AND max_crit < 5 AND suspicious_count < 2 ORDER BY created_at DESC, id DESC LIMIT $top_up)"

echo "copying from $replica: the first $max analyzed top-level rows by sha256, top-up $top_up"
if empty samples; then
	copy samples "WHERE id IN (
		SELECT id FROM (SELECT id FROM public.samples WHERE $analyzed ORDER BY sha256 LIMIT $max) a
		UNION $topups)"
else
	echo "  samples: kept, $(local_sql -c "SELECT count(*) FROM replica.samples") rows"
fi
local_sql -c "CREATE TABLE IF NOT EXISTS replica.rehearsal_topups (id bigint PRIMARY KEY)"
if empty rehearsal_topups; then
	printf 'COPY (%s) TO STDOUT;\n' "$topups" > "$work/q.sql"
	remote < "$work/q.sql" | local_sql -c "\\copy replica.rehearsal_topups (id) FROM STDIN"
fi

# What names the selected files: digests and packages, as SQL literals of
# text arrays, quoted by Postgres so that no name can break the query.
local_sql -c "SELECT quote_literal(array_agg(sha256)::text) FROM replica.samples" > "$work/shas"
local_sql -c "SELECT quote_literal(coalesce(array_agg(DISTINCT purl_base), '{}')::text) FROM replica.samples WHERE purl_base <> ''" > "$work/purls"
shas=$(cat "$work/shas")
purls=$(cat "$work/purls")
if empty sample_locations; then
	copy sample_locations "WHERE parent_sha256 = '' AND sha256 = ANY ($shas::text[])"
else
	echo "  sample_locations: kept, $(local_sql -c "SELECT count(*) FROM replica.sample_locations") rows"
fi
fresh sightings "WHERE subject = ANY ($shas::text[]) OR subject = ANY ($purls::text[])"
fresh label_events "WHERE sha256 = ANY ($shas::text[])"
fresh reports "WHERE sha256 = ANY ($shas::text[])"
fresh popular_packages ""
fresh sighting_acquisitions ""

echo "pulled: $(local_sql -c "SELECT count(*) FILTER (WHERE $analyzed) FROM replica.samples") analyzed top-level rows"
