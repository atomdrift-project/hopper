#!/bin/sh
# Canonical table set for a hopper logical replica — the SOLE source of truth.
# setup.sh reconciles the remote publication to exactly this set, promote.sh
# builds a local one from it, and the other replica scripts read the schema
# from here. TestReplicatedTablesAreTheVerdictSchema fails when a table is
# added to store/schema.sql and not here. Consumed by the scripts that source
# this file, not by this file itself.
#
# The tables live in schema REPLICA_SCHEMA on both sides. Logical replication
# matches relations by schema-qualified name, so the replica's copy is in the
# schema the publisher's hopper writes (its --store), created by setup.sh from
# store/schema.sql.
#
# Every verdict table except walk_staging: it is UNLOGGED scratch space, and a
# publication cannot carry an unlogged table. The legacy tables in public have
# been frozen since the 2026-11-15 migration and are not published.
# shellcheck disable=SC2034
REPLICA_SCHEMA="${REPLICA_SCHEMA:-verdict}"
case "$REPLICA_SCHEMA" in
    ""|[!a-z_]*|*[!a-z0-9_]*)
        echo "error: REPLICA_SCHEMA must be a lower-case PostgreSQL identifier, got '$REPLICA_SCHEMA'" >&2
        exit 1
        ;;
esac
# shellcheck disable=SC2034
REPLICATED_TABLES='names samples scanners verdicts claims contents refs scans locations queue sightings sighting_acquisitions reports popular_packages gauntlet_runs gauntlet_samples gauntlet_results gauntlet_withdrawals label_events hopper_kv'
