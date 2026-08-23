#!/bin/sh
# Canonical table set for a hopper logical replica — the SOLE source of truth.
# setup.sh builds the remote publication from it, promote.sh rebuilds a local
# one, and replica_index_policy.go embeds it so the guard test knows which
# tables are published. Nothing duplicates the list; add a table here only.
# Consumed by the scripts that source this file, not by this file itself.
#
# A published table needs a replica identity (a PRIMARY KEY suffices) and pays
# apply cost for every index slim-indexes.sh keeps on it, so publish a table
# only when a replica read path actually reads it.
# shellcheck disable=SC2034
REPLICATED_TABLES='samples reports sample_locations sightings claims label_events sample_location_history popular_packages'
