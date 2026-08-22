#!/bin/sh
# Canonical table set for a hopper logical replica.
# Keep this aligned with scripts/master/freebsd-bastille.sh.
# Consumed by the scripts that source this file, not by this file itself.
# shellcheck disable=SC2034
REPLICATED_TABLES='samples reports sample_locations sightings claims label_events sample_location_history'
