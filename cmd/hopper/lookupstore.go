package main

import (
	"context"

	"github.com/atomdrift-project/hopper"
)

// lookup answers /v1/lookup for an artifact named by a lowercase sha256, a
// version-less package URL and version, or both: from the verdict store when
// one is open (hopper.LookupStore), else from the legacy tables.
func (s *apiServer) lookup(ctx context.Context, sha, base, version string) (*hopper.LookupRecord, error) {
	if s.results == nil {
		return s.db.LookupRecord(ctx, sha, base, version)
	}
	return hopper.LookupStore(ctx, s.results, sha, base, version)
}

// addSightingsToStore records sightings in the verdict store's ledger, by
// the same rules the legacy ledger applies (hopper.AddSightingsToStore), or
// as a source's history (hopper.BackfillSightingsToStore).
func (s *apiServer) addSightingsToStore(ctx context.Context, sightings []hopper.Sighting, backfill bool) (int, error) {
	if backfill {
		return hopper.BackfillSightingsToStore(ctx, s.results, sightings, string(cliAppName()))
	}
	return hopper.AddSightingsToStore(ctx, s.results, sightings, string(cliAppName()))
}
