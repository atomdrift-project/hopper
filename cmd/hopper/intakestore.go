package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// intakestore.go answers the producer-facing routes (/v1/intake/held,
// /v1/intake/popular, provenance, the hot-pool drain feed, the ancestry
// check, the cleave write-back) from whichever schema holds the corpus: the
// verdict store when apiServer.results is set, the legacy tables otherwise.

// provenance returns the capture sidecar stored for sha: nil when the file
// has none, hopper.ErrNotFound when hopper has no such file.
func (s *apiServer) provenance(ctx context.Context, sha string) ([]byte, error) {
	if s.results == nil {
		return s.db.ProvenanceBySHA256(ctx, sha)
	}
	digest, err := hex.DecodeString(sha)
	if err != nil {
		return nil, hopper.ErrNotFound
	}
	prov, err := s.results.Provenance(ctx, digest)
	if errors.Is(err, store.ErrNotFound) {
		return nil, hopper.ErrNotFound
	}
	return prov, err
}

// setProvenance stores sidecar as the capture sidecar of an existing file,
// reporting false when hopper has no such file. sample carries the sidecar
// and the release it names (see uploadSample).
func (s *apiServer) setProvenance(ctx context.Context, sample *hopper.Sample) (bool, error) {
	if s.results == nil {
		return s.db.SetProvenance(ctx, sample)
	}
	digest, err := hex.DecodeString(sample.SHA256)
	if err != nil {
		return false, fmt.Errorf("set provenance: %w", err)
	}
	return s.results.SetProvenance(ctx, digest, sample.Provenance, sample.PURLBase, sample.Version)
}

// held returns the digests among shas whose bytes hopper can produce.
func (s *apiServer) held(ctx context.Context, shas []string) ([]string, error) {
	if s.results == nil {
		return s.db.KnownSHA256(ctx, shas)
	}
	digests := make([][]byte, 0, len(shas))
	for _, sha := range shas {
		if d, err := hex.DecodeString(sha); err == nil {
			digests = append(digests, d)
		}
	}
	found, err := s.results.Held(ctx, digests)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(found))
	for i, d := range found {
		out[i] = hex.EncodeToString(d)
	}
	return out, nil
}

// incoming returns a page of the hot pool's drain feed.
func (s *apiServer) incoming(ctx context.Context, q hopper.IncomingQuery) ([]*hopper.IncomingLocation, error) {
	if s.results == nil {
		return s.db.OldestIncomingLocations(ctx, q)
	}
	if q.Class != hopper.IncomingUnknown && q.Class != hopper.IncomingClassified {
		return nil, hopper.ErrNotFound
	}
	page, err := s.results.Incoming(ctx, store.IncomingQuery{
		Before: q.Before, AfterSeen: q.After.FirstSeenAt, AfterPath: q.After.Path,
		Unknown: q.Class == hopper.IncomingUnknown, Limit: q.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*hopper.IncomingLocation, len(page))
	for i, in := range page {
		out[i] = &hopper.IncomingLocation{
			FirstSeenAt: in.SeenAt, Mtime: in.Mtime, SHA256: hex.EncodeToString(in.SHA256), Path: in.Path, Label: in.Label,
		}
	}
	return out, nil
}

// setPopular records a popularity ranking.
func (s *apiServer) setPopular(ctx context.Context, pkgs []hopper.PopularPackage) error {
	if s.results == nil {
		return s.db.SetPopularPackages(ctx, pkgs)
	}
	ranks := make([]store.Popular, len(pkgs))
	for i, p := range pkgs {
		ranks[i] = store.Popular{Name: p.PURLBase, Ecosystem: p.Ecosystem, Source: p.Source, Rank: p.Rank}
	}
	return s.results.SetPopular(ctx, ranks)
}

// sightingsInAncestry checks a file and everything holding it for sightings.
func (s *apiServer) sightingsInAncestry(ctx context.Context, sha string) (*hopper.SightingsAncestry, error) {
	if s.results == nil {
		return s.db.SightingsInAncestry(ctx, sha)
	}
	return hopper.SightingsInAncestryFromStore(ctx, s.results, sha)
}

// rescanForCleave answers POST /api/cleave-result from the verdict store. A
// cleave re-run speaks for atomscan alone, and a write of it would drop the
// jurors' opinions of the file and its members (the store takes a scan's
// silence for a juror as the juror having no opinion), so the file is queued
// for a whole scan by the fleet instead, which reaches the same report with
// the jurors beside it. A file scanned since the rescan cooldown began, or
// with no path to read it from, is reported unchanged.
func (s *apiServer) rescanForCleave(ctx context.Context, w http.ResponseWriter, sha, remote string) {
	err := s.requestRescan(ctx, sha)
	status := "queued"
	switch {
	case errors.Is(err, hopper.ErrRescanNotEligible):
		status = "unchanged"
	case err != nil:
		slog.ErrorContext(ctx, "cleave result: queue rescan failed", "sha256", sha, "error", err, "remote", remote)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	default:
	}
	slog.InfoContext(ctx, "cleave result: whole scan "+status, "sha256", sha, "remote", remote)
	writeTriageJSON(w, map[string]string{"status": status})
}
