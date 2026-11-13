package main

// triagestore.go answers the triage endpoints from the verdict schema
// (store) when apiServer.results is set. The wire format stays the
// legacy hopper.Sample, which cyclotron decodes by field name; only the
// fields cyclotron reads are filled (PLAN.md, "Triage queues on the new
// tables").

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// triageKnown reports whether the verdict schema serves the queue.
func triageKnown(name string) bool {
	return slices.Contains(store.TriageQueueNames(), name)
}

// triageSelectStore returns up to limit files of the queue, as samples.
// excluded holds validated hex digests.
func (s *apiServer) triageSelectStore(ctx context.Context, name string, limit int, excluded []string) ([]*hopper.Sample, error) {
	digests := make([][]byte, 0, len(excluded))
	for _, sha := range excluded {
		if b, err := hex.DecodeString(sha); err == nil {
			digests = append(digests, b)
		}
	}
	candidates, err := s.results.Triage(ctx, name, limit, digests)
	if err != nil {
		return nil, err
	}
	out := make([]*hopper.Sample, 0, len(candidates))
	for i := range candidates {
		out = append(out, candidateSample(&candidates[i]))
	}
	return out, nil
}

// candidateSample is a candidate in the shape the triage API has always
// served.
func candidateSample(c *store.Candidate) *hopper.Sample {
	sample := &hopper.Sample{
		SHA256: hex.EncodeToString(c.SHA256), Path: c.Path, Feed: c.Feed, Label: c.Label, LabelSource: c.LabelSource,
		PURLBase: c.Name, Version: c.Version, FileType: c.FileType, SizeBytes: c.SizeBytes, CreatedAt: c.CreatedAt,
	}
	if !c.ScannedAt.IsZero() {
		at := c.ScannedAt
		sample.AnalyzedAt = &at
	}
	if len(c.Top) > 0 {
		if b, err := json.Marshal(c.Top); err == nil {
			sample.TopTraits = string(b)
		}
	}
	if g := c.Gauntlet; g != nil {
		var run hopper.GauntletRun
		_ = json.Unmarshal(g.Metadata, &run) //nolint:errcheck // a run without readable rules still names its evidence
		sample.Gauntlet = &hopper.GauntletEvidence{
			Key: g.Key, RunID: g.RunID, ObservedAt: g.ObservedAt, Expected: g.Expected, Status: g.Status,
			Rules: run.Rules["ascan"], Result: g.Payload,
		}
	}
	return sample
}

// triageDepthStore is a queue's depth from the verdict schema. The gauntlet
// queue also reports its depth by kind of failure, as it always has.
func (s *apiServer) triageDepthStore(ctx context.Context, name string) (map[string]any, error) {
	if name != "gauntlet" {
		depth, capped, err := s.results.TriageDepth(ctx, name)
		return map[string]any{"queue": name, "depth": depth, "capped": capped}, err
	}
	picks, err := s.results.Triage(ctx, name, store.TriageDepthCap, nil)
	if err != nil {
		return nil, err
	}
	counts := map[string]int64{"false_positive": 0, "miss": 0}
	for i := range picks {
		if strings.EqualFold(picks[i].Gauntlet.Expected, "good") {
			counts["false_positive"]++
		} else {
			counts["miss"]++
		}
	}
	return map[string]any{
		"queue": name, "depth": int64(len(picks)), "capped": len(picks) >= store.TriageDepthCap, "by_failure": counts,
	}, nil
}

// fileReport records a triage report in the verdict schema and answers the
// request, with the statuses the legacy path gives.
func (s *apiServer) fileReport(ctx context.Context, w http.ResponseWriter, r *http.Request, sha, reportType string, req *reportRequest) {
	digest, _ := hex.DecodeString(sha) //nolint:errcheck // validated by the caller
	err := retryDBAccessNoValue(ctx, "insert report", sha, func(ctx context.Context) error {
		return s.results.FileReport(ctx, store.TriageReport{
			SHA256: digest, Type: reportType, Provider: strings.TrimSpace(req.Provider), Content: req.Content, EvidenceKey: req.EvidenceKey,
		})
	})
	switch {
	case errors.Is(err, store.ErrGauntletEvidence):
		v1Error(w, http.StatusNotFound, "unknown_gauntlet_evidence", "Unknown gauntlet evidence.")
	case errors.Is(err, store.ErrNotFound):
		slog.WarnContext(ctx, "report rejected: no such sample", "sha256", sha, "type", reportType, "remote", r.RemoteAddr)
		v1Error(w, http.StatusNotFound, "unknown_sample", "Unknown sample.")
	case err != nil:
		slog.ErrorContext(ctx, "report: insert failed", "sha256", sha, "type", reportType, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
	default:
		slog.InfoContext(ctx, "report recorded", "sha256", sha, "type", reportType, "remote", r.RemoteAddr)
		writeTriageJSON(w, map[string]string{"status": "recorded"})
	}
}

// storeCatalog is the verdict schema's store as the catalog a move records
// itself in (hopper.MoveCatalog).
type storeCatalog struct{ st *store.Store }

// catalog is where moves are recorded: the verdict schema when a results
// store is set, else the legacy tables.
func (s *apiServer) catalog() hopper.MoveCatalog {
	if s.results != nil {
		return storeCatalog{s.results}
	}
	return s.db
}

func digestOf(sha string) []byte {
	b, _ := hex.DecodeString(sha) //nolint:errcheck // callers pass validated hex
	return b
}

func (c storeCatalog) TopLevelLocationsRecorded(ctx context.Context, sha256, first, second string) (firstOK, secondOK bool, err error) {
	return c.st.LocationsRecorded(ctx, digestOf(sha256), first, second)
}

// PrepareLocationMove records the destination and any relabel. A conviction
// then queues the package's other files for a rescan, best effort: the label
// is the decision and does not fail because a follow-up did.
func (c storeCatalog) PrepareLocationMove(
	ctx context.Context, sha256, oldRel, newRel string, relabel *hopper.LocationRelabel, expectedLabel string,
) (bool, error) {
	var r *store.Relabel
	if relabel != nil {
		r = &store.Relabel{Label: hopper.CanonicalLabel(relabel.Label), Source: relabel.Source}
	}
	ok, err := c.st.PrepareMove(ctx, digestOf(sha256), oldRel, newRel, r, expectedLabel)
	if errors.Is(err, store.ErrLabelChanged) {
		return false, hopper.ErrLocationLabelChanged
	}
	if err == nil && ok && r != nil && r.Label == "bad" {
		n, err := c.st.QueueSiblings(ctx, digestOf(sha256))
		switch {
		case err != nil:
			slog.WarnContext(ctx, "sibling rescan after conviction failed", "sha256", sha256, "error", err)
		case n > 0:
			slog.InfoContext(ctx, "conviction queued sibling artifacts for rescan", "sha256", sha256, "queued", n)
		default:
		}
	}
	return ok, err
}

func (c storeCatalog) FinishLocationMove(ctx context.Context, sha256, oldRel, newRel string) (bool, error) {
	return c.st.FinishMove(ctx, digestOf(sha256), oldRel, newRel)
}

func (c storeCatalog) DonorLocationsForSHA(ctx context.Context, sha256, pool string, limit int) ([]*hopper.SampleLocation, error) {
	paths, err := c.st.Donors(ctx, digestOf(sha256), pool, limit)
	locs := make([]*hopper.SampleLocation, len(paths))
	for i, p := range paths {
		locs[i] = &hopper.SampleLocation{SHA256: sha256, Path: p}
	}
	return locs, err
}

// triageSample is what a ruling needs to know about a file: its label and
// where it is (the most recently seen path).
func (s *apiServer) triageSample(ctx context.Context, sha string) (*hopper.Sample, error) {
	if s.results == nil {
		return s.db.SampleBySHA256(ctx, sha)
	}
	l, err := s.results.LabelOf(ctx, digestOf(sha))
	if errors.Is(err, store.ErrNotFound) {
		return nil, hopper.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sample := &hopper.Sample{SHA256: sha, Label: l.Label, LabelSource: l.LabelSource}
	if len(l.Paths) > 0 {
		sample.Path = l.Paths[0]
	}
	return sample, nil
}
