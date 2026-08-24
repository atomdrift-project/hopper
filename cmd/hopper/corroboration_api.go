package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// handleCorroborationStatus reports what the lookup path has observed about the
// corroboration ledger. GET /_/corroboration.
//
// An operator surface, in the /_/ namespace beside /_/replica and for the same
// reason: it answers "is this behaving?" rather than serving anyone's data. It
// reads process counters only — no database, no locks, no allocation that
// scales with the corpus — so it is safe to poll and safe on a replica.
//
// Two independent things live here because one is only readable beside the
// other. The ledger counters say whether samples.corroborated still agrees with
// the sightings table; the record-pool counters say how much of the lookup
// traffic ever reached a query at all, which is what decides whether a small
// disagreement count means "healthy" or "barely sampled".
func (s *apiServer) handleCorroborationStatus(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	c := s.db.CorroborationStats()
	rec := s.db.RecordCacheStats()

	// Reported as two directions, never as one drift number. A mark that did
	// not happen and a clear that did not happen have different causes — the
	// second implicates the ledger's DELETE path specifically — and a combined
	// figure would hide which of them moved.
	body := map[string]any{
		"ledger": map[string]any{
			"cited_but_not_flagged": c.CitedButNotFlagged,
			"flagged_but_not_cited": c.FlaggedButNotCited,
		},
		// What the corroboration floor is actually doing. `tightened` is the
		// one to watch: it counts stored verdicts an outside claim made
		// stricter, which is the population where this overrides measurement.
		"floor": map[string]any{
			"derived":   c.Derived,
			"tightened": c.Tightened,
		},
		"records": map[string]any{
			"served":   rec.Served,
			"loaded":   rec.Loaded,
			"entries":  rec.Entries,
			"capacity": rec.Capacity,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.WarnContext(r.Context(), "corroboration status: write failed", "error", err)
	}
}
