package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/atomdrift-project/hopper"
)

// GET /api/sightings/ancestry?sha256=... checks each file and all parents for
// applicable sightings. A positive answer carries witnesses; a clear answer
// is emitted only after the full parent walk succeeds. Unknown ancestry is an
// error, not a clear reputation. Consumers can safely fail closed on old servers.
func (s *apiServer) handleSightingsAncestry(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	shas := r.URL.Query()["sha256"]
	if len(shas) == 0 || len(shas) > 16 {
		writeJSONError(w, http.StatusBadRequest, `{"error":"between 1 and 16 sha256 values required"}`)
		return
	}
	for i, sha := range shas {
		shas[i] = strings.ToLower(sha)
		if !validSHA256(shas[i]) {
			writeJSONError(w, http.StatusBadRequest, `{"error":"invalid sha256"}`)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()
	bySHA := make(map[string]*hopper.SightingsAncestry)
	for _, sha := range shas {
		if _, done := bySHA[sha]; done {
			continue
		}
		result, err := s.db.SightingsInAncestry(ctx, sha)
		if err != nil {
			if errors.Is(err, hopper.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, `{"error":"unknown file or ancestor"}`)
			} else {
				slog.ErrorContext(ctx, "sightings ancestry check failed", "sha256", sha, "error", err)
				writeJSONError(w, http.StatusServiceUnavailable, `{"error":"ancestry check incomplete"}`)
			}
			return
		}
		bySHA[sha] = result
	}
	writeTriageJSON(w, map[string]any{"version": 1, "complete": true, "by_sha256": bySHA})
}
