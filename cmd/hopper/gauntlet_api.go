package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// maxGauntletBody bounds one run envelope. A 50-sample cohort carrying every
// engine's verdict is about half a megabyte.
const maxGauntletBody = 32 << 20

// gauntletRunResponse acknowledges a run by the identity hopper derived for it,
// which a producer checks before it forgets its own copy.
type gauntletRunResponse struct {
	ID       string `json:"id"`
	Inserted bool   `json:"inserted"`
}

// handleGauntletRun records one gauntlet run: the observations the gauntlet
// queue selects benchmark disagreements from.
//
//	POST /v1/gauntlet/runs  hopper.GauntletRun → {"id": "…", "inserted": bool}
//
// A run is recorded whole or not at all. Replaying a stored run is 200 with
// inserted false, so a producer can retry until it hears back; a run whose
// identity is stored with other content is 409 and changes nothing.
func (s *apiServer) handleGauntletRun(w http.ResponseWriter, r *http.Request) {
	if s.db == nil && s.results == nil {
		writeRetryable(w, retryAfterStarting, "starting", "Starting.")
		return
	}
	var in hopper.GauntletRun
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGauntletBody))
	if err := dec.Decode(&in); err != nil {
		slog.WarnContext(r.Context(), "gauntlet run rejected: invalid json", "remote", r.RemoteAddr, "error", err)
		v1Error(w, http.StatusBadRequest, "invalid_json", "Invalid json.")
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		v1Error(w, http.StatusBadRequest, "trailing_data", "One run per request.")
		return
	}
	run, err := hopper.PrepareGauntletRun(in)
	if err != nil {
		slog.WarnContext(r.Context(), "gauntlet run rejected", "producer", in.Producer, "source", in.Source,
			"error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusBadRequest, "invalid_run", err.Error())
		return
	}

	// Detached: a producer that hangs up must not abort a run half-written.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), apiQueryTimeout)
	defer cancel()
	var fresh bool
	if s.results != nil {
		fresh, err = s.results.AddGauntletRun(ctx, run)
	} else {
		fresh, err = s.db.StoreGauntletRun(ctx, in)
	}
	if errors.Is(err, store.ErrGauntletConflict) || errors.Is(err, hopper.ErrGauntletConflict) {
		slog.WarnContext(ctx, "gauntlet run conflicts with the stored run", "id", run.ID,
			"producer", run.Producer, "observed_at", run.ObservedAt, "remote", r.RemoteAddr)
		v1Error(w, http.StatusConflict, "run_conflict", "Run identity is stored with different content.", "id", run.ID)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "gauntlet run: store failed", "id", run.ID, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	slog.InfoContext(ctx, "gauntlet run recorded", "id", run.ID, "producer", run.Producer,
		"observed_at", run.ObservedAt, "samples", len(run.Samples), "inserted", fresh, "remote", r.RemoteAddr)
	writeTriageJSON(w, gauntletRunResponse{ID: run.ID, Inserted: fresh})
}
