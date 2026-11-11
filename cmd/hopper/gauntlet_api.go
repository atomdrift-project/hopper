package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/atomdrift-project/hopper"
)

const maxGauntletBody = 32 << 20

func (s *apiServer) handleGauntletRun(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	var run hopper.GauntletRun
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGauntletBody))
	if err := dec.Decode(&run); err != nil {
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid run"}`)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeJSONError(w, http.StatusBadRequest, `{"error":"trailing data"}`)
		return
	}
	normalized, err := hopper.NormalizeGauntletRun(run)
	if err != nil {
		writeTriageJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	fresh, err := s.db.StoreGauntletRun(r.Context(), normalized)
	if errors.Is(err, hopper.ErrGauntletConflict) {
		writeJSONError(w, http.StatusConflict, `{"error":"run identity has different content"}`)
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "store gauntlet run", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"store failed"}`)
		return
	}
	writeTriageJSON(w, map[string]any{"id": normalized.ID, "inserted": fresh})
}

func (s *apiServer) handleGetGauntletRun(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	run, err := s.db.GauntletRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, `{"error":"unknown run"}`)
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, `{"error":"read failed"}`)
		return
	}
	writeTriageJSON(w, run)
}

func writeTriageJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
