package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper/store"
)

// ledgerapi.go is the acquirers' half of the sightings ledger: marking the
// claims a pass has tried to fetch, retracting claims a source withdrew, and
// the one-claim-per-target acquisition ledger. Each is a write, so each goes
// through hopper; acquirers read the queues they drain with read-only SQL.
//
//	POST /v1/sightings/attempted  [{"source","subject","affected"}, ...] → {"changed": n}
//	POST /v1/sightings/retract    [{"source","subject","affected"}, ...] → {"changed": n}
//	POST /v1/acquisitions/claim   {"target","lease_seconds"}             → {"claimed": bool}
//	POST /v1/acquisitions/finish  {"target","acquired","retry_after_seconds","error"} → {"finished": bool}
//	POST /v1/acquisitions/release {"target"}                             → {"released": bool}

// Bounds on what one request may carry. A key is three short strings; a
// target is a URL or a package coordinate.
const (
	maxSightingKeyBody   = maxSightingsBatch * 512
	maxAcquisitionTarget = 2048
	maxAcquisitionError  = 2000
	maxAcquisitionBody   = 16 << 10
)

type sightingKeyRequest struct {
	Source   string `json:"source"`
	Subject  string `json:"subject"`
	Affected string `json:"affected"`
}

// A sightingKeyOp applies one write to a batch of ledger rows and returns
// how many it changed.
type sightingKeyOp struct {
	write func(st *store.Store, ctx context.Context, keys []store.SightingKey) (int64, error)
	name  string
}

var (
	markAttempted = sightingKeyOp{name: "mark attempted", write: (*store.Store).MarkAttempted}
	retract       = sightingKeyOp{name: "retract", write: (*store.Store).Retract}
)

// handleSightingKeys answers a write to ledger rows named by key.
func (s *apiServer) handleSightingKeys(op sightingKeyOp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.results == nil {
			v1Error(w, http.StatusNotImplemented, "needs_verdict_store", "Needs the verdict store.")
			return
		}
		var reqs []sightingKeyRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxSightingKeyBody+1)).Decode(&reqs); err != nil {
			slog.WarnContext(r.Context(), "sightings "+op.name+" rejected: invalid json", "remote", r.RemoteAddr, "error", err)
			v1Error(w, http.StatusBadRequest, "invalid_json", "Invalid json.")
			return
		}
		if len(reqs) > maxSightingsBatch {
			v1Error(w, http.StatusRequestEntityTooLarge, "too_many_sightings", "Too many sightings.", "max", maxSightingsBatch)
			return
		}
		keys := make([]store.SightingKey, 0, len(reqs))
		for _, k := range reqs {
			if k.Source == "" || k.Subject == "" {
				v1Error(w, http.StatusBadRequest, "source_and_subject_required", "Source and subject are required.")
				return
			}
			subject := strings.TrimSpace(k.Subject)
			if validSHA256(strings.ToLower(subject)) {
				subject = strings.ToLower(subject)
			}
			keys = append(keys, store.SightingKey{Source: k.Source, Subject: subject, Affected: k.Affected})
		}
		// Detached: an acquirer that hangs up must not leave half a pass marked.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), sightingsStoreTimeout)
		defer cancel()
		n, err := op.write(s.results, ctx, keys)
		if err != nil {
			slog.ErrorContext(ctx, "sightings "+op.name+" failed", "count", len(keys), "error", err, "remote", r.RemoteAddr)
			v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
			return
		}
		slog.InfoContext(ctx, "sightings "+op.name, "received", len(keys), "changed", n, "remote", r.RemoteAddr)
		writeTriageJSON(w, sightingsResponse{Changed: int(n)})
	}
}

type acquisitionRequest struct {
	Target            string  `json:"target"`
	Error             string  `json:"error"`
	LeaseSeconds      float64 `json:"lease_seconds"`
	RetryAfterSeconds float64 `json:"retry_after_seconds"`
	Acquired          bool    `json:"acquired"`
}

// decodeAcquisition reads an acquisition request with a usable target. On
// failure it has answered the request.
func (s *apiServer) decodeAcquisition(w http.ResponseWriter, r *http.Request) (*acquisitionRequest, bool) {
	if s.results == nil {
		v1Error(w, http.StatusNotImplemented, "needs_verdict_store", "Needs the verdict store.")
		return nil, false
	}
	var req acquisitionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAcquisitionBody)).Decode(&req); err != nil {
		v1Error(w, http.StatusBadRequest, "invalid_json", "Invalid json.")
		return nil, false
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" || len(req.Target) > maxAcquisitionTarget {
		v1Error(w, http.StatusBadRequest, "invalid_target", "Target is required, at most 2048 bytes.")
		return nil, false
	}
	return &req, true
}

// handleAcquisitionClaim claims one acquisition target for the caller.
func (s *apiServer) handleAcquisitionClaim(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeAcquisition(w, r)
	if !ok {
		return
	}
	if req.LeaseSeconds <= 0 {
		v1Error(w, http.StatusBadRequest, "invalid_lease", "lease_seconds must be positive.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()
	claimed, err := s.results.ClaimAcquisition(ctx, req.Target, time.Duration(req.LeaseSeconds*float64(time.Second)))
	if err != nil {
		slog.ErrorContext(ctx, "acquisition claim failed", "target", req.Target, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	writeTriageJSON(w, map[string]bool{"claimed": claimed})
}

// handleAcquisitionFinish records how a claimed target's fetch ended.
func (s *apiServer) handleAcquisitionFinish(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeAcquisition(w, r)
	if !ok {
		return
	}
	reason := req.Error
	if len(reason) > maxAcquisitionError {
		// Operational detail belongs in logs; the row keeps a bounded summary.
		reason = strings.ToValidUTF8(reason[:maxAcquisitionError], "")
	}
	// Detached: the outcome of a finished fetch must land even if the caller
	// has gone.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), apiQueryTimeout)
	defer cancel()
	finished, err := s.results.FinishAcquisition(ctx, req.Target, req.Acquired,
		time.Duration(req.RetryAfterSeconds*float64(time.Second)), reason)
	if err != nil {
		slog.ErrorContext(ctx, "acquisition finish failed", "target", req.Target, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	writeTriageJSON(w, map[string]bool{"finished": finished})
}

// handleAcquisitionRelease gives back a claim the caller took and could not
// finish because it was shutting down, so the target is claimed again by a
// later pass instead of being reported as abandoned. A finished or acquired
// target is never released (store.ReleaseAcquisition).
func (s *apiServer) handleAcquisitionRelease(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeAcquisition(w, r)
	if !ok {
		return
	}
	// Detached: the caller is shutting down and may hang up, and a release
	// that lands after it has gone is still the right outcome.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), apiQueryTimeout)
	defer cancel()
	released, err := s.results.ReleaseAcquisition(ctx, req.Target)
	if err != nil {
		slog.ErrorContext(ctx, "acquisition release failed", "target", req.Target, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	slog.InfoContext(ctx, "acquisition release", "target", req.Target, "released", released, "remote", r.RemoteAddr)
	writeTriageJSON(w, map[string]bool{"released": released})
}
