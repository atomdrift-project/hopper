package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/atomdrift-project/hopper/store"
	"github.com/atomdrift-project/hopper/v7result"
)

// results.go stores a worker's result in the verdict schema (store).
// handleResult hands a result here when apiServer.results is set; until the
// migration it is not, and results go to DB.StoreResult as before.
//
// A version 8 body (Content-Type application/x-ndjson) is decoded by
// scanresult.Decode. Anything else is a version 7 JSON object, converted by
// v7result.Convert; that path is fromV7 and its helpers below, and goes when every
// worker sends version 8.

// verdictResult is one decoded result, whichever version it came in.
type verdictResult struct {
	sha256  string // the scanned artifact
	worker  string // qualified with the sender's address
	files   []scanresult.File
	ms      int64
	missing bool // the worker could not find the bytes where it was sent
}

// storeVerdicts decodes, stores and answers one result. The caller holds an
// ingestion slot.
func (s *apiServer) storeVerdicts(w http.ResponseWriter, r *http.Request, lane string) {
	start := time.Now()
	res, ok := s.decodeVerdictResult(w, r)
	if !ok {
		return
	}
	recordResultPhase(r.Context(), "body", lane, time.Since(start))

	// Detached from the request, as in handleResult: a worker that hangs up
	// must not abort a store of work it has finished.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), resultStoreTimeout)
	defer cancel()

	start = time.Now()
	stats, err := s.writeVerdicts(ctx, res)
	recordResultPhase(r.Context(), "store", lane, time.Since(start))
	claimedPath := s.tracker.release(res.sha256)
	s.tracker.recordResult(res.worker, err != nil)
	if res.missing {
		// Not there: forget the location, and let another worker try the
		// file wherever else it is.
		s.markUnavailable(ctx, res.sha256, claimedPath, "missing")
		s.releaseClaims(ctx, []string{res.sha256})
	}
	switch {
	case errors.Is(err, scanresult.ErrMalformed):
		slog.WarnContext(r.Context(), "result rejected", "worker", res.worker, "sha256", res.sha256,
			"path", claimedPath, "error", err)
		s.progress.recordErrorf(1, "store", "result rejected: %s: %v", res.sha256, err)
		v1Error(w, http.StatusUnprocessableEntity, "result_rejected_malformed", "Result rejected: malformed.")
		return
	case err != nil:
		logResultStoreError(r.Context(), ctx, "store result failed after accepting worker result", res.sha256, err)
		s.progress.recordErrorf(1, "store", "store result: %s: %v", res.sha256, err)
		v1Error(w, http.StatusInternalServerError, "store_result_failed", "Store result failed.")
		return
	default:
	}

	stored := stats.Changed()
	if stored {
		s.progress.analyzed.Add(1)
		slog.InfoContext(r.Context(), "result stored", "worker", res.worker, "sha256", res.sha256, "path", claimedPath,
			"files", stats.Files, "judged", stats.Judged, "deferred", stats.Deferred, "new_samples", stats.NewSamples, "retyped", stats.Retyped,
			"verdicts", stats.Verdicts, "stamped", stats.Stamped, "jurors_removed", stats.JurorsRemoved,
			"claims", stats.Claims, "claims_removed", stats.ClaimsRemoved,
			"reports", stats.Reports, "reports_unchanged", stats.ReportsUnchanged,
			"contents", stats.Contents, "orphaned", stats.Orphaned, "refs", stats.Refs, "refs_removed", stats.RefsRemoved,
			"duration_ms", res.ms, "store_ms", time.Since(start).Milliseconds())
	} else {
		recordRedundantResult(r.Context(), lane)
		slog.DebugContext(r.Context(), "result already current; nothing stored",
			"worker", res.worker, "sha256", res.sha256, "path", claimedPath, "files", stats.Files, "late", stats.Late)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "stored": stored}) //nolint:errcheck,errchkjson // best-effort response
}

// writeVerdicts stores res, retrying transient database failures. A store is
// one transaction, so a retry starts clean. Two results for one artifact
// arriving together are stored one after the other, in the store's order of
// their scans; each is answered for itself.
func (s *apiServer) writeVerdicts(ctx context.Context, res *verdictResult) (store.Stats, error) {
	if len(res.files) == 0 {
		return store.Stats{}, nil
	}
	return retryDBAccess(ctx, "store verdicts", res.sha256, func(ctx context.Context) (store.Stats, error) {
		return s.results.Write(ctx, res.files)
	})
}

// decodeVerdictResult reads the body within the result limits and decodes it.
// On failure it has answered the request.
func (s *apiServer) decodeVerdictResult(w http.ResponseWriter, r *http.Request) (*verdictResult, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-ndjson" {
		return s.fromV7(w, r)
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(resultBodyTimeout)) //nolint:errcheck // optional
	rb, err := resultBody(r)
	if err != nil {
		v1Error(w, http.StatusUnsupportedMediaType, "unsupported_content_encoding", "Unsupported content-encoding.")
		return nil, false
	}
	defer rb.cleanup()
	body := bytes.NewBuffer(make([]byte, 0, min(max(rb.sizeHint, 0), hopper.MaxJSONSizeHint)))
	if _, err := body.ReadFrom(rb.body); err != nil || rb.overLimit() {
		if rb.overLimit() {
			slog.Warn("result rejected: body exceeds size limit", "limit_bytes", int64(maxResultBodyBytes), "remote", r.RemoteAddr)
			v1Error(w, http.StatusRequestEntityTooLarge, "result_too_large", "Result body exceeds size limit.")
			return nil, false
		}
		slog.Warn("result rejected: body unreadable", "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusBadRequest, "result_body_unreadable", "Result body unreadable.")
		return nil, false
	}
	files, err := scanresult.Decode(body.Bytes())
	if err != nil {
		slog.Warn("result rejected: invalid version 8 body", "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusBadRequest, "invalid_result_body", "Invalid result body.")
		return nil, false
	}
	root := files[0]
	if !validWorkerName(root.Scan.Worker) || root.Verdict == nil {
		slog.Warn("result rejected: no worker or no verdict for the scanned file",
			"worker", root.Scan.Worker, "sha256", hex.EncodeToString(root.SHA256), "remote", r.RemoteAddr)
		v1Error(w, http.StatusBadRequest, "invalid_result", "Invalid worker, or no verdict for the scanned file.")
		return nil, false
	}
	return &verdictResult{
		files: files, sha256: hex.EncodeToString(root.SHA256),
		worker: qualifiedWorkerName(root.Scan.Worker, r.RemoteAddr), ms: root.Scan.MS,
	}, true
}

// fromV7 reads a version 7 result and converts it. It goes when every worker
// sends version 8.
func (s *apiServer) fromV7(w http.ResponseWriter, r *http.Request) (*verdictResult, bool) {
	req := decodeResultRequest(w, r)
	if req == nil {
		return nil, false
	}
	req.Worker = qualifiedWorkerName(req.Worker, r.RemoteAddr)
	res := &verdictResult{sha256: req.SHA256, worker: req.Worker, ms: req.DurationMs}
	sha, err := hex.DecodeString(req.SHA256)
	if err != nil {
		v1Error(w, http.StatusBadRequest, "invalid_sha256_or_worker", "Invalid sha256 or worker.")
		return nil, false
	}
	if req.Error != "" {
		verdict, ok := v7Failure(req.Error)
		if !ok {
			// The worker could not find the bytes: that is about where the
			// file is, not about the file, so there is no verdict to record.
			slog.Info("worker could not read the sample; no verdict recorded",
				"worker", req.Worker, "sha256", req.SHA256, "error", trimClientError(req.Error))
			res.files, res.missing = []scanresult.File{}, true
			return res, true
		}
		res.files = []scanresult.File{{SHA256: sha, Verdict: verdict, Scan: scanresult.Stamp{At: time.Now().UTC(), Worker: req.Worker}}}
		return res, true
	}
	// The report's own ruleset wins; these are the fallbacks handleResult uses.
	ruleset := s.TraitsVersion()
	if wt := s.tracker.traits(req.Worker); ruleset == "" && len(wt) >= 5 {
		ruleset = wt[:5]
	}
	c, err := v7result.Convert(&v7result.Result{
		At: time.Now().UTC(), SHA256: req.SHA256, Worker: req.Worker, Ruleset: ruleset,
		ML: req.ML, LLM: req.LLM, Raw: req.Raw,
	}, hopper.CriticalLevel)
	if err != nil {
		s.tracker.release(req.SHA256)
		s.tracker.recordResult(req.Worker, true)
		slog.Warn("result rejected: version 7 body cannot be converted", "worker", req.Worker, "sha256", req.SHA256, "error", err)
		v1Error(w, http.StatusUnprocessableEntity, "result_rejected_malformed", "Result rejected: malformed.")
		return nil, false
	}
	for reason, n := range c.Omitted {
		slog.Debug("version 7 result: entries not stored", "sha256", req.SHA256, "reason", reason, "count", n)
	}
	res.files = c.Files
	return res, true
}

// v7Failure turns a version 7 worker error into the verdict version 8 would
// have sent. ok is false when the error says nothing about the file itself.
func v7Failure(msg string) (verdict json.RawMessage, ok bool) {
	outcome := "error"
	switch skip, permanent := classifyResultError(msg); {
	case skip == "missing":
		return nil, false
	case skip == "timeout":
		outcome = "timeout"
	case permanent:
		outcome = "unsupported"
	default:
	}
	verdict, err := json.Marshal(map[string]string{"outcome": outcome, "error": trimClientError(msg)})
	return verdict, err == nil
}
