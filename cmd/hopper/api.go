package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"codeberg.org/atomdrift/hopper"
)

// apiServer handles the pull-based work API. Workers poll /api/next for
// jobs, submit results via /api/result, and fetch file content from
// /api/file/{sha256}. All state lives in the database; the workerTracker
// is an in-memory cache for the dashboard.
type apiServer struct {
	db          *hopper.DB
	tracker     *workerTracker
	progress    *loadProgress
	dataRoot    string   // absolute path to the data directory; paths are served relative to this
	allowedDirs []string // resolved absolute paths that /api/file may serve from
}

// workerTracker is an in-memory view of active workers, updated on every
// API call. The dashboard reads from it instead of polling nodes.
type workerTracker struct {
	mu      sync.RWMutex
	workers map[string]*workerStats
}

type workerStats struct {
	LastSeen     time.Time
	Slots        int
	ActiveClaims int // jobs claimed but not yet returned
	Analyzed     int64
	Errors       int64
	Version      string
	Traits       string
}

func newWorkerTracker() *workerTracker {
	return &workerTracker{workers: make(map[string]*workerStats)}
}

func (wt *workerTracker) update(name string, slots int, version, traits string, claimed int) {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	ws, ok := wt.workers[name]
	if !ok {
		if len(wt.workers) >= maxTrackedWorkers {
			return // silently drop to prevent memory exhaustion
		}
		ws = &workerStats{}
		wt.workers[name] = ws
	}
	ws.LastSeen = time.Now()
	ws.Slots = slots
	ws.Version = version
	ws.Traits = traits
	ws.ActiveClaims += claimed
}

func (wt *workerTracker) recordResult(name string, isError bool) {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	ws, ok := wt.workers[name]
	if !ok {
		ws = &workerStats{}
		wt.workers[name] = ws
	}
	ws.LastSeen = time.Now()
	if ws.ActiveClaims > 0 {
		ws.ActiveClaims--
	}
	if isError {
		ws.Errors++
	} else {
		ws.Analyzed++
	}
}

// namedWorkerStats is workerStats with the worker name attached.
type namedWorkerStats struct {
	workerStats

	Name string
}

// all returns a snapshot of workers seen within the last hour.
// Stale entries are pruned on each call.
func (wt *workerTracker) all() []namedWorkerStats {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	cutoff := time.Now().Add(-1 * time.Hour)
	for name, ws := range wt.workers {
		if ws.LastSeen.Before(cutoff) {
			delete(wt.workers, name)
		}
	}
	out := make([]namedWorkerStats, 0, len(wt.workers))
	for name, ws := range wt.workers {
		out = append(out, namedWorkerStats{Name: name, workerStats: *ws})
	}
	return out
}

// registerAPI mounts the work API routes on the given mux.
func (s *apiServer) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/next", s.handleNext)
	mux.HandleFunc("POST /api/result", s.handleResult)
	mux.HandleFunc("GET /api/file/{sha256}", s.handleFile)
}

const (
	maxClaimCount      = 10
	claimExpiry        = 30 * time.Minute
	maxWorkerNameLen   = 64
	maxResultBodyBytes = 8 << 20 // 8 MiB — plenty for cleave+litmus JSON.
	maxTrackedWorkers  = 200
)

// validWorkerName checks that the name is non-empty, <= maxWorkerNameLen,
// and contains only printable ASCII without control chars or whitespace tricks.
func validWorkerName(name string) bool {
	if name == "" || len(name) > maxWorkerNameLen {
		return false
	}
	for _, r := range name {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' {
			return false
		}
	}
	return true
}

// handleNext claims work items for a worker.
// GET /api/next?worker=nuc&count=3&slots=4&version=0.8.2&traits=abc123.
func (s *apiServer) handleNext(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		http.Error(w, `{"error":"starting"}`, http.StatusServiceUnavailable)
		return
	}
	worker := r.URL.Query().Get("worker")
	if !validWorkerName(worker) {
		http.Error(w, `{"error":"invalid worker name"}`, http.StatusBadRequest)
		return
	}

	count := 1
	if v := r.URL.Query().Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			count = n
		}
	}
	if count > maxClaimCount {
		count = maxClaimCount
	}

	slots := 1
	if v := r.URL.Query().Get("slots"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			slots = n
		}
	}
	version := r.URL.Query().Get("version")
	traits := r.URL.Query().Get("traits")

	jobs, err := s.db.ClaimJobs(r.Context(), worker, count, claimExpiry)
	if err != nil {
		slog.Error("claim jobs failed", "worker", worker, "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	// Update tracker with claim count so the dashboard knows the worker is active.
	s.tracker.update(worker, slots, version, traits, len(jobs))

	// Persist worker heartbeat to DB for crash recovery.
	wk := hopper.Worker{Name: worker, Slots: slots, Version: version, Traits: traits}
	if err := s.db.UpsertWorker(r.Context(), wk); err != nil {
		slog.Debug("upsert worker failed", "worker", worker, "error", err)
	}

	if len(jobs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Strip the data root to return relative paths. Workers join these
	// with their own data root to find files locally.
	if s.dataRoot != "" {
		prefix := s.dataRoot + string(filepath.Separator)
		for i := range jobs {
			jobs[i].Path = strings.TrimPrefix(jobs[i].Path, prefix)
		}
	}

	slog.Debug("claimed jobs", "worker", worker, "count", len(jobs))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"jobs": jobs}); err != nil {
		slog.Error("failed to encode claim response", "error", err)
	}
}

// resultRequest is the JSON body for POST /api/result.
type resultRequest struct {
	SHA256     string          `json:"sha256"`
	Worker     string          `json:"worker"`
	ML         json.RawMessage `json:"ml"`
	Raw        json.RawMessage `json:"raw"`
	Error      string          `json:"error"`
	DurationMs int64           `json:"duration_ms"`
}

// handleResult receives an analysis result from a worker.
func (s *apiServer) handleResult(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxResultBodyBytes))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}

	var req resultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if !validSHA256(req.SHA256) || !validWorkerName(req.Worker) {
		http.Error(w, `{"error":"invalid sha256 or worker"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if req.Error != "" {
		// Look up the sample path for more useful error logs.
		samplePath := ""
		if sample, err := s.db.SampleBySHA256(ctx, req.SHA256); err == nil {
			samplePath = sample.Path
		}

		if isPermanentError(req.Error) {
			// Unsupported file type, missing file, etc. — mark so it's
			// never queued again, but preserve the record.
			skip := "unsupported"
			if strings.Contains(req.Error, "Path does not exist") {
				skip = "missing"
			}
			if err := s.db.SetSkip(ctx, req.SHA256, skip); err != nil {
				slog.Error("mark permanent failure failed", "sha256", req.SHA256, "error", err)
			} else {
				slog.Info("marked sample", "sha256", req.SHA256, "path", samplePath, "skip", skip, "reason", req.Error)
			}
		} else {
			// Transient error — release claim so another worker can try.
			if err := s.db.UnclaimJobs(ctx, []string{req.SHA256}); err != nil {
				slog.Error("unclaim failed", "sha256", req.SHA256, "error", err)
			}
			slog.Warn("worker reported analysis error",
				"worker", req.Worker, "sha256", req.SHA256, "path", samplePath, "error", req.Error)
		}
		s.progress.errors.Add(1)
		s.tracker.recordResult(req.Worker, true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck,errchkjson // best-effort response
		return
	}

	// Store cleave result.
	canonical := extractCanonicalSHA(req.SHA256, req.Raw)
	if err := s.db.UpdateCleaveResult(ctx, req.SHA256, req.Raw, canonical); err != nil {
		slog.Error("store cleave result failed", "sha256", req.SHA256, "error", err)
		http.Error(w, `{"error":"store cleave result"}`, http.StatusInternalServerError)
		return
	}

	// Store litmus result.
	if err := s.db.UpdateLitmusResult(ctx, req.SHA256, req.ML); err != nil {
		slog.Error("store litmus result failed", "sha256", req.SHA256, "error", err)
	}

	s.progress.analyzed.Add(1)
	s.tracker.recordResult(req.Worker, false)

	// Explode archive members.
	parent, err := s.db.SampleBySHA256(ctx, req.SHA256)
	if err != nil {
		if !errors.Is(err, hopper.ErrNotFound) {
			slog.Error("fetch for explosion failed", "sha256", req.SHA256, "error", err)
		}
	} else {
		if n, err := s.db.ExplodeArchiveMembers(ctx, parent); err != nil {
			slog.Error("archive explosion failed", "sha256", req.SHA256, "error", err)
		} else if n > 0 {
			slog.Debug("exploded archive members", "sha256", req.SHA256, "members", n)
			s.progress.exploded.Add(n)
		}
	}

	slog.Debug("result stored", "worker", req.Worker, "sha256", req.SHA256, "duration_ms", req.DurationMs)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck,errchkjson // best-effort response
}

// isPermanentError returns true for analysis errors that will never succeed
// on retry — the sample should be deleted rather than reclaimed.
func isPermanentError(msg string) bool {
	return strings.Contains(msg, "Unsupported file type") ||
		strings.Contains(msg, "Path does not exist")
}

// validSHA256 checks that s is exactly 64 lowercase hex characters.
func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// handleFile serves file content for remote workers.
// GET /api/file/{sha256}.
func (s *apiServer) handleFile(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha256")
	if !validSHA256(sha) {
		http.Error(w, `{"error":"invalid sha256"}`, http.StatusBadRequest)
		return
	}

	sample, err := s.db.SampleBySHA256(r.Context(), sha)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		} else {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		}
		return
	}

	// Path containment: resolve symlinks and verify the file is under
	// one of the allowed sample directories. Prevents serving arbitrary
	// files if a sample row has a crafted or symlinked path.
	resolved, err := filepath.EvalSymlinks(sample.Path)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if !s.pathAllowed(resolved) {
		slog.Warn("file request blocked: path outside allowed directories",
			"sha256", sha, "path", sample.Path, "resolved", resolved)
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	// Serve the file directly (no directory listings — the path is a file).
	f, err := os.Open(resolved) //nolint:gosec // path validated above
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	defer f.Close() //nolint:errcheck // best-effort close
	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

// pathAllowed checks that resolved is under one of the allowed sample directories.
func (s *apiServer) pathAllowed(resolved string) bool {
	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(resolved, dir+string(filepath.Separator)) || resolved == dir {
			return true
		}
	}
	return false
}
