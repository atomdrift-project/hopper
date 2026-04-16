package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
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
	workers map[string]*workerStats
	mu      sync.RWMutex
}

type workerStats struct { //nolint:govet // fields grouped logically, not by alignment.
	LastSeen     time.Time
	LastClaimed  time.Time // when the most recent batch of claims was made
	TotalClaimed int64
	Analyzed     int64
	Errors       int64
	Version      string
	Traits       string
	Slots        int
	ActiveClaims int // jobs claimed but not yet returned
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
	now := time.Now()
	ws.LastSeen = now
	ws.Slots = slots
	ws.Version = version
	ws.Traits = traits
	ws.ActiveClaims += claimed
	ws.TotalClaimed += int64(claimed)
	if claimed > 0 {
		ws.LastClaimed = now
	}
}

// claimLimit returns how many more jobs the worker may claim right now.
// Workers that have never returned a result are capped at warmupClaimLimit
// total. If the worker's claims have all expired (older than claimExpiry),
// the warmup counters are reset so a reconnecting worker can try again.
// claimLimit returns how many more jobs the worker may claim right now.
// Workers that have never returned a result are capped by their active
// (unreturned) claim count — they can hold up to maxClaimCount jobs at once
// but must return results to free capacity for more. Once a worker has
// returned at least one result, the cap is lifted to maxClaimCount per request.
func (wt *workerTracker) claimLimit(name string) int {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	ws, ok := wt.workers[name]
	if !ok {
		return maxClaimCount
	}
	if ws.Analyzed+ws.Errors > 0 {
		return maxClaimCount // proven worker, no warmup cap
	}
	// Unproven worker: limit by active (unreturned) claims, not total.
	// This lets workers refill their prefetch buffer as results come back
	// without hitting a cumulative ceiling.
	remaining := maxClaimCount - ws.ActiveClaims
	if remaining > 0 {
		return remaining
	}
	return 0
}

func (wt *workerTracker) activeClaims(name string) int {
	wt.mu.RLock()
	defer wt.mu.RUnlock()
	if ws, ok := wt.workers[name]; ok {
		return ws.ActiveClaims
	}
	return 0
}

func (wt *workerTracker) lastSeen(name string) time.Time {
	wt.mu.RLock()
	defer wt.mu.RUnlock()
	if ws, ok := wt.workers[name]; ok {
		return ws.LastSeen
	}
	return time.Time{}
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
type namedWorkerStats struct { //nolint:govet // embedding first is idiomatic.
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
	mux.Handle("GET /data/", s.safeFileServer())
}

const (
	maxClaimCount      = 32
	claimExpiry        = 30 * time.Minute
	staleClaimAge      = 2 * time.Hour
	maxWorkerNameLen   = 64
	maxResultBodyBytes = 64 << 20 // 64 MiB — complex samples with many embedded binaries produce large cleave reports.
	maxTrackedWorkers  = 200
	apiQueryTimeout = 30 * time.Second
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

// qualifiedWorkerName returns "name:ip" to disambiguate workers that share
// a hostname. Loopback addresses are left unqualified since the local
// litmus worker is always unique.
func qualifiedWorkerName(name, addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return name
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return name
	}
	return name + ":" + host
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
	worker = qualifiedWorkerName(worker, r.RemoteAddr)

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

	// Cap claims for workers that haven't returned any results yet.
	if limit := s.tracker.claimLimit(worker); limit == 0 {
		slog.Warn("unproven worker at active claim limit, waiting for results", "worker", worker, "active", s.tracker.activeClaims(worker)) //nolint:gosec // worker is sanitized by validWorkerName
		s.tracker.update(worker, slots, version, traits, 0)
		w.WriteHeader(http.StatusNoContent)
		return
	} else if count > limit {
		count = limit
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	jobs, err := s.db.ClaimJobs(ctx, worker, count, claimExpiry)
	if err != nil {
		slog.Error("claim jobs failed", "worker", worker, "error", err) //nolint:gosec // worker is sanitized by validWorkerName
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	// Update tracker with claim count so the dashboard knows the worker is active.
	s.tracker.update(worker, slots, version, traits, len(jobs))

	// Persist worker heartbeat to DB for crash recovery.
	wk := hopper.Worker{Name: worker, Slots: slots, Version: version, Traits: traits}
	if err := s.db.UpsertWorker(ctx, wk); err != nil {
		slog.Debug("upsert worker failed", "worker", worker, "error", err) //nolint:gosec // worker is sanitized by validWorkerName
	}

	if len(jobs) == 0 {
		//nolint:gosec // worker is sanitized by validWorkerName.
		slog.Info("no work available", "worker", worker,
			"active_claims", s.tracker.activeClaims(worker))
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Strip the data root to return relative paths. Workers join these
	// with their own data root to find files locally. Resolve each path
	// first so legacy rows with unresolved symlinks still match.
	if s.dataRoot != "" {
		prefix := s.dataRoot + string(filepath.Separator)
		for i := range jobs {
			p := jobs[i].Path
			if resolved, err := filepath.EvalSymlinks(p); err == nil {
				p = resolved
			} else if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			jobs[i].Path = strings.TrimPrefix(p, prefix)
		}
	}

	active := s.tracker.activeClaims(worker)
	for _, j := range jobs {
		//nolint:gosec // worker is sanitized by validWorkerName.
		slog.Info("claimed", "worker", worker, "sha256", j.SHA256,
			"path", j.Path, "size", j.SizeBytes, "active_claims", active)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"jobs": jobs}); err != nil {
		slog.Error("failed to encode claim response", "error", err)
	}
}

// resultRequest is the JSON body for POST /api/result.
type resultRequest struct { //nolint:govet // JSON field order matches API docs.
	DurationMs int64           `json:"duration_ms"`
	ML         json.RawMessage `json:"ml"`
	Raw        json.RawMessage `json:"raw"`
	SHA256     string          `json:"sha256"`
	Worker     string          `json:"worker"`
	Error      string          `json:"error"`
}

// handleResult receives an analysis result from a worker.
func (s *apiServer) handleResult(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		http.Error(w, `{"error":"starting"}`, http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxResultBodyBytes))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}

	var req resultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Warn("result rejected: invalid json", "error", err, "body_len", len(body))
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if !validSHA256(req.SHA256) || !validWorkerName(req.Worker) {
		slog.Warn("result rejected: invalid fields", "worker", req.Worker, "sha256", req.SHA256)
		http.Error(w, `{"error":"invalid sha256 or worker"}`, http.StatusBadRequest)
		return
	}
	req.Worker = qualifiedWorkerName(req.Worker, r.RemoteAddr)

	// No artificial timeout here — result processing involves multiple
	// sequential DB writes (cleave, litmus, explosion) that can legitimately
	// take longer than a single query timeout.
	ctx := r.Context()

	if req.Error != "" {
		// Look up the sample path for more useful error logs.
		samplePath := ""
		if sample, err := s.db.SampleBySHA256(ctx, req.SHA256); err == nil {
			samplePath = sample.Path
		}

		if strings.Contains(req.Error, "Unsupported file type") ||
			strings.Contains(req.Error, "Path does not exist") ||
			strings.Contains(req.Error, "Failed to decrypt") ||
			strings.Contains(req.Error, "Password required") ||
			strings.Contains(req.Error, "invalid Zip archive") ||
			strings.Contains(req.Error, "analysis timed out") {
			// Unsupported file type, missing file, etc. — mark so it's
			// never queued again, but preserve the record.
			skip := "unsupported"
			if strings.Contains(req.Error, "Path does not exist") {
				skip = "missing"
			} else if strings.Contains(req.Error, "analysis timed out") {
				skip = "timeout"
			}
			if err := s.db.SetSkip(ctx, req.SHA256, skip); err != nil {
				slog.Error("mark permanent failure failed", "sha256", req.SHA256, "error", err)
			} else {
				//nolint:gosec // sha256 validated, path from DB.
				slog.Info("marked sample", "sha256", req.SHA256,
					"path", samplePath, "skip", skip, "reason", req.Error)
			}
		} else {
			// Transient error — release claim so another worker can try.
			if err := s.db.UnclaimJobs(ctx, []string{req.SHA256}); err != nil {
				slog.Error("unclaim failed", "sha256", req.SHA256, "error", err)
			}
			//nolint:gosec // worker sanitized by validWorkerName, sha256 by validSHA256, path from DB
			slog.Warn("worker reported analysis error",
				"worker", req.Worker, "sha256", req.SHA256, "path", samplePath, "error", req.Error)
		}
		s.progress.errors.Add(1)
		s.tracker.recordResult(req.Worker, true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck,errchkjson // best-effort response
		return
	}

	// Parse cleave result once — used for both storage and explosion.
	parsed := hopper.ParseCleaveResult(req.SHA256, req.Raw)
	if err := s.db.UpdateCleaveResult(ctx, req.SHA256, req.Raw, &parsed); err != nil {
		slog.Error("store cleave result failed", "sha256", req.SHA256, "error", err)
		// Still record the result so ActiveClaims is decremented — otherwise
		// the worker's claim count is permanently inflated for this slot.
		s.tracker.recordResult(req.Worker, true)
		s.progress.errors.Add(1)
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
	resultPath := ""
	parent, err := s.db.SampleParentInfo(ctx, req.SHA256)
	if err != nil {
		if !errors.Is(err, hopper.ErrNotFound) {
			slog.Error("fetch for explosion failed", "sha256", req.SHA256, "error", err)
		}
	} else {
		resultPath = parent.Path
		parent.CleaveResult = req.Raw // already have it — avoid re-reading from DB
		if n, err := s.db.ExplodeArchiveMembers(ctx, parent); err != nil {
			slog.Error("archive explosion failed", "sha256", req.SHA256, "error", err)
		} else if n > 0 {
			slog.Debug("exploded archive members", "sha256", req.SHA256, "members", n) //nolint:gosec // sha256 validated by validSHA256
			s.progress.exploded.Add(n)
		}
	}

	//nolint:gosec // worker sanitized by validWorkerName, sha256 by validSHA256, path from DB
	slog.Info("result stored", "worker", req.Worker, "sha256", req.SHA256, "path", resultPath,
		"duration_ms", req.DurationMs, "active_claims", s.tracker.activeClaims(req.Worker))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck,errchkjson // best-effort response
}

// validSHA256 checks that s is exactly 64 hex characters.
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
	if s.db == nil {
		http.Error(w, `{"error":"starting"}`, http.StatusServiceUnavailable)
		return
	}
	sha := r.PathValue("sha256")
	if !validSHA256(sha) {
		http.Error(w, `{"error":"invalid sha256"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	sample, err := s.db.SampleBySHA256(ctx, sha)
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
	allowed := false
	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(resolved, dir+string(filepath.Separator)) || resolved == dir {
			allowed = true
			break
		}
	}
	if !allowed {
		//nolint:gosec // sha256 validated by validSHA256, path from DB lookup
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

// safeFileServer returns an HTTP handler that serves files from dataRoot
// by relative path (e.g. GET /data/bad/sample.bin). This avoids the DB
// lookup that /api/file/{sha256} requires — workers already know the
// relative path from /api/next.
//
// Symlinks are resolved and the final path is checked against allowedDirs,
// matching the security model of handleFile.
func (s *apiServer) safeFileServer() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relPath := strings.TrimPrefix(r.URL.Path, "/data/")
		if relPath == "" || relPath[0] == '/' {
			http.NotFound(w, r)
			return
		}
		// Clean the path and reject anything that escapes the root.
		cleaned := filepath.Clean(filepath.FromSlash(relPath))
		if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}

		absPath := filepath.Join(s.dataRoot, cleaned)
		resolved, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		allowed := false
		for _, dir := range s.allowedDirs {
			if strings.HasPrefix(resolved, dir+string(filepath.Separator)) || resolved == dir {
				allowed = true
				break
			}
		}
		if !allowed {
			//nolint:gosec // relPath is cleaned via filepath.Clean above; logging for diagnostics
			slog.Warn("data request blocked: path outside allowed directories",
				"rel", relPath, "resolved", resolved)
			http.NotFound(w, r)
			return
		}

		f, err := os.Open(resolved) //nolint:gosec // path validated above
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close() //nolint:errcheck // best-effort close
		stat, err := f.Stat()
		if err != nil || stat.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	})
}
