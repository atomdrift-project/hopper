package main

import (
	"context"
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
	"sync/atomic"
	"time"
	"unicode"

	"codeberg.org/atomdrift/hopper"
	"github.com/codeGROOVE-dev/retry"
)

// apiServer handles the pull-based work API. Workers poll /api/next for
// jobs, submit results via /api/result, and fetch file content from
// /api/file/{sha256}. Sample data lives in the database; per-job claim
// state lives in workerTracker (see below).
type apiServer struct {
	db         *hopper.DB
	tracker    *workerTracker
	progress   *loadProgress
	explosions chan explosionJob // archive-expansion work, drained by background goroutines
	// traitsVersion holds the short prefix of the current traits repo
	// commit. Stored in an atomic.Pointer so the periodic rules-update
	// goroutine can refresh it concurrently with read traffic from
	// /api/next, /api/result, and the dashboard. Empty = rescan disabled.
	traitsVersion       atomic.Pointer[string]
	hopperStart         time.Time // process start; gates force-rescan claim tier
	dataRoot            string    // resolved absolute path to the data directory
	allowedDirs         []string  // resolved absolute paths that /api/file may serve from
	forceRescanPrefixes []string  // normalized relative paths to re-analyze when analysis predates hopperStart
	explosionWG         sync.WaitGroup
	rescanAge           time.Duration
}

// TraitsVersion returns the current canonical traits version. Safe for
// concurrent callers; empty if not yet set or if the local litmus
// hasn't reported a version.
func (s *apiServer) TraitsVersion() string {
	if v := s.traitsVersion.Load(); v != nil {
		return *v
	}
	return ""
}

// SetTraitsVersion updates the canonical traits version. Called once at
// startup with the initial value, and again after every periodic
// rules-update rotation so dashboard staleness checks reflect what the
// local litmus is actually running.
func (s *apiServer) SetTraitsVersion(v string) {
	s.traitsVersion.Store(&v)
}

// explosionJob defers archive-member expansion off the /api/result hot path.
// Workers don't care about the result of explosion — it only seeds new rows
// in samples for future analysis.
type explosionJob struct {
	sha256 string
	raw    json.RawMessage
}

const maxClientErrorRunes = 120

// workerTracker holds in-memory worker stats AND active job claims.
//
// Claims used to live in samples.claimed_by/claimed_at in Postgres. That made
// every poll an UPDATE on the multi-million-row samples table, which (a) blew
// out the visibility map so "index only" scans degraded into million-fetch
// heap probes, and (b) prevented HOT updates because claimed_by/claimed_at
// were both indexed — so each claim wrote a new tuple plus a new entry in
// every other index. The result was 71 GB of relation for 5.3 GB of data and
// a Tier-3 query that took 5+ seconds.
//
// Claims are now in-memory only. Durability does not matter: the worst case
// of losing claim state (Hopper restart, crash, in-memory eviction) is that
// two workers analyze the same file. Cleave/litmus analysis is deterministic-
// ish and UpdateCleaveResult is idempotent, so a duplicate is wasted CPU, not
// corruption. Hopper restart actually improves recovery here — old DB-stored
// claims used to block re-claim for up to 30 minutes.
type workerTracker struct {
	workers map[string]*workerStats
	claims  map[string]claim // sha256 -> claim
	mu      sync.RWMutex
}

// claim records that a sha256 is currently out with a worker.
type claim struct {
	at     time.Time
	worker string
	path   string // for dashboard/log display; avoids a per-worker DB lookup
}

type workerStats struct {
	LastSeen     time.Time
	LastClaimed  time.Time // when the most recent batch of claims was made
	LastUpserted time.Time // when we last persisted a heartbeat row to the workers table
	Version      string
	Traits       string
	TotalClaimed int64
	Analyzed     int64
	Errors       int64
	Slots        int
	ActiveClaims int     // jobs claimed but not yet returned
	RSSMB        int     // last reported RSS in MiB (0 = unknown)
	Load1        float64 // last reported 1-minute load average (0 = unknown)
}

func newWorkerTracker() *workerTracker {
	return &workerTracker{
		workers: make(map[string]*workerStats),
		claims:  make(map[string]claim),
	}
}

// tryClaimBatch picks up to want candidates that aren't currently held by
// another worker (or whose hold is older than expiry), records them under
// the given worker name, and returns the claimed jobs. Order of cands
// determines priority — the caller pre-sorts.
func (wt *workerTracker) tryClaimBatch(cands []hopper.ClaimJob, worker string, expiry time.Duration, want int) []hopper.ClaimJob {
	if want <= 0 || len(cands) == 0 {
		return nil
	}
	wt.mu.Lock()
	defer wt.mu.Unlock()
	now := time.Now()
	out := make([]hopper.ClaimJob, 0, want)
	for _, c := range cands {
		if existing, ok := wt.claims[c.SHA256]; ok {
			if now.Sub(existing.at) < expiry {
				continue
			}
			wt.decrementActiveLocked(existing.worker)
		}
		wt.claims[c.SHA256] = claim{worker: worker, path: c.Path, at: now}
		out = append(out, c)
		if len(out) == want {
			break
		}
	}
	if len(out) > 0 {
		ws, ok := wt.workers[worker]
		if !ok && len(wt.workers) < maxTrackedWorkers {
			ws = &workerStats{}
			wt.workers[worker] = ws
		}
		if ws != nil {
			ws.ActiveClaims += len(out)
			ws.TotalClaimed += int64(len(out))
			ws.LastClaimed = now
			ws.LastSeen = now
		}
	}
	return out
}

func (wt *workerTracker) decrementActiveLocked(worker string) {
	if ws := wt.workers[worker]; ws != nil && ws.ActiveClaims > 0 {
		ws.ActiveClaims--
	}
}

// release drops a single claim and decrements the holding worker's
// ActiveClaims counter. Returns the path that was associated with the
// claim so the caller can log it without a separate DB lookup. Returns
// "" if the sha256 wasn't held.
func (wt *workerTracker) release(sha string) string {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	c, ok := wt.claims[sha]
	if !ok {
		return ""
	}
	delete(wt.claims, sha)
	wt.decrementActiveLocked(c.worker)
	return c.path
}

// releaseMany drops a batch of claims.
func (wt *workerTracker) releaseMany(shas []string) {
	if len(shas) == 0 {
		return
	}
	wt.mu.Lock()
	defer wt.mu.Unlock()
	for _, s := range shas {
		c, ok := wt.claims[s]
		if !ok {
			continue
		}
		delete(wt.claims, s)
		wt.decrementActiveLocked(c.worker)
	}
}

// oldestPerWorker returns the oldest active claim per worker name, dropping
// claims older than maxAge from the map as it walks. The dashboard calls
// this on every render — there is no separate sweep goroutine.
func (wt *workerTracker) oldestPerWorker(maxAge time.Duration) map[string]hopper.WorkerClaim {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-maxAge)
	out := map[string]hopper.WorkerClaim{}
	for sha, c := range wt.claims {
		if c.at.Before(cutoff) {
			delete(wt.claims, sha)
			wt.decrementActiveLocked(c.worker)
			continue
		}
		if cur, ok := out[c.worker]; !ok || c.at.Before(cur.ClaimedAt) {
			out[c.worker] = hopper.WorkerClaim{Worker: c.worker, Path: c.path, ClaimedAt: c.at}
		}
	}
	return out
}

func (wt *workerTracker) pruneExpiredClaimsLocked(worker string, expiry time.Duration, now time.Time) {
	if expiry <= 0 {
		return
	}
	cutoff := now.Add(-expiry)
	for sha, c := range wt.claims {
		if c.worker == worker && c.at.Before(cutoff) {
			delete(wt.claims, sha)
			wt.decrementActiveLocked(c.worker)
		}
	}
}

// update records a worker heartbeat. ActiveClaims/TotalClaimed/LastClaimed
// are owned by tryClaimBatch and release; do not bump them here.
func (wt *workerTracker) update(name string, slots int, version, traits string, rssMB int, load1 float64) {
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
	ws.RSSMB = rssMB
	ws.Load1 = load1
}

// shouldUpsertWorker reports whether the workers-table heartbeat row for the
// named worker should be re-persisted, and stamps the time if so. The DB row
// is purely for crash inspection — the dashboard reads from this tracker —
// so it can lag the in-memory view by a few tens of seconds without harm.
// Without this throttle every /api/next does a WAL-flushed write.
func (wt *workerTracker) shouldUpsertWorker(name string, interval time.Duration) bool {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	ws := wt.workers[name]
	if ws == nil {
		return true // first sighting; let the caller persist
	}
	now := time.Now()
	if now.Sub(ws.LastUpserted) < interval {
		return false
	}
	ws.LastUpserted = now
	return true
}

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
	wt.pruneExpiredClaimsLocked(name, claimExpiry, time.Now())
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

func (wt *workerTracker) traits(name string) string {
	wt.mu.RLock()
	defer wt.mu.RUnlock()
	if ws, ok := wt.workers[name]; ok {
		return ws.Traits
	}
	return ""
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

// recordResult bumps the analyzed/errors counter for a worker. The matching
// claim is dropped separately by release(); call that first so ActiveClaims
// is decremented before the counter bump.
func (wt *workerTracker) recordResult(name string, isError bool) {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	ws, ok := wt.workers[name]
	if !ok {
		ws = &workerStats{}
		wt.workers[name] = ws
	}
	ws.LastSeen = time.Now()
	if isError {
		ws.Errors++
	} else {
		ws.Analyzed++
	}
}

// resetClaims drops every claim held by the named worker. Call this when a
// worker process is restarted so stale claims from the old process don't
// permanently block the new one from receiving work.
func (wt *workerTracker) resetClaims(name string) {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	for sha, c := range wt.claims {
		if c.worker == name {
			delete(wt.claims, sha)
		}
	}
	if ws, ok := wt.workers[name]; ok {
		ws.ActiveClaims = 0
	}
}

// namedWorkerStats is workerStats with the worker name attached.
type namedWorkerStats struct { //nolint:govet // embedded field must come first per embeddedstructfieldcheck
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
	maxResultBodyBytes = 256 << 20 // 256 MiB — some archive cleave reports legitimately exceed 128 MiB.
	maxTrackedWorkers  = 200
	apiQueryTimeout    = 30 * time.Second
	resultStoreTimeout = 10 * time.Minute
	dbRetryInitial     = 100 * time.Millisecond
	dbRetryMax         = 5 * time.Second

	// Candidate fetch over-fetches the worker's requested count so concurrent
	// pollers walking the same head-of-queue rows don't all collapse onto the
	// same prefix. tryClaimBatch handles the deduplication in memory.
	candidateOverfetch = 8
	minCandidates      = 32

	// workerUpsertInterval throttles DB heartbeat writes per worker so a
	// busy worker polling several times per second doesn't generate a
	// matching write storm to the workers table.
	workerUpsertInterval = 30 * time.Second

	// explosionQueueSize bounds how many cleave results may be waiting for
	// background archive expansion. Set well above expected steady-state so
	// transient bursts don't push back on /api/result.
	explosionQueueSize    = 4096
	explosionWorkers      = 4
	explosionDrainTimeout = 30 * time.Second
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
//
//nolint:gocognit,maintidx // single sequence of input validation + claim flow; splitting hides control flow
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

	var rssMB int
	if v := r.URL.Query().Get("rss_mb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			rssMB = n
		}
	}
	var load1 float64
	if v := r.URL.Query().Get("load1"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			load1 = f
		}
	}

	// Cap claims for workers that haven't returned any results yet.
	if limit := s.tracker.claimLimit(worker); limit == 0 {
		//nolint:gosec // worker is sanitized by validWorkerName
		slog.Warn("unproven worker at active claim limit, waiting for results",
			"worker", worker, "active", s.tracker.activeClaims(worker))
		s.tracker.update(worker, slots, version, traits, rssMB, load1)
		w.WriteHeader(http.StatusNoContent)
		return
	} else if count > limit {
		count = limit
	}

	// Heartbeat first so the dashboard sees the worker even on no-work polls.
	s.tracker.update(worker, slots, version, traits, rssMB, load1)

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	// Persist worker heartbeat to DB for crash recovery, throttled. The
	// dashboard reads live worker state from the in-memory tracker; the DB
	// row is only for post-crash inspection.
	if s.tracker.shouldUpsertWorker(worker, workerUpsertInterval) {
		wk := hopper.Worker{Name: worker, Slots: slots, Version: version, Traits: traits}
		if err := s.db.UpsertWorker(ctx, wk); err != nil {
			slog.Debug("upsert worker failed", "worker", worker, "error", err) //nolint:gosec // worker is sanitized by validWorkerName
		}
	}

	jobs, err := s.claimJobs(ctx, worker, count)
	if err != nil {
		slog.Error("claim jobs failed", "worker", worker, "error", err) //nolint:gosec // worker is sanitized by validWorkerName
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	if len(jobs) == 0 {
		var rescanPending int64
		if s.TraitsVersion() != "" {
			if n, err := s.db.CountRescanPending(ctx, s.TraitsVersion(), s.rescanAge); err == nil {
				rescanPending = n
			} else {
				slog.Debug("count rescan pending failed", "worker", worker, "error", err) //nolint:gosec // worker is sanitized by validWorkerName
			}
		}
		//nolint:gosec // worker is sanitized by validWorkerName.
		slog.Info("no work available", "worker", worker,
			"active_claims", s.tracker.activeClaims(worker),
			"traits_version", s.TraitsVersion(),
			"rescan_age", s.rescanAge,
			"rescan_pending", rescanPending,
			"force_rescan_prefixes", len(s.forceRescanPrefixes))
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Validate files before handing them to workers. Files that were
	// replaced or removed since indexing are released back from the in-
	// memory claim set and marked skip so they don't block the queue.
	var unclaimSHAs []string
	validated := jobs[:0]
	for _, j := range jobs {
		if j.Path == "" || j.Path == "." {
			slog.Warn("skipping job with empty path", //nolint:gosec // structured logging, worker validated
				"worker", worker, "sha256", j.SHA256)
			if err := s.db.SetSkip(ctx, j.SHA256, "empty_path"); err != nil {
				slog.Error("mark empty_path failed", "sha256", j.SHA256, "error", err) //nolint:gosec // structured logging
			}
			unclaimSHAs = append(unclaimSHAs, j.SHA256)
			continue
		}
		diskPath := sampleDiskPath(s.dataRoot, filepath.FromSlash(j.Path))
		info, err := os.Stat(diskPath) //nolint:gosec // path from DB lookup, not user input
		if err != nil {
			//nolint:gosec // worker validated, sha256/path from DB
			slog.Warn("claimed file missing on disk",
				"worker", worker, "sha256", j.SHA256, "path", j.Path, "disk_path", diskPath)
			if err := s.db.SetSkip(ctx, j.SHA256, "missing"); err != nil {
				slog.Error("mark missing failed", "sha256", j.SHA256, "error", err) //nolint:gosec // structured logging
			}
			unclaimSHAs = append(unclaimSHAs, j.SHA256)
			continue
		}
		if j.SizeBytes > 0 && info.Size() != j.SizeBytes {
			//nolint:gosec // sha256 validated, path from DB, sizes are int64
			slog.Warn("claimed file size mismatch — file was likely replaced",
				"worker", worker, "sha256", j.SHA256, "path", j.Path,
				"db_size", j.SizeBytes, "disk_size", info.Size())
			if err := s.db.SetSkip(ctx, j.SHA256, "corrupt"); err != nil {
				slog.Error("mark corrupt failed", "sha256", j.SHA256, "error", err) //nolint:gosec // structured logging
			}
			unclaimSHAs = append(unclaimSHAs, j.SHA256)
			continue
		}
		validated = append(validated, j)
	}
	jobs = validated
	s.tracker.releaseMany(unclaimSHAs)

	// Strip the data root to return relative paths. Workers join these
	// with their own data root to find files locally. EvalSymlinks inside
	// stripDataRoot handles DB paths that use a symlinked prefix.
	if s.dataRoot != "" {
		prefix := s.dataRoot + string(filepath.Separator)
		for i := range jobs {
			if !filepath.IsAbs(jobs[i].Path) {
				jobs[i].Path = filepath.ToSlash(jobs[i].Path)
				continue
			}
			jobs[i].Path = filepath.ToSlash(stripDataRoot(jobs[i].Path, prefix))
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
type resultRequest struct {
	SHA256     string          `json:"sha256"`
	Worker     string          `json:"worker"`
	Error      string          `json:"error"`
	ML         json.RawMessage `json:"ml"`
	Raw        json.RawMessage `json:"raw"`
	DurationMs int64           `json:"duration_ms"`
}

// handleResult receives an analysis result from a worker.
func (s *apiServer) handleResult(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		http.Error(w, `{"error":"starting"}`, http.StatusServiceUnavailable)
		return
	}
	// Stream-decode rather than io.ReadAll: avoids a duplicate 128 MiB buffer
	// per concurrent uploader. The Raw/ML json.RawMessage fields still land
	// in memory once each, but we lose the second whole-body copy.
	limited := io.LimitReader(r.Body, maxResultBodyBytes)
	dec := json.NewDecoder(limited)
	var req resultRequest
	if err := dec.Decode(&req); err != nil {
		slog.Warn("result rejected: invalid json", //nolint:gosec // structured logging
			"error", err,
			"remote", r.RemoteAddr,
		)
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if !validSHA256(req.SHA256) || !validWorkerName(req.Worker) {
		slog.Warn("result rejected: invalid fields", "worker", req.Worker, "sha256", req.SHA256)
		http.Error(w, `{"error":"invalid sha256 or worker"}`, http.StatusBadRequest)
		return
	}
	req.Worker = qualifiedWorkerName(req.Worker, r.RemoteAddr)

	// Once the result body is accepted, persist it independently of the
	// client connection. Workers may time out or disconnect while Hopper is
	// still doing DB work, and that must not discard completed analysis.
	ctx, cancelStore := context.WithTimeout(context.WithoutCancel(r.Context()), resultStoreTimeout)
	defer cancelStore()

	if req.Error != "" {
		clientErr := trimClientError(req.Error)

		// Look up the sample path for more useful error logs.
		samplePath := ""
		if sample, err := retryDBAccess(ctx, "sample lookup for worker error", req.SHA256, func(ctx context.Context) (*hopper.Sample, error) {
			return s.db.SampleBySHA256(ctx, req.SHA256)
		}); err == nil {
			samplePath = sample.Path
		}

		if skip, permanent := classifyResultError(req.Error); permanent {
			// Permanent failure (unsupported file type, missing file, etc.) —
			// mark so it's never queued again, but preserve the record.
			if err := retryDBAccessNoValue(ctx, "mark permanent failure", req.SHA256, func(ctx context.Context) error {
				return s.db.SetSkip(ctx, req.SHA256, skip)
			}); err != nil {
				slog.Error("mark permanent failure failed", "sha256", req.SHA256, "error", err)
			} else {
				//nolint:gosec // sha256 validated, path from DB.
				slog.Info("marked sample", "sha256", req.SHA256,
					"path", samplePath, "skip", skip, "reason", clientErr)
			}
		} else {
			if err := retryDBAccessNoValue(ctx, "record analysis error", req.SHA256, func(ctx context.Context) error {
				return s.db.SetNote(ctx, req.SHA256, clientErr)
			}); err != nil {
				slog.Error("record analysis error failed", "sha256", req.SHA256, "error", err)
			}
			//nolint:gosec // worker sanitized by validWorkerName, sha256 by validSHA256, path from DB
			slog.Warn("worker reported analysis error",
				"worker", req.Worker, "sha256", req.SHA256, "path", samplePath, "error", clientErr)
		}
		s.progress.recordErrorf(1, "worker", "worker: %s: %s", req.SHA256, clientErr)
		// Drop the in-memory claim so another worker can try it. Order matters:
		// release decrements ActiveClaims, then recordResult bumps Errors.
		s.tracker.release(req.SHA256)
		s.tracker.recordResult(req.Worker, true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck,errchkjson // best-effort response
		return
	}

	// Parse cleave result once — used for both storage and explosion.
	parsed := hopper.ParseCleaveResult(req.SHA256, req.Raw)

	// Determine the traits version used for this analysis: prefer the
	// version embedded in the cleave result (authoritative), fall back to
	// the server's local litmus version, then the worker's self-reported
	// traits hash.
	tv := parsed.TraitsVersion
	if tv == "" {
		tv = s.TraitsVersion()
	}
	if tv == "" {
		if wt := s.tracker.traits(req.Worker); len(wt) >= 5 {
			tv = wt[:5]
		}
	}

	if err := retryDBAccessNoValue(ctx, "store cleave result", req.SHA256, func(ctx context.Context) error {
		return s.db.UpdateCleaveResult(ctx, req.SHA256, req.Raw, &parsed, tv)
	}); err != nil {
		logResultStoreError(r.Context(), ctx, "store cleave result failed after accepting worker result", req.SHA256, err)
		// Drop the claim and bump errors so the worker's slot frees up — without
		// this, the worker's ActiveClaims is permanently inflated for this job.
		s.tracker.release(req.SHA256)
		s.tracker.recordResult(req.Worker, true)
		s.progress.recordErrorf(1, "store", "store cleave result: %s: %v", req.SHA256, err)
		errMsg := `{"error":"store cleave result failed"}`
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			errMsg = `{"error":"store cleave result failed: database write context was canceled or timed out"}`
		}
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	// Store litmus result.
	if err := retryDBAccessNoValue(ctx, "store litmus result", req.SHA256, func(ctx context.Context) error {
		return s.db.UpdateLitmusResult(ctx, req.SHA256, req.ML)
	}); err != nil {
		s.progress.recordErrorf(1, "store", "store litmus result: %s: %v", req.SHA256, err)
		slog.Error("store litmus result failed", "sha256", req.SHA256, "error", err)
	}

	s.progress.analyzed.Add(1)
	path := s.tracker.release(req.SHA256)
	s.tracker.recordResult(req.Worker, false)

	// Hand archive expansion to the background pool. The worker doesn't
	// care about the result, and a 200-entry JAR shouldn't keep its HTTP
	// connection (or our pool conn) busy.
	s.enqueueExplosion(ctx, explosionJob{sha256: req.SHA256, raw: req.Raw})

	//nolint:gosec // worker sanitized by validWorkerName, sha256 by validSHA256, path from in-memory claim
	slog.Info("result stored", "worker", req.Worker, "sha256", req.SHA256, "path", path,
		"duration_ms", req.DurationMs, "active_claims", s.tracker.activeClaims(req.Worker))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck,errchkjson // best-effort response
}

// startExplosions launches the background pool that expands archive cleave
// results into child sample rows. Call once after the apiServer's db is set.
// Workers exit only when the queue is closed via drainExplosions; that lets
// graceful shutdown actually finish in-flight DB writes instead of failing
// them with context.Canceled the moment main shuts down.
func (s *apiServer) startExplosions(ctx context.Context) {
	// Decouple from cancellation so workers survive a ctx-Done shutdown
	// long enough for drainExplosions to flush the channel. db.Close runs
	// after drainExplosions in main, so the pool stays alive.
	explosionCtx := context.WithoutCancel(ctx)
	s.explosions = make(chan explosionJob, explosionQueueSize)
	for range explosionWorkers {
		s.explosionWG.Go(func() {
			for job := range s.explosions {
				// Per-job panic recovery so a malformed cleave result can't
				// crash the worker (which would shrink the pool until restart).
				func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("explosion worker recovered from panic",
								"sha256", job.sha256, "panic", r)
						}
					}()
					s.processExplosion(explosionCtx, job)
				}()
			}
		})
	}
}

// drainExplosions closes the queue and waits for in-flight expansions to
// finish, capped at explosionDrainTimeout so a wedged DB doesn't hang
// shutdown. Call exactly once.
func (s *apiServer) drainExplosions() {
	if s.explosions == nil {
		return
	}
	close(s.explosions)
	done := make(chan struct{})
	go func() { s.explosionWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(explosionDrainTimeout):
		slog.Warn("explosion drain timed out; some archive members may not be enqueued",
			"timeout", explosionDrainTimeout)
	}
}

func (s *apiServer) processExplosion(ctx context.Context, job explosionJob) {
	parent, err := retryDBAccess(ctx, "fetch sample for archive explosion", job.sha256, func(ctx context.Context) (*hopper.Sample, error) {
		return s.db.SampleParentInfo(ctx, job.sha256)
	})
	if err != nil {
		if !errors.Is(err, hopper.ErrNotFound) {
			slog.Error("fetch for explosion failed", "sha256", job.sha256, "error", err)
		}
		return
	}
	parent.CleaveResult = job.raw // we already have it; avoid re-reading from DB
	n, err := retryDBAccess(ctx, "explode archive members", job.sha256, func(ctx context.Context) (int64, error) {
		return s.db.ExplodeArchiveMembers(ctx, parent)
	})
	if err != nil {
		slog.Error("archive explosion failed", "sha256", job.sha256, "error", err)
		return
	}
	if n > 0 {
		slog.Debug("exploded archive members", "sha256", job.sha256, "members", n)
		s.progress.exploded.Add(n)
		s.progress.queued.Add(n)
		s.progress.analyzed.Add(n)
	}
}

// enqueueExplosion hands the job off to the background pool, falling back to
// inline processing if the queue is full so we never lose a result. A full
// queue means the explosion workers can't keep up — log it so the operator
// notices.
func (s *apiServer) enqueueExplosion(ctx context.Context, job explosionJob) {
	if s.explosions == nil {
		s.processExplosion(ctx, job)
		return
	}
	select {
	case s.explosions <- job:
	default:
		slog.Warn("explosion queue full; processing inline", "sha256", job.sha256, "queue_size", explosionQueueSize)
		s.processExplosion(ctx, job)
	}
}

// claimJobs walks the three priority tiers (unanalyzed → force-rescan →
// stale-traits) in order, fetching candidate batches from the DB and
// claiming the first count that aren't held by another worker. Over-fetches
// so that contention with other concurrent pollers doesn't starve a
// requester at the head of the queue.
func (s *apiServer) claimJobs(ctx context.Context, worker string, count int) ([]hopper.ClaimJob, error) {
	want := count
	overfetch := max(count*candidateOverfetch, minCandidates)

	cands, err := s.db.UnanalyzedCandidates(ctx, s.hopperStart, overfetch)
	if err != nil {
		return nil, err
	}
	out := s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)
	if len(out) >= count {
		return out, nil
	}

	if len(s.forceRescanPrefixes) > 0 {
		want = count - len(out)
		cands, err = s.db.ForceRescanCandidates(ctx, s.hopperStart, s.forceRescanPrefixes, want*candidateOverfetch)
		if err != nil {
			return out, err
		}
		out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
		if len(out) >= count {
			return out, nil
		}
	}

	if s.TraitsVersion() != "" {
		want = count - len(out)
		cands, err = s.db.StaleTraitsCandidates(ctx, s.TraitsVersion(), s.rescanAge, s.hopperStart, want*candidateOverfetch)
		if err != nil {
			return out, err
		}
		out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
	}
	return out, nil
}

func retryDBAccessNoValue(ctx context.Context, op, sha256 string, fn func(context.Context) error) error {
	_, err := retryDBAccess(ctx, op, sha256, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, fn(ctx)
	})
	return err
}

func retryDBAccess[T any](ctx context.Context, op, sha256 string, fn func(context.Context) (T, error)) (T, error) {
	return retry.DoWithData(
		func() (T, error) {
			v, err := fn(ctx)
			if err == nil {
				return v, nil
			}
			if ctx.Err() != nil ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, hopper.ErrNotFound) {
				return v, retry.Unrecoverable(err)
			}
			return v, err
		},
		retry.Context(ctx),
		retry.UntilSucceeded(),
		retry.Delay(dbRetryInitial),
		retry.MaxDelay(dbRetryMax),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.LastErrorOnly(true),
		retry.WrapContextErrorWithLastError(true),
		retry.OnRetry(func(attempt uint, err error) {
			slog.Warn("database operation failed; retrying",
				"op", op, "sha256", sha256, "attempt", attempt+1, "error", err)
		}),
	)
}

func logResultStoreError(reqCtx, storeCtx context.Context, msg, sha256 string, err error) {
	attrs := []any{"sha256", sha256, "error", err}
	if reqErr := reqCtx.Err(); reqErr != nil {
		attrs = append(attrs, "request_context", reqErr)
	}
	if storeErr := storeCtx.Err(); storeErr != nil {
		attrs = append(attrs, "store_context", storeErr)
	}
	slog.Error(msg, attrs...)
}

// validSHA256 checks that s is exactly 64 lowercase hex characters.
// Rejecting mixed case at the edge prevents a misbehaving worker from
// creating a case-variant duplicate of an existing sample — the samples
// table treats sha256 as a plain TEXT column, so "abc…" and "ABC…" count
// as distinct values under UNIQUE.
func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// classifyResultError categorizes a worker-reported analysis error. If the
// error matches a known permanent failure mode (unsupported format, missing
// file, encrypted archive, etc.) it returns the skip-reason string and true.
// Unknown errors are treated as transient and the caller re-queues the job.
//
// Order matters: more-specific cases come first so e.g. "Path does not
// exist" classifies as "missing" rather than "unsupported".
func classifyResultError(errMsg string) (string, bool) {
	switch {
	case strings.Contains(errMsg, "Path does not exist"),
		strings.Contains(errMsg, "no local path"):
		return "missing", true
	case strings.Contains(errMsg, "analysis timed out"):
		return "timeout", true
	case strings.Contains(errMsg, "Password"),
		strings.Contains(errMsg, "Failed to decrypt"):
		return "encrypted", true
	case strings.Contains(errMsg, "CRC error"),
		strings.Contains(errMsg, "invalid gzip header"),
		strings.Contains(errMsg, "bad magic"),
		strings.Contains(errMsg, "NUL byte"),
		strings.Contains(errMsg, "checksum mismatch"),
		strings.Contains(errMsg, "Invalid timestamp"):
		return "corrupt", true
	case strings.Contains(errMsg, "Unsupported file type"),
		strings.Contains(errMsg, "invalid Zip archive"),
		strings.Contains(errMsg, "Failed to read tar entry"),
		strings.Contains(errMsg, "Failed to parse package.json"),
		strings.Contains(errMsg, "multi-disk"):
		return "unsupported", true
	}
	return "", false
}

func trimClientError(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return ""
	}
	count := 0
	for i := range msg {
		if count == maxClientErrorRunes {
			return strings.TrimSpace(msg[:i])
		}
		count++
	}
	return msg
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

	// Archive member: extracted children aren't stored on disk under their
	// own SHA — they live inside the parent. Resolve to the parent path,
	// stream-extract the inner file, and serve those bytes.
	if sample.Parent != "" {
		s.serveArchiveMember(ctx, w, r, sample, sha)
		return
	}

	// Path containment: resolve symlinks and verify the file is under
	// one of the allowed sample directories. Prevents serving arbitrary
	// files if a sample row has a crafted or symlinked path.
	diskPath := sampleDiskPath(s.dataRoot, filepath.FromSlash(sample.Path))
	resolved, err := filepath.EvalSymlinks(diskPath)
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
			"sha256", sha, "path", sample.Path, "resolved", resolved,
			"remote", r.RemoteAddr, "allowed_dirs", s.allowedDirs)
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

// archiveMemberMaxBytes caps the result of an archive-member extraction.
// Generous enough for source files and manifests; blocks accidental
// extraction of multi-GB blobs into memory.
const archiveMemberMaxBytes = 8 * 1024 * 1024

// serveArchiveMember resolves child to its parent on disk, reads the parent,
// extracts the requested inner path, and writes the bytes back. Reuses the
// same path-containment check as the top-level serve.
func (s *apiServer) serveArchiveMember(ctx context.Context, w http.ResponseWriter, r *http.Request, child *hopper.Sample, sha string) {
	parent, err := s.db.SampleBySHA256(ctx, child.Parent)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			http.Error(w, `{"error":"parent not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	innerPath := hopper.PathInsideArchive(child.Path)
	if innerPath == "" {
		http.Error(w, `{"error":"child has no archive-relative path"}`, http.StatusInternalServerError)
		return
	}

	diskPath := sampleDiskPath(s.dataRoot, filepath.FromSlash(parent.Path))
	resolved, err := filepath.EvalSymlinks(diskPath)
	if err != nil {
		http.Error(w, `{"error":"parent file missing"}`, http.StatusNotFound)
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
		slog.Warn("archive-member request blocked: parent path outside allowed directories",
			"sha256", sha, "parent_sha", parent.SHA256, "parent_path", parent.Path,
			"resolved", resolved, "remote", r.RemoteAddr, "allowed_dirs", s.allowedDirs)
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	archive, err := os.ReadFile(resolved) //nolint:gosec // path validated above
	if err != nil {
		http.Error(w, `{"error":"parent unreadable"}`, http.StatusInternalServerError)
		return
	}
	body, err := hopper.ExtractFromArchive(archive, parent.FileType, innerPath, archiveMemberMaxBytes)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found in archive"):
			http.Error(w, `{"error":"not found in archive"}`, http.StatusNotFound)
		case strings.Contains(err.Error(), "too large"):
			http.Error(w, `{"error":"file too large"}`, http.StatusRequestEntityTooLarge)
		case strings.Contains(err.Error(), "unsupported archive"):
			http.Error(w, `{"error":"unsupported archive type"}`, http.StatusUnsupportedMediaType)
		default:
			//nolint:gosec // sha256 validated by validSHA256
			slog.Warn("archive-member extraction failed",
				"sha256", sha, "parent_sha", parent.SHA256, "error", err)
			http.Error(w, `{"error":"extraction failed"}`, http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if _, err := w.Write(body); err != nil { //nolint:gosec // body served as application/octet-stream; sha256 validated
		slog.Debug("archive-member write failed", "sha256", sha, "error", err)
	}
}

// stripDataRoot converts an absolute DB path to a path relative to prefix.
// DB paths may use a symlinked prefix (e.g. /srv/home/t/data → /srv/data)
// that differs from the resolved dataRoot. EvalSymlinks resolves the entire
// chain including intermediate symlinks.
func stripDataRoot(dbPath, prefix string) string {
	strip := func(path, root string) (string, bool) {
		rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return rel, true
		}
		return "", false
	}

	if rel, ok := strip(dbPath, prefix); ok {
		return rel
	}
	resolvedPath, pathErr := filepath.EvalSymlinks(dbPath)
	resolvedPrefix, prefixErr := filepath.EvalSymlinks(prefix)
	if pathErr == nil && prefixErr == nil {
		if rel, ok := strip(resolvedPath, resolvedPrefix); ok {
			return rel
		}
	}
	// Return as-is; the /api/file/{sha256} download fallback can still serve it.
	return dbPath
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
