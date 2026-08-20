package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
	"github.com/codeGROOVE-dev/retry"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/klauspost/compress/zstd"
)

// apiServer handles the pull-based work API. Workers poll /api/next for
// jobs, submit results via /api/result, and fetch file content from
// /api/file/{sha256}. Sample data lives in the database; per-job claim
// state lives in workerTracker (see below).
type apiServer struct {
	hopperStart         time.Time
	db                  *hopper.DB
	progress            *loadProgress
	extractSem          chan struct{}
	resultSem           chan struct{}
	extractCache        *extractCache
	traitsVersion       atomic.Pointer[string]
	tracker             *workerTracker
	dataRoot            string
	allowedDirs         []string
	forceRescanPrefixes []string
	requiredMounts      []string
	rescanAge           time.Duration
	ready               atomic.Bool
	datasetIncomplete   bool
}

// errSaturated is returned by the slot-acquire helpers when no slot frees
// within slotAcquireWait. Handlers map it to a 503 + Retry-After so a saturated
// server sheds load fast: the client backs off and retries rather than holding
// a connection open with no response headers until its own timeout fires (the
// failure mode that reads as "context deadline exceeded while awaiting
// headers"). Distinct from ctx cancellation, which means the client gave up.
var errSaturated = errors.New("slot pool saturated")

// slotAcquireWait bounds how long a request queues for a slot before being
// shed. Long enough to absorb sub-second contention — a slot usually frees the
// moment a neighbouring extraction finishes — yet short enough to shed well
// before any client timeout, turning an opaque hang into an actionable 503.
const slotAcquireWait = 3 * time.Second

// slotWaitLogThreshold is the slot-acquisition wait above which a successful
// acquire is still logged: the request was served, but the queue was deep
// enough to be worth surfacing as a contention signal before it tips into
// shedding. Below it, acquisition is effectively free and not worth a line.
const slotWaitLogThreshold = 500 * time.Millisecond

// acquireSlot takes a token from sem, returning nil on success, errSaturated if
// none frees within slotAcquireWait, or ctx.Err() if ctx ends first. A nil sem
// means unlimited (tests construct apiServer directly).
func acquireSlot(ctx context.Context, sem chan struct{}) error {
	return acquireSlotWithin(ctx, sem, slotAcquireWait)
}

// acquireSlotWithin is acquireSlot with an explicit shed deadline, so a test can
// exercise the saturation path without waiting the production slotAcquireWait.
func acquireSlotWithin(ctx context.Context, sem chan struct{}, wait time.Duration) error {
	if sem == nil {
		return nil
	}
	select { // fast path: a slot is free right now
	case sem <- struct{}{}:
		return nil
	default:
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case sem <- struct{}{}:
		return nil
	case <-timer.C:
		return errSaturated
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acquireExtract takes an archive-extraction slot, shedding with errSaturated if
// none frees within slotAcquireWait. Its signature matches the extractCache
// gate, so the cache's heavy builds shed on the same bound.
func (s *apiServer) acquireExtract(ctx context.Context) error {
	return acquireSlot(ctx, s.extractSem)
}

// releaseExtract returns a slot taken by acquireExtract.
func (s *apiServer) releaseExtract() {
	if s.extractSem != nil {
		<-s.extractSem
	}
}

// acquireResult takes a result-ingestion slot, shedding with errSaturated if
// none frees within slotAcquireWait. Gating before the body is decoded means a
// saturated server leaves request bodies unread in the kernel socket buffer
// instead of materializing them on the heap.
func (s *apiServer) acquireResult(ctx context.Context) error {
	return acquireSlot(ctx, s.resultSem)
}

// releaseResult returns a slot taken by acquireResult.
func (s *apiServer) releaseResult() {
	if s.resultSem != nil {
		<-s.resultSem
	}
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
	path   string
	lease  time.Duration
}

// claimLease returns how long a claim on a sample of sizeBytes is held before
// another worker may steal it. Small samples keep baseLease; a large archive
// (a multi-GB ISO) whose scan can outrun the base gets a lease scaled to a
// pessimistic scan-rate floor, capped at maxClaimLease — so a legitimately
// in-progress big scan keeps its claim instead of being re-claimed mid-flight
// (which would double the work and burn one of its limited retry attempts).
func claimLease(baseLease time.Duration, sizeBytes int64) time.Duration {
	lease := baseLease
	if sizeBytes > 0 {
		if scaled := time.Duration(sizeBytes/leaseBytesPerSecond) * time.Second; scaled > lease {
			lease = scaled
		}
	}
	if lease > maxClaimLease {
		lease = maxClaimLease
	}
	return lease
}

type workerStats struct {
	OldestQueueSince time.Time
	LastClaimed      time.Time
	LastUpserted     time.Time
	LastErrorAt      time.Time
	LastCompletion   time.Time
	LastSeen         time.Time
	LastPollAt       time.Time
	Tools            string
	Traits           string
	Version          string
	LastError        string
	Slots            int
	ActiveClaims     int
	RSSMB            int
	Queue            int
	ReportedActive   int
	MemReservedMB    int
	MemCeilingMB     int
	LastWant         int
	LastClaim        int
	BufferRoom       int
	TotalClaimed     int64
	Analyzed         int64
	FilesPerSec      float64
	ErrorsRecent     int
	Load1            float64
	Errors           int64
}

func newWorkerTracker() *workerTracker {
	return &workerTracker{
		workers: make(map[string]*workerStats),
		claims:  make(map[string]claim),
	}
}

// tryClaimBatch picks up to want candidates that aren't currently held by
// another worker (or whose per-claim lease has elapsed), records them under
// the given worker name, and returns the claimed jobs. baseLease is the minimum
// hold; a large sample's lease is scaled up from it by claimLease. Order of
// cands determines priority — the caller pre-sorts.
func (wt *workerTracker) tryClaimBatch(cands []hopper.ClaimJob, worker string, baseLease time.Duration, want int) []hopper.ClaimJob {
	if want <= 0 || len(cands) == 0 {
		return nil
	}
	wt.mu.Lock()
	defer wt.mu.Unlock()
	now := time.Now()
	out := make([]hopper.ClaimJob, 0, want)
	for _, c := range cands {
		if existing, ok := wt.claims[c.SHA256]; ok {
			if now.Sub(existing.at) < existing.lease {
				continue
			}
			wt.decrementActiveLocked(existing.worker)
		}
		wt.claims[c.SHA256] = claim{worker: worker, path: c.Path, at: now, lease: claimLease(baseLease, c.SizeBytes)}
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

// renewClaims refreshes the hold timestamp on the worker's in-progress claims,
// so a legitimately long-running scan (a multi-hour ISO) keeps its claim for as
// long as the worker keeps heartbeating about it — instead of expiring after a
// fixed lease and being re-claimed mid-flight. Scan time is driven by member
// count, not bytes, so no size-derived lease can predict it; liveness can. Only
// claims this worker actually holds are touched; unknown or other-worker shas
// are ignored, so a stale or spoofed heartbeat can't extend someone else's hold.
func (wt *workerTracker) renewClaims(worker string, shas []string, now time.Time) {
	if len(shas) == 0 {
		return
	}
	wt.mu.Lock()
	defer wt.mu.Unlock()
	for _, sha := range shas {
		if c, ok := wt.claims[sha]; ok && c.worker == worker {
			c.at = now
			wt.claims[sha] = c
		}
	}
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

// pruneExpiredClaimsLocked drops the named worker's claims whose per-claim lease
// (size-scaled at claim time) has elapsed, so a worker's stale holds don't count
// against its claim limit.
func (wt *workerTracker) pruneExpiredClaimsLocked(worker string, now time.Time) {
	for sha, c := range wt.claims {
		if c.worker == worker && now.Sub(c.at) >= c.lease {
			delete(wt.claims, sha)
			wt.decrementActiveLocked(c.worker)
		}
	}
}

// update records a worker heartbeat. ActiveClaims/TotalClaimed/LastClaimed
// are owned by tryClaimBatch and release; do not bump them here.
func (wt *workerTracker) update(name string, slots int, version, traits string, rssMB int, load1 float64, tools string) {
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
	ws.Tools = tools
}

// heartbeat records a dedicated /api/heartbeat check-in. It refreshes the same
// liveness signals as update plus the worker's self-reported local-queue
// telemetry, which the work-claim path can't supply. ActiveClaims/TotalClaimed/
// LastClaimed stay owned by tryClaimBatch and release; do not bump them here.
//
// It returns true when hb carries a client-side error string that differs from
// the previous beat's, so the caller can surface it to the log exactly once.
// lastError is sticky across beats, so logging every non-empty value would
// repeat the same line at the heartbeat cadence; keying on a change logs each
// distinct error once while the trailing ErrorsRecent count conveys the volume.
func (wt *workerTracker) heartbeat(name string, hb *workerHeartbeat) (newError bool) {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	ws, ok := wt.workers[name]
	if !ok {
		if len(wt.workers) >= maxTrackedWorkers {
			return false // silently drop to prevent memory exhaustion
		}
		ws = &workerStats{}
		wt.workers[name] = ws
	}
	newError = hb.lastError != "" && hb.lastError != ws.LastError
	ws.LastSeen = time.Now()
	ws.Slots = hb.slots
	ws.Version = hb.version
	ws.Traits = hb.traits
	ws.RSSMB = hb.rssMB
	ws.Load1 = hb.load1
	ws.Tools = hb.tools
	ws.Queue = hb.queue
	ws.ReportedActive = hb.active
	ws.MemReservedMB = hb.memReservedMB
	ws.MemCeilingMB = hb.memCeilingMB
	ws.LastWant = hb.lastWant
	ws.LastClaim = hb.lastClaim
	ws.BufferRoom = hb.bufferRoom
	ws.LastPollAt = hb.lastPollAt
	ws.OldestQueueSince = hb.oldestQueueSince
	ws.LastCompletion = hb.lastCompletion
	ws.FilesPerSec = hb.filesPerSec
	ws.ErrorsRecent = hb.errorsRecent
	ws.LastError = hb.lastError
	ws.LastErrorAt = hb.lastErrorAt
	return newError
}

// workerHeartbeat is the parsed payload of one /api/heartbeat request. Timestamps
// are already converted from the worker's relative ages to absolute hopper-clock
// times at receipt, so the dashboard can render them with time.Since.
type workerHeartbeat struct { //nolint:govet // embedded-first ordering over fieldalignment's pointer-packing
	lastSeenSignals

	oldestQueueSince time.Time
	lastCompletion   time.Time
	lastErrorAt      time.Time
	lastPollAt       time.Time
	lastError        string
	queue            int
	active           int
	memReservedMB    int
	memCeilingMB     int
	lastWant         int
	lastClaim        int
	bufferRoom       int
	filesPerSec      float64
	errorsRecent     int
}

// lastSeenSignals are the liveness fields shared by /api/next and /api/heartbeat.
type lastSeenSignals struct {
	version string
	traits  string
	tools   string
	slots   int
	rssMB   int
	load1   float64
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
	wt.pruneExpiredClaimsLocked(name, time.Now())
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
//

// namedWorkerStats pairs a worker's name with its stats for the dashboard
// snapshot. Embedded field first per Go style; the optimal-alignment ordering
// (Name ahead of the embedded block) is declined deliberately — this is a
// short-lived snapshot value, not a hot allocation.
type namedWorkerStats struct { //nolint:govet // embedded-first ordering over fieldalignment's pointer-packing
	workerStats

	Name string
}

// all returns a snapshot of workers seen within workerRetentionWindow.
// Stale entries are pruned on each call.
func (wt *workerTracker) all() []namedWorkerStats {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	cutoff := time.Now().Add(-workerRetentionWindow)
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
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/next", s.handleNext)
	mux.HandleFunc("GET /api/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /api/result", s.handleResult)
	mux.HandleFunc("POST /api/upload", s.handleUpload)
	mux.HandleFunc("POST /api/known", s.handleKnown)
	mux.HandleFunc("POST /api/sightings", s.handleSightings)
	mux.HandleFunc("GET /api/locations/incoming", s.handleIncomingLocations)
	mux.HandleFunc("POST /api/triage", s.handleTriage)
	mux.HandleFunc("POST /api/rescan/{sha256}", s.handleRescan)
	mux.HandleFunc("GET /api/sample/{sha256}", s.handleSample)
	mux.HandleFunc("GET /api/sample", s.handleSampleByPURL)
	mux.HandleFunc("GET /api/file/{sha256}", s.handleFile)
	mux.HandleFunc("GET /api/provenance/{sha256}", s.handleProvenance)
	mux.Handle("GET /data/", s.safeFileServer())
}

// handleHealthz is a liveness probe that deliberately touches nothing — no
// database, no locks, no allocation-heavy path — so it answers exactly when
// the HTTP serving loop itself is healthy and times out exactly when it
// isn't. During the 2026-07-09 memory-pressure incident every existing
// endpoint needed a DB pool or the dashboard render to diagnose remotely;
// this gives monitors and humans a probe whose failure isolates the fault to
// the process/server layer.
func (s *apiServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck,errchkjson // best-effort response
		"status": "ok",
		"uptime": time.Since(s.hopperStart).Round(time.Second).String(),
	})
}

const (
	maxClaimCount = 32
	claimExpiry   = 30 * time.Minute // base (minimum) claim lease
	staleClaimAge = 2 * time.Hour
	// leaseBytesPerSecond scales a large sample's claim lease past claimExpiry so
	// an in-progress multi-GB scan is not re-claimed mid-flight. A deliberately
	// low, pessimistic scan-rate floor (not a real throughput figure) so the
	// lease comfortably exceeds actual scan time: ~2 MiB/s → a 13 GiB ISO leases
	// ~1.8 h. Small samples stay at claimExpiry.
	leaseBytesPerSecond = 2 << 20
	// maxClaimLease caps the size-scaled lease so a worker that dies mid-scan
	// releases even a huge archive within a bounded window.
	maxClaimLease    = 2 * time.Hour
	maxWorkerNameLen = 64
	// maxResultBodyBytes caps the DECOMPRESSED result body. Raised to 1 GiB for
	// multi-GB OS ISOs, which explode into tens of thousands of members whose
	// combined report can exceed 512 MiB. Ingestion holds the envelope and
	// expands several times over, bounded by the resultSem fan-in (min(8,NCPU)),
	// so the broker's worst-case result memory scales with this — size the hopper
	// host accordingly, or add a low-concurrency large-result lane if it bites.
	maxResultBodyBytes = 1 << 30 // 1 GiB
	maxTrackedWorkers  = 200
	apiQueryTimeout = 30 * time.Second
	// sightingsStoreTimeout bounds one AddSightings attempt. Large feed
	// snapshots can flip many samples.corroborated rows; the old shared
	// apiQueryTimeout (30s) was too tight and timed out under load
	// (2026-08-17). Each attempt gets a fresh budget; see sightingsAttempts.
	sightingsStoreTimeout = 5 * time.Minute
	// sightingsAttempts is how many times /api/sightings retries AddSightings
	// on a transient failure (lock timeout, brief outage, per-attempt
	// deadline). Permanent PG errors and a canceled request stop immediately.
	sightingsAttempts = 3
	resultStoreTimeout = 10 * time.Minute
	dbRetryInitial     = 100 * time.Millisecond
	dbRetryMax         = 5 * time.Second
	// dbRetryAttempts caps how many times a single DB operation is retried on a
	// transient error. The governing context still bounds total wall time, but an
	// attempt cap stops a table-wide stall (e.g. a lock_timeout storm, SQLSTATE
	// 55P03) from being amplified: without it, every blocked worker re-queued for
	// the same lock for the full 10-minute store budget, and the pile of waiters
	// was itself the contention.
	//
	// At dbRetryInitial=100ms doubling to dbRetryMax=5s under full jitter, 28
	// attempts spans ~2 minutes of worst-case backoff — long enough to ride out a
	// DB failover or a brief contention window without losing completed analysis,
	// matching the "retry with backoff up to ~2 minutes" reliability standard,
	// yet bounded so a real outage degrades gracefully instead of storming.
	dbRetryAttempts = 28

	// Candidate fetch over-fetches the worker's requested count so concurrent
	// pollers walking the same head-of-queue rows don't all collapse onto the
	// same prefix. tryClaimBatch handles the deduplication in memory.
	candidateOverfetch = 8
	minCandidates      = 32

	// workerUpsertInterval throttles DB heartbeat writes per worker so a
	// busy worker polling several times per second doesn't generate a
	// matching write storm to the workers table.
	workerUpsertInterval = 30 * time.Second

	// maxUploadBytes caps the artifact bytes in an /api/upload. Matches prism's
	// web upload limit so anything that gets past prism fits here too.
	maxUploadBytes = 100 << 20
	// uploadProvenanceMaxBytes caps the provenance part of a multipart upload.
	// A sidecar carries at most two metadata records, each with Raw bounded by
	// hopper.MaxRawBytes (256 KiB), plus small scalar fields.
	uploadProvenanceMaxBytes = 1 << 20
	// maxUploadEnvelopeBytes caps a full multipart upload body: the artifact
	// (maxUploadBytes) plus the provenance part and multipart framing overhead.
	maxUploadEnvelopeBytes = maxUploadBytes + uploadProvenanceMaxBytes + (64 << 10)
	// uploadFilenameMax bounds the on-disk filename component to keep paths
	// reasonable across filesystems; longer names are truncated, never
	// rejected, so users still get an analysis.
	uploadFilenameMax = 200
	// uploadBodyTimeout caps how long the body of a single /api/upload may
	// take to arrive. Defends against slow-loris streams that hold a temp
	// file open while dripping bytes under maxUploadBytes.
	uploadBodyTimeout = 5 * time.Minute
	// resultBodyTimeout caps how long the body of a single /api/result may
	// take to arrive — the same slow-loris defense as uploadBodyTimeout, but
	// roomier because a result body may reach maxResultBodyBytes (1 GiB
	// decompressed, though zstd-compressed far smaller on the wire). Workers run
	// on the local network, so even a slow-link budget is ample.
	resultBodyTimeout = 10 * time.Minute
	// uploadTmpMaxAge is how long an orphaned .tmp/up-* file may live
	// before startup sweep deletes it. Long enough that an in-flight
	// upload across a process restart still survives if the operator
	// bounces hopper mid-request.
	uploadTmpMaxAge = 1 * time.Hour
	// uploadStoreTimeout caps the detached-context DB store that runs
	// after a successful body write. Long enough for retryDBAccess to
	// chew through transient blips with full-jitter backoff; short enough
	// to surface a real outage to logs without leaving the file orphaned.
	uploadStoreTimeout = 2 * time.Minute
	// uploadDir is the fallback directory under dataRoot where new uploads land:
	// <root>/incoming/uploads. Workers pick them up via the upload tier
	// in claimJobs. It also anchors the spool (.tmp) and extract cache for
	// EVERY upload regardless of destination tree — the post-hash rename must
	// stay on one filesystem, and the service unit grants ReadWritePaths on
	// this root — while recognized producers use the richer coordinate/digest
	// layout in uploadRelDir.
	uploadDir = "incoming/uploads"
	// uploadDirScan and uploadDirPrism split uploads by producer so each tree
	// can carry its own promotion policy. Worker dependency mirroring and
	// `atomscan --hopper` are registry artifacts with fetch provenance and are
	// promotable; prism uploads are arbitrary user submissions, which may be
	// demoted to bad on evidence but must never be auto-promoted into the good
	// pool (a blessed coordinate suppresses future scanning, so promoting
	// attacker-chosen bytes is a poisoning path). Producers are told apart by
	// the sidecar's required fetch.collector.
	uploadDirScan       = "incoming/scan"
	uploadDirPrism      = "incoming/prism"
	uploadDirForager    = "incoming/forager"
	legacyUploadDir     = "unknown/uploads"
	legacyUploadScan    = "unknown/scan"
	legacyUploadPrism   = "unknown/prism"
	legacyUploadForager = "unknown/forager"
)

// uploadRootFor picks the destination tree for a new upload from the producer
// recorded in its provenance sidecar: "scan+<host>" (worker mirroring or the
// --hopper CLI) and "prism" get their own roots, and everything else — other
// collectors, and the deprecated raw-body path that carries no sidecar at all —
// keeps the legacy root. Unattributable bytes therefore never land in a tree a
// promoting daemon watches.
func uploadRootFor(prov *hopper.Sidecar) string {
	if prov == nil {
		return uploadDir
	}
	collector := prov.Fetch.Collector
	// The producer identity is the part before the instance suffix
	// ("scan+galadriel" -> "scan", "forager+0a45da17" -> "forager").
	if i := strings.IndexByte(collector, '+'); i >= 0 {
		collector = collector[:i]
	}
	collector = strings.ToLower(strings.TrimSpace(collector))
	switch collector {
	case "scan":
		return uploadDirScan
	case "prism":
		return uploadDirPrism
	case "forager":
		return uploadDirForager
	default:
		return uploadDir
	}
}

// uploadRoots are current and legacy upload trees. Used to decide whether a
// re-uploaded sha already sits in an upload tree (and must stay there) or lives
// elsewhere in the pool entirely.
var uploadRoots = []string{
	uploadDir, uploadDirScan, uploadDirPrism, uploadDirForager,
	legacyUploadDir, legacyUploadScan, legacyUploadPrism, legacyUploadForager,
}

// existingUploadDir returns the directory of an already-stored sample when it
// sits in one of the upload trees, else "". A sha parked in an upload tree keeps
// its directory on re-upload: re-sending the same bytes (a legacy
// unknown/uploads/ row re-sent by scan now that it routes to unknown/scan/, or a
// producer retrying) must be idempotent, not a second copy in another tree that
// the single row can only point at one of. Rows outside the upload trees
// (already promoted, foraged) return "" and fall through to the producer's root,
// exactly as they did when every upload shared one directory.
func existingUploadDir(existingPath string) string {
	// path.Dir("") is ".", so an absent path falls out here too.
	dir := path.Dir(filepath.ToSlash(existingPath))
	if dir == "." {
		return ""
	}
	for _, root := range uploadRoots {
		if dir == root || strings.HasPrefix(dir, root+"/") {
			return dir
		}
	}
	return ""
}

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

type workerToolSet map[string]bool

func parseWorkerTools(values []string) (string, *workerToolSet) {
	if values == nil {
		return "", nil
	}
	tools := workerToolSet{}
	for _, value := range values {
		for raw := range strings.SplitSeq(value, ",") {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			switch name {
			case "7za", "7zz", "7zr", "p7zip":
				name = "7z"
			default:
			}
			tools[name] = true
		}
	}
	canonical := make([]string, 0, len(tools))
	for _, name := range []string{"rizin", "upx", "innoextract", "7z"} {
		if tools[name] {
			canonical = append(canonical, name)
		}
	}
	return strings.Join(canonical, ","), &tools
}

func workerCanAnalyzeFileType(fileType string, tools *workerToolSet) bool {
	return workerCanAnalyzeFile(fileType, "", tools)
}

func workerCanAnalyzeFile(fileType, filePath string, tools *workerToolSet) bool {
	if tools == nil {
		return true
	}
	ft := normalizeFileType(fileType)
	if ft == "" && filePath == "" {
		return true
	}
	if requiresTool(ft, filePath, "rizin") && !(*tools)["rizin"] {
		return false
	}
	if requiresTool(ft, filePath, "upx") && !(*tools)["upx"] {
		return false
	}
	if requiresTool(ft, filePath, "innoextract") && !(*tools)["innoextract"] {
		return false
	}
	if requiresTool(ft, filePath, "7z") && !(*tools)["7z"] {
		return false
	}
	return true
}

func normalizeFileType(fileType string) string {
	ft := strings.ToLower(strings.TrimSpace(fileType))
	ft = strings.ReplaceAll(ft, "-", "_")
	ft = strings.ReplaceAll(ft, " ", "_")
	return ft
}

func requiresTool(fileType, filePath, tool string) bool {
	switch tool {
	case "rizin":
		return isNativeBinaryFileType(fileType)
	case "upx":
		return fileType == "elf" || fileType == "pe"
	case "innoextract":
		return fileType == "msi" || hasFileExtension(filePath, ".msi", ".msp") || fileType == "pe"
	case "7z":
		return fileType == "pe"
	default:
		return false
	}
}

func isNativeBinaryFileType(fileType string) bool {
	switch fileType {
	case "elf", "pe", "macho", "mach_o":
		return true
	default:
		return false
	}
}

func hasFileExtension(filePath string, exts ...string) bool {
	if filePath == "" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	return slices.Contains(exts, ext)
}

func filterCandidatesByWorkerTools(cands []hopper.ClaimJob, tools *workerToolSet) []hopper.ClaimJob {
	if tools == nil || len(cands) == 0 {
		return cands
	}
	out := cands[:0]
	for _, c := range cands {
		if workerCanAnalyzeFile(c.FileType, c.Path, tools) {
			out = append(out, c)
		}
	}
	return out
}

// filterCandidatesBySize drops candidates larger than the worker's advertised
// max file size, so a memory-constrained worker is never handed an archive that
// would OOM it during analysis. maxBytes <= 0 means the worker set no cap (a
// large worker, or one on a version predating the max_bytes signal), in which
// case every candidate is eligible. Compacts in place like the tools filter.
func filterCandidatesBySize(cands []hopper.ClaimJob, maxBytes int64) []hopper.ClaimJob {
	if maxBytes <= 0 || len(cands) == 0 {
		return cands
	}
	out := cands[:0]
	for _, c := range cands {
		if c.SizeBytes <= maxBytes {
			out = append(out, c)
		}
	}
	return out
}

const (
	// bigArchiveBytes is the size above which a sample (a multi-GB OS ISO or
	// similar container) is routed only to high-core workers. Unpacking and
	// scanning it pins a machine for many minutes, so it belongs on a box that
	// can chew through its members in parallel and still serve other work — not
	// a small node it would monopolize.
	bigArchiveBytes = 1 << 30 // 1 GiB
	// bigArchiveMinSlots is the minimum advertised worker slots required to be
	// offered a big archive.
	bigArchiveMinSlots = 16
)

// filterCandidatesBySlots keeps big archives (> bigArchiveBytes) off workers
// advertising fewer than bigArchiveMinSlots slots. Small workers keep serving
// the high-rate stream of ordinary samples; a big archive simply waits for a
// capable worker to poll — it stays unanalyzed (cleave_result IS NULL), so
// nothing is lost, and the memory-admission gate on the capable worker still
// governs how many it runs at once. A worker that reports no slot count
// (older builds default to slots=1) is treated as small. Compacts in place.
func filterCandidatesBySlots(cands []hopper.ClaimJob, slots int) []hopper.ClaimJob {
	if slots >= bigArchiveMinSlots || len(cands) == 0 {
		return cands
	}
	out := cands[:0]
	for _, c := range cands {
		if c.SizeBytes <= bigArchiveBytes {
			out = append(out, c)
		}
	}
	return out
}

// filterCandidates applies the worker-eligibility filters every claim tier
// shares: tool capabilities, the worker's per-file size cap, and big-archive
// slot routing. One place so a new eligibility rule can't be forgotten in a tier.
func filterCandidates(cands []hopper.ClaimJob, tools *workerToolSet, maxBytes int64, slots int) []hopper.ClaimJob {
	return filterCandidatesBySlots(filterCandidatesBySize(filterCandidatesByWorkerTools(cands, tools), maxBytes), slots)
}

// sizeClass buckets a job by on-disk size for handout interleaving:
// 0 = small (<1 MiB), 1 = medium (<32 MiB), 2 = large. Matches the litmus
// worker-benchmark classes so measurements line up across both repos.
func sizeClass(sizeBytes int64) int {
	switch {
	case sizeBytes < 1<<20:
		return 0
	case sizeBytes < 32<<20:
		return 1
	default:
		return 2
	}
}

// interleaveBySizeClass spreads each size class evenly across the candidate
// list: the k-th of n jobs in a class lands at fractional position (2k+1)/2n
// of the stream, so every claimed batch carries a representative mix of small
// and large work. Without this a worker whose batch happens to be all large
// archives pins every slot for minutes while small samples starve behind them
// — on the litmus worker benchmark, mixing the handout cut median small-sample
// turnaround ~10x when paired with the worker's smallest-first dispatch.
// Positions compare as integer rationals scaled to a 2^32 grid (exact for any
// realistic batch size); the sort is stable, so jobs within a class keep
// their tier ordering.
func interleaveBySizeClass(cands []hopper.ClaimJob) []hopper.ClaimJob {
	if len(cands) < 3 {
		return cands
	}
	var counts [3]uint64
	for i := range cands {
		counts[sizeClass(cands[i].SizeBytes)]++
	}
	type keyedJob struct {
		job hopper.ClaimJob
		key uint64
	}
	keyed := make([]keyedJob, len(cands))
	var seen [3]uint64
	for i := range cands {
		class := sizeClass(cands[i].SizeBytes)
		keyed[i] = keyedJob{
			key: ((2*seen[class] + 1) << 32) / (2 * counts[class]),
			job: cands[i],
		}
		seen[class]++
	}
	slices.SortStableFunc(keyed, func(a, b keyedJob) int {
		switch {
		case a.key < b.key:
			return -1
		case a.key > b.key:
			return 1
		default:
			return 0
		}
	})
	out := make([]hopper.ClaimJob, len(cands))
	for i := range keyed {
		out[i] = keyed[i].job
	}
	return out
}

// handleHeartbeat records a worker check-in without claiming work. The claim
// path (/api/next) only contacts hopper when a worker has buffer room, so a
// saturated worker can vanish from the dashboard for minutes; this endpoint
// gives every worker a fixed-cadence liveness signal carrying RSS, load, queue
// depth, and local-queue telemetry. Heartbeats are display-only and are never
// persisted to the DB — the worker recomputes everything each beat, so a DB
// write would be pure load with no recovery value.
// GET /api/heartbeat?worker=nuc&slots=4&active=3&queue=2&fps=1.5&version=0.8.2&...
// parseActiveSHAs splits a heartbeat's comma-separated in-progress-sha list,
// keeping only well-formed sha256s and bounding the count (by the max a worker
// could hold) so a malformed or hostile heartbeat can't drive an unbounded walk.
func parseActiveSHAs(list string) []string {
	parts := strings.Split(list, ",")
	if len(parts) > maxClaimCount {
		parts = parts[:maxClaimCount]
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if validSHA256(p) {
			out = append(out, p)
		}
	}
	return out
}

func (s *apiServer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	worker := r.URL.Query().Get("worker")
	if !validWorkerName(worker) {
		slog.WarnContext(r.Context(), "heartbeat rejected: invalid worker name",
			"worker", worker, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"invalid worker name"}`, http.StatusBadRequest)
		return
	}
	worker = qualifiedWorkerName(worker, r.RemoteAddr)

	q := r.URL.Query()
	now := time.Now()
	hb := workerHeartbeat{
		lastSeenSignals: lastSeenSignals{
			slots:   queryIntDefault(q, "slots", 1),
			version: q.Get("version"),
			traits:  q.Get("traits"),
			load1:   queryFloat(q, "load1"),
		},
		queue:         queryIntDefault(q, "queue", 0),
		active:        queryIntDefault(q, "active", 0),
		memReservedMB: queryIntDefault(q, "mem_reserved_mb", 0),
		memCeilingMB:  queryIntDefault(q, "mem_ceiling_mb", 0),
		lastWant:      queryIntDefault(q, "want", 0),
		lastClaim:     queryIntDefault(q, "last_claim", 0),
		bufferRoom:    queryIntDefault(q, "buffer_room", 0),
		filesPerSec:   queryFloat(q, "fps"),
		errorsRecent:  queryIntDefault(q, "errs", 0),
		lastError:     q.Get("err"),
	}
	hb.tools, _ = parseWorkerTools(q["tools"])
	if n := queryIntDefault(q, "rss_mb", -1); n >= 0 {
		hb.rssMB = n
	}
	// Refresh the lease on the worker's in-progress claims so a long-running scan
	// (a multi-hour ISO) isn't re-claimed mid-flight. The list is bounded by the
	// worker's slot count, so it stays small.
	if active := q.Get("active_shas"); active != "" {
		s.tracker.renewClaims(worker, parseActiveSHAs(active), now)
	}
	// Ages arrive relative to the worker's clock; anchor them to hopper's clock
	// at receipt so the dashboard renders a live "x ago" without clock-sync.
	if s, ok := queryAgeBefore(q, "oldest_s", now); ok {
		hb.oldestQueueSince = s
	}
	if s, ok := queryAgeBefore(q, "done_age_s", now); ok {
		hb.lastCompletion = s
	}
	if s, ok := queryAgeBefore(q, "poll_age_s", now); ok {
		hb.lastPollAt = s
	}
	if s, ok := queryAgeBefore(q, "err_age_s", now); ok {
		hb.lastErrorAt = s
	}

	if s.tracker.heartbeat(worker, &hb) {
		// Worker-side analysis errors are otherwise invisible here: heartbeats
		// are display-only, so without this the only signal is a number ticking
		// up on the dashboard. Surface the actual error so it lands in the
		// journal/Loki alongside hopper's own logs.
		slog.Warn("worker reported error", //nolint:gosec // structured logging
			"worker", worker,
			"error", hb.lastError,
			"errors_recent", hb.errorsRecent,
		)
	}
	w.WriteHeader(http.StatusNoContent)
}

// queryIntDefault returns the named query value parsed as a non-negative int,
// or def when absent, unparseable, or negative.
func queryIntDefault(q url.Values, name string, def int) int {
	if v := q.Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// queryFloat parses the named query value as a non-negative float, or 0.
func queryFloat(q url.Values, name string) float64 {
	if v := q.Get(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	return 0
}

// queryAgeBefore reads the named query value as an age in seconds and returns
// the absolute time that many seconds before now. ok is false when the param is
// absent or invalid, leaving the caller's timestamp zero.
func queryAgeBefore(q url.Values, name string, now time.Time) (time.Time, bool) {
	v := q.Get(name)
	if v == "" {
		return time.Time{}, false
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return time.Time{}, false
	}
	return now.Add(-time.Duration(secs) * time.Second), true
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
		slog.WarnContext(r.Context(), "next rejected: invalid worker name",
			"worker", worker, "remote", r.RemoteAddr)
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
	tools, toolCaps := parseWorkerTools(r.URL.Query()["tools"])

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
	// Largest file the worker will accept (bytes); absent/0 means no cap. Only
	// files this size or smaller are handed to the worker, keeping large archives
	// off memory-constrained workers that would OOM analyzing them.
	var maxBytes int64
	if v := r.URL.Query().Get("max_bytes"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}

	// Cap claims for workers that haven't returned any results yet.
	if limit := s.tracker.claimLimit(worker); limit == 0 {
		//nolint:gosec // worker is sanitized by validWorkerName
		slog.Warn("unproven worker at active claim limit, waiting for results",
			"worker", worker, "active", s.tracker.activeClaims(worker))
		s.tracker.update(worker, slots, version, traits, rssMB, load1, tools)
		w.WriteHeader(http.StatusNoContent)
		return
	} else if count > limit {
		count = limit
	}

	// Heartbeat first so the dashboard sees the worker even on no-work polls.
	s.tracker.update(worker, slots, version, traits, rssMB, load1, tools)

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

	jobs, err := s.claimJobs(ctx, worker, count, toolCaps, maxBytes, slots)
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

	// Files replaced or removed since indexing are released back from the
	// in-memory claim set and marked skip so they don't block the queue.
	jobs = s.validateClaimJobs(ctx, jobs, worker)

	// Count this hand-out against each sample. Poison samples that wedge a
	// worker never report a result, so the attempt counter is the only signal
	// that catches them; the reaper skips a sample once it crosses
	// hopper.MaxClaimAttempts. Best-effort: a failed bump must not deny work.
	if len(jobs) > 0 {
		claimedSHAs := make([]string, len(jobs))
		for i := range jobs {
			claimedSHAs[i] = jobs[i].SHA256
		}
		if err := s.db.IncrementAttempts(ctx, claimedSHAs); err != nil {
			//nolint:gosec // worker sanitized by validWorkerName
			slog.Warn("increment claim attempts failed",
				"worker", worker, "count", len(claimedSHAs), "error", err)
		}

		// Stamp which claimed samples carry a provenance sidecar, so the worker
		// fetches the registry record (/api/provenance/{sha256}) only for those.
		// Best-effort: on a probe failure HasProvenance stays false and the
		// worker simply skips the fetch — it never blocks handing out work.
		if withProv, err := s.db.ShasWithProvenance(ctx, claimedSHAs); err != nil {
			//nolint:gosec // worker sanitized by validWorkerName
			slog.Warn("provenance presence probe failed",
				"worker", worker, "count", len(claimedSHAs), "error", err)
		} else {
			for i := range jobs {
				jobs[i].HasProvenance = withProv[jobs[i].SHA256]
			}
		}
	}

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

// validateClaimJobs drops jobs whose bytes are not servable before a worker is
// handed them, releasing each dropped job's in-memory claim. A file removed or
// replaced since indexing is marked skip so it stops re-entering the queue; one
// that is merely unreachable right now is released unmarked, so it comes back
// when the mount does. Filters in place: the returned slice aliases jobs.
func (s *apiServer) validateClaimJobs(ctx context.Context, jobs []hopper.ClaimJob, worker string) []hopper.ClaimJob {
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
		location := &hopper.Sample{SHA256: j.SHA256, Path: j.Path}
		f, info, err := s.openKnownSampleFile(ctx, location, worker)
		if err != nil {
			if s.datasetIncomplete {
				// Local disk is not authoritative in this mode — the file being
				// absent here says nothing about whether it exists in the corpus.
				// Release the claim without marking it, so the record stays
				// trainable (skip=''); it'll be handed out again if the bytes
				// ever land locally. Attempts aren't incremented for unclaimed
				// jobs (below), so this can't trip the poison reaper.
				slog.Debug("claimed file absent locally; leaving unmarked (dataset-incomplete)", //nolint:gosec // structured logging
					"worker", worker, "sha256", j.SHA256, "path", j.Path)
				unclaimSHAs = append(unclaimSHAs, j.SHA256)
				continue
			}
			skip := ""
			switch {
			case errors.Is(err, os.ErrNotExist):
				skip = "missing"
			case errors.Is(err, errSamplePathRejected):
				skip = "invalid_path"
			case errors.Is(err, errSampleNotRegular):
				skip = "corrupt"
			default:
				// Transient (EIO, a mount still coming up): leave skip empty so
				// the claim is released rather than the sample condemned.
			}
			if skip == "" {
				//nolint:gosec // G706: worker is validated; sha256/path come from the DB
				slog.Warn("claimed file temporarily unavailable; releasing claim",
					"worker", worker, "sha256", j.SHA256, "path", j.Path, "error", err)
				unclaimSHAs = append(unclaimSHAs, j.SHA256)
				continue
			}
			//nolint:gosec // worker validated, sha256/path from DB
			slog.Warn("claimed file unavailable on all known paths",
				"worker", worker, "sha256", j.SHA256, "path", j.Path, "skip", skip, "error", err)
			if err := s.db.SetSkip(ctx, j.SHA256, skip); err != nil {
				slog.Error("mark unavailable sample failed", "sha256", j.SHA256, "skip", skip, "error", err) //nolint:gosec // structured logging
			}
			unclaimSHAs = append(unclaimSHAs, j.SHA256)
			continue
		}
		f.Close() //nolint:errcheck,gosec // probe handle; only the stat mattered
		j.Path = location.Path
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
	s.tracker.releaseMany(unclaimSHAs)
	return validated
}

// resultRequest is the JSON body for POST /api/result.
type resultRequest struct {
	SHA256     string          `json:"sha256"`
	Worker     string          `json:"worker"`
	Error      string          `json:"error"`
	ML         json.RawMessage `json:"ml"`
	LLM        json.RawMessage `json:"llm"`
	Raw        json.RawMessage `json:"raw"`
	DurationMs int64           `json:"duration_ms"`
}

// resultBody returns a reader over the request body, transparently
// decompressing when the worker advertised a Content-Encoding we support.
// Both the compressed input and the decompressed output are bounded by
// maxResultBodyBytes: a hostile or buggy client must not be able to drive
// the server OOM with a small zstd stream that expands without limit. The
// limits allow one extra byte so overLimit can distinguish "body exceeded
// the cap" (the truncated JSON then fails to decode) from a genuinely
// malformed body — callers should report the former as 413, not 400. The
// returned cleanup must be called once decoding is done.
// resultReader is the decoded result-body stream plus the two closures the
// caller needs alongside it: overLimit reports whether the size cap was hit
// (so a truncated decode can be surfaced as 413 rather than 400), and cleanup
// releases any decoder resources.
type resultReader struct {
	body      io.Reader
	overLimit func() bool
	cleanup   func()
}

func resultBody(r *http.Request) (resultReader, error) {
	raw := &io.LimitedReader{R: r.Body, N: maxResultBodyBytes + 1}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
		return resultReader{body: raw, overLimit: func() bool { return raw.N <= 0 }, cleanup: func() {}}, nil
	case "zstd":
		// One decoder per request: result POSTs are infrequent and large, so
		// the decoder setup is dwarfed by the decode itself. Single-threaded
		// and low-memory keeps the per-request footprint small under bursts.
		zr, err := zstd.NewReader(raw, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
		if err != nil {
			return resultReader{}, err
		}
		out := &io.LimitedReader{R: zr, N: maxResultBodyBytes + 1}
		return resultReader{body: out, overLimit: func() bool { return out.N <= 0 || raw.N <= 0 }, cleanup: zr.Close}, nil
	default:
		return resultReader{}, errors.New("unsupported content-encoding")
	}
}

// recordWorkerError applies a worker's self-reported analysis failure and
// answers it. A permanent cause (unsupported type, missing bytes) marks skip so
// the sample never re-enters the queue; anything else is recorded as a note and
// left queueable. Either way the in-memory claim is dropped so the worker's slot
// frees up. ctx is the store context, already detached from the request.
func (s *apiServer) recordWorkerError(ctx context.Context, w http.ResponseWriter, req *resultRequest) {
	clientErr := trimClientError(req.Error)

	// Look up the sample path for more useful error logs.
	samplePath := ""
	if sample, err := retryDBAccess(ctx, "sample lookup for worker error", req.SHA256, func(ctx context.Context) (*hopper.Sample, error) {
		return s.db.SampleBySHA256(ctx, req.SHA256)
	}); err == nil {
		samplePath = sample.Path
	}

	skip, permanent := classifyResultError(req.Error)
	if permanent && s.datasetIncomplete && skip == "missing" {
		// Dataset-incomplete mode: a worker that can't find the bytes locally
		// says nothing about whether the sample exists in the corpus. Demote
		// this to a transient error (recorded as a note, re-queued) instead of
		// marking skip='missing', so the record stays trainable and the
		// missing-marking never replicates to the primary.
		permanent = false
	}
	if permanent {
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
}

// handleResult receives an analysis result from a worker.
func (s *apiServer) handleResult(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		http.Error(w, `{"error":"starting"}`, http.StatusServiceUnavailable)
		return
	}
	// Bound concurrent ingestions before reading the body: each result expands
	// to several times its (up-to-maxResultBodyBytes) size and is held across a
	// DB store that can stall, so an unbounded fan-in is a heap blow-up. When
	// saturated, shed load with a Retry-After rather than buffering more bodies.
	waitStart := time.Now()
	if err := s.acquireResult(r.Context()); err != nil {
		if errors.Is(err, errSaturated) {
			recordLoadShed(r.Context(), "result")
			slog.WarnContext(r.Context(), "result shed: ingestion slots saturated",
				"remote", r.RemoteAddr, "wait", slotAcquireWait.String())
		}
		writeRetryable(w, retryAfterBusy, `{"error":"busy: result ingestion saturated"}`)
		return
	}
	if waited := time.Since(waitStart); waited > slotWaitLogThreshold {
		slog.WarnContext(r.Context(), "result ingestion slot wait was slow",
			"remote", r.RemoteAddr, "waited_ms", waited.Milliseconds())
	}
	defer s.releaseResult()
	// Slow-loris defense: bound how long the (up to maxResultBodyBytes) body may
	// take to arrive, mirroring handleUpload. Uses the per-request response controller
	// so it doesn't impose a global ReadTimeout on long-lived /data downloads.
	// SetReadDeadline returns http.ErrNotSupported under httptest; harmless.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(resultBodyTimeout)) //nolint:errcheck // optional
	// Stream-decode rather than io.ReadAll: avoids a duplicate 128 MiB buffer
	// per concurrent uploader. The Raw/ML json.RawMessage fields still land
	// in memory once each, but we lose the second whole-body copy.
	rb, err := resultBody(r)
	if err != nil {
		slog.Warn("result rejected: bad content-encoding", //nolint:gosec // structured logging
			"error", err,
			"remote", r.RemoteAddr,
		)
		http.Error(w, `{"error":"unsupported content-encoding"}`, http.StatusUnsupportedMediaType)
		return
	}
	defer rb.cleanup()
	dec := json.NewDecoder(rb.body)
	var req resultRequest
	if err := dec.Decode(&req); err != nil {
		// An over-limit body is truncated mid-document and fails the decode;
		// report it as 413 so the worker sees the real cause instead of a
		// generic "invalid json" 400.
		if rb.overLimit() {
			slog.Warn("result rejected: body exceeds size limit", //nolint:gosec // structured logging
				"limit_bytes", int64(maxResultBodyBytes),
				"remote", r.RemoteAddr,
			)
			http.Error(w, `{"error":"result body exceeds size limit"}`, http.StatusRequestEntityTooLarge)
			return
		}
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
		s.recordWorkerError(ctx, w, &req)
		return
	}

	// Parse cleave result once — used for both storage and explosion.
	parsed := hopper.ParseCleaveResult(req.SHA256, req.Raw)
	if parsed.RootSHA != "" && parsed.RootSHA != req.SHA256 {
		claimedPath := s.tracker.release(req.SHA256)
		s.tracker.recordResult(req.Worker, true)
		s.progress.recordErrorf(1, "identity", "result root sha mismatch: claimed %s reported %s", req.SHA256, parsed.RootSHA)
		//nolint:gosec // G706: worker is validated; both shas are hex-checked
		slog.Warn("result rejected: cleave root sha mismatch",
			"worker", req.Worker, "claimed_sha256", req.SHA256,
			"reported_sha256", parsed.RootSHA, "path", claimedPath)
		writeJSONError(w, http.StatusUnprocessableEntity, `{"error":"cleave result root sha256 does not match claimed sample"}`)
		return
	}

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

	// Store the parent's cleave/litmus/llm analysis and, for an archive, all its
	// members in one atomic transaction (StoreResult). This runs under ctx, which
	// is detached from the client request (context.WithoutCancel above) with its
	// own timeout, so a worker disconnect can't abort a partially-applied store.
	// Replaces the former "truncate now, recreate members later via a best-effort
	// async pool" path, whose silent member loss produced truncated parents with
	// no members (no content, permanent data loss).
	stats, err := retryDBAccess(ctx, "store result", req.SHA256, func(ctx context.Context) (hopper.StoreStats, error) {
		return s.db.StoreResult(ctx, req.SHA256, req.Raw, req.ML, req.LLM, &parsed, tv)
	})
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			claimedPath := s.tracker.release(req.SHA256)
			s.tracker.recordResult(req.Worker, false)
			// The row can disappear after a claim when a concurrent authoritative
			// walk reconciles a moved/deleted file. The worker completed valid work,
			// but there is no longer a record to update; acknowledge it so the client
			// does not retry the same permanent no-op.
			//nolint:gosec // G706: worker is validated; sha256 is hex-checked, path from the DB
			slog.Info("discarded stale result for absent sample",
				"worker", req.Worker, "sha256", req.SHA256, "path", claimedPath)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "stored": false}) //nolint:errcheck,errchkjson // best-effort response
			return
		}
		logResultStoreError(r.Context(), ctx, "store result failed after accepting worker result", req.SHA256, err)
		// Drop the claim and bump errors so the worker's slot frees up — without
		// this, the worker's ActiveClaims is permanently inflated for this job.
		s.tracker.release(req.SHA256)
		s.tracker.recordResult(req.Worker, true)
		s.progress.recordErrorf(1, "store", "store result: %s: %v", req.SHA256, err)
		errMsg := `{"error":"store result failed"}`
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			errMsg = `{"error":"store result failed: database write context was canceled or timed out"}`
		}
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	s.progress.analyzed.Add(1)
	if stats.Members > 0 {
		s.progress.exploded.Add(stats.MembersStored)
		s.progress.queued.Add(stats.MembersStored)
		s.progress.analyzed.Add(stats.MembersStored)
		//nolint:gosec // sha256 validated by validSHA256; counts are ints
		slog.Info("stored archive members atomically",
			"sha256", req.SHA256, "members", stats.Members, "stored", stats.MembersStored)
	}
	claimedPath := s.tracker.release(req.SHA256)
	s.tracker.recordResult(req.Worker, false)

	//nolint:gosec // worker sanitized by validWorkerName, sha256 by validSHA256, path from in-memory claim
	slog.Info("result stored", "worker", req.Worker, "sha256", req.SHA256, "path", claimedPath,
		"duration_ms", req.DurationMs, "active_claims", s.tracker.activeClaims(req.Worker))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck,errchkjson // best-effort response
}

// claimJobs walks the priority tiers (interactive uploads → forced
// rescans → unanalyzed backlog → path-prefix rescans → stale traits) in
// order, fetching candidate batches from the DB and claiming the first
// count that aren't held by another worker. Over-fetches so that
// contention with other concurrent pollers doesn't starve a requester at
// the head of the queue.
func (s *apiServer) claimJobs(
	ctx context.Context, worker string, count int, tools *workerToolSet, maxBytes int64, slots int,
) ([]hopper.ClaimJob, error) {
	want := count
	overfetch := max(count*candidateOverfetch, minCandidates)

	// Tier U: interactive uploads (Source="upload"). Drained ahead of
	// every other tier so a user staring at the /file/<sha> page gets
	// their result as fast as a worker can produce it.
	cands, err := s.db.UploadCandidates(ctx, overfetch)
	if err != nil {
		return nil, err
	}
	cands = filterCandidates(cands, tools, maxBytes, slots)
	out := s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)
	if len(out) >= count {
		return out, nil
	}

	// Tier 0: operator-initiated rescans (RequestRescan). Drained before
	// the unanalyzed backlog so a user-requested re-queue jumps the line
	// instead of waiting for its SHA prefix to come up in the Tier 1
	// random-pivot rotation.
	want = count - len(out)
	cands, err = s.db.ForcedRescanCandidates(ctx, s.hopperStart, overfetch)
	if err != nil {
		return out, err
	}
	cands = filterCandidates(cands, tools, maxBytes, slots)
	out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
	if len(out) >= count {
		return out, nil
	}

	// Tier B: big archives (multi-GB ISOs) for capable workers only. Rare and
	// large, a big archive seldom falls inside a busy worker's small random-pivot
	// poll window (Tier 1), so without a dedicated lookup it would be claimed
	// almost only by large startup polls and could sit unscanned for a long time.
	// A capable worker drains any pending one up front, regardless of poll size;
	// the slot gate keeps big archives off small workers they would monopolize.
	if slots >= bigArchiveMinSlots {
		want = count - len(out)
		cands, err = s.db.BigArchiveCandidates(ctx, bigArchiveBytes, s.hopperStart, want*candidateOverfetch)
		if err != nil {
			return out, err
		}
		cands = filterCandidates(cands, tools, maxBytes, slots)
		out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
		if len(out) >= count {
			return out, nil
		}
	}

	// Tier 1: the main unanalyzed-samples queue. Candidates arrive in random
	// SHA order (pivot scan), so interleaving size classes loses nothing and
	// guarantees every batch mixes small and large work — the other tiers keep
	// their deliberate orderings (upload FIFO, operator FIFO, staleness).
	want = count - len(out)
	cands, err = s.db.UnanalyzedCandidates(ctx, s.hopperStart, want*candidateOverfetch)
	if err != nil {
		return out, err
	}
	cands = interleaveBySizeClass(filterCandidates(cands, tools, maxBytes, slots))
	out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
	if len(out) >= count {
		return out, nil
	}

	// Tier 1b: repair jobs flagged via the rescan column (e.g. archives left
	// memberless by the former async explosion — re-analysis regenerates members
	// atomically via StoreResult). Drained after the unanalyzed backlog so bulk
	// repair never starves fresh ingestion, but ahead of path-prefix and
	// stale-traits rescans.
	want = count - len(out)
	cands, err = s.db.RepairCandidates(ctx, want*candidateOverfetch)
	if err != nil {
		return out, err
	}
	cands = filterCandidates(cands, tools, maxBytes, slots)
	out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
	if len(out) >= count {
		return out, nil
	}

	if len(s.forceRescanPrefixes) > 0 {
		want = count - len(out)
		cands, err = s.db.ForceRescanCandidates(ctx, s.hopperStart, s.forceRescanPrefixes, want*candidateOverfetch)
		if err != nil {
			return out, err
		}
		cands = filterCandidates(cands, tools, maxBytes, slots)
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
		cands = filterCandidates(cands, tools, maxBytes, slots)
		out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
	}
	return out, nil
}

// permanentPGError reports whether err is a deterministic PostgreSQL error
// that cannot succeed on retry, so retryDBAccess should surface it immediately
// instead of looping. It matches the SQLSTATE class (first two characters):
//
//	22 — data exception (e.g. 22021 invalid byte sequence: a NUL byte in text)
//	23 — integrity constraint violation
//	42 — syntax error or access rule violation (a programming bug)
//
// Transient classes (08 connection, 40 serialization/deadlock, 53 insufficient
// resources, 57 operator intervention, …) are deliberately excluded so they
// keep retrying. Without this, a single malformed archive member triggered a
// retry storm of thousands of attempts against SQLSTATE 22021.
func permanentPGError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || len(pgErr.Code) < 2 {
		return false
	}
	switch pgErr.Code[:2] {
	case "22", "23", "42":
		return true
	default:
		return false
	}
}

// insertFailCause classifies why a sample insert failed so the failure metric
// can tell a database under lock contention (the silent ingestion outage of
// 2026-06-14) apart from malformed input or a dropped connection. The set is
// small and fixed so the "cause" metric label stays low-cardinality.
type insertFailCause int

const (
	causeOther            insertFailCause = iota // unclassified
	causeLockTimeout                             // 55P03 lock_not_available (lock_timeout fired) or SQLite busy/locked
	causeStatementTimeout                        // 57014 query_canceled (statement_timeout fired)
	causeSerialization                           // 40001 serialization_failure
	causeDeadlock                                // 40P01 deadlock_detected
	causeConstraint                              // class 23 integrity constraint violation
	causeData                                    // class 22 data exception (e.g. bad encoding)
	causeConnection                              // class 08 connection exception
	causeContext                                 // context deadline exceeded or cancellation
	numInsertFailCauses
)

// String is the value used for the metric's "cause" label.
func (c insertFailCause) String() string {
	switch c {
	case causeLockTimeout:
		return "lock_timeout"
	case causeStatementTimeout:
		return "statement_timeout"
	case causeSerialization:
		return "serialization"
	case causeDeadlock:
		return "deadlock"
	case causeConstraint:
		return "constraint"
	case causeData:
		return "data"
	case causeConnection:
		return "connection"
	case causeContext:
		return "context"
	default:
		return "other"
	}
}

// classifyInsertFailure maps an insert error to a cause. It checks context
// errors first (they wrap the driver error during a timeout), then the
// PostgreSQL SQLSTATE, then the SQLite contention strings so one classifier
// covers both backends.
func classifyInsertFailure(err error) insertFailCause {
	switch {
	case err == nil:
		return causeOther
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return causeContext
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "55P03":
			return causeLockTimeout
		case "57014":
			return causeStatementTimeout
		case "40001":
			return causeSerialization
		case "40P01":
			return causeDeadlock
		}
		if len(pgErr.Code) >= 2 {
			switch pgErr.Code[:2] {
			case "23":
				return causeConstraint
			case "22":
				return causeData
			case "08":
				return causeConnection
			}
		}
		return causeOther
	}
	// SQLite (dev/test) surfaces lock contention as a message, not a code.
	if msg := err.Error(); strings.Contains(msg, "database is locked") || strings.Contains(msg, "table is locked") {
		return causeLockTimeout
	}
	return causeOther
}

func retryDBAccessNoValue(ctx context.Context, op, shaHex string, fn func(context.Context) error) error {
	_, err := retryDBAccess(ctx, op, shaHex, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, fn(ctx)
	})
	return err
}

func retryDBAccess[T any](ctx context.Context, op, shaHex string, fn func(context.Context) (T, error)) (T, error) {
	return retry.DoWithData(
		func() (T, error) {
			v, err := fn(ctx)
			if err == nil {
				return v, nil
			}
			if ctx.Err() != nil ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, hopper.ErrNotFound) ||
				permanentPGError(err) {
				return v, retry.Unrecoverable(err)
			}
			return v, err
		},
		retry.Context(ctx),
		retry.Attempts(dbRetryAttempts),
		retry.Delay(dbRetryInitial),
		retry.MaxDelay(dbRetryMax),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.LastErrorOnly(true),
		retry.WrapContextErrorWithLastError(true),
		retry.OnRetry(func(attempt uint, err error) {
			slog.Warn("database operation failed; retrying",
				"op", op, "sha256", shaHex, "attempt", attempt+1, "error", err)
		}),
	)
}

func logResultStoreError(reqCtx, storeCtx context.Context, msg, shaHex string, err error) {
	attrs := []any{"sha256", shaHex, "error", err}
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

// uploadResponse is the JSON body returned by POST /api/upload.
// uploadResponse answers /api/upload. ProvenanceApplied separates the two things
// an upload can accomplish — storing bytes and refreshing metadata — so a
// producer can tell a sidecar that landed from one that did not. Without it a
// re-send of known bytes and a genuine first store are indistinguishable 200s.
type uploadResponse struct {
	SHA256            string `json:"sha256"`
	AlreadyAnalyzed   bool   `json:"already_analyzed"`
	ProvenanceApplied bool   `json:"provenance_applied"`
	Size              int64  `json:"size"`
}

// sanitizeUploadFilename returns a safe on-disk filename component, or ""
// if nothing usable survives. Hardening, in order:
//
//   - filepath.Base strips any directory prefix (defence in depth; clients
//     shouldn't send one).
//   - Path separators, NULs, and control chars are dropped.
//   - Whitespace runs collapse to single spaces, then outer space is trimmed.
//   - Pure-dot strings (".", "..", "...") are rejected — they're either
//     traversal attempts or filesystem-special names.
//   - Trailing dots and spaces are trimmed (Windows strips them silently,
//     so "evil.exe." would resolve to "evil.exe" on a Windows analyst box).
//   - Reserved Windows device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) are
//     replaced with the sha-derived placeholder by returning "" — the
//     caller substitutes.
//   - Truncated to uploadFilenameMax bytes on a UTF-8-safe boundary so the
//     on-disk name is always well-formed UTF-8.
func sanitizeUploadFilename(raw string) string {
	raw = filepath.Base(raw)
	if raw == "." || raw == ".." || raw == "/" || raw == `\` {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	prevSpace := false
	for _, r := range raw {
		switch {
		case r == utf8.RuneError:
			continue
		case r == '/' || r == '\\' || r == 0:
			continue
		case unicode.IsSpace(r):
			// Whitespace check comes before the generic control-char filter
			// so tab/CR/LF collapse to a single space rather than vanishing,
			// which would silently glue separate words together.
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
			prevSpace = false
		}
	}
	// Strip trailing dots and spaces — Windows ignores them, which lets a
	// crafted "evil.exe." appear as "evil.exe" once the corpus is moved.
	out := strings.TrimRight(strings.TrimSpace(b.String()), ". ")
	if out == "" {
		return ""
	}
	// Any all-dots survivor is suspicious; reject.
	if strings.Trim(out, ".") == "" {
		return ""
	}
	// Reserved Windows device name (case-insensitive, with or without extension).
	if pkgparse.ReservedDeviceName(out) {
		return ""
	}
	if len(out) > uploadFilenameMax {
		// Preserve extension if possible so file-type detection still works.
		ext := filepath.Ext(out)
		var cut int
		if ext != "" && len(ext) < 16 {
			cut = uploadFilenameMax - len(ext)
		} else {
			cut = uploadFilenameMax
			ext = ""
		}
		// Round cut DOWN to a UTF-8 rune boundary so we never split a
		// multi-byte rune. utf8.RuneStart is true at boundary bytes.
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut] + ext
	}
	return out
}

// writeJSONError emits a JSON error body with the correct Content-Type and
// no-store cache directives. The stdlib http.Error otherwise overrides
// Content-Type to text/plain, and leaves caching to intermediary defaults.
func writeJSONError(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	// gosec G705: not an XSS vector — Content-Type is application/json with
	// X-Content-Type-Options: nosniff (set above), so the body is never
	// interpreted as HTML; the only interpolated values are JSON-escaped.
	_, _ = io.WriteString(w, body) //nolint:errcheck,gosec // best-effort response; see above
}

// recoverMiddleware turns a handler panic into a logged 500 rather than an
// abrupt connection drop. Without it a panic unwinds to net/http's
// per-connection recover, which writes a raw stack to the server's default
// logger (not slog) and closes the socket mid-response — surfacing to the
// client as a truncated read / "connection reset" with no structured
// server-side record of what failed. Logging the method, path, remote, panic
// value, and stack here makes any handler panic root-causable, and is the
// outermost wrapper so it also catches panics raised inside the tracing
// middleware. ErrAbortHandler is the sanctioned "abandon this response" signal,
// so it is re-raised for net/http to swallow rather than logged as a fault.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:contextcheck // r.Context() carries the request's trace span; there is no inbound ctx param to thread
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler { //nolint:errorlint // recovered value is any; net/http compares this sentinel with ==
				panic(v)
			}
			slog.ErrorContext(r.Context(), "panic in HTTP handler",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr,
				"panic", fmt.Sprintf("%v", v), "stack", string(debug.Stack()))
			// Best-effort 500: lands only if no response bytes were written yet;
			// after a partial write the connection still drops, but now with a log.
			w.WriteHeader(http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// snippet returns a single-line, log-safe excerpt of up to limit bytes of b, with
// control characters folded to spaces and a trailing ellipsis when truncated.
// Used to surface a malformed payload in a log line without dumping the whole
// body or smearing it across multiple lines.
func snippet(b []byte, limit int) string {
	truncated := len(b) > limit
	if truncated {
		b = b[:limit]
	}
	s := strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(string(b), ""))
	if truncated {
		s += "…"
	}
	return s
}

// checkBrowserCSRF rejects requests that browser security signals identify
// as cross-origin form posts. The upload endpoint should never be hit by a
// browser-served HTML form. Anything that looks like a cross-site form submit
// is treated as hostile. Returns nil when the request passes.
func checkBrowserCSRF(r *http.Request) error {
	// Sec-Fetch-Site is set by every modern browser. "same-origin" and
	// "same-site" are normal user-driven requests from prism; "none" is a
	// user-typed URL (no upload there). "cross-site" is forbidden.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return errors.New("cross-site request blocked")
	}
	// Block obvious form-submission content types. Raw uploads are
	// application/octet-stream or unset; provenance-carrying uploads are
	// multipart/form-data sent by non-browser clients (forager and scan).
	// Multipart is deliberately not blocked because provenance uploads require
	// it; Sec-Fetch-Site remains the browser boundary. The classic CSRF-able
	// simple types below have no legitimate use on this endpoint.
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch strings.TrimSpace(strings.ToLower(ct)) {
	case "application/x-www-form-urlencoded", "text/plain":
		return errors.New("disallowed Content-Type for upload")
	}
	return nil
}

// resolveDataPath joins the relative path under dataRoot and asserts the
// cleaned result is still strictly inside dataRoot. Belt-and-braces against
// any future regression in sanitizeUploadFilename — if a "../"-shaped name
// ever survives, this catch fires before we touch the filesystem.
// filepath.Join already calls Clean, and dataRoot is cleaned+absolute at
// startup, so no re-cleaning is needed here.
func (s *apiServer) resolveDataPath(rel string) (string, error) {
	abs := filepath.Join(s.dataRoot, rel)
	if abs != s.dataRoot && !strings.HasPrefix(abs, s.dataRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes data root %q", rel, s.dataRoot)
	}
	return abs, nil
}

// handleUpload accepts a file upload from prism, a scan worker or a forager
// node, persists it under the tree its provenance routes it to (see
// uploadRelDir), and inserts a sample row tagged Source="upload" so the upload
// tier in claimJobs hands it to the next free worker. The request body IS the file (no
// multipart): keeps the streaming write zero-copy and lets prism just
// io.Copy its incoming body straight through.
//
// Query parameters:
//   - filename: optional, hint for on-disk name and DB.Filename. Sanitized
//     to a safe basename; falls back to "<sha[:16]>.bin" if missing or empty
//     after sanitization.
//
// Response: 200 OK with JSON {"sha256", "size", "already_analyzed"}.
// Idempotent — re-uploading the same content returns the existing sample,
// with already_analyzed=true if cleave_result is populated.
//
// maxKnownBatch caps the digests one /api/known request may probe. Bounds the
// query and the response, and keeps the batch well under SQLite's bound-param
// limit. A bulk producer chunks larger work into successive requests.
const maxKnownBatch = 1024

type knownRequest struct {
	SHA256 []string `json:"sha256"`
}

type knownResponse struct {
	Known []string `json:"known"`
}

// handleKnown answers "which of these digests do you already have?" with a
// single index-only lookup, so a producer can skip transferring bytes hopper
// holds. It is unauthenticated — sample existence is already visible in the web
// UI — and reads nothing but the sha256 key, making it the cheapest probe the
// store offers. The response lists only the known digests; unknown ones are
// simply absent.
func (s *apiServer) handleKnown(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	// Bound the body: maxKnownBatch 64-hex strings plus JSON framing, generously.
	var req knownRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxKnownBatch*72+1024)).Decode(&req); err != nil {
		slog.WarnContext(r.Context(), "known rejected: invalid json", "remote", r.RemoteAddr, "error", err)
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid json"}`)
		return
	}
	if len(req.SHA256) > maxKnownBatch {
		slog.WarnContext(r.Context(), "known rejected: too many digests",
			"remote", r.RemoteAddr, "count", len(req.SHA256), "max", maxKnownBatch)
		writeJSONError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(`{"error":"too many digests (max %d)"}`, maxKnownBatch))
		return
	}
	// Keep only well-formed lowercase-hex digests; a malformed entry can never
	// match and would only waste a bind slot.
	valid := req.SHA256[:0]
	for _, sha := range req.SHA256 {
		if validSHA256(sha) {
			valid = append(valid, sha)
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()
	known, err := s.db.KnownSHA256(ctx, valid)
	if err != nil {
		slog.Error("known: query failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if known == nil {
		known = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(knownResponse{Known: known}) //nolint:errcheck,errchkjson // best-effort response
}

// maxSightingsBatch caps the records one /api/sightings request may carry.
// Producers pushing a large feed snapshot (Aikido, OSV) chunk into requests of
// at most this size; the store upserts each request in its own transaction.
const maxSightingsBatch = 50000

// maxSightingBody bounds the request body. Each record is small (a source, a
// subject, an optional url + note); this leaves generous headroom per row.
const maxSightingBody = maxSightingsBatch * 1024

type sightingRequest struct {
	Source  string `json:"source"`
	Subject string `json:"subject"`
	URL     string `json:"url"`
	Note    string `json:"note"`
}

type sightingsResponse struct {
	Changed int `json:"changed"`
}

// handleSightings idempotently records external-corroboration sightings. A
// producer (gauntlet, forager, cyclotron, promoter) POSTs the citations it
// already parsed; the store upserts them and flips samples.corroborated for any
// matching sample. Re-pushing an unchanged snapshot is a cheap no-op, so a
// producer may safely re-send on every poll.
//
// Body is either a JSON array ([{source,subject,url,note},…]) for the small
// trickle, or NDJSON (one object per line, Content-Type application/x-ndjson)
// for streaming a large feed. Like /api/result and /api/rescan it is internal
// and unauthenticated; hopper-api is not publicly reachable.
//
// 200 {"changed":N}; 400 on malformed JSON; 413 when the batch exceeds
// maxSightingsBatch; 503 while the DB is still starting. Store retries up to
// sightingsAttempts times with full-jitter backoff; each attempt is capped at
// sightingsStoreTimeout.
func (s *apiServer) handleSightings(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}

	body := io.LimitReader(r.Body, maxSightingBody+1)
	var reqs []sightingRequest
	var err error
	if ndjson := strings.Contains(r.Header.Get("Content-Type"), "ndjson"); ndjson {
		reqs, err = decodeSightingsNDJSON(body)
	} else {
		err = json.NewDecoder(body).Decode(&reqs)
	}
	if err != nil {
		slog.WarnContext(r.Context(), "sightings rejected: invalid json", "remote", r.RemoteAddr, "error", err)
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid json"}`)
		return
	}
	if len(reqs) > maxSightingsBatch {
		slog.WarnContext(r.Context(), "sightings rejected: batch too large",
			"remote", r.RemoteAddr, "count", len(reqs), "max", maxSightingsBatch)
		writeJSONError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(`{"error":"too many sightings (max %d)"}`, maxSightingsBatch))
		return
	}

	sightings := make([]hopper.Sighting, len(reqs))
	for i, req := range reqs {
		subject := req.Subject
		// Normalize a sha256 subject to lowercase to match stored digests; a PURL
		// is left verbatim. AddSightings drops anything that is neither.
		if validSHA256(strings.ToLower(subject)) {
			subject = strings.ToLower(subject)
		}
		sightings[i] = hopper.Sighting{Source: req.Source, Subject: subject, URL: req.URL, Note: req.Note}
	}

	changed, err := retry.DoWithData(
		func() (int, error) {
			ctx, cancel := context.WithTimeout(r.Context(), sightingsStoreTimeout)
			defer cancel()
			n, err := s.db.AddSightings(ctx, sightings)
			if err == nil {
				return n, nil
			}
			// Client gone or a deterministic PG fault → stop. Per-attempt
			// deadline and lock timeouts stay retryable within sightingsAttempts.
			if r.Context().Err() != nil ||
				errors.Is(err, context.Canceled) ||
				permanentPGError(err) {
				return n, retry.Unrecoverable(err)
			}
			return n, err
		},
		retry.Context(r.Context()),
		retry.Attempts(sightingsAttempts),
		retry.Delay(dbRetryInitial),
		retry.MaxDelay(dbRetryMax),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.LastErrorOnly(true),
		retry.WrapContextErrorWithLastError(true),
		retry.OnRetry(func(attempt uint, err error) {
			slog.WarnContext(r.Context(), "sightings: store failed; retrying",
				"attempt", attempt+1, "error", err, "remote", r.RemoteAddr)
		}),
	)
	if err != nil {
		slog.ErrorContext(r.Context(), "sightings: store failed", "error", err, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	slog.InfoContext(r.Context(), "sightings recorded", "received", len(sightings), "changed", changed, "remote", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(sightingsResponse{Changed: changed}) //nolint:errcheck,errchkjson // best-effort response
}

// decodeSightingsNDJSON reads newline-delimited sighting objects from r. A
// json.Decoder consumes successive JSON values across newlines, so no line
// buffering is needed; blank input yields an empty slice.
func decodeSightingsNDJSON(r io.Reader) ([]sightingRequest, error) {
	dec := json.NewDecoder(r)
	var out []sightingRequest
	for {
		var one sightingRequest
		err := dec.Decode(&one)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, one)
		if len(out) > maxSightingsBatch {
			return out, nil // caller rejects; stop reading an oversized stream
		}
	}
}

//nolint:gosec // G706: structured logging of request-derived fields (remote, error); not a format string
func (s *apiServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSONError(w, http.StatusServiceUnavailable, `{"error":"starting"}`)
		return
	}
	if s.dataRoot == "" {
		writeJSONError(w, http.StatusServiceUnavailable, `{"error":"no data root configured"}`)
		return
	}

	// CSRF/browser-form guard. Cheap, rejects the most common cross-origin
	// shapes before we read any body bytes.
	if err := checkBrowserCSRF(r); err != nil {
		slog.Warn("upload rejected: csrf guard", "reason", err,
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
			"origin", r.Header.Get("Origin"), "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusForbidden, `{"error":"forbidden"}`)
		return
	}

	// Content-Length pre-check. Lets us reject oversized uploads before
	// allocating a temp file. ContentLength is -1 when unknown (chunked).
	if r.ContentLength > maxUploadEnvelopeBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, `{"error":"file too large"}`)
		return
	}
	if r.ContentLength == 0 {
		writeJSONError(w, http.StatusBadRequest, `{"error":"empty body"}`)
		return
	}

	// Slowloris defense: bound how long the body may take. Uses the
	// per-request response controller so workers downloading large samples
	// over /data/* aren't affected by a global server-level ReadTimeout.
	// SetReadDeadline returns http.ErrNotSupported when the underlying
	// ResponseWriter doesn't implement it (e.g. httptest); harmless.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadBodyTimeout)) //nolint:errcheck // optional

	// Dispatch on body shape. A multipart body carries the required, validated
	// provenance envelope (forager nodes, prism's browser form); a raw body is
	// the legacy thin-row path, retained until every uploader sends provenance.
	// A malformed Content-Type parses to an empty type and falls through to raw.
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && mediaType == "multipart/form-data" {
		s.handleUploadMultipart(w, r)
		return
	}

	slog.WarnContext(r.Context(), "upload: legacy raw body without provenance (deprecated)", "remote", r.RemoteAddr)
	body := http.MaxBytesReader(w, r.Body, maxUploadBytes)
	s.storeUpload(w, r, body, r.URL.Query().Get("filename"), nil)
}

// handleUploadMultipart handles a provenance-carrying upload: a multipart body
// with a "provenance" part (the JSON sidecar, required and validated) followed
// by a "file" part (the artifact bytes). The provenance MUST precede the file
// so it is parsed before the large stream begins. Both forager (remote, lightly
// trusted nodes) and prism (human submissions) use this path.
func (s *apiServer) handleUploadMultipart(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadEnvelopeBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		slog.WarnContext(r.Context(), "upload rejected: cannot read multipart body",
			"remote", r.RemoteAddr, "error", err, "content_type", r.Header.Get("Content-Type"))
		writeJSONError(w, http.StatusBadRequest, `{"error":"malformed multipart body"}`)
		return
	}

	var prov *hopper.Sidecar
	const maxParts = 8
	parts := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				slog.WarnContext(r.Context(), "upload rejected: envelope exceeds size limit",
					"remote", r.RemoteAddr, "limit", maxUploadEnvelopeBytes, "part", parts)
				writeJSONError(w, http.StatusRequestEntityTooLarge, `{"error":"file too large"}`)
				return
			}
			slog.WarnContext(r.Context(), "upload rejected: malformed multipart stream",
				"remote", r.RemoteAddr, "error", err, "part", parts)
			writeJSONError(w, http.StatusBadRequest, `{"error":"malformed multipart body"}`)
			return
		}
		parts++
		if parts > maxParts {
			_ = part.Close() //nolint:errcheck // best-effort
			slog.WarnContext(r.Context(), "upload rejected: too many parts",
				"remote", r.RemoteAddr, "max", maxParts)
			writeJSONError(w, http.StatusBadRequest, `{"error":"too many parts"}`)
			return
		}

		switch part.FormName() {
		case "provenance":
			// Read one byte past the cap so a part that exactly fills the limit
			// is distinguishable from one that overflows it. A bare
			// LimitReader(cap) truncates an over-cap part silently, and the
			// half-JSON that survives fails json.Unmarshal below — surfacing an
			// oversized payload as the misleading "invalid provenance json".
			buf, rerr := io.ReadAll(io.LimitReader(part, uploadProvenanceMaxBytes+1))
			_ = part.Close() //nolint:errcheck // best-effort
			if rerr != nil {
				slog.WarnContext(r.Context(), "upload rejected: provenance read failed",
					"remote", r.RemoteAddr, "error", rerr)
				writeJSONError(w, http.StatusBadRequest, `{"error":"provenance read failed"}`)
				return
			}
			if len(buf) > uploadProvenanceMaxBytes {
				slog.WarnContext(r.Context(), "upload rejected: provenance exceeds size limit",
					"remote", r.RemoteAddr, "limit", uploadProvenanceMaxBytes)
				writeJSONError(w, http.StatusRequestEntityTooLarge, `{"error":"provenance too large"}`)
				return
			}
			var sc hopper.Sidecar
			if err := json.Unmarshal(buf, &sc); err != nil {
				// The body is unparseable, so there are no fields to key on;
				// log the parse error and a bounded snippet of the raw bytes so
				// the producer's malformed payload can be reconstructed.
				slog.WarnContext(r.Context(), "upload rejected: invalid provenance json",
					"remote", r.RemoteAddr,
					"error", err,
					"bytes", len(buf),
					"snippet", snippet(buf, 512))
				writeJSONError(w, http.StatusBadRequest, `{"error":"invalid provenance json"}`)
				return
			}
			// Finalize first so an over-cap Raw is trimmed rather than rejected,
			// then validate the required core. The producer's claimed sha is
			// checked against the bytes we actually hash in storeUpload, so
			// provenance and content cannot disagree.
			sc.Finalize()
			if err := sc.Validate(); err != nil {
				slog.WarnContext(r.Context(), "upload rejected: provenance failed validation",
					"remote", r.RemoteAddr,
					"error", err,
					"sha256", sc.Artifact.SHA256,
					"collector", sc.Fetch.Collector,
					"purl", sc.Package.PURL)
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf(`{"error":%q}`, "invalid provenance: "+err.Error()))
				return
			}
			prov = &sc
		case "file":
			if prov == nil {
				slog.WarnContext(r.Context(), "upload rejected: file part precedes provenance",
					"remote", r.RemoteAddr)
				writeJSONError(w, http.StatusBadRequest, `{"error":"provenance part must precede file part"}`)
				return
			}
			// storeUpload consumes the part stream and writes the response.
			s.storeUpload(w, r, part, prov.Artifact.Filename, prov)
			return
		default:
			_ = part.Close() //nolint:errcheck // ignore unexpected parts
		}
	}
	// No file part. A provenance-only body is a backfill: attach the sidecar to a
	// sample hopper already holds the bytes for (matched by artifact.sha256),
	// without moving any bytes. A body with neither file nor provenance is a
	// malformed upload.
	if prov != nil {
		s.storeProvenanceOnly(w, r, prov)
		return
	}
	slog.WarnContext(r.Context(), "upload rejected: no file or provenance part",
		"remote", r.RemoteAddr, "parts", parts)
	writeJSONError(w, http.StatusBadRequest, `{"error":"missing file part"}`)
}

// refreshProvenance merges an incoming sidecar onto whatever the row already
// carries and writes the result, reporting whether a row matched. It is the only
// writer for a provenance refresh, because the sample upsert deliberately is not
// one: sampleConflictUpdatePG keeps a stored sidecar over an incoming one, which
// is right for the walker (a later filesystem walk carries no provenance, so
// first-write-wins protects the collector's capture-time record) and wrong for a
// producer sending a newer registry snapshot. Routing both upload shapes through
// here keeps them from disagreeing about what an accepted sidecar does.
//
// Merging preserves the original discovery wrapper — the Feed that recorded how
// the dependency was first found — while swapping the registry snapshot (see
// [hopper.Sidecar.MergeRefresh]). The read-then-write can race a concurrent
// refresh; both preserve the same prior Feed, so the worst case is a lost
// registry update recovered on the next scan, acceptable for best-effort
// provenance. The incoming sidecar was Finalized and Validated by the caller.
func (s *apiServer) refreshProvenance(ctx context.Context, prov *hopper.Sidecar) (bool, error) {
	sha := prov.Artifact.SHA256 // Validate() guarantees 64 lowercase hex
	toStore := prov
	if existingRaw, err := s.db.ProvenanceBySHA256(ctx, sha); err == nil && len(existingRaw) > 0 {
		var existing hopper.Sidecar
		if err := json.Unmarshal(existingRaw, &existing); err == nil {
			existing.MergeRefresh(prov)
			existing.Finalize()
			toStore = &existing
		} else {
			slog.WarnContext(ctx, "provenance refresh: unparseable prior sidecar; overwriting",
				"sha256", sha, "error", err)
		}
	}
	// Reuse the upload projection (provenance JSONB + scalar identity columns,
	// including purl_base); SetProvenance only reads those, never the
	// path/label/source fields, so the existing row's bytes and verdict are safe.
	return s.db.SetProvenance(ctx, uploadSample(sha, toStore.Artifact.Filename, "", toStore.Artifact.SizeBytes, toStore))
}

// storeProvenanceOnly attaches or refreshes a provenance sidecar on a sample
// hopper already holds the bytes for (e.g. a dependency re-fetched by a scan).
// No bytes move; the sample is matched by the sidecar's artifact.sha256.
//
// A digest hopper has no row for is a 404, not a 200: there is nothing to attach
// the sidecar to, so reporting success would tell the producer its metadata had
// landed when the request changed nothing. Producers negotiate with /api/known
// first, so this fires only when the row went away in between — which is worth a
// log line rather than a silent no-op.
func (s *apiServer) storeProvenanceOnly(w http.ResponseWriter, r *http.Request, prov *hopper.Sidecar) {
	sha := prov.Artifact.SHA256 // Validate() guarantees 64 lowercase hex
	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	applied, err := s.refreshProvenance(ctx, prov)
	if err != nil {
		slog.ErrorContext(r.Context(), "upload: set provenance", "sha256", sha, "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if !applied {
		slog.WarnContext(r.Context(), "provenance backfill rejected: no such sample",
			"sha256", sha, "collector", prov.Fetch.Collector, "purl", prov.Package.PURL, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusNotFound, `{"error":"unknown sample"}`)
		return
	}
	slog.InfoContext(r.Context(), "provenance set", "sha256", sha, "applied", applied)
	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck,errchkjson // best-effort response
	_ = json.NewEncoder(w).Encode(map[string]any{"sha256": sha, "provenance_backfilled": applied})
}

// storeUpload streams src to the upload tree its provenance routes it to (see
// uploadRelDir) while hashing, verifies the bytes against the provenance claim
// (when present), dedupes by sha, and upserts the sample row. prov is nil for the legacy raw
// path. When present, its scalar claims fill the descriptive columns, but the
// trust-bearing label is never taken from it — an upload arrives over a lightly
// trusted boundary, so analysis, not the producer, decides a sample's label.
//
//nolint:gosec // G703/G706: shard paths are confined to dataRoot via resolveDataPath; logging is structured
func (s *apiServer) storeUpload(w http.ResponseWriter, r *http.Request, src io.Reader, claimedName string, prov *hopper.Sidecar) {
	// Stream to a temp file under the uploads root while hashing. Temp
	// lives on the same filesystem as the final location so the post-hash
	// rename is atomic and cross-device-safe.
	tmpDir, err := s.resolveDataPath(filepath.Join(uploadDir, ".tmp"))
	if err != nil {
		slog.ErrorContext(r.Context(), "upload: resolve tmp dir", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if err := mkdirSharedAll(tmpDir); err != nil {
		slog.ErrorContext(r.Context(), "upload: mkdir tmp", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	tmpFile, err := os.CreateTemp(tmpDir, "up-*")
	if err != nil {
		slog.ErrorContext(r.Context(), "upload: create temp", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // best-effort; drops the spool copy on both the error path and after the final link

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmpFile, hasher), src)
	var syncErr error
	if copyErr == nil {
		syncErr = tmpFile.Sync()
	}
	closeErr := tmpFile.Close()
	if copyErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(copyErr, &maxErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, `{"error":"file too large"}`)
			return
		}
		// Read-deadline expiration surfaces as a net.Error with Timeout()=true.
		var netErr net.Error
		if errors.As(copyErr, &netErr) && netErr.Timeout() {
			//nolint:gosec // structured logging
			slog.WarnContext(r.Context(), "upload: body read timeout", "bytes", written, "remote", r.RemoteAddr)
			writeJSONError(w, http.StatusRequestTimeout, `{"error":"upload timeout"}`)
			return
		}
		//nolint:gosec // structured logging
		slog.WarnContext(r.Context(), "upload: stream copy failed", "error", copyErr, "bytes", written, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusBadRequest, `{"error":"upload failed"}`)
		return
	}
	if closeErr != nil {
		slog.ErrorContext(r.Context(), "upload: temp close", "error", closeErr)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if syncErr != nil {
		slog.ErrorContext(r.Context(), "upload: temp sync", "error", syncErr)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if written == 0 {
		slog.WarnContext(r.Context(), "upload rejected: empty body", "remote", r.RemoteAddr) //nolint:gosec // structured logging
		writeJSONError(w, http.StatusBadRequest, `{"error":"empty body"}`)
		return
	}

	sha := hex.EncodeToString(hasher.Sum(nil))

	// The producer's claimed sha must match the bytes we actually received, so a
	// tampered or mispaired provenance/file pair can't be stored as if matched.
	if prov != nil && prov.Artifact.SHA256 != sha {
		//nolint:gosec // structured logging
		slog.WarnContext(r.Context(), "upload: provenance sha mismatch", "claimed", prov.Artifact.SHA256, "actual", sha, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusBadRequest, `{"error":"content does not match provenance sha256"}`)
		return
	}

	filename := sanitizeUploadFilename(claimedName)
	if filename == "" {
		filename = sha[:16] + ".bin"
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	// Look up any existing row for this sha BEFORE writing the final path:
	// placeUpload keeps bytes hopper already holds exactly where they are, so
	// re-sending a known sample — under a rotating filename, or with provenance
	// that would route it elsewhere entirely — never spawns a second copy.
	existing, err := retryDBAccess(ctx, "upload sample lookup", sha, func(ctx context.Context) (*hopper.Sample, error) {
		return s.db.SampleBySHA256(ctx, sha)
	})
	if err != nil && !errors.Is(err, hopper.ErrNotFound) {
		slog.WarnContext(r.Context(), "upload: existing sample lookup", "sha256", sha, "error", err)
	}
	alreadyAnalyzed := existing != nil && len(existing.CleaveResult) > 0

	relPath, err := s.placeUpload(r.Context(), tmpPath, sha, filename, prov, existing)
	if err != nil {
		slog.ErrorContext(r.Context(), "upload: store bytes", "sha256", sha, "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	filename = filepath.Base(relPath)

	// Insert (sticky upsert; no-op on the bytes for a duplicate sha). The store
	// context is detached from r.Context() so a client disconnect during DB
	// retries doesn't orphan the on-disk file behind a missing row; matches
	// handleResult's persistence model.
	sample := uploadSample(sha, filename, relPath, written, prov)
	storeCtx, cancelStore := context.WithTimeout(context.WithoutCancel(r.Context()), uploadStoreTimeout)
	defer cancelStore()
	if err := retryDBAccessNoValue(storeCtx, "upload sample insert", sha, func(ctx context.Context) error {
		return s.db.InsertSample(ctx, sample)
	}); err != nil {
		s.progress.recordInsertFailure(1, err)
		slog.Error("upload: insert sample", "sha256", sha, "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if existing != nil && existing.Path != "" && existing.Path != relPath {
		healed, healErr := s.db.PromotePrimaryLocation(storeCtx, sha, existing.Path, relPath)
		if healErr != nil {
			slog.Error("upload: promote verified replacement location",
				"sha256", sha, "old_path", existing.Path, "new_path", relPath, "error", healErr)
		} else if healed {
			slog.Info("upload: replaced unusable canonical location with verified bytes",
				"sha256", sha, "old_path", existing.Path, "new_path", relPath)
		}
	}

	// A sidecar arriving with bytes must land the same way it would have arrived
	// alone: the upsert above keeps a stored sidecar over an incoming one, so
	// without this the producer that sent more (bytes AND metadata) would
	// accomplish less than the one that sent metadata alone, and both would be
	// answered with an identical 200.
	//
	// Unconditional, rather than skipped for rows this request created. Whether
	// the row pre-existed is not knowable here: the lookup above tolerates its
	// own failure, and a concurrent producer can insert between it and the
	// upsert. Both would report a sidecar as applied that never was — the same
	// lie in a new place, and an intermittent one that surfaces only under the DB
	// contention this path already retries through. At ~120 such uploads a day
	// the redundant write is not worth reasoning about; an observed result is.
	// Best-effort: the bytes and the row are already durable, so a failed refresh
	// is reported, not fatal.
	var provApplied bool
	if prov != nil {
		applied, refreshErr := s.refreshProvenance(storeCtx, prov)
		if refreshErr != nil {
			slog.Error("upload: refresh provenance", "sha256", sha, "error", refreshErr)
		}
		provApplied = applied
	}

	//nolint:gosec // structured logging; filename sanitized, remote is r.RemoteAddr
	slog.Info("upload accepted",
		"sha256", sha, "size", written, "filename", filename,
		"has_provenance", prov != nil, "provenance_applied", provApplied,
		"already_analyzed", alreadyAnalyzed, "remote", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(uploadResponse{ //nolint:errcheck,errchkjson // best-effort response
		SHA256:            sha,
		Size:              written,
		AlreadyAnalyzed:   alreadyAnalyzed,
		ProvenanceApplied: provApplied,
	})
}

// placeUpload publishes the spooled bytes and returns the path to record on the
// row, relative to the data root and slash-separated.
//
// Bytes hopper already holds stay exactly where they are: an upload of a known
// digest refreshes the row's provenance without laying down a second copy under
// whatever path this handler would choose today. Producers negotiate with
// /api/known before sending, so a re-send is rare — but the guarantee belongs on
// this side of the trust boundary rather than in every client, and it is what
// keeps a layout change from duplicating the corpus.
//
// The components uploadRelDir derives from producer claims are validated by
// pkgparse.SafePathSegment, and every resulting path is confined to dataRoot by
// resolveDataPath.
//
//nolint:gosec // G703: paths confined to dataRoot by resolveDataPath; see above
func (s *apiServer) placeUpload(ctx context.Context, tmpPath, sha, filename string, prov *hopper.Sidecar, existing *hopper.Sample) (string, error) {
	// Already recorded at a path whose file is still there: keep it.
	if existing != nil && existing.Path != "" {
		if abs, err := s.resolveDataPath(existing.Path); err == nil {
			if matches, matchErr := fileMatchesSHA256(abs, sha); matchErr == nil && matches {
				return existing.Path, nil
			} else if matchErr == nil {
				slog.WarnContext(ctx, "upload: existing path has wrong bytes; publishing a verified replacement location",
					"sha256", sha, "path", existing.Path)
			}
		}
	}
	// A known digest re-sent under a rotating filename must not spawn a second
	// copy, so the stored name wins over the claimed one.
	if existing != nil && existing.Filename != "" {
		if reuse := sanitizeUploadFilename(existing.Filename); reuse != "" {
			filename = reuse
		}
	}

	relDir, digestKeyed := uploadRelDir(sha, prov)
	absPath, err := s.resolveDataPath(filepath.Join(relDir, filename))
	if err != nil {
		return "", err
	}
	// filename is a sanitized basename, so the target's parent is the shard.
	absDir := filepath.Dir(absPath)
	if err := mkdirSharedAll(absDir); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", absDir, err)
	}
	claimed, err := claimSamplePath(tmpPath, absPath, sha, digestKeyed)
	if err != nil {
		return "", err
	}
	if claimed != absPath {
		slog.WarnContext(ctx, "upload: path held by another digest; stored under a qualified name",
			"sha256", sha, "dir", relDir, "filename", filepath.Base(claimed))
	}
	// Uploaded samples are immutable; force the read-only, group-readable sample
	// mode (os.CreateTemp left the spool file at 0600, owner-only).
	if err := os.Chmod(claimed, sampleFileMode); err != nil {
		slog.WarnContext(ctx, "upload: chmod sample read-only", "error", err, "path", claimed)
	}
	if err := syncUploadDir(filepath.Dir(claimed)); err != nil {
		return "", fmt.Errorf("sync upload directory: %w", err)
	}
	return filepath.ToSlash(filepath.Join(relDir, filepath.Base(claimed))), nil
}

// claimSamplePath publishes the spooled file at abs and returns the path it
// actually claimed, which differs from abs only when abs was already held by a
// different sample's bytes.
//
// It links rather than renames because a rename silently clobbers. Neither the
// coordinate tier nor the legacy shard — keyed on only sha[:4] — makes a path
// unique to one digest, so two unrelated samples sharing a filename collide, and
// a corpus is full of "index.js" and "setup.py". The clobbered sample's row
// survives the overwrite still pointing at the path, so its recorded digest no
// longer describes the bytes stored there. os.Link fails with EEXIST instead,
// making the collision observable.
//
// digestKeyed reports whether abs is derived from the full digest, in which case
// an occupant can only be this same sample's bytes and is kept as-is.
func claimSamplePath(src, abs, sha string, digestKeyed bool) (string, error) {
	err := os.Link(src, abs)
	if err == nil {
		return abs, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("link %s: %w", abs, err)
	}
	if matches, matchErr := fileMatchesSHA256(abs, sha); matchErr == nil && matches {
		return abs, nil
	} else if digestKeyed && matchErr != nil {
		return "", fmt.Errorf("verify existing digest-keyed path %s: %w", abs, matchErr)
	}
	// Foreign bytes hold the path. Qualify with our own digest, which cannot
	// collide with another sample; a second EEXIST is this sample's own earlier
	// upload landing on the same qualified name. The digest goes before the
	// extension so the file still sniffs as its own type
	// ("…/ab/cd/index.js" → "…/ab/cd/index-9f2c1a7bd004.js"); twelve hex digits
	// are far beyond collision range for the handful of samples that can share
	// one path, and keep the name inside NAME_MAX given uploadFilenameMax.
	ext := filepath.Ext(abs)
	qualified := strings.TrimSuffix(abs, ext) + "-" + sha[:12] + ext
	if err := os.Link(src, qualified); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("link %s: %w", qualified, err)
		}
		matches, matchErr := fileMatchesSHA256(qualified, sha)
		if matchErr != nil {
			return "", fmt.Errorf("verify qualified upload path %s: %w", qualified, matchErr)
		}
		if !matches {
			return "", fmt.Errorf("qualified upload path %s is occupied by different bytes", qualified)
		}
	}
	return qualified, nil
}

func syncUploadDir(name string) error {
	dir, err := os.Open(name) //nolint:gosec // caller confines upload paths to dataRoot
	if err != nil {
		return err
	}
	defer dir.Close() //nolint:errcheck // sync result is authoritative
	return dir.Sync()
}

// uploadSample builds the row for a stored upload. Source is always "upload"
// (the trust-boundary marker, distinct from a co-located forager's trusted
// "forager" direct-insert) and Label is always "unknown" — neither is taken
// from the producer. When provenance is present, its scalar claims fill the
// descriptive columns and the finalized sidecar is preserved verbatim in the
// provenance JSONB.
func uploadSample(sha, filename, relPath string, size int64, prov *hopper.Sidecar) *hopper.Sample {
	// An uploaded artifact is observed now — nothing else records when it
	// arrived, and the row is only as old as this write. mtime is what the
	// promotion queue ages against, so leaving it NULL kept every upload out of
	// promotion entirely rather than merely young: a row with no mtime never
	// satisfies the age gate, no matter how long it sits.
	now := time.Now().UTC()
	sample := &hopper.Sample{
		SHA256:      sha,
		Source:      "upload",
		Filename:    filename,
		Path:        relPath,
		Label:       "unknown",
		LabelSource: "upload",
		SizeBytes:   size,
		Mtime:       &now,
	}
	if prov != nil {
		// Capture time when the producer recorded one: a dependency fetched from a
		// registry was published before we saw it, and the age gate should measure
		// from when the bytes existed, not from when they reached us.
		if !prov.Fetch.At.IsZero() {
			at := prov.Fetch.At
			sample.Mtime = &at
		}
		if provJSON, err := json.Marshal(prov); err == nil {
			sample.Provenance = provJSON
		}
		if !prov.Fetch.At.IsZero() {
			at := prov.Fetch.At
			sample.FetchedAt = &at
		}
		sample.URL = prov.Fetch.URL
		// Where the bytes were served from. Derived rather than claimed — the
		// sidecar has no domain field — and the same eTLD+1 forager records, so
		// uploads group alongside foraged samples in the domain column. An unknown
		// origin leaves the column empty; only the path uses a placeholder.
		if domain := uploadDomain(prov.Fetch.URL); domain != unknownDomain {
			sample.Domain = domain
		}
		sample.Ecosystem = prov.Package.Ecosystem
		sample.Package = prov.Package.Name
		sample.Version = prov.Package.Version
		sample.Feed = prov.Package.Feed
		// Project the version-less PURL into the queryable column, mirroring
		// forager's direct-insert path — so an uploaded dependency is findable by
		// purl_base, not just by the PURL buried in the provenance JSONB.
		// Canonicalized first, so a purl_base is written in one spelling no matter
		// which form the (possibly older) uploading client used.
		sample.PURLBase = pkgparse.VersionlessPURL(pkgparse.CanonicalizePURL(prov.Package.PURL))
	}
	// Fill name/version gaps from the filename, mirroring the walker's
	// fillSampleProvenance: producer claims win, the parse only fills blanks.
	// Uploaded dependencies often carry a version-less PURL ("pkg:npm/pg")
	// whose release is visible only in the filename ("pg-8.23.0.tgz").
	parsedName, parsedVersion, _ := pkgparse.ParseFilename(filename)
	if sample.Package == "" {
		sample.Package = parsedName
	}
	if sample.Version == "" {
		if v := pkgparse.VersionForName(filename, sample.Package); v != "" {
			sample.Version = v
		} else {
			sample.Version = parsedVersion
		}
	}
	return sample
}

// sweepUploadTmp removes orphaned upload temp files older than uploadTmpMaxAge.
// Crashes mid-upload leave files in <dataRoot>/incoming/uploads/.tmp/up-* that
// nothing else cleans up; without this they accumulate forever.
func (s *apiServer) sweepUploadTmp() {
	if s.dataRoot == "" {
		return
	}
	tmpDir := filepath.Join(s.dataRoot, uploadDir, ".tmp")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Debug("upload tmp sweep: readdir failed", "dir", tmpDir, "error", err)
		}
		return
	}
	cutoff := time.Now().Add(-uploadTmpMaxAge)
	var removed int
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "up-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		full := filepath.Join(tmpDir, e.Name())
		if err := os.Remove(full); err == nil {
			removed++
		}
	}
	if removed > 0 {
		slog.Info("upload tmp sweep", "removed", removed, "dir", tmpDir)
	}
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
	case strings.Contains(errMsg, "Exceeded maximum"),
		strings.Contains(errMsg, "file count limit exceeded"),
		strings.Contains(errMsg, "Maximum archive depth"),
		strings.Contains(errMsg, "Maximum decode depth"),
		strings.Contains(errMsg, "potential zip bomb"),
		// Worker size-cap rejections: current workers say "exceeds per-job
		// cap", pre-spool workers said "exceeds per-job prefetch cap". Both
		// are deterministic for a given file size, so re-queuing only bounces
		// the sample between hopper and the worker until the reaper gives up.
		strings.Contains(errMsg, "exceeds per-job"):
		// Deterministic analysis-guard trips (file count, archive/decode depth,
		// total extraction size, decompression bomb). The same input always
		// blows the same guard, so re-queuing only burns worker capacity until
		// the poison reaper gives up — mark it permanently skipped now. These
		// mirror the 4xx client errors cleave's own server returns. Note the
		// transient guards ("too many active analysis tasks", "Server
		// overloaded") are deliberately excluded — those must stay retryable.
		return "oversized", true
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

// handleSample returns the stored analysis envelope for a sha256.
// GET /api/sample/{sha256}
//
// 200 is hopper.Envelope (ml / llm / raw as stored). 204 means the row exists
// but has not been analyzed yet. 404 is unknown. Parent archive envelopes are
// not reassembled — beamline wants the stored columns, fast.
func (s *apiServer) handleSample(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
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
			slog.ErrorContext(r.Context(), "sample: lookup failed",
				"sha256", sha, "error", err, "remote", r.RemoteAddr)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		}
		return
	}
	writeSampleEnvelope(w, sample)
}

// handleSampleByPURL returns the newest analyzed top-level sample for a PURL.
// GET /api/sample?purl=pkg:...
//
// This is a point lookup (SampleByPURL), not the prism feed. The feed query
// walks analyzed_at and omits cleave_result; beamline needs both a seek on
// purl_base and a full envelope (ml / llm / raw).
func (s *apiServer) handleSampleByPURL(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("purl"))
	if raw == "" {
		http.Error(w, `{"error":"missing purl"}`, http.StatusBadRequest)
		return
	}
	canon := pkgparse.CanonicalizePURL(raw)
	if len(canon) < 4 || !strings.EqualFold(canon[:4], "pkg:") {
		http.Error(w, `{"error":"not a package URL"}`, http.StatusBadRequest)
		return
	}
	base := pkgparse.VersionlessPURL(canon)
	version := pkgparse.PURLVersion(canon)

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	sample, err := s.db.SampleByPURL(ctx, base, version)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "sample: purl lookup failed",
			"purl", canon, "error", err, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	writeSampleEnvelope(w, sample)
}

func writeSampleEnvelope(w http.ResponseWriter, sample *hopper.Sample) {
	if len(sample.LitmusResult) == 0 && len(sample.CleaveResult) == 0 && len(sample.LLMResult) == 0 {
		w.Header().Set("X-Sha256", sample.SHA256)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	env := hopper.Envelope(sample)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Sha256", sample.SHA256)
	// gosec taints env and sample.SHA256 through the DB from the request's
	// purl: env is machine-generated JSON served as application/json with
	// nosniff (never interpreted as markup), and SHA256 is a stored hash.
	if _, err := w.Write(env); err != nil { //nolint:gosec // G705: JSON body, not markup; see above
		slog.Warn("write sample envelope failed", "sha256", sample.SHA256, "error", err) //nolint:gosec // G706: sha256 is a stored hash
	}
}

// handleProvenance serves the provenance sidecar a sample was ingested with, so
// a worker can apply its registry record (and a forensic reader can inspect the
// raw upstream documents) without re-fetching. GET /api/provenance/{sha256}.
// 204 when the sample exists but carries no sidecar; 404 when it is unknown. The
// sidecar is fixed for a content-addressed sha256, so the response is cacheable.
func (s *apiServer) handleProvenance(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	sha := r.PathValue("sha256")
	if !validSHA256(sha) {
		http.Error(w, `{"error":"invalid sha256"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	prov, err := s.db.ProvenanceBySHA256(ctx, sha)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		} else {
			slog.ErrorContext(r.Context(), "provenance: lookup failed",
				"sha256", sha, "error", err, "remote", r.RemoteAddr)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		}
		return
	}
	if len(prov) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The sidecar is fixed for a content-addressed sha256, so it never changes:
	// mark it immutable with a one-year max-age (HTTP's effective "forever").
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if _, err := w.Write(prov); err != nil { //nolint:gosec // prov is stored JSON served with nosniff; sha256 validated by validSHA256
		slog.Warn("write provenance failed", "sha256", sha, "error", err) //nolint:gosec // sha256 validated by validSHA256
	}
}

// rescanRequestCooldown is the minimum age of the most recent analysis before a
// manual re-queue via POST /api/rescan is accepted. It bounds re-queue storms
// for a single sample, enforced atomically in RequestRescan's UPDATE. prism
// applies a matching UI cooldown before offering its rescan button and caps the
// aggregate request rate; keep the two values in sync if either changes.
const rescanRequestCooldown = 15 * time.Minute

// handleRescan re-queues one top-level sample for re-analysis: RequestRescan
// clears its cached analysis fields so the next worker poll picks it up as Tier
// 1 (unanalyzed) work. This is the write side of prism's rescan button — prism
// reads from a replica but routes the write here so it lands on the master,
// keeping every write funneled through hopper. Like /api/result it is an
// internal, worker-facing endpoint; hopper-api is not publicly reachable.
//
// POST /api/rescan/{sha256}. 200 {"status":"queued"} on success; 409 when the
// sample is not eligible (unknown, an archive child, skipped, or analyzed
// within rescanRequestCooldown); 503 while the DB is still starting; 500 on an
// unexpected store error.
func (s *apiServer) handleRescan(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	sha := strings.ToLower(r.PathValue("sha256"))
	if !validSHA256(sha) {
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid sha256"}`)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	if err := s.db.RequestRescan(ctx, sha, rescanRequestCooldown); err != nil {
		if errors.Is(err, hopper.ErrRescanNotEligible) {
			writeJSONError(w, http.StatusConflict, `{"error":"not eligible"}`)
			return
		}
		slog.ErrorContext(r.Context(), "rescan: request failed",
			"sha256", sha, "error", err, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	slog.InfoContext(r.Context(), "rescan queued", "sha256", sha, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck,errchkjson // map[string]string is JSON-safe; best-effort response
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

// handleFile serves file content for remote workers.
// GET /api/file/{sha256}.
func (s *apiServer) handleFile(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	sha := r.PathValue("sha256")
	if !validSHA256(sha) {
		http.Error(w, `{"error":"invalid sha256"}`, http.StatusBadRequest)
		return
	}
	setDownloadDeadline(w) // bound stalled-client writes for both member and top-level serves

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	sample, err := s.db.SampleBySHA256(ctx, sha)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		} else {
			slog.ErrorContext(r.Context(), "file: sample lookup failed",
				"sha256", sha, "error", err, "remote", r.RemoteAddr)
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

	f, stat, err := s.openKnownSampleFile(ctx, sample, r.RemoteAddr)
	if err != nil {
		s.markServeMissing(ctx, sample, err)
		if errors.Is(err, errSamplePathRejected) || errors.Is(err, errSampleNotRegular) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		writeMissingSampleFile(w, err, `{"error":"sample file gone"}`)
		return
	}
	defer f.Close() //nolint:errcheck // best-effort close
	w.Header().Set("Content-Type", "application/octet-stream")
	// Content-addressed by sha256: the bytes never change, so cache forever.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

var (
	errSamplePathRejected = errors.New("sample path outside allowed directories")
	errSampleNotRegular   = errors.New("sample path is not a regular file")
)

// openKnownSampleFile opens the canonical path first. Only if that fails does
// it query the active top-level location ledger and try each distinct path in
// newest-first order. A successful fallback compare-and-swaps samples.path so
// later requests return to the one-query fast path.
func (s *apiServer) openKnownSampleFile(ctx context.Context, sample *hopper.Sample, remote string) (*os.File, os.FileInfo, error) {
	open := func(storedPath string) (*os.File, os.FileInfo, error) {
		diskPath := sampleDiskPath(s.dataRoot, filepath.FromSlash(storedPath))
		resolved, err := filepath.EvalSymlinks(diskPath)
		if err != nil {
			return nil, nil, err
		}
		allowed := false
		for _, dir := range s.allowedDirs {
			if strings.HasPrefix(resolved, dir+string(filepath.Separator)) || resolved == dir {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, nil, fmt.Errorf("%w: %s", errSamplePathRejected, resolved)
		}
		f, err := os.Open(resolved) //nolint:gosec // resolved path passed containment check above
		if err != nil {
			return nil, nil, err
		}
		stat, err := f.Stat()
		if err != nil {
			f.Close() //nolint:errcheck,gosec // abandoning the handle; the stat error is what matters
			return nil, nil, err
		}
		if !stat.Mode().IsRegular() {
			f.Close() //nolint:errcheck,gosec // abandoning a handle we will not serve from
			return nil, nil, fmt.Errorf("%w: %s", errSampleNotRegular, resolved)
		}
		return f, stat, nil
	}

	f, stat, primaryErr := open(sample.Path)
	if primaryErr == nil {
		if sample.Skip == "missing" {
			reactivated, err := s.db.ReactivatePrimaryLocation(ctx, sample.SHA256, sample.Path)
			if err != nil {
				slog.WarnContext(ctx, "recovered sample path catalog repair failed",
					"sha256", sample.SHA256, "path", sample.Path, "error", err)
			} else if reactivated {
				sample.Skip = ""
				slog.InfoContext(ctx, "sample path recovered",
					"sha256", sample.SHA256, "path", sample.Path, "remote", remote)
			}
		}
		return f, stat, nil
	}
	locations, err := s.db.TopLevelLocationsForSHA(ctx, sample.SHA256)
	if err != nil {
		slog.ErrorContext(ctx, "sample location fallback lookup failed",
			"sha256", sample.SHA256, "primary_path", sample.Path, "error", err, "remote", remote)
		return nil, nil, fmt.Errorf("lookup alternate sample locations: %w", err)
	}

	seen := map[string]struct{}{sample.Path: {}}
	paths := []string{sample.Path}
	for _, loc := range locations {
		if loc.Path == "" {
			continue
		}
		if _, ok := seen[loc.Path]; ok {
			continue
		}
		seen[loc.Path] = struct{}{}
		paths = append(paths, loc.Path)
	}

	firstTransient := error(nil)
	rejected := errors.Is(primaryErr, errSamplePathRejected)
	notRegular := errors.Is(primaryErr, errSampleNotRegular)
	if !errors.Is(primaryErr, os.ErrNotExist) && !rejected && !notRegular {
		firstTransient = primaryErr
	}
	attempts := 1
	for _, candidate := range paths[1:] {
		attempts++
		f, stat, err = open(candidate)
		if err == nil {
			healed, healErr := s.db.PromotePrimaryLocation(ctx, sample.SHA256, sample.Path, candidate)
			if healErr != nil {
				slog.WarnContext(ctx, "sample path fallback healing failed",
					"sha256", sample.SHA256, "old_path", sample.Path,
					"selected_path", candidate, "error", healErr)
			}
			slog.InfoContext(ctx, "sample path fallback succeeded",
				"sha256", sample.SHA256, "old_path", sample.Path,
				"selected_path", candidate, "candidate_count", len(paths),
				"attempts", attempts, "primary_healed", healed, "remote", remote)
			sample.Path = candidate
			return f, stat, nil
		}
		switch {
		case errors.Is(err, os.ErrNotExist):
		case errors.Is(err, errSamplePathRejected):
			rejected = true
		case errors.Is(err, errSampleNotRegular):
			notRegular = true
		case firstTransient == nil:
			firstTransient = err
		default:
			// A later transient error; the first one is the one reported.
		}
	}
	if firstTransient != nil {
		return nil, nil, firstTransient
	}
	if rejected {
		slog.WarnContext(ctx, "file request blocked: all known paths unavailable or outside allowed directories",
			"sha256", sample.SHA256, "primary_path", sample.Path,
			"candidate_count", len(paths), "remote", remote, "allowed_dirs", s.allowedDirs)
		return nil, nil, errSamplePathRejected
	}
	if notRegular {
		return nil, nil, errSampleNotRegular
	}
	return nil, nil, os.ErrNotExist
}

// isClientGone reports whether err (or the request context) indicates the
// caller disconnected rather than the server failing: a cancelled/expired
// context, or a write to a socket the peer already closed (EPIPE/ECONNRESET,
// or a closed connection). These must not count as server errors.
func isClientGone(ctx context.Context, err error) bool {
	return ctx.Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, net.ErrClosed)
}

// Retry-After hints (delta-seconds, RFC 9110 §10.2.3) carried on the download
// 503s so a client backs off a concrete amount rather than guessing. Small: on
// a healthy host these conditions clear in a beat.
const (
	retryAfterStarting  = 5 // process still warming up
	retryAfterBusy      = 2 // extraction slots free fast
	retryAfterTransient = 3 // fd exhaustion / transient I/O
)

// writeRetryable writes a 503 with a Retry-After header, so the retryable signal
// carries an explicit backoff, not just the status class.
func writeRetryable(w http.ResponseWriter, retryAfterSec int, body string) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
	http.Error(w, body, http.StatusServiceUnavailable)
}

// markServeMissing flips a top-level sample to skip='missing' when a serve
// found its bytes gone from disk (ENOENT), so selection queries that exclude
// skipped rows (promoter's candidate walks, gauntlet's cohorts) stop offering
// a file no client can download — one wasted fetch total instead of one per
// client per pass until the next reconcile walk notices the deletion (hours).
// Mirrors /api/next's claim validation: only ENOENT marks (transient I/O
// errors stay retryable), dataset-incomplete mode never marks (local disk is
// not authoritative there), and an existing skip is preserved. A vanished
// dataRoot (unmounted volume) makes every file ENOENT, so marking also
// requires the root itself to still exist. A stray mark self-heals: the
// walker clears 'missing' when it re-observes the file.
func (s *apiServer) markServeMissing(ctx context.Context, sample *hopper.Sample, err error) {
	// Member rows (parent != '') have no direct disk path — their "!!"-delimited
	// Path never resolves — so only a top-level row's ENOENT is evidence of a
	// deletion. Members are cascaded by the reconcile walk.
	if !errors.Is(err, os.ErrNotExist) || s.datasetIncomplete || sample.Skip != "" || sample.Parent != "" {
		return
	}
	if _, rerr := os.Stat(s.dataRoot); rerr != nil { //nolint:gosec // G703: dataRoot is trusted process configuration
		//nolint:gosec // G706: structured logging of trusted process configuration and DB fields
		slog.Error("data root inaccessible; not marking sample missing",
			"data_root", s.dataRoot, "sha256", sample.SHA256, "error", rerr)
		return
	}
	//nolint:gosec // sha256/path come from the DB row, not the request
	slog.Warn("sample bytes gone on disk; marking missing", "sha256", sample.SHA256, "path", sample.Path)
	if merr := s.db.SetSkip(ctx, sample.SHA256, "missing"); merr != nil {
		slog.Error("mark missing failed", "sha256", sample.SHA256, "error", merr) //nolint:gosec // structured logging
	}
}

// writeMissingSampleFile maps a failure to resolve or open a sample file whose
// DB row exists to a status the client can act on. The record asserts the file
// should be on disk, so ENOENT means it was deleted — permanent, and 410 Gone
// ("existed, now gone") is more precise than 404. Anything else — fd exhaustion
// (EMFILE) under load, a transient mount/I-O blip — is retryable → 503, so a
// caller does not permanently abandon a file that is merely briefly unreachable.
func writeMissingSampleFile(w http.ResponseWriter, err error, goneJSON string) {
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, goneJSON, http.StatusGone)
		return
	}
	writeRetryable(w, retryAfterTransient, `{"error":"temporarily unavailable"}`)
}

// downloadWriteTimeout bounds a single file-serving response. Generous enough
// for a multi-GB archive over the LAN, short enough that a stalled reader (one
// that stops draining, so the TCP send buffer fills and io.Copy blocks forever)
// is reclaimed rather than leaking its handler goroutine, buffers, and any
// extraction slot it holds.
const downloadWriteTimeout = 10 * time.Minute

// setDownloadDeadline applies downloadWriteTimeout to the response connection.
// Mirrors the per-request SetReadDeadline the upload/result handlers use; best
// effort, so httptest and non-deadline writers simply no-op.
func setDownloadDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(downloadWriteTimeout)) //nolint:errcheck // optional hardening
}

// archiveMemberMaxBytes caps a single file extracted from inside an archive.
// Members stream (sendfile for stored zip entries, a bounded decompressor for
// compressed ones), so memory per request is independent of this value — it is
// a policy ceiling, not a memory guard. The size check is pre-write against the
// member's declared size and the copy is LimitReader-bounded, so a large (or
// lying) member can't blow up RAM. Whole-file serving (/data and top-level
// /api/file) is uncapped; this only limits extract-from-archive requests.
const archiveMemberMaxBytes = 250 << 20 // 250 MiB

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
		slog.ErrorContext(ctx, "archive-member: parent lookup failed",
			"sha256", sha, "parent_sha", child.Parent, "error", err, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	innerPath := hopper.PathInsideArchive(child.Path)
	if innerPath == "" {
		// The child's stored path lacks the "!!" archive delimiter, so there is
		// no member to extract. This happens when the parent archive itself has
		// no on-disk path (e.g. a path-less direct insert): memberSamplesFromEnvelope
		// then mints members without the delimiter, and they are unservable. It
		// is a permanent condition, so return 422 (not a retryable 5xx) and log
		// it — previously this was a silent 500 that workers retried forever.
		//nolint:gosec // sha256 validated by validSHA256
		slog.Warn("archive-member unservable: child path has no archive delimiter",
			"sha256", sha, "parent_sha", child.Parent, "child_path", child.Path)
		http.Error(w, `{"error":"child has no archive-relative path"}`, http.StatusUnprocessableEntity)
		return
	}

	f, stat, err := s.openKnownSampleFile(ctx, parent, r.RemoteAddr)
	if err != nil {
		s.markServeMissing(ctx, parent, err)
		if errors.Is(err, errSamplePathRejected) {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		if errors.Is(err, errSampleNotRegular) {
			http.Error(w, `{"error":"parent not a file"}`, http.StatusUnprocessableEntity)
			return
		}
		writeMissingSampleFile(w, err, `{"error":"parent file gone"}`)
		return
	}
	defer f.Close() //nolint:errcheck // best-effort close

	// Presence probe: everything a HEAD can truthfully answer is already
	// settled — the member row exists, its path carries an archive delimiter,
	// and the parent's bytes are on disk and readable. Extracting to serve a
	// body net/http will discard would re-run a whole decompressor per probe,
	// and the triage queues that batch archive members probe far more samples
	// than they fetch. Answer here instead. Content-Length is deliberately
	// omitted: the member's extracted size isn't known without doing the work,
	// and a wrong one is worse than none.
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	// Content-addressed by sha256: the extracted member's bytes never change.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	// Compressed tars (tar.xz/tar.zst/tar.gz/tar.bz2) are not seekable, so
	// extracting member K re-runs the whole decompressor from byte 0 — O(N×M) for
	// N members of an M-byte archive. Serve them through the cache: the first
	// member decompresses the parent once (holding an extraction slot for just
	// that work), and every later member streams off the resulting seekable tar
	// with no slot contention. A disabled or over-budget cache falls through to
	// direct streaming below.
	if hopper.IsCompressedTar(parent.FileType) {
		ct, cerr := s.extractCache.readerAt(ctx, parent.SHA256, f, stat.Size(), parent.FileType)
		switch {
		case cerr == nil:
			defer ct.done()
			streamMember(ctx, w, ct.r, ct.size, "tar", innerPath, sha, parent)
			return
		case errors.Is(cerr, errCacheDisabled), errors.Is(cerr, errCacheTooLarge):
			// Fall through to direct streaming.
		case errors.Is(cerr, errSaturated):
			// The cache's heavy-build gate is the extraction-slot pool; shed fast.
			recordLoadShed(ctx, "extract")
			slog.WarnContext(ctx, "extract shed: slots saturated (cache build)",
				"sha256", sha, "parent_sha", parent.SHA256, "remote", r.RemoteAddr)
			writeRetryable(w, retryAfterBusy, `{"error":"busy: extraction slots exhausted"}`)
			return
		case errors.Is(cerr, context.Canceled), errors.Is(cerr, context.DeadlineExceeded):
			// Client gave up or the request deadline fired mid-build; nothing
			// useful to send, but answer retryable in case the socket is alive.
			writeRetryable(w, retryAfterBusy, `{"error":"busy: extraction slots exhausted"}`)
			return
		default:
			// The one-time decompression failed: a corrupt or unsupported codec
			// stream. Map it like any other extraction failure.
			writeExtractError(ctx, w, cerr, innerPath, sha, parent)
			return
		}
	}

	// Direct path: plain tar, zip, 7z, rpm, deb, or a compressed tar too large to
	// cache. Bound concurrency with an extraction slot — acquired here (not
	// earlier) so the cheap parent lookup and path checks above don't hold one
	// while blocking.
	waitStart := time.Now()
	if err := s.acquireExtract(ctx); err != nil {
		if errors.Is(err, errSaturated) {
			recordLoadShed(ctx, "extract")
			slog.WarnContext(ctx, "extract shed: slots saturated",
				"sha256", sha, "parent_sha", parent.SHA256, "remote", r.RemoteAddr)
		}
		writeRetryable(w, retryAfterBusy, `{"error":"busy: extraction slots exhausted"}`)
		return
	}
	if waited := time.Since(waitStart); waited > slotWaitLogThreshold {
		slog.WarnContext(ctx, "extraction slot wait was slow",
			"sha256", sha, "parent_sha", parent.SHA256, "waited_ms", waited.Milliseconds())
	}
	defer s.releaseExtract()

	// Stream the single member straight from disk to the socket: zip uses the
	// file as random-access (only the central directory plus the member's working
	// set are resident), stored entries copy via sendfile(2). The whole parent
	// archive — which can be multiple GB — is never read into memory.
	streamMember(ctx, w, f, stat.Size(), parent.FileType, innerPath, sha, parent)
}

// streamMember writes the member at innerPath out of the archive (src, size,
// fileType) to w, translating any extraction failure to a status code. setLen
// fires once with the leaf size just before the first byte, so a pre-write error
// leaves the response status free for writeExtractError to set.
func streamMember(ctx context.Context, w http.ResponseWriter, src io.ReaderAt, size int64, fileType, innerPath, sha string, parent *hopper.Sample) {
	err := hopper.StreamArchiveMember(src, size, fileType, innerPath, archiveMemberMaxBytes,
		func(n int64) { w.Header().Set("Content-Length", strconv.FormatInt(n, 10)) }, w)
	if err != nil {
		writeExtractError(ctx, w, err, innerPath, sha, parent)
	}
}

// writeExtractError maps an archive-extraction failure to an HTTP status and
// logs it. Shared by the cached and direct member-serving paths.
func writeExtractError(ctx context.Context, w http.ResponseWriter, err error, innerPath, sha string, parent *hopper.Sample) {
	switch {
	case errors.Is(err, hopper.ErrArchiveMemberNotFound):
		http.Error(w, `{"error":"not found in archive"}`, http.StatusNotFound)
	case errors.Is(err, hopper.ErrArchiveMemberTooLarge):
		//nolint:gosec // sha256 validated by validSHA256
		slog.Info("archive-member over size cap",
			"sha256", sha, "parent_sha", parent.SHA256, "parent_type", parent.FileType,
			"inner_path", innerPath, "cap_bytes", archiveMemberMaxBytes)
		http.Error(w, `{"error":"file too large"}`, http.StatusRequestEntityTooLarge)
	case errors.Is(err, hopper.ErrArchiveEncrypted):
		http.Error(w, `{"error":"encrypted archive: could not decrypt with known passwords"}`, http.StatusUnprocessableEntity)
	case errors.Is(err, hopper.ErrUnsupportedArchive):
		// Log the container type so the coverage gap is visible: which
		// parent/nested archive formats workers want but hopper can't serve.
		//nolint:gosec // sha256 validated by validSHA256
		slog.Info("archive-member unsupported container",
			"sha256", sha, "parent_sha", parent.SHA256, "parent_type", parent.FileType,
			"inner_path", innerPath, "error", err)
		http.Error(w, `{"error":"unsupported archive type"}`, http.StatusUnsupportedMediaType)
	case isClientGone(ctx, err):
		// The client closed the connection mid-stream (broken pipe / reset) or its
		// request context expired. Not a server fault, and bytes may already be on
		// the wire, so there is no status to set — just log it quietly so it stays
		// out of the 5xx error budget.
		//nolint:gosec // sha256 validated by validSHA256
		slog.Debug("archive-member request abandoned by client",
			"sha256", sha, "parent_sha", parent.SHA256, "error", err)
	case hopper.IsCorruptArchive(err):
		//nolint:gosec // sha256 validated by validSHA256
		slog.Info("archive-member extraction: corrupt archive",
			"sha256", sha, "parent_sha", parent.SHA256, "error", err)
		http.Error(w, `{"error":"corrupt archive"}`, http.StatusUnprocessableEntity)
	default:
		// The parent is open and readable (checked above), so a remaining
		// extraction failure is a property of the archive data — a corrupt codec
		// stream IsCorruptArchive doesn't have a typed sentinel for
		// (zstd/xz/lzma/7z/crx/rpm/deb), a truncated member, etc. Permanent, so
		// 422 (not a retryable 5xx): the client must not loop on a fundamentally
		// unextractable member. Logged at Warn because a spike here can also mean a
		// genuine new gap worth investigating.
		//nolint:gosec // sha256 validated by validSHA256
		slog.Warn("archive-member extraction failed (treated as permanent)",
			"sha256", sha, "parent_sha", parent.SHA256, "error", err)
		// Headers may already be sent if the failure was mid-stream; in that case
		// http.Error's WriteHeader is a no-op and only logs.
		http.Error(w, `{"error":"extraction failed"}`, http.StatusUnprocessableEntity)
	}
}

// stripDataRoot converts an absolute DB path to a path relative to prefix.
// DB paths may use a symlinked prefix (e.g. /srv/home/t/data → /srv/data)
// that differs from the resolved dataRoot. EvalSymlinks resolves the entire
// chain including intermediate symlinks.
func stripDataRoot(dbPath, prefix string) string {
	strip := func(abs, root string) (string, bool) {
		rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(abs))
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
		setDownloadDeadline(w) // bound stalled-client writes on /data/ downloads
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
			// /data makes no DB existence claim, so a vanished file is just 404.
			// A non-ENOENT failure (fd exhaustion under load, transient I/O) is
			// retryable (503) — don't tell a caller a present file is gone.
			if errors.Is(err, os.ErrNotExist) {
				http.NotFound(w, r)
			} else {
				writeRetryable(w, retryAfterTransient, "temporarily unavailable")
			}
			return
		}
		defer f.Close() //nolint:errcheck // best-effort close
		stat, err := f.Stat()
		if err != nil {
			writeRetryable(w, retryAfterTransient, "temporarily unavailable")
			return
		}
		if stat.IsDir() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// Content-addressed by sha256 (the path embeds the hash), so cache forever.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	})
}
