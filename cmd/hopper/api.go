package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"codeberg.org/atomdrift/hopper"
	"github.com/codeGROOVE-dev/retry"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/klauspost/compress/zstd"
)

// apiServer handles the pull-based work API. Workers poll /api/next for
// jobs, submit results via /api/result, and fetch file content from
// /api/file/{sha256}. Sample data lives in the database; per-job claim
// state lives in workerTracker (see below).
type apiServer struct {
	db       *hopper.DB
	tracker  *workerTracker
	progress *loadProgress
	// extractSem bounds in-flight archive-member extractions. Each can run a
	// decompressor and spool a multi-GB intermediate container to disk, so an
	// unbounded burst of /api/file requests for members would otherwise pile up
	// CPU and scratch space. nil disables the limit (e.g. in tests).
	extractSem chan struct{}
	// traitsVersion holds the short prefix of the current traits repo
	// commit. Stored in an atomic.Pointer so the periodic rules-update
	// goroutine can refresh it concurrently with read traffic from
	// /api/next, /api/result, and the dashboard. Empty = rescan disabled.
	traitsVersion       atomic.Pointer[string]
	hopperStart         time.Time // process start; gates force-rescan claim tier
	dataRoot            string    // resolved absolute path to the data directory
	allowedDirs         []string  // resolved absolute paths that /api/file may serve from
	forceRescanPrefixes []string  // normalized relative paths to re-analyze when analysis predates hopperStart
	rescanAge           time.Duration
	// uploadTokenHash holds sha256(HOPPER_UPLOAD_TOKEN). Storing only the
	// hash means a process-memory disclosure (core dump, /proc/<pid>/mem,
	// swap) does not leak the secret in usable form. Compare with
	// subtle.ConstantTimeCompare against sha256(incoming). uploadTokenSet
	// distinguishes "no token configured" from the 2^-256 case of a hash
	// that happens to be all-zero.
	uploadTokenHash [sha256.Size]byte
	uploadTokenSet  bool
}

// acquireExtract blocks until an archive-extraction slot is free or ctx is
// done. A nil extractSem means unlimited (tests construct apiServer directly).
func (s *apiServer) acquireExtract(ctx context.Context) error {
	if s.extractSem == nil {
		return nil
	}
	select {
	case s.extractSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseExtract returns a slot taken by acquireExtract.
func (s *apiServer) releaseExtract() {
	if s.extractSem != nil {
		<-s.extractSem
	}
}

// errUploadDisabled is the sentinel for "no HOPPER_UPLOAD_TOKEN configured".
// The auth handler dispatches on this with errors.Is to return 503 (disabled)
// rather than 401 (auth failed).
var errUploadDisabled = errors.New("upload endpoint disabled (set HOPPER_UPLOAD_TOKEN)")

// setUploadToken stores sha256(token) for later constant-time comparison.
// The plaintext is scoped to this call; once it returns, the only in-memory
// copy is the SHA-256 digest. Returns an error if the token is too short to
// meet the minimum-entropy threshold.
func (s *apiServer) setUploadToken(token string) error {
	if len(token) < uploadTokenMinLen {
		return fmt.Errorf("token must be at least %d bytes (got %d)", uploadTokenMinLen, len(token))
	}
	s.uploadTokenHash = sha256.Sum256([]byte(token))
	s.uploadTokenSet = true
	return nil
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
	path   string // for dashboard/log display; avoids a per-worker DB lookup
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
	mux.HandleFunc("GET /api/next", s.handleNext)
	mux.HandleFunc("GET /api/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /api/result", s.handleResult)
	mux.HandleFunc("POST /api/upload", s.handleUpload)
	mux.HandleFunc("GET /api/file/{sha256}", s.handleFile)
	mux.Handle("GET /data/", s.safeFileServer())
}

const (
	maxClaimCount      = 32
	claimExpiry        = 30 * time.Minute
	staleClaimAge      = 2 * time.Hour
	maxWorkerNameLen   = 64
	maxResultBodyBytes = 512 << 20 // 512 MiB — some archive cleave reports legitimately exceed 256 MiB.
	maxTrackedWorkers  = 200
	apiQueryTimeout    = 30 * time.Second
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

	// maxUploadBytes caps an interactive /api/upload body. Matches prism's
	// web upload limit so anything that gets past prism fits here too.
	maxUploadBytes = 100 << 20
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
	// roomier because a result body may reach maxResultBodyBytes (512 MiB).
	// Workers run on the local network, so even a slow-link budget is ample.
	resultBodyTimeout = 10 * time.Minute
	// uploadTokenMinLen is the smallest acceptable HOPPER_UPLOAD_TOKEN.
	// 32 chars yields >=128 bits with hex encoding, >=192 bits with base64.
	// A random `openssl rand -hex 32` produces 64 chars and meets this with
	// room to spare. Rejecting short tokens at config time keeps a typo
	// from silently degrading auth strength below the threat model.
	uploadTokenMinLen = 32
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
	// uploadDir is the directory under dataRoot where interactive uploads
	// land: <root>/unknown/uploads. Workers pick them up via the upload
	// tier in claimJobs.
	uploadDir = "unknown/uploads"
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

func workerCanAnalyzeFile(fileType, path string, tools *workerToolSet) bool {
	if tools == nil {
		return true
	}
	ft := normalizeFileType(fileType)
	if ft == "" && path == "" {
		return true
	}
	if requiresTool(ft, path, "rizin") && !(*tools)["rizin"] {
		return false
	}
	if requiresTool(ft, path, "upx") && !(*tools)["upx"] {
		return false
	}
	if requiresTool(ft, path, "innoextract") && !(*tools)["innoextract"] {
		return false
	}
	if requiresTool(ft, path, "7z") && !(*tools)["7z"] {
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

func requiresTool(fileType, path, tool string) bool {
	switch tool {
	case "rizin":
		return isNativeBinaryFileType(fileType)
	case "upx":
		return fileType == "elf" || fileType == "pe"
	case "innoextract":
		return fileType == "msi" || hasFileExtension(path, ".msi", ".msp") || fileType == "pe"
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

func hasFileExtension(path string, exts ...string) bool {
	if path == "" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
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
func (s *apiServer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	worker := r.URL.Query().Get("worker")
	if !validWorkerName(worker) {
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

	jobs, err := s.claimJobs(ctx, worker, count, toolCaps)
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

// handleResult receives an analysis result from a worker.
func (s *apiServer) handleResult(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		http.Error(w, `{"error":"starting"}`, http.StatusServiceUnavailable)
		return
	}
	// Slow-loris defense: bound how long the (up to 256 MiB) body may take to
	// arrive, mirroring handleUpload. Uses the per-request response controller
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
	path := s.tracker.release(req.SHA256)
	s.tracker.recordResult(req.Worker, false)

	//nolint:gosec // worker sanitized by validWorkerName, sha256 by validSHA256, path from in-memory claim
	slog.Info("result stored", "worker", req.Worker, "sha256", req.SHA256, "path", path,
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
func (s *apiServer) claimJobs(ctx context.Context, worker string, count int, tools *workerToolSet) ([]hopper.ClaimJob, error) {
	want := count
	overfetch := max(count*candidateOverfetch, minCandidates)

	// Tier U: interactive uploads (Source="upload"). Drained ahead of
	// every other tier so a user staring at the /file/<sha> page gets
	// their result as fast as a worker can produce it.
	cands, err := s.db.UploadCandidates(ctx, overfetch)
	if err != nil {
		return nil, err
	}
	cands = filterCandidatesByWorkerTools(cands, tools)
	out := s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)
	if len(out) >= count {
		return out, nil
	}

	// Tier 0: operator-initiated rescans (RequestRescan). Drained before
	// the unanalyzed backlog so a user-requested re-queue jumps the line
	// instead of waiting for its SHA prefix to come up in the Tier 1
	// random-pivot rotation.
	want = count - len(out)
	cands, err = s.db.ForcedRescanCandidates(ctx, overfetch)
	if err != nil {
		return out, err
	}
	cands = filterCandidatesByWorkerTools(cands, tools)
	out = append(out, s.tracker.tryClaimBatch(cands, worker, claimExpiry, want)...)
	if len(out) >= count {
		return out, nil
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
	cands = interleaveBySizeClass(filterCandidatesByWorkerTools(cands, tools))
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
	cands = filterCandidatesByWorkerTools(cands, tools)
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
		cands = filterCandidatesByWorkerTools(cands, tools)
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
		cands = filterCandidatesByWorkerTools(cands, tools)
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
type uploadResponse struct {
	SHA256          string `json:"sha256"`
	AlreadyAnalyzed bool   `json:"already_analyzed"`
	Size            int64  `json:"size"`
}

// reservedWindowsNames are device names that Windows treats specially in any
// directory, with or without an extension. We never want to write a file
// whose stem matches one of these — even on Linux deployments, the corpus
// occasionally gets rsync'd onto Windows analyst boxes.
var reservedWindowsNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com1": {}, "com2": {}, "com3": {}, "com4": {}, "com5": {},
	"com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {}, "lpt5": {},
	"lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
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
	stem := strings.ToLower(out)
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if _, bad := reservedWindowsNames[stem]; bad {
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
	_, _ = io.WriteString(w, body) //nolint:errcheck // best-effort response
}

// checkUploadAuth validates the bearer token on /api/upload. Both sides
// are hashed to a fixed 32-byte digest before comparison so:
//
//   - subtle.ConstantTimeCompare runs over constant-length inputs — it
//     would otherwise short-circuit on length mismatch and leak the server
//     token's length via response timing.
//   - The plaintext token never sits in long-lived process memory; only
//     its SHA-256 does. A core dump or /proc/<pid>/mem read by a
//     post-compromise adversary still finds the hash, not the secret.
//
// Returns errUploadDisabled when no token is configured (the handler
// translates that to 503); any other error becomes 401. The HTTP response
// body is the same in either case — the distinction is for logging.
func (s *apiServer) checkUploadAuth(r *http.Request) error {
	if !s.uploadTokenSet {
		return errUploadDisabled
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return errors.New("missing or malformed Authorization header")
	}
	got := sha256.Sum256([]byte(auth[len(prefix):]))
	if subtle.ConstantTimeCompare(got[:], s.uploadTokenHash[:]) != 1 {
		return errors.New("invalid token")
	}
	return nil
}

// checkBrowserCSRF rejects requests that browser security signals identify
// as cross-origin form posts. The upload endpoint should never be hit by a
// browser-served HTML form: prism uploads with an explicit fetch(),
// command-line clients send Authorization headers. Anything that looks
// like a cross-site form submit is treated as hostile. Returns nil when
// the request passes.
func checkBrowserCSRF(r *http.Request) error {
	// Sec-Fetch-Site is set by every modern browser. "same-origin" and
	// "same-site" are normal user-driven requests from prism; "none" is a
	// user-typed URL (no upload there). "cross-site" is forbidden.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return errors.New("cross-site request blocked")
	}
	// Block obvious form-submission content types. Raw uploads are
	// application/octet-stream or unset; browsers can only set those via
	// fetch(), which triggers a preflight (and the server doesn't answer
	// preflights, so it's already blocked). Browser-issued <form> submits
	// land here with one of the three CORS "simple" types below.
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch strings.TrimSpace(strings.ToLower(ct)) {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
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

// handleUpload accepts an interactive file upload from prism, persists it
// under <dataRoot>/unknown/uploads/<aa>/<bb>/<filename>, and inserts a
// sample row tagged Source="upload" so the upload tier in claimJobs hands
// it to the next free worker. The request body IS the file (no
// multipart): keeps the streaming write zero-copy and lets prism just
// io.Copy its incoming body straight through.
//
// Auth: requires "Authorization: Bearer <HOPPER_UPLOAD_TOKEN>". When the
// env var is unset the route is disabled (returns 503) — fail-closed.
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
//nolint:gosec,maintidx // paths confined to dataRoot via resolveDataPath; linear hardening flow
func (s *apiServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSONError(w, http.StatusServiceUnavailable, `{"error":"starting"}`)
		return
	}
	if s.dataRoot == "" {
		writeJSONError(w, http.StatusServiceUnavailable, `{"error":"no data root configured"}`)
		return
	}

	// Auth first — every later step touches disk or DB.
	if err := s.checkUploadAuth(r); err != nil {
		slog.Warn("upload rejected: auth", "reason", err, "remote", r.RemoteAddr)
		if errors.Is(err, errUploadDisabled) {
			writeJSONError(w, http.StatusServiceUnavailable, `{"error":"upload disabled"}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="hopper"`)
		writeJSONError(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
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
	if r.ContentLength > maxUploadBytes {
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

	rawName := r.URL.Query().Get("filename")
	filename := sanitizeUploadFilename(rawName)

	// Stream to a temp file under the uploads root while hashing. Temp
	// lives on the same filesystem as the final location so the post-hash
	// rename is atomic and cross-device-safe.
	tmpDir, err := s.resolveDataPath(filepath.Join(uploadDir, ".tmp"))
	if err != nil {
		slog.Error("upload: resolve tmp dir", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if err := mkdirSharedAll(tmpDir); err != nil {
		slog.Error("upload: mkdir tmp", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	tmpFile, err := os.CreateTemp(tmpDir, "up-*")
	if err != nil {
		slog.Error("upload: create temp", "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // best-effort; succeeds on error path, no-op after rename

	body := http.MaxBytesReader(w, r.Body, maxUploadBytes)
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmpFile, hasher), body)
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
			slog.Warn("upload: body read timeout", "bytes", written, "remote", r.RemoteAddr)
			writeJSONError(w, http.StatusRequestTimeout, `{"error":"upload timeout"}`)
			return
		}
		//nolint:gosec // structured logging
		slog.Warn("upload: stream copy failed", "error", copyErr, "bytes", written, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusBadRequest, `{"error":"upload failed"}`)
		return
	}
	if closeErr != nil {
		slog.Error("upload: temp close", "error", closeErr)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	if written == 0 {
		writeJSONError(w, http.StatusBadRequest, `{"error":"empty body"}`)
		return
	}

	sha := hex.EncodeToString(hasher.Sum(nil))
	if filename == "" {
		filename = sha[:16] + ".bin"
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	// Look up any existing row for this sha BEFORE writing the final path.
	// If we already have this sample, reuse its on-disk filename rather
	// than spawning a second copy under a new shard path — otherwise an
	// attacker re-uploading the same bytes with a rotating filename query
	// param fills the disk despite the sha-level dedupe.
	existing, err := retryDBAccess(ctx, "upload sample lookup", sha, func(ctx context.Context) (*hopper.Sample, error) {
		return s.db.SampleBySHA256(ctx, sha)
	})
	if err != nil && !errors.Is(err, hopper.ErrNotFound) {
		slog.Warn("upload: existing sample lookup", "sha256", sha, "error", err)
	}
	alreadyAnalyzed := existing != nil && len(existing.CleaveResult) > 0

	// Final location: unknown/uploads/<aa>/<bb>/<filename>. When the sha is
	// already known, reuse the stored filename so we land at the same path
	// instead of creating a duplicate.
	if existing != nil && existing.Filename != "" {
		if reuse := sanitizeUploadFilename(existing.Filename); reuse != "" {
			filename = reuse
		}
	}
	relDir := filepath.Join(uploadDir, sha[:2], sha[2:4])
	relPath := filepath.Join(relDir, filename)
	absDir, err := s.resolveDataPath(relDir)
	if err != nil {
		slog.Error("upload: shard path escapes data root", "rel", relDir, "error", err)
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid filename"}`)
		return
	}
	absPath, err := s.resolveDataPath(relPath)
	if err != nil {
		slog.Error("upload: target path escapes data root", "rel", relPath, "error", err)
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid filename"}`)
		return
	}
	if err := mkdirSharedAll(absDir); err != nil {
		slog.Error("upload: mkdir shard", "error", err, "dir", absDir)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	// Idempotent: if the file already exists for this sha, Rename atomically
	// replaces it. Same content, same sha — bytes are identical.
	if err := os.Rename(tmpPath, absPath); err != nil {
		slog.Error("upload: rename", "error", err, "from", tmpPath, "to", absPath)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	// Uploaded samples are immutable; force the read-only, group-readable sample
	// mode (os.CreateTemp left the temp file at 0600, owner-only).
	if err := os.Chmod(absPath, sampleFileMode); err != nil {
		slog.Warn("upload: chmod sample read-only", "error", err, "path", absPath)
	}

	// Insert (no-op if duplicate sha). Path uses forward slashes — hopper
	// stores POSIX-style paths even on Windows, matching every other
	// ingest source. The store context is detached from r.Context() so a
	// client disconnect during DB retries doesn't orphan the on-disk file
	// behind a missing row; matches handleResult's persistence model.
	storeCtx, cancelStore := context.WithTimeout(context.WithoutCancel(r.Context()), uploadStoreTimeout)
	defer cancelStore()
	if err := retryDBAccessNoValue(storeCtx, "upload sample insert", sha, func(ctx context.Context) error {
		return s.db.InsertSample(ctx, &hopper.Sample{
			SHA256:      sha,
			Source:      "upload",
			Filename:    filename,
			Path:        filepath.ToSlash(relPath),
			Label:       "unknown",
			LabelSource: "upload",
			SizeBytes:   written,
		})
	}); err != nil {
		s.progress.recordInsertFailure(1, err)
		slog.Error("upload: insert sample", "sha256", sha, "error", err)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}

	//nolint:gosec // structured logging; filename sanitized, remote is r.RemoteAddr
	slog.Info("upload accepted",
		"sha256", sha, "size", written, "filename", filename,
		"already_analyzed", alreadyAnalyzed, "remote", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(uploadResponse{ //nolint:errcheck,errchkjson // best-effort response
		SHA256:          sha,
		Size:            written,
		AlreadyAnalyzed: alreadyAnalyzed,
	})
}

// sweepUploadTmp removes orphaned upload temp files older than uploadTmpMaxAge.
// Crashes mid-upload leave files in <dataRoot>/unknown/uploads/.tmp/up-* that
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
		path := filepath.Join(tmpDir, e.Name())
		if err := os.Remove(path); err == nil {
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
		writeMissingSampleFile(w, err, `{"error":"sample file gone"}`)
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
		writeMissingSampleFile(w, err, `{"error":"sample file gone"}`)
		return
	}
	defer f.Close() //nolint:errcheck // best-effort close
	stat, err := f.Stat()
	if err != nil {
		writeMissingSampleFile(w, err, `{"error":"sample file gone"}`)
		return
	}
	if stat.IsDir() {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
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

	diskPath := sampleDiskPath(s.dataRoot, filepath.FromSlash(parent.Path))
	resolved, err := filepath.EvalSymlinks(diskPath)
	if err != nil {
		writeMissingSampleFile(w, err, `{"error":"parent file gone"}`)
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

	f, err := os.Open(resolved) //nolint:gosec // path validated above
	if err != nil {
		writeMissingSampleFile(w, err, `{"error":"parent file gone"}`)
		return
	}
	defer f.Close() //nolint:errcheck // best-effort close
	stat, err := f.Stat()
	if err != nil {
		writeMissingSampleFile(w, err, `{"error":"parent file gone"}`)
		return
	}
	if stat.IsDir() {
		http.Error(w, `{"error":"parent not a file"}`, http.StatusUnprocessableEntity)
		return
	}

	// Bound concurrent extractions: a burst of member requests could otherwise
	// run many decompressors and spool many intermediate archives to disk at
	// once. Acquired here (not earlier) so the cheap parent lookup and path
	// checks above don't hold a slot while blocking.
	if err := s.acquireExtract(ctx); err != nil {
		writeRetryable(w, retryAfterBusy, `{"error":"busy: extraction slots exhausted"}`)
		return
	}
	defer s.releaseExtract()

	// Stream the single member straight from disk to the socket: zip uses the
	// file as random-access (only the central directory plus the member's
	// working set are resident), stored entries copy via sendfile(2). The whole
	// parent archive — which can be multiple GB — is never read into memory.
	// setLen sets Content-Length just before the first byte; on a pre-write
	// error nothing has been written so the status code below is still honoured.
	w.Header().Set("Content-Type", "application/octet-stream")
	err = hopper.StreamArchiveMember(f, stat.Size(), parent.FileType, innerPath, archiveMemberMaxBytes,
		func(n int64) { w.Header().Set("Content-Length", strconv.FormatInt(n, 10)) }, w)
	if err != nil {
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
			// The client closed the connection mid-stream (broken pipe / reset)
			// or its request context expired. Not a server fault, and bytes may
			// already be on the wire, so there is no status to set — just log it
			// quietly so it stays out of the 5xx error budget.
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
			// extraction failure is a property of the archive data — a corrupt
			// codec stream IsCorruptArchive doesn't have a typed sentinel for
			// (zstd/xz/lzma/7z/crx/rpm/deb), a truncated member, etc. Permanent,
			// so 422 (not a retryable 5xx): the client must not loop on a
			// fundamentally unextractable member. Logged at Warn because a spike
			// here can also mean a genuine new gap worth investigating.
			//nolint:gosec // sha256 validated by validSHA256
			slog.Warn("archive-member extraction failed (treated as permanent)",
				"sha256", sha, "parent_sha", parent.SHA256, "error", err)
			// Headers may already be sent if the failure was mid-stream; in that
			// case http.Error's WriteHeader is a no-op and only logs.
			http.Error(w, `{"error":"extraction failed"}`, http.StatusUnprocessableEntity)
		}
		return
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
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	})
}
