package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeGROOVE-dev/retry"
)

// defaultRemoteLitmusPort is appended to --litmus-nodes entries that omit a
// port. Matches the default that `litmus serve` binds to.
const defaultRemoteLitmusPort = "49999"

// analyzer is anything that can run a single litmus analysis. Both the local
// litmus subprocess (*litmusServer) and remote litmus HTTP servers
// (*remoteLitmus) implement this. The slot loop wraps every call in
// analyzeWithRetry, so implementations only need to make one HTTP request
// per call and return errRetryable on 503.
type analyzer interface {
	Analyze(ctx context.Context, sha256, path string) (*analyzeResult, error)
	Slots() int
	MemoryMB() int // total system memory; 0 = unknown (treated as largest tier)
	Name() string
	Health(ctx context.Context) (*nodeHealth, error)
	Info(ctx context.Context) (*nodeInfo, error)
	Update(ctx context.Context) (*updateResult, error)
}

// nodeInfo is the parsed /_/info response. Used at startup for capacity
// discovery and version-mismatch detection across the pool.
type nodeInfo struct { //nolint:govet // small struct; readability over padding minimization.
	Version      string // litmus binary version (CARGO_PKG_VERSION)
	ModelCommit  string // models repo commit/version, "" if unknown
	TraitsCommit string // cleave traits repo commit/version, "" if unknown
	Slots        int    // configured concurrency limit
	CPUs         int    // detected CPU count (informational)
	MaxUploadMB  int    // max body size accepted by /analyze
	TotalMemMB   int    // total system memory in MiB (0 = unknown)
}

// updateResult summarizes a /_/update call. Both flags are independent —
// either, neither, or both pulls may have succeeded; the reload runs
// regardless of pull success so the server always returns to a usable state.
type updateResult struct { //nolint:govet // small struct; readability over padding.
	Version       string
	ModelCommit   string
	TraitsCommit  string
	ElapsedMs     int64
	ModelsUpdated bool
	TraitsUpdated bool
	ModelsErr     string
	TraitsErr     string
}

// fetchInfo issues a single GET /_/info and parses the JSON response. Used
// by both local and remote nodes' Info() methods so the wire format stays
// in one place.
func fetchInfo(ctx context.Context, client *http.Client, baseURL string) (*nodeInfo, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, baseURL+"/_/info", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) //nolint:gosec // base URL constructed from operator-supplied address
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/_/info status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, err
	}
	var raw struct {
		Version      string  `json:"version"`
		Slots        int     `json:"slots"`
		CPUs         int     `json:"cpus"`
		MaxUploadMB  int     `json:"max_upload_mb"`
		TotalMemMB   int     `json:"total_mem_mb"`
		ModelCommit  *string `json:"model_commit"`
		TraitsCommit *string `json:"traits_commit"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse /_/info: %w", err)
	}
	out := &nodeInfo{
		Version:     raw.Version,
		Slots:       raw.Slots,
		CPUs:        raw.CPUs,
		MaxUploadMB: raw.MaxUploadMB,
		TotalMemMB:  raw.TotalMemMB,
	}
	if raw.ModelCommit != nil {
		out.ModelCommit = *raw.ModelCommit
	}
	if raw.TraitsCommit != nil {
		out.TraitsCommit = *raw.TraitsCommit
	}
	return out, nil
}

// postUpdate issues a single POST /_/update and parses the response. The
// timeout is generous because models_repo + traits_repo run a git pull and
// the model reload can take tens of seconds on a cold litmus.
func postUpdate(ctx context.Context, client *http.Client, baseURL string) (*updateResult, error) {
	updateCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(updateCtx, http.MethodPost, baseURL+"/_/update", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) //nolint:gosec // base URL constructed from operator-supplied address
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// Try to surface the structured error if litmus returned one.
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errBody) == nil && errBody.Error != "" {
			return nil, fmt.Errorf("/_/update status %d: %s", resp.StatusCode, errBody.Error)
		}
		return nil, fmt.Errorf("/_/update status %d", resp.StatusCode)
	}

	var raw struct {
		Version       string  `json:"version"`
		ElapsedMs     int64   `json:"elapsed_ms"`
		ModelsUpdated bool    `json:"models_updated"`
		TraitsUpdated bool    `json:"traits_updated"`
		ModelsError   *string `json:"models_error"`
		TraitsError   *string `json:"traits_error"`
		ModelCommit   *string `json:"model_commit"`
		TraitsCommit  *string `json:"traits_commit"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse /_/update: %w", err)
	}
	out := &updateResult{
		Version:       raw.Version,
		ElapsedMs:     raw.ElapsedMs,
		ModelsUpdated: raw.ModelsUpdated,
		TraitsUpdated: raw.TraitsUpdated,
	}
	if raw.ModelCommit != nil {
		out.ModelCommit = *raw.ModelCommit
	}
	if raw.TraitsCommit != nil {
		out.TraitsCommit = *raw.TraitsCommit
	}
	if raw.ModelsError != nil {
		out.ModelsErr = *raw.ModelsError
	}
	if raw.TraitsError != nil {
		out.TraitsErr = *raw.TraitsError
	}
	return out, nil
}

// nodeHealth is the slice of /_/health a hopper node-monitor cares about.
// Both local and remote nodes report the same shape; "down" is synthesized
// by the monitor when a poll fails (the server itself never returns it).
type nodeHealth struct { //nolint:govet // small struct; readability over padding minimization.
	Status        string  // "ok" | "starting" | "saturated" | "degraded" | "failed" | "down"
	Reason        string  // litmus-supplied free-form code, e.g. "memory_pressure"
	Load          float64 // 0..1, live_tasks / max_concurrent_tasks
	LoadAvg       float64 // 1-minute system load average from the host
	RSSMB         int     // resident set size in MiB
	LiveTasks     int     // currently-running tasks
	ActiveTasks   int     // active_tasks counter (may include orphaned)
	OrphanedTasks int     // tasks that timed out but thread still running
	MaxConcurrent int     // configured worker slot count
	UptimeSecs    int64   // seconds since the litmus process started
	// StuckRequests lists in-flight requests exceeding 60s. Populated from
	// /_/requests when the node is saturated or has orphans.
	StuckRequests []stuckRequest
}

// stuckRequest is an in-flight litmus request exceeding 60s, surfaced in the
// dashboard so operators can see which file and analysis phase is blocking.
type stuckRequest struct {
	Name      string
	ElapsedMs int64
	Phase     string
	ThreadID  uint64
	TimedOut  bool
}

// fetchHealth issues a single GET /_/health and parses the JSON response.
// Used by both local and remote nodes' Health() methods so the wire format
// stays in one place.
func fetchHealth(ctx context.Context, client *http.Client, baseURL string) (*nodeHealth, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, baseURL+"/_/health", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) //nolint:gosec // base URL constructed from operator-supplied address
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, err
	}
	var raw struct {
		Status        string  `json:"status"`
		Reason        string  `json:"reason"`
		Load          float64 `json:"load"`
		LoadAvg       float64 `json:"load_avg"`
		RSSMB         int     `json:"rss_mb"`
		LiveTasks     int     `json:"live_tasks"`
		ActiveTasks   int     `json:"active_tasks"`
		OrphanedTasks int     `json:"orphaned_tasks"`
		MaxConcurrent int     `json:"max_concurrent_tasks"`
		UptimeSecs    int64   `json:"uptime_secs"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse /_/health: %w", err)
	}
	// Litmus returns "starting"/"degraded" with HTTP 503; "saturated" comes
	// back with 200 since a fully-utilised pool is the target steady state,
	// not a fault. Any other non-200 we don't recognise gets bucketed as
	// degraded so it shows up on the dashboard.
	status := raw.Status
	if status == "" {
		if resp.StatusCode == http.StatusOK {
			status = "ok"
		} else {
			status = "degraded"
		}
	}
	h := &nodeHealth{
		Status:        status,
		Reason:        raw.Reason,
		Load:          raw.Load,
		LoadAvg:       raw.LoadAvg,
		RSSMB:         raw.RSSMB,
		LiveTasks:     raw.LiveTasks,
		ActiveTasks:   raw.ActiveTasks,
		OrphanedTasks: raw.OrphanedTasks,
		MaxConcurrent: raw.MaxConcurrent,
		UptimeSecs:    raw.UptimeSecs,
	}

	// When the node is saturated or has orphans, fetch /_/requests for
	// stuck-request detail. Skip the extra call when healthy.
	if raw.OrphanedTasks > 0 || status == "saturated" {
		h.StuckRequests = fetchStuckRequests(ctx, client, baseURL)
	}

	return h, nil
}

// fetchStuckRequests calls /_/requests and returns entries exceeding 60s.
func fetchStuckRequests(ctx context.Context, client *http.Client, baseURL string) []stuckRequest {
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+"/_/requests", http.NoBody)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req) //nolint:gosec // base URL constructed from operator-supplied address
	if err != nil {
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil
	}
	var parsed struct {
		Requests []struct {
			Name      string `json:"name"`
			ElapsedMs int64  `json:"elapsed_ms"`
			TimedOut  bool   `json:"timed_out"`
			Phase     string `json:"phase"`
			ThreadID  uint64 `json:"thread_id"`
		} `json:"requests"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return nil
	}
	var stuck []stuckRequest
	for _, r := range parsed.Requests {
		if r.ElapsedMs > 60_000 {
			stuck = append(stuck, stuckRequest{
				Name:      r.Name,
				ElapsedMs: r.ElapsedMs,
				Phase:     r.Phase,
				ThreadID:  r.ThreadID,
				TimedOut:  r.TimedOut,
			})
		}
	}
	return stuck
}

// remoteLitmus is a litmus server reachable over HTTP at a remote address.
// Capacity is discovered once at startup via /_/info; per-request retries
// (transport blips and 503s) are handled by analyzeWithRetry, not here.
type remoteLitmus struct { //nolint:govet // small struct; readability over padding minimization.
	client   *http.Client
	addr     string // host:port (no scheme)
	url      string // http://host:port
	slots    int    // discovered from /_/info
	cpus     int    // discovered from /_/info; informational
	memoryMB int    // total system memory in MiB; 0 = unknown
}

// dialRemoteLitmus connects to addr, fetches /_/info, and returns a node
// ready for use. addr may be "host" (port defaults to 49999) or "host:port".
func dialRemoteLitmus(ctx context.Context, addr string) (*remoteLitmus, error) {
	if !strings.Contains(addr, ":") {
		addr = addr + ":" + defaultRemoteLitmusPort
	}
	base := "http://" + addr

	// Conservative initial pool sizing; tightened to slots+2 once /_/info
	// returns the actual concurrency limit. Plain HTTP — local hub, no TLS.
	client := &http.Client{
		// No top-level timeout; per-request deadline lives on ctx so long
		// analyses (up to 120s+) aren't cut off arbitrarily.
		Transport: &http.Transport{
			MaxConnsPerHost:     16,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     5 * time.Minute,
			DisableCompression:  true, // malware binaries don't compress
		},
	}

	infoCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(infoCtx, http.MethodGet, base+"/_/info", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	resp, err := client.Do(req) //nolint:gosec // operator-supplied address from --litmus-nodes
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dial %s: /_/info returned status %d", addr, resp.StatusCode)
	}

	var info struct {
		Version     string `json:"version"`
		Slots       int    `json:"slots"`
		CPUs        int    `json:"cpus"`
		MaxUploadMB int    `json:"max_upload_mb"`
		TotalMemMB  int    `json:"total_mem_mb"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&info); err != nil {
		return nil, fmt.Errorf("dial %s: parse /_/info: %w", addr, err)
	}
	if info.Slots < 1 {
		return nil, fmt.Errorf("dial %s: invalid slot count %d", addr, info.Slots)
	}

	// Right-size the connection pool to the discovered slot count so each
	// concurrent request gets a persistent connection.
	if t, ok := client.Transport.(*http.Transport); ok {
		t.MaxConnsPerHost = info.Slots + 2
		t.MaxIdleConnsPerHost = info.Slots + 2
	}

	slog.Info("remote litmus dialed",
		"addr", addr,
		"slots", info.Slots,
		"cpus", info.CPUs,
		"version", info.Version,
		"max_upload_mb", info.MaxUploadMB,
		"total_mem_mb", info.TotalMemMB)

	return &remoteLitmus{
		client:   client,
		addr:     addr,
		url:      base,
		slots:    info.Slots,
		cpus:     info.CPUs,
		memoryMB: info.TotalMemMB,
	}, nil
}

// Slots reports the discovered concurrency limit on this remote node.
func (r *remoteLitmus) Slots() int { return r.slots }

// MemoryMB returns the total system memory discovered at dial time.
func (r *remoteLitmus) MemoryMB() int { return r.memoryMB }

// Name returns the address used for logs and metrics.
func (r *remoteLitmus) Name() string { return r.addr }

// Health polls /_/health on the remote and returns a parsed snapshot.
func (r *remoteLitmus) Health(ctx context.Context) (*nodeHealth, error) {
	return fetchHealth(ctx, r.client, r.url)
}

// Info fetches the latest /_/info from the remote (uncached). Used for
// version-mismatch detection after the optional /_/update step.
func (r *remoteLitmus) Info(ctx context.Context) (*nodeInfo, error) {
	return fetchInfo(ctx, r.client, r.url)
}

// Update asks the remote to pull fresh models + traits and reload. Both
// pulls are independently non-fatal on the litmus side; this method only
// errors on transport / parse / 5xx, not on individual pull failures
// (which are surfaced via updateResult.ModelsErr / TraitsErr).
func (r *remoteLitmus) Update(ctx context.Context) (*updateResult, error) {
	return postUpdate(ctx, r.client, r.url)
}

// Analyze uploads the file via multipart and parses the response. The body is
// streamed through an io.Pipe so memory use is bounded regardless of file
// size. Returns errRetryable on 503 so analyzeWithRetry can back off and
// retry on a different node (or this one, after the queue rebalances).
func (r *remoteLitmus) Analyze(ctx context.Context, sha256, path string) (*analyzeResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from a sample row managed by hopper
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // open-file close

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	// Pump the file through the multipart writer in a goroutine so http.Client
	// can read the wire format directly. CloseWithError(nil) closes cleanly;
	// CloseWithError(err) propagates the failure to the HTTP client side.
	go func() {
		err := func() error {
			part, err := mw.CreateFormFile("file", filepath.Base(path))
			if err != nil {
				return err
			}
			if _, err := io.Copy(part, f); err != nil {
				return err
			}
			return mw.Close()
		}()
		_ = pw.CloseWithError(err)
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url+"/analyze", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Sample-Sha256", sha256)

	resp, err := r.client.Do(req) //nolint:gosec // operator-supplied address validated by dialRemoteLitmus
	if err != nil {
		return nil, fmt.Errorf("litmus %s: %w", r.addr, err)
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP response close

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, errRetryable
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512)) //nolint:errcheck // best-effort error body
		return nil, fmt.Errorf("litmus %s: %s: HTTP %d: %s", r.addr, sha256, resp.StatusCode, bytes.TrimSpace(msg))
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("litmus %s: read response: %w", r.addr, err)
	}

	var envelope struct {
		ML  json.RawMessage `json:"ml"`
		Raw json.RawMessage `json:"raw"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("litmus %s: parse envelope: %w", r.addr, err)
	}

	canonical := extractCanonicalSHA(sha256, envelope.Raw)

	var totalMs int64
	if v := resp.Header.Get("X-Total-Ms"); v != "" {
		if parsed, parseErr := strconv.ParseInt(v, 10, 64); parseErr == nil {
			totalMs = parsed
		}
	}

	return &analyzeResult{
		ML:        envelope.ML,
		Raw:       envelope.Raw,
		Canonical: canonical,
		TotalMs:   totalMs,
	}, nil
}

// analyzeWithRetry wraps a single analyzer.Analyze call with the retry policy
// historically applied to the local litmus path: 12 attempts, 2s→2min
// exponential backoff with jitter, retrying on errRetryable (503) and
// transient network errors. Used by every slot in startAnalysisWorkers so
// local and remote nodes share one retry policy.
// errNodeUnreachable is returned when the node's health monitor reports it as
// down, so the worker can fail fast instead of burning through retries.
var errNodeUnreachable = errors.New("node unreachable")

func analyzeWithRetry(ctx context.Context, node analyzer, mon *nodeMonitor, sha256, path string) (*analyzeResult, error) {
	r, err := retry.DoWithData(
		func() (*analyzeResult, error) {
			// Fail fast if the health monitor already knows the node is down.
			if mon != nil {
				if snap := mon.Snapshot(); snap != nil && !snap.Reachable {
					return nil, fmt.Errorf("%w: %s", errNodeUnreachable, snap.LastErr)
				}
			}
			return node.Analyze(ctx, sha256, path)
		},
		retry.Attempts(4),
		retry.Context(ctx),
		retry.Delay(2*time.Second),
		retry.MaxDelay(15*time.Second),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.MaxJitter(3*time.Second),
		retry.RetryIf(func(err error) bool {
			// Don't retry if the health monitor says the node is down.
			if errors.Is(err, errNodeUnreachable) {
				return false
			}
			return errors.Is(err, errRetryable) || isRetryableNetError(err)
		}),
		retry.OnRetry(func(attempt uint, _ error) {
			slog.Debug("analyze retrying",
				"node", node.Name(),
				"path", path,
				"attempt", attempt+1)
		}),
		retry.LastErrorOnly(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", node.Name(), path, err)
	}
	return r, nil
}

// parseLitmusNodes splits the --litmus-nodes flag value (comma-separated
// host[:port]) into addresses. Whitespace is trimmed; empty entries skipped.
func parseLitmusNodes(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// nodeStatusSnapshot is the latest health observation for one node, plus the
// metadata the dashboard wants to render. It's stored as an atomic.Pointer
// inside nodeMonitor so the dashboard reads without locks. A new snapshot
// is allocated and stored on every poll.
type nodeStatusSnapshot struct { //nolint:govet // small struct; readability over padding minimization.
	Health       nodeHealth // last successful health body (zero on first failure)
	LastUpdate   time.Time  // when this snapshot was written
	LastErr      string     // empty when Health is fresh; populated when the most recent poll failed
	Reachable    bool       // false ⇒ poll failed; render as "down"
	Restarts     int        // cumulative restart count (local node only)
	TotalMemMB   int        // total physical memory from /_/info (0 = unknown)
	TraitsCommit string     // short commit hash from /_/info (refreshed every ~60s)
	Version      string     // litmus binary version from /_/info
}

// nodeMonitor periodically polls one node's /_/health and exposes the latest
// snapshot to the dashboard via Snapshot(). Each monitor owns one goroutine,
// started by startNodeMonitors and stopped when its context is cancelled.
type nodeMonitor struct {
	node           analyzer
	snap           atomic.Pointer[nodeStatusSnapshot]
	analyzed       atomic.Int64 // cumulative completions on this node, incremented by analysis workers
	analyzeErrors  atomic.Int64 // cumulative analysis errors on this node
	lastCompleted  atomic.Int64 // unix nanos of last successful completion
	inFlight       sync.Map     // slot ID (int) → *workerState; written by analysis workers
	restartCounter func() int   // optional: returns cumulative restart count (local node only)
	pollCount      int          // incremented each tick; drives periodic /_/info refresh
}

// IncrAnalyzed increments the per-node completion counter. Called by analysis
// workers after each successful analysis on this node.
func (m *nodeMonitor) IncrAnalyzed() {
	m.analyzed.Add(1)
	m.lastCompleted.Store(time.Now().UnixNano())
}

// Analyzed returns the cumulative completion count for this node.
func (m *nodeMonitor) Analyzed() int64 { return m.analyzed.Load() }

// IncrErrors increments the per-node error counter.
func (m *nodeMonitor) IncrErrors() { m.analyzeErrors.Add(1) }

// Errors returns the cumulative error count for this node.
func (m *nodeMonitor) Errors() int64 { return m.analyzeErrors.Load() }

// LastCompletedAge returns how long ago the last successful analysis finished,
// or zero if none have completed yet.
func (m *nodeMonitor) LastCompletedAge() time.Duration {
	ns := m.lastCompleted.Load()
	if ns == 0 {
		return 0
	}
	return time.Since(time.Unix(0, ns)).Round(time.Second)
}

// TrackSlot records that slot id is working on file. Call with "" to clear.
func (m *nodeMonitor) TrackSlot(id int, file string) {
	if file == "" {
		m.inFlight.Delete(id)
	} else {
		m.inFlight.Store(id, &workerState{File: file, StartedAt: time.Now()})
	}
}

// inFlightJob is one currently-running analysis task on a node.
type inFlightJob struct {
	File    string
	Elapsed time.Duration
}

// InFlightList returns all running jobs on this node, sorted oldest-first.
func (m *nodeMonitor) InFlightList() []inFlightJob {
	now := time.Now()
	var jobs []inFlightJob
	m.inFlight.Range(func(_, v any) bool {
		ws, ok := v.(*workerState)
		if ok {
			jobs = append(jobs, inFlightJob{
				File:    ws.File,
				Elapsed: now.Sub(ws.StartedAt).Round(time.Second),
			})
		}
		return true
	})
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].Elapsed > jobs[j].Elapsed
	})
	return jobs
}

// Snapshot returns the most recent observation, or nil if no poll has run yet.
func (m *nodeMonitor) Snapshot() *nodeStatusSnapshot {
	return m.snap.Load()
}

// Name returns the underlying node's name (for log/dashboard labels).
func (m *nodeMonitor) Name() string { return m.node.Name() }

// Slots returns the underlying node's slot count.
func (m *nodeMonitor) Slots() int { return m.node.Slots() }

// nodeHealthPollInterval is how often each monitor polls /_/health. Short
// enough that the dashboard feels live; long enough to be invisible against
// real analysis traffic.
const nodeHealthPollInterval = 5 * time.Second

// startNodeMonitors creates one monitor per node and spawns a polling
// goroutine for each. Goroutines exit when ctx is cancelled.
func startNodeMonitors(ctx context.Context, nodes []analyzer) []*nodeMonitor {
	if len(nodes) == 0 {
		return nil
	}
	monitors := make([]*nodeMonitor, len(nodes))
	for i, n := range nodes {
		m := &nodeMonitor{node: n}
		if ls, ok := n.(*litmusServer); ok {
			m.restartCounter = ls.Restarts
		}
		monitors[i] = m
		go m.run(ctx)
	}
	return monitors
}

// run polls /_/health on a fixed interval, writing each observation into the
// monitor's atomic snapshot. The first poll is performed immediately so the
// dashboard has data on its first tick instead of after one full interval.
func (m *nodeMonitor) run(ctx context.Context) {
	m.poll(ctx)
	ticker := time.NewTicker(nodeHealthPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.poll(ctx)
		}
	}
}

// infoPollEvery controls how many health polls pass between /_/info refreshes.
// At 5s health intervals this means ~60s between info fetches.
const infoPollEvery = 12

// poll performs one health request and stores the result. Failures become a
// "down" snapshot with the error string preserved for dashboard display.
// Every infoPollEvery ticks it also fetches /_/info to refresh version and
// traits commit.
func (m *nodeMonitor) poll(ctx context.Context) {
	m.pollCount++

	// Carry forward previous info fields; refresh periodically.
	var traitsCommit, version string
	var totalMemMB int
	if old := m.snap.Load(); old != nil {
		traitsCommit = old.TraitsCommit
		version = old.Version
		totalMemMB = old.TotalMemMB
	}
	if m.pollCount%infoPollEvery == 1 { // first poll + every Nth
		if info, err := m.node.Info(ctx); err == nil {
			traitsCommit = info.TraitsCommit
			version = info.Version
			if info.TotalMemMB > 0 {
				totalMemMB = info.TotalMemMB
			}
		}
	}

	h, err := m.node.Health(ctx)
	if err != nil {
		// Preserve the previous successful Health body so the dashboard can
		// still show the last-known good values alongside the "down" mark.
		var prev nodeHealth
		if old := m.snap.Load(); old != nil {
			prev = old.Health
		}
		m.snap.Store(&nodeStatusSnapshot{
			Health:       prev,
			LastUpdate:   time.Now(),
			LastErr:      err.Error(),
			Reachable:    false,
			TotalMemMB:   totalMemMB,
			TraitsCommit: traitsCommit,
			Version:      version,
		})
		return
	}
	restarts := 0
	if m.restartCounter != nil {
		restarts = m.restartCounter()
	}
	m.snap.Store(&nodeStatusSnapshot{
		Health:       *h,
		LastUpdate:   time.Now(),
		Reachable:    true,
		Restarts:     restarts,
		TotalMemMB:   totalMemMB,
		TraitsCommit: traitsCommit,
		Version:      version,
	})
}

// updateAllNodes asks every node to pull fresh models + traits in parallel.
// Best-effort: failures are logged at warn level but never abort the run.
// Returns once every node has either responded or errored. Skips silently
// if nodes is empty.
func updateAllNodes(ctx context.Context, nodes []analyzer) {
	if len(nodes) == 0 {
		return
	}
	type result struct {
		err  error
		res  *updateResult
		name string
	}
	results := make(chan result, len(nodes))
	for _, n := range nodes {
		node := n
		go func() {
			r, err := node.Update(ctx)
			results <- result{name: node.Name(), res: r, err: err}
		}()
	}
	for range nodes {
		r := <-results
		switch {
		case r.err != nil:
			slog.Warn("rules/model update failed (continuing)",
				"node", r.name, "error", r.err)
		case r.res == nil:
			// shouldn't happen, but be defensive
			slog.Warn("rules/model update returned nothing", "node", r.name)
		default:
			slog.Info("rules/model update applied",
				"node", r.name,
				"models_updated", r.res.ModelsUpdated,
				"traits_updated", r.res.TraitsUpdated,
				"models_error", r.res.ModelsErr,
				"traits_error", r.res.TraitsErr,
				"version", r.res.Version,
				"model_commit", r.res.ModelCommit,
				"traits_commit", r.res.TraitsCommit,
				"reload_ms", r.res.ElapsedMs)
		}
	}
}

// nodeInfoSnapshot pairs a node name with its fetched info. Used for the
// version mismatch comparison so we can log which node has which version.
type nodeInfoSnapshot struct {
	Info *nodeInfo
	Name string
	Err  string
}

// fetchAllNodeInfo calls Info() on every node in parallel, with a per-node
// timeout already enforced inside fetchInfo. Failures become snapshots with
// Err set; the caller decides whether to surface them.
func fetchAllNodeInfo(ctx context.Context, nodes []analyzer) []nodeInfoSnapshot {
	if len(nodes) == 0 {
		return nil
	}
	type result struct {
		info *nodeInfo
		err  error
		name string
	}
	results := make(chan result, len(nodes))
	for _, n := range nodes {
		node := n
		go func() {
			info, err := node.Info(ctx)
			results <- result{name: node.Name(), info: info, err: err}
		}()
	}
	out := make([]nodeInfoSnapshot, 0, len(nodes))
	for range nodes {
		r := <-results
		snap := nodeInfoSnapshot{Name: r.name, Info: r.info}
		if r.err != nil {
			snap.Err = r.err.Error()
		}
		out = append(out, snap)
	}
	return out
}

// warnVersionMismatch compares litmus binary version + model_commit +
// traits_commit across the pool. Logs each node's versions at info level so
// the operator has a record. If any field disagrees across nodes, also logs
// a single warn-level line listing the divergence per field. Empty / unknown
// values participate in the comparison so "node A reports a commit, node B
// reports null" is treated as a real mismatch worth knowing about.
func warnVersionMismatch(snaps []nodeInfoSnapshot) {
	if len(snaps) == 0 {
		return
	}
	for _, s := range snaps {
		if s.Err != "" {
			slog.Warn("node version probe failed", "node", s.Name, "error", s.Err)
			continue
		}
		slog.Info("node version",
			"node", s.Name,
			"litmus", s.Info.Version,
			"model_commit", s.Info.ModelCommit,
			"traits_commit", s.Info.TraitsCommit)
	}

	// Compare each field across nodes that responded successfully.
	type field struct {
		name string
		get  func(*nodeInfo) string
	}
	fields := []field{
		{"litmus_version", func(i *nodeInfo) string { return i.Version }},
		{"model_commit", func(i *nodeInfo) string { return i.ModelCommit }},
		{"traits_commit", func(i *nodeInfo) string { return i.TraitsCommit }},
	}

	for _, f := range fields {
		seen := make(map[string][]string) // value -> []nodeName
		for _, s := range snaps {
			if s.Err != "" || s.Info == nil {
				continue
			}
			v := f.get(s.Info)
			seen[v] = append(seen[v], s.Name)
		}
		if len(seen) <= 1 {
			continue // all agree (or no successful responses)
		}
		// Build a stable, human-readable description of the divergence.
		groups := make([]string, 0, len(seen))
		for v, names := range seen {
			label := v
			if label == "" {
				label = "(unknown)"
			}
			groups = append(groups, fmt.Sprintf("%s=[%s]", label, strings.Join(names, ",")))
		}
		sort.Strings(groups)
		slog.Warn("node version mismatch",
			"field", f.name,
			"groups", strings.Join(groups, " "))
	}
}

// dialAllRemoteLitmus dials each address concurrently. Failures are logged
// and the node is omitted from the result — startup never fails because of
// an unreachable remote node, on the principle that N working nodes are
// better than aborting the run. Failed addresses are returned so callers can
// retry them later.
func dialAllRemoteLitmus(ctx context.Context, addrs []string) (nodes []*remoteLitmus, failed []string) {
	if len(addrs) == 0 {
		return nil, nil
	}
	type result struct {
		node *remoteLitmus
		err  error
		addr string
	}
	results := make(chan result, len(addrs))
	for _, addr := range addrs {
		go func(addr string) {
			n, err := dialRemoteLitmus(ctx, addr)
			results <- result{node: n, err: err, addr: addr}
		}(addr)
	}
	for range addrs {
		r := <-results
		if r.err != nil {
			slog.Warn("remote litmus unreachable at startup; skipping",
				"addr", r.addr, "error", r.err)
			failed = append(failed, r.addr)
			continue
		}
		nodes = append(nodes, r.node)
	}
	return nodes, failed
}

// ---------------------------------------------------------------------------
// Size-tiered analysis queues
// ---------------------------------------------------------------------------
//
// Nodes are ranked by memory into quartile tiers. Files are routed to a tier
// channel based on size thresholds proportional to node memory. A worker at
// tier T draws from tiers 0..T, preferring its own tier so large nodes drain
// large files first but help with small files when idle. Nodes with unknown
// memory (0) are placed in the highest tier and receive all files.

const numSizeTiers = 4

// sizeTieredQueues routes loadJobs to per-tier channels based on file size,
// so smaller-memory nodes only see smaller files.
type sizeTieredQueues struct {
	queues     [numSizeTiers]chan loadJob
	thresholds [numSizeTiers]int64 // files <= thresholds[i] go to queues[i]
	memBreaks  [numSizeTiers]int   // max node memory (MiB) for each tier
	tierByNode map[string]int      // node name → tier index
}

// newSizeTieredQueues builds tiered queues from the known node set.
// maxFileBytes is the global per-file size cap (e.g. 100 MiB).
func newSizeTieredQueues(nodes []analyzer, queueCap int, maxFileBytes int64) *sizeTieredQueues {
	sq := &sizeTieredQueues{
		tierByNode: make(map[string]int, len(nodes)),
	}
	perTier := queueCap / numSizeTiers
	if perTier < 1 {
		perTier = 1
	}
	for i := range sq.queues {
		sq.queues[i] = make(chan loadJob, perTier)
	}

	// Collect node memories; 0 means unknown → treated as max.
	mems := make([]int, len(nodes))
	maxMem := 0
	for i, n := range nodes {
		mems[i] = n.MemoryMB()
		if mems[i] > maxMem {
			maxMem = mems[i]
		}
	}

	// If no memory info available at all, everything goes to the last tier
	// and all workers read from it — equivalent to the old single-queue behavior.
	if maxMem == 0 {
		for i := range sq.thresholds {
			sq.thresholds[i] = maxFileBytes
		}
		for _, n := range nodes {
			sq.tierByNode[n.Name()] = numSizeTiers - 1
		}
		slog.Info("size-tiered queues: no memory info, all nodes at max tier")
		return sq
	}

	// Sort unique memory values to compute tier boundaries.
	sorted := make([]int, len(mems))
	copy(sorted, mems)
	sort.Ints(sorted)
	// Replace 0 (unknown) with maxMem for threshold computation.
	for i, m := range sorted {
		if m == 0 {
			sorted[i] = maxMem
		}
	}

	// Tier boundaries: percentile 25/50/75/100 of the node memory distribution.
	for t := 0; t < numSizeTiers; t++ {
		idx := ((t + 1) * len(sorted) / numSizeTiers) - 1
		if idx < 0 {
			idx = 0
		}
		tierMem := sorted[idx]
		sq.memBreaks[t] = tierMem
		// File size threshold proportional to this tier's memory share.
		sq.thresholds[t] = maxFileBytes * int64(tierMem) / int64(maxMem)
		if sq.thresholds[t] < 1 {
			sq.thresholds[t] = 1
		}
	}
	// Last tier always accepts everything.
	sq.thresholds[numSizeTiers-1] = maxFileBytes
	sq.memBreaks[numSizeTiers-1] = maxMem

	// Assign each node to a tier based on its memory.
	for _, n := range nodes {
		sq.tierByNode[n.Name()] = sq.tierForMem(n.MemoryMB())
	}

	slog.Info("size-tiered queues configured",
		"thresholds_bytes", sq.thresholds,
		"mem_breaks_mb", sq.memBreaks,
		"tier_assignments", sq.tierByNode)
	return sq
}

// Send routes a job to the appropriate tier channel based on file size.
func (sq *sizeTieredQueues) Send(ctx context.Context, job loadJob) error {
	tier := numSizeTiers - 1
	for t := 0; t < numSizeTiers; t++ {
		if job.sizeBytes <= sq.thresholds[t] {
			tier = t
			break
		}
	}
	select {
	case sq.queues[tier] <- job:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes all tier channels, signaling workers to drain and exit.
func (sq *sizeTieredQueues) Close() {
	for i := range sq.queues {
		close(sq.queues[i])
	}
}

// TierForNode returns the tier assigned to the named node.
func (sq *sizeTieredQueues) TierForNode(name string) int {
	if t, ok := sq.tierByNode[name]; ok {
		return t
	}
	return numSizeTiers - 1
}

// AssignNode registers a late-joining node into a tier based on its memory.
func (sq *sizeTieredQueues) AssignNode(n analyzer) {
	tier := sq.tierForMem(n.MemoryMB())
	sq.tierByNode[n.Name()] = tier
	slog.Info("late-joined node assigned tier", "node", n.Name(), "memory_mb", n.MemoryMB(), "tier", tier)
}

// tierForMem returns the tier a node with the given memory belongs to.
// Unknown (0) maps to the highest tier.
func (sq *sizeTieredQueues) tierForMem(memMB int) int {
	if memMB <= 0 {
		return numSizeTiers - 1
	}
	for t := 0; t < numSizeTiers; t++ {
		if memMB <= sq.memBreaks[t] {
			return t
		}
	}
	return numSizeTiers - 1
}

// recvJob blocks until a job is available from any tier up to maxTier.
// It prefers the worker's own tier (highest accessible) to keep large files
// on large nodes, falling back to lower tiers when the own tier is empty.
// Returns the job and true, or zero-value and false when all accessible
// channels are closed and drained.
func (sq *sizeTieredQueues) recvJob(ctx context.Context, maxTier int) (loadJob, bool) {
	// Fast path: non-blocking try on our own tier.
	select {
	case job, ok := <-sq.queues[maxTier]:
		if ok {
			return job, true
		}
	default:
	}

	// Slow path: blocking select across tiers 0..maxTier + ctx.Done.
	// Use reflect.Select for dynamic case count.
	cases := make([]reflect.SelectCase, maxTier+2)
	for t := 0; t <= maxTier; t++ {
		cases[t] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(sq.queues[t]),
		}
	}
	cases[maxTier+1] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	}

	chosen, value, ok := reflect.Select(cases)
	if chosen == maxTier+1 {
		// ctx.Done fired.
		return loadJob{}, false
	}
	if !ok {
		// Channel closed. Check if ALL accessible tiers are closed.
		// Drain remaining open channels before giving up.
		for {
			openCases := make([]reflect.SelectCase, 0, maxTier+2)
			tierMap := make([]int, 0, maxTier+2)
			for t := 0; t <= maxTier; t++ {
				// Skip the tier that just closed by trying a non-blocking recv.
				select {
				case job, open := <-sq.queues[t]:
					if open {
						// Got a job from this tier while probing — return it.
						return job, true
					}
					// This tier is closed and drained, skip it.
				default:
					// Still open (or has buffered items), include it.
					openCases = append(openCases, reflect.SelectCase{
						Dir:  reflect.SelectRecv,
						Chan: reflect.ValueOf(sq.queues[t]),
					})
					tierMap = append(tierMap, t)
				}
			}
			if len(openCases) == 0 {
				return loadJob{}, false
			}
			// Add ctx.Done.
			openCases = append(openCases, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(ctx.Done()),
			})
			chosen, value, ok = reflect.Select(openCases)
			if chosen == len(openCases)-1 {
				return loadJob{}, false
			}
			if ok {
				return value.Interface().(loadJob), true
			}
			// Another channel closed, loop to rebuild cases.
		}
	}
	return value.Interface().(loadJob), true
}

// monitorPool is a thread-safe, append-only collection of node monitors.
// The dashboard reads the current snapshot on every tick via All(); the
// late-join retry goroutine appends via Add(). Internally it swaps an
// atomic pointer to an immutable slice so readers never block.
type monitorPool struct {
	p atomic.Pointer[[]*nodeMonitor]
}

func newMonitorPool(initial []*nodeMonitor) *monitorPool {
	mp := &monitorPool{}
	if initial == nil {
		initial = []*nodeMonitor{}
	}
	mp.p.Store(&initial)
	return mp
}

// All returns the current snapshot. The returned slice must not be mutated.
func (mp *monitorPool) All() []*nodeMonitor {
	return *mp.p.Load()
}

// Add appends new monitors and atomically publishes the updated list.
func (mp *monitorPool) Add(monitors ...*nodeMonitor) {
	for {
		old := mp.p.Load()
		next := make([]*nodeMonitor, len(*old)+len(monitors))
		copy(next, *old)
		copy(next[len(*old):], monitors)
		if mp.p.CompareAndSwap(old, &next) {
			return
		}
	}
}
