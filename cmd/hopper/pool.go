package main

import (
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
	"sort"
	"strconv"
	"strings"
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
	RSSMB         int     // resident set size in MiB
	LiveTasks     int     // currently-running tasks
	ActiveTasks   int     // active_tasks counter (may include orphaned)
	MaxConcurrent int     // configured worker slot count
	UptimeSecs    int64   // seconds since the litmus process started
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
		RSSMB         int     `json:"rss_mb"`
		LiveTasks     int     `json:"live_tasks"`
		ActiveTasks   int     `json:"active_tasks"`
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
	return &nodeHealth{
		Status:        status,
		Reason:        raw.Reason,
		Load:          raw.Load,
		RSSMB:         raw.RSSMB,
		LiveTasks:     raw.LiveTasks,
		ActiveTasks:   raw.ActiveTasks,
		MaxConcurrent: raw.MaxConcurrent,
		UptimeSecs:    raw.UptimeSecs,
	}, nil
}

// remoteLitmus is a litmus server reachable over HTTP at a remote address.
// Capacity is discovered once at startup via /_/info; per-request retries
// (transport blips and 503s) are handled by analyzeWithRetry, not here.
type remoteLitmus struct { //nolint:govet // small struct; readability over padding minimization.
	client *http.Client
	addr   string // host:port (no scheme)
	url    string // http://host:port
	slots  int    // discovered from /_/info
	cpus   int    // discovered from /_/info; informational
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
		"max_upload_mb", info.MaxUploadMB)

	return &remoteLitmus{
		client: client,
		addr:   addr,
		url:    base,
		slots:  info.Slots,
		cpus:   info.CPUs,
	}, nil
}

// Slots reports the discovered concurrency limit on this remote node.
func (r *remoteLitmus) Slots() int { return r.slots }

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
		return nil, fmt.Errorf("litmus %s: %d %s", r.addr, resp.StatusCode, msg)
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
func analyzeWithRetry(ctx context.Context, node analyzer, sha256, path string) (*analyzeResult, error) {
	r, err := retry.DoWithData(
		func() (*analyzeResult, error) {
			return node.Analyze(ctx, sha256, path)
		},
		retry.Attempts(12),
		retry.Context(ctx),
		retry.Delay(2*time.Second),
		retry.MaxDelay(2*time.Minute),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.MaxJitter(3*time.Second),
		retry.RetryIf(func(err error) bool {
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
	Health     nodeHealth // last successful health body (zero on first failure)
	LastUpdate time.Time  // when this snapshot was written
	LastErr    string     // empty when Health is fresh; populated when the most recent poll failed
	Reachable  bool       // false ⇒ poll failed; render as "down"
}

// nodeMonitor periodically polls one node's /_/health and exposes the latest
// snapshot to the dashboard via Snapshot(). Each monitor owns one goroutine,
// started by startNodeMonitors and stopped when its context is cancelled.
type nodeMonitor struct {
	node analyzer
	snap atomic.Pointer[nodeStatusSnapshot]
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

// poll performs one health request and stores the result. Failures become a
// "down" snapshot with the error string preserved for dashboard display.
func (m *nodeMonitor) poll(ctx context.Context) {
	h, err := m.node.Health(ctx)
	if err != nil {
		// Preserve the previous successful Health body so the dashboard can
		// still show the last-known good values alongside the "down" mark.
		var prev nodeHealth
		if old := m.snap.Load(); old != nil {
			prev = old.Health
		}
		m.snap.Store(&nodeStatusSnapshot{
			Health:     prev,
			LastUpdate: time.Now(),
			LastErr:    err.Error(),
			Reachable:  false,
		})
		return
	}
	m.snap.Store(&nodeStatusSnapshot{
		Health:     *h,
		LastUpdate: time.Now(),
		Reachable:  true,
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
// better than aborting the run.
func dialAllRemoteLitmus(ctx context.Context, addrs []string) []*remoteLitmus {
	if len(addrs) == 0 {
		return nil
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
	var nodes []*remoteLitmus
	for range addrs {
		r := <-results
		if r.err != nil {
			slog.Warn("remote litmus unreachable at startup; skipping",
				"addr", r.addr, "error", r.err)
			continue
		}
		nodes = append(nodes, r.node)
	}
	return nodes
}
