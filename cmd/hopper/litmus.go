package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeGROOVE-dev/retry"
)

const restartRecoveryDelay = 15 * time.Second

// litmusServer manages a litmus API server subprocess.
type litmusServer struct { //nolint:govet // field order is chosen for readability over padding minimization.
	client      *http.Client
	cmd         *exec.Cmd
	bin         string // path to litmus binary
	url         string // base URL (e.g. http://127.0.0.1:PORT)
	port        string
	dirs        []string
	mu          sync.Mutex
	maxRSSGB    int
	maxWorkers  int
	timeoutSecs int
	verbose     bool
	stopped     atomic.Bool
	pid         atomic.Int64

	// inFlight tracks what each hopper analysis worker is currently doing.
	inFlight sync.Map // worker ID (int) → *workerState
}

type workerState struct { //nolint:govet // tiny runtime-only struct; readability wins here.
	File      string
	StartedAt time.Time
}

type workerSnapshot struct { //nolint:govet // compact summary struct; layout is not performance-critical.
	Busy       int
	Idle       int
	OldestMS   int64
	OldestFile string
}

// litmusConfig holds options for starting a litmus server.
type litmusConfig struct {
	Bin         string   // path to litmus binary (default: "litmus")
	Dirs        []string // directories to allow for /analyze-path
	MaxRSSGB    int      // memory limit in GB (0 = let litmus decide)
	MaxWorkers  int      // max concurrent analysis requests to send
	TimeoutSecs int      // per-request analysis timeout (0 = litmus default: 600s)
	Verbose     bool     // enable debug logging in litmus
}

func newLitmusServer(cfg litmusConfig) *litmusServer {
	if cfg.Bin == "" {
		cfg.Bin = "litmus"
	}
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = 8
	}
	return &litmusServer{
		bin:         cfg.Bin,
		dirs:        cfg.Dirs,
		maxRSSGB:    cfg.MaxRSSGB,
		maxWorkers:  cfg.MaxWorkers,
		timeoutSecs: cfg.TimeoutSecs,
		verbose:     cfg.Verbose,
		client: &http.Client{
			// Slightly longer than litmus's analysis timeout so litmus always
			// has a chance to return 504 before the client gives up.
			Timeout: time.Duration(cfg.TimeoutSecs+60) * time.Second,
		},
	}
}

func closeLogFile(name string, f *os.File) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil {
		//nolint:gosec // value is sanitized before logging; this is a false positive on slog taint flow.
		slog.Warn("failed to close litmus log file", "log", sanitizeLogString(name), "error", err)
	}
}

func sanitizeLogString(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

func killProcess(reason string, proc *os.Process, attrs ...any) {
	if proc == nil {
		return
	}
	if err := proc.Kill(); err != nil {
		slog.Warn(reason, append(attrs, "error", err)...)
	}
}

func waitCommand(reason string, cmd *exec.Cmd, attrs ...any) {
	if cmd == nil {
		return
	}
	if err := cmd.Wait(); err != nil {
		slog.Debug(reason, append(attrs, "error", err)...)
	}
}

func (s *litmusServer) currentPID() int {
	return int(s.pid.Load())
}

// Start launches the litmus server and waits for it to become healthy.
// It picks a random available port.
func (s *litmusServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil {
		return errors.New("litmus server already started")
	}

	updateLitmus(ctx)

	var lastErr error
	for range 3 {
		port, l, err := freePort(ctx)
		if err != nil {
			return fmt.Errorf("find free port: %w", err)
		}
		s.port = port
		s.url = "http://127.0.0.1:" + port

		if err := s.startLocked(ctx, l); err != nil {
			lastErr = err
			slog.Warn("failed to start litmus, retrying with new port", "port", port, "error", err)
			continue
		}
		return nil
	}
	return fmt.Errorf("litmus failed to start after 3 attempts: %w", lastErr)
}

// updateLitmus attempts to build and install the latest litmus from ../litmus.
// On failure it logs the error and falls back to whatever version is already installed.
func updateLitmus(ctx context.Context) {
	dir := "../litmus"
	if _, err := os.Stat(dir); err != nil {
		slog.Warn("litmus source not found, using installed version", "dir", dir)
		return
	}

	slog.Info("updating litmus", "dir", dir)

	pull := exec.CommandContext(ctx, "git", "pull")
	pull.Dir = dir
	if out, err := pull.CombinedOutput(); err != nil {
		slog.Error("git pull failed for litmus, using installed version", "error", err, "output", string(out))
		return
	}

	install := exec.CommandContext(ctx, "make", "install")
	install.Dir = dir
	if out, err := install.CombinedOutput(); err != nil {
		slog.Error("make install failed for litmus, using installed version", "error", err, "output", string(out))
		return
	}

	slog.Info("litmus updated successfully")
}

func (s *litmusServer) startLocked(ctx context.Context, l net.Listener) error {
	if l != nil {
		if err := l.Close(); err != nil {
			slog.Warn("failed to close probe listener", "error", err)
		}
	}
	bind := "127.0.0.1:" + s.port

	args := []string{"serve", "--bind", bind}
	if len(s.dirs) > 0 {
		args = append(args, "--allowed-dirs", strings.Join(s.dirs, ","))
	}
	if s.maxRSSGB > 0 {
		args = append(args, "--max-rss-gb", strconv.Itoa(s.maxRSSGB))
	}
	if s.timeoutSecs > 0 {
		args = append(args, "--timeout-secs", strconv.Itoa(s.timeoutSecs))
	}
	if s.verbose {
		args = append(args, "--verbose")
	}

	cmd := exec.CommandContext(ctx, s.bin, args...) //nolint:gosec // bin path is from trusted CLI flag

	logDir := xdgLogDir()
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return fmt.Errorf("create litmus log directory: %w", err)
	}

	logFile, err := os.CreateTemp(logDir, "litmus-*.log")
	if err != nil {
		return fmt.Errorf("create litmus log file: %w", err)
	}

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		closeLogFile(logFile.Name(), logFile)
		return fmt.Errorf("start litmus: %w", err)
	}
	s.cmd = cmd
	s.pid.Store(int64(cmd.Process.Pid))

	//nolint:gosec // values are sanitized or derived locally; this is a false positive on structured slog fields.
	slog.Info("starting litmus server",
		"bind", bind,
		"pid", cmd.Process.Pid,
		"log", sanitizeLogString(logFile.Name()),
		"args", sanitizeLogString(strings.Join(args, " ")))

	if err := s.waitHealthy(ctx); err != nil {
		//nolint:gosec // values are sanitized or derived locally; this is a false positive on structured slog fields.
		slog.Error("litmus server failed readiness check",
			"pid", cmd.Process.Pid,
			"bind", bind,
			"error", err,
			"log", sanitizeLogString(logFile.Name()))
		killProcess("failed to kill unready litmus server", cmd.Process, "pid", cmd.Process.Pid)
		waitCommand("litmus exited after readiness failure", cmd, "pid", cmd.Process.Pid)
		closeLogFile(logFile.Name(), logFile)
		s.cmd = nil
		s.pid.Store(0)
		return fmt.Errorf("litmus not healthy: %w", err)
	}

	slog.Info("litmus server ready", "url", s.url, "pid", cmd.Process.Pid)
	return nil
}

// Stop kills the litmus server.
func (s *litmusServer) Stop() {
	s.stopped.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		slog.Info("stopping litmus server", "pid", s.cmd.Process.Pid, "url", s.url)
		killProcess("failed to kill litmus server during stop", s.cmd.Process, "pid", s.cmd.Process.Pid)
		waitCommand("litmus exited during stop", s.cmd, "pid", s.cmd.Process.Pid)
		s.cmd = nil
		s.pid.Store(0)
		slog.Info("litmus server stopped")
	}
}

// Monitor watches the litmus process and restarts it on crash.
// Blocks until ctx is cancelled or Stop is called.
func (s *litmusServer) Monitor(ctx context.Context) error {
	restarts := 0
	for {
		pid := s.currentPID()
		err := s.waitExit(ctx)
		s.pid.Store(0)
		if ctx.Err() != nil || s.stopped.Load() {
			return ctx.Err()
		}
		restarts++
		slog.Warn("litmus server crashed",
			"pid", pid,
			"url", s.url,
			"error", err,
			"restarts", restarts)

		delay := time.Duration(1<<min(restarts-1, 4)) * time.Second
		slog.Info("restarting litmus server",
			"previous_pid", pid,
			"url", s.url,
			"delay", delay,
			"attempt", restarts)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}

		if s.stopped.Load() {
			return nil
		}

		s.mu.Lock()
		err = s.startLocked(ctx, nil)
		s.mu.Unlock()
		if err != nil {
			slog.Error("failed to restart litmus",
				"previous_pid", pid,
				"url", s.url,
				"attempt", restarts,
				"next_delay", time.Duration(1<<min(restarts, 4))*time.Second,
				"error", err)
			continue
		}
		slog.Info("litmus restart waiting for recovery window",
			"pid", s.currentPID(),
			"url", s.url,
			"delay", restartRecoveryDelay,
			"attempt", restarts)
		select {
		case <-time.After(restartRecoveryDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
		slog.Info("litmus server restarted",
			"restarts", restarts,
			"pid", s.currentPID(),
			"url", s.url)
	}
}

func (s *litmusServer) waitExit(ctx context.Context) error {
	if s.cmd == nil {
		return errors.New("no process")
	}
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *litmusServer) waitHealthy(ctx context.Context) error {
	deadline := time.After(120 * time.Second) // litmus loads model + YARA, may take longer than cleave
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return errors.New("timeout waiting for litmus to start")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/_/health", http.NoBody)
			if err != nil {
				continue
			}
			resp, err := s.client.Do(req) //nolint:gosec // URL is constructed from localhost + port
			if err != nil {
				continue
			}
			if err := resp.Body.Close(); err != nil {
				slog.Debug("close litmus health body", "error", err)
			}
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}
}

// TrackWorker registers a worker as analyzing a file. Call with "" to clear.
func (s *litmusServer) TrackWorker(workerID int, file string) {
	if file == "" {
		s.inFlight.Delete(workerID)
	} else {
		s.inFlight.Store(workerID, &workerState{File: file, StartedAt: time.Now()})
	}
}

// workerSummary returns counts and the oldest in-flight file for logging.
func (s *litmusServer) workerSummary() workerSnapshot {
	now := time.Now()
	summary := workerSnapshot{Idle: s.maxWorkers}
	s.inFlight.Range(func(_, v any) bool {
		ws, ok := v.(*workerState)
		if !ok {
			return true
		}
		summary.Busy++
		elapsed := now.Sub(ws.StartedAt).Milliseconds()
		if elapsed > summary.OldestMS {
			summary.OldestMS = elapsed
			summary.OldestFile = ws.File
		}
		return true
	})
	summary.Idle -= summary.Busy
	if summary.Idle < 0 {
		summary.Idle = 0
	}
	return summary
}

// WatchHealth periodically polls litmus /_/health and /_/requests, logs the
// state, and kills litmus if any request has been stuck longer than the
// configured timeout. Runs alongside Monitor; call in a separate goroutine.
func (s *litmusServer) WatchHealth(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	stuckThreshold := time.Duration(s.timeoutSecs) * time.Second
	if stuckThreshold == 0 {
		stuckThreshold = 600 * time.Second
	}
	// Kill if any request exceeds 2x the timeout — it's clearly stuck.
	killThreshold := 2 * stuckThreshold

	healthFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if s.stopped.Load() {
			return
		}

		health := s.pollHealth(ctx)
		if health == nil {
			healthFailures++
			if healthFailures >= 3 {
				pid := s.currentPID()
				slog.Error("litmus health check failed repeatedly, killing to force restart",
					"failures", healthFailures,
					"pid", pid,
					"url", s.url)
				s.mu.Lock()
				if s.cmd != nil && s.cmd.Process != nil {
					killProcess("failed to kill unhealthy litmus server", s.cmd.Process, "pid", s.cmd.Process.Pid)
				}
				s.mu.Unlock()
				healthFailures = 0
			}
			continue
		}
		healthFailures = 0

		summary := s.workerSummary()

		level := slog.LevelDebug
		if !isStdoutTTY() && (health.ActiveTasks > 0 || summary.Busy > 0) {
			level = slog.LevelInfo
		}
		slog.Default().Log(ctx, level, "litmus health",
			"live_tasks", health.LiveTasks,
			"orphaned_tasks", health.OrphanedTasks,
			"active_tasks", health.ActiveTasks,
			"max_concurrent", health.MaxConcurrent,
			"load", fmt.Sprintf("%.2f", health.Load),
			"rss_mb", health.RSSMB,
			"litmus_oldest_ms", health.OldestRequestMs,
			"litmus_oldest_name", health.OldestRequestName,
			"hopper_busy", summary.Busy,
			"hopper_idle", summary.Idle,
			"hopper_oldest_ms", summary.OldestMS,
			"hopper_oldest_file", summary.OldestFile,
		)

		if health.OldestRequestMs > killThreshold.Milliseconds() {
			pid := s.currentPID()
			slog.Error("litmus has stuck request, killing to force restart",
				"oldest_request_ms", health.OldestRequestMs,
				"oldest_request_name", health.OldestRequestName,
				"kill_threshold_ms", killThreshold.Milliseconds(),
				"pid", pid,
				"url", s.url,
				"hopper_busy", summary.Busy,
				"hopper_idle", summary.Idle,
				"hopper_oldest_file", summary.OldestFile,
			)
			s.mu.Lock()
			if s.cmd != nil && s.cmd.Process != nil {
				killProcess("failed to kill stuck litmus server", s.cmd.Process, "pid", s.cmd.Process.Pid)
			}
			s.mu.Unlock()
		}
	}
}

type litmusHealth struct { //nolint:govet // JSON field grouping is clearer than padding order.
	ActiveTasks       int     `json:"active_tasks"`
	LiveTasks         int     `json:"live_tasks"`
	OrphanedTasks     int     `json:"orphaned_tasks"`
	MaxConcurrent     int     `json:"max_concurrent_tasks"`
	Load              float64 `json:"load"`
	RSSMB             int     `json:"rss_mb"`
	OldestRequestMs   int64
	OldestRequestName string
}

func (s *litmusServer) pollHealth(ctx context.Context) *litmusHealth {
	// Poll health.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/_/health", http.NoBody)
	if err != nil {
		return nil
	}
	resp, err := s.client.Do(req) //nolint:gosec // localhost only
	if err != nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("close litmus health response after read failure", "error", closeErr)
		}
		return nil
	}
	if err := resp.Body.Close(); err != nil {
		slog.Debug("close litmus health response", "error", err)
	}

	var h litmusHealth
	if json.Unmarshal(body, &h) != nil {
		return nil
	}

	// Poll in-flight requests for oldest.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/_/requests", http.NoBody)
	if err != nil {
		return &h
	}
	resp, err = s.client.Do(req) //nolint:gosec // localhost only
	if err != nil {
		return &h
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, 32768))
	if err != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("close litmus requests response after read failure", "error", closeErr)
		}
		return &h
	}
	if err := resp.Body.Close(); err != nil {
		slog.Debug("close litmus requests response", "error", err)
	}

	var reqList struct {
		Requests []struct {
			Name      string `json:"name"`
			ElapsedMs int64  `json:"elapsed_ms"`
		} `json:"requests"`
	}
	if json.Unmarshal(body, &reqList) == nil && len(reqList.Requests) > 0 {
		// Requests are sorted by elapsed descending — first is oldest.
		h.OldestRequestMs = reqList.Requests[0].ElapsedMs
		h.OldestRequestName = reqList.Requests[0].Name
	}

	return &h
}

// analyzeResult holds the split litmus response for storage in hopper.
type analyzeResult struct { //nolint:govet // result fields are grouped by meaning for call sites.
	ML        json.RawMessage // ml section → litmus_result column
	Raw       json.RawMessage // raw section → cleave_result column
	Canonical string          // canonical SHA256 from raw.fs[]
	TotalMs   int64           // server-reported total analysis time (from X-Total-Ms header)
}

var errRetryable = errors.New("service unavailable")

// Analyze sends a file to the litmus server for analysis.
// Returns the split response (ml + raw sections) and extracted canonical SHA.
// Retries on 503 (litmus at capacity) with exponential backoff.
func (s *litmusServer) Analyze(ctx context.Context, sha256, path string) (*analyzeResult, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: path})
	if err != nil {
		return nil, err
	}

	r, err := retry.DoWithData(
		func() (*analyzeResult, error) {
			return s.doAnalyze(ctx, sha256, body)
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
			slog.Debug("litmus analyze retrying",
				"path", path,
				"url", s.url,
				"pid", s.currentPID(),
				"attempt", attempt+1)
		}),
		retry.LastErrorOnly(true),
	)
	if err != nil {
		return nil, fmt.Errorf("litmus: %s: %w", path, err)
	}
	return r, nil
}

func (s *litmusServer) doAnalyze(ctx context.Context, sha256 string, body []byte) (*analyzeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/analyze-path", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req) //nolint:gosec // URL is constructed from localhost + port
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP response

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, errRetryable
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512)) //nolint:errcheck // best-effort error body
		return nil, fmt.Errorf("litmus: %d %s", resp.StatusCode, msg)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("litmus: read response: %w", err)
	}

	// Split the {"ml": {...}, "raw": {...}} envelope.
	var envelope struct {
		ML  json.RawMessage `json:"ml"`
		Raw json.RawMessage `json:"raw"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("litmus: parse envelope: %w", err)
	}

	canonical := extractCanonicalSHA(sha256, envelope.Raw)

	var totalMs int64
	if v := resp.Header.Get("X-Total-Ms"); v != "" {
		parsed, parseErr := strconv.ParseInt(v, 10, 64)
		if parseErr != nil {
			//nolint:gosec // header value is sanitized before logging; this is a false positive on slog taint flow.
			slog.Debug("invalid X-Total-Ms header", "value", sanitizeLogString(v), "error", parseErr)
		} else {
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

// extractCanonicalSHA computes the minimum SHA256 across files in the raw cleave report.
func extractCanonicalSHA(sha256 string, raw json.RawMessage) string {
	var report struct {
		Files []struct {
			SHA256 string `json:"sha"`
			Score  int    `json:"x"`
			Depth  int    `json:"dp"`
		} `json:"fs"`
	}
	if json.Unmarshal(raw, &report) != nil {
		return sha256
	}
	canonical := sha256
	for _, f := range report.Files {
		if len(f.SHA256) == 64 && f.SHA256 < canonical {
			canonical = f.SHA256
		}
	}
	return canonical
}

// Workers returns the max concurrent analysis workers.
func (s *litmusServer) Workers() int { return s.maxWorkers }

func freePort(ctx context.Context) (string, net.Listener, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		if err := l.Close(); err != nil {
			slog.Warn("failed to close listener with unexpected address", "error", err)
		}
		return "", nil, errors.New("unexpected listener address type")
	}
	return strconv.Itoa(addr.Port), l, nil
}

func isRetryableNetError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Common connection-level errors (refused, reset, broken pipe).
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe")
}

func isStdoutTTY() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
